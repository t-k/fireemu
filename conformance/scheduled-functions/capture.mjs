// Coordinator-only concrete shape executor. Imports do not read OAuth or send requests.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, mkdir, open, readFile, realpath } from "node:fs/promises";
import { dirname, join, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  acquireProjectLocks,
  releaseProjectLock,
  fields,
} from "../src/auth-fs-cross/stage2-sandbox.mjs";
import { admissionProblems } from "../src/auth-fs-cross/sandbox.mjs";
import { collectShape, PROJECT, MAX_REQUESTS, shapeRequests } from "./shape.mjs";

const REPO = fileURLToPath(new URL("../../", import.meta.url));
const TASK_ID = "SCHEDULED-FUNCTIONS";
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const SOURCES = [
  "conformance/scheduled-functions/shape.mjs",
  "conformance/scheduled-functions/capture.mjs",
  "conformance/src/auth-fs-cross/stage2-sandbox.mjs",
  "conformance/src/auth-fs-cross/sandbox.mjs",
];

export async function harnessDigest() {
  const hash = createHash("sha256");
  for (const path of SOURCES)
    hash
      .update(path)
      .update("\0")
      .update(await readFile(join(REPO, path)))
      .update("\0");
  return hash.digest("hex");
}

async function durable(path, value, flags = "wx") {
  const handle = await open(path, flags, 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(value)}\n`);
    await handle.sync();
  } finally {
    await handle.close();
  }
  const directory = await open(dirname(path), "r");
  try {
    await directory.sync();
  } finally {
    await directory.close();
  }
}

function approved(ownerText, pins) {
  let approval = false;
  for (const line of ownerText.split("\n")) {
    const [date, subject = "", body = "", author = ""] = line
      .replace(/^\s*-\s*/, "")
      .split("|")
      .map((s) => s.trim());
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || !subject.startsWith(TASK_ID)) continue;
    // Withdrawal lines use several layouts, including a word before packetSha256.
    if (body.includes(pins.packetSha256) && /\b(REVOKED|WITHDRAWN|SUPERSEDED)\b/i.test(body)) {
      approval = false;
      continue;
    }
    const entry = fields(body);
    if (entry.packetSha256 !== pins.packetSha256) continue;
    if (/REVOKED/i.test(body) || (entry.decision && entry.decision !== "APPROVE")) {
      approval = false;
      continue;
    }
    if (
      subject === "SCHEDULED-FUNCTIONS stage-2 shape packet" &&
      entry.decision === "APPROVE" &&
      /^(オーナー|Claude|調整役)/.test(author) &&
      entry.sourceCommit === pins.sourceCommit &&
      entry.harnessDigest === pins.harnessDigest &&
      entry.maxRequests === "64" &&
      entry.reserveUsd === "1"
    )
      approval = true;
  }
  return approval;
}

function budget(rows) {
  const amounts = new Map();
  for (const [index, row] of rows.entries()) {
    if (row.taskId !== TASK_ID) continue;
    for (const key of ["estimatedUsd", "maxEstimatedUsd", "reserveUsd"]) {
      if (
        Object.hasOwn(row, key) &&
        (typeof row[key] !== "number" || !Number.isFinite(row[key]) || row[key] < 0)
      )
        throw new Error("invalid task budget row");
    }
    const amount = Math.max(row.estimatedUsd ?? 0, row.maxEstimatedUsd ?? 0, row.reserveUsd ?? 0);
    if (!Number.isFinite(amount) || amount < 0) throw new Error("invalid task budget row");
    const key = row.attemptId ?? `unlinked-${index}`;
    amounts.set(key, Math.max(amounts.get(key) ?? 0, amount));
  }
  if ([...amounts.values()].reduce((a, b) => a + b, 0) + 1 > 10)
    throw new Error("task budget exhausted");
}

export async function captureShape({
  root,
  packetPath,
  sourceCommit,
  coordinatorSend = false,
  getToken,
  send,
  clock = () => new Date(),
}) {
  if (!coordinatorSend) throw new Error("explicit coordinator send required");
  const lane = await realpath(join(root, "docs.local/runs/codex-lane8"));
  const packet = await realpath(packetPath);
  if (!packet.startsWith(`${lane}${sep}`))
    throw new Error("packet is outside the private lane directory");
  const packetStat = await lstat(packetPath);
  if (!packetStat.isFile() || packetStat.isSymbolicLink() || packetStat.mode & 0o077)
    throw new Error("packet must be a private regular file");
  const bytes = await readFile(packet);
  const plan = JSON.parse(bytes);
  const packetSha256 = sha256(bytes);
  if (
    plan.schemaVersion !== 1 ||
    plan.project !== PROJECT ||
    plan.maxRequests !== MAX_REQUESTS ||
    plan.reserveUsd !== 1 ||
    !/^[a-f0-9]{40}$/.test(plan.sourceCommit ?? "") ||
    sourceCommit !== plan.sourceCommit ||
    plan.harnessDigest !== (await harnessDigest())
  )
    throw new Error("packet source or runner binding differs");
  shapeRequests({ ...plan, now: clock().getTime() });
  if (typeof getToken !== "function") throw new Error("coordinator credential provider required");
  const runs = join(root, "docs.local/runs");
  const ledger = join(runs, "sandbox-ledger.jsonl");
  const lockDir = join(runs, "sandbox-locks");
  const guardPath = join(lockDir, `${PROJECT}.recovery-guard`);
  const guard = await lstat(guardPath);
  if (!guard.isFile() || guard.isSymbolicLink())
    throw new Error("foreign recovery guard is missing");
  const locks = await acquireProjectLocks({
    lockDir,
    legacyLock: `${ledger}.lock`,
    projects: [PROJECT],
    body: {
      taskId: TASK_ID,
      packetId: packetSha256,
      sourceCommit,
      pid: process.pid,
      acquiredAt: clock().toISOString(),
    },
  });
  let reserved = false;
  try {
    const ledgerText = await readFile(ledger, "utf8");
    const rows = ledgerText
      .split("\n")
      .filter((s) => s.trim())
      .map((s) => JSON.parse(s));
    if (
      !approved(await readFile(join(root, "docs.local/instructions/owner-decisions.md"), "utf8"), {
        ...plan,
        packetSha256,
      })
    )
      throw new Error("packet approval missing or revoked");
    const problems = admissionProblems(ledgerText, PROJECT, clock().getTime());
    if (problems.length) throw new Error(`sandbox admission refused: ${problems.join("; ")}`);
    if (
      rows.some(
        (r) =>
          r.taskId === TASK_ID && (r.packetSha256 === packetSha256 || r.attemptId === plan.runId),
      )
    )
      throw new Error("this packet or run already started");
    budget(rows);
    const directory = join(lane, `shape-${plan.runId}`);
    await mkdir(directory, { mode: 0o700 });
    const laneHandle = await open(lane, "r");
    try {
      await laneHandle.sync();
    } finally {
      await laneHandle.close();
    }
    await durable(join(directory, "packet.json"), plan);
    const common = {
      project: PROJECT,
      database: null,
      taskId: TASK_ID,
      gitSha: sourceCommit,
      corpusDigest: packetSha256,
      packetSha256,
      harnessDigest: plan.harnessDigest,
      attemptId: plan.runId,
      runDir: directory,
      estimatedUsd: 1,
    };
    // Any failure after the reservation leaves the lock and conservative budget charge.
    reserved = true;
    await durable(
      ledger,
      {
        ...common,
        ts: clock().toISOString(),
        event: "started",
        outcome: "reserved",
        requests: null,
      },
      "a",
    );
    let summary;
    try {
      const token = await getToken();
      summary = await collectShape({
        ...plan,
        accessToken: token,
        send,
        clock: () => clock().getTime(),
        save: (row) => durable(join(directory, "requests.jsonl"), row, "a"),
      });
    } catch {
      summary = { outcome: "shape-needs-review", cleanupVerified: false, captureError: true };
    }
    const afterGuard = await lstat(guardPath);
    summary.guardUnchanged =
      afterGuard.ino === guard.ino &&
      afterGuard.dev === guard.dev &&
      afterGuard.size === guard.size &&
      afterGuard.mtimeMs === guard.mtimeMs;
    summary.directory = directory;
    await durable(join(directory, "summary.json"), summary);
    await durable(
      ledger,
      {
        ...common,
        ts: clock().toISOString(),
        event: "needs-recovery",
        outcome: "shape-needs-review",
        requests: summary.attempted ?? null,
        sandboxAtBaseline: false,
      },
      "a",
    );
    return summary;
  } finally {
    if (!reserved) for (const lock of locks.toReversed()) await releaseProjectLock(lock);
  }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try {
    if (process.argv.length !== 4 || process.argv[3] !== "--coordinator-send")
      throw new Error("coordinator command required");
    const common = execFileSync(
      "git",
      ["rev-parse", "--path-format=absolute", "--git-common-dir"],
      { cwd: REPO, encoding: "utf8" },
    ).trim();
    const sourceCommit = execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: REPO,
      encoding: "utf8",
    }).trim();
    const summary = await captureShape({
      root: dirname(common),
      packetPath: process.argv[2],
      sourceCommit,
      coordinatorSend: true,
      getToken: async () =>
        execFileSync("gcloud", ["auth", "application-default", "print-access-token"], {
          encoding: "utf8",
          maxBuffer: 8192,
          timeout: 30000,
        }).trim(),
    });
    process.stdout.write(`${JSON.stringify(summary)}\n`);
    process.exitCode = 2; // Shape outcomes always require coordinator review before lock release.
  } catch {
    process.stderr.write(
      "Scheduled shape capture did not complete; inspect the private journal and lock.\n",
    );
    process.exitCode = 1;
  }
}
