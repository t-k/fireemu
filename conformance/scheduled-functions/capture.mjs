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
import { collectShape, PROJECT, MAX_REQUESTS, shapeRequests, ownedResources } from "./shape.mjs";
import { collectRecovery, RECOVERY_MAX_REQUESTS } from "./recovery.mjs";

const REPO = fileURLToPath(new URL("../../", import.meta.url));
const TASK_ID = "SCHEDULED-FUNCTIONS";
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const SOURCES = [
  "conformance/scheduled-functions/shape.mjs",
  "conformance/scheduled-functions/capture.mjs",
  "conformance/scheduled-functions/recovery.mjs",
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

function approved(ownerText, pins, recovery = false) {
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
      subject ===
        (recovery
          ? "SCHEDULED-FUNCTIONS stage-2 job recovery packet"
          : "SCHEDULED-FUNCTIONS stage-2 shape packet") &&
      entry.decision === "APPROVE" &&
      /^(オーナー|Claude|調整役)/.test(author) &&
      entry.sourceCommit === pins.sourceCommit &&
      entry.harnessDigest === pins.harnessDigest &&
      entry.maxRequests === String(recovery ? RECOVERY_MAX_REQUESTS : MAX_REQUESTS) &&
      entry.reserveUsd === String(recovery ? 0.25 : 1) &&
      (!recovery ||
        (entry.originalRunId === pins.originalRunId &&
          entry.originalPacketSha256 === pins.originalPacketSha256))
    )
      approval = true;
  }
  return approval;
}

function budget(rows, reserveUsd = 1) {
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
  if ([...amounts.values()].reduce((a, b) => a + b, 0) + reserveUsd > 10)
    throw new Error("task budget exhausted");
}

async function recoveryAdmission({ plan, rows, ledgerText, lane, now }) {
  const target = (row) =>
    row.project === PROJECT &&
    row.taskId === TASK_ID &&
    row.attemptId === plan.originalRunId &&
    row.packetSha256 === plan.originalPacketSha256;
  const lines = ledgerText.split("\n").filter((line) => line.trim());
  const index = rows.findLastIndex(target);
  const original = rows[index];
  if (
    !original ||
    sha256(lines[index]) !== plan.originalLedgerRowSha256 ||
    original.event !== "needs-recovery" ||
    original.outcome !== "shape-needs-review" ||
    original.sandboxAtBaseline !== false ||
    original.requests !== 32
  )
    throw new Error("original recovery ledger proof differs");
  const then = Date.parse(original.ts);
  if (!Number.isFinite(then) || !Number.isFinite(now) || now - then < 30 * 60000)
    throw new Error("recovery must keep the 30-minute spacing");
  if (
    rows.some(
      (row) =>
        row.project === PROJECT &&
        (!Number.isFinite(Date.parse(row.ts)) || Date.parse(row.ts) > then),
    )
  )
    throw new Error("newer or unreadable sandbox activity blocks recovery");
  const journal = await readFile(join(lane, "shape-" + plan.originalRunId, "requests.jsonl"));
  if (sha256(journal) !== plan.originalJournalSha256)
    throw new Error("original recovery journal differs");
  const remaining = rows.filter((row) => !target(row));
  const problems = admissionProblems(remaining.map(JSON.stringify).join("\n"), PROJECT, now);
  // The shared helper groups by task. Also check each other attempt independently.
  const attempts = new Map();
  for (const row of remaining) {
    if (row.project !== PROJECT || typeof row.taskId !== "string") continue;
    const key = row.taskId + "|" + (row.attemptId ?? "unlinked");
    const group = attempts.get(key) ?? [];
    group.push(
      row.event === undefined && row.outcome === "reserved" ? { ...row, event: "started" } : row,
    );
    attempts.set(key, group);
  }
  for (const group of attempts.values())
    problems.push(...admissionProblems(group.map(JSON.stringify).join("\n"), PROJECT, now));
  return problems;
}

async function captureAttempt(
  {
    root,
    packetPath,
    sourceCommit,
    coordinatorSend = false,
    getToken,
    send,
    clock = () => new Date(),
    sleep,
  },
  recovery = false,
) {
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
    plan.maxRequests !== (recovery ? RECOVERY_MAX_REQUESTS : MAX_REQUESTS) ||
    plan.reserveUsd !== (recovery ? 0.25 : 1) ||
    (recovery ? plan.kind !== "job-recovery" : plan.kind !== undefined) ||
    !/^[a-f0-9]{40}$/.test(plan.sourceCommit ?? "") ||
    sourceCommit !== plan.sourceCommit ||
    plan.harnessDigest !== (await harnessDigest())
  )
    throw new Error("packet source or runner binding differs");
  if (recovery) {
    ownedResources(plan.originalRunId);
    ownedResources(plan.runId);
    if (
      plan.originalRunId === plan.runId ||
      ![plan.originalPacketSha256, plan.originalLedgerRowSha256, plan.originalJournalSha256].every(
        (v) => /^[a-f0-9]{64}$/.test(v ?? ""),
      )
    )
      throw new Error("invalid original recovery proof");
  } else shapeRequests({ ...plan, now: clock().getTime() });
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
      !approved(
        await readFile(join(root, "docs.local/instructions/owner-decisions.md"), "utf8"),
        {
          ...plan,
          packetSha256,
        },
        recovery,
      )
    )
      throw new Error("packet approval missing or revoked");
    const problems = recovery
      ? await recoveryAdmission({ plan, rows, ledgerText, lane, now: clock().getTime() })
      : admissionProblems(ledgerText, PROJECT, clock().getTime());
    if (problems.length) throw new Error(`sandbox admission refused: ${problems.join("; ")}`);
    if (
      rows.some(
        (r) =>
          r.taskId === TASK_ID && (r.packetSha256 === packetSha256 || r.attemptId === plan.runId),
      )
    )
      throw new Error("this packet or run already started");
    budget(rows, plan.reserveUsd);
    const directory = join(lane, (recovery ? "recovery-" : "shape-") + plan.runId);
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
      estimatedUsd: plan.reserveUsd,
      ...(recovery
        ? { originalAttemptId: plan.originalRunId, originalPacketSha256: plan.originalPacketSha256 }
        : {}),
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
      summary = await (recovery ? collectRecovery : collectShape)({
        ...plan,
        accessToken: token,
        send,
        sleep,
        clock: () => clock().getTime(),
        save: (row) => durable(join(directory, "requests.jsonl"), row, "a"),
      });
    } catch {
      summary = {
        outcome: recovery ? "recovery-needs-review" : "shape-needs-review",
        cleanupVerified: false,
        captureError: true,
      };
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
        outcome: recovery ? "recovery-needs-review" : "shape-needs-review",
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
    if (
      process.argv.length !== 4 ||
      !["--coordinator-send", "--coordinator-recover"].includes(process.argv[3])
    )
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
    const summary = await (
      process.argv[3] === "--coordinator-recover" ? captureRecovery : captureShape
    )({
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

export async function captureShape(options) {
  return captureAttempt(options);
}

export async function captureRecovery(options) {
  return captureAttempt(options, true);
}
