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

const MODES = Object.freeze({
  shape: {
    kind: undefined,
    subject: "SCHEDULED-FUNCTIONS stage-2 shape packet",
    maxRequests: MAX_REQUESTS,
    reserveUsd: 1,
    prefix: "shape-",
    outcome: "shape-needs-review",
    collect: collectShape,
  },
  "job-recovery": {
    kind: "job-recovery",
    subject: "SCHEDULED-FUNCTIONS stage-2 job recovery packet",
    maxRequests: RECOVERY_MAX_REQUESTS,
    reserveUsd: 0.25,
    prefix: "recovery-",
    outcome: "recovery-needs-review",
    collect: collectRecovery,
  },
  "calendar-seed": {
    kind: "calendar-seed",
    subject: "SCHEDULED-FUNCTIONS calendar seed packet",
    maxRequests: 64,
    reserveUsd: 0.25,
    prefix: "calendar-",
    outcome: "calendar-needs-review",
    collect: async (options) => (await import("./calendar.mjs")).collectCalendar(options),
  },
  "calendar-recovery": {
    kind: "calendar-recovery",
    subject: "SCHEDULED-FUNCTIONS calendar recovery packet",
    maxRequests: 64,
    reserveUsd: 0.25,
    prefix: "calendar-recovery-",
    outcome: "calendar-recovery-needs-review",
    collect: async (options) =>
      (await import("./calendar-recovery.mjs")).collectCalendarRecovery(options),
  },
});

export async function harnessDigest(mode = "shape") {
  if (!Object.hasOwn(MODES, mode)) throw new Error("unknown capture mode");
  const hash = createHash("sha256");
  const sources = mode.startsWith("calendar-")
    ? [
        ...SOURCES,
        "conformance/scheduled-functions/calendar.mjs",
        "conformance/scheduled-functions/calendar-recovery.mjs",
        "conformance/scheduled-functions/calendar-cases.json",
        "conformance/scheduled-functions/calendar-settled-topic.mjs",
      ]
    : SOURCES;
  for (const path of sources)
    hash
      .update(path)
      .update("\0")
      .update(await readFile(join(REPO, path)))
      .update("\0");
  return hash.digest("hex");
}

async function durable(path, value, flags = "wx", raw = false) {
  const handle = await open(path, flags, 0o600);
  try {
    await handle.writeFile(raw ? value : `${JSON.stringify(value)}\n`);
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

async function privateProof(path, lane) {
  const stat = await lstat(path),
    resolved = await realpath(path);
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.mode & 0o077 ||
    !resolved.startsWith(lane + sep)
  )
    throw new Error("original recovery proof must be a private regular lane file");
  return readFile(path);
}

function approved(ownerText, pins, mode = "shape") {
  const config = MODES[mode],
    recovery = mode === "job-recovery" || mode === "calendar-recovery",
    calendar = mode.startsWith("calendar-");
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
      subject === config.subject &&
      entry.decision === "APPROVE" &&
      /^(オーナー|Claude|調整役)/.test(author) &&
      entry.sourceCommit === pins.sourceCommit &&
      entry.harnessDigest === pins.harnessDigest &&
      entry.maxRequests === String(config.maxRequests) &&
      entry.reserveUsd === String(config.reserveUsd) &&
      (!calendar || entry.corpusDigest === pins.corpusDigest) &&
      (mode !== "calendar-seed" || entry.maxExtraRequests === "3") &&
      (mode !== "calendar-recovery" || entry.maxDeleteAttemptsPerJob === "3") &&
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

async function recoveryAdmission({ plan, rows, ledgerText, lane, now, mode = "job-recovery" }) {
  const calendar = mode === "calendar-recovery";
  const target = (row) =>
    row.project === PROJECT && row.taskId === TASK_ID && row.attemptId === plan.originalRunId;
  const lines = ledgerText.split("\n").filter((line) => line.trim());
  const index = rows.findLastIndex(target);
  const original = rows[index];
  if (
    !original ||
    original.packetSha256 !== plan.originalPacketSha256 ||
    rows.some(
      (row) =>
        target(row) &&
        row.packetSha256 !== undefined &&
        row.packetSha256 !== plan.originalPacketSha256,
    ) ||
    sha256(lines[index]) !== plan.originalLedgerRowSha256 ||
    original.event !== "needs-recovery" ||
    original.outcome !== (calendar ? "calendar-needs-review" : "shape-needs-review") ||
    original.sandboxAtBaseline !== false ||
    original.requests !== (calendar ? plan.originalRequests : 32) ||
    (calendar &&
      (original.kind !== "calendar-seed" ||
        original.gitSha !== plan.originalSourceCommit ||
        original.harnessDigest !== plan.originalHarnessDigest ||
        original.corpusDigest !== plan.originalCorpusDigest))
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
  const originalDirectory = join(lane, (calendar ? "calendar-" : "shape-") + plan.originalRunId);
  const journal = calendar
    ? await privateProof(join(originalDirectory, "requests.jsonl"), lane)
    : await readFile(join(originalDirectory, "requests.jsonl"));
  if (sha256(journal) !== plan.originalJournalSha256)
    throw new Error("original recovery journal differs");
  if (calendar) {
    const rawPacket = await privateProof(join(originalDirectory, "raw-packet.json"), lane);
    if (sha256(rawPacket) !== plan.originalPacketSha256)
      throw new Error("original recovery packet differs");
    const originalPacket = JSON.parse(rawPacket);
    if (
      originalPacket.schemaVersion !== 1 ||
      originalPacket.kind !== "calendar-seed" ||
      originalPacket.project !== PROJECT ||
      originalPacket.runId !== plan.originalRunId ||
      originalPacket.sourceCommit !== plan.originalSourceCommit ||
      originalPacket.harnessDigest !== plan.originalHarnessDigest ||
      originalPacket.corpusDigest !== plan.originalCorpusDigest ||
      originalPacket.maxRequests !== 64 ||
      originalPacket.maxExtraRequests !== 3 ||
      originalPacket.reserveUsd !== 0.25
    )
      throw new Error("original recovery packet binding differs");
    const journalRows = journal
      .toString("utf8")
      .split("\n")
      .filter((line) => line.trim())
      .map((line) => JSON.parse(line));
    const before = journalRows.filter((row) => row.state === "before-send");
    if (
      before.length !== plan.originalRequests ||
      new Set(before.map((row) => row.id)).size !== before.length
    )
      throw new Error("original recovery journal request count differs");
    const templates = new Map(
      (await import("./calendar.mjs"))
        .calendarRequests(
          plan.originalRunId,
          originalPacket.projectNumber,
          before.length ? Date.parse(before[0].dispatchAt) : then,
        )
        .map((spec) => [spec.id, spec]),
    );
    let extras = 0;
    const sent = new Set();
    for (const row of journalRows) {
      if (
        !row ||
        typeof row.id !== "string" ||
        ![
          "before-send",
          "response-headers",
          "response-persisted",
          "transport-unknown",
          "body-unknown",
        ].includes(row.state)
      )
        throw new Error("original recovery journal row differs");
      if (row.state !== "before-send") {
        if (!sent.has(row.id)) throw new Error("original recovery journal ordering differs");
        continue;
      }
      sent.add(row.id);
      let id = row.id;
      if (/^read-topic-poll-[1-3]$/.test(id)) {
        id = "read-topic";
        extras++;
      } else if (/^c0[1-8]-read-before-pause$/.test(id)) {
        id = id.slice(0, 3) + "-read-paused";
        extras++;
      } else if (/^c0[1-8]-delete-retry-[1-3]$/.test(id)) {
        id = id.slice(0, 3) + "-delete";
        extras++;
      }
      const spec = templates.get(id);
      if (
        !spec ||
        row.method !== spec.method ||
        row.url !== spec.url ||
        (row.timeoutMs !== undefined && row.timeoutMs !== (spec.timeoutMs ?? 10000)) ||
        !Number.isFinite(Date.parse(row.dispatchAt)) ||
        JSON.stringify(row.json ?? null) !== JSON.stringify(spec.json ?? null)
      )
        throw new Error("original recovery journal request binding differs");
    }
    if (extras > 3) throw new Error("original recovery journal extra-request budget differs");
    if (plan.recoveryScope === "settled-jobs-topic-only") {
      (await import("./calendar-settled-topic.mjs")).proveSettledCalendarJobs(
        journalRows,
        originalPacket,
      );
      if (Date.parse(journalRows.at(-1).responseAt) > then)
        throw new Error("original recovery end-row time differs");
    }
    if (
      plan.recoveryScope === "topic-only" &&
      (!before.some((r) => r.id === "create-topic") ||
        before.some(
          (r) => r.method !== "GET" && r.id !== "create-topic" && r.id !== "delete-topic",
        ))
    )
      throw new Error("topic-only original scope has no topic intent or a job mutation");
  }
  return projectAdmissionProblems(
    rows.filter((row) => !target(row)),
    now,
  );
}

function projectAdmissionProblems(rows, now) {
  const problems = admissionProblems(rows.map(JSON.stringify).join("\n"), PROJECT, now);
  // The shared helper groups by task. Also check each other attempt independently.
  const attempts = new Map();
  for (const row of rows) {
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
  mode = "shape",
) {
  if (!Object.hasOwn(MODES, mode)) throw new Error("unknown capture mode");
  const config = MODES[mode],
    recovery = mode === "job-recovery" || mode === "calendar-recovery",
    calendar = mode.startsWith("calendar-");
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
    plan.maxRequests !== config.maxRequests ||
    plan.reserveUsd !== config.reserveUsd ||
    plan.kind !== config.kind ||
    !/^[a-f0-9]{40}$/.test(plan.sourceCommit ?? "") ||
    sourceCommit !== plan.sourceCommit ||
    plan.harnessDigest !== (await harnessDigest(mode))
  )
    throw new Error("packet source or runner binding differs");
  if (
    calendar &&
    (plan.corpusDigest !== (await calendarCorpusDigest()) ||
      (mode === "calendar-seed" && plan.maxExtraRequests !== 3) ||
      (mode === "calendar-recovery" && plan.maxDeleteAttemptsPerJob !== 3))
  )
    throw new Error("calendar corpus or packet binding differs");
  if (
    plan.recoveryScope !== undefined &&
    (mode !== "calendar-recovery" ||
      !["topic-only", "settled-jobs-topic-only"].includes(plan.recoveryScope))
  )
    throw new Error("invalid calendar recovery scope");
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
  } else if (calendar)
    (await import("./calendar.mjs")).calendarRequests(
      plan.runId,
      plan.projectNumber,
      clock().getTime(),
    );
  else shapeRequests({ ...plan, now: clock().getTime() });
  if (
    mode === "calendar-recovery" &&
    (!Number.isSafeInteger(plan.originalRequests) ||
      plan.originalRequests < 0 ||
      plan.originalRequests > 64 ||
      !/^[a-f0-9]{40}$/.test(plan.originalSourceCommit ?? "") ||
      ![plan.originalHarnessDigest, plan.originalCorpusDigest].every((pin) =>
        /^[a-f0-9]{64}$/.test(pin ?? ""),
      ) ||
      plan.originalCorpusDigest !== plan.corpusDigest)
  )
    throw new Error("original calendar recovery binding differs");
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
        mode,
      )
    )
      throw new Error("packet approval missing or revoked");
    const problems = recovery
      ? await recoveryAdmission({ plan, rows, ledgerText, lane, now: clock().getTime(), mode })
      : projectAdmissionProblems(rows, clock().getTime());
    if (problems.length) throw new Error(`sandbox admission refused: ${problems.join("; ")}`);
    if (
      rows.some(
        (r) =>
          r.taskId === TASK_ID && (r.packetSha256 === packetSha256 || r.attemptId === plan.runId),
      )
    )
      throw new Error("this packet or run already started");
    budget(rows, plan.reserveUsd);
    const directory = join(lane, config.prefix + plan.runId);
    await mkdir(directory, { mode: 0o700 });
    const laneHandle = await open(lane, "r");
    try {
      await laneHandle.sync();
    } finally {
      await laneHandle.close();
    }
    await durable(join(directory, "packet.json"), plan);
    if (calendar) await durable(join(directory, "raw-packet.json"), bytes, "wx", true);
    const common = {
      project: PROJECT,
      database: null,
      taskId: TASK_ID,
      gitSha: sourceCommit,
      corpusDigest: calendar ? plan.corpusDigest : packetSha256,
      ...(calendar ? { kind: config.kind } : {}),
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
      summary = await config.collect({
        ...plan,
        accessToken: token,
        send,
        sleep,
        clock: () => clock().getTime(),
        save: (row) => durable(join(directory, "requests.jsonl"), row, "a"),
      });
    } catch {
      summary = {
        outcome: config.outcome,
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
        outcome: config.outcome,
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
    const executors = {
      "--coordinator-send": captureShape,
      "--coordinator-recover": captureRecovery,
      "--coordinator-calendar": captureCalendar,
      "--coordinator-calendar-recover": captureCalendarRecovery,
    };
    if (process.argv.length !== 4 || !Object.hasOwn(executors, process.argv[3]))
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
    const summary = await executors[process.argv[3]]({
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
    process.exitCode = 2; // Every mode requires coordinator review before lock release.
  } catch {
    process.stderr.write(
      "Scheduled capture did not complete; inspect the private journal and lock.\n",
    );
    process.exitCode = 1;
  }
}

export async function captureShape(options) {
  return captureAttempt(options);
}

export async function captureRecovery(options) {
  return captureAttempt(options, "job-recovery");
}

export async function calendarCorpusDigest() {
  return sha256(await readFile(join(REPO, "conformance/scheduled-functions/calendar-cases.json")));
}

export async function captureCalendar(options) {
  return captureAttempt(options, "calendar-seed");
}
export async function captureCalendarRecovery(options) {
  return captureAttempt(options, "calendar-recovery");
}
