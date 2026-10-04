// The sandbox protocol of the formal recording: what must hold in the shared ledger and the owner
// decisions before anything is sent, the project lock, and the ledger lines the run writes. Pure where
// it can be, so every rule is tested without a network. The coordinator writes the envelope (E) and
// version (V) lines; the recorder only reads them.

import { createHash } from "node:crypto";
import {
  appendFileSync,
  closeSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  statSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { join } from "node:path";

export const TASK_ID = "FUNCTIONS-EVENTS-SANDBOX";
export const PROJECT = "fireemu-oracle-events";
export const TASK_CAP_USD = 34;
export const RESERVE_USD = 4;
export const MAX_REQUESTS = 520;
export const CLI_MAX = 2;
export const SPACING_MINUTES = 30;
export const TOPIC = "FUNCTIONS-EVENTS formal";
export const ENVELOPE_TOPIC = `${TOPIC} envelope`;
const sha256 = (text) => createHash("sha256").update(text).digest("hex");

export function ledgerEntries(text) {
  const entries = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      const entry = JSON.parse(line);
      if (entry && typeof entry === "object") entries.push(entry);
    } catch {
      // a line that does not parse belongs to the lane that wrote it
    }
  }
  return entries;
}

const OPEN_EVENTS = new Set(["started", "needs-recovery"]);
/** A line that closes a run cleanly: the sandbox is at its baseline, or the run says it was prepared/recorded and kept no lock. */
const cleanClose = (row) =>
  !OPEN_EVENTS.has(row.event) &&
  row.sandboxAtBaseline !== false &&
  (row.sandboxAtBaseline === true ||
    row.event === "cleanup-verified" ||
    (["prepared", "recorded"].includes(row.outcome) && row.lockRetained === false));

/**
 * Why a run may not start on the events project now: no clean closing line to start from, a run of
 * any task left open after the latest one (a `started` or `needs-recovery` line with no later clean
 * closing line), the last line of the project in the last 30 minutes, or a line whose time cannot be read.
 */
export function ledgerProblems(ledgerText, now = Date.now()) {
  const problems = [];
  const rows = ledgerEntries(ledgerText).filter((row) => row.project === PROJECT);
  for (const row of rows) {
    if (!Number.isFinite(Date.parse(row.ts)))
      problems.push(
        `a line of ${row.taskId ?? "no task"} has an unreadable time ${JSON.stringify(row.ts)}`,
      );
  }
  // The baseline is the latest clean closing line of the project; only what follows it can be open.
  let anchor = -1;
  rows.forEach((row, index) => {
    if (cleanClose(row)) anchor = index;
  });
  if (anchor < 0) problems.push(`${PROJECT} has no clean closing line to start from`);
  const open = new Map();
  for (const row of rows.slice(anchor + 1)) {
    if (typeof row.taskId !== "string") continue;
    if (OPEN_EVENTS.has(row.event)) open.set(row.taskId, row);
    else if (cleanClose(row)) open.delete(row.taskId);
    else if (row.event === "finished") open.set(row.taskId, row);
  }
  for (const [task, row] of open)
    problems.push(`${task} has a run that did not end cleanly (${row.event} at ${row.ts})`);
  const last = rows
    .map((row) => Date.parse(row.ts))
    .filter(Number.isFinite)
    .toSorted((a, b) => b - a)[0];
  if (last !== undefined && now - last < SPACING_MINUTES * 60_000)
    problems.push(`the last line of ${PROJECT} is less than ${SPACING_MINUTES} minutes old`);
  return problems;
}

/** The task's estimated cost so far (each run once, at its highest estimate) plus this run's reserve must stay within the owner's cap. */
export function budgetProblems(ledgerText, { reserve = RESERVE_USD, cap = TASK_CAP_USD } = {}) {
  const byRun = new Map();
  for (const row of ledgerEntries(ledgerText)) {
    if (row.taskId !== TASK_ID) continue;
    const cost = row.estimatedUsd ?? 0;
    if (typeof cost !== "number" || !Number.isFinite(cost) || cost < 0)
      return [`a line of the task has a cost that is not a number: ${JSON.stringify(cost)}`];
    const key = row.runDir ?? `${row.ts}`;
    byRun.set(key, Math.max(byRun.get(key) ?? 0, cost));
  }
  const spent = [...byRun.values()].reduce((a, b) => a + b, 0);
  return spent + reserve > cap + 1e-9
    ? [
        `the task has used US$${spent.toFixed(2)}; this run's reserve US$${reserve.toFixed(2)} passes the cap of US$${cap}`,
      ]
    : [];
}

// ---- owner decisions ---------------------------------------------------------------------------

const DATE_LINE = /^- \d{4}-\d{2}-\d{2} \| /;
export function fields(text) {
  return Object.fromEntries(
    text
      .split(";")
      .map((part) => part.trim())
      .filter((part) => part.includes("="))
      .map((part) => [
        part.slice(0, part.indexOf("=")).trim(),
        part.slice(part.indexOf("=") + 1).trim(),
      ]),
  );
}
const number = (value) => (/^\d+(\.\d+)?$/.test(value ?? "") ? Number(value) : Number.NaN);
const decidedBy = (text) => text.startsWith("オーナー") || text.startsWith("Claude（委任");

/**
 * The approval of this exact version, or the reasons there is none. Two lines are needed:
 *   - D | FUNCTIONS-EVENTS formal envelope | envelopeId=…; project=…; maxRequests=…; cliMax=…; reserveUsd=…; retries=none; writes=…; onStop=… | (owner or delegated coordinator) | …
 *     (`writes` and `onStop` are for the reader of the line: the declared resources only, and the lock stays on needs-recovery)
 *   - D | FUNCTIONS-EVENTS formal | decision=APPROVE; envelopeId=…; packetSha256=…; harnessSha256=…; sourceCommit=… | (owner or delegated coordinator) | …
 * The envelope must cover this recorder's limits. A later line saying REVOKED withdraws the version
 * (by packet SHA) or the envelope (by its id).
 */
export function approval(ownerText, { packetSha256, harnessSha256, sourceCommit }) {
  const envelopes = new Map();
  let version;
  for (const raw of ownerText.split("\n")) {
    const line = raw.trim();
    if (!DATE_LINE.test(line)) continue;
    const [, topic = "", body = "", decider = ""] = line
      .slice(2)
      .split(" | ")
      .map((c) => c.trim());
    if (topic !== TOPIC && topic !== ENVELOPE_TOPIC && !topic.startsWith(`${TOPIC} `)) continue;
    if (/\bREVOKED\b/i.test(body)) {
      if (body.includes(packetSha256)) version = undefined;
      const id = /\benvelopeId=([A-Za-z0-9_-]+)/.exec(body)?.[1];
      if (id) {
        envelopes.delete(id);
        if (version?.envelopeId === id) version = undefined;
      }
      continue;
    }
    if (!decidedBy(decider)) continue;
    const entry = fields(body);
    if (topic === ENVELOPE_TOPIC && entry.envelopeId) envelopes.set(entry.envelopeId, entry);
    else if (
      topic === TOPIC &&
      entry.decision === "APPROVE" &&
      entry.packetSha256 === packetSha256 &&
      entry.harnessSha256 === harnessSha256 &&
      entry.sourceCommit === sourceCommit
    )
      version = { ...entry, line };
  }
  if (!version)
    return { problems: ["no approval line for this packet, harness and source commit"] };
  const envelope = envelopes.get(version.envelopeId);
  if (!envelope)
    return {
      problems: [
        `the approval names envelope ${version.envelopeId}, which has no (or a revoked) envelope line`,
      ],
    };
  const problems = [];
  if (envelope.project !== PROJECT) problems.push("the envelope names another project");
  if (!(number(envelope.maxRequests) >= MAX_REQUESTS))
    problems.push(`the envelope allows fewer than ${MAX_REQUESTS} requests`);
  if (!(number(envelope.cliMax) >= CLI_MAX))
    problems.push(`the envelope allows fewer than ${CLI_MAX} CLI runs`);
  if (envelope.retries !== "none") problems.push("the envelope does not say retries=none");
  if (!(number(envelope.reserveUsd) >= RESERVE_USD))
    problems.push(`the envelope reserves less than US$${RESERVE_USD}`);
  return problems.length
    ? { problems }
    : { approval: { envelopeId: version.envelopeId, line: version.line }, problems: [] };
}

/** An approval is used once: a run of the same packet that already started refuses a second start. */
export function packetUsed(ledgerText, packetSha256) {
  return ledgerEntries(ledgerText).some(
    (row) => row.taskId === TASK_ID && row.event === "started" && row.packetSha256 === packetSha256,
  );
}

// ---- the project lock --------------------------------------------------------------------------

export function acquireLock({ lockDir, legacyLock, body }) {
  try {
    lstatSync(legacyLock);
    throw new Error("the legacy shared lock is held; not starting");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  mkdirSync(lockDir, { recursive: true, mode: 0o700 });
  if (statSync(lockDir).mode & 0o077) throw new Error(`${lockDir} is not private (mode 700)`);
  const path = join(lockDir, `${PROJECT}.lock`);
  let fd;
  try {
    fd = openSync(path, "wx", 0o600);
  } catch (error) {
    if (error.code === "EEXIST")
      throw new Error(`the lock of ${PROJECT} is held; not starting`, { cause: error });
    throw error;
  }
  const text = JSON.stringify(body);
  try {
    writeSync(fd, text);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  return { path, inode: lstatSync(path).ino, sha256: sha256(text) };
}

/** Removes the lock only while it is still this run's file (same inode, same body). */
export function releaseLock(lock) {
  const found = lstatSync(lock.path);
  if (!found.isFile() || found.isSymbolicLink() || found.ino !== lock.inode)
    throw new Error("the lock was replaced; left in place");
  if (sha256(readFileSync(lock.path, "utf8")) !== lock.sha256)
    throw new Error("the lock was rewritten; left in place");
  unlinkSync(lock.path);
}

// ---- ledger lines ------------------------------------------------------------------------------

export function startedLine({
  ts,
  runDir,
  packetSha256,
  harnessSha256,
  gitSha,
  approval: approved,
  lock,
}) {
  return {
    ts,
    event: "started",
    taskId: TASK_ID,
    project: PROJECT,
    database: "(default)",
    phase: "formal-record",
    runDir,
    packetSha256,
    harnessSha256,
    gitSha,
    envelopeId: approved.envelopeId,
    maxRequests: MAX_REQUESTS,
    cliMax: CLI_MAX,
    estimatedUsd: RESERVE_USD,
    lockSha256: lock.sha256,
  };
}

/** The closing line; the lock stays when the outcome is needs-recovery. */
export function finishedLine({
  ts,
  runDir,
  packetSha256,
  gitSha,
  outcome,
  requests,
  cliAttempts,
  lockRetained,
}) {
  return {
    ts,
    event: "finished",
    taskId: TASK_ID,
    project: PROJECT,
    database: "(default)",
    phase: "formal-record",
    runDir,
    packetSha256,
    gitSha,
    outcome,
    requests,
    cliAttempts,
    estimatedUsd: RESERVE_USD,
    lockRetained,
  };
}

export function appendLedger(path, row) {
  appendFileSync(path, `${JSON.stringify(row)}\n`, { mode: 0o600, flag: "a" });
}
