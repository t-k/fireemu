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
  realpathSync,
  statSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { isAbsolute, join, relative } from "node:path";

export const TASK_ID = "FUNCTIONS-EVENTS-SANDBOX";
export const PROJECT = "fireemu-oracle-events";
// The task cap: US$34 until owner ledger 843 (US$40), then US$50 by the owner ledger line 856 (v6's three failed Gen1 Storage triggers
// made the one-at-a-time v7 necessary): the counted 36.60 plus the v7 reserve of 4.00 is 40.60.
export const TASK_CAP_USD = 50;
export const RESERVE_USD = 4;
export const MAX_REQUESTS = 520;
// Seven CLI runs (v7): the dry run of the 22, the main deploy of 18, one deploy for each of the four Gen1 Storage functions, the delete.
export const CLI_MAX = 7;
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

const isCount = (value) => Number.isInteger(value) && value >= 0;
const time = (row) => Date.parse(row.ts);

/**
 * What a run's transport journal says about what was sent, or undefined when it cannot be trusted:
 * a line that does not parse, a state or a kind we do not know, a repeated or orphaned sequence number.
 * `mutating` counts every send whose `mutation` flag is not exactly false; `unknown` counts every send
 * with no answer and every answer that is not a success or a refusal.
 */
export function journalFacts(text) {
  const sends = new Map();
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    let entry;
    try {
      entry = JSON.parse(line);
    } catch {
      return undefined;
    }
    if (!entry || typeof entry !== "object" || !Number.isInteger(entry.seq)) return undefined;
    if (entry.state === "before-send") {
      if (sends.has(entry.seq)) return undefined;
      sends.set(entry.seq, { mutation: entry.mutation, kind: undefined });
    } else if (entry.state === "response-persisted") {
      const send = sends.get(entry.seq);
      if (!send || send.kind !== undefined || typeof entry.kind !== "string") return undefined;
      send.kind = entry.kind;
    } else return undefined;
  }
  let mutating = 0;
  let unknown = 0;
  for (const send of sends.values()) {
    if (send.mutation !== false) mutating += 1;
    if (send.kind !== "success" && send.kind !== "refusal") unknown += 1;
  }
  return { sent: sends.size, mutating, unknown };
}

/**
 * Whether the rows of one run (all lines of the project that name its run directory) show a run that
 * wrote nothing and left nothing behind, so the next run need not wait out the spacing. Every condition
 * must hold; anything missing or unreadable is a no:
 *   - exactly three lines: `started`, `finished`, `cleanup-verified`, of this task, in that time order;
 *   - the closing line says `stopped-clean`, no lock kept, no CLI attempt of any kind (deploy, delete, dry run), a request count;
 *   - the close line says the sandbox is at its baseline, no unknown answers, the same request count;
 *   - the run's own journal agrees: that many sends, none of them mutating, none without a usable answer.
 */
function writesNothing(rows, readJournal) {
  if (typeof readJournal !== "function" || rows.length !== 3) return false;
  const [started, finished, closed] = ["started", "finished", "cleanup-verified"].map((event) =>
    rows.find((row) => row.event === event),
  );
  if (!started || !finished || !closed) return false;
  if (!rows.every((row) => row.taskId === TASK_ID)) return false;
  const [t0, t1, t2] = [started, finished, closed].map(time);
  if (!(Number.isFinite(t0) && Number.isFinite(t1) && Number.isFinite(t2) && t0 <= t1 && t1 <= t2))
    return false;
  const cli = finished.cliAttempts;
  if (finished.outcome !== "stopped-clean" || finished.lockRetained !== false) return false;
  // every CLI attempt counts, the dry run too (a run before it had only `deploy` and `delete`)
  if (!cli || cli.deploy !== 0 || cli.delete !== 0 || !isCount(finished.requests)) return false;
  if (Object.values(cli).some((attempts) => attempts !== 0)) return false;
  if (closed.sandboxAtBaseline !== true || closed.unknownAnswers !== 0) return false;
  if (closed.requests !== finished.requests) return false;
  let facts;
  try {
    const text = readJournal(started.runDir);
    facts = typeof text === "string" ? journalFacts(text) : undefined;
  } catch {
    return false;
  }
  return facts?.mutating === 0 && facts.unknown === 0 && facts.sent === finished.requests;
}

/** The lines that belong to a run that wrote nothing (see `writesNothing`); they do not hold the spacing. */
function spacingExempt(rows, readJournal) {
  const byRun = new Map();
  for (const row of rows) {
    if (typeof row.runDir !== "string" || row.runDir === "") continue;
    byRun.set(row.runDir, [...(byRun.get(row.runDir) ?? []), row]);
  }
  const exempt = new Set();
  for (const group of byRun.values())
    if (writesNothing(group, readJournal)) for (const row of group) exempt.add(row);
  return exempt;
}

/**
 * Why a run may not start on the events project now: no clean closing line to start from, a run of
 * any task left open after the latest one (a `started` or `needs-recovery` line with no later clean
 * closing line), the last line of the project in the last 30 minutes, or a line whose time cannot be read.
 * The spacing runs from the latest line that does not belong to a run that wrote nothing: such a run
 * (`readJournal(runDir)` returns its transport journal) leaves the project as it was and does not hold it.
 * Without a journal reader every run holds the spacing.
 */
export function ledgerProblems(ledgerText, now = Date.now(), { readJournal } = {}) {
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
  const exempt = spacingExempt(rows, readJournal);
  const last = rows
    .filter((row) => !exempt.has(row))
    .map(time)
    .filter(Number.isFinite)
    .toSorted((a, b) => b - a)[0];
  if (last !== undefined && now - last < SPACING_MINUTES * 60_000)
    problems.push(`the last line of ${PROJECT} is less than ${SPACING_MINUTES} minutes old`);
  return problems;
}

const isCost = (value) => typeof value === "number" && Number.isFinite(value) && value >= 0;

/**
 * The task's estimated cost so far plus this run's reserve must stay within the owner's cap (ledger 776).
 * Each run counts once. A run counts at its highest estimate (the reserve its `started` line books) unless the
 * coordinator closed it with a `cleanup-verified` line of the task: then that line's `estimatedUsd` is the run's
 * actual cost (owner ledger 823). Fail closed: a cost that is not a number (a close line with no cost included),
 * two close lines of one run with different costs, and a run with no close line (it stays at its reserve).
 */
export function budgetProblems(ledgerText, { reserve = RESERVE_USD, cap = TASK_CAP_USD } = {}) {
  const byRun = new Map();
  for (const row of ledgerEntries(ledgerText)) {
    if (row.taskId !== TASK_ID) continue;
    const closing =
      row.event === "cleanup-verified" && typeof row.runDir === "string" && row.runDir !== "";
    const cost = closing ? row.estimatedUsd : (row.estimatedUsd ?? 0);
    if (!isCost(cost))
      return [`a line of the task has a cost that is not a number: ${JSON.stringify(cost)}`];
    const key = row.runDir ?? `${row.ts}`;
    const run = byRun.get(key) ?? { highest: 0, closes: [] };
    run.highest = Math.max(run.highest, cost);
    if (closing) run.closes.push(cost);
    byRun.set(key, run);
  }
  let spent = 0;
  for (const [key, run] of byRun) {
    if (run.closes.some((cost) => cost !== run.closes[0]))
      return [`the run ${JSON.stringify(key)} has close lines with different costs`];
    spent += run.closes.length > 0 ? run.closes[0] : run.highest;
  }
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

/**
 * The transport journal of a run directory under `runsDir`, for the spacing check. Throws for a run
 * directory outside `runsDir`, a journal that is not a plain file, or one that cannot be read.
 */
export function readRunJournal(runsDir, runDir) {
  const base = realpathSync(runsDir);
  const dir = realpathSync(runDir);
  const rel = relative(base, dir);
  if (rel === "" || rel.startsWith("..") || isAbsolute(rel))
    throw new Error("the run directory is outside the runs directory");
  const path = join(dir, "transport", "journal.jsonl");
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("the journal is not a plain file");
  return readFileSync(path, "utf8");
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
