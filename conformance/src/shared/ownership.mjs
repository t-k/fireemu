// Recorder ownership: which names this run created, which it may delete, and which outcomes are
// still unknown. Functions over a small state object; no framework and no transport code. The
// caller sends the requests and reports what happened. See ownership.README.md for the contract.
//
// Three rules, and nothing else:
//   1. Issued names: every create or delete intent is a JSONL row, fsynced before the request is
//      sent, and its answer is a second row, fsynced after the answer.
//   2. Delete guard: a name may be deleted only if this run's own create of it answered 2xx, or
//      answered unknown and a later direct GET showed the name.
//   3. Unknown answers: a transport error, an unreadable body, a status below 200, a 3xx, a 5xx,
//      a 408, a 499 or a pending operation on a create or delete is unknown. An unknown create is
//      settled only by a direct GET whose body shows the name; a GET that finds nothing never
//      settles it, however late, and the name stays in the report for the coordinator. An unknown
//      delete is settled in this run only by such a GET, or by a GET that finds nothing once the
//      A2 delay has passed, and it keeps closureReady false either way.

import {
  closeSync,
  fsyncSync,
  ftruncateSync,
  openSync,
  readFileSync,
  unlinkSync,
  writeSync,
  existsSync,
} from "node:fs";
import { dirname } from "node:path";

export const LEDGER_VERSION = 1;

/**
 * The A2 read-back delay (10 minutes): how long after an unknown answer a GET that finds nothing
 * counts as late. It is the default and the floor of the setting recorded in the ledger.
 */
export const SETTLE_ABSENT_AFTER_MS = 10 * 60 * 1000;

/** The answer classes of a create or delete. */
export const ANSWER_CLASSES = Object.freeze(["ok", "conflict", "notFound", "refused", "unknown"]);

export class OwnershipError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "OwnershipError";
    this.code = code;
  }
}

const NAME_LIMIT = 1024;
const TRANSPORT = /^[a-z0-9][a-z0-9._-]{0,31}$/u;

function hasControl(text) {
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

function checkName(name) {
  if (
    typeof name !== "string" ||
    name.length === 0 ||
    name.length > NAME_LIMIT ||
    hasControl(name)
  ) {
    throw new OwnershipError(
      "bad-name",
      "a name is a non-empty string of at most 1024 characters without control characters",
    );
  }
}

function checkTransport(transport) {
  if (typeof transport !== "string" || !TRANSPORT.test(transport)) {
    throw new OwnershipError(
      "bad-transport",
      "a transport is a short lowercase label such as rest, grpc, cli or sdk",
    );
  }
}

/**
 * Classifies the answer to a create or a delete. `answer` is what the caller observed:
 * `{ status, bodyReadable, transportError, operationPending }`. A body counts as readable only when
 * the caller says so with `bodyReadable: true` (an empty body is readable). `operationPending: true`
 * says the request returned a long-running operation that is not read as done: the effect on the
 * name is unknown.
 */
export function classifyAnswer(answer) {
  if (answer === null || typeof answer !== "object") {
    throw new OwnershipError("bad-answer", "an answer is an object");
  }
  const { status, bodyReadable, transportError, operationPending } = answer;
  const unknown = (reason) => ({
    class: "unknown",
    status: Number.isInteger(status) ? status : null,
    reason,
  });
  if (transportError) return unknown("transport-error");
  // A long-running operation was accepted but its effect on the name is not known yet.
  if (operationPending === true) return unknown("operation-pending");
  if (!Number.isInteger(status) || status < 0 || status > 999) return unknown("invalid-status");
  if (bodyReadable !== true) return unknown("unreadable-body");
  if (status < 200) return unknown("status-below-200");
  if (status < 300) return { class: "ok", status };
  if (status < 400) return unknown("redirect");
  // A server or client timeout, and a call cancelled after it left (gRPC CANCELLED is 499): the
  // request may have been applied, so the answer was lost.
  if (status === 408) return unknown("request-timeout");
  if (status === 499) return unknown("cancelled");
  if (status === 409) return { class: "conflict", status };
  if (status === 404) return { class: "notFound", status };
  if (status < 500) return { class: "refused", status };
  if (status < 600) return unknown("server-error");
  return unknown("invalid-status");
}

/** What a direct GET of a name showed: `present`, `absent` or `unknown`. */
export function classifyRead(answer) {
  const classified = classifyAnswer(answer);
  const observed =
    classified.class === "ok" ? "present" : classified.class === "notFound" ? "absent" : "unknown";
  return { ...classified, observed };
}

function blankName() {
  return {
    owned: false,
    created: false,
    via: null,
    open: null,
    unsettled: null,
    deleteUnknown: false,
  };
}

function entry(state, name) {
  let st = state.names.get(name);
  if (!st) {
    st = blankName();
    state.names.set(name, st);
  }
  return st;
}

// ---- transitions: shared by the live path and the replay of a ledger ----

function applyIntent(state, row) {
  const st = entry(state, row.name);
  if (st.open)
    throw new OwnershipError("in-flight", `${row.action} of ${row.name} is already in flight`);
  st.open = { ticket: row.ticket, action: row.action, name: row.name, transport: row.transport };
}

function applyAnswer(state, row) {
  const st = entry(state, row.name);
  if (!st.open || st.open.ticket !== row.ticket || st.open.action !== row.action) {
    throw new OwnershipError(
      "stale-ticket",
      `no open ${row.action} ticket ${row.ticket} for ${row.name}`,
    );
  }
  st.open = null;
  const klass = row.class;
  if (row.action === "create") {
    if (klass === "ok") {
      st.owned = true;
      st.created = true;
      st.via = "create";
    } else if (klass === "unknown") {
      st.unsettled = unknownAnswer(state, row);
    }
    return;
  }
  if (klass === "ok" || klass === "notFound") {
    st.owned = false;
  } else if (klass === "unknown") {
    st.unsettled = unknownAnswer(state, row);
    st.deleteUnknown = true;
    state.unknownDeletes += 1;
  }
}

/** Starts the sticky record of an unknown answer: it stays in the report for the whole run. */
function unknownAnswer(state, row) {
  const record = {
    name: row.name,
    action: row.action,
    ticket: row.ticket,
    reason: row.reason ?? "unknown",
    answeredAt: row.at,
    since: Date.parse(row.at),
    synthetic: row.synthetic === true,
    settled: false,
    settledBy: null,
    settledAt: null,
    absentReads: [],
  };
  state.unknownAnswers.push(record);
  return record;
}

function applyRead(state, row) {
  const st = state.names.get(row.name);
  if (!st || !st.unsettled) return;
  if (row.observed === "unknown") return;
  const record = st.unsettled;
  if (row.observed === "absent") {
    const afterDelay = Date.parse(row.at) - record.since >= state.settleAbsentAfterMs;
    record.absentReads.push({ at: row.at, afterDelay });
    // Absence alone never settles an unknown create: the request may still take effect (a timed-out
    // create was seen 40 minutes later), so only the coordinator can accept the name. An unknown
    // delete is settled by absence once the delay has passed; it still keeps closure false.
    if (record.action === "create" || !afterDelay) return;
    settle(st, record, "absent-after-delay", row.at);
    st.owned = false;
    return;
  }
  // Only positive evidence settles an answer at once: a GET whose body shows the name.
  settle(st, record, "present", row.at);
  if (record.action === "create") {
    st.owned = true;
    st.created = true;
    st.via = "settled-read";
  }
}

function settle(st, record, by, at) {
  record.settled = true;
  record.settledBy = by;
  record.settledAt = at;
  st.unsettled = null;
}

function apply(state, row) {
  if (row.phase === "intent") applyIntent(state, row);
  else if (row.phase === "answer") applyAnswer(state, row);
  else if (row.phase === "read") applyRead(state, row);
}

// ---- the ledger file ----

function writeAll(io, fd, text) {
  const buffer = Buffer.from(text, "utf8");
  let written = 0;
  while (written < buffer.length) {
    const n = io.writeSync(fd, buffer, written, buffer.length - written);
    if (!(n > 0)) throw new OwnershipError("ledger-write", "a ledger write made no progress");
    written += n;
  }
}

/** Every operation that would write starts here: a closed or failed state writes nothing. */
function ensureWritable(state) {
  if (!state.closed) return;
  throw state.failed
    ? new OwnershipError("ledger-failed", "a ledger write failed: the state is closed, resume it")
    : new OwnershipError("closed", "the ownership ledger is closed");
}

function append(state, row) {
  ensureWritable(state);
  state.rowSeq += 1;
  const full = {
    v: LEDGER_VERSION,
    runId: state.runId,
    seq: state.rowSeq,
    at: new Date(state.now()).toISOString(),
    ...row,
  };
  try {
    writeAll(state.io, state.fd, `${JSON.stringify(full)}\n`);
    state.io.fsyncSync(state.fd);
  } catch (error) {
    // The disk may hold a half row or a row that was never flushed, and the in-memory state was not
    // advanced. Going on would write a second intent for a name or bytes after a partial line, so
    // the state stops here; a resume of the file decides what the half-written row meant.
    state.failed = true;
    shutdown(state);
    throw error;
  }
  return full;
}

/** Closes the descriptor and releases the writer lock. Safe to call twice. */
function shutdown(state) {
  state.closed = true;
  if (state.fd !== null) {
    try {
      closeSync(state.fd);
    } catch {
      // the descriptor is already gone
    }
    state.fd = null;
  }
  releaseLock(state.lockPath);
  state.lockPath = null;
}

// ---- the single-writer lock ----

function holderAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return true; // not a pid: treat the lock as held
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error.code === "EPERM";
  }
}

/**
 * Takes `<path>.lock` exclusively (the pid of the holder inside). A lock whose holder process is
 * gone is taken over (a crashed run is resumed); a lock whose holder runs, or whose content is not
 * a pid, refuses the open. Same host only; a recycled pid keeps a dead holder's lock alive.
 */
function acquireLock(path) {
  const lockPath = `${path}.lock`;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      const fd = openSync(lockPath, "wx");
      try {
        writeSync(fd, `${process.pid}\n`);
      } finally {
        closeSync(fd);
      }
      return lockPath;
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
      let holder;
      try {
        holder = Number.parseInt(readFileSync(lockPath, "utf8"), 10);
      } catch (readError) {
        if (readError.code === "ENOENT") continue; // released meanwhile: try again
        throw readError;
      }
      if (holderAlive(holder)) {
        throw new OwnershipError(
          "ledger-locked",
          `${path} is open in another writer (${lockPath}); remove the lock only if no recorder holds it`,
        );
      }
      unlinkSync(lockPath); // the holder is gone
    }
  }
  throw new OwnershipError("ledger-locked", `${path} could not be locked (${lockPath})`);
}

function releaseLock(lockPath) {
  if (lockPath === null) return;
  try {
    unlinkSync(lockPath);
  } catch {
    // already removed
  }
}

const ROW_PHASES = new Set(["open", "intent", "answer", "read", "guard", "resume"]);

function parseRows(text, runId) {
  const lines = text.split("\n");
  const tail = lines.pop();
  const rows = [];
  for (const [index, line] of lines.entries()) {
    let row;
    try {
      row = JSON.parse(line);
    } catch {
      throw new OwnershipError("corrupt-ledger", `ledger line ${index + 1} is not JSON`);
    }
    if (
      row === null ||
      typeof row !== "object" ||
      row.v !== LEDGER_VERSION ||
      !ROW_PHASES.has(row.phase)
    ) {
      throw new OwnershipError("corrupt-ledger", `ledger line ${index + 1} is not a ledger row`);
    }
    if (typeof row.at !== "string" || Number.isNaN(Date.parse(row.at))) {
      throw new OwnershipError("corrupt-ledger", `ledger line ${index + 1} has no valid time`);
    }
    if (row.runId !== runId) {
      throw new OwnershipError(
        "foreign-run",
        `ledger line ${index + 1} belongs to run ${String(row.runId)}, not ${runId}: a run never adopts another run's names`,
      );
    }
    if (row.seq !== index + 1) {
      throw new OwnershipError(
        "corrupt-ledger",
        `ledger line ${index + 1} has sequence ${String(row.seq)}`,
      );
    }
    if ((index === 0) !== (row.phase === "open")) {
      throw new OwnershipError(
        "corrupt-ledger",
        index === 0
          ? "the first ledger row is not the open row"
          : `ledger line ${index + 1} is a second open row`,
      );
    }
    if (row.phase === "open" && !Number.isSafeInteger(row.settleAbsentAfterMs)) {
      throw new OwnershipError("corrupt-ledger", "the open row has no valid settle delay");
    }
    rows.push(row);
  }
  // Bytes after the last newline are a write that never finished: its fsync did not return, so
  // the request it announced was not sent. They are dropped, and the count is recorded.
  return { rows, droppedTailBytes: Buffer.byteLength(tail, "utf8") };
}

function newState(runId, now, io) {
  return {
    runId,
    now,
    io,
    fd: null,
    rowSeq: 0,
    ticket: 0,
    names: new Map(),
    unknownDeletes: 0,
    unknownAnswers: [],
    settleAbsentAfterMs: SETTLE_ABSENT_AFTER_MS,
    lockPath: null,
    closed: false,
    failed: false,
  };
}

function checkSettleDelay(value, allowShort) {
  if (
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > Number.MAX_SAFE_INTEGER / 4 ||
    (value < SETTLE_ABSENT_AFTER_MS && !allowShort)
  ) {
    throw new OwnershipError(
      "bad-settle-delay",
      `settleAbsentAfterMs is an integer of at least ${SETTLE_ABSENT_AFTER_MS} (the A2 read-back)`,
    );
  }
}

/**
 * Opens (or resumes) the ledger of one run. An existing ledger is replayed; a row of another run
 * is refused. An intent with no answer (the process died after sending) becomes an unknown answer.
 */
export function openOwnership({
  path,
  runId,
  now = Date.now,
  io = { writeSync, fsyncSync },
  settleAbsentAfterMs,
  testOnlyAllowShortSettleDelay = false,
}) {
  if (typeof path !== "string" || path === "")
    throw new OwnershipError("bad-path", "a ledger path is required");
  if (typeof runId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u.test(runId)) {
    throw new OwnershipError(
      "bad-run-id",
      "a run id is 1 to 64 characters of letters, digits, dot, underscore and hyphen",
    );
  }
  if (settleAbsentAfterMs !== undefined)
    checkSettleDelay(settleAbsentAfterMs, testOnlyAllowShortSettleDelay);
  const state = newState(runId, now, io);
  state.lockPath = acquireLock(path);
  try {
    return openLocked(state, path, settleAbsentAfterMs, testOnlyAllowShortSettleDelay);
  } catch (error) {
    shutdown(state);
    throw error;
  }
}

function openLocked(state, path, requestedDelay, allowShort) {
  let dropped = 0;
  let rows = [];
  const existed = existsSync(path);
  if (existed) {
    const parsed = parseRows(readFileSync(path, "utf8"), state.runId);
    dropped = parsed.droppedTailBytes;
    rows = parsed.rows;
  }
  if (rows.length > 0) {
    // The delay is a fact of the run: it is read from the ledger, and a resume cannot change it.
    const recorded = rows[0].settleAbsentAfterMs;
    if (requestedDelay !== undefined && requestedDelay !== recorded) {
      throw new OwnershipError(
        "settle-delay-mismatch",
        `the ledger records settleAbsentAfterMs ${recorded}; a resume cannot use ${requestedDelay}`,
      );
    }
    checkSettleDelay(recorded, allowShort);
    state.settleAbsentAfterMs = recorded;
  } else {
    state.settleAbsentAfterMs = requestedDelay ?? SETTLE_ABSENT_AFTER_MS;
  }
  for (const row of rows) {
    apply(state, row);
    state.rowSeq = row.seq;
    if (row.phase === "intent") state.ticket = Math.max(state.ticket, row.ticket);
  }
  state.fd = openSync(path, "a");
  if (!existed) {
    const parent = openSync(dirname(path), "r");
    try {
      state.io.fsyncSync(parent);
    } finally {
      closeSync(parent);
    }
  } else if (dropped > 0) {
    // Cut the unfinished row off so the next row starts on a line of its own.
    const keep = readFileSync(path).length - dropped;
    ftruncateSync(state.fd, keep);
    state.io.fsyncSync(state.fd);
  }
  if (rows.length === 0) {
    // A new ledger (or one that held only an unfinished first row) starts with the settings of the run.
    append(state, { phase: "open", settleAbsentAfterMs: state.settleAbsentAfterMs });
    return state;
  }
  append(state, { phase: "resume", droppedTailBytes: dropped });
  for (const st of state.names.values()) {
    if (!st.open) continue;
    const open = st.open;
    const row = append(state, {
      phase: "answer",
      ticket: open.ticket,
      action: open.action,
      name: open.name,
      transport: open.transport,
      class: "unknown",
      status: null,
      reason: "no-answer",
      synthetic: true,
    });
    applyAnswer(state, row);
  }
  return state;
}

export function closeOwnership(state) {
  if (state.closed) return;
  shutdown(state);
}

// ---- the three operations a recorder performs ----

function intent(state, action, { name, transport }) {
  ensureWritable(state);
  checkName(name);
  checkTransport(transport);
  const st = state.names.get(name);
  if (st?.open)
    throw new OwnershipError("in-flight", `${st.open.action} of ${name} is already in flight`);
  if (st?.unsettled) {
    throw new OwnershipError(
      "unsettled",
      `${name} has an unknown ${st.unsettled.action} answer; settle it with a direct GET first`,
    );
  }
  state.ticket += 1;
  const row = { phase: "intent", ticket: state.ticket, action, name, transport };
  append(state, row);
  applyIntent(state, row);
  return Object.freeze({ ticket: row.ticket, action, name, transport });
}

/** Call before sending a create. The row is durable when this returns. */
export function beginCreate(state, spec) {
  return intent(state, "create", spec);
}

/**
 * Call before sending a delete. Refuses (OwnershipError `not-owned`) a name this run did not
 * create, and (`unsettled`) a name with an unsettled unknown answer. The row is durable when this
 * returns.
 */
export function beginDelete(state, spec) {
  ensureWritable(state);
  checkName(spec?.name);
  const verdict = mayDelete(state, spec.name);
  if (!verdict.allowed) {
    checkTransport(spec.transport);
    append(state, {
      phase: "guard",
      action: "delete",
      name: spec.name,
      transport: spec.transport,
      allowed: false,
      reason: verdict.reason,
    });
    throw new OwnershipError(verdict.reason, `${spec.name} may not be deleted: ${verdict.reason}`);
  }
  return intent(state, "delete", spec);
}

/** Call with what came back for a ticket. Returns the answer class. */
export function recordAnswer(state, ticket, answer) {
  ensureWritable(state);
  const st = state.names.get(ticket?.name);
  if (!st?.open || st.open.ticket !== ticket.ticket) {
    throw new OwnershipError("stale-ticket", "the ticket is not the open request of its name");
  }
  const classified = classifyAnswer(answer);
  const row = {
    phase: "answer",
    ticket: ticket.ticket,
    action: ticket.action,
    name: ticket.name,
    transport: ticket.transport,
    class: classified.class,
    status: classified.status ?? null,
    ...(classified.reason ? { reason: classified.reason } : {}),
  };
  applyAnswer(state, append(state, row));
  return classified;
}

/**
 * Call with the answer of a direct GET of exactly `name` (never a list: a name missing from a list
 * is not a 404). A GET counts as present only when `answer.bodyName` is given and equals `name`;
 * a 2xx with no `bodyName`, or with another, is unknown. A present GET settles an unknown answer of
 * that name at once. A GET that finds nothing is recorded as evidence; it settles an unknown delete
 * once the settle delay has passed, and never settles an unknown create. A GET never makes a name
 * owned by itself.
 */
export function recordRead(state, { name, transport, answer }) {
  ensureWritable(state);
  checkName(name);
  checkTransport(transport);
  const st = state.names.get(name);
  if (st?.open)
    throw new OwnershipError("in-flight", `${st.open.action} of ${name} is still in flight`);
  let read = classifyRead(answer);
  const unusable = (reason) => ({
    class: "unknown",
    status: read.status,
    reason,
    observed: "unknown",
  });
  if (read.observed === "present" && answer.bodyName === undefined) {
    read = unusable("missing-body-name");
  } else if (
    read.observed !== "unknown" &&
    answer.bodyName !== undefined &&
    answer.bodyName !== name
  ) {
    read = unusable("name-mismatch");
  }
  const row = {
    phase: "read",
    action: "get",
    name,
    transport,
    class: read.class,
    status: read.status ?? null,
    observed: read.observed,
    ...(read.reason ? { reason: read.reason } : {}),
  };
  applyRead(state, append(state, row));
  return read.observed;
}

// ---- queries ----

/** The delete guard: `{ allowed, reason }`, without writing anything. */
export function mayDelete(state, name) {
  const st = state.names.get(name);
  if (st?.open) return { allowed: false, reason: "in-flight" };
  if (st?.unsettled) return { allowed: false, reason: "unsettled" };
  // A DELETE is never sent again after an unknown answer, whatever a GET then showed: the name
  // stays owned and undeleted, and only the coordinator's separate A2 read-back closes it.
  if (st?.deleteUnknown) return { allowed: false, reason: "unknown-delete-not-resent" };
  // Ownership is a fact about how the name came to exist, so it outlives this run's own delete:
  // deleting again is harmless (a 404) and is how a recorder probes a deleted name.
  if (!st?.created) return { allowed: false, reason: "not-owned" };
  return { allowed: true, reason: st.via };
}

export function isOwned(state, name) {
  return state.names.get(name)?.owned === true;
}

/** Names with an unknown answer no direct GET has settled yet. */
export function unsettledNames(state) {
  return [...state.names]
    .filter(([, st]) => st.unsettled)
    .map(([name]) => name)
    .toSorted();
}

/** What the report says about one unknown answer. */
function describeUnknown(state, record) {
  let stateName;
  if (record.settled) stateName = `settled-${record.settledBy}`;
  else if (record.action === "create" && record.absentReads.length > 0)
    stateName = "unknown-create-absent-unconfirmed";
  else stateName = `unknown-${record.action}-unsettled`;
  return {
    name: record.name,
    action: record.action,
    ticket: record.ticket,
    reason: record.reason,
    answeredAt: record.answeredAt,
    synthetic: record.synthetic,
    state: stateName,
    settled: record.settled,
    settledBy: record.settledBy,
    settledAt: record.settledAt,
    // Every unknown create or delete needs the separate read-back (A2) at least this long after
    // the answer before any close row.
    eligibleForA2At: new Date(record.since + state.settleAbsentAfterMs).toISOString(),
    requiresA2: true,
    absentReads: record.absentReads.map((read) => ({ ...read })),
  };
}

/**
 * Whether the run may be called closed on ownership grounds: nothing in flight, nothing unsettled,
 * nothing created and not yet deleted, and no unknown DELETE answer ever (a settled one counts:
 * its answer was never seen). `unknownAnswers` lists every unknown answer of the run, settled or
 * not, so the coordinator's A2 read-back and close row can name them; `details` is the unsettled
 * part. A create that stays unknown after a GET found nothing is `absentUnconfirmed`: absence
 * alone never settles it, so the coordinator must accept the name or run a recovery.
 */
export function closureReport(state) {
  const reasons = [];
  // Names are unique, so no pair of them compares equal.
  for (const [name, st] of [...state.names].toSorted(([a], [b]) => (a < b ? -1 : 1))) {
    if (st.open) reasons.push(`in-flight:${name}`);
    if (st.unsettled) reasons.push(`unsettled-${st.unsettled.action}:${name}`);
    if (st.unsettled?.action === "create" && st.unsettled.absentReads.length > 0)
      reasons.push(`unknown-create-absent-unconfirmed:${name}`);
    if (st.owned) reasons.push(`owned-not-deleted:${name}`);
  }
  if (state.unknownDeletes > 0) reasons.push(`unknown-delete-answers:${state.unknownDeletes}`);
  const unknownAnswers = state.unknownAnswers.map((record) => describeUnknown(state, record));
  const absentUnconfirmed = unknownAnswers
    .filter((item) => item.state === "unknown-create-absent-unconfirmed")
    .map((item) => item.name)
    .toSorted();
  return {
    closureReady: reasons.length === 0,
    reasons,
    unknownDeletes: state.unknownDeletes,
    owned: [...state.names]
      .filter(([, st]) => st.owned)
      .map(([name]) => name)
      .toSorted(),
    unsettled: unsettledNames(state),
    // What each unsettled name is waiting for, and why it is unknown.
    details: unknownAnswers
      .filter((item) => !item.settled)
      .toSorted((a, b) => (a.name < b.name ? -1 : 1)), // one unsettled answer per name
    unknownAnswers,
    a2Required: unknownAnswers.length > 0,
    absentUnconfirmed,
    coordinatorNote:
      absentUnconfirmed.length === 0
        ? null
        : `${absentUnconfirmed.join(", ")}: a create with an unknown answer that no own GET has shown; absence alone never settles it, so the coordinator must accept the name or run a recovery`,
  };
}

/** Parses a ledger file for a run without opening it for writing (for reports and tests). */
export function readLedger(path, runId) {
  return parseRows(readFileSync(path, "utf8"), runId);
}
