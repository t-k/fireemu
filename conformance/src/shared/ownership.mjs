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
//      settles it, however late, and the name stays in the report for the coordinator (who may
//      accept it with acceptUnconfirmed). An unknown delete is sticky: a GET that finds nothing is
//      only evidence, and it keeps closureReady false. A name this run deleted with a 2xx settles
//      only when an own GET reads it as 404.

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

/** The longest settle delay: an answer time plus the delay must still be a date (about 71,000 years). */
export const MAX_SETTLE_DELAY_MS = 2 ** 51;

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
    // Reads or delete answers of 404 for a create this run confirmed and did not delete.
    missingReads: 0,
    // After this run's own DELETE answered 2xx: null (none), "unverified" (no own GET read it back
    // yet), "verified" (the last own GET answered 404) or "present" (the last own GET showed it).
    deletePhase: null,
    // The coordinator accepted an unconfirmed create of this name (ledger reference recorded).
    accepted: false,
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
  touch(state, row);
}

/** The time of the last request (an intent, a real answer or a read), for the A2 read-back. */
function touch(state, row) {
  if (row.synthetic === true) return;
  const at = Date.parse(row.at);
  if (state.lastRequestAt === null || at > state.lastRequestAt) state.lastRequestAt = at;
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
  touch(state, row);
  const klass = row.class;
  if (row.action === "create") {
    if (klass === "ok") {
      st.owned = true;
      st.created = true;
      st.via = "create";
      st.missingReads = 0; // a new confirmed create starts with no 404 against it
      st.deletePhase = null;
    } else if (klass === "unknown") {
      st.unsettled = unknownAnswer(state, row);
    }
    return;
  }
  if (klass === "ok") {
    // Gone as far as the answer says; it counts as settled only after an own GET reads 404.
    st.owned = false;
    st.missingReads = 0;
    st.deletePhase = "unverified";
  } else if (klass === "notFound") {
    // A 404 for a create this run confirmed is not a settlement (a read-after-write lag can hide a
    // live resource): only this run's own DELETE answered 2xx, or the coordinator's A2, settles it.
    if (st.owned) st.missingReads += 1;
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
  touch(state, row);
  if (!st || row.observed === "unknown") return;
  if (!st.unsettled) {
    if (row.observed === "absent") {
      // A create this run confirmed that reads 404 stays open (a lag can hide a live resource); a
      // name this run deleted with a 2xx is read back by this 404.
      if (st.owned) st.missingReads += 1;
      else if (st.deletePhase !== null) st.deletePhase = "verified";
    } else if (st.deletePhase !== null) {
      st.deletePhase = "present";
    }
    return;
  }
  const record = st.unsettled;
  if (row.observed === "absent") {
    const afterDelay = Date.parse(row.at) - record.since >= state.settleAbsentAfterMs;
    record.absentReads.push({ at: row.at, afterDelay });
    // Absence alone settles no unknown answer, however late: a timed-out create was seen 40
    // minutes later, and the answer to an unknown delete was never seen. Only the coordinator's
    // A2 read-back, or an acceptance of the name, closes it. The read is kept as evidence.
    return;
  }
  // Only positive evidence settles an answer: a GET whose body shows the name.
  settle(st, record, "present", row.at);
  if (record.action === "create") {
    st.owned = true;
    st.created = true;
    st.via = "settled-read";
    st.deletePhase = null;
  }
}

function settle(st, record, by, at) {
  record.settled = true;
  record.settledBy = by;
  record.settledAt = at;
  st.unsettled = null;
}

function applyAccept(state, row) {
  const st = state.names.get(row.name);
  const record = st?.unsettled;
  if (!record || record.action !== "create") {
    throw new OwnershipError(
      "corrupt-ledger",
      `an acceptance of ${row.name} has no unknown create`,
    );
  }
  record.acceptedBy = row.ledgerRef;
  settle(st, record, "accepted", row.at);
  st.accepted = true;
}

function apply(state, row) {
  if (row.phase === "intent") applyIntent(state, row);
  else if (row.phase === "answer") applyAnswer(state, row);
  else if (row.phase === "read") applyRead(state, row);
  else if (row.phase === "accept") applyAccept(state, row);
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

/**
 * Closes the descriptor and releases the writer lock, once. A second call must do nothing: the
 * descriptor number may belong to another file by then, and the lock to another writer.
 */
function shutdown(state) {
  if (state.closed) return;
  state.closed = true;
  if (state.fd !== null) {
    try {
      closeSync(state.fd);
    } catch {
      // the descriptor is already gone
    }
  }
  releaseLock(state.lockPath);
}

// ---- the single-writer lock ----

function holderAlive(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return true; // not a pid: treat the lock as held
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error.code === "EPERM"; // alive, but another user's
  }
}

function createLock(lockPath) {
  const fd = openSync(lockPath, "wx");
  try {
    writeSync(fd, `${process.pid}\n`);
  } finally {
    closeSync(fd);
  }
  return lockPath;
}

/**
 * Takes `<path>.lock` exclusively (the pid of the holder inside). A lock whose holder process is
 * gone is taken over (a crashed run is resumed); a lock whose holder runs, or whose content cannot
 * be read as a pid, refuses the open, and so does a takeover that loses a race. Same host only; a
 * recycled pid keeps a dead holder's lock alive.
 */
function acquireLock(path) {
  const lockPath = `${path}.lock`;
  try {
    return createLock(lockPath);
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
  }
  let holder;
  try {
    holder = Number.parseInt(readFileSync(lockPath, "utf8"), 10);
  } catch {
    holder = Number.NaN; // unreadable: not ours to take
  }
  if (holderAlive(holder)) {
    throw new OwnershipError(
      "ledger-locked",
      `${path} is open in another writer (${lockPath}); remove the lock only if no recorder holds it`,
    );
  }
  try {
    unlinkSync(lockPath); // the holder is gone
    return createLock(lockPath);
  } catch {
    throw new OwnershipError(
      "ledger-locked",
      `${lockPath} of a gone writer could not be taken over`,
    );
  }
}

function releaseLock(lockPath) {
  try {
    unlinkSync(lockPath);
  } catch {
    // already removed
  }
}

const ROW_PHASES = new Set(["open", "intent", "answer", "read", "guard", "resume", "accept"]);

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
    lastRequestAt: null,
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
    value > MAX_SETTLE_DELAY_MS ||
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
  if (settleAbsentAfterMs !== undefined) {
    checkSettleDelay(settleAbsentAfterMs, testOnlyAllowShortSettleDelay);
  }
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
  if (action === "create" && st?.deleteUnknown) {
    // Its delete may still take effect and remove the new resource, and every answer on the name
    // would be ambiguous.
    throw new OwnershipError(
      "unknown-delete-not-reused",
      `${name} has an unknown delete answer; it is never created again in this run`,
    );
  }
  if (action === "create" && st?.accepted) {
    throw new OwnershipError(
      "accepted-unconfirmed-not-reused",
      `${name} was accepted as an unconfirmed create; it is never created again in this run`,
    );
  }
  if (st?.unsettled) {
    throw new OwnershipError(
      "unsettled",
      `${name} has an unknown ${st.unsettled.action} answer; settle it with a direct GET first`,
    );
  }
  state.ticket += 1;
  const row = { phase: "intent", ticket: state.ticket, action, name, transport };
  applyIntent(state, append(state, row));
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

/**
 * Records that the coordinator accepted an unconfirmed create: an unknown create of `name` that no
 * own GET showed, with at least one GET that found nothing after the settle delay. `ledgerRef` is
 * the owner-ledger line (or recovery packet) naming the run, the name and the reads; it is required.
 * The name leaves the unsettled set and closureReady no longer waits for it; every other name is
 * untouched, and the name is never created again in this run.
 */
export function acceptUnconfirmed(state, name, ledgerRef) {
  ensureWritable(state);
  checkName(name);
  if (
    typeof ledgerRef !== "string" ||
    ledgerRef.trim() === "" ||
    ledgerRef.length > NAME_LIMIT ||
    hasControl(ledgerRef)
  ) {
    throw new OwnershipError(
      "bad-ledger-ref",
      "an acceptance names the owner-ledger line or recovery packet that accepted it",
    );
  }
  const record = state.names.get(name)?.unsettled;
  if (!record || record.action !== "create") {
    throw new OwnershipError("not-unconfirmed", `${name} has no unsettled unknown create`);
  }
  if (!record.absentReads.some((read) => read.afterDelay)) {
    throw new OwnershipError(
      "absent-read-required",
      `${name} has no GET that found nothing after the settle delay`,
    );
  }
  const row = append(state, { phase: "accept", name, ticket: record.ticket, ledgerRef });
  applyAccept(state, row);
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

function namesWhere(state, test) {
  return [...state.names]
    .filter(([, st]) => test(st))
    .map(([name]) => name)
    .toSorted();
}

/** What the report says about one unknown answer. */
function describeUnknown(state, record) {
  let stateName;
  if (record.settled) stateName = `settled-${record.settledBy}`;
  else if (record.action === "create" && record.absentReads.length > 0)
    stateName = "unknown-create-absent-unconfirmed";
  else if (record.absentReads.length > 0) stateName = "unknown-delete-absent-in-run";
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
    acceptedBy: record.acceptedBy ?? null,
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
    if (st.owned && st.missingReads > 0) reasons.push(`confirmed-create-reads-404:${name}`);
    // Our own DELETE answered 2xx; it settles only once an own GET reads the name as 404.
    if (st.deletePhase === "unverified") reasons.push(`deleted-unverified:${name}`);
    if (st.deletePhase === "present") reasons.push(`deleted-but-present:${name}`);
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
    deletedUnverified: namesWhere(state, (st) => st.deletePhase === "unverified"),
    deletedButPresent: namesWhere(state, (st) => st.deletePhase === "present"),
    accepted: state.unknownAnswers
      .filter((record) => record.settledBy === "accepted")
      .map((record) => ({ name: record.name, ledgerRef: record.acceptedBy, at: record.settledAt })),
    // The time of the last request, and the earliest the A2 read-back may start: the delay after it.
    lastRequestAt:
      state.lastRequestAt === null ? null : new Date(state.lastRequestAt).toISOString(),
    a2NotBefore:
      state.lastRequestAt === null
        ? null
        : new Date(state.lastRequestAt + state.settleAbsentAfterMs).toISOString(),
    // Created names that read 404 before this run deleted them: open until the A2 read-back.
    confirmedReadsMissing: [...state.names]
      .filter(([, st]) => st.owned && st.missingReads > 0)
      .map(([name]) => name)
      .toSorted(),
    // What each unsettled name is waiting for, and why it is unknown.
    details: unsettledNames(state).map((name) =>
      describeUnknown(state, state.names.get(name).unsettled),
    ),
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
