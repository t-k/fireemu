// Recorder ownership: which names this run created, which it may delete, and which outcomes are
// still unknown. Functions over a small state object; no framework and no transport code. The
// caller sends the requests and reports what happened. See ownership.README.md for the contract.
//
// Three rules, and nothing else:
//   1. Issued names: every create or delete intent is a JSONL row, fsynced before the request is
//      sent, and its answer is a second row, fsynced after the answer.
//   2. Delete guard: a name may be deleted only if this run's own create of it answered 2xx, or
//      answered unknown and a later direct GET showed the name.
//   3. Unknown answers: a transport error, an unreadable body, a status below 200, a 3xx or a 5xx
//      on a create or delete is unknown. Only a direct GET of that name settles it, and any
//      unknown DELETE keeps closureReady false.

import {
  closeSync,
  fsyncSync,
  ftruncateSync,
  openSync,
  readFileSync,
  writeSync,
  existsSync,
} from "node:fs";
import { dirname } from "node:path";

export const LEDGER_VERSION = 1;

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
    deleted: false,
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
      st.deleted = false;
    } else if (klass === "unknown") {
      st.unsettled = { action: "create", ticket: row.ticket, reason: row.reason ?? "unknown" };
    }
    return;
  }
  if (klass === "ok" || klass === "notFound") {
    st.owned = false;
    st.deleted = true;
  } else if (klass === "unknown") {
    st.unsettled = { action: "delete", ticket: row.ticket, reason: row.reason ?? "unknown" };
    st.deleteUnknown = true;
    state.unknownDeletes += 1;
  }
}

function applyRead(state, row) {
  const st = state.names.get(row.name);
  if (!st || !st.unsettled) return;
  if (row.observed === "unknown") return;
  const settled = st.unsettled;
  st.unsettled = null;
  if (settled.action === "create") {
    if (row.observed === "present") {
      st.owned = true;
      st.created = true;
      st.via = "settled-read";
      st.deleted = false;
    }
    return;
  }
  // An unknown delete: the name is still there (still ours) or it is gone.
  if (row.observed === "absent") {
    st.owned = false;
    st.deleted = true;
  }
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

function append(state, row) {
  if (state.closed) throw new OwnershipError("closed", "the ownership ledger is closed");
  state.rowSeq += 1;
  const full = {
    v: LEDGER_VERSION,
    runId: state.runId,
    seq: state.rowSeq,
    at: new Date(state.now()).toISOString(),
    ...row,
  };
  writeAll(state.io, state.fd, `${JSON.stringify(full)}\n`);
  state.io.fsyncSync(state.fd);
  return full;
}

const ROW_PHASES = new Set(["intent", "answer", "read", "guard", "resume"]);

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
    path: null,
    rowSeq: 0,
    ticket: 0,
    names: new Map(),
    unknownDeletes: 0,
    closed: false,
  };
}

/**
 * Opens (or resumes) the ledger of one run. An existing ledger is replayed; a row of another run
 * is refused. An intent with no answer (the process died after sending) becomes an unknown answer.
 */
export function openOwnership({ path, runId, now = Date.now, io = { writeSync, fsyncSync } }) {
  if (typeof path !== "string" || path === "")
    throw new OwnershipError("bad-path", "a ledger path is required");
  if (typeof runId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u.test(runId)) {
    throw new OwnershipError(
      "bad-run-id",
      "a run id is 1 to 64 characters of letters, digits, dot, underscore and hyphen",
    );
  }
  const state = newState(runId, now, io);
  state.path = path;
  let dropped = 0;
  const existed = existsSync(path);
  if (existed) {
    const parsed = parseRows(readFileSync(path, "utf8"), runId);
    dropped = parsed.droppedTailBytes;
    for (const row of parsed.rows) {
      apply(state, row);
      state.rowSeq = row.seq;
      if (row.phase === "intent") state.ticket = Math.max(state.ticket, row.ticket);
    }
  }
  state.fd = openSync(path, "a");
  if (!existed) {
    const parent = openSync(dirname(path), "r");
    try {
      fsyncSync(parent);
    } finally {
      closeSync(parent);
    }
  } else if (dropped > 0) {
    // Cut the unfinished row off so the next row starts on a line of its own.
    const keep = readFileSync(path).length - dropped;
    ftruncateSync(state.fd, keep);
    fsyncSync(state.fd);
  }
  if (existed) {
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
  }
  return state;
}

export function closeOwnership(state) {
  if (state.closed) return;
  state.closed = true;
  closeSync(state.fd);
}

// ---- the three operations a recorder performs ----

function intent(state, action, { name, transport }) {
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
  append(state, row);
  applyAnswer(state, row);
  return classified;
}

/**
 * Call with the answer of a direct GET of exactly `name`. Settles an unknown answer of that name
 * when the GET is conclusive (present or absent); it never makes a name owned by itself.
 * `answer.bodyName`, when given, must equal `name`: a body about another name is unknown.
 */
export function recordRead(state, { name, transport, answer }) {
  checkName(name);
  checkTransport(transport);
  const st = state.names.get(name);
  if (st?.open)
    throw new OwnershipError("in-flight", `${st.open.action} of ${name} is still in flight`);
  let read = classifyRead(answer);
  if (read.observed !== "unknown" && answer.bodyName !== undefined && answer.bodyName !== name) {
    read = { class: "unknown", status: read.status, reason: "name-mismatch", observed: "unknown" };
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
  append(state, row);
  applyRead(state, row);
  return read.observed;
}

// ---- queries ----

/** The delete guard: `{ allowed, reason }`, without writing anything. */
export function mayDelete(state, name) {
  const st = state.names.get(name);
  if (st?.open) return { allowed: false, reason: "in-flight" };
  if (st?.unsettled) return { allowed: false, reason: "unsettled" };
  // A DELETE is never sent again after an unknown answer, whatever a GET then showed: the name
  // stays owned and undeleted, and a later cleanup run settles it.
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

/**
 * Whether the run may be called closed on ownership grounds: nothing in flight, nothing unsettled,
 * nothing created and not yet deleted, and no unknown DELETE answer ever (a settled one counts:
 * its answer was never seen).
 */
export function closureReport(state) {
  const reasons = [];
  for (const [name, st] of [...state.names].toSorted(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
    if (st.open) reasons.push(`in-flight:${name}`);
    if (st.unsettled) reasons.push(`unsettled-${st.unsettled.action}:${name}`);
    if (st.owned) reasons.push(`owned-not-deleted:${name}`);
  }
  if (state.unknownDeletes > 0) reasons.push(`unknown-delete-answers:${state.unknownDeletes}`);
  return {
    closureReady: reasons.length === 0,
    reasons,
    unknownDeletes: state.unknownDeletes,
    owned: [...state.names]
      .filter(([, st]) => st.owned)
      .map(([name]) => name)
      .toSorted(),
    unsettled: unsettledNames(state),
  };
}

/** Parses a ledger file for a run without opening it for writing (for reports and tests). */
export function readLedger(path, runId) {
  return parseRows(readFileSync(path, "utf8"), runId);
}
