import { constants } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import { DRAFT_REQUEST_LIMITS } from "./request-counter.mjs";

const plain = (value) => value !== null && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype;
const matches = (value, pattern) => typeof value === "string" && !/[\r\n]/.test(value) && pattern.test(value);
const requestId = (value) => matches(value, /^[A-Za-z0-9][A-Za-z0-9._/-]{0,159}$/);

function record(value, keys) {
  if (!plain(value)) throw new Error();
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => !keys.includes(key))) throw new Error();
  const copy = {};
  for (const key of keys) {
    const field = Object.getOwnPropertyDescriptor(value, key);
    if (!field?.enumerable || !Object.hasOwn(field, "value")) throw new Error();
    copy[key] = field.value;
  }
  return copy;
}

function ids(value, maximum) {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length === 0 || value.length > maximum || Reflect.ownKeys(value).length !== value.length + 1) throw new Error();
  const copy = [];
  for (let index = 0; index < value.length; index++) {
    const field = Object.getOwnPropertyDescriptor(value, String(index));
    if (!field?.enumerable || !Object.hasOwn(field, "value") || !requestId(field.value)) throw new Error();
    copy.push(field.value);
  }
  if (new Set(copy).size !== copy.length) throw new Error();
  return copy;
}

/** Persist closed counter events in a fresh run-local file; this does not admit production traffic. */
export async function createReservationJournal(input) {
  let options;
  let io;
  let requestIds;
  let preflightIds;
  const { maxRequests, recoveryReserve } = DRAFT_REQUEST_LIMITS;
  const normalCap = maxRequests - recoveryReserve;
  try {
    options = record(input, ["directory", "runId", "sourceCommit", "manifestDigest", "requestIds", "preflightIds", "io"]);
    io = record(options.io, ["open", "lstat"]);
    if (typeof options.directory !== "string" || options.directory.length > 4096 || options.directory.includes("\0") || !isAbsolute(options.directory) || resolve(options.directory) !== options.directory || !matches(options.runId, /^[a-z0-9][a-z0-9-]{0,47}$/) || !matches(options.sourceCommit, /^[a-f0-9]{40}$/) || !matches(options.manifestDigest, /^[a-f0-9]{64}$/) || [io.open, io.lstat].some((method) => typeof method !== "function")) throw new Error();
    requestIds = ids(options.requestIds, maxRequests);
    preflightIds = ids(options.preflightIds, 64);
    if (preflightIds.some((id) => !id.startsWith("preflight/") || !requestIds.includes(id)) || requestIds.some((id) => id.startsWith("preflight/") && !preflightIds.includes(id))) throw new Error();
  } catch { throw new Error("invalid reservation journal input"); }
  const path = join(options.directory, "reservations.jsonl");
  const declared = new Set(requestIds);
  const used = new Set();
  let directory;
  let file;
  let directoryIdentity;
  let fileIdentity;
  let size = 0;
  let sequence = 0;
  let state = "opened";
  let phase = "preflight";
  let busy = false;
  let uncertain = false;
  let closed = false;
  let requests = 0;
  let normal = 0;
  let recovery = 0;

  async function verifyIdentity(expectedSize) {
    const dir = await io.lstat(options.directory);
    if (!dir.isDirectory() || (dir.mode & 0o777) !== 0o700 || dir.dev !== directoryIdentity.dev || dir.ino !== directoryIdentity.ino) throw new Error();
    for (const stat of [await file.stat(), await io.lstat(path)]) {
      if (!stat.isFile() || (stat.mode & 0o777) !== 0o600 || stat.nlink !== 1 || stat.dev !== fileIdentity.dev || stat.ino !== fileIdentity.ino || stat.size !== expectedSize) throw new Error();
    }
  }

  async function append(event, data) {
    const bytes = Buffer.from(`${JSON.stringify({ schemaVersion: 1, sequence: sequence + 1, runId: options.runId, sourceCommit: options.sourceCommit, manifestDigest: options.manifestDigest, event, data })}\n`);
    try {
      await verifyIdentity(size);
      let offset = 0;
      while (offset < bytes.length) {
        const { bytesWritten } = await file.write(bytes, offset, bytes.length - offset, null);
        if (!Number.isSafeInteger(bytesWritten) || bytesWritten <= 0 || bytesWritten > bytes.length - offset) throw new Error();
        offset += bytesWritten;
      }
      await verifyIdentity(size + bytes.length);
      await file.sync();
      await verifyIdentity(size + bytes.length);
      size += bytes.length;
      sequence++;
    } catch { uncertain = true; throw new Error("reservation journal uncertain"); }
  }

  async function closeHandles() {
    let failed = false;
    for (const [handle, clear] of [[file, () => { file = null; }], [directory, () => { directory = null; }]]) {
      if (handle) {
        try { await handle.close(); clear(); } catch { failed = true; }
      }
    }
    if (failed) { uncertain = true; throw new Error("reservation journal uncertain"); }
  }

  try {
    const stat = await io.lstat(options.directory);
    if (!stat.isDirectory() || (stat.mode & 0o777) !== 0o700) throw new Error();
    directoryIdentity = { dev: stat.dev, ino: stat.ino };
    directory = await io.open(options.directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    const openedDirectory = await directory.stat();
    if (!openedDirectory.isDirectory() || (openedDirectory.mode & 0o777) !== 0o700 || openedDirectory.dev !== stat.dev || openedDirectory.ino !== stat.ino) throw new Error();
    file = await io.open(path, constants.O_CREAT | constants.O_EXCL | constants.O_APPEND | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    const openedFile = await file.stat();
    if (!openedFile.isFile() || (openedFile.mode & 0o777) !== 0o600 || openedFile.nlink !== 1 || openedFile.size !== 0) throw new Error();
    fileIdentity = { dev: openedFile.dev, ino: openedFile.ino };
    await append("opened", { requestIds, preflightIds, maxRequests, recoveryReserve });
    await directory.sync();
    await verifyIdentity(size);
  } catch {
    await closeHandles().catch(() => {});
    throw new Error("reservation journal creation failed");
  }

  const completePreflight = () => preflightIds.every((id) => used.has(id));
  const gate = () => { if (busy || closed || uncertain || state === "terminal") throw new Error(); };

  async function event(kind, input) {
    let row;
    try {
      gate();
      if (kind === "started") {
        row = record(input, ["runId", "maxRequests", "recoveryReserve", "preflightIds"]);
        row.preflightIds = ids(row.preflightIds, 64);
        if (state !== "opened" || row.runId !== options.runId || row.maxRequests !== maxRequests || row.recoveryReserve !== recoveryReserve || JSON.stringify(row.preflightIds) !== JSON.stringify(preflightIds)) throw new Error();
      } else if (kind === "reserved") {
        row = record(input, ["attempt", "operationId", "phase"]);
        if (state !== "started" || row.attempt !== requests + 1 || !declared.has(row.operationId) || used.has(row.operationId) || !["preflight", "normal", "recovery"].includes(row.phase) || requests >= maxRequests) throw new Error();
        if (row.phase === "preflight" ? phase !== "preflight" || !preflightIds.includes(row.operationId) : !completePreflight() || preflightIds.includes(row.operationId)) throw new Error();
        if (phase === "recovery" && row.phase !== "recovery") throw new Error();
        if (row.phase === "recovery" ? recovery >= recoveryReserve : normal >= normalCap) throw new Error();
      } else {
        row = record(input, ["outcome", "requests", "normal", "recovery", "maxRequests"]);
        if (state !== "started" || !["preflight-failed", "finished", "needs-recovery", "stopped-no-mutation", "recovered"].includes(row.outcome) || row.requests !== requests || row.normal !== normal || row.recovery !== recovery || row.maxRequests !== maxRequests) throw new Error();
        if (row.outcome === "preflight-failed" ? phase !== "preflight" : !completePreflight()) throw new Error();
        if (row.outcome === "stopped-no-mutation" && recovery !== 0) throw new Error();
        if (row.outcome === "recovered" && recovery < 1) throw new Error();
      }
    } catch { throw new Error("reservation journal event refused"); }
    busy = true;
    try {
      await append(kind, row);
      if (kind === "started") state = "started";
      else if (kind === "reserved") {
        requests++;
        if (row.phase === "recovery") recovery++;
        else normal++;
        used.add(row.operationId);
        phase = row.phase;
      } else state = "terminal";
    } finally { busy = false; }
  }

  return Object.freeze({
    onStarted(row) { return event("started", row); },
    onReserve(row) { return event("reserved", row); },
    onTerminal(row) { return event("terminal", row); },
    async close() {
      if (busy) throw new Error("reservation journal event refused");
      if (closed && !file && !directory) return;
      closed = true;
      busy = true;
      try { await closeHandles(); } finally { busy = false; }
    },
    snapshot() { return Object.freeze({ state, busy, uncertain, closed, requests, normal, recovery, sendAuthorized: false }); },
  });
}
