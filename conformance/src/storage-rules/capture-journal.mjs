import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import { createRedactor } from "./redaction.mjs";

// Run-local, append-only capture of what a request intended (intent), what came back (response, redacted and stored as a
// content-addressed blob), what it meant (facts), which run-time values were bound (proof) and what the controller
// said (note); plus the credential evidence (proofs, ownership and cleanup receipts of the fixture accounts). Every row and blob is synced before the call returns. Anything a writer is given is redacted or refused,
// so no file under the run directory holds bearer material. This performs no HTTP.
const plain = (value) => value !== null && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype;
const matches = (value, pattern) => typeof value === "string" && !/[\r\n]/.test(value) && pattern.test(value);
const requestId = (value) => matches(value, /^[A-Za-z0-9][A-Za-z0-9._/-]{0,159}$/);
const MAX_ROW_BYTES = 256 * 1024;
const MAX_BLOB_BYTES = 2 * 1024 * 1024;
const MAX_NOTE = 4096;
const MAX_EVIDENCE = 8192;
const FIXTURE_ACCOUNTS = new Set(["user-a", "user-b", "revoked-token", "foreign-project-token"]);
const FIXTURE_PROJECTS = new Set(["fireemu-oracle-query", "fireemu-oracle-idp"]);

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

function stringArray(value, maximum) {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length > maximum || Reflect.ownKeys(value).length !== value.length + 1) throw new Error();
  return value.map((entry, index) => {
    const field = Object.getOwnPropertyDescriptor(value, String(index));
    if (!field?.enumerable || !Object.hasOwn(field, "value") || typeof field.value !== "string") throw new Error();
    return field.value;
  });
}

// A JSON tree of strings, safe integers, booleans and null only, so a fact can be checked for bearer material as text.
function plainJson(value, depth = 0) {
  if (depth > 6) throw new Error();
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") { if (value.length > 4096) throw new Error(); return value; }
  if (typeof value === "number") { if (!Number.isSafeInteger(value)) throw new Error(); return value; }
  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype || value.length > 64 || Reflect.ownKeys(value).length !== value.length + 1) throw new Error();
    return value.map((entry, index) => {
      const field = Object.getOwnPropertyDescriptor(value, String(index));
      if (!field?.enumerable || !Object.hasOwn(field, "value")) throw new Error();
      return plainJson(field.value, depth + 1);
    });
  }
  if (!plain(value)) throw new Error();
  const keys = Reflect.ownKeys(value);
  if (keys.length > 32 || keys.some((key) => typeof key !== "string" || key.length > 64)) throw new Error();
  return Object.fromEntries(keys.map((key) => {
    const field = Object.getOwnPropertyDescriptor(value, key);
    if (!field?.enumerable || !Object.hasOwn(field, "value")) throw new Error();
    return [key, plainJson(field.value, depth + 1)];
  }));
}

export async function createCaptureJournal(input) {
  let options; let io; let redactor;
  try {
    options = record(input, ["directory", "runId", "sourceCommit", "manifestDigest", "digestSalt", "requestIds", "io"]);
    io = record(options.io, ["open", "lstat", "mkdir"]);
    if (typeof options.directory !== "string" || options.directory.length > 4096 || options.directory.includes("\0") || !isAbsolute(options.directory) || resolve(options.directory) !== options.directory || !matches(options.runId, /^[a-z0-9][a-z0-9-]{0,47}$/) || !matches(options.sourceCommit, /^[a-f0-9]{40}$/) || !matches(options.manifestDigest, /^[a-f0-9]{64}$/) || !matches(options.digestSalt, /^[0-9a-f]{64}$/) || [io.open, io.lstat, io.mkdir].some((method) => typeof method !== "function")) throw new Error();
    options.requestIds = stringArray(options.requestIds, 20000);
    if (options.requestIds.length === 0 || options.requestIds.some((id) => !requestId(id)) || new Set(options.requestIds).size !== options.requestIds.length) throw new Error();
    redactor = createRedactor({ digestSalt: options.digestSalt });
  } catch { throw new Error("invalid capture journal input"); }
  const declared = new Set(options.requestIds);
  const path = join(options.directory, "captures.jsonl");
  const blobDirectory = join(options.directory, "blobs");
  const intents = new Map();
  const responded = new Set();
  let directory; let file; let blobs;
  let directoryIdentity; let fileIdentity; let blobsIdentity;
  let size = 0; let sequence = 0;
  let busy = false; let uncertain = false; let closed = false;

  async function verifyIdentity(expectedSize) {
    const dir = await io.lstat(options.directory);
    if (!dir.isDirectory() || (dir.mode & 0o777) !== 0o700 || dir.dev !== directoryIdentity.dev || dir.ino !== directoryIdentity.ino) throw new Error();
    const blobStat = await io.lstat(blobDirectory);
    if (!blobStat.isDirectory() || (blobStat.mode & 0o777) !== 0o700 || blobStat.dev !== blobsIdentity.dev || blobStat.ino !== blobsIdentity.ino) throw new Error();
    for (const stat of [await file.stat(), await io.lstat(path)]) {
      if (!stat.isFile() || (stat.mode & 0o777) !== 0o600 || stat.nlink !== 1 || stat.dev !== fileIdentity.dev || stat.ino !== fileIdentity.ino || stat.size !== expectedSize) throw new Error();
    }
  }

  async function writeAll(handle, bytes) {
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesWritten } = await handle.write(bytes, offset, bytes.length - offset, null);
      if (!Number.isSafeInteger(bytesWritten) || bytesWritten <= 0 || bytesWritten > bytes.length - offset) throw new Error();
      offset += bytesWritten;
    }
  }

  async function append(event, data) {
    const bytes = Buffer.from(`${JSON.stringify({ schemaVersion: 1, sequence: sequence + 1, runId: options.runId, sourceCommit: options.sourceCommit, manifestDigest: options.manifestDigest, event, data })}\n`);
    if (bytes.length > MAX_ROW_BYTES) throw new Error();
    await verifyIdentity(size);
    await writeAll(file, bytes);
    await verifyIdentity(size + bytes.length);
    await file.sync();
    await verifyIdentity(size + bytes.length);
    size += bytes.length;
    sequence++;
  }

  async function writeBlob(bytes) {
    const sha = createHash("sha256").update(bytes).digest("hex");
    const blobPath = join(blobDirectory, `${sha}.bin`);
    let handle;
    try {
      handle = await io.open(blobPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    } catch (error) {
      if (error?.code !== "EEXIST") throw error;
      const stat = await io.lstat(blobPath);
      if (!stat.isFile() || (stat.mode & 0o777) !== 0o600 || stat.nlink !== 1 || stat.size !== bytes.length) throw new Error();
      return sha;
    }
    try {
      const stat = await handle.stat();
      if (!stat.isFile() || (stat.mode & 0o777) !== 0o600 || stat.nlink !== 1 || stat.size !== 0) throw new Error();
      await writeAll(handle, bytes);
      await handle.sync();
    } finally { await handle.close(); }
    await blobs.sync();
    return sha;
  }

  async function closeHandles() {
    let failed = false;
    for (const [handle, clear] of [[file, () => { file = null; }], [blobs, () => { blobs = null; }], [directory, () => { directory = null; }]]) {
      if (handle) { try { await handle.close(); clear(); } catch { failed = true; } }
    }
    if (failed) { uncertain = true; throw new Error("capture journal uncertain"); }
  }

  try {
    const stat = await io.lstat(options.directory);
    if (!stat.isDirectory() || (stat.mode & 0o777) !== 0o700) throw new Error();
    directoryIdentity = { dev: stat.dev, ino: stat.ino };
    directory = await io.open(options.directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    const opened = await directory.stat();
    if (!opened.isDirectory() || (opened.mode & 0o777) !== 0o700 || opened.dev !== stat.dev || opened.ino !== stat.ino) throw new Error();
    await io.mkdir(blobDirectory, { mode: 0o700 });
    const blobStat = await io.lstat(blobDirectory);
    if (!blobStat.isDirectory() || (blobStat.mode & 0o777) !== 0o700) throw new Error();
    blobsIdentity = { dev: blobStat.dev, ino: blobStat.ino };
    blobs = await io.open(blobDirectory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    file = await io.open(path, constants.O_CREAT | constants.O_EXCL | constants.O_APPEND | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    const openedFile = await file.stat();
    if (!openedFile.isFile() || (openedFile.mode & 0o777) !== 0o600 || openedFile.nlink !== 1 || openedFile.size !== 0) throw new Error();
    fileIdentity = { dev: openedFile.dev, ino: openedFile.ino };
    await append("opened", { requestCount: options.requestIds.length, requestIdsSha256: createHash("sha256").update(JSON.stringify(options.requestIds)).digest("hex") });
    await directory.sync();
    await blobs.sync();
    await verifyIdentity(size);
  } catch {
    await closeHandles().catch(() => {});
    throw new Error("capture journal creation failed");
  }

  const gate = () => { if (busy || closed || uncertain) throw new Error(); };

  async function event(kind, build) {
    let plan;
    try { gate(); plan = build(); } catch { throw new Error("capture journal event refused"); }
    busy = true;
    try {
      const row = await plan();
      await append(kind, row.data);
      row.after?.();
    } catch {
      uncertain = true;
      throw new Error("capture journal uncertain");
    } finally { busy = false; }
  }

  const declaredOperation = (id) => { if (!requestId(id) || !declared.has(id)) throw new Error(); };

  return Object.freeze({
    writeIntent(input) {
      return event("intent", () => {
        const row = record(input, ["operationId", "phase", "targetSha256", "redactedTarget", "mutationKey"]);
        declaredOperation(row.operationId);
        if (intents.has(row.operationId) || !["preflight", "normal", "recovery"].includes(row.phase) || !matches(row.targetSha256, /^[0-9a-f]{64}$/) || typeof row.redactedTarget !== "string" || row.redactedTarget.length > 4096 || redactor.text(row.redactedTarget) !== row.redactedTarget || (row.mutationKey !== null && !matches(row.mutationKey, /^[A-Za-z0-9._/:()-]{1,1100}$/))) throw new Error();
        return async () => ({ data: row, after: () => intents.set(row.operationId, row.targetSha256) });
      });
    },
    writeResponse(input) {
      return event("response", () => {
        const row = record(input, ["operationId", "attempt", "response"]);
        declaredOperation(row.operationId);
        const response = record(row.response, ["status", "rawHeaders", "bytes"]);
        if (!intents.has(row.operationId) || responded.has(row.operationId) || !Number.isSafeInteger(row.attempt) || row.attempt < 1 || !Number.isInteger(response.status) || response.status < 100 || response.status > 599) throw new Error();
        const headers = redactor.headers(stringArray(response.rawHeaders, 512));
        const redacted = redactor.bytes(response.bytes);
        if (redacted.bytes.length > MAX_BLOB_BYTES) throw new Error();
        return async () => {
          const sha = await writeBlob(redacted.bytes);
          return { data: { operationId: row.operationId, attempt: row.attempt, targetSha256: intents.get(row.operationId), status: response.status, rawHeaders: headers, blob: { sha256: sha, bytes: redacted.bytes.length }, originalSha256: redacted.originalSha256, spans: redacted.spans }, after: () => responded.add(row.operationId) };
        };
      });
    },
    writeFacts(input) {
      return event("facts", () => {
        const row = record(input, ["operationId", "kind", "verdict", "facts"]);
        declaredOperation(row.operationId);
        if (!responded.has(row.operationId) || !matches(row.kind, /^[a-z0-9-]{1,48}$/) || !matches(row.verdict, /^[a-z-]{1,24}$/)) throw new Error();
        const facts = plainJson(row.facts);
        const text = JSON.stringify(facts);
        if (redactor.text(text) !== text) throw new Error();
        return async () => ({ data: { operationId: row.operationId, kind: row.kind, verdict: row.verdict, facts } });
      });
    },
    writeProof(input) {
      return event("proof", () => {
        const row = record(input, ["runId", "type", "key", "operationId", "attempt", "valueSha256"]);
        declaredOperation(row.operationId);
        if (row.runId !== options.runId || !matches(row.type, /^[a-z-]{1,32}$/) || typeof row.key !== "string" || row.key.length === 0 || row.key.length > 1024 || redactor.text(row.key) !== row.key || !Number.isSafeInteger(row.attempt) || row.attempt < 1 || !matches(row.valueSha256, /^[0-9a-f]{64}$/)) throw new Error();
        return async () => ({ data: row });
      });
    },
    // What the credential modules learn, as digests only: the counted cache's proofs and the session's token proofs.
    writeCredentialProof(input) {
      return event("credential-proof", () => {
        const proof = plainJson(input);
        if (!plain(proof) || !matches(proof.status, /^[A-Z][A-Z_]{2,63}$/) || proof.sendAuthorized !== false) throw new Error();
        const text = JSON.stringify(proof);
        if (text.length > MAX_EVIDENCE || redactor.text(text) !== text) throw new Error();
        return async () => ({ data: proof });
      });
    },
    // The fixture accounts the run created and proved absent again. Only fixed keys; the address appears as a salted digest.
    writeOwnership(input) {
      return event("ownership", () => {
        const row = record(input, ["account", "project", "uid", "runPrefix", "emailSha256", "creationRequestId"]);
        if (!FIXTURE_ACCOUNTS.has(row.account) || !FIXTURE_PROJECTS.has(row.project) || !matches(row.uid, /^[A-Za-z0-9._-]{1,128}$/) || !matches(row.runPrefix, /^storage-rules-[a-z0-9][a-z0-9-]{0,47}$/) || (row.account !== "foreign-project-token" && !row.uid.startsWith(`${row.runPrefix}-`)) || !matches(row.emailSha256, /^[0-9a-f]{64}$/) || !matches(row.creationRequestId, /^auth\/[a-z-]{1,32}\/(?:create|sign-up)$/)) throw new Error();
        if (redactor.text(JSON.stringify(row)) !== JSON.stringify(row)) throw new Error();
        return async () => ({ data: row });
      });
    },
    writeCleanup(input) {
      return event("cleanup", () => {
        const row = record(input, ["account", "project", "uid", "absent", "requestId"]);
        if (!FIXTURE_ACCOUNTS.has(row.account) || !FIXTURE_PROJECTS.has(row.project) || !matches(row.uid, /^[A-Za-z0-9._-]{1,128}$/) || row.absent !== true || !matches(row.requestId, /^(?:recovery\/)?auth\/[a-z-]{1,32}\/absence$/)) throw new Error();
        if (redactor.text(JSON.stringify(row)) !== JSON.stringify(row)) throw new Error();
        return async () => ({ data: row });
      });
    },
    writeNote(input) {
      return event("note", () => {
        const row = record(input, ["operationId", "text"]);
        if (row.operationId !== null) declaredOperation(row.operationId);
        if (typeof row.text !== "string" || row.text.length === 0 || row.text.length > MAX_NOTE) throw new Error();
        const text = redactor.text(row.text);
        return async () => ({ data: { operationId: row.operationId, text } });
      });
    },
    async close() {
      if (busy) throw new Error("capture journal event refused");
      if (closed && !file && !directory && !blobs) return;
      closed = true; busy = true;
      try { await closeHandles(); } finally { busy = false; }
    },
    snapshot() { return Object.freeze({ busy, uncertain, closed, events: sequence, intents: intents.size, responses: responded.size, sendAuthorized: false }); },
  });
}
