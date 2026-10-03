import * as fs from "node:fs/promises";
import { constants } from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";
import { isDeepStrictEqual } from "node:util";

const DEFAULT_LIMITS = Object.freeze({
  maxRecords: 512,
  maxBytes: 1048576,
  maxReportBytes: 262144,
  deadlineMs: 3000,
});
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const hash = (value) => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
const object = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const identifier = (value) =>
  typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(value);
const keys = (value, names) =>
  object(value) && isDeepStrictEqual(Object.keys(value).sort(), [...names].sort());
const encode = (record) => Buffer.from(`${JSON.stringify(record)}\n`);
const result = (state, reason) => ({
  state,
  reasons: reason ? [reason] : [],
  durabilityAcknowledged: false,
  allDayCertified: false,
  historicalCompleteness: "UNKNOWN",
  externalApprovalVerified: false,
});

function boundedLimits(input = {}) {
  if (!object(input) || Object.keys(input).some((key) => !(key in DEFAULT_LIMITS)))
    throw new Error("Invalid limits");
  const limits = { ...DEFAULT_LIMITS, ...input };
  for (const [key, value] of Object.entries(limits)) {
    if (!Number.isSafeInteger(value) || value < 1 || value > DEFAULT_LIMITS[key])
      throw new Error(`Invalid limit ${key}`);
  }
  return limits;
}

function validScope(scope) {
  if (!keys(scope, ["campaign", "utcDay", "runRoot", "harnessH", "buildPins", "nativeRoot"]))
    return false;
  const pins = scope.buildPins;
  const native = scope.nativeRoot;
  return (
    identifier(scope.campaign) &&
    typeof scope.utcDay === "string" &&
    /^\d{4}-\d{2}-\d{2}$/.test(scope.utcDay) &&
    Number.isFinite(Date.parse(`${scope.utcDay}T00:00:00Z`)) &&
    new Date(`${scope.utcDay}T00:00:00Z`).toISOString().slice(0, 10) === scope.utcDay &&
    typeof scope.runRoot === "string" &&
    path.isAbsolute(scope.runRoot) &&
    scope.runRoot === path.resolve(scope.runRoot) &&
    hash(scope.harnessH) &&
    keys(pins, ["sourceCommit", "binarySha256", "runnerSha256"]) &&
    /^[a-f0-9]{40}$/.test(pins.sourceCommit) &&
    hash(pins.binarySha256) &&
    hash(pins.runnerSha256) &&
    keys(native, ["pid", "start", "sid"]) &&
    Number.isSafeInteger(native.pid) &&
    native.pid > 0 &&
    Number.isSafeInteger(native.sid) &&
    native.sid > 0 &&
    typeof native.start === "string" &&
    native.start.length > 0 &&
    native.start.length <= 256
  );
}

function authorityScope(raw, digest, limits) {
  if (!Buffer.isBuffer(raw) || raw.length > limits.maxBytes || !hash(digest) || sha(raw) !== digest)
    throw new Error("Invalid authority bytes or digest");
  const authority = JSON.parse(raw.toString("utf8"));
  if (
    !keys(authority, ["schema", "authorityId", "scope"]) ||
    authority.schema !== "scoped-attempt-authority/v1" ||
    !identifier(authority.authorityId) ||
    !validScope(authority.scope)
  )
    throw new Error("Invalid authority scope");
  return authority.scope;
}

function reportOutcome(raw, record, scope, attemptId, limits) {
  if (raw === undefined || raw === null) return result("unknown", "Missing raw report");
  if (!Buffer.isBuffer(raw) || raw.length > limits.maxReportBytes)
    return result("unknown", "Unbounded raw report");
  if (raw.length !== record.reportBytes || sha(raw) !== record.reportSha256)
    return result("rejected", "Raw report SHA or byte length mismatch");
  let report;
  try {
    report = JSON.parse(raw.toString("utf8"));
  } catch {
    return result("unknown", "Unparseable raw report");
  }
  if (
    !object(report) ||
    report.schema !== "attempt-report/v1" ||
    !report.scope ||
    !report.attemptId
  )
    return result("unknown", "Incomplete raw report");
  if (!isDeepStrictEqual(report.scope, scope) || report.attemptId !== attemptId)
    return result("rejected", "Foreign report scope or attempt");
  if (report.outcome !== "pass" && report.outcome !== "fail")
    return result("unknown", "Inconclusive raw report");
  return result("complete");
}

// This pure validator establishes only consistency of the supplied scoped records.
// It cannot authenticate owner approval or inventory any historical campaign.
export function reduceAttemptRecords(
  scope,
  records,
  { reports = new Map(), limits: inputLimits } = {},
) {
  let limits;
  try {
    limits = boundedLimits(inputLimits);
  } catch {
    return result("rejected", "Invalid limits");
  }
  if (!validScope(scope) || !Array.isArray(records) || !(reports instanceof Map))
    return result("rejected", "Invalid scoped records");
  if (records.length + 1 > limits.maxRecords) return result("unknown", "Record limit exceeded");
  const births = new Map();
  let sealed = false;
  let unknown = false;
  for (let index = 0; index < records.length; index++) {
    const record = records[index];
    if (
      !object(record) ||
      record.seq !== index + 1 ||
      !isDeepStrictEqual(record.scope, scope) ||
      sealed
    )
      return result("rejected", "Sequence, scope or sealed admission mismatch");
    if (record.type === "birth") {
      if (
        !keys(record, ["type", "seq", "scope", "attemptId", "planSha256"]) ||
        !identifier(record.attemptId) ||
        !hash(record.planSha256) ||
        births.has(record.attemptId)
      )
        return result("rejected", "Invalid or duplicate birth");
      births.set(record.attemptId, { seq: record.seq, terminal: false });
    } else if (record.type === "terminal") {
      const birth = births.get(record.attemptId);
      if (
        !keys(record, [
          "type",
          "seq",
          "scope",
          "attemptId",
          "reportFile",
          "reportSha256",
          "reportBytes",
        ]) ||
        !birth ||
        birth.terminal
      )
        return result("rejected", "Terminal without unique birth");
      if (record.reportFile === null) {
        if (record.reportSha256 !== null || record.reportBytes !== 0)
          return result("rejected", "Invalid missing report reference");
        unknown = true;
      } else {
        if (
          record.reportFile !== `report-${birth.seq}.json` ||
          !hash(record.reportSha256) ||
          !Number.isSafeInteger(record.reportBytes) ||
          record.reportBytes < 0
        )
          return result("rejected", "Invalid report reference");
        const outcome = reportOutcome(
          reports.get(record.reportFile),
          record,
          scope,
          record.attemptId,
          limits,
        );
        if (outcome.state === "rejected") return outcome;
        if (outcome.state === "unknown") unknown = true;
      }
      birth.terminal = true;
    } else if (record.type === "seal") {
      if (
        !keys(record, ["type", "seq", "scope", "tail", "births"]) ||
        record.tail !== index ||
        record.births !== births.size ||
        births.size === 0 ||
        [...births.values()].some((birth) => !birth.terminal)
      )
        return result("rejected", "Unknown writers or incorrect sealed tail");
      sealed = true;
    } else return result("rejected", "Unrecognized record");
  }
  return result(
    unknown ? "unknown" : sealed ? "complete" : "open",
    unknown ? "Unresolved terminal evidence" : undefined,
  );
}

export function validateAttemptLedger({
  authorityBytes,
  authoritySha256,
  ledgerBytes,
  reports = new Map(),
  limits: inputLimits,
} = {}) {
  let limits;
  let scope;
  try {
    limits = boundedLimits(inputLimits);
    if (Buffer.isBuffer(authorityBytes) && authorityBytes.length > limits.maxBytes)
      return result("unknown", "Authority byte limit exceeded");
    scope = authorityScope(authorityBytes, authoritySha256, limits);
  } catch {
    return result("rejected", "Invalid authority or limits");
  }
  if (!Buffer.isBuffer(ledgerBytes) || ledgerBytes.length > limits.maxBytes)
    return result("unknown", "Missing or unbounded ledger bytes");
  if (ledgerBytes.length === 0 || ledgerBytes.at(-1) !== 10)
    return result("unknown", "Unresolved ledger tail");
  const lines = ledgerBytes.toString("utf8").slice(0, -1).split("\n");
  if (lines.length > limits.maxRecords) return result("unknown", "Record limit exceeded");
  let records;
  try {
    records = lines.map((line) => {
      const record = JSON.parse(line);
      if (JSON.stringify(record) !== line) throw new Error("Noncanonical or duplicate members");
      return record;
    });
  } catch {
    return result("unknown", "Unparseable ledger bytes");
  }
  const header = records.shift();
  if (
    !keys(header, ["type", "seq", "scope", "authoritySha256"]) ||
    header.type !== "header" ||
    header.seq !== 0 ||
    header.authoritySha256 !== authoritySha256 ||
    !isDeepStrictEqual(header.scope, scope)
  )
    return result("rejected", "Foreign header authority");
  const verdict = reduceAttemptRecords(scope, records, { reports, limits });
  return verdict.state === "open"
    ? result("unknown", "Unsealed ledger; historical tail unknown")
    : verdict;
}

// A fresh, fixed child directory is exclusively owned for this handle's lifetime.
// The caller must exclusively control its namespace and forbid external writers.
// Readback rechecks detect observed interference; they are not an atomic snapshot
// against arbitrary concurrent writers. Published authority/report bytes are immutable.
// No recovery takeover, directory discovery, producer launch or process probing is performed.
// The caller must await registerBirth before any attempt side effect. An ack means
// full write, file sync, directory sync when publishing, and exact readback succeeded.
// Deadline expiry does not cancel a kernel syscall; it permanently denies further ack.
export async function createAttemptLedger({
  authorityBytes,
  authoritySha256,
  limits: inputLimits,
  io = fs,
  now = Date.now,
} = {}) {
  const limits = boundedLimits(inputLimits);
  const retainedAuthority = Buffer.isBuffer(authorityBytes)
    ? Buffer.from(authorityBytes)
    : authorityBytes;
  const scope = authorityScope(retainedAuthority, authoritySha256, limits);
  const runRoot = scope.runRoot;
  const directory = path.join(runRoot, "attempt-ledger");
  const journalPath = path.join(directory, "ledger.jsonl");
  const authorityPath = path.join(directory, "authority.json");
  const handles = new Set();
  const identities = new Map();
  const records = [];
  const reports = new Map();
  let journal;
  let parent;
  let dir;
  let offset = 0;
  let busy = false;
  let admissionClosed = false;
  let closed = false;
  let poison = null;
  let sealedAck = false;
  let deadline;
  const fail = (message) => {
    poison ??= message;
    return new Error(`Ledger unknown: ${poison}`);
  };
  const checkDay = () => {
    if (new Date(now()).toISOString().slice(0, 10) !== scope.utcDay)
      throw new Error("UTC day differs from frozen scope");
  };
  function checkLive(operationDeadline) {
    if (closed || poison) throw fail(poison || "closed during operation");
    if (Date.now() >= operationDeadline) throw fail("deadline expired");
    checkDay();
  }
  async function syscall(action, cleanup = false, syscallDeadline = deadline) {
    if (!cleanup) checkLive(syscallDeadline);
    const remaining = syscallDeadline - Date.now();
    if (remaining <= 0) throw fail("deadline expired");
    let timer;
    try {
      const value = await Promise.race([
        Promise.resolve().then(action),
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(fail("unresolved syscall deadline")), remaining);
        }),
      ]);
      if (!cleanup) checkLive(syscallDeadline);
      else if (Date.now() >= syscallDeadline) throw fail("cleanup deadline expired");
      return value;
    } finally {
      clearTimeout(timer);
    }
  }
  async function open(file, flags) {
    return syscall(async () => {
      const handle = await io.open(file, flags, 0o600);
      handles.add(handle);
      // If open resolved after its caller timed out, do not leak the late handle.
      if (closed || poison) {
        await handle.close();
        handles.delete(handle);
        throw fail("late open");
      }
      return handle;
    });
  }
  async function release(handle, cleanupDeadline = deadline) {
    try {
      await syscall(() => handle.close(), true, cleanupDeadline);
      handles.delete(handle);
    } catch (error) {
      throw fail(error.message);
    }
  }
  async function pin(file, handle, directoryExpected = false) {
    const stat = await syscall(() => io.lstat(file));
    const actual = await syscall(() => handle.stat());
    const previous = identities.get(file);
    if (
      stat.isSymbolicLink() ||
      (directoryExpected ? !stat.isDirectory() : !stat.isFile() || stat.nlink !== 1) ||
      stat.dev !== actual.dev ||
      stat.ino !== actual.ino ||
      (previous && (previous.dev !== stat.dev || previous.ino !== stat.ino)) ||
      (await syscall(() => io.realpath(file))) !== file
    )
      throw fail("root alias or substituted filesystem identity");
    identities.set(file, { dev: stat.dev, ino: stat.ino, directoryExpected });
  }
  async function guard() {
    checkDay();
    for (const [file, identity] of identities) {
      const stat = await syscall(() => io.lstat(file));
      if (
        stat.isSymbolicLink() ||
        (!identity.directoryExpected && stat.nlink !== 1) ||
        stat.dev !== identity.dev ||
        stat.ino !== identity.ino ||
        (await syscall(() => io.realpath(file))) !== file
      )
        throw fail("substituted filesystem identity");
    }
  }
  async function read(handle, maximum) {
    const stat = await syscall(() => handle.stat());
    if (!Number.isSafeInteger(stat.size) || stat.size < 0 || stat.size > maximum)
      throw fail("byte limit exceeded");
    const buffer = Buffer.alloc(stat.size);
    let position = 0;
    while (position < buffer.length) {
      const { bytesRead } = await syscall(() =>
        handle.read(buffer, position, buffer.length - position, position),
      );
      if (!Number.isInteger(bytesRead) || bytesRead <= 0 || bytesRead > buffer.length - position)
        throw fail("read made zero or invalid progress");
      position += bytesRead;
    }
    return buffer;
  }
  async function fullWrite(handle, raw, position = 0) {
    let written = 0;
    while (written < raw.length) {
      const { bytesWritten } = await syscall(() =>
        handle.write(raw, written, raw.length - written, position + written),
      );
      if (
        !Number.isInteger(bytesWritten) ||
        bytesWritten <= 0 ||
        bytesWritten > raw.length - written
      )
        throw fail("write made zero or invalid progress");
      written += bytesWritten;
    }
    await syscall(() => handle.sync());
  }
  async function publish(file, raw) {
    const handle = await open(
      file,
      constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | constants.O_NOFOLLOW,
    );
    try {
      await pin(file, handle);
      await fullWrite(handle, raw);
      await syscall(() => dir.sync());
      const retained = await read(handle, raw.length);
      if (!retained.equals(raw)) throw fail("published raw readback mismatch");
    } finally {
      await release(handle);
    }
  }
  async function append(record) {
    const raw = encode(record);
    if (records.length + 1 >= limits.maxRecords || offset + raw.length > limits.maxBytes)
      throw fail("ledger finite bound exceeded");
    await guard();
    const before = await read(journal, limits.maxBytes);
    const expected = Buffer.concat([
      encode({ type: "header", seq: 0, scope, authoritySha256 }),
      ...records.map(encode),
    ]);
    if (!before.equals(expected)) throw fail("journal tail altered before append");
    await fullWrite(journal, raw, offset);
    const after = await read(journal, limits.maxBytes);
    if (!after.equals(Buffer.concat([before, raw]))) throw fail("journal readback mismatch");
    await guard();
    records.push(record);
    offset += raw.length;
  }
  async function operation(action, commitsSeal = false) {
    if (closed) throw new Error("Ledger closed");
    if (poison) throw fail(poison);
    if (busy) throw new Error("Concurrent ledger operation rejected");
    busy = true;
    const operationDeadline = Date.now() + limits.deadlineMs;
    deadline = operationDeadline;
    try {
      await guard();
      const value = await action();
      checkLive(operationDeadline);
      if (commitsSeal) sealedAck = true;
      return value;
    } catch (error) {
      throw fail(error.message);
    } finally {
      busy = false;
    }
  }
  async function close() {
    if (closed && handles.size === 0) return;
    closed = true;
    admissionClosed = true;
    let failure;
    for (const handle of [...handles]) {
      try {
        await release(handle, Date.now() + limits.deadlineMs);
      } catch (error) {
        failure ??= error;
      }
    }
    if (failure) throw failure;
  }
  async function verifyAuthority() {
    const authority = await open(authorityPath, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      await pin(authorityPath, authority);
      if (!(await read(authority, limits.maxBytes)).equals(retainedAuthority))
        throw fail("authority raw bytes mismatch");
    } finally {
      await release(authority);
    }
  }
  async function refreshReports() {
    for (const record of records.filter(
      (record) => record.type === "terminal" && record.reportFile !== null,
    )) {
      const file = path.join(directory, record.reportFile);
      const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
      try {
        await pin(file, handle);
        reports.set(record.reportFile, await read(handle, limits.maxReportBytes));
      } finally {
        await release(handle);
      }
    }
  }
  try {
    deadline = Date.now() + limits.deadlineMs;
    checkDay();
    parent = await open(runRoot, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    await pin(runRoot, parent, true);
    await syscall(() => io.mkdir(directory, { mode: 0o700 }));
    await syscall(() => parent.sync());
    dir = await open(directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    await pin(directory, dir, true);
    await publish(authorityPath, retainedAuthority);
    journal = await open(
      journalPath,
      constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | constants.O_NOFOLLOW,
    );
    await pin(journalPath, journal);
    const header = encode({ type: "header", seq: 0, scope, authoritySha256 });
    if (header.length > limits.maxBytes) throw fail("header byte bound exceeded");
    await fullWrite(journal, header);
    await syscall(() => dir.sync());
    if (!(await read(journal, limits.maxBytes)).equals(header))
      throw fail("header readback mismatch");
    offset = header.length;
  } catch (error) {
    try {
      await close();
    } catch {
      /* An unresolved close is also unknown, never an ack. */
    }
    throw error;
  }
  return Object.freeze({
    ioStatus() {
      // A successful seal is a historical owned-I/O acknowledgement, not a fresh
      // filesystem readback. Sticky unknown invalidates it; producer certification
      // must independently acquire and validate its immutable supplied snapshot.
      if (poison) return result("unknown", poison);
      if (sealedAck) return { ...result("complete"), durabilityAcknowledged: true };
      if (closed) return result("unknown", "Closed without durable seal");
      return reduceAttemptRecords(scope, records, { reports, limits });
    },
    async registerBirth({ attemptId, planBytes } = {}) {
      if (admissionClosed) throw new Error("Birth admission closed");
      if (
        !identifier(attemptId) ||
        !Buffer.isBuffer(planBytes) ||
        planBytes.length > limits.maxReportBytes
      )
        throw new Error("Invalid bounded birth");
      if (records.some((record) => record.type === "birth" && record.attemptId === attemptId))
        throw new Error("Duplicate birth rejected");
      const planSha256 = sha(Buffer.from(planBytes));
      return operation(async () => {
        const record = { type: "birth", seq: records.length + 1, scope, attemptId, planSha256 };
        await append(record);
        return { seq: record.seq, attemptId, durable: true };
      });
    },
    async recordTerminal({ attemptId, reportBytes: raw } = {}) {
      if (admissionClosed) throw new Error("Terminal admission closed");
      const birth = records.find(
        (record) => record.type === "birth" && record.attemptId === attemptId,
      );
      if (
        !birth ||
        records.some((record) => record.type === "terminal" && record.attemptId === attemptId)
      )
        throw new Error("Terminal requires unique unfinished birth");
      if (raw !== null && (!Buffer.isBuffer(raw) || raw.length > limits.maxReportBytes))
        throw new Error("Invalid bounded report bytes");
      const retained = raw === null ? null : Buffer.from(raw);
      return operation(async () => {
        const reportFile = retained === null ? null : `report-${birth.seq}.json`;
        if (retained !== null) await publish(path.join(directory, reportFile), retained);
        const record = {
          type: "terminal",
          seq: records.length + 1,
          scope,
          attemptId,
          reportFile,
          reportSha256: retained === null ? null : sha(retained),
          reportBytes: retained?.length ?? 0,
        };
        await append(record);
        if (retained !== null) reports.set(reportFile, retained);
        return { seq: record.seq, attemptId, durable: true };
      });
    },
    async seal() {
      if (admissionClosed) throw new Error("Ledger admission closed or sealed");
      admissionClosed = true;
      if (busy) throw fail("seal raced an accepted writer");
      return operation(async () => {
        const seal = {
          type: "seal",
          seq: records.length + 1,
          scope,
          tail: records.length,
          births: records.filter((record) => record.type === "birth").length,
        };
        await verifyAuthority();
        // Re-read every bound report before fixing the tail. Cached bytes are not evidence.
        await refreshReports();
        const verdict = reduceAttemptRecords(scope, [...records, seal], { reports, limits });
        if (verdict.state !== "complete")
          throw fail(verdict.reasons.join("; ") || "unknown terminal");
        await append(seal);
        await verifyAuthority();
        await refreshReports();
        await guard();
        const ledgerBytes = await read(journal, limits.maxBytes);
        // The final journal await is also an interference/lifecycle boundary.
        await verifyAuthority();
        await refreshReports();
        await guard();
        const final = validateAttemptLedger({
          authorityBytes: retainedAuthority,
          authoritySha256,
          ledgerBytes,
          reports,
          limits,
        });
        if (final.state !== "complete") throw fail("final sealed readback unknown");
        return { ...final, durabilityAcknowledged: true };
      }, true);
    },
    close,
  });
}
