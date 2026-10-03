import { createHash } from "node:crypto";
import { createStreamingWriteGate } from "./streaming-write-gate.mjs";
import { createStreamingReceiptQueue } from "./streaming-receipts.mjs";
import { createStreamingJournal } from "./streaming-journal.mjs";
import { reduceStreamingProvenance } from "./streaming-provenance.mjs";
import { validateCredential } from "./streaming-frames.mjs";

const PATH = "/google.pubsub.v1.Subscriber/StreamingPull";
const STOP_ROWS = 4;
const STOP_BYTES = 256;
const causes = new Set([
  "client-cancel",
  "abort",
  "deadline",
  "close",
  "reset",
  "revocation",
  "uncertain",
]);
const metadataKeys = new Set(["authorization", "x-goog-request-params", "x-goog-user-project"]);
const limitKeys = [
  "maxActions",
  "maxFrames",
  "maxFrameBytes",
  "maxOutgoingBytes",
  "maxIncomingBytes",
  "maxIncomingFrames",
  "maxChunks",
  "maxHeaderBytes",
  "maxHeaderEvents",
  "maxHeaderPairs",
  "maxEvents",
  "maxNativeCallbacks",
  "maxChronologyRows",
  "maxJournalEntries",
  "maxEntryBytes",
  "maxJournalBytes",
  "maxMessageBytes",
  "maxWriterRows",
  "maxWriterRecordBytes",
  "maxWriterBytes",
];
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
function positive(value) {
  if (!Number.isSafeInteger(value) || value <= 0)
    throw new Error("finite positive bounds required");
  return value;
}
function liveDeadline(deadlineAt) {
  const remaining = deadlineAt - performance.now();
  if (!Number.isFinite(deadlineAt) || remaining <= 0 || remaining > 2147483647)
    throw new Error("live bounded absolute deadline required");
  return remaining;
}
function ownData(object, allowed) {
  if (
    !object ||
    typeof object !== "object" ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(object))
  )
    throw new Error("closed own-data object required");
  for (const key of Reflect.ownKeys(object))
    if (!allowed.has(key) || !Object.hasOwn(Object.getOwnPropertyDescriptor(object, key), "value"))
      throw new Error("closed own-data object required");
}
function checked(value) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error("capacity arithmetic overflow");
  return value;
}
function validateLimits(input) {
  ownData(input, new Set(limitKeys));
  const limits = {};
  for (const key of limitKeys) limits[key] = positive(input[key]);
  if (limits.maxFrameBytes > 4294967295) throw new Error("finite wire bound required");
  const normalRows = checked(5 * limits.maxActions + limits.maxEvents + limits.maxNativeCallbacks);
  const chronologyRows = checked(3 * limits.maxActions + limits.maxNativeCallbacks + STOP_ROWS);
  const minimumEntry = checked(
    1024 +
      6 * limits.maxHeaderBytes +
      16 * limits.maxHeaderPairs +
      4 * Math.ceil(Math.max(limits.maxIncomingBytes, limits.maxFrameBytes + 5) / 3),
  );
  const physicalRecord = checked(256 + 4 * Math.ceil(limits.maxEntryBytes / 3));
  if (
    limits.maxJournalEntries < checked(normalRows + STOP_ROWS) ||
    limits.maxChronologyRows < chronologyRows ||
    limits.maxEntryBytes < minimumEntry ||
    limits.maxJournalBytes < checked(normalRows * limits.maxEntryBytes + STOP_ROWS * STOP_BYTES) ||
    limits.maxWriterRows < limits.maxJournalEntries ||
    limits.maxWriterRecordBytes < physicalRecord ||
    limits.maxWriterBytes < checked(limits.maxWriterRows * limits.maxWriterRecordBytes)
  )
    throw new Error("conservative shared and reserved capacities required");
  return { limits, normalRows };
}
function admittedEndpoint(authority) {
  if (typeof authority !== "string" || authority.length > 128)
    throw new Error("bare admitted authority required");
  const endpoint = new URL(authority);
  if (
    endpoint.origin !== authority ||
    (authority !== "https://pubsub.googleapis.com" &&
      !(
        endpoint.protocol === "http:" &&
        ["localhost", "127.0.0.1", "[::1]"].includes(endpoint.hostname)
      ))
  )
    throw new Error("bare admitted authority required");
  return endpoint;
}
function admittedMetadata(metadata, credential) {
  ownData(metadata, metadataKeys);
  let total = 0;
  const snapshot = {};
  for (const key of Reflect.ownKeys(metadata)) {
    const value = metadata[key];
    if (typeof value !== "string" || value.length > 16391 || /[\r\n]/.test(value))
      throw new Error("bounded metadata required");
    const size = Buffer.byteLength(value);
    if (size > 16391) throw new Error("bounded metadata required");
    total += Buffer.byteLength(key) + size;
    if (total > 32768) throw new Error("bounded metadata required");
    if (key === "authorization" && (credential === undefined || value !== `Bearer ${credential}`))
      throw new Error("bound authorization required");
    snapshot[key] = value;
  }
  return Object.freeze(snapshot);
}
function wireTimeout(deadlineAt) {
  const remaining = deadlineAt - performance.now();
  for (const [unit, scale] of [
    ["n", 1e-6],
    ["u", 1e-3],
    ["m", 1],
    ["S", 1000],
    ["M", 60000],
    ["H", 3600000],
  ]) {
    const value = Math.floor(remaining / scale);
    if (value >= 1 && value <= 99999999) return `${value}${unit}`;
  }
  throw new Error("native deadline expired");
}
async function bounded(work, deadlineAt) {
  let timer;
  const expired = new Promise((_, reject) => {
    timer = setTimeout(
      () => reject(new Error("absolute deadline")),
      Math.max(0, deadlineAt - performance.now()),
    );
  });
  try {
    return await Promise.race([work, expired]);
  } finally {
    clearTimeout(timer);
  }
}

/** Caller owns exclusively created handles and closes them after all underlying calls settle. */
export function createOwnedJournalWriter({ fileHandle, directoryHandle, deadlineAt, limits }) {
  liveDeadline(deadlineAt);
  for (const key of ["maxWriterRows", "maxWriterRecordBytes", "maxWriterBytes"])
    positive(limits?.[key]);
  if (
    typeof fileHandle?.write !== "function" ||
    typeof fileHandle?.sync !== "function" ||
    typeof directoryHandle?.sync !== "function"
  )
    throw new Error("owned file and directory handles required");
  let attemptedRows = 0,
    acknowledgedRows = 0,
    totalBytes = 0,
    busy = false,
    failed = false;
  const check = (signal) => {
    if (failed || signal?.aborted || performance.now() >= deadlineAt)
      throw new Error("writer stopped");
  };
  async function write(row, { signal } = {}) {
    try {
      check(signal);
      if (busy) throw new Error("writer overlap");
      ownData(row, new Set(["index", "bodyBase64", "bodyBytes", "sha256"]));
      if (
        row.index !== attemptedRows ||
        !Number.isSafeInteger(row.index) ||
        typeof row.bodyBase64 !== "string" ||
        row.bodyBase64.length > limits.maxWriterRecordBytes ||
        !Number.isSafeInteger(row.bodyBytes) ||
        row.bodyBytes < 0 ||
        row.bodyBytes > limits.maxWriterRecordBytes ||
        typeof row.sha256 !== "string" ||
        row.sha256.length !== 64 ||
        !/^[a-f0-9]{64}$/.test(row.sha256)
      )
        throw new Error("canonical ordered journal row required");
      const body = Buffer.from(row.bodyBase64, "base64");
      if (
        body.toString("base64") !== row.bodyBase64 ||
        body.length !== row.bodyBytes ||
        sha(body) !== row.sha256
      )
        throw new Error("journal body binding mismatch");
      const record = Buffer.from(
        JSON.stringify({
          index: row.index,
          bodyBase64: row.bodyBase64,
          bodyBytes: row.bodyBytes,
          sha256: row.sha256,
        }) + "\n",
      );
      if (
        attemptedRows >= limits.maxWriterRows ||
        record.length > limits.maxWriterRecordBytes ||
        record.length > limits.maxWriterBytes - totalBytes
      )
        throw new Error("writer bound");
      busy = true;
      attemptedRows++;
      const position = totalBytes;
      totalBytes += record.length;
      const result = await bounded(
        Promise.resolve().then(() => {
          check(signal);
          return fileHandle.write(record, 0, record.length, position);
        }),
        deadlineAt,
      );
      check(signal);
      if (result?.bytesWritten !== record.length) throw new Error("short journal write");
      await bounded(
        Promise.resolve().then(() => {
          check(signal);
          return fileHandle.sync();
        }),
        deadlineAt,
      );
      check(signal);
      await bounded(
        Promise.resolve().then(() => {
          check(signal);
          return directoryHandle.sync();
        }),
        deadlineAt,
      );
      check(signal);
      acknowledgedRows++;
    } catch {
      failed = true;
      throw new Error("journal acknowledgement unavailable");
    } finally {
      busy = false;
    }
  }
  return { write, report: () => ({ attemptedRows, acknowledgedRows, totalBytes, busy, failed }) };
}

/** Injected ownership only: no connection, discovery, retries, native completeness or crash proof. */
export function createOwnedStreamingBridge({
  session,
  authority,
  path,
  metadata = {},
  deadlineAt,
  signal,
  limits: inputLimits,
  guard,
  liveCheck,
  write,
  onFrame,
  credential,
}) {
  const remaining = liveDeadline(deadlineAt);
  const { limits, normalRows } = validateLimits(inputLimits);
  const endpoint = admittedEndpoint(authority);
  validateCredential(credential);
  const wireMetadata = admittedMetadata(metadata, credential);
  if (path !== PATH) throw new Error("StreamingPull path required");
  for (const callback of [guard, liveCheck, write, onFrame])
    if (typeof callback !== "function") throw new Error("owned callbacks required");
  if (
    typeof session?.request !== "function" ||
    typeof session?.destroy !== "function" ||
    typeof session?.on !== "function" ||
    typeof session?.removeListener !== "function"
  )
    throw new Error("owned native session required");
  let stream, gate, receipts, journal, donePromise;
  let admissionClosed = false,
    stopping = false,
    cancelIssued = false,
    destroyIssued = false,
    streamClosed = false,
    sessionClosed = false,
    encodingAllowed = true,
    draining = false;
  let nextSeq = 0,
    normalEntries = 0,
    normalBytes = 0,
    reservedEntries = 0,
    reservedBytes = 0,
    nativeCallbacks = 0,
    lostCallbacks = 0,
    nextReceiptIndex = 0;
  const chronology = [],
    bindings = [],
    pendingBindings = new Map(),
    reasons = new Set(),
    listeners = [];
  let resolveClosure;
  const closure = new Promise((resolve) => {
    resolveClosure = resolve;
  });
  const closureCheck = () => {
    if (sessionClosed && (!stream || streamClosed)) resolveClosure();
  };
  const unknown = (why) => {
    reasons.add(why);
  };
  const localCause = (cause) =>
    causes.has(cause) ? (cause === "local-close" ? "close" : cause) : "uncertain";
  function seq() {
    if (nextSeq >= Number.MAX_SAFE_INTEGER) {
      unknown("sequence-bound");
      stopNow("uncertain");
      return null;
    }
    return nextSeq++;
  }
  function projection(row, reserved = false) {
    if (chronology.length >= limits.maxChronologyRows - (reserved ? 0 : STOP_ROWS)) {
      unknown("chronology-bound");
      stopNow("uncertain");
      return null;
    }
    chronology.push(row);
    return row;
  }
  function store(body, row, reserved = false, binding) {
    if (!journal) {
      unknown("journal-unavailable");
      return null;
    }
    const bytes = Buffer.from(JSON.stringify(body));
    if (
      bytes.length > (reserved ? STOP_BYTES : limits.maxEntryBytes) ||
      (!reserved &&
        (normalEntries >= normalRows ||
          bytes.length > limits.maxJournalBytes - STOP_ROWS * STOP_BYTES - normalBytes)) ||
      (reserved &&
        (reservedEntries >= STOP_ROWS || bytes.length > STOP_ROWS * STOP_BYTES - reservedBytes))
    ) {
      unknown("journal-capacity");
      stopNow("uncertain");
      return null;
    }
    if (reserved) {
      reservedEntries++;
      reservedBytes += bytes.length;
    } else {
      normalEntries++;
      normalBytes += bytes.length;
    }
    let ticket;
    try {
      ticket = journal.append(bytes);
    } catch {
      unknown("journal-refusal");
      stopNow("uncertain");
      return null;
    }
    if (binding) {
      binding.journalIndex = ticket.index;
      binding.state = "pending";
    }
    ticket.committed.then(
      (ack) => {
        if (
          ack.index !== ticket.index ||
          ack.bodyBytes !== bytes.length ||
          ack.sha256 !== sha(bytes)
        ) {
          unknown("ticket-mismatch");
          stopNow("uncertain");
          return;
        }
        if (row) row.committed = true;
        if (binding) binding.state = "committed";
      },
      () => {
        unknown("uncommitted-record");
        if (binding) binding.state = "uncommitted";
        stopNow("uncertain");
      },
    );
    return ticket;
  }
  function marker(event, reserved = false) {
    const value = seq();
    if (value === null) return null;
    const row = projection({ kind: "marker", seq: value, committed: false, event }, reserved);
    if (row) store({ type: "native", row }, row, reserved);
    return row;
  }
  function stopNow(cause = "uncertain", haltGate = true) {
    if (stopping) return closure;
    stopping = true;
    admissionClosed = true;
    cause = cause === "local-close" ? "close" : localCause(cause);
    const value = seq();
    if (value !== null) {
      const row = projection(
        { kind: "local-stop-entry", seq: value, committed: false, cause },
        true,
      );
      if (row) store({ type: "stop", row }, row, true);
    }
    if (haltGate)
      gate?.stop(
        cause === "close"
          ? "local-close"
          : ["client-cancel", "abort", "deadline", "revocation"].includes(cause)
            ? cause
            : "uncertain",
      );
    if (stream && !cancelIssued) {
      cancelIssued = true;
      try {
        stream.close(8);
      } catch {
        unknown("native-cancel-throw");
      }
    }
    if (!destroyIssued) {
      destroyIssued = true;
      try {
        session.destroy();
      } catch {
        unknown("native-destroy-throw");
      }
    }
    marker("local-stop-return", true);
    closureCheck();
    return closure;
  }
  function nativeAdmission() {
    if (nativeCallbacks >= limits.maxNativeCallbacks) {
      lostCallbacks = Math.min(Number.MAX_SAFE_INTEGER, lostCallbacks + 1);
      unknown("native-callback-bound");
      stopNow("uncertain");
      return false;
    }
    nativeCallbacks++;
    return true;
  }
  function capture(kind, raw, flags = 0) {
    if (!nativeAdmission()) return;
    const value = seq();
    if (value === null) return;
    if (draining) {
      lostCallbacks++;
      unknown("callback-after-drain");
      return;
    }
    if (kind === "data" && !encodingAllowed) {
      lostCallbacks++;
      unknown("nonidentity-data-refused");
      stopNow("uncertain");
      return;
    }
    const row = projection(
      kind === "data"
        ? {
            kind,
            seq: value,
            committed: false,
            bodyBytes: ArrayBuffer.isView(raw) ? raw.byteLength : 0,
          }
        : { kind, seq: value, committed: false, flags, rawHeaders: [] },
    );
    if (!row) return;
    const binding = { seq: value, kind, receiptIndex: nextReceiptIndex, state: "tentative" };
    if (bindings.length >= limits.maxEvents) {
      lostCallbacks++;
      unknown("receipt-binding-bound");
      stopNow("uncertain");
      return;
    }
    if (pendingBindings.has(nextReceiptIndex)) {
      lostCallbacks++;
      unknown("receipt-index-collision");
      stopNow("uncertain");
      return;
    }
    bindings.push(binding);
    pendingBindings.set(nextReceiptIndex, { row, binding });
    let admitted = false;
    try {
      admitted = kind === "data" ? receipts.data(raw) : receipts.headers(kind, raw, flags);
    } catch {
      unknown("receipt-capture-throw");
      stopNow("uncertain");
    }
    if (admitted) {
      nextReceiptIndex++;
      if (kind !== "data") {
        row.rawHeaders = raw.slice();
        for (let i = 0; i < raw.length; i += 2)
          if (raw[i] === "grpc-encoding" && raw[i + 1] !== "identity") {
            encodingAllowed = false;
            unknown("nonidentity-encoding");
            stopNow("uncertain");
          }
      }
    } else {
      lostCallbacks++;
      unknown("receipt-refused");
      if (kind !== "data") {
        pendingBindings.delete(binding.receiptIndex);
        binding.state = "raw-absent";
      }
      stopNow("uncertain");
    }
  }
  function lifecycle(event, queueKind, stopCause) {
    if (!nativeAdmission()) return;
    const value = seq();
    if (value === null) return;
    const row = projection({ kind: "marker", seq: value, committed: false, event });
    if (!row) return;
    if (draining) {
      lostCallbacks++;
      unknown("callback-after-drain");
      return;
    }
    const binding = {
      seq: value,
      kind: queueKind,
      receiptIndex: nextReceiptIndex,
      state: "tentative",
    };
    if (bindings.length >= limits.maxEvents || pendingBindings.has(nextReceiptIndex)) {
      unknown("receipt-binding-bound");
      lostCallbacks++;
      stopNow("uncertain");
      return;
    }
    bindings.push(binding);
    pendingBindings.set(nextReceiptIndex, { row, binding });
    if (receipts.lifecycle(queueKind)) nextReceiptIndex++;
    else {
      binding.state = "raw-absent";
      pendingBindings.delete(binding.receiptIndex);
      lostCallbacks++;
      unknown("receipt-refused");
    }
    if (stopCause) {
      unknown("native-lifecycle-stop");
      stopNow(stopCause);
    }
  }
  function closed(which) {
    if (which === "stream") {
      if (streamClosed) {
        unknown("duplicate-close");
        return;
      }
      streamClosed = true;
    } else {
      if (sessionClosed) {
        unknown("duplicate-close");
        return;
      }
      sessionClosed = true;
    }
    marker("native-close-ack", true);
    closureCheck();
    if (!stopping) {
      unknown("unexpected-native-close");
      stopNow("close");
    }
  }
  function listen(owner, event, callback) {
    owner.on(event, callback);
    listeners.push([owner, event, callback]);
  }
  function bindStream() {
    for (const kind of ["response", "headers", "trailers"])
      listen(stream, kind, (_headers, flags, raw) =>
        capture(kind === "headers" ? "additional" : kind, raw, flags),
      );
    listen(stream, "data", (bytes) => capture("data", bytes));
    listen(stream, "end", () => lifecycle("peer-end", "end"));
    listen(stream, "close", () => closed("stream"));
    listen(stream, "error", () => lifecycle("peer-error", "error", "uncertain"));
    listen(stream, "aborted", () => lifecycle("peer-reset", "reset", "reset"));
    listen(stream, "frameError", () => lifecycle("peer-error", "error", "uncertain"));
    listen(stream, "timeout", () => lifecycle("peer-error", "error", "deadline"));
  }
  listen(session, "close", () => closed("session"));
  listen(session, "error", () => {
    if (receipts) lifecycle("peer-error", "error", "uncertain");
    else {
      unknown("constructor-native-error");
      stopNow("uncertain");
    }
  });
  listen(session, "goaway", () => {
    if (receipts) lifecycle("peer-goaway", "goaway", "uncertain");
    else {
      unknown("constructor-native-goaway");
      stopNow("uncertain");
    }
  });
  journal = createStreamingJournal({
    maxEntries: limits.maxJournalEntries,
    maxEntryBytes: limits.maxEntryBytes,
    maxTotalBytes: limits.maxJournalBytes,
    deadlineAt,
    write,
    stopOwned: () => stopNow("uncertain"),
  });
  const wallMs = Math.ceil(remaining);
  receipts = createStreamingReceiptQueue({
    maxFrameBytes: limits.maxFrameBytes,
    maxTotalBytes: limits.maxIncomingBytes,
    maxFrames: limits.maxIncomingFrames,
    maxChunks: limits.maxChunks,
    maxHeaderBytes: limits.maxHeaderBytes,
    maxHeaderEvents: limits.maxHeaderEvents,
    maxHeaderPairs: limits.maxHeaderPairs,
    maxEvents: limits.maxEvents,
    wallMs,
    deadlineAt,
    credential,
    stopOwned: ({ reason }) => {
      if (reason) unknown("receipt-stop");
      return stopNow(reason === "deadline" ? "deadline" : "uncertain");
    },
    persist: async (record) => {
      const pending = pendingBindings.get(record.index);
      if (!pending || pending.binding.kind !== record.kind) {
        unknown("orphan-receipt");
        stopNow("uncertain");
        throw new Error("receipt binding unavailable");
      }
      pendingBindings.delete(record.index);
      if (record.kind === "data") {
        pending.row.bodyBytes = record.raw.bodyBytes;
        if (record.raw.truncated) unknown("truncated-raw");
      } else if (record.rawHeaders) pending.row.rawHeaders = record.rawHeaders.slice();
      const ticket = store(
        { type: "receipt", nativeSeq: pending.row.seq, receipt: record },
        pending.row,
        false,
        pending.binding,
      );
      if (!ticket) throw new Error("receipt commit unavailable");
      await ticket.committed;
    },
    onFrame: (frame, context) => (admissionClosed ? undefined : onFrame(frame, context)),
  });
  gate = createStreamingWriteGate({
    maxFrames: limits.maxFrames,
    maxFrameBytes: limits.maxFrameBytes,
    maxOutgoingBytes: limits.maxOutgoingBytes,
    maxActions: limits.maxActions,
    wallMs,
    deadlineAt,
    credential,
    guard,
    liveCheck: (intent) => (admissionClosed ? false : liveCheck(intent)),
    persist: async (intent) => {
      const ticket = store({ type: "action", intent });
      if (!ticket) throw new Error("intent commit unavailable");
      await ticket.committed;
    },
    contain: ({ origin }) => stopNow(origin === "local-close" ? "close" : origin),
    issue: (intent, wire) => {
      if (admissionClosed) throw new Error("native admission closed");
      marker("issue-entry");
      if (intent.kind === "half-close") {
        const value = seq();
        const row = projection({ kind: "half-close-entry", seq: value, committed: false });
        if (row) store({ type: "native", row }, row);
      }
      try {
        if (admissionClosed) throw new Error("native admission closed after capture");
        let result;
        if (intent.kind === "open") {
          unknown("pre-return-stream-window");
          result = session.request({
            ...wireMetadata,
            ":method": "POST",
            ":scheme": endpoint.protocol.slice(0, -1),
            ":authority": endpoint.host,
            ":path": PATH,
            "content-type": "application/grpc+proto",
            te: "trailers",
            "grpc-accept-encoding": "identity",
            "grpc-encoding": "identity",
            "grpc-timeout": wireTimeout(deadlineAt),
          });
          stream = result;
          if (
            typeof stream?.on !== "function" ||
            typeof stream?.write !== "function" ||
            typeof stream?.end !== "function" ||
            typeof stream?.close !== "function" ||
            typeof stream?.removeListener !== "function"
          )
            throw new Error("owned stream required");
          bindStream();
          if (stopping && !cancelIssued) {
            cancelIssued = true;
            try {
              stream.close(8);
            } catch {
              unknown("native-cancel-throw");
            }
          }
        } else if (intent.kind === "frame") result = stream.write(wire);
        else if (intent.kind === "half-close") result = stream.end();
        else stopNow("client-cancel", false);
        marker("issue-return");
        return intent.kind === "frame" ? result : undefined;
      } catch {
        unknown("native-issue-throw");
        stopNow("uncertain");
        throw new Error("native issue unknown");
      }
    },
  });
  const onAbort = () => {
    unknown("operator-abort");
    stopNow("abort");
  };
  signal?.addEventListener("abort", onAbort, { once: true });
  if (signal?.aborted) onAbort();
  function action(method, bytes) {
    if (admissionClosed || performance.now() >= deadlineAt) {
      if (performance.now() >= deadlineAt) stopNow("deadline");
      throw new Error("bridge admission closed");
    }
    return gate[method](bytes);
  }
  function done() {
    if (donePromise) return donePromise;
    stopNow("close");
    donePromise = (async () => {
      const [gateReport, receiptReport] = await Promise.all([gate.done(), receipts.done()]);
      for (const pending of pendingBindings.values()) {
        pending.binding.state = "raw-absent";
        unknown("missing-raw-receipt");
      }
      pendingBindings.clear();
      draining = true;
      const journalReport = await journal.done();
      if (!sessionClosed || (stream && !streamClosed)) unknown("native-close-unconfirmed");
      const provenance = reduceStreamingProvenance(chronology, {
        maxRows: limits.maxChronologyRows,
        maxHeaderPairs: limits.maxHeaderPairs,
        maxHeaderBytes: limits.maxHeaderBytes,
        maxMessageBytes: limits.maxMessageBytes,
      });
      const terminationRequired =
        gateReport.terminationRequired ||
        receiptReport.terminationRequired ||
        journalReport.terminationRequired ||
        !sessionClosed ||
        (!!stream && !streamClosed) ||
        gateReport.unknownActions > 0 ||
        receiptReport.unknownEvents > 0 ||
        journalReport.unknownEntries > 0;
      if (terminationRequired) unknown("unresolved-owned-work");
      const report = structuredClone({
        provenance,
        gate: gateReport,
        receipts: receiptReport,
        journal: journalReport,
        chronology,
        bindings,
        nativeCallbacks,
        lostCallbacks,
        native: {
          streamCreated: !!stream,
          streamClosed,
          sessionClosed,
          cancelIssued,
          destroyIssued,
        },
        verdict: reasons.size || terminationRequired ? "uncertain" : provenance.verdict,
        reasons: [...reasons].toSorted(),
        terminationRequired,
      });
      signal?.removeEventListener("abort", onAbort);
      for (const [owner, event, callback] of listeners) owner.removeListener(event, callback);
      return report;
    })();
    return donePromise;
  }
  return {
    open: () => action("open"),
    write: (bytes) => action("write", bytes),
    halfClose: () => action("halfClose"),
    cancel: () => action("cancel"),
    stopNow: (cause) => stopNow(cause),
    done,
  };
}
