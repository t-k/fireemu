const metadataKinds = new Set(["response", "trailers", "additional"]);
const schemas = new Map([
  ["response", new Set(["kind", "seq", "committed", "flags", "rawHeaders"])],
  ["trailers", new Set(["kind", "seq", "committed", "flags", "rawHeaders"])],
  ["additional", new Set(["kind", "seq", "committed", "flags", "rawHeaders"])],
  ["data", new Set(["kind", "seq", "committed", "bodyBytes"])],
  ["local-stop-entry", new Set(["kind", "seq", "committed", "cause"])],
  ["half-close-entry", new Set(["kind", "seq", "committed"])],
  ["marker", new Set(["kind", "seq", "committed", "event"])],
]);
const localCauses = new Set([
  "client-cancel",
  "abort",
  "deadline",
  "close",
  "reset",
  "revocation",
  "uncertain",
]);
const markerEvents = new Set([
  "issue-entry",
  "issue-return",
  "peer-end",
  "peer-close",
  "peer-error",
  "peer-reset",
  "peer-goaway",
  "local-stop-return",
  "native-close-ack",
]);

function plainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)
  );
}
function dataField(object, name) {
  const descriptor = Object.getOwnPropertyDescriptor(object, name);
  return descriptor && Object.hasOwn(descriptor, "value") ? descriptor.value : undefined;
}
function validShape(row, keys) {
  for (const key of Reflect.ownKeys(row)) {
    if (!keys.has(key)) return false;
    if (!Object.hasOwn(Object.getOwnPropertyDescriptor(row, key), "value")) return false;
  }
  return true;
}
function statusValue(raw) {
  if (raw.length === 0) return null;
  let value = 0;
  for (let i = 0; i < raw.length; i++) {
    const digit = raw.charCodeAt(i) - 48;
    if (digit < 0 || digit > 9) return null;
    value = Math.min(17, value * 10 + digit);
  }
  return value <= 16 ? value : null;
}
function decodeMessage(raw) {
  for (let i = 0; i < raw.length; i++) {
    const unit = raw.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = raw.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new URIError("unpaired surrogate");
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new URIError("unpaired surrogate");
    }
  }
  return decodeURIComponent(raw);
}
function terminalValue(row, maxMessageBytes, reasons) {
  let statuses = 0;
  let messages = 0;
  let rawStatus;
  let rawMessage;
  const statusDetailsRaw = [];
  for (let i = 0; i < row.rawHeaders.length; i += 2) {
    const name = row.rawHeaders[i].toLowerCase();
    const value = row.rawHeaders[i + 1];
    if (name === "grpc-status") {
      statuses++;
      rawStatus = value;
    }
    if (name === "grpc-message") {
      messages++;
      rawMessage = value;
    }
    if (name === "grpc-status-details-bin") statusDetailsRaw.push(value);
  }
  let valid = true;
  const taint = (reason) => {
    reasons.add(reason);
    valid = false;
  };
  if (!row.committed) taint("uncommitted-terminal");
  if (statuses === 0) taint("missing-status");
  if (statuses > 1) taint("duplicate-status");
  const status = statuses === 1 ? statusValue(rawStatus) : null;
  if (statuses === 1 && status === null) taint("invalid-status");
  if (messages > 1) taint("duplicate-message");
  let message = null;
  if (messages === 1) {
    try {
      message = decodeMessage(rawMessage);
      if (Buffer.byteLength(message, "utf8") > maxMessageBytes) taint("message-byte-limit");
    } catch {
      taint("invalid-message");
    }
  }
  return valid ? { status, message, statusDetailsRaw } : null;
}

/**
 * Classify bounded normalized native evidence, ordered by unique native sequence numbers.
 * `committed` is the adapter's assertion; this pure reducer cannot prove journal binding or fsync.
 * A peerTerminal retained under an uncertain verdict is diagnostic, never a completion certificate.
 * bodyBytes, when supplied on DATA, is a nonnegative safe integer diagnostic; payload is not read.
 */
export function reduceStreamingProvenance(rows, bounds) {
  if (!plainObject(bounds)) throw new TypeError("explicit bounds are required");
  for (const name of ["maxRows", "maxHeaderPairs", "maxHeaderBytes", "maxMessageBytes"]) {
    if (!Number.isSafeInteger(dataField(bounds, name)) || dataField(bounds, name) <= 0) {
      throw new TypeError(`${name} must be a positive safe integer`);
    }
  }
  const { maxRows, maxHeaderPairs, maxHeaderBytes, maxMessageBytes } = bounds;
  const reasons = new Set();
  const result = {
    localCause: null,
    localCauseSeq: null,
    peerTerminal: null,
    peerTerminalSeq: null,
    verdict: "uncertain",
    reasons: [],
  };
  const finish = () => {
    result.reasons = [...reasons].toSorted();
    return result;
  };
  if (!Array.isArray(rows)) {
    reasons.add("invalid-rows");
    return finish();
  }
  if (rows.length > maxRows) {
    reasons.add("row-limit");
    return finish();
  }

  // Complete schema and cumulative raw-byte admission precedes sorting, copying and decoding.
  const seen = new Set();
  const duplicates = new Set();
  let headerBytes = 0;
  for (let i = 0; i < rows.length; i++) {
    const row = dataField(rows, String(i));
    if (
      !plainObject(row) ||
      typeof dataField(row, "kind") !== "string" ||
      typeof dataField(row, "committed") !== "boolean"
    ) {
      reasons.add("invalid-row");
      continue;
    }
    const keys = schemas.get(row.kind);
    if (!keys) {
      reasons.add("unknown-kind");
      continue;
    }
    if (!validShape(row, keys)) {
      reasons.add("invalid-row");
      continue;
    }
    if (!Number.isSafeInteger(row.seq) || row.seq < 0) {
      reasons.add("invalid-sequence");
      continue;
    }
    if (seen.has(row.seq)) {
      duplicates.add(row.seq);
      reasons.add("duplicate-sequence");
    }
    seen.add(row.seq);
    if (metadataKinds.has(row.kind)) {
      if (!Number.isInteger(row.flags) || row.flags < 0 || row.flags > 255)
        reasons.add("invalid-flags");
      const raw = row.rawHeaders;
      if (!Array.isArray(raw) || raw.length % 2 !== 0) {
        reasons.add("invalid-headers");
        continue;
      }
      if (raw.length / 2 > maxHeaderPairs) {
        reasons.add("header-pair-limit");
        return finish();
      }
      for (let j = 0; j < raw.length; j++) {
        const value = dataField(raw, String(j));
        if (typeof value !== "string") {
          reasons.add("invalid-headers");
          continue;
        }
        const remaining = maxHeaderBytes - headerBytes;
        if (value.length > remaining) {
          reasons.add("header-byte-limit");
          return finish();
        }
        const size = Buffer.byteLength(value, "utf8");
        if (size > remaining) {
          reasons.add("header-byte-limit");
          return finish();
        }
        headerBytes += size;
      }
    }
    if (row.kind === "local-stop-entry" && !localCauses.has(row.cause))
      reasons.add("invalid-cause");
    if (row.kind === "marker" && !markerEvents.has(row.event)) reasons.add("unknown-event");
    if (
      row.kind === "data" &&
      row.bodyBytes !== undefined &&
      (!Number.isSafeInteger(row.bodyBytes) || row.bodyBytes < 0)
    )
      reasons.add("invalid-row");
  }

  // Only admitted rows enter the chronological scan; duplicated identities have no tie-break authority.
  const chronology = [];
  for (let i = 0; i < rows.length; i++) {
    const row = dataField(rows, String(i));
    if (
      !plainObject(row) ||
      typeof dataField(row, "kind") !== "string" ||
      typeof dataField(row, "committed") !== "boolean"
    )
      continue;
    const keys = schemas.get(row.kind);
    if (
      !keys ||
      !validShape(row, keys) ||
      !Number.isSafeInteger(row.seq) ||
      row.seq < 0 ||
      duplicates.has(row.seq)
    )
      continue;
    if (metadataKinds.has(row.kind)) {
      if (
        !Number.isInteger(row.flags) ||
        row.flags < 0 ||
        row.flags > 255 ||
        !Array.isArray(row.rawHeaders) ||
        row.rawHeaders.length % 2 !== 0
      )
        continue;
      let valid = true;
      for (let j = 0; j < row.rawHeaders.length; j++)
        if (typeof dataField(row.rawHeaders, String(j)) !== "string") valid = false;
      if (!valid) continue;
    }
    if (row.kind === "local-stop-entry" && !localCauses.has(row.cause)) continue;
    if (row.kind === "marker" && !markerEvents.has(row.event)) continue;
    if (
      row.kind === "data" &&
      row.bodyBytes !== undefined &&
      (!Number.isSafeInteger(row.bodyBytes) || row.bodyBytes < 0)
    )
      continue;
    chronology.push(row);
  }
  chronology.sort((a, b) => a.seq - b.seq);
  let firstStop = null;
  let firstHalf = null;
  let terminalCount = 0;
  for (const row of chronology) {
    if (row.kind === "local-stop-entry" && firstStop === null) firstStop = row;
    if (row.kind === "half-close-entry" && firstHalf === null) firstHalf = row;
    if (row.kind === "data" && terminalCount > 0) reasons.add("data-after-terminal");
    if (row.kind !== "trailers" && !(row.kind === "response" && (row.flags & 1) !== 0)) continue;
    terminalCount++;
    if (terminalCount > 1) reasons.add("second-terminal");
    if (firstStop !== null && firstStop.seq < row.seq) reasons.add("peer-after-local-stop");
    const peer = terminalValue(row, maxMessageBytes, reasons);
    if (peer !== null && result.peerTerminal === null) {
      result.peerTerminal = peer;
      result.peerTerminalSeq = row.seq;
    }
  }
  const local = firstStop ?? firstHalf;
  if (local !== null) {
    result.localCause = firstStop === null ? "half-close" : local.cause;
    result.localCauseSeq = local.seq;
  }
  if (terminalCount === 0 && firstStop === null) reasons.add("missing-peer-terminal");
  if (reasons.size === 0)
    result.verdict = result.peerTerminal === null ? "local-stop" : "peer-terminal";
  return finish();
}
