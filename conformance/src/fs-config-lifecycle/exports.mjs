// Managed-export files captured for the format interop programs (scope decision C2).
//
// An export is a set of LevelDB log files. Committed copies must not carry the sandbox project
// id or run-specific database ids, so each is replaced by a placeholder of the same length and
// every affected log record's CRC-32C is recomputed. Restoring swaps them back and recomputes
// again; a capture is committed only when restoring reproduces the original bytes exactly.

import { createHash } from "node:crypto";

const BLOCK = 32 * 1024;
const HEADER = 7;

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0x82f63b78 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

export function crc32c(bytes) {
  let c = 0xffffffff;
  for (const byte of bytes) c = CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/** LevelDB's masked CRC, as its log header stores it. */
export const maskCrc = (crc) => ((((crc >>> 15) | (crc << 17)) >>> 0) + 0xa282ead8) >>> 0;

/**
 * The records of one log file: offset, length and type of each, walking 32 KiB blocks and
 * skipping block trailers. Throws when a stored CRC does not match its record.
 */
export function logRecords(bytes, { verify = true } = {}) {
  const records = [];
  let at = 0;
  while (at < bytes.length) {
    const left = BLOCK - (at % BLOCK);
    if (left < HEADER) {
      at += left;
      continue;
    }
    if (at + HEADER > bytes.length) throw new Error(`truncated record header at ${at}`);
    const stored = bytes.readUInt32LE(at);
    const length = bytes.readUInt16LE(at + 4);
    const type = bytes[at + 6];
    if (type === 0 && length === 0) {
      at += left; // zero padding up to the block end
      continue;
    }
    const end = at + HEADER + length;
    if (end > bytes.length) throw new Error(`truncated record at ${at}`);
    if (verify && maskCrc(crc32c(bytes.subarray(at + 6, end))) !== stored)
      throw new Error(`bad record checksum at ${at}`);
    records.push({ at, length, type });
    at = end;
  }
  return records;
}

// Output files and the overall metadata are LevelDB logs; a per-kind `.export_metadata` is a
// bare protobuf message.
const isLog = (name) => /(^|\/)output-\d+$/.test(name) || name.endsWith(".overall_export_metadata");

/**
 * Replaces each `[from, to]` pair (equal byte lengths) in every record payload and fixes the
 * record CRCs. A value that spans two record fragments cannot be replaced safely and throws.
 */
export function substitute(bytes, pairs) {
  for (const [from, to] of pairs)
    if (Buffer.byteLength(from) !== Buffer.byteLength(to))
      throw new Error(`placeholder length differs for ${from}`);
  const out = Buffer.from(bytes);
  for (const record of logRecords(out)) {
    const payload = out.subarray(record.at + HEADER, record.at + HEADER + record.length);
    let text = payload.toString("latin1");
    for (const [from, to] of pairs) text = text.replaceAll(from, to);
    Buffer.from(text, "latin1").copy(payload);
    out.writeUInt32LE(
      maskCrc(crc32c(out.subarray(record.at + 6, record.at + HEADER + record.length))),
      record.at,
    );
  }
  const whole = out.toString("latin1");
  for (const [from] of pairs)
    if (whole.includes(from)) throw new Error(`a value spans record fragments: ${from}`);
  return out;
}

/** A placeholder for the sandbox project id with the same byte length. */
export const PROJECT_PLACEHOLDER = "demo-fs-config-00000";

/**
 * The same-length replacements of one run's private and run-specific ids: the project and
 * each program database (by letter, so a capture restores into any program's same letter).
 */
export function capturePairs(ctx, program) {
  if (ctx.project.length !== PROJECT_PLACEHOLDER.length)
    throw new Error("project placeholder length");
  return [
    [ctx.project, PROJECT_PLACEHOLDER],
    ...(program.databases ?? []).map((letter) => {
      const id = `cfg${ctx.run}-${program.ordinal.toString(36).padStart(2, "0")}${letter}`;
      return [id, `cfg0000000000-00${letter}`];
    }),
  ];
}

function readVarint(bytes, at) {
  let value = 0n;
  let shift = 0n;
  for (;;) {
    const byte = bytes[at++];
    value |= BigInt(byte & 0x7f) << shift;
    if (!(byte & 0x80)) return [value, at];
    shift += 7n;
  }
}

function writeVarint(value) {
  const out = [];
  let v = BigInt(value);
  do {
    let byte = Number(v & 0x7fn);
    v >>= 7n;
    if (v > 0n) byte |= 0x80;
    out.push(byte);
  } while (v > 0n);
  return Buffer.from(out);
}

/** Rewrites the varint fields `zeroed` of one message to zero; other fields are kept. */
function zeroVarints(body, zeroed) {
  const out = [];
  let at = 0;
  while (at < body.length) {
    const start = at;
    const [tag, afterTag] = readVarint(body, at);
    const field = Number(tag >> 3n);
    const wire = Number(tag & 7n);
    if (wire === 0) {
      const [, afterValue] = readVarint(body, afterTag);
      out.push(
        zeroed.includes(field)
          ? Buffer.concat([writeVarint(tag), writeVarint(0)])
          : body.subarray(start, afterValue),
      );
      at = afterValue;
    } else if (wire === 2) {
      const [length, afterLength] = readVarint(body, afterTag);
      at = afterLength + Number(length);
      out.push(body.subarray(start, at));
    } else {
      throw new Error(`unexpected wire type ${wire} in export metadata`);
    }
  }
  return Buffer.concat(out);
}

/**
 * A partition `.export_metadata` with what legitimately differs between two exports of the
 * same data set to zero: the export window (header fields 1.2 and 1.3) and the output digest
 * (field 2.5), which covers the output file's run-specific database ids. The output file
 * itself is compared separately.
 */
export function maskExportWindow(bytes) {
  const out = [];
  let at = 0;
  while (at < bytes.length) {
    const [tag, afterTag] = readVarint(bytes, at);
    const field = Number(tag >> 3n);
    if (Number(tag & 7n) !== 2) throw new Error("unexpected wire type in export metadata");
    const [length, afterLength] = readVarint(bytes, afterTag);
    const body = bytes.subarray(afterLength, afterLength + Number(length));
    at = afterLength + Number(length);
    const masked = zeroVarints(body, field === 1 ? [2, 3] : field === 2 ? [5] : []);
    out.push(writeVarint(tag), writeVarint(masked.length), masked);
  }
  return Buffer.concat(out);
}

export const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

/**
 * Normalizes a captured export (`{relativeName: Buffer}`) for commit, proving that restoring
 * it yields the original bytes. Returns `{files: {name: base64}, originals: {name: sha256}}`.
 */
export function normalizeCapture(files, pairs) {
  const normalized = {};
  const originals = {};
  for (const [name, bytes] of Object.entries(files).toSorted(([a], [b]) => a.localeCompare(b))) {
    originals[name] = sha256(bytes);
    if (!isLog(name)) {
      for (const [from] of pairs)
        if (bytes.toString("latin1").includes(from)) throw new Error(`${name} carries ${from}`);
    }
    const out = isLog(name) && bytes.length ? substitute(bytes, pairs) : Buffer.from(bytes);
    const back =
      isLog(name) && out.length
        ? substitute(
            out,
            pairs.map(([a, b]) => [b, a]),
          )
        : out;
    if (sha256(back) !== originals[name]) throw new Error(`${name} does not restore exactly`);
    normalized[name] = out.toString("base64");
  }
  return { files: normalized, originals };
}

/** Restores a committed capture for one run's ids; verifies the original digests when known. */
export function restoreCapture(capture, pairs, { verifyOriginals = false } = {}) {
  const files = {};
  for (const [name, base64] of Object.entries(capture.files)) {
    const bytes = Buffer.from(base64, "base64");
    files[name] = isLog(name) && bytes.length ? substitute(bytes, pairs) : bytes;
    if (verifyOriginals && sha256(files[name]) !== capture.originals[name])
      throw new Error(`${name} does not restore to the recorded original`);
  }
  return files;
}
