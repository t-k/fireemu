// The request budget and the capture journal of a recording. The budget refuses a request before it is
// sent once the cap is reached; the journal writes one JSON line for every exchange as it happens, with
// a long string (a 10 MB payload) replaced by its length and SHA-256 and no header at all, so that a
// credential cannot reach it.

import { createHash } from "node:crypto";
import { appendFileSync, closeSync, fsyncSync, mkdirSync, openSync, writeFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";

export class BudgetExceeded extends Error {
  constructor(max) {
    super(`the request budget of ${max} is spent`);
    this.name = "BudgetExceeded";
  }
}

export function createBudget(max) {
  if (!Number.isSafeInteger(max) || max <= 0)
    throw new Error("the budget must be a positive integer");
  let used = 0;
  return Object.freeze({
    max,
    /** Counts one request, or throws before it is sent when the budget is spent. */
    consume() {
      if (used >= max) throw new BudgetExceeded(max);
      used += 1;
      return used;
    },
    used: () => used,
    remaining: () => max - used,
  });
}

export const OMIT_ABOVE = 4096;
const MAX_UNKNOWNS_LISTED = 100;
export const RAW_FRAME_BOUNDS = Object.freeze({ bytes: 16_384, frames: 24 });
function assertRawFrame(bytes, index) {
  if (
    !Buffer.isBuffer(bytes) ||
    bytes.length > RAW_FRAME_BOUNDS.bytes ||
    !Number.isSafeInteger(index) ||
    index < 1 ||
    index > RAW_FRAME_BOUNDS.frames
  )
    throw new Error("raw frame byte/count bound exceeded before persistence");
}

/** The value with every string longer than OMIT_ABOVE characters replaced by its length and digest. */
export function sanitize(value) {
  if (typeof value === "string")
    return value.length > OMIT_ABOVE
      ? {
          omitted: {
            length: value.length,
            sha256: createHash("sha256").update(value).digest("hex"),
          },
        }
      : value;
  if (Array.isArray(value)) return value.map(sanitize);
  if (value !== null && typeof value === "object")
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, sanitize(item)]));
  return value;
}

/** An append-only JSON-lines file, flushed after every line. */
export function createFileJournal(path) {
  const handle = openSync(path, "ax", 0o600);
  const blobDirectory = `${basename(path)}.frames`;
  let createdFrameDirectory = false;
  let closed = false;
  return Object.freeze({
    write(entry) {
      appendFileSync(handle, `${JSON.stringify(entry)}\n`);
      fsyncSync(handle);
    },
    /** Raw protobuf frames are the sole bounded payload exception to note sanitization. */
    writeFrame(bytes, index) {
      assertRawFrame(bytes, index);
      if (closed) throw new Error("the journal is closed");
      if (!createdFrameDirectory) {
        mkdirSync(join(dirname(path), blobDirectory), { mode: 0o700 });
        createdFrameDirectory = true;
      }
      const blob = `${blobDirectory}/frame-${String(index).padStart(6, "0")}.pb`;
      const frameHandle = openSync(join(dirname(path), blob), "wx", 0o600);
      try {
        writeFileSync(frameHandle, bytes);
        fsyncSync(frameHandle);
      } finally {
        closeSync(frameHandle);
      }
      return blob;
    },
    close() {
      closed = true;
      closeSync(handle);
    },
  });
}

/** The capture of a recording: numbers each exchange and writes it, sanitized, to the journal. */
export function createCapture({ journal, now = () => new Date() }) {
  let n = 0;
  let unknown = 0;
  let rawFrames = 0;
  const unknowns = [];
  const cases = new Map();
  return Object.freeze({
    record(entry) {
      n += 1;
      if (entry.unknown === true) {
        unknown += 1;
        if (unknowns.length < MAX_UNKNOWNS_LISTED)
          unknowns.push({ n, case: entry.case, step: entry.step, op: entry.op });
      }
      const line = { n, at: now().toISOString(), ...sanitize(entry) };
      journal.write(line);
      if (typeof entry.case === "string") cases.set(entry.case, (cases.get(entry.case) ?? 0) + 1);
      return n;
    },
    /** A note that is not an exchange: a case that started, ended or failed. */
    note(kind, data = {}) {
      journal.write({ at: now().toISOString(), note: kind, ...sanitize(data) });
    },
    /** Persist exact bounded stream bytes; metadata still follows the ordinary sanitizer. */
    frame(data, bytes) {
      const frameMaximum = data?.direction === "in" ? 4 : data?.direction === "out" ? 2 : 0;
      if (!Number.isSafeInteger(data?.frame) || data.frame < 1 || data.frame > frameMaximum)
        throw new Error("raw frame direction/index bound exceeded before persistence");
      assertRawFrame(bytes, rawFrames + 1);
      if (typeof journal.writeFrame !== "function")
        throw new Error("the journal cannot persist raw frames");
      const blob = journal.writeFrame(bytes, rawFrames + 1);
      rawFrames += 1;
      const identity = {
        blob,
        bodyBytes: bytes.length,
        sha256: createHash("sha256").update(bytes).digest("hex"),
      };
      journal.write({
        ...sanitize(data),
        at: now().toISOString(),
        note: "stream-frame",
        ...identity,
      });
      return identity;
    },
    count: () => n,
    /** How many exchanges had an answer that does not say what was done. */
    unknownCount: () => unknown,
    /** The first exchanges with such an answer, for the read-back that has to settle each. */
    unknowns: () => structuredClone(unknowns),
    perCase: () => Object.fromEntries(cases),
  });
}
