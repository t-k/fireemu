// The request budget and the capture journal of a recording. The budget refuses a request before it is
// sent once the cap is reached; the journal writes one JSON line for every exchange as it happens, with
// a long string (a 10 MB payload) replaced by its length and SHA-256 and no header at all, so that a
// credential cannot reach it.

import { createHash } from "node:crypto";
import { appendFileSync, closeSync, fsyncSync, openSync } from "node:fs";

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
  return Object.freeze({
    write(entry) {
      appendFileSync(handle, `${JSON.stringify(entry)}\n`);
      fsyncSync(handle);
    },
    close: () => closeSync(handle),
  });
}

/** The capture of a recording: numbers each exchange and writes it, sanitized, to the journal. */
export function createCapture({ journal, now = () => new Date() }) {
  let n = 0;
  let unknown = 0;
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
    count: () => n,
    /** How many exchanges had an answer that does not say what was done. */
    unknownCount: () => unknown,
    /** The first exchanges with such an answer, for the read-back that has to settle each. */
    unknowns: () => structuredClone(unknowns),
    perCase: () => Object.fromEntries(cases),
  });
}
