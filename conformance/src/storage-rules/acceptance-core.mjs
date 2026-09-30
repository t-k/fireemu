import { createHash } from "node:crypto";

// Shared parts of the response classifiers: one complete raw response is copied into a plain record, and the helpers
// below read it without ever exposing a body or header value to a fact.
const nativeLength = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(Uint8Array.prototype), "length").get;
export const bad = (message) => { throw new Error(message); };

export function readResponse(value) {
  const fail = () => bad("invalid acceptance response");
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) fail();
  const keys = Reflect.ownKeys(value);
  if (keys.length !== 3 || !["status", "rawHeaders", "bytes"].every((key) => keys.includes(key))) fail();
  for (const key of keys) {
    const field = Object.getOwnPropertyDescriptor(value, key);
    if (!field?.enumerable || !Object.hasOwn(field, "value")) fail();
  }
  const { status, rawHeaders, bytes } = value;
  if (!Number.isInteger(status) || status < 100 || status > 599) fail();
  if (!Array.isArray(rawHeaders) || Object.getPrototypeOf(rawHeaders) !== Array.prototype || rawHeaders.length % 2 !== 0 || rawHeaders.length > 512) fail();
  const headerKeys = Reflect.ownKeys(rawHeaders);
  if (headerKeys.length !== rawHeaders.length + 1) fail();
  for (const key of headerKeys) {
    if (key === "length") continue;
    const field = Object.getOwnPropertyDescriptor(rawHeaders, key);
    if (typeof key !== "string" || !/^(?:0|[1-9]\d*)$/.test(key) || !field?.enumerable || !Object.hasOwn(field, "value") || typeof field.value !== "string") fail();
  }
  if (!Buffer.isBuffer(bytes) || Object.getPrototypeOf(bytes) !== Buffer.prototype) fail();
  const size = nativeLength.call(bytes);
  const headers = new Map();
  for (let index = 0; index < rawHeaders.length; index += 2) {
    const name = rawHeaders[index].toLowerCase();
    headers.set(name, [...(headers.get(name) ?? []), rawHeaders[index + 1]]);
  }
  const copy = Buffer.alloc(size);
  Uint8Array.prototype.set.call(copy, bytes);
  return { status, headers, bytes: copy };
}

export const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
export const single = (headers, name) => (headers.get(name)?.length === 1 ? headers.get(name)[0] : headers.has(name) ? null : undefined);
export function jsonBody(response) {
  const type = single(response.headers, "content-type");
  if (typeof type !== "string" || !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(type.trim())) return undefined;
  try { return JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(response.bytes)); } catch { return undefined; }
}
export const isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
export const decimal = (value, max = 19) => typeof value === "string" && new RegExp(`^[1-9]\\d{0,${max - 1}}$`).test(value);
export const size = (value) => typeof value === "string" && /^(?:0|[1-9]\d{0,15})$/.test(value);
export const common = (response) => Object.freeze({ status: response.status, bodyBytes: response.bytes.length, bodySha256: digest(response.bytes) });
export const result = (kind, verdict, facts) => Object.freeze({ kind, verdict, facts: Object.freeze(facts) });
export const unexpected = (kind, response) => result(kind, "unexpected", common(response));


/** RFC 3339 UTC with an optional fraction of at most nine digits, for a date that exists (`Date.parse` alone accepts 30 February). */
export function isTimestamp(value) {
  if (typeof value !== "string") return false;
  const match = /^(\d{4})-(\d{2})-(\d{2})T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,9})?Z$/.exec(value);
  if (!match) return false;
  const [year, month, day] = [Number(match[1]), Number(match[2]), Number(match[3])];
  // An impossible date (a 30th of February, month 13, day 00) overflows into another month, so the month alone tells.
  return new Date(Date.UTC(year, month - 1, day)).getUTCMonth() === month - 1;
}

/** A Google API error: the status, `error.code`, `error.status` and a message all agree. */
export function googleError(response, code, status) {
  if (response.status !== code) return false;
  const body = jsonBody(response);
  return isObject(body) && isObject(body.error) && body.error.code === code && body.error.status === status && typeof body.error.message === "string";
}

/** A result that also hands one or more bearer values to the caller. They live in a non-enumerable, frozen property, so they never serialize. */
export function secretResult(kind, verdict, facts, secrets) {
  const out = { kind, verdict, facts: Object.freeze(facts) };
  Object.defineProperty(out, "secretFacts", { value: Object.freeze({ ...secrets }), enumerable: false });
  return Object.freeze(out);
}
