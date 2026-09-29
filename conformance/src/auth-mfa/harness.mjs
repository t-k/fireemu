// Normalization and TOTP arithmetic of the AUTH-MFA sandbox harness. This module is part of the
// fixture's harness digest (run.mjs): a change here makes every saved row stale. Request
// construction, the production/local context and transient classification come from the
// AUTH-ACCOUNT harness; token decoding comes from the AUTH-CREDENTIAL harness; the request
// guard and the corpus rules live in guard.mjs.
//
// A TOTP shared secret, a session info and a pending credential are credentials: none of them
// is ever recorded. Codes are computed here from the secret an enrollment start returned
// (RFC 6238, HMAC-SHA1, 30-second steps, six digits) and are never recorded either.

import { createHmac } from "node:crypto";

import { normalizeCredentialResponse } from "../auth-credential/tokens.mjs";

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** The bytes of an RFC 4648 base32 string (padding and letter case ignored). */
export function base32Decode(text) {
  let bits = 0;
  let value = 0;
  const bytes = [];
  for (const char of String(text).replace(/=+$/, "").toUpperCase()) {
    const index = BASE32.indexOf(char);
    if (index < 0) throw new Error("not a base32 secret");
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

/** The RFC 4226 HOTP value of `counter` as a zero-padded string of `digits` digits. */
export function hotp(key, counter, digits = 6) {
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac("sha1", key).update(message).digest();
  const offset = mac[19] & 0x0f;
  const binary =
    ((mac[offset] & 0x7f) << 24) |
    (mac[offset + 1] << 16) |
    (mac[offset + 2] << 8) |
    mac[offset + 3];
  return String(binary % 10 ** digits).padStart(digits, "0");
}

export const TOTP_PERIOD_SECONDS = 30;

/** The time step of a Unix time in seconds. */
export const timeStep = (seconds) => Math.floor(seconds / TOTP_PERIOD_SECONDS);

/** The TOTP code of a base32 secret at a time step. */
export const totpCode = (secret, step) => hotp(base32Decode(secret), step);

/**
 * A code no step within `span` of `step` produces: a wrong code that stays wrong for any
 * window a project can configure (at most ten steps) and any clock skew of a few minutes.
 */
export function wrongCode(secret, step, span = 20) {
  const near = new Set();
  for (let s = step - span; s <= step + span; s += 1) near.add(totpCode(secret, s));
  for (let n = 0; ; n += 1) {
    const code = String(n).padStart(6, "0");
    if (!near.has(code)) return code;
  }
}

/** Keys whose string value names a second factor. */
const ENROLLMENT_KEYS = new Set(["mfaEnrollmentId", "second_factor_identifier"]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * Per-program names of second factors. A factor is named by the order in which the program
 * first saw it and by its shape (production issues UUIDs), so both targets compare equal when
 * they issue different ids for the same factors, and a token's `second_factor_identifier` is
 * visibly the factor a lookup lists.
 */
export function createEnrollmentRegistry() {
  const names = new Map();
  const name = (id) => {
    if (!names.has(id)) {
      const shape = UUID.test(id) ? "uuid" : "other";
      names.set(id, `<enrollment:${names.size + 1}:${shape}>`);
    }
    return names.get(id);
  };
  const collect = (value, key) => {
    if (typeof value === "string") {
      if (ENROLLMENT_KEYS.has(key) && value.length >= 8) name(value);
    } else if (Array.isArray(value)) for (const v of value) collect(v, key);
    else if (value && typeof value === "object")
      for (const [k, v] of Object.entries(value)) collect(v, k);
  };
  const replace = (value) => {
    if (typeof value === "string") {
      let out = value;
      for (const [id, placeholder] of names) out = out.replaceAll(id, placeholder);
      return out;
    }
    if (Array.isArray(value)) return value.map(replace);
    if (value && typeof value === "object")
      return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, replace(v)]));
    return value;
  };
  return {
    /** Registers the factors a (normalized) answer names, then replaces every occurrence. */
    apply(recorded) {
      collect(recorded, "");
      return replace(recorded);
    },
    /** Replaces the factors already known in an arbitrary value (config projections). */
    replace,
    size: () => names.size,
  };
}

/**
 * The seconds from the target's clock at send time to an enrollment deadline, rounded to ten
 * seconds: the enrollment session lifetime the answer announces, without any wall-clock time.
 */
export function deadlineAfter(instant, sentSeconds) {
  const millis = Date.parse(instant);
  if (!Number.isFinite(millis) || !Number.isFinite(sentSeconds)) return "not-a-time";
  const seconds = Math.round((millis / 1000 - sentSeconds) / 10) * 10;
  return `${seconds >= 0 ? "+" : "-"}${Math.abs(seconds)}s`;
}

const INSTANT = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.(\d+))?Z$/;
/** Instants of a factor whose precision is part of the answer's shape. */
const FACTOR_TIME_KEYS = new Set(["enrolledAt", "finalizeEnrollmentTime"]);

/**
 * A factor instant inside the run window becomes `<run-time:instant:fraction-N>`, N the digits
 * of its fraction (production writes microseconds). Any other instant is kept for the shared
 * normalization.
 */
function shapeFactorTimes(value, ctx, key = "") {
  if (typeof value === "string" && FACTOR_TIME_KEYS.has(key)) {
    const match = INSTANT.exec(value);
    const millis = Date.parse(value);
    if (match && millis >= ctx.window.from && millis <= ctx.window.to)
      return `<run-time:instant:fraction-${match[1]?.length ?? 0}>`;
    return value;
  }
  if (Array.isArray(value)) return value.map((v) => shapeFactorTimes(v, ctx, key));
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, shapeFactorTimes(v, ctx, k)]),
    );
  return value;
}

/**
 * The recorded form of one HTTP answer: factor instants shaped as above, the AUTH-CREDENTIAL
 * normalization (tokens decoded;
 * secrets, session infos, pending credentials, ids, run-window times, the project, its number
 * and the API key as placeholders), then second factors named by the program's registry.
 * `project` limits the answer to one top-level member (a config answer carries key material).
 */
export function normalizeMfaResponse(status, text, ctx, registry, { project } = {}) {
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    return { status, nonJson: true };
  }
  if (project && body && typeof body === "object" && !body.error)
    body = { [project]: body[project] ?? null };
  // An action link carries its code and the API key; the code alone is enough here (AUTH-ACTION
  // compares links).
  if (body && typeof body === "object" && typeof body.oobLink === "string")
    body = { ...body, oobLink: "<oobLink>" };
  const recorded = normalizeCredentialResponse(
    status,
    JSON.stringify(shapeFactorTimes(body, ctx)),
    ctx,
  );
  return registry.apply(recorded);
}
