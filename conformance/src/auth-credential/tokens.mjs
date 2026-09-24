// Pure token helpers of the AUTH-CREDENTIAL sandbox harness: JWT decoding, the token-aware
// normalization of recorded answers, relations between tokens of one program, deliberate token
// damage, and custom-token payloads. Nothing here performs I/O.
//
// A recorded token is replaced by its decoded header and claims. Signatures and key ids are
// never compared: production signs with Google-held keys, fireemu with a local key. What is
// compared is the algorithm, whether a key id and a type are present, and every claim. A token's
// lifetime is recorded as `exp` relative to its own `iat`; `auth_time` and times across steps are
// compared through explicit relations, so no wall-clock second and no latency is compared.

import { createSign } from "node:crypto";

import { normalizeConfig } from "../auth-account/harness.mjs";

/** Response members that carry a JWT the comparison decodes. */
export const JWT_KEYS = new Set(["idToken", "id_token", "access_token", "sessionCookie"]);
/** Audience every Firebase custom token carries. */
export const CUSTOM_TOKEN_AUDIENCE =
  "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit";
const GENERATED_ID = /^[A-Za-z0-9]{28}$/;
const JWT_SHAPE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/;

const base64url = (value) => Buffer.from(value).toString("base64url");

/** The decoded header and claims of a compact JWT, or undefined when it is not one. */
export function decodeJwt(token) {
  if (typeof token !== "string" || !JWT_SHAPE.test(token)) return undefined;
  const [header, payload, signature] = token.split(".");
  try {
    return {
      header: JSON.parse(Buffer.from(header, "base64url").toString("utf8")),
      claims: JSON.parse(Buffer.from(payload, "base64url").toString("utf8")),
      signature,
    };
  } catch {
    return undefined;
  }
}

/**
 * `iat` and `exp` relative to the token's own `iat`. `auth_time` is a placeholder: how far it
 * lies before `iat` measures the caller's latency, not behavior, so it is compared only through
 * explicit relations between steps.
 */
function relativeTimes(claims) {
  const out = { ...claims };
  const iat = typeof claims.iat === "number" ? claims.iat : undefined;
  if (iat !== undefined) out.iat = "<iat>";
  if (typeof claims.exp === "number") {
    if (iat === undefined) out.exp = "<exp>";
    else if (claims.exp === iat) out.exp = "iat";
    else out.exp = `iat${claims.exp > iat ? "+" : "-"}${Math.abs(claims.exp - iat)}`;
  }
  if (typeof claims.auth_time === "number") out.auth_time = "<auth_time>";
  if (typeof out.sub === "string" && GENERATED_ID.test(out.sub)) out.sub = "<generated-localId>";
  return out;
}

/**
 * The recorded form of one JWT: its algorithm, whether a key id and a type are present (not
 * their values), and its claims with `iat` and `exp` relative to `iat`.
 */
export function describeJwt(token) {
  const decoded = decodeJwt(token);
  if (!decoded) return undefined;
  const { alg, kid, typ, ...otherHeader } = decoded.header;
  return {
    header: {
      alg,
      kid: kid === undefined ? "<absent>" : "<present>",
      typ: typ ?? "<absent>",
      ...(Object.keys(otherHeader).length ? { other: Object.keys(otherHeader).toSorted() } : {}),
    },
    signature: decoded.signature ? "<present>" : "<absent>",
    claims: relativeTimes(decoded.claims),
  };
}

/** A number equal to the project number, anywhere in decoded claims, is masked as in strings. */
function maskNumbers(value, projectNumber) {
  if (typeof value === "number")
    return String(value) === projectNumber ? "<project-number>" : value;
  if (Array.isArray(value)) return value.map((v) => maskNumbers(v, projectNumber));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, maskNumbers(v, projectNumber)]),
    );
  }
  return value;
}

/**
 * Generated ids are masked one by one, so a token also records whether its `sub` is its
 * `user_id` and, in an answer that names the account, whether it is that `localId`.
 */
function identityRelations(claims, localId) {
  const out = {};
  if (typeof claims.sub === "string" && typeof claims.user_id === "string") {
    out.subIsUserId = claims.sub === claims.user_id;
  }
  if (typeof claims.sub === "string" && typeof localId === "string") {
    out.subIsLocalId = claims.sub === localId;
  }
  // A legacy token names its account only as user_id.
  if (typeof claims.user_id === "string" && typeof localId === "string") {
    out.userIdIsLocalId = claims.user_id === localId;
  }
  return out;
}

function decodeTokens(value, key, ctx, localId) {
  // A TOTP enrollment secret is a credential and is never recorded.
  if (key === "sharedSecretKey" && typeof value === "string") return "<sharedSecretKey>";
  if (JWT_KEYS.has(key) && typeof value === "string") {
    const described = describeJwt(value);
    // A token that does not decode is never recorded raw.
    if (!described) return "<undecodable-jwt>";
    const identity = identityRelations(decodeJwt(value).claims, localId);
    return { "<jwt>": maskNumbers({ ...described, ...identity }, ctx.target.projectNumber) };
  }
  if (Array.isArray(value)) return value.map((v) => decodeTokens(v, key, ctx, localId));
  if (value && typeof value === "object") {
    // An answer names its account as `localId`, or as `user_id` in a Secure Token answer.
    const named = [value.localId, value.user_id].find((id) => typeof id === "string") ?? localId;
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, decodeTokens(v, k, ctx, named)]),
    );
  }
  return value;
}

/**
 * The recorded form of one HTTP answer: JWTs decoded as above, then the AUTH-ACCOUNT
 * normalization (run id, project, project number, API key, generated ids, run-window times,
 * refresh tokens and other opaque credentials).
 */
export function normalizeCredentialResponse(status, text, ctx) {
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    return { status, nonJson: true };
  }
  return { status, body: normalizeConfig(decodeTokens(body, "", ctx, undefined), ctx) };
}

/**
 * Looks up `path` in a recorded answer, descending into a JWT's claims when a segment meets a
 * token string (`idToken.auth_time`).
 */
export function tokenPath(value, path) {
  let current = value;
  for (const segment of String(path).split(".")) {
    if (typeof current === "string") current = decodeJwt(current)?.claims;
    if (current === null || current === undefined) return undefined;
    current = current[segment];
  }
  return current;
}

/**
 * How two values of one program relate. `time` compares whole seconds (numbers or numeric
 * strings); `same` compares identity (a refresh token handed back unchanged).
 */
export function relate(kind, left, right) {
  if (left === undefined || right === undefined) return "missing";
  if (kind === "same") return left === right ? "same" : "different";
  if (kind === "time") {
    const a = Number(left);
    const b = Number(right);
    if (!Number.isFinite(a) || !Number.isFinite(b)) return "not-a-time";
    if (a === b) return "equal";
    return a < b ? "earlier" : "later";
  }
  throw new Error(`unknown relation kind ${kind}`);
}

/** A copy of a signed JWT damaged in one declared way. */
export function tamper(token, how) {
  const [header, payload, signature] = token.split(".");
  switch (how) {
    case "signature": {
      // Flip bits in the middle of the signature so it stays well-formed base64url.
      const bytes = Buffer.from(signature, "base64url");
      bytes[Math.floor(bytes.length / 2)] ^= 0xff;
      return `${header}.${payload}.${bytes.toString("base64url")}`;
    }
    case "strip-signature":
      return `${header}.${payload}.`;
    case "alg-none": {
      const decoded = JSON.parse(Buffer.from(header, "base64url").toString("utf8"));
      return `${base64url(JSON.stringify({ ...decoded, alg: "none" }))}.${payload}.`;
    }
    case "payload": {
      // Keeps the signature but changes a claim, so only signature verification can refuse it.
      const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
      const changed = { ...claims, fireemu_tampered: true };
      return `${header}.${base64url(JSON.stringify(changed))}.${signature}`;
    }
    default:
      throw new Error(`unknown tamper ${how}`);
  }
}

/**
 * The claims of one custom token from a corpus spec: the issuing service account, the time it
 * is minted, and optional overrides. `omit` removes a claim; `set` replaces or adds claims.
 */
export function customTokenClaims(spec, serviceAccount, nowSeconds, substitute) {
  const iat = nowSeconds + (spec.iatOffset ?? 0);
  const claims = {
    iss: serviceAccount,
    sub: serviceAccount,
    aud: CUSTOM_TOKEN_AUDIENCE,
    iat,
    exp: iat + (spec.lifetime ?? 3600),
    uid: spec.uid === undefined ? undefined : substitute(spec.uid),
    ...(spec.claims === undefined ? {} : { claims: spec.claims }),
    ...spec.set,
  };
  for (const key of spec.omit ?? []) delete claims[key];
  if (claims.uid === undefined) delete claims.uid;
  return claims;
}

/** An RS256 JWT signed with a local PEM key; the local stand-in for IAM `signJwt`. */
export function signLocally(claims, privateKeyPem, kid) {
  const header = base64url(JSON.stringify({ alg: "RS256", kid, typ: "JWT" }));
  const payload = base64url(JSON.stringify(claims));
  const signer = createSign("RSA-SHA256");
  signer.update(`${header}.${payload}`);
  return `${header}.${payload}.${signer.sign(privateKeyPem).toString("base64url")}`;
}
