// Recording form of an AUTH-FEDERATION answer (draft). The same normalization applies to the
// sandbox and to fireemu, so the two can be compared row by row:
// - the run's issuer host (a preview channel with a per-deploy hash), the run tag, the project,
//   its number and the Web API key become placeholders;
// - certificates (the run's IdP certificate, the service's SP certificates) become
//   placeholders with their count kept;
// - ID tokens and session cookies are recorded as their header and claims (times relative to
//   `iat`), never as the token.

// Secure Token answers a refresh with the new ID token as `access_token` (and `id_token`).
const TOKEN_KEYS = new Set([
  "idToken",
  "id_token",
  "access_token",
  "sessionCookie",
  "oauthIdToken",
]);
const MASKED = {
  refreshToken: "<refresh-token>",
  refresh_token: "<refresh-token>",
  oauthAccessToken: "<oauth-access-token>",
  pendingToken: "<pending-token>",
  sessionId: "<session-id>",
  x509Certificate: "<certificate>",
  localId: "<local-id>",
  user_id: "<local-id>",
  sub: "<subject>",
};

/** Account times: when a record was made or used, never the same twice. */
const TIME_KEYS = new Set([
  "createdAt",
  "lastLoginAt",
  "lastRefreshAt",
  "passwordUpdatedAt",
  "validSince",
]);

/** Claims with `exp`, `auth_time` and `nbf` relative to a numeric `iat`, and `iat` masked. */
function relativeTimes(claims) {
  const iat = claims.iat;
  if (typeof iat !== "number") return claims;
  const out = { ...claims };
  for (const key of ["exp", "auth_time", "nbf"]) {
    if (typeof out[key] === "number") {
      out[key] = `iat${out[key] - iat >= 0 ? "+" : ""}${out[key] - iat}`;
    }
  }
  out.iat = "<iat>";
  return out;
}

function decodeToken(token) {
  const [header, payload] = String(token).split(".");
  try {
    const decode = (part) => JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
    return { "<jwt>": { header: decode(header), claims: relativeTimes(decode(payload)) } };
  } catch {
    return "<unparsable-token>";
  }
}

/** `text` with the run's identifiers as placeholders (the issuer host first: it holds both). */
function placeholders(text, ctx) {
  let out = ctx.issuerHost ? text.replaceAll(ctx.issuerHost, "<issuer-host>") : text;
  out = out.replaceAll(ctx.run, "<run>").replaceAll(ctx.project, "<project>");
  if (ctx.projectNumber) out = out.replaceAll(String(ctx.projectNumber), "<project-number>");
  // An answer may echo the Web API key (a handler URL's `apiKey`).
  if (ctx.apiKey) out = out.replaceAll(String(ctx.apiKey), "<api-key>");
  return out;
}

/**
 * The recorded form of `value`, with the run's identifiers as placeholders in values and in
 * object keys (a provider ID keys `firebase.identities`). Token and masked members are found
 * by their key as answered.
 */
export function normalize(value, ctx, key = "") {
  if (TIME_KEYS.has(key) && (typeof value === "string" || typeof value === "number")) {
    return "<time>";
  }
  if (typeof value === "string") {
    if (TOKEN_KEYS.has(key)) return normalize(decodeToken(value), ctx);
    if (MASKED[key]) return MASKED[key];
    // The IdP's claims as the service echoes them, as JSON text.
    if (key === "rawUserInfo") {
      try {
        return { "<json>": normalize(JSON.parse(value), ctx) };
      } catch {
        return placeholders(value, ctx);
      }
    }
    return placeholders(value, ctx);
  }
  if (Array.isArray(value)) return value.map((item) => normalize(item, ctx, key));
  if (value && typeof value === "object") {
    const out = {};
    // Echoed ID token claims (sign_in_attributes, rawUserInfo) carry absolute times.
    for (const [k, v] of Object.entries(relativeTimes(value))) {
      const recordedKey = placeholders(k, ctx);
      if (Object.hasOwn(out, recordedKey)) throw new Error(`key ${recordedKey} collides`);
      out[recordedKey] = normalize(v, ctx, k);
    }
    return out;
  }
  return value;
}

/** The recorded form of an HTTP answer. */
export function normalizeHttp(status, text, ctx) {
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    body = text === "" ? undefined : "<non-json>";
  }
  return { status, body: normalize(body, ctx) };
}
