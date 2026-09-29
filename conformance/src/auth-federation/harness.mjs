// Recording form of an AUTH-FEDERATION answer (draft). The same normalization applies to the
// sandbox and to fireemu, so the two can be compared row by row:
// - the run's issuer host (a preview channel with a per-deploy hash), the run tag, the project,
//   its number and the Web API key become placeholders;
// - certificates (the run's IdP certificate, the service's SP certificates) become
//   placeholders with their count kept;
// - ID tokens and session cookies are recorded as their header (the key ID masked) and claims
//   (times relative to `iat`), never as the token.

import { readAuthnRequest } from "./saml.mjs";

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
  // The project's password-hash key material (a config answer), never recorded.
  signerKey: "<bytes>",
  saltSeparator: "<bytes>",
  salt: "<bytes>",
};

/**
 * Members kept only in a form known not to be secret: production's redacted password hash,
 * and client secrets this harness made (`fireemu-…`); any other value is masked.
 */
const KEPT_ONLY = {
  passwordHash: (value) => (value === "UkVEQUNURUQ=" ? value : "<bytes>"),
  clientSecret: (value) => (value.startsWith("fireemu-") ? value : "<client-secret>"),
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

/**
 * Tokens minted after the sign-in: a refresh's (`id_token`, `access_token`) and a session
 * cookie. Their `auth_time` is the sign-in's, and whether it falls in their own second or an
 * earlier one depends on when they were sent, so it is recorded only as not after `iat`
 * (AUTH-FEDERATION Q1, 2026-09-29). A later `auth_time` stays as it is.
 */
const MINTED_LATER = new Set(["id_token", "access_token", "sessionCookie"]);

function decodeToken(token, key) {
  const [header, payload] = String(token).split(".");
  try {
    const decode = (part) => JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
    // The key ID names a key of the run's issuer or of the service: it differs per key.
    const { kid, ...rest } = decode(header);
    const recorded = kid === undefined ? rest : { ...rest, kid: "<kid>" };
    const claims = relativeTimes(decode(payload));
    if (MINTED_LATER.has(key) && /^iat(\+0|-\d+)$/.test(String(claims.auth_time))) {
      claims.auth_time = "<=iat";
    }
    return { "<jwt>": { header: recorded, claims } };
  } catch {
    return "<unparsable-token>";
  }
}

/**
 * A SAML `authUri` as recorded: the SSO endpoint and the AuthnRequest it carries, with the
 * request ID and issue time (per request) masked in their form, and the relay state masked.
 */
function samlAuthUri(value, ctx) {
  const { xml } = readAuthnRequest(value);
  const request = xml
    // The service drops a leading zero of the hex ID now and then (record-saml 7789f0).
    .replace(/(\sID=")_[0-9a-f]{1,32}"/, '$1<id:_hex>"')
    .replace(/(\sID=")(?!<id)[^"]*"/, '$1<id>"')
    .replace(/(\sIssueInstant=")\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z"/, '$1<time:millis>"')
    .replace(/(\sIssueInstant=")(?!<time)[^"]*"/, '$1<time>"');
  return {
    "<saml-authn-request>": {
      endpoint: placeholders(value.split("?")[0], ctx),
      request: placeholders(request, ctx),
      relayState: "<relay-state>",
    },
  };
}

/** Unix times in seconds from 2020 to 2040: a number in a message that is one is a time. */
const UNIX_SECONDS = /\b(1[6-9]|20|21)\d{8}\b/g;

/**
 * An error message as recorded: claims it quotes as JSON with their times relative to `iat`,
 * and any other Unix time masked (both differ on every request).
 */
function normalizeMessage(message, ctx) {
  let out = message;
  const start = out.indexOf("{");
  if (start !== -1) {
    try {
      const quoted = JSON.parse(out.slice(start));
      if (quoted && typeof quoted === "object" && !Array.isArray(quoted)) {
        out = `${out.slice(0, start)}${JSON.stringify(relativeTimes(quoted))}`;
      }
    } catch {
      // Not a JSON tail: only the times below.
    }
  }
  // SAML's time checks quote the current instant and the attribute's (record-saml 7789f0).
  const isoTimes = /\b\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z\b/g;
  return placeholders(out.replace(UNIX_SECONDS, "<time>").replace(isoTimes, "<time>"), ctx);
}

/** `text` with the run's identifiers as placeholders (the issuer host first: it holds both). */
function placeholders(text, ctx) {
  let out = ctx.issuerHost ? text.replaceAll(ctx.issuerHost, "<issuer-host>") : text;
  out = out.replaceAll(ctx.run, "<run>").replaceAll(ctx.project, "<project>");
  // What made one pass's credentials differ from the next pass's (record-strict-safety).
  if (ctx.passTag) out = out.replaceAll(ctx.passTag, "<pass>");
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
    if (TOKEN_KEYS.has(key)) return normalize(decodeToken(value, key), ctx);
    if (MASKED[key]) return MASKED[key];
    // A corpus that tags its passes sends a new raw nonce each pass, so the hash the answer
    // echoes differs; its form is kept, as the authUri's nonce is.
    if (key === "nonce" && ctx.passTag && /^[0-9a-f]{64}$/.test(value)) return "<nonce:hex64>";
    if (KEPT_ONLY[key]) return KEPT_ONLY[key](value);
    // The service's authorization state, and the nonce it makes when none is given, differ
    // on every createAuthUri (the nonce's form is kept).
    if (key === "authUri" && value.includes("SAMLRequest=")) return samlAuthUri(value, ctx);
    if (key === "authUri") {
      const uri = value
        .replace(/([?&]state=)[^&#]*/, "$1<state>")
        .replace(/([?&]nonce=)[0-9a-f]{64}(?=[&#]|$)/, "$1<nonce:hex64>");
      return placeholders(uri, ctx);
    }
    if (key === "message") return normalizeMessage(value, ctx);
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

/**
 * The recorded form of an HTTP answer. With `paths` (dotted), only those members of the body
 * are recorded (a config write answers the whole project config).
 */
export function normalizeHttp(status, text, ctx, paths) {
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    body = text === "" ? undefined : "<non-json>";
  }
  if (paths && body && typeof body === "object") body = pick(body, paths);
  return { status, body: normalize(body, ctx) };
}

/** Only the members of `value` at the dotted `paths`, in their places. */
function pick(value, paths) {
  const out = {};
  for (const path of paths) {
    const keys = path.split(".");
    const found = keys.reduce((node, key) => node?.[key], value);
    if (found === undefined) continue;
    keys.reduce((node, key, index) => {
      node[key] = index === keys.length - 1 ? found : (node[key] ?? {});
      return node[key];
    }, out);
  }
  return out;
}
