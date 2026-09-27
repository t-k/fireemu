// Recording form of an AUTH-FEDERATION answer (draft). The same normalization applies to the
// sandbox and to fireemu, so the two can be compared row by row:
// - the run tag, the project and its number become placeholders;
// - certificates (the run's IdP certificate, the service's SP certificates) become
//   placeholders with their count kept;
// - ID tokens and session cookies are recorded as their header and claims (times relative to
//   `iat`), never as the token.

const TOKEN_KEYS = new Set(["idToken", "id_token", "sessionCookie", "oauthIdToken"]);
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

function decodeToken(token) {
  const [header, payload] = String(token).split(".");
  try {
    const decode = (part) => JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
    const claims = decode(payload);
    const iat = claims.iat;
    for (const key of ["exp", "auth_time", "nbf"]) {
      if (typeof claims[key] === "number" && typeof iat === "number") {
        claims[key] = `iat${claims[key] - iat >= 0 ? "+" : ""}${claims[key] - iat}`;
      }
    }
    if (typeof iat === "number") claims.iat = "<iat>";
    return { "<jwt>": { header: decode(header), claims } };
  } catch {
    return "<unparsable-token>";
  }
}

/** The recorded form of `value`, with the run's identifiers as placeholders. */
export function normalize(value, ctx, key = "") {
  if (typeof value === "string") {
    if (TOKEN_KEYS.has(key)) return normalize(decodeToken(value), ctx);
    if (MASKED[key]) return MASKED[key];
    let text = value.replaceAll(ctx.run, "<run>").replaceAll(ctx.project, "<project>");
    if (ctx.projectNumber) text = text.replaceAll(String(ctx.projectNumber), "<project-number>");
    return text;
  }
  if (Array.isArray(value)) return value.map((item) => normalize(item, ctx, key));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, normalize(v, ctx, k)]),
    );
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
