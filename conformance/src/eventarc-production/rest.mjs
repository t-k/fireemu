// The REST transport of the Eventarc recordings. It is the transport of the Pub/Sub recordings with three
// additions that stage A lacked:
//
// - the raw bytes of every answer (`bodyBase64`, `bodyBytes`) and its headers are captured, so that the
//   layout of an answer (indentation, member order, final newline, content length) is recorded and not
//   only the parsed JSON. The request asks for the identity encoding, so that `content-length` is the
//   length of the bytes that were read;
// - the credential variants of the token-format probes: a `ya29.`-shaped and a JWT-shaped token that
//   Google never issued, a JWT-shaped token whose expiry is in 1970, and a bearer token the caller
//   obtained (a token of another scope). The capture names the mode, never the token;
// - the quota project can be overridden for one request (`quotaProject`, `null` for none).
//
// One attempt for each request, counted against the budget before it is sent. A transport error or a
// timeout is an unknown answer and is never retried.

import { parseBody } from "../pubsub-production/rest.mjs";

const b64url = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");

/** The tokens Google never issued, by mode. None is a credential: each is built from constants. */
export const TOKEN_MODES = Object.freeze({
  invalid: "invalid-token-for-the-recording",
  "ya29-garbage": "ya29.fireemu-recorder-not-a-token-0000000000000000",
  "jwt-garbage": `${b64url({ alg: "RS256", typ: "JWT" })}.${b64url({ iss: "fireemu-recorder", sub: "x" })}.fireemu-recorder-not-a-signature`,
  "jwt-expired-unsigned": `${b64url({ alg: "RS256", typ: "JWT" })}.${b64url({ iss: "https://accounts.google.com", aud: "fireemu-recorder", iat: 0, exp: 1 })}.fireemu-recorder-not-a-signature`,
});

const DEFAULT_MODES = new Set(["default", "none"]);

/** The mode a `token` option names, and the bearer it sends (or null). Throws for anything else. */
function resolveToken(token) {
  if (typeof token === "string" && DEFAULT_MODES.has(token)) return { mode: token, bearer: null };
  if (typeof token === "string" && Object.hasOwn(TOKEN_MODES, token))
    return { mode: token, bearer: TOKEN_MODES[token] };
  if (
    token !== null &&
    typeof token === "object" &&
    typeof token.label === "string" &&
    /^[a-z0-9-]{1,40}$/.test(token.label) &&
    typeof token.bearer === "string" &&
    token.bearer !== ""
  )
    return { mode: token.label, bearer: token.bearer };
  throw new Error("unknown credential mode");
}

export function createRawRest({
  base,
  budget,
  capture,
  getToken = null,
  quotaProject = null,
  fetchImpl = fetch,
  defaultTimeoutMs = 30_000,
  now = Date.now,
}) {
  if (typeof base !== "string" || !/^https?:\/\/[^/]+$/.test(base))
    throw new Error("the REST base must be an origin");
  return Object.freeze({
    name: "rest",
    async request({
      label,
      op,
      method,
      path,
      body,
      token = "default",
      quotaProject: quota = quotaProject,
      timeoutMs = defaultTimeoutMs,
    }) {
      const credential = resolveToken(token);
      budget.consume();
      const headers = { "accept-encoding": "identity" };
      if (body !== undefined) headers["content-type"] = "application/json";
      if (credential.bearer !== null) headers.authorization = `Bearer ${credential.bearer}`;
      else if (credential.mode === "default" && getToken !== null)
        headers.authorization = `Bearer ${await getToken()}`;
      const sendsQuota = quota !== null && credential.mode !== "none";
      if (sendsQuota) headers["x-goog-user-project"] = quota;
      const payload = body === undefined ? undefined : JSON.stringify(body);
      const started = now();
      const entry = {
        ...label,
        transport: "rest",
        op,
        tokenMode: credential.mode,
        request: { method, path, ...(body === undefined ? {} : { body }) },
        ...(payload === undefined ? {} : { requestBytes: Buffer.byteLength(payload) }),
        // The one header that is recorded: where the quota of the call is charged (never a credential).
        ...(sendsQuota ? { quotaProject: quota } : {}),
      };
      let response;
      try {
        const reply = await fetchImpl(`${base}${path}`, {
          method,
          headers,
          body: payload,
          signal: AbortSignal.timeout(timeoutMs),
        });
        const raw = Buffer.from(await reply.arrayBuffer());
        const parsed = parseBody(raw.toString("utf8"));
        const received = Object.fromEntries(
          [...reply.headers.entries()].filter(([name]) => name !== "set-cookie"),
        );
        response = {
          status: reply.status,
          body: parsed,
          bodyBase64: raw.toString("base64"),
          bodyBytes: raw.length,
          headers: received,
        };
        // A status below 200, a redirect, a server error (other than 501, which says the method is not
        // implemented and so was not applied), and a success whose body is not JSON do not say what was done.
        if (
          reply.status < 200 ||
          (reply.status >= 300 && reply.status < 400) ||
          (reply.status >= 500 && reply.status !== 501) ||
          (reply.status < 300 && parsed !== null && typeof parsed.raw === "string")
        )
          response.unknown = true;
      } catch (error) {
        // Only the kind of failure is kept: never the message, which could carry a header.
        response = {
          status: null,
          unknown: true,
          error: error?.name === "TimeoutError" ? "timeout" : "transport",
        };
      }
      entry.response = response;
      entry.ms = now() - started;
      if (response.unknown) entry.unknown = true;
      capture.record(entry);
      return { status: response.status, body: response.body, unknown: response.unknown === true };
    },
  });
}
