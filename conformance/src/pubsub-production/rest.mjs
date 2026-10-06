// The REST transport of a recording: one attempt for each request, counted against the budget before it
// is sent, captured as it happens. A transport error or a timeout is an unknown answer (`unknown: true`,
// no status): it is recorded and never retried.

const INVALID_TOKEN = "invalid-token-for-the-recording";
const TEXT_LIMIT = 4096;

export function parseBody(text) {
  if (text === "") return null;
  try {
    return JSON.parse(text);
  } catch {
    return { raw: text.slice(0, TEXT_LIMIT) };
  }
}

export function createRest({
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
    /**
     * Sends one request. `token` is "default" (the owner's token, none against an emulator), "none" or
     * "invalid". `label` names the case and the step in the capture.
     */
    async request({
      label,
      op,
      method,
      path,
      body,
      token = "default",
      timeoutMs = defaultTimeoutMs,
      remainingTime,
      getCredential,
    }) {
      budget.consume();
      const headers = {};
      if (body !== undefined) headers["content-type"] = "application/json";
      if (token === "invalid") headers.authorization = `Bearer ${INVALID_TOKEN}`;
      else if (token === "default" && getToken !== null)
        headers.authorization = `Bearer ${await (getCredential ? getCredential(getToken) : getToken())}`;
      if (quotaProject !== null && token !== "none") headers["x-goog-user-project"] = quotaProject;
      if (remainingTime) timeoutMs = Math.min(timeoutMs, remainingTime());
      const started = now();
      const entry = {
        ...label,
        transport: "rest",
        op,
        request: { method, path, ...(body === undefined ? {} : { body }) },
      };
      let response;
      try {
        const reply = await fetchImpl(`${base}${path}`, {
          method,
          headers,
          body: body === undefined ? undefined : JSON.stringify(body),
          signal: AbortSignal.timeout(timeoutMs),
          redirect: "manual",
        });
        const bytes =
          typeof reply.arrayBuffer === "function"
            ? Buffer.from(await reply.arrayBuffer())
            : Buffer.from(await reply.text(), "utf8");
        const text = bytes.toString("utf8");
        const parsed = parseBody(text);
        const contentLength = reply.headers?.get("content-length");
        response = {
          status: reply.status,
          body: parsed,
          bodyBytes: bytes.length,
          ...(contentLength == null ? {} : { contentLength }),
        };
        let readable = text === "";
        if (text !== "") {
          try {
            const json = JSON.parse(text);
            readable = json !== null && typeof json === "object" && !Array.isArray(json);
          } catch {
            readable = false;
          }
        }
        if (
          reply.status < 200 ||
          (reply.status >= 300 && reply.status < 400) ||
          reply.status >= 500 ||
          reply.status === 499 ||
          !readable
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
