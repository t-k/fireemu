// Request capture for the scheduled-delivery recorders: one injected `send`, an allowlist that every
// request must pass, a durable journal row written before each request and after each answer, and
// the class of every answer. Importing this module acquires no credentials and sends nothing.
//
// The classes are the ones the calendar v6 review settled on: an answer to a mutation is
// `transport` (no answer), `unreadable` (a status with no readable body), `unknown-status`
// (below 200, 3xx or 5xx), `2xx` or `4xx`. The first three are unknown: the effect may or may not
// have happened, and a later read never turns that into a clean close.

export const MAX_BODY_BYTES = 8 * 1024 * 1024;

/** The class of one answer (`null` is a request that got no answer at all). */
export function answerClass(a) {
  if (!a) return "transport";
  if (a.bodyUnknown) return "unreadable";
  if (a.status < 200 || (a.status >= 300 && a.status < 400) || a.status >= 500)
    return "unknown-status";
  return a.status < 300 ? "2xx" : "4xx";
}
export const isUnknownClass = (a) =>
  ["transport", "unreadable", "unknown-status"].includes(answerClass(a));

export const readable = (a) =>
  !!a && !a.bodyUnknown && a.json !== null && a.json !== undefined && typeof a.json === "object";

/** An expired or rejected credential: the run stops where it is. */
export class AuthStop extends Error {}

export function createCapture({
  accessToken,
  save,
  send,
  clock = Date.now,
  maxRequests,
  maxRequestCap,
  allow,
  quotaProject,
  timeoutFor = () => 10000,
  maxBodyBytes = MAX_BODY_BYTES,
}) {
  if (typeof accessToken !== "string" || !accessToken || /[\r\n]/.test(accessToken))
    throw new Error("coordinator token required");
  if (typeof save !== "function") throw new Error("private persistence required");
  if (typeof allow !== "function") throw new Error("an allowlist is required");
  if (!Number.isSafeInteger(maxRequests) || maxRequests < 1 || maxRequests > maxRequestCap)
    throw new Error("invalid request cap");
  if (typeof quotaProject !== "string" || !quotaProject) throw new Error("quota project required");
  let attempted = 0;
  let completed = 0;
  let authStop = null;

  async function boundedBody(response) {
    const bytes = Buffer.from(await response.arrayBuffer());
    if (bytes.length > maxBodyBytes) throw new Error("body too large");
    return bytes;
  }

  async function capture(spec) {
    if (!allow(spec)) throw new Error("request not allowed: " + spec.id);
    if (attempted >= maxRequests) throw new Error("request cap exceeded");
    const timeoutMs = spec.timeoutMs ?? timeoutFor(spec);
    const dispatchAt = new Date(clock()).toISOString();
    try {
      await save({
        id: spec.id,
        state: "before-send",
        method: spec.method,
        url: spec.url,
        ...(spec.json ? { json: spec.json } : {}),
        dispatchAt,
        timeoutMs,
      });
    } catch {
      throw new Error("private persistence failed before dispatch");
    }
    attempted++;
    let response;
    try {
      response = await send({
        method: spec.method,
        url: spec.url,
        redirect: "manual",
        signal: AbortSignal.timeout(timeoutMs),
        headers: {
          authorization: "Bearer " + accessToken,
          "x-goog-user-project": quotaProject,
          "content-type": "application/json",
        },
        ...(spec.json ? { body: JSON.stringify(spec.json) } : {}),
      });
    } catch {
      await save({
        id: spec.id,
        state: "transport-unknown",
        responseAt: new Date(clock()).toISOString(),
      });
      return null;
    }
    await save({
      id: spec.id,
      state: "response-headers",
      status: response.status,
      responseAt: new Date(clock()).toISOString(),
    });
    let rawBytes;
    try {
      rawBytes = await boundedBody(response);
    } catch {
      await save({
        id: spec.id,
        state: "body-unknown",
        status: response.status,
        responseAt: new Date(clock()).toISOString(),
      });
      return { status: response.status, json: null, bodyUnknown: true };
    }
    if (rawBytes.toString("utf8").includes(accessToken))
      throw new Error("response reflected a credential; capture stopped");
    const responseAt = new Date(clock()).toISOString();
    await save({
      id: spec.id,
      state: "response-persisted",
      status: response.status,
      contentType: response.headers.get("content-type"),
      dispatchAt,
      responseAt,
      bodyBase64: rawBytes.toString("base64"),
      bodyBytes: rawBytes.length,
    });
    completed++;
    let json;
    try {
      json = JSON.parse(rawBytes.toString("utf8"));
    } catch {
      json = null;
    }
    const answer = {
      status: response.status,
      json,
      rawBytes,
      bodyBytes: rawBytes.length,
      dispatchAt,
      responseAt,
    };
    // A 401 is never a production answer to record: the credential is not good. A 403 is the same,
    // except on a request that exists to observe a permission (`observe: true`), where it is data.
    if (answer.status === 401 || (answer.status === 403 && !spec.observe)) {
      authStop = { id: spec.id, status: answer.status };
      throw new AuthStop(spec.id);
    }
    return answer;
  }
  return {
    capture,
    counts: () => ({ attempted, completed, unknown: attempted - completed }),
    authStop: () => authStop,
  };
}
