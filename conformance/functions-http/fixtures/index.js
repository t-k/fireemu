// The same side-effect-free exports are deployed to production and loaded by fireemu.
const { createHash } = require("node:crypto");
const { onCall, onRequest, HttpsError } = require("firebase-functions/v2/https");

const region = "us-central1";
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const sleep = (millis) => new Promise((resolve) => setTimeout(resolve, millis));

function httpHandler(request, response) {
  const mode = request.path.split("/").filter(Boolean)[0] ?? "echo";
  const raw = request.rawBody ?? Buffer.alloc(0);
  if (raw.length > 4096) {
    response.status(413).end();
    return;
  }
  if (mode === "throw-sync") throw new Error("fixture synchronous failure");
  if (mode === "throw-async") return Promise.reject(new Error("fixture rejected promise"));
  if (mode === "timeout") return new Promise(() => {});
  if (mode === "no-response") return;

  if (mode === "large") {
    response.type("text/plain").send("x".repeat(1024 * 1024));
    return;
  }
  if (mode === "stream") {
    response.type("text/plain");
    response.write("first\n");
    return sleep(50).then(() => response.end("second\n"));
  }
  if (mode === "status") {
    response.set("x-fireemu-probe", "response-header");
    const status = request.query.status === "204" ? 204 : 201;
    response.status(status).send(status === 204 ? undefined : "response-body");
    return;
  }

  const forwardedFor = request.get("x-forwarded-for") ?? "";
  response.json({
    method: request.method,
    path: request.path,
    query: request.query,
    contentType: request.get("content-type") ?? null,
    customHeader: request.get("x-fireemu-probe") ?? null,
    forwardedForPresent: forwardedFor.length > 0,
    forwardedForHopCount: forwardedFor ? forwardedFor.split(",").length : 0,
    forwardedProto: request.get("x-forwarded-proto") ?? null,
    executionIdPresent: Boolean(request.get("function-execution-id")),
    body: request.body ?? null,
    rawBodyLength: raw.length,
    rawBodySha256: digest(raw),
  });
}

exports.fireemuHttpProbe = onRequest(
  { region, timeoutSeconds: 1, minInstances: 0, maxInstances: 1, cors: false },
  httpHandler,
);

exports.fireemuCallableProbe = onCall(
  { region, timeoutSeconds: 10, minInstances: 0, maxInstances: 1, heartbeatSeconds: null },
  async (request, response) => {
    const data = request.data ?? {};
    if (JSON.stringify(data).length > 4096) {
      throw new HttpsError("resource-exhausted", "request exceeds fixture limit");
    }
    if (data.op === "error") {
      throw new HttpsError(data.code, `fixture ${data.code}`, { marker: "bounded" });
    }
    if (data.op === "unhandled-error") throw new Error("fixture unhandled failure");
    if (data.op === "auth") {
      return request.auth
        ? {
            uid: request.auth.uid,
            email: request.auth.token.email ?? null,
            emailVerified: request.auth.token.email_verified ?? false,
            signInProvider: request.auth.token.firebase?.sign_in_provider ?? null,
          }
        : { auth: null };
    }
    if (data.op === "stream") {
      await response.sendChunk({ ordinal: 1 });
      await sleep(50);
      await response.sendChunk({ ordinal: 2 });
      return { complete: true };
    }
    return data.value ?? null;
  },
);
