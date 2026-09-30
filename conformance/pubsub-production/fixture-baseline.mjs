// Capture-only fixed fixture prerequisites. The admitted coordinator owns credentials, locks and durable storage.
import { createHash } from "node:crypto";
import { responseBytes } from "./preflight.mjs";
const PROJECT = "fireemu-oracle-idp";
export function baselineRequests(projectNumber) {
  if (!/^[0-9]{12,13}$/.test(projectNumber)) throw new Error("explicit project number required");
  const principal = `service-${projectNumber}@gcp-sa-pubsub.iam.gserviceaccount.com`;
  return Object.freeze(
    [
      {
        id: "identity",
        method: "GET",
        url: `https://cloudresourcemanager.googleapis.com/v3/projects/${PROJECT}`,
        readOnly: true,
      },
      {
        id: "project-iam",
        method: "POST",
        url: `https://cloudresourcemanager.googleapis.com/v1/projects/${PROJECT}:getIamPolicy`,
        requestBody: '{"options":{"requestedPolicyVersion":3}}',
        readOnly: true,
      },
      {
        id: "pubsub-service-identity",
        method: "GET",
        url: `https://iam.googleapis.com/v1/projects/${PROJECT}/serviceAccounts/${encodeURIComponent(principal)}`,
        readOnly: true,
      },
    ].map(Object.freeze),
  );
}
export async function collectBaseline({
  projectNumber,
  accessToken,
  guard,
  persist,
  send = (request) => fetch(request.url, request),
  clock = Date.now,
  signal,
}) {
  if (typeof guard !== "function" || typeof persist !== "function")
    throw new Error("live admission and durable receipt sink required");
  if (signal !== undefined && !(signal instanceof AbortSignal))
    throw new Error("abort signal required");
  if (
    typeof accessToken !== "string" ||
    !accessToken ||
    accessToken.length > 16384 ||
    /\s/.test(accessToken)
  )
    throw new Error("bounded coordinator credential required");
  const requests = baselineRequests(projectNumber),
    started = clock();
  const deadline = new AbortController();
  const wallTimer = setTimeout(() => deadline.abort(), 600000);
  wallTimer.unref();
  const overall = signal ? AbortSignal.any([signal, deadline.signal]) : deadline.signal;
  let attempted = 0,
    completed = 0,
    terminationRequired = false;
  // Pending callbacks belong to the runner's collector process. An interrupted callback requires verified process termination before lock release.
  async function bounded(operation, activeSignal = overall) {
    activeSignal.throwIfAborted();
    let settled = false,
      onAbort;
    const pending = Promise.resolve()
      .then(operation)
      .finally(() => {
        settled = true;
      });
    const aborted = new Promise((_resolve, reject) => {
      onAbort = () => {
        if (!settled) terminationRequired = true;
        reject(new Error("baseline operation interrupted"));
      };
      activeSignal.addEventListener("abort", onAbort, { once: true });
      if (activeSignal.aborted) onAbort();
    });
    try {
      return await Promise.race([pending, aborted]);
    } finally {
      activeSignal.removeEventListener("abort", onAbort);
    }
  }
  async function save(row) {
    if (JSON.stringify(row).includes(accessToken)) throw new Error("credential reflection refused");
    await bounded(() => persist(row, { signal: overall }));
    remaining();
  }
  function remaining() {
    const value = 600000 - (clock() - started);
    overall.throwIfAborted();
    if (value <= 0) throw new Error("baseline wall bound exhausted");
    return Math.min(30000, value);
  }
  try {
    for (const request of requests) {
      remaining();
      await bounded(() => guard(request, { signal: overall }));
      remaining();
      // A rejected or interrupted reservation may already have reached durable storage.
      attempted++;
      await save({ ...request, state: "before-send" });
      await bounded(() => guard(request, { signal: overall }));
      const timeout = remaining();
      const requestAbort = new AbortController();
      const requestSignal = AbortSignal.any([
        overall,
        requestAbort.signal,
        AbortSignal.timeout(timeout),
      ]);
      let response;
      try {
        response = await bounded(
          () =>
            send({
              ...request,
              ...(request.requestBody ? { body: request.requestBody } : {}),
              redirect: "manual",
              signal: requestSignal,
              headers: {
                authorization: `Bearer ${accessToken}`,
                "x-goog-user-project": PROJECT,
                ...(request.requestBody ? { "content-type": "application/json" } : {}),
              },
            }),
          requestSignal,
        );
        remaining();
        const headers = Array.from(response.headers);
        if (headers.flat().reduce((size, value) => size + Buffer.byteLength(value), 0) > 16384)
          throw new Error("baseline header bound exceeded");
        await save({ id: request.id, state: "response-headers", status: response.status, headers });
        const bytes = await bounded(() => responseBytes(response), requestSignal);
        remaining();
        if (bytes.includes(Buffer.from(accessToken)))
          throw new Error("credential reflection refused");
        await save({
          ...request,
          state: "response-persisted",
          status: response.status,
          headers,
          body: bytes.toString("utf8"),
          bodyBase64: bytes.toString("base64"),
          bodyBytes: bytes.length,
          bodySha256: createHash("sha256").update(bytes).digest("hex"),
        });
        completed++;
        if (response.status >= 300 && response.status < 400)
          throw new Error("baseline redirect refused");
      } finally {
        requestAbort.abort();
        if (response?.body && !response.body.locked) {
          if (overall.aborted) {
            terminationRequired = true;
            Promise.resolve()
              .then(() => response.body.cancel())
              .catch(() => {});
            overall.throwIfAborted();
          }
          const cleanup = AbortSignal.any([overall, AbortSignal.timeout(1000)]);
          await bounded(() => response.body.cancel(), cleanup);
        }
      }
    }
    remaining();
    if (terminationRequired) throw new Error("collector process termination required");
    return {
      outcome: "captured-read-only-baseline",
      attempted,
      completed,
      unknown: attempted - completed,
    };
  } catch {
    return {
      outcome: "incomplete-read-only-baseline",
      attempted,
      completed,
      unknown: attempted - completed,
      ...(terminationRequired ? { terminationRequired: true } : {}),
    };
  } finally {
    clearTimeout(wallTimer);
  }
}
