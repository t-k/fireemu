// The fixture of the TASK-QUEUE-FUNCTIONS recordings: eight v2 task queue functions. The queue is the function (its id is
// the queue id), so each function declares the queue settings one group of cases needs. Each delivery prints two lines,
// `TQ_FRAME {json}`: `start` when the request arrives (what Cloud Tasks sent, seen before the SDK wraps it, and what the
// SDK handed the handler) and `end` when the handler returns or throws. The recorder reads these lines from Cloud
// Logging. Nothing here talks to another service.
//
// A task says what its function does through its own data: `data.script` is a list of steps, one per attempt (the
// attempt is `X-CloudTasks-TaskRetryCount`; the last step repeats), and each step is `{ status, sleepMs }` where `status`
// is "ok" or one of the `HttpsError` codes in CODES. The status Cloud Tasks gets is the SDK's own mapping of that code.
//
// Every function pins region us-central1: the Firebase CLI places a function with no region by its trigger's service
// default. The run's suffix (`suffix.json`, written into the source copy by the recorder) keeps the function ids, and so
// the queue ids, new for every run: Cloud Tasks refuses a queue id that was deleted within the last days.
const { AsyncLocalStorage } = require("node:async_hooks");
const { createHash } = require("node:crypto");
const { setGlobalOptions } = require("firebase-functions/v2");
const { HttpsError } = require("firebase-functions/v2/https");
const { onTaskDispatched } = require("firebase-functions/v2/tasks");
const { suffix } = require("./suffix.json");

const MARK = "TQ_FRAME";
const REGION = "us-central1";
setGlobalOptions({ region: REGION });

/** The error codes a step may name, and the HTTP status the SDK answers for each (firebase-functions 7.3.2). */
const CODES = new Set([
  "internal",
  "resource-exhausted",
  "unavailable",
  "invalid-argument",
  "not-found",
  "permission-denied",
]);
const SHOWN_HEADERS = new Set([
  "content-type",
  "content-length",
  "user-agent",
  "accept-encoding",
  "x-forwarded-proto",
]);
const MAX_TEXT = 4096;
const iso = (ms) => new Date(ms).toISOString();
const print = (frame) => console.log(MARK + " " + JSON.stringify(frame));
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const requests = new AsyncLocalStorage();

/** The request as received. A credential is reduced to its scheme and segment count; other headers keep a value only when listed. */
function describeRequest(req) {
  const headers = {};
  for (const [name, value] of Object.entries(req.headers)) {
    if (name === "authorization") {
      const [scheme, rest = ""] = String(value).split(" ", 2);
      headers[name] = { scheme, segments: rest.split(".").length };
    } else if (SHOWN_HEADERS.has(name) || name.startsWith("x-cloudtasks-")) headers[name] = value;
    else headers[name] = null;
  }
  const raw = req.rawBody ? Buffer.from(req.rawBody) : Buffer.alloc(0);
  return {
    method: req.method,
    path: req.originalUrl ?? req.url,
    headers,
    bodyLength: raw.length,
    bodySha256: createHash("sha256").update(raw).digest("hex"),
    bodyText: raw.length <= MAX_TEXT ? raw.toString("utf8") : null,
  };
}

/** The HTTP function with the request kept for the handler. It carries the SDK's own `__endpoint`, so the deploy sees the same function. */
function observed(task) {
  const wrapper = (req, res) => requests.run(describeRequest(req), () => task(req, res));
  return Object.assign(wrapper, task);
}

function stepOf(data, retryCount) {
  const script = Array.isArray(data?.script) ? data.script : [];
  const step = script[Math.min(retryCount, script.length - 1)] ?? {};
  const status = CODES.has(step.status) ? step.status : "ok";
  const sleepMs = Number.isInteger(step.sleepMs) && step.sleepMs > 0 ? step.sleepMs : 0;
  return { status, sleepMs };
}

function handler(role) {
  const fn = role + suffix;
  return async (task) => {
    const startedAt = Date.now();
    const retryCount = task.retryCount ?? 0;
    const step = stepOf(task.data, retryCount);
    print({
      kind: "start",
      function: fn,
      role,
      at: iso(startedAt),
      run: task.data?.run ?? null,
      case: task.data?.case ?? null,
      request: requests.getStore() ?? null,
      context: {
        id: task.id ?? null,
        queueName: task.queueName ?? null,
        retryCount: task.retryCount ?? null,
        executionCount: task.executionCount ?? null,
        scheduledTime: task.scheduledTime ?? null,
        previousResponse: task.previousResponse ?? null,
        retryReason: task.retryReason ?? null,
        hasAuth: task.auth !== undefined,
      },
      step,
    });
    if (step.sleepMs > 0) await sleep(step.sleepMs);
    print({
      kind: "end",
      function: fn,
      role,
      at: iso(Date.now()),
      startedAt: iso(startedAt),
      run: task.data?.run ?? null,
      case: task.data?.case ?? null,
      id: task.id ?? null,
      retryCount: task.retryCount ?? null,
      status: step.status,
    });
    if (step.status !== "ok") throw new HttpsError(step.status, "scripted " + step.status);
  };
}

/** The role, the queue settings it declares, in the SDK's own option names. An absent option is the SDK default. */
const ROLES = {
  tqdef: {},
  tqretry: {
    retryConfig: { maxAttempts: 6, minBackoffSeconds: 1, maxBackoffSeconds: 6, maxDoublings: 2 },
  },
  tqlimit: { retryConfig: { maxAttempts: 2, minBackoffSeconds: 1, maxBackoffSeconds: 2 } },
  tqwindow: {
    retryConfig: {
      maxAttempts: 100,
      maxRetrySeconds: 6,
      minBackoffSeconds: 1,
      maxBackoffSeconds: 2,
      maxDoublings: 1,
    },
  },
  tqconc1: { rateLimits: { maxConcurrentDispatches: 1, maxDispatchesPerSecond: 500 } },
  tqconc2: { rateLimits: { maxConcurrentDispatches: 2, maxDispatchesPerSecond: 500 } },
  tqrate: { rateLimits: { maxConcurrentDispatches: 100, maxDispatchesPerSecond: 1 } },
  tqdead: { retryConfig: { maxAttempts: 2, minBackoffSeconds: 1, maxBackoffSeconds: 2 } },
};

for (const [role, options] of Object.entries(ROLES))
  exports[role + suffix] = observed(onTaskDispatched(options, handler(role)));
