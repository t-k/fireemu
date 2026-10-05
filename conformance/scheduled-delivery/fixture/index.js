// The fixture of the SCHEDULED-FUNCTIONS delivery recording: three v2 and two v1 scheduled functions.
// Each invocation prints one line, `SCHED_DELIVERY_FRAME {json}`, that says what the function was
// handed: the HTTP request a v2 function received (method, every header but the credential, the raw
// body), the event the SDK built from it, and for v1 the context. The recorder reads these lines from
// Cloud Logging. Nothing here talks to another service.
//
// Every function pins region us-central1: the Firebase CLI places a function with no region by its
// trigger's service default, and the FE v4 run lost a function to us-east1 that way.
const { AsyncLocalStorage } = require("node:async_hooks");
const functionsV1 = require("firebase-functions/v1");
const { setGlobalOptions } = require("firebase-functions/v2");
const { onSchedule } = require("firebase-functions/v2/scheduler");

const MARK = "SCHED_DELIVERY_FRAME";
const REGION = "us-central1";
// The v2 string form of onSchedule takes no options; this is what puts it in the pinned region.
setGlobalOptions({ region: REGION });

const printFrame = (frame) =>
  console.log(MARK + " " + JSON.stringify({ receivedAt: new Date().toISOString(), ...frame }));

// ---- v2: the request the Scheduler sent, seen before the SDK wraps it -------------------------------

const requests = new AsyncLocalStorage();

/** The request as received. The credential is reduced to its presence and length. */
function describeRequest(req) {
  const headers = { ...req.headers };
  if (typeof headers.authorization === "string")
    headers.authorization = "<credential, " + headers.authorization.length + " chars>";
  const raw = req.rawBody ? req.rawBody.toString("utf8") : null;
  return {
    method: req.method,
    url: req.originalUrl ?? req.url,
    headers,
    rawBodyLength: raw === null ? null : raw.length,
    rawBody: raw !== null && raw.length <= 4096 ? raw : null,
    body: req.body === undefined ? null : req.body,
  };
}

/**
 * Wraps the HTTP function onSchedule returns so that the request can be described. The wrapper carries
 * the SDK's own properties (`__endpoint`, `__trigger`, `run`), so the deploy sees the same function.
 */
function observed(scheduled) {
  const wrapper = (req, res) => requests.run(describeRequest(req), () => scheduled(req, res));
  return Object.assign(wrapper, scheduled);
}

/** What the SDK handed the handler, including what is not enumerable. */
function describeEvent(event) {
  const descriptor = Object.getOwnPropertyDescriptor(event, "context");
  let context = null;
  try {
    context = JSON.parse(JSON.stringify(event.context));
  } catch {
    context = null;
  }
  return {
    event: JSON.parse(JSON.stringify(event)),
    eventKeys: Object.keys(event),
    contextProperty: descriptor
      ? {
          enumerable: descriptor.enumerable,
          configurable: descriptor.configurable,
          hasGetter: typeof descriptor.get === "function",
        }
      : null,
    context,
  };
}

const frameV2 = (handler, event, extra = {}) =>
  printFrame({
    handler,
    generation: 2,
    request: requests.getStore() ?? null,
    ...describeEvent(event),
    ...extra,
  });

// The string form of onSchedule (no options, no time zone: the default applies).
exports.schedOkV2 = observed(
  onSchedule("every 1 minutes", async (event) => {
    frameV2("schedOkV2", event);
  }),
);

// Fails while the attempt is within twenty seconds of the scheduled time, so a retry chain fails a few
// times and then succeeds. Retry declared with every option the SDK has but maxRetrySeconds.
exports.schedRetryV2 = observed(
  onSchedule(
    {
      schedule: "every 5 minutes",
      timeZone: "Asia/Tokyo",
      region: REGION,
      retryCount: 6,
      minBackoffSeconds: 4,
      maxBackoffSeconds: 50,
      maxDoublings: 2,
    },
    async (event) => {
      const elapsedMs = Date.now() - Date.parse(event.scheduleTime);
      const failing = elapsedMs < 20_000;
      frameV2("schedRetryV2", event, { elapsedMs, failing });
      if (failing) throw new Error("deliberate failure of a scheduled attempt");
    },
  ),
);

// Runs longer than its own timeout, across the next occurrence, with no retry.
exports.schedSlowV2 = observed(
  onSchedule(
    { schedule: "every 1 minutes", region: REGION, timeoutSeconds: 90, retryCount: 0 },
    async (event) => {
      frameV2("schedSlowV2", event, { phase: "start" });
      await new Promise((resolve) => setTimeout(resolve, 100_000));
      frameV2("schedSlowV2", event, { phase: "end" });
    },
  ),
);

// ---- v1: the message the Scheduler published and the context the SDK builds --------------------------

// Every argument the handler was called with is printed: the SDK documents a context-only handler, and
// what fireemu passes locally is one of the things the recording is compared with.
const frameV1 = (handler, args, extra = {}) =>
  printFrame({
    handler,
    generation: 1,
    argumentCount: args.length,
    arguments: args.map((a) => JSON.parse(JSON.stringify(a ?? null))),
    context: JSON.parse(JSON.stringify(args[args.length - 1] ?? null)),
    ...extra,
  });

// A context-only handler, an explicit time zone.
exports.schedOkV1 = functionsV1
  .region(REGION)
  .pubsub.schedule("every 1 minutes")
  .timeZone("Asia/Tokyo")
  .onRun(async (...args) => {
    frameV1("schedOkV1", args);
  });

// Always fails; no failure policy, so the subscriber does not retry. The time zone is omitted.
exports.schedFailV1 = functionsV1
  .region(REGION)
  .pubsub.schedule("every 5 minutes")
  .onRun(async (...args) => {
    frameV1("schedFailV1", args, { failing: true });
    throw new Error("deliberate failure of a scheduled v1 handler");
  });
