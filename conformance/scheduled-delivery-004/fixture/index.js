// The fixture of the fourth SCHEDULED-FUNCTIONS delivery recording (packet delivery-004): four v2 and two v1 scheduled
// functions. The three `decl*` functions exist for their declarations (read back from the Scheduler job after a deploy,
// and again after two redeploys of a job changed from outside); the others are the retry targets and probes.
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
const { RESET_VALUE } = require("firebase-functions/v2/options");
const { onSchedule } = require("firebase-functions/v2/scheduler");

// The recorder rewrites this number before each redeploy so that the source differs and the CLI updates the functions
// (it skips an unchanged one); nothing reads it.
const ROUND = 1;
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

// Fails while the attempt is within twenty seconds of the scheduled time, so a retry chain fails a few
// times and then succeeds. Retry declared with every option the SDK has but maxRetrySeconds. retryCount is 4, the
// largest value Cloud Scheduler accepts: it refused 6 (run e0ec2f41, 400 "invalid retry count. The retry_count must be
// a positive integer less than 5").
exports.schedRetryV2 = observed(
  onSchedule(
    {
      schedule: "every 5 minutes",
      timeZone: "Asia/Tokyo",
      region: REGION,
      retryCount: 4,
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

// Always fails; no failure policy, so the subscriber does not retry. The time zone is omitted.
exports.schedFailV1 = functionsV1
  .region(REGION)
  .pubsub.schedule("every 5 minutes")
  .onRun(async (...args) => {
    frameV1("schedFailV1", args, { failing: true });
    throw new Error("deliberate failure of a scheduled v1 handler");
  });

// The Gen1 retry probe: always fails, and declares retryCount 1. Run 2's schedFailV1 declared no count and ran once
// per occurrence; the question here is whether a declared count makes Cloud Scheduler or Pub/Sub deliver the message of
// a failed handler again (a repeated message id would show it).
exports.schedRetryV1 = functionsV1
  .region(REGION)
  .pubsub.schedule("every 5 minutes")
  .retryConfig({ retryCount: 1 })
  .onRun(async (...args) => {
    frameV1("schedRetryV1", args, { failing: true });
    throw new Error("deliberate failure of a scheduled v1 handler with a retry count");
  });

// ---- v2: declarations read back from the Scheduler job --------------------------------------------------------
//
// None of these runs on its schedule (1 January, 00:00 UTC); the recorder forces each once per pass.

// Every optional setting explicitly reset (RESET_VALUE is null in the manifest).
exports.declNullV2 = observed(
  onSchedule(
    {
      schedule: "0 0 1 1 *",
      region: REGION,
      timeZone: RESET_VALUE,
      retryCount: RESET_VALUE,
      maxRetrySeconds: RESET_VALUE,
      minBackoffSeconds: RESET_VALUE,
      maxBackoffSeconds: RESET_VALUE,
      maxDoublings: RESET_VALUE,
    },
    async (event) => {
      frameV2("declNullV2", event, { round: ROUND });
    },
  ),
);

// The same settings omitted.
exports.declOmitV2 = observed(
  onSchedule({ schedule: "0 0 1 1 *", region: REGION }, async (event) => {
    frameV2("declOmitV2", event, { round: ROUND });
  }),
);

// A function timeout between the Scheduler's default attempt deadline (180 s) and its maximum (1800 s): the CLI turns it
// into the job's attemptDeadline.
exports.declTimeoutV2 = observed(
  onSchedule({ schedule: "0 0 1 1 *", region: REGION, timeoutSeconds: 540 }, async (event) => {
    frameV2("declTimeoutV2", event, { round: ROUND });
  }),
);
