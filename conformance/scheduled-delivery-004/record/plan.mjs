// The names, schedules and pins of the delivery recording. Pure data and pure functions of it:
// importing this module sends nothing and reads nothing.

export const PROJECT = "fireemu-oracle-sbx";
export const REGION = "us-central1";
export const CODEBASE = "scheduled-delivery";
export const NODE_VERSION = "22.22.1";
export const FIREBASE_TOOLS_VERSION = "15.28.2";
export const FIREBASE_FUNCTIONS_VERSION = "7.3.2";

/** The six deployed functions, case-exact, by generation. */
export const FUNCTIONS = Object.freeze({
  v2: Object.freeze(["schedRetryV2", "declNullV2", "declOmitV2", "declTimeoutV2"]),
  v1: Object.freeze(["schedFailV1", "schedRetryV1"]),
});
export const ALL_FUNCTIONS = Object.freeze([...FUNCTIONS.v2, ...FUNCTIONS.v1]);

/** Cloud Run service ids and Eventarc trigger ids are lowercase; GCF v2 names keep their case. */
export const runServiceId = (fn) => fn.toLowerCase();

/** The Scheduler job (and, for v1, the Pub/Sub topic) the Firebase CLI creates for a function. */
export const scheduleId = (fn) => "firebase-schedule-" + fn + "-" + REGION;
export const jobName = (id) => "projects/" + PROJECT + "/locations/" + REGION + "/jobs/" + id;
export const topicName = (id) => "projects/" + PROJECT + "/topics/" + id;
export const functionName = (fn) =>
  "projects/" + PROJECT + "/locations/" + REGION + "/functions/" + fn;

/** What the fixture declares, as the SDK discovery must report it (the offline check pins these). */
export const DECLARED = Object.freeze({
  schedRetryV2: {
    platform: "gcfv2",
    schedule: "every 5 minutes",
    timeZone: "Asia/Tokyo",
    retryConfig: { retryCount: 4, minBackoffSeconds: 4, maxBackoffSeconds: 50, maxDoublings: 2 },
  },
  schedFailV1: { platform: "gcfv1", schedule: "every 5 minutes", timeZone: undefined },
  // The Gen1 retry probe: schedFailV1 declares no count; this one declares retryCount 1. A Gen1 schedule's discovered
  // retryConfig lists the options it does not set as null (the SDK's v1 builder).
  schedRetryV1: {
    platform: "gcfv1",
    schedule: "every 5 minutes",
    timeZone: undefined,
    retryConfig: {
      retryCount: 1,
      minBackoffDuration: null,
      maxBackoffDuration: null,
      maxDoublings: null,
      maxRetryDuration: null,
    },
  },
  // The declaration probes (never run on their schedule, 1 January): every optional setting reset with RESET_VALUE
  // (null in the manifest), the same settings omitted (an empty retryConfig and no time zone), and a function
  // timeout of 540 s, which the CLI turns into the job's attemptDeadline.
  declNullV2: {
    platform: "gcfv2",
    schedule: "0 0 1 1 *",
    timeZone: undefined,
    retryConfig: {
      retryCount: null,
      maxDoublings: null,
      maxRetrySeconds: null,
      minBackoffSeconds: null,
      maxBackoffSeconds: null,
    },
  },
  declOmitV2: {
    platform: "gcfv2",
    schedule: "0 0 1 1 *",
    timeZone: undefined,
    retryConfig: {},
  },
  declTimeoutV2: {
    platform: "gcfv2",
    schedule: "0 0 1 1 *",
    timeZone: undefined,
    retryConfig: {},
    timeoutSeconds: 540,
  },
});

/**
 * The deploys. Round 1 deploys every function. Rounds 2 and 3 redeploy only the declaration functions, after the
 * recorder has changed their Scheduler jobs from outside (`DRIFT`): firebase-tools (15.28.2, `cloudscheduler.js`)
 * leaves a job alone unless its schedule, time zone, attemptDeadline or a retryConfig field it sends differs, so what
 * the redeploy resets and what it keeps is what the omitted-versus-null case asks. The source of each redeploy differs
 * by the `ROUND` number in the fixture, because the CLI skips a function whose source is unchanged.
 */
export const ROUND_FUNCTIONS = Object.freeze(["declNullV2", "declOmitV2", "declTimeoutV2"]);
export const ROUNDS = 3;
const RETRY_DRIFT = (count, doublings, max, zone) => ({
  timeZone: zone,
  retryConfig: {
    retryCount: count,
    minBackoffDuration: "4s",
    maxBackoffDuration: max,
    maxDoublings: doublings,
  },
});
/** The change made to each job from outside before the redeploy of round 2 or 3: the PATCH body and its `updateMask`. */
export const DRIFT = Object.freeze({
  2: Object.freeze({
    declNullV2: { mask: "timeZone,retryConfig", body: RETRY_DRIFT(2, 1, "30s", "Asia/Tokyo") },
    declOmitV2: { mask: "timeZone,retryConfig", body: RETRY_DRIFT(2, 1, "30s", "Asia/Tokyo") },
    declTimeoutV2: { mask: "attemptDeadline", body: { attemptDeadline: "300s" } },
  }),
  3: Object.freeze({
    declNullV2: {
      mask: "timeZone,retryConfig",
      body: RETRY_DRIFT(3, 2, "60s", "America/New_York"),
    },
    declOmitV2: {
      mask: "timeZone,retryConfig",
      body: RETRY_DRIFT(3, 2, "60s", "America/New_York"),
    },
    declTimeoutV2: { mask: "attemptDeadline", body: { attemptDeadline: "240s" } },
  }),
});

/**
 * The extra Scheduler jobs the recorder itself creates (never deployed), each aimed at the `schedRetryV2` function
 * so that a retry rule is observed without deploying another function. Their names carry the run id. The target
 * (uri and OIDC account) is copied from the deployed job's readback at run time, so these differ from it only in the
 * retry rule and the schedule. Every field and value form below was accepted by production in run
 * 156715222b86ea44 (whole seconds, `retryCount` 0 to 5, `maxDoublings` 1 to 5); `maxDoublings 0` and the combination
 * of a count with a window were not recorded: an answer of 400 to either is the observation.
 */
export const EXTRA_JOBS = Object.freeze([
  // The interaction of a count and a window, with whole seconds only (run 156715222b86ea44 sent a fractional window
  // here and was refused). The backoff is the recorded one of the `duration` job (min 4 s, max 10 s: gaps of about
  // 4, 8 and 10 s, attempts at 0, 4.6, 13.2 and 23.7 s). A count of 3 allows four attempts and a window of 20 s allows
  // three (the fourth would be at about 23.7 s): three means the chain stops at the first limit reached, four that
  // retries continue until both limits are used up.
  {
    key: "count",
    cases: ["count-and-duration-interaction"],
    schedule: "0 0 1 1 *",
    timeZone: "UTC",
    retryConfig: {
      retryCount: 3,
      maxRetryDuration: "20s",
      minBackoffDuration: "4s",
      maxBackoffDuration: "10s",
    },
  },
  // The linear step after the doublings. The deployed `schedRetryV2` is the control (min 4 s, max 50 s, 2 doublings,
  // count 4: gaps of about 4, 8, 16 and 18.5 s in both earlier runs, where the documented rule gives 32). These three
  // use the largest count Cloud Scheduler accepts (5, six attempts) and a cap (100 s) no gap reaches: no doublings,
  // one, and three, at two minima, so the gap after the doublings can be read as a function of both.
  {
    key: "double0",
    cases: ["linear-after-doublings"],
    schedule: "0 0 1 1 *",
    timeZone: "UTC",
    retryConfig: {
      retryCount: 5,
      minBackoffDuration: "3s",
      maxBackoffDuration: "100s",
      maxDoublings: 0,
    },
  },
  {
    key: "double1",
    cases: ["linear-after-doublings"],
    schedule: "0 0 1 1 *",
    timeZone: "UTC",
    retryConfig: {
      retryCount: 5,
      minBackoffDuration: "4s",
      maxBackoffDuration: "100s",
      maxDoublings: 1,
    },
  },
  {
    key: "double3",
    cases: ["linear-after-doublings"],
    schedule: "0 0 1 1 *",
    timeZone: "UTC",
    retryConfig: {
      retryCount: 5,
      minBackoffDuration: "2s",
      maxBackoffDuration: "100s",
      maxDoublings: 3,
    },
  },
]);

export const RUN_ID = /^[a-f0-9]{16}$/;
export const extraJobId = (runId, key) => {
  if (!RUN_ID.test(runId ?? "")) throw new Error("invalid run ID");
  return "fe-sd-" + runId + "-" + key;
};
/** The pull subscription the recorder puts on a v1 function's topic. */
export const pullSubscriptionId = (runId, fn) => {
  if (!RUN_ID.test(runId ?? "")) throw new Error("invalid run ID");
  return "fe-sd-" + runId + "-pull-" + fn.toLowerCase();
};
export const subscriptionName = (id) => "projects/" + PROJECT + "/subscriptions/" + id;

/** The marker the fixture prints before each frame. */
export const FRAME_MARK = "SCHED_DELIVERY_FRAME";

/** The ids of the Scheduler jobs the recorder may touch: the six the CLI creates and the extra ones. */
export const jobIds = (runId) => [
  ...ALL_FUNCTIONS.map(scheduleId),
  ...EXTRA_JOBS.map((job) => extraJobId(runId, job.key)),
];
