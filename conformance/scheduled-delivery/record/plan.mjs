// The names, schedules and pins of the delivery recording. Pure data and pure functions of it:
// importing this module sends nothing and reads nothing.

export const PROJECT = "fireemu-oracle-sbx";
export const REGION = "us-central1";
export const CODEBASE = "scheduled-delivery";
export const NODE_VERSION = "22.22.1";
export const FIREBASE_TOOLS_VERSION = "15.28.2";
export const FIREBASE_FUNCTIONS_VERSION = "7.3.2";

/** The five deployed functions, case-exact, by generation. */
export const FUNCTIONS = Object.freeze({
  v2: Object.freeze(["schedOkV2", "schedRetryV2", "schedSlowV2"]),
  v1: Object.freeze(["schedOkV1", "schedFailV1"]),
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
  schedOkV2: { platform: "gcfv2", schedule: "every 1 minutes", timeZone: undefined },
  schedRetryV2: {
    platform: "gcfv2",
    schedule: "every 5 minutes",
    timeZone: "Asia/Tokyo",
    retryConfig: { retryCount: 4, minBackoffSeconds: 4, maxBackoffSeconds: 50, maxDoublings: 2 },
  },
  schedSlowV2: { platform: "gcfv2", schedule: "every 1 minutes", timeoutSeconds: 90 },
  schedOkV1: { platform: "gcfv1", schedule: "every 1 minutes", timeZone: "Asia/Tokyo" },
  schedFailV1: { platform: "gcfv1", schedule: "every 5 minutes" },
});

/**
 * The extra Scheduler jobs the recorder itself creates (never deployed), up to three, each aimed at the
 * `schedRetryV2` function so that a retry rule is observed without deploying another function. Their
 * names carry the run id. The target (uri and OIDC account) is copied from the deployed job's readback
 * at run time, so these differ from it only in the retry rule and the schedule.
 */
export const EXTRA_JOBS = Object.freeze([
  {
    key: "zero",
    cases: ["zero-no-retry"],
    schedule: "0 0 1 1 *",
    timeZone: "UTC",
    retryConfig: { retryCount: 0 },
  },
  {
    key: "duration",
    cases: ["duration-only"],
    schedule: "0 0 1 1 *",
    timeZone: "UTC",
    retryConfig: { maxRetryDuration: "30s", minBackoffDuration: "4s", maxBackoffDuration: "10s" },
  },
  {
    key: "count",
    cases: ["count-and-duration-interaction", "fractional-retry-duration"],
    schedule: "0 0 1 1 *",
    timeZone: "UTC",
    retryConfig: {
      retryCount: 3,
      maxRetryDuration: "20.5s",
      minBackoffDuration: "2.5s",
      maxBackoffDuration: "20s",
      maxDoublings: 1,
    },
  },
  // The boundary probe: Cloud Scheduler's message says "less than 5" and it refused 6 (run e0ec2f41), but 5 was
  // never sent. A 2xx is deleted and read back; a 400 is the recorded refusal. Until it is recorded, 5 is unrecorded.
  {
    key: "retry5",
    cases: ["retry-count-five"],
    schedule: "0 0 1 1 *",
    timeZone: "UTC",
    retryConfig: { retryCount: 5 },
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

/** The ids of the Scheduler jobs the recorder may touch: the five the CLI creates and the extra ones. */
export const jobIds = (runId) => [
  ...ALL_FUNCTIONS.map(scheduleId),
  ...EXTRA_JOBS.map((job) => extraJobId(runId, job.key)),
];
