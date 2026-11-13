// The names, pins and limits of the TASK-QUEUE-FUNCTIONS sandbox recording. Pure data and pure functions of it:
// importing this module sends nothing and reads nothing.

export const PROJECT = "fireemu-oracle-events";
export const REGION = "us-central1";
export const CODEBASE = "task-queue";
export const NODE_VERSION = "22.22.1";
export const FIREBASE_TOOLS_VERSION = "15.28.2";
export const FIREBASE_FUNCTIONS_VERSION = "7.3.2";
export const FUNCTIONS_FRAMEWORK_VERSION = "5.0.5";

/**
 * The eight task queue functions of the fixture and the queue settings each declares (the SDK's option names). The queue is
 * the function: its id is the function id, which is the role plus the run's suffix, so every run uses queue ids no
 * earlier run used (Cloud Tasks refuses a queue id deleted within the last days; it answered 400 "existed too recently"
 * 72 hours after a delete on 2026-11-07).
 */
export const ROLES = Object.freeze({
  tqdef: Object.freeze({}),
  tqretry: Object.freeze({
    retryConfig: Object.freeze({
      maxAttempts: 6,
      minBackoffSeconds: 1,
      maxBackoffSeconds: 6,
      maxDoublings: 2,
    }),
  }),
  tqlimit: Object.freeze({
    retryConfig: Object.freeze({ maxAttempts: 2, minBackoffSeconds: 1, maxBackoffSeconds: 2 }),
  }),
  tqwindow: Object.freeze({
    retryConfig: Object.freeze({
      maxAttempts: 100,
      maxRetrySeconds: 6,
      minBackoffSeconds: 1,
      maxBackoffSeconds: 2,
      maxDoublings: 1,
    }),
  }),
  tqconc1: Object.freeze({
    rateLimits: Object.freeze({ maxConcurrentDispatches: 1, maxDispatchesPerSecond: 500 }),
  }),
  tqconc2: Object.freeze({
    rateLimits: Object.freeze({ maxConcurrentDispatches: 2, maxDispatchesPerSecond: 500 }),
  }),
  tqrate: Object.freeze({
    rateLimits: Object.freeze({ maxConcurrentDispatches: 100, maxDispatchesPerSecond: 1 }),
  }),
  tqdead: Object.freeze({
    retryConfig: Object.freeze({ maxAttempts: 2, minBackoffSeconds: 1, maxBackoffSeconds: 2 }),
  }),
});
export const ROLE_IDS = Object.freeze(Object.keys(ROLES));

export const RUN_ID = /^[a-f0-9]{16}$/;
/** The marker every task of a run carries in its data, in its id and in its name. */
export const runMarker = (runId) => {
  if (!RUN_ID.test(runId ?? "")) throw new Error("invalid run ID");
  return "tqrun-" + runId;
};
/** The six hexadecimal digits that make the function and queue ids of a run. */
export const suffixOf = (runId) => {
  if (!RUN_ID.test(runId ?? "")) throw new Error("invalid run ID");
  return runId.slice(0, 6);
};

/** The function ids of a run: every role plus the suffix. Lower case, so the Cloud Run service id is the same text. */
export const functionsOf = (runId, program = "default") => {
  if (!["default", "burst"].includes(program)) throw new Error("unknown program " + program);
  return Object.freeze(
    (program === "burst" ? ["tqrate"] : ROLE_IDS).map((role) => role + suffixOf(runId)),
  );
};
export const roleOf = (fn) =>
  ROLE_IDS.find((role) => fn.startsWith(role) && fn.length === role.length + 6) ?? null;
export const functionOfRole = (runId, role) => {
  if (!ROLE_IDS.includes(role)) throw new Error("unknown role " + role);
  return role + suffixOf(runId);
};

/**
 * The fixture id inside a resource name, an Artifact Registry package id (`<project>__<region>__<function>`, with its
 * `%2Fcache` sibling) or a bare id: a role and six hexadecimal digits. Whether it is this run's is for the caller; the
 * recognizer finds the functions, queues and images of ANY run of this fixture, because the CLI deploy of the codebase
 * deletes every function of the codebase the source no longer has.
 */
export const fixtureIdIn = (text) => {
  const last = String(text ?? "")
    .split("/")
    .filter((part) => part !== "")
    .at(-1)
    ?.split("__")
    .at(-1)
    ?.replace(/%2Fcache$/, "");
  return last !== undefined &&
    ROLE_IDS.some((role) => new RegExp("^" + role + "[0-9a-f]{6}$").test(last))
    ? last
    : null;
};

export const functionName = (fn) =>
  "projects/" + PROJECT + "/locations/" + REGION + "/functions/" + fn;
export const queueName = (fn) => "projects/" + PROJECT + "/locations/" + REGION + "/queues/" + fn;
export const taskName = (fn, id) => queueName(fn) + "/tasks/" + id;

/** The marker the fixture prints before each frame. */
export const FRAME_MARK = "TQ_FRAME";

/** The Google Cloud APIs the run needs. A missing one stops the run before anything is created: nothing is ever enabled. */
export const REQUIRED_SERVICES = Object.freeze([
  "artifactregistry.googleapis.com",
  "cloudbilling.googleapis.com",
  "cloudbuild.googleapis.com",
  "cloudfunctions.googleapis.com",
  "cloudtasks.googleapis.com",
  "compute.googleapis.com",
  "eventarc.googleapis.com",
  "eventarcpublishing.googleapis.com",
  "firebaseextensions.googleapis.com",
  "run.googleapis.com",
  "storage.googleapis.com",
]);

// How long the run waits, in seconds: after a deploy before it reads back (a queue the deploy created needs a moment before
// it dispatches as configured), after the last task before the logs are read for the last time, and between two steps.
// A delivery that has not come by the end of its window is recorded as not delivered, never retried.
export const PROPAGATION_WAIT_SECONDS = 90;
export const DELIVERY_WINDOW_SECONDS = 240;
export const LOG_DELAY_SECONDS = 120;
export const STEP_GAP_SECONDS = 1;

/** The Artifact Registry package of a Gen2 function's image (and its `/cache` sibling), as the repository names them. */
export const packageId = (fn) =>
  PROJECT.replaceAll("-", "--") + "__" + REGION.replaceAll("-", "--") + "__" + fn;
export const packageIds = (fn) => [packageId(fn), packageId(fn) + "%2Fcache"];

/**
 * The two buckets a Gen2 deployment leaves objects in: the source upload slot (the CLI's zip, named by the deploy's own
 * generateUploadUrl answer) and the build's copy. The run lists both before and after; it deletes only the upload object
 * that answer named, and leaves the copies in the sources bucket (reported, not deleted).
 */
export const sourceBuckets = (projectNumber) => [
  `gcf-v2-uploads-${projectNumber}.${REGION}.cloudfunctions.appspot.com`,
  `gcf-v2-sources-${projectNumber}-${REGION}`,
];

/** The one bucket the recorder may delete objects in: the CLI's own source upload slot for the region. */
export const uploadBucket = (projectNumber) => sourceBuckets(projectNumber)[0];

const UPLOAD_OBJECT = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.zip$/;

/**
 * Whether a name may be adopted as one of this deployment's upload objects: the upload bucket of the project and a plain
 * object name (the recorded form is `<uuid>.zip`). Whether the deployment actually made it is decided by the receipt in the
 * CLI log, never by the name. The Gen2 sources bucket is inventory only: nothing in it is ever read by name or deleted.
 */
export const isOwnUploadObject = (projectNumber, bucket, name) =>
  bucket === uploadBucket(projectNumber) && typeof name === "string" && UPLOAD_OBJECT.test(name);
