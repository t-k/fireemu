// The names, pins and operations of the Python Functions slice 2 sandbox check. Pure data and pure functions of it:
// importing this module sends nothing and reads nothing.

export const PROJECT = "fireemu-oracle-events";
export const REGION = "us-central1";
export const CODEBASE = "pycheck";
export const NODE_VERSION = "22.22.1";
export const FIREBASE_TOOLS_VERSION = "15.28.2";
export const FIREBASE_FUNCTIONS_PY_VERSION = "0.6.0";
export const PYTHON_RUNTIME = "python312";

/** The SDK functions, each beside the raw function that takes the same delivery before the SDK parses it. */
export const FAMILIES = Object.freeze({
  firestoreCreated: { sdk: "pcfsc", raw: "pcfscraw" },
  firestoreUpdated: { sdk: "pcfsu", raw: null },
  pubsub: { sdk: "pcps", raw: "pcpsraw" },
  storage: { sdk: "pcst", raw: "pcstraw" },
  eventarc: { sdk: "pcea", raw: "pcearaw" },
  scheduler: { sdk: "pcsch", raw: "pcschraw" },
  tasks: { sdk: "pctask", raw: "pctaskraw" },
});
export const ALL_FUNCTIONS = Object.freeze(
  Object.values(FAMILIES).flatMap((f) => [f.sdk, ...(f.raw ? [f.raw] : [])]),
);
/** Functions whose delivery is a Scheduler job run, and those that are Cloud Tasks queues. */
export const SCHEDULER_FUNCTIONS = Object.freeze([FAMILIES.scheduler.sdk, FAMILIES.scheduler.raw]);
export const TASK_FUNCTIONS = Object.freeze([FAMILIES.tasks.sdk, FAMILIES.tasks.raw]);

export const TOPIC = "pycheck-orders";
export const COLLECTION = "pycheck-src";
export const EVENT_TYPE = "pycheck.thing.v1.happened";
export const CHANNEL = "firebase";
export const OBJECT_PREFIX = "pycheck/";
/** The App Engine location the check creates the project's app in when there is none (owner ledger 2226; kept afterwards). */
export const APP_ENGINE_LOCATION = "us-central";

export const RUN_ID = /^[a-f0-9]{16}$/;
/** The marker every payload of a run carries; the fixture reads it back out of what it was given. */
export const runMarker = (runId) => {
  if (!RUN_ID.test(runId ?? "")) throw new Error("invalid run ID");
  return "pcrun-" + runId;
};

/** Cloud Run service ids and Eventarc trigger ids are lowercase; every function name here already is. */
export const functionName = (fn) =>
  "projects/" + PROJECT + "/locations/" + REGION + "/functions/" + fn;
export const jobId = (fn) => "firebase-schedule-" + fn + "-" + REGION;
export const jobName = (id) => "projects/" + PROJECT + "/locations/" + REGION + "/jobs/" + id;
export const queueName = (fn) => "projects/" + PROJECT + "/locations/" + REGION + "/queues/" + fn;
export const topicName = (id) => "projects/" + PROJECT + "/topics/" + id;

/** The marker the fixture prints before each frame. */
export const FRAME_MARK = "PYCHECK_FRAME";

/** The Google Cloud APIs the run needs. A missing one stops the run before anything is created. */
export const REQUIRED_SERVICES = Object.freeze([
  "artifactregistry.googleapis.com",
  "cloudbuild.googleapis.com",
  "cloudfunctions.googleapis.com",
  "cloudscheduler.googleapis.com",
  "cloudtasks.googleapis.com",
  // The CLI ensures these for every functions deployment and enables a missing one without asking; the run starts only
  // when they are already on, so the deploy changes no service (the delivery and blocking recordings did the same).
  "compute.googleapis.com",
  "eventarc.googleapis.com",
  "eventarcpublishing.googleapis.com",
  "firebaseextensions.googleapis.com",
  "firestore.googleapis.com",
  "pubsub.googleapis.com",
  "run.googleapis.com",
  "storage.googleapis.com",
]);

// How long the run waits, in seconds: after a deploy before it reads back, and for each family after its source
// operation. A frame that has not come by the end of its window is recorded as not delivered, never retried.
export const PROPAGATION_WAIT_SECONDS = 90;
export const DELIVERY_WINDOW_SECONDS = 180;
export const LOG_DELAY_SECONDS = 120;
export const STEP_GAP_SECONDS = 5;

/** The Artifact Registry package of a Gen2 function's image (and its `/cache` sibling), as the repository names them. */
export const packageId = (fn) =>
  PROJECT.replaceAll("-", "--") + "__" + REGION.replaceAll("-", "--") + "__" + fn;
export const packageIds = (fn) => [packageId(fn), packageId(fn) + "%2Fcache"];

/**
 * The two buckets a Gen2 deployment leaves objects in (the source upload and the build's copy). Their objects are not
 * deleted by this check; the run reads them before and after and reports what was added.
 */
export const sourceBuckets = (projectNumber) => [
  `gcf-v2-uploads-${projectNumber}.${REGION}.cloudfunctions.appspot.com`,
  `gcf-v2-sources-${projectNumber}-${REGION}`,
];

/**
 * Whether an object that appeared in a source bucket during the run is one of this deployment's: in the upload bucket any
 * new object with a plain name (the CLI's source upload), in the source bucket one under a function of this run (the
 * precedent's rule). Anything else is reported and left alone.
 */
export function isOwnSourceObject(projectNumber, bucket, name) {
  if (
    typeof name !== "string" ||
    name.length === 0 ||
    name.length > 1024 ||
    [...name].some((ch) => ch.charCodeAt(0) < 32)
  )
    return false;
  const [uploads, sources] = sourceBuckets(projectNumber);
  if (bucket === uploads)
    return /^[A-Za-z0-9._/-]+$/.test(name) && !name.startsWith("/") && !name.includes("..");
  if (bucket === sources) return ALL_FUNCTIONS.includes(name.split("/")[0]) && !name.includes("..");
  return false;
}

/** Every Scheduler job and Cloud Tasks queue the CLI creates for the run's functions. */
export const JOB_IDS = Object.freeze(SCHEDULER_FUNCTIONS.map(jobId));
export const QUEUE_IDS = Object.freeze([...TASK_FUNCTIONS]);

/** The prefix of the Pub/Sub subscriptions Eventarc creates for this region's triggers (named after the function). */
export const triggerSubscriptionPrefix = "eventarc-" + REGION + "-";
