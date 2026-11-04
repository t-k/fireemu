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
  "cloudbilling.googleapis.com",
  "cloudbuild.googleapis.com",
  "cloudfunctions.googleapis.com",
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

/**
 * The two services this project does not have on (coordinator ruling R5): the recorder enables exactly the missing ones of
 * these, once, after every read-only preflight check has passed, reads them back, and leaves them enabled. Nothing else is
 * ever enabled.
 */
export const ENABLE_SERVICES = Object.freeze([
  "cloudscheduler.googleapis.com",
  "cloudtasks.googleapis.com",
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

/** Every Scheduler job and Cloud Tasks queue the CLI creates for the run's functions. */
export const JOB_IDS = Object.freeze(SCHEDULER_FUNCTIONS.map(jobId));
export const QUEUE_IDS = Object.freeze([...TASK_FUNCTIONS]);

/** The prefix of the Pub/Sub subscriptions Eventarc creates for this region's triggers (named after the function). */
export const triggerSubscriptionPrefix = "eventarc-" + REGION + "-";
