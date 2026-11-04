// Constants of the blocking-function check: the project, the one function, the names of everything the run may create,
// the waits, and the URLs the run reads. Nothing here sends anything.
export const PROJECT = "fireemu-oracle-idp";
export const REGION = "us-central1";
export const CODEBASE = "pcblock";
export const FUNCTION = "pcblock";
export const NODE_VERSION = "22.22.1";
export const FIREBASE_TOOLS_VERSION = "15.28.2";
export const FIREBASE_FUNCTIONS_PY_VERSION = "0.6.0";
export const BLOCKING_EVENT = "beforeCreate";
export const BLOCKING_EVENT_TYPE = "providers/cloud.auth/eventTypes/user.beforeCreate";

export const RUN_ID = /^[a-f0-9]{16}$/;

/** The marker the fixture prints before each frame. */
export const FRAME_MARK = "PYBLOCK_FRAME";

export const functionName = (fn = FUNCTION) =>
  "projects/" + PROJECT + "/locations/" + REGION + "/functions/" + fn;

/** The Google Cloud APIs the run needs. A missing one stops the run before anything is created. */
export const REQUIRED_SERVICES = Object.freeze([
  "artifactregistry.googleapis.com",
  "cloudbuild.googleapis.com",
  "cloudfunctions.googleapis.com",
  // The CLI ensures these for every functions deployment and enables a missing one without asking; the run starts only
  // when they are already on, so the deploy changes no service.
  "compute.googleapis.com",
  "eventarc.googleapis.com",
  "firebaseextensions.googleapis.com",
  "identitytoolkit.googleapis.com",
  "pubsub.googleapis.com",
  "run.googleapis.com",
  "storage.googleapis.com",
]);

export const PROPAGATION_WAIT_SECONDS = 60;
export const DELIVERY_WINDOW_SECONDS = 120;
export const LOG_DELAY_SECONDS = 120;

/** The Artifact Registry package of the function's image (and its `/cache` sibling), as the repository names them. */
export const packageId = (fn = FUNCTION) =>
  PROJECT.replaceAll("-", "--") + "__" + REGION.replaceAll("-", "--") + "__" + fn;
export const packageIds = (fn = FUNCTION) => [packageId(fn), packageId(fn) + "%2Fcache"];

/**
 * The two buckets a Gen2 deployment leaves objects in (the source upload and the build's copy). Their objects are not
 * deleted by this check; the run reads them before and after and reports what was added.
 */
export const sourceBuckets = (projectNumber) => [
  `gcf-v2-uploads-${projectNumber}.${REGION}.cloudfunctions.appspot.com`,
  `gcf-v2-sources-${projectNumber}-${REGION}`,
];

export const CONFIG_URL = `https://identitytoolkit.googleapis.com/admin/v2/projects/${PROJECT}/config`;
export const SIGN_UP_URL = "https://identitytoolkit.googleapis.com/v1/accounts:signUp";
export const ACCOUNTS_URL = `https://identitytoolkit.googleapis.com/v1/projects/${PROJECT}/accounts`;
