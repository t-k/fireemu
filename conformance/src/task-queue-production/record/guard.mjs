// The allowlist of every REST request the recording may send. Anything that matches no rule is refused before it is
// journaled or sent. Each rule pins the method, the host, the path (case-exact names), the allowed query keys, and the
// body, and says whether it is a mutation. The queues, tasks and Artifact Registry packages are named by the run, so a
// rule can only touch what this run created. Adapted from the Python Functions check's guard.mjs (work/python-functions-check
// 650824f6c): the rules for the other services are gone, and the createTask rule admits only a body whose time-free shape is
// the shape of a step of the corpus program.
import { ABSENT_QUEUE, plannedShapes, plannedTaskNames, shapeOf } from "../corpus.mjs";
import {
  PROJECT,
  REGION,
  functionsOf,
  isOwnUploadObject,
  packageIds,
  sourceBuckets,
  suffixOf,
  uploadBucket,
} from "../plan.mjs";

const decodeName = (text) => {
  try {
    return decodeURIComponent(text);
  } catch {
    return null;
  }
};
const esc = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
// An empty list matches nothing (a bare `(?:)` would match the empty id).
const alt = (names) => (names.length === 0 ? "(?!)" : "(?:" + names.map(esc).join("|") + ")");
const OPERATION_ID = "[A-Za-z0-9._-]+";
const BUILD_ID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";

export const ownPackages = (runId) => functionsOf(runId).flatMap(packageIds);

/** The queue ids of a run: its functions' and the one that is never deployed. */
export const queueIdsOf = (runId) => [...functionsOf(runId), ABSENT_QUEUE + suffixOf(runId)];

/**
 * Rules for one run. `projectNumber` is for the Service Usage and Cloud Build reads. A rule is
 * `[method, host, path regex, query keys allowed, body check, mutation]`.
 */
export function rules(runId, projectNumber, state = { objects: new Set(), targets: null }) {
  const P = esc(PROJECT);
  const R = esc(REGION);
  const fns = alt(functionsOf(runId));
  const queues = alt(queueIdsOf(runId));
  const packages = alt(ownPackages(runId));
  const num = (n) => (v) => v === String(n);
  const token = (v) => /^[A-Za-z0-9_=.%+/-]{1,2048}$/.test(v);
  const q = (spec) => spec;
  const nothing = (json) => json === undefined;
  const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
  const empty = (json) => json === undefined || (isObject(json) && Object.keys(json).length === 0);
  const read = (host, path, query = q({})) => ["GET", host, path, query, nothing, false];
  const taskNames = plannedTaskNames(runId);
  // The shapes the program may send, once the targets are known: before the readbacks no createTask is allowed.
  let shapes = null;
  let shapesFor = null;
  const allowedShape = (json) => {
    if (state.targets === null) return false;
    if (shapesFor !== state.targets) {
      shapes = plannedShapes(runId, state.targets);
      shapesFor = state.targets;
    }
    return shapes.has(shapeOf(json));
  };
  const taskPath = (pathname) => {
    const m = /^\/v2\/(projects\/[^/]+\/locations\/[^/]+\/queues\/[^/]+\/tasks\/[^/]+)$/.exec(
      pathname,
    );
    return m ? decodeName(m[1]) : null;
  };
  return [
    // identity and the project's own state
    read("cloudresourcemanager.googleapis.com", `^/v1/projects/${P}$`),
    read(
      "serviceusage.googleapis.com",
      `^/v1/projects/${esc(projectNumber)}/services$`,
      q({ filter: (v) => v === "state:ENABLED", pageSize: num(200), pageToken: token }),
    ),
    [
      "POST",
      "cloudresourcemanager.googleapis.com",
      `^/v1/projects/${P}:getIamPolicy$`,
      q({}),
      empty,
      false,
    ],
    // Cloud Functions: lists, the run's functions, the leftovers' deletes (one at a time, exact names)
    read(
      "cloudfunctions.googleapis.com",
      `^/v1/projects/${P}/locations/(?:${R}|-)/functions$`,
      q({ pageToken: token }),
    ),
    read(
      "cloudfunctions.googleapis.com",
      `^/v2/projects/${P}/locations/(?:${R}|-)/functions$`,
      q({ pageToken: token }),
    ),
    read("cloudfunctions.googleapis.com", `^/v2/projects/${P}/locations/${R}/functions/${fns}$`),
    [
      "DELETE",
      "cloudfunctions.googleapis.com",
      `^/v2/projects/${P}/locations/${R}/functions/${fns}$`,
      q({}),
      nothing,
      true,
    ],
    read(
      "cloudfunctions.googleapis.com",
      `^/v2/projects/${P}/locations/${R}/operations/${OPERATION_ID}$`,
    ),
    read(
      "cloudbuild.googleapis.com",
      `^/v1/projects/${esc(projectNumber)}/locations/${R}/builds/${BUILD_ID}$`,
    ),
    // Cloud Run and Eventarc (reads only; the CLI makes and deletes the services)
    read(
      "run.googleapis.com",
      `^/v2/projects/${P}/locations/(?:${R}|-)/services$`,
      q({ pageToken: token }),
    ),
    read("run.googleapis.com", `^/v2/projects/${P}/locations/${R}/services/${fns}:getIamPolicy$`),
    read(
      "eventarc.googleapis.com",
      `^/v1/projects/${P}/locations/(?:${R}|-)/triggers$`,
      q({ pageToken: token }),
    ),
    read(
      "eventarc.googleapis.com",
      `^/v1/projects/${P}/locations/${R}/channels$`,
      q({ pageToken: token }),
    ),
    read(
      "pubsub.googleapis.com",
      `^/v1/projects/${P}/topics$`,
      q({ pageSize: num(1000), pageToken: token }),
    ),
    read(
      "pubsub.googleapis.com",
      `^/v1/projects/${P}/subscriptions$`,
      q({ pageSize: num(1000), pageToken: token }),
    ),
    // Artifact Registry: lists, and the deletes of this run's own function images
    read(
      "artifactregistry.googleapis.com",
      `^/v1/projects/${P}/locations/${R}/repositories/gcf-artifacts/packages$`,
      q({ pageToken: token, pageSize: num(100) }),
    ),
    read(
      "artifactregistry.googleapis.com",
      `^/v1/projects/${P}/locations/${R}/repositories/gcf-artifacts/packages/${packages}$`,
    ),
    [
      "DELETE",
      "artifactregistry.googleapis.com",
      `^/v1/projects/${P}/locations/${R}/repositories/gcf-artifacts/packages/${packages}$`,
      q({}),
      nothing,
      true,
    ],
    read(
      "artifactregistry.googleapis.com",
      `^/v1/projects/${P}/locations/${R}/operations/${OPERATION_ID}$`,
    ),
    // Cloud Tasks: the list, the run's queues (a read each, and the delete of a leftover queue), and the tasks of the program
    read(
      "cloudtasks.googleapis.com",
      `^/v2/projects/${P}/locations/${R}/queues$`,
      q({ pageSize: num(500), pageToken: token }),
    ),
    read("cloudtasks.googleapis.com", `^/v2/projects/${P}/locations/${R}/queues/${queues}$`),
    [
      "POST",
      "cloudtasks.googleapis.com",
      `^/v2/projects/${P}/locations/${R}/queues/${queues}/tasks$`,
      q({}),
      allowedShape,
      true,
    ],
    [
      "GET",
      "cloudtasks.googleapis.com",
      `^/v2/projects/${P}/locations/${R}/queues/${queues}/tasks/[^/]+$`,
      q({}),
      nothing,
      false,
      (pathname) => taskNames.has(taskPath(pathname)),
    ],
    [
      "DELETE",
      "cloudtasks.googleapis.com",
      `^/v2/projects/${P}/locations/${R}/queues/${queues}/tasks/[^/]+$`,
      q({}),
      nothing,
      true,
      (pathname) => taskNames.has(taskPath(pathname)),
    ],
    [
      "DELETE",
      "cloudtasks.googleapis.com",
      `^/v2/projects/${P}/locations/${R}/queues/${fns}$`,
      q({}),
      nothing,
      true,
    ],
    // The Gen2 source buckets: object lists only (read-only inventory)
    ...sourceBuckets(projectNumber).map((name) =>
      read(
        "storage.googleapis.com",
        `^/storage/v1/b/${esc(name)}/o$`,
        q({ maxResults: num(1000), pageToken: token }),
      ),
    ),
    // The upload object the deploy's own generateUploadUrl answer named (the run adopted it from the CLI log): its metadata
    // is read, and it is deleted once, by generation. The sources bucket has no object rule.
    ...[
      ["GET", false, q({ fields: (v) => v === "bucket,name,generation" })],
      ["DELETE", true, q({ ifGenerationMatch: (v) => /^\d{1,20}$/.test(v) })],
    ].map(([method, mutation, query]) => [
      method,
      "storage.googleapis.com",
      `^/storage/v1/b/${esc(uploadBucket(projectNumber))}/o/[^/]+$`,
      query,
      nothing,
      mutation,
      (pathname, params) =>
        state.objects.has(
          uploadBucket(projectNumber) + "/" + decodeName(pathname.split("/o/")[1]),
        ) &&
        (method === "GET" || params.has("ifGenerationMatch")),
    ]),
    // Cloud Logging (a read through POST): the filter is one the recorder builds
    [
      "POST",
      "logging.googleapis.com",
      `^/v2/entries:list$`,
      q({}),
      (json) =>
        JSON.stringify(json?.resourceNames) === JSON.stringify(["projects/" + PROJECT]) &&
        typeof json.filter === "string" &&
        json.filter.length < 6000 &&
        json.pageSize <= 200 &&
        json.orderBy === "timestamp asc" &&
        isObject(json) &&
        Object.keys(json).every((k) =>
          ["resourceNames", "filter", "orderBy", "pageSize", "pageToken"].includes(k),
        ),
      false,
    ],
  ].map(([method, host, path, keys, body, mutation, check]) => ({
    method,
    host,
    path: new RegExp(path),
    query: keys,
    body,
    mutation,
    check,
  }));
}

/** The matching rule of a request, or `null`. */
export function matchRule(spec, ruleList) {
  let url;
  try {
    url = new URL(spec.url);
  } catch {
    return null;
  }
  if (url.protocol !== "https:" || url.username || url.password || url.hash) return null;
  if (url.port) return null;
  for (const rule of ruleList) {
    if (rule.method !== spec.method || rule.host !== url.hostname) continue;
    if (!rule.path.test(url.pathname)) continue;
    const keys = [...url.searchParams.keys()];
    if (new Set(keys).size !== keys.length) continue;
    if (!keys.every((key) => rule.query[key]?.(url.searchParams.get(key)) === true)) continue;
    if (!rule.body(spec.json)) continue;
    if (rule.check && rule.check(url.pathname, url.searchParams) !== true) continue;
    return rule;
  }
  return null;
}

export function createGuard(runId, projectNumber) {
  const state = { objects: new Set(), targets: null };
  const ruleList = rules(runId, projectNumber, state);
  return {
    allow: (spec) => matchRule(spec, ruleList) !== null,
    isMutation: (spec) => matchRule(spec, ruleList)?.mutation === true,
    /** Records the upload object the deploy's receipt named, so that it may be read and deleted; false for any other name. */
    adoptObject: (bucket, name) => {
      if (!isOwnUploadObject(projectNumber, bucket, name)) return false;
      state.objects.add(bucket + "/" + name);
      return true;
    },
    adoptedObjects: () => [...state.objects],
    /** The function URLs and service accounts the readbacks gave: a createTask is allowed only toward these. */
    setTargets: (targets) => {
      state.targets = structuredClone(targets);
    },
  };
}
