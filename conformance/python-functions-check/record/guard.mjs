// The allowlist of every REST request the check may send. Anything that matches no rule is refused before it is
// journaled or sent. Each rule pins the method, the host, the path (case-exact names), the allowed query keys, and the
// body, and says whether it is a mutation. The Firestore document, the Storage object and the Artifact Registry
// packages are named by the run, so a rule can only touch what this run created.
import {
  ALL_FUNCTIONS,
  COLLECTION,
  JOB_IDS,
  ENABLE_SERVICES,
  CHANNEL,
  OBJECT_PREFIX,
  PROJECT,
  QUEUE_IDS,
  REGION,
  TOPIC,
  packageIds,
  runMarker,
  isOwnUploadObject,
  sourceBuckets,
  uploadBucket,
} from "./plan.mjs";

const decodeName = (text) => {
  try {
    return decodeURIComponent(text);
  } catch {
    return null;
  }
};
const esc = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const alt = (names) => "(?:" + names.map(esc).join("|") + ")";
const OPERATION_ID = "[A-Za-z0-9._-]+";
const BUILD_ID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
// The project's default bucket, in either of the two forms Firebase gives it; no other bucket is ever touched.
const BUCKET = `(?:${esc(PROJECT)}\\.firebasestorage\\.app|${esc(PROJECT)}\\.appspot\\.com)`;

const isPlainObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/**
 * The body of the one policy write on a Cloud Run service: the policy the service has, minus the public members. It has
 * only `policy`, whose only keys are `version`, `etag` and `bindings`; every binding is a `roles/` role with a list of
 * string members and, when it had one, its `condition` object; no member is `allUsers` or `allAuthenticatedUsers`, so the
 * write can only remove.
 */
export function policyWithoutPublicMembers(json) {
  if (
    !isPlainObject(json) ||
    Object.keys(json).some((k) => k !== "policy") ||
    !isPlainObject(json.policy)
  )
    return false;
  const policy = json.policy;
  if (Object.keys(policy).some((k) => !["version", "etag", "bindings"].includes(k))) return false;
  if (policy.etag !== undefined && typeof policy.etag !== "string") return false;
  if (policy.version !== undefined && !Number.isInteger(policy.version)) return false;
  const bindings = policy.bindings ?? [];
  return (
    Array.isArray(bindings) &&
    bindings.every(
      (b) =>
        isPlainObject(b) &&
        Object.keys(b).every((k) => k === "role" || k === "members" || k === "condition") &&
        (b.condition === undefined || isPlainObject(b.condition)) &&
        typeof b.role === "string" &&
        b.role.startsWith("roles/") &&
        Array.isArray(b.members) &&
        b.members.every(
          (m) => typeof m === "string" && m !== "allUsers" && m !== "allAuthenticatedUsers",
        ),
    )
  );
}

/**
 * The policy to write back after taking `allUsers` out of a service's policy: only the `roles/run.invoker` binding that has
 * no condition loses that one member (a binding left with no member is dropped); every other binding stays verbatim. A
 * policy of a shape this does not know (a field beyond `version`, `etag` and `bindings`, a binding field beyond `role`,
 * `members` and `condition`, members that are not text, `allAuthenticatedUsers`) is refused, and so is a policy that
 * holds `allUsers` anywhere else (another role, or a conditional binding): the write would have to change what the
 * check never granted, so it is reported as a finding and nothing is sent.
 */
export function withoutPublicMember(policy) {
  if (!isPlainObject(policy)) return { ok: false, why: "policy-not-an-object" };
  if (Object.keys(policy).some((k) => !["version", "etag", "bindings"].includes(k)))
    return { ok: false, why: "policy-fields" };
  if (policy.bindings !== undefined && !Array.isArray(policy.bindings))
    return { ok: false, why: "bindings-not-a-list" };
  const kept = [];
  for (const binding of policy.bindings ?? []) {
    if (
      !isPlainObject(binding) ||
      Object.keys(binding).some((k) => !["role", "members", "condition"].includes(k)) ||
      typeof binding.role !== "string" ||
      !Array.isArray(binding.members) ||
      binding.members.some((m) => typeof m !== "string" || m === "allAuthenticatedUsers") ||
      (binding.condition !== undefined && !isPlainObject(binding.condition))
    )
      return { ok: false, why: "binding-shape" };
    if (!binding.members.includes("allUsers")) {
      kept.push(structuredClone(binding));
      continue;
    }
    if (binding.role !== "roles/run.invoker" || binding.condition !== undefined)
      return { ok: false, why: "public-member-outside-the-invoker-binding" };
    const members = binding.members.filter((m) => m !== "allUsers");
    if (members.length > 0) kept.push({ ...structuredClone(binding), members });
  }
  return {
    ok: true,
    policy: {
      ...(Number.isInteger(policy.version) ? { version: policy.version } : {}),
      ...(typeof policy.etag === "string" ? { etag: policy.etag } : {}),
      bindings: kept,
    },
  };
}

export const ownPackages = () => ALL_FUNCTIONS.flatMap(packageIds);

/**
 * Rules for one run. `projectNumber` is for the Service Usage and Cloud Build reads. A rule is
 * `[method, host, path regex, query keys allowed, body check, mutation]`.
 */
export function rules(runId, projectNumber, state = { objects: new Set() }) {
  const P = esc(PROJECT);
  const R = esc(REGION);
  const marker = runMarker(runId);
  const doc = esc(marker + "-a");
  const object = esc(encodeURIComponent(OBJECT_PREFIX + marker + "-a.json"));
  const fns = alt(ALL_FUNCTIONS);
  const jobs = alt(JOB_IDS);
  const queues = alt(QUEUE_IDS);
  const packages = alt(ownPackages().map((id) => id));
  const num = (n) => (v) => v === String(n);
  const token = (v) => /^[A-Za-z0-9_=.%+/-]{1,2048}$/.test(v);
  const q = (spec) => spec;
  const nothing = (json) => json === undefined;
  const empty = (json) => json === undefined || (isObject(json) && Object.keys(json).length === 0);
  const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
  const onlyKeys = (json, keys) =>
    isObject(json) && Object.keys(json).every((k) => keys.includes(k));
  const read = (host, path, query = q({})) => ["GET", host, path, query, nothing, false];
  const invokerRemoval = (json) => policyWithoutPublicMembers(json);
  return [
    // identity and the project's own state
    // The project's identity: the recorded read of this project (FE v7), whose projectNumber names the buckets below.
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
    read("firebase.googleapis.com", `^/v1beta1/projects/${P}/adminSdkConfig$`),
    read("appengine.googleapis.com", `^/v1/apps/${P}$`),
    // The one enable the run may make: exactly the missing ones of the two services this project lacks, once.
    [
      "POST",
      "serviceusage.googleapis.com",
      `^/v1/projects/${esc(projectNumber)}/services:batchEnable$`,
      q({}),
      (json) =>
        onlyKeys(json, ["serviceIds"]) &&
        Array.isArray(json.serviceIds) &&
        json.serviceIds.length >= 1 &&
        new Set(json.serviceIds).size === json.serviceIds.length &&
        json.serviceIds.every((id) => ENABLE_SERVICES.includes(id)),
      true,
    ],
    read("serviceusage.googleapis.com", `^/v1/operations/${OPERATION_ID}$`),
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
    // Cloud Run and Eventarc (reads only; the CLI makes and deletes the services and the triggers)
    read(
      "run.googleapis.com",
      `^/v2/projects/${P}/locations/(?:${R}|-)/services$`,
      q({ pageToken: token }),
    ),
    // The service-level public invoker the CLI adds to HTTP, callable and blocking functions: read, and removed (only that
    // member) before the function is deleted. The services are the run's function ids.
    read("run.googleapis.com", `^/v2/projects/${P}/locations/${R}/services/${fns}:getIamPolicy$`),
    [
      "POST",
      "run.googleapis.com",
      `^/v2/projects/${P}/locations/${R}/services/${fns}:setIamPolicy$`,
      q({}),
      invokerRemoval,
      true,
    ],
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
    // The Eventarc channel `firebase` the CLI creates when it is missing: read, and deleted once when the run owns it.
    read("eventarc.googleapis.com", `^/v1/projects/${P}/locations/${R}/channels/${esc(CHANNEL)}$`),
    [
      "DELETE",
      "eventarc.googleapis.com",
      `^/v1/projects/${P}/locations/${R}/channels/${esc(CHANNEL)}$`,
      q({}),
      nothing,
      true,
    ],
    read(
      "eventarc.googleapis.com",
      `^/v1/projects/${P}/locations/${R}/operations/${OPERATION_ID}$`,
    ),
    read(
      "pubsub.googleapis.com",
      `^/v1/projects/${P}/topics/eventarc-channel-${R}-${esc(CHANNEL)}-[0-9]+$`,
    ),
    // Artifact Registry: lists, and the deletes of this run's own function images
    read(
      "artifactregistry.googleapis.com",
      `^/v1/projects/${P}/locations/${R}/repositories$`,
      q({ pageToken: token, pageSize: num(100) }),
    ),
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
    // Cloud Scheduler: lists, the run's jobs, the forced runs, and a leftover job's delete
    read(
      "cloudscheduler.googleapis.com",
      `^/v1/projects/${P}/locations/${R}/jobs$`,
      q({ pageSize: num(500), pageToken: token }),
    ),
    read("cloudscheduler.googleapis.com", `^/v1/projects/${P}/locations/${R}/jobs/${jobs}$`),
    [
      "POST",
      "cloudscheduler.googleapis.com",
      `^/v1/projects/${P}/locations/${R}/jobs/${jobs}:run$`,
      q({}),
      empty,
      true,
    ],
    [
      "DELETE",
      "cloudscheduler.googleapis.com",
      `^/v1/projects/${P}/locations/${R}/jobs/${jobs}$`,
      q({}),
      nothing,
      true,
    ],
    // Cloud Tasks: lists, the run's queues, the two tasks, and a leftover queue's delete
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
      (json) => {
        const http = json?.task?.httpRequest;
        return (
          onlyKeys(json, ["task"]) &&
          onlyKeys(json.task, ["httpRequest"]) &&
          onlyKeys(http, ["url", "httpMethod", "headers", "body", "oidcToken"]) &&
          http.httpMethod === "POST" &&
          /^https:\/\/[a-z0-9.-]+\.run\.app\/?$|^https:\/\/[a-z0-9.-]+\.cloudfunctions\.net\/[A-Za-z0-9_-]*$/.test(
            http.url,
          ) &&
          typeof http.body === "string" &&
          Buffer.from(http.body, "base64").toString("utf8").includes(marker) &&
          onlyKeys(http.oidcToken, ["serviceAccountEmail", "audience"]) &&
          /^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+\.gserviceaccount\.com$/.test(
            http.oidcToken.serviceAccountEmail,
          )
        );
      },
      true,
    ],
    [
      "DELETE",
      "cloudtasks.googleapis.com",
      `^/v2/projects/${P}/locations/${R}/queues/${queues}$`,
      q({}),
      nothing,
      true,
    ],
    // Pub/Sub: the one topic the run owns (create, two publishes, delete) and the lists
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
    read("pubsub.googleapis.com", `^/v1/projects/${P}/topics/${esc(TOPIC)}$`),
    [
      "PUT",
      "pubsub.googleapis.com",
      `^/v1/projects/${P}/topics/${esc(TOPIC)}$`,
      q({}),
      (json) => isObject(json) && Object.keys(json).length === 0,
      true,
    ],
    [
      "DELETE",
      "pubsub.googleapis.com",
      `^/v1/projects/${P}/topics/${esc(TOPIC)}$`,
      q({}),
      nothing,
      true,
    ],
    [
      "POST",
      "pubsub.googleapis.com",
      `^/v1/projects/${P}/topics/${esc(TOPIC)}:publish$`,
      q({}),
      (json) =>
        onlyKeys(json, ["messages"]) &&
        Array.isArray(json.messages) &&
        json.messages.length === 1 &&
        onlyKeys(json.messages[0], ["data", "attributes", "orderingKey"]) &&
        json.messages[0].attributes?.run === marker,
      true,
    ],
    // Firestore: the run's one document in the check's collection (create, update, delete) and the list that proves it empty
    read(
      "firestore.googleapis.com",
      `^/v1/projects/${P}/databases/\\(default\\)/documents/${esc(COLLECTION)}$`,
      q({ pageSize: num(100), pageToken: token }),
    ),
    read(
      "firestore.googleapis.com",
      `^/v1/projects/${P}/databases/\\(default\\)/documents/${esc(COLLECTION)}/${doc}$`,
    ),
    [
      "POST",
      "firestore.googleapis.com",
      `^/v1/projects/${P}/databases/\\(default\\)/documents/${esc(COLLECTION)}$`,
      q({ documentId: (v) => v === marker + "-a" }),
      (json) => onlyKeys(json, ["fields"]) && json.fields?.run?.stringValue === marker,
      true,
    ],
    [
      "PATCH",
      "firestore.googleapis.com",
      `^/v1/projects/${P}/databases/\\(default\\)/documents/${esc(COLLECTION)}/${doc}$`,
      q({
        "updateMask.fieldPaths": (v) => v === "n",
        "currentDocument.exists": (v) => v === "true",
      }),
      (json) => onlyKeys(json, ["fields"]) && onlyKeys(json.fields, ["n"]),
      true,
    ],
    [
      "DELETE",
      "firestore.googleapis.com",
      `^/v1/projects/${P}/databases/\\(default\\)/documents/${esc(COLLECTION)}/${doc}$`,
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
    // Cloud Storage: the default bucket (read), the objects under the check's prefix (list), and the run's one object
    read("storage.googleapis.com", `^/storage/v1/b/${BUCKET}$`),
    // The default bucket's notification configs (read only): part of the inventory the closure compares.
    read("storage.googleapis.com", `^/storage/v1/b/${BUCKET}/notificationConfigs$`),
    read(
      "storage.googleapis.com",
      `^/storage/v1/b/${BUCKET}/o$`,
      q({ prefix: (v) => v === OBJECT_PREFIX, versions: (v) => v === "true", pageToken: token }),
    ),
    read("storage.googleapis.com", `^/storage/v1/b/${BUCKET}/o/${object}$`),
    [
      "POST",
      "storage.googleapis.com",
      `^/upload/storage/v1/b/${BUCKET}/o$`,
      q({
        uploadType: (v) => v === "media",
        name: (v) => v === OBJECT_PREFIX + marker + "-a.json",
      }),
      (json) => onlyKeys(json, ["run"]) && json.run === marker,
      true,
    ],
    [
      "DELETE",
      "storage.googleapis.com",
      `^/storage/v1/b/${BUCKET}/o/${object}$`,
      q({}),
      nothing,
      true,
    ],
    // Eventarc publishing: two events on the Firebase channel
    [
      "POST",
      "eventarcpublishing.googleapis.com",
      `^/v1/projects/${P}/locations/${R}/channels/firebase:publishEvents$`,
      q({}),
      (json) =>
        onlyKeys(json, ["events"]) &&
        Array.isArray(json.events) &&
        json.events.length === 1 &&
        json.events[0]["@type"] === "type.googleapis.com/io.cloudevents.v1.CloudEvent" &&
        typeof json.events[0].textData === "string" &&
        json.events[0].textData.includes(marker),
      true,
    ],
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
        onlyKeys(json, ["resourceNames", "filter", "orderBy", "pageSize", "pageToken"]),
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
  const state = { objects: new Set() };
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
  };
}
