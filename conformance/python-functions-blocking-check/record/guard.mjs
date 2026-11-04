// The allowlist of every REST request the blocking check may send. Anything that matches no rule is refused before it is
// journaled or sent. Each rule pins the method, the host, the path (case-exact names), the allowed query keys and the body,
// and says whether it is a mutation. The one sign-up body is built from the run's id, and an account can be read or deleted
// only when its id was returned by this run's own sign-up (`state.localIds`).
import {
  FUNCTION,
  PROJECT,
  REGION,
  isOwnUploadObject,
  packageIds,
  sourceBuckets,
  uploadBucket,
} from "./plan.mjs";
import { signUpBody } from "./script.mjs";

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

/**
 * The body of the one policy write on a Cloud Run service: the policy the service has, minus the public members. It has
 * only `policy`, whose only keys are `version`, `etag` and `bindings`; every binding is a `roles/` role with a list of
 * string members and, when it had one, its `condition` object; no member is `allUsers` or `allAuthenticatedUsers`, so the
 * write can only remove.
 */
export function policyWithoutPublicMembers(json) {
  if (!isObject(json) || Object.keys(json).some((k) => k !== "policy") || !isObject(json.policy))
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
        isObject(b) &&
        Object.keys(b).every((k) => k === "role" || k === "members" || k === "condition") &&
        (b.condition === undefined || isObject(b.condition)) &&
        typeof b.role === "string" &&
        b.role.startsWith("roles/") &&
        Array.isArray(b.members) &&
        b.members.every(
          (m) => typeof m === "string" && m !== "allUsers" && m !== "allAuthenticatedUsers",
        ),
    )
  );
}

export const ownPackages = () => packageIds();

const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/** Rules for one run. `state.localIds` is the set of account ids this run's sign-up returned. */
export function rules(runId, projectNumber, state = { localIds: new Set(), objects: new Set() }) {
  const P = esc(PROJECT);
  const R = esc(REGION);
  const fn = esc(FUNCTION);
  const packages = alt(ownPackages());
  const num = (n) => (v) => v === String(n);
  const token = (v) => /^[A-Za-z0-9_=.%+/-]{1,2048}$/.test(v);
  const nothing = (json) => json === undefined;
  const empty = (json) => json === undefined || (isObject(json) && Object.keys(json).length === 0);
  const onlyKeys = (json, keys) =>
    isObject(json) && Object.keys(json).every((k) => keys.includes(k));
  const known = (id) => typeof id === "string" && state.localIds.has(id);
  const read = (host, path, query = {}) => ["GET", host, path, query, nothing, false];
  return [
    // identity and the project's own state
    read("firebase.googleapis.com", `^/v1beta1/projects/${P}$`),
    read("serviceusage.googleapis.com", `^/v1/projects/${esc(projectNumber)}/services$`, {
      filter: (v) => v === "state:ENABLED",
      pageSize: num(200),
      pageToken: token,
    }),
    [
      "POST",
      "cloudresourcemanager.googleapis.com",
      `^/v1/projects/${P}:getIamPolicy$`,
      {},
      empty,
      false,
    ],
    // the Identity Platform configuration, read before the deploy, after it and after the cleanup (never written here)
    read("identitytoolkit.googleapis.com", `^/admin/v2/projects/${P}/config$`),
    // the one sign-up, and the account it made
    [
      "POST",
      "identitytoolkit.googleapis.com",
      `^/v1/accounts:signUp$`,
      {},
      (json) => JSON.stringify(json) === JSON.stringify(signUpBody(runId)),
      true,
    ],
    [
      "POST",
      "identitytoolkit.googleapis.com",
      `^/v1/projects/${P}/accounts:query$`,
      {},
      (json) => JSON.stringify(json) === JSON.stringify({ returnUserInfo: false }),
      false,
    ],
    [
      "POST",
      "identitytoolkit.googleapis.com",
      `^/v1/projects/${P}/accounts:lookup$`,
      {},
      (json) =>
        onlyKeys(json, ["localId"]) &&
        Array.isArray(json.localId) &&
        json.localId.length === 1 &&
        known(json.localId[0]),
      false,
    ],
    [
      "POST",
      "identitytoolkit.googleapis.com",
      `^/v1/projects/${P}/accounts:delete$`,
      {},
      (json) => onlyKeys(json, ["localId"]) && known(json.localId),
      true,
    ],
    // Cloud Functions: lists, the function, the leftover's delete, its operation
    read("cloudfunctions.googleapis.com", `^/v2/projects/${P}/locations/(?:${R}|-)/functions$`, {
      pageToken: token,
    }),
    read("cloudfunctions.googleapis.com", `^/v2/projects/${P}/locations/${R}/functions/${fn}$`),
    [
      "DELETE",
      "cloudfunctions.googleapis.com",
      `^/v2/projects/${P}/locations/${R}/functions/${fn}$`,
      {},
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
    // Cloud Run: the list, the function's service, its public-invoker policy, and the removal of that public member before the delete
    read("run.googleapis.com", `^/v2/projects/${P}/locations/(?:${R}|-)/services$`, {
      pageToken: token,
    }),
    read("run.googleapis.com", `^/v2/projects/${P}/locations/${R}/services/${fn}$`),
    read("run.googleapis.com", `^/v2/projects/${P}/locations/${R}/services/${fn}:getIamPolicy$`),
    [
      "POST",
      "run.googleapis.com",
      `^/v2/projects/${P}/locations/${R}/services/${fn}:setIamPolicy$`,
      {},
      policyWithoutPublicMembers,
      true,
    ],
    // The project's Eventarc triggers and Pub/Sub topics and subscriptions: read-only inventory (a blocking function has none)
    read("eventarc.googleapis.com", `^/v1/projects/${P}/locations/(?:${R}|-)/triggers$`, {
      pageToken: token,
    }),
    read("pubsub.googleapis.com", `^/v1/projects/${P}/topics$`, {
      pageSize: num(1000),
      pageToken: token,
    }),
    read("pubsub.googleapis.com", `^/v1/projects/${P}/subscriptions$`, {
      pageSize: num(1000),
      pageToken: token,
    }),
    // Artifact Registry: the repository, lists, and the deletes of this function's own images
    read(
      "artifactregistry.googleapis.com",
      `^/v1/projects/${P}/locations/${R}/repositories/gcf-artifacts$`,
    ),
    read(
      "artifactregistry.googleapis.com",
      `^/v1/projects/${P}/locations/${R}/repositories/gcf-artifacts/packages$`,
      { pageToken: token, pageSize: num(100) },
    ),
    read(
      "artifactregistry.googleapis.com",
      `^/v1/projects/${P}/locations/${R}/repositories/gcf-artifacts/packages/${packages}$`,
    ),
    [
      "DELETE",
      "artifactregistry.googleapis.com",
      `^/v1/projects/${P}/locations/${R}/repositories/gcf-artifacts/packages/${packages}$`,
      {},
      nothing,
      true,
    ],
    read(
      "artifactregistry.googleapis.com",
      `^/v1/projects/${P}/locations/${R}/operations/${OPERATION_ID}$`,
    ),
    // The Gen2 source buckets: object lists only (read-only inventory)
    ...sourceBuckets(projectNumber).map((name) =>
      read("storage.googleapis.com", `^/storage/v1/b/${esc(name)}/o$`, {
        maxResults: num(1000),
        pageToken: token,
      }),
    ),
    // The upload object the deploy's own generateUploadUrl answer named (the run adopted it from the CLI log): its metadata
    // is read, and it is deleted once, by generation. The sources bucket has no object rule.
    ...[
      ["GET", false, { fields: (v) => v === "bucket,name,generation" }],
      ["DELETE", true, { ifGenerationMatch: (v) => /^\d{1,20}$/.test(v) }],
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
      {},
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
  const state = { localIds: new Set(), objects: new Set() };
  const ruleList = rules(runId, projectNumber, state);
  return {
    allow: (spec) => matchRule(spec, ruleList) !== null,
    isMutation: (spec) => matchRule(spec, ruleList)?.mutation === true,
    /** Records an account id this run's own sign-up returned, so that it may be read and deleted. */
    adopt: (localId) => {
      if (typeof localId === "string" && /^[A-Za-z0-9]{20,40}$/.test(localId))
        state.localIds.add(localId);
    },
    adopted: () => [...state.localIds],
    /** Records the upload object the deploy's receipt named, so that it may be read and deleted; false for any other name. */
    adoptObject: (bucket, name) => {
      if (!isOwnUploadObject(projectNumber, bucket, name)) return false;
      state.objects.add(bucket + "/" + name);
      return true;
    },
    adoptedObjects: () => [...state.objects],
  };
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
  if (!isObject(policy)) return { ok: false, why: "policy-not-an-object" };
  if (Object.keys(policy).some((k) => !["version", "etag", "bindings"].includes(k)))
    return { ok: false, why: "policy-fields" };
  if (policy.bindings !== undefined && !Array.isArray(policy.bindings))
    return { ok: false, why: "bindings-not-a-list" };
  const kept = [];
  for (const binding of policy.bindings ?? []) {
    if (
      !isObject(binding) ||
      Object.keys(binding).some((k) => !["role", "members", "condition"].includes(k)) ||
      typeof binding.role !== "string" ||
      !Array.isArray(binding.members) ||
      binding.members.some((m) => typeof m !== "string" || m === "allAuthenticatedUsers") ||
      (binding.condition !== undefined && !isObject(binding.condition))
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
