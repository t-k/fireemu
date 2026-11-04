// The allowlist of every REST request the blocking check may send. Anything that matches no rule is refused before it is
// journaled or sent. Each rule pins the method, the host, the path (case-exact names), the allowed query keys and the body,
// and says whether it is a mutation. The one sign-up body is built from the run's id, and an account can be read or deleted
// only when its id was returned by this run's own sign-up (`state.localIds`).
import {
  FUNCTION,
  PROJECT,
  REGION,
  isOwnSourceObject,
  packageIds,
  sourceBuckets,
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
    // Cloud Run: the list, the function's service and its public-invoker policy (reads only)
    read("run.googleapis.com", `^/v2/projects/${P}/locations/(?:${R}|-)/services$`, {
      pageToken: token,
    }),
    read("run.googleapis.com", `^/v2/projects/${P}/locations/${R}/services/${fn}$`),
    read("run.googleapis.com", `^/v2/projects/${P}/locations/${R}/services/${fn}:getIamPolicy$`),
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
    // The deployment's own new objects in those buckets: read and delete, one name at a time, after the run adopted it
    ...sourceBuckets(projectNumber).flatMap((name) =>
      [
        ["GET", false],
        ["DELETE", true],
      ].map(([method, mutation]) => [
        method,
        "storage.googleapis.com",
        `^/storage/v1/b/${esc(name)}/o/[^/]+$`,
        {},
        nothing,
        mutation,
        (pathname) => state.objects.has(name + "/" + decodeName(pathname.split("/o/")[1])),
      ]),
    ),
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
    if (rule.check && rule.check(url.pathname) !== true) continue;
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
    /** Records a source object the deployment added, so that it may be read and deleted; false when it is not one of the deployment's. */
    adoptObject: (bucket, name) => {
      if (!isOwnSourceObject(projectNumber, bucket, name)) return false;
      state.objects.add(bucket + "/" + name);
      return true;
    },
    adoptedObjects: () => [...state.objects],
  };
}
