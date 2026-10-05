// The allowlist of every REST request the delivery recorder may send. Anything that matches no rule is
// refused before it is journaled or sent. Each rule pins the method, the host, the path (case-exact
// names), the allowed query keys, and the body, and says whether it is a mutation.
import {
  EXTRA_JOBS,
  FUNCTIONS,
  PROJECT,
  REGION,
  extraJobId,
  jobIds,
  pullSubscriptionId,
  scheduleId,
} from "./plan.mjs";

const esc = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const alt = (names) => "(?:" + names.map(esc).join("|") + ")";

export { jobIds };
export const pullIds = (runId) => FUNCTIONS.v1.map((fn) => pullSubscriptionId(runId, fn));
export const v1TopicIds = () => FUNCTIONS.v1.map(scheduleId);

const OPERATION_ID = "[A-Za-z0-9._-]+";
const BUILD_ID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";

/**
 * Rules for one run. `projectNumber` is for the Service Usage reads only. A rule is
 * `[method, host, path regex, query keys allowed, body check, mutation]`.
 */
export function rules(runId, projectNumber) {
  const P = esc(PROJECT);
  const R = esc(REGION);
  const jobs = alt(jobIds(runId));
  const extra = alt(EXTRA_JOBS.map((job) => extraJobId(runId, job.key)));
  const subs = alt(pullIds(runId));
  const topics = alt(v1TopicIds());
  const v2names = alt(FUNCTIONS.v2);
  const v1names = alt(FUNCTIONS.v1);
  const num = (n) => (v) => v === String(n);
  const token = (v) => /^[A-Za-z0-9_=.%+/-]{1,2048}$/.test(v);
  const q = (spec) => spec;
  const empty = (json) => json === undefined || (json && Object.keys(json).length === 0);
  const nothing = (json) => json === undefined;
  const sched = "cloudscheduler.googleapis.com";
  const pubsub = "pubsub.googleapis.com";
  const gcf = "cloudfunctions.googleapis.com";
  return [
    // identity and the project's own state (reads)
    [
      "GET",
      "firebaserules.googleapis.com",
      `^/v1/projects/${P}/releases/cloud\\.firestore$`,
      q({}),
      nothing,
      false,
    ],
    [
      "GET",
      "serviceusage.googleapis.com",
      `^/v1/projects/${esc(projectNumber)}/services$`,
      q({ filter: (v) => v === "state:ENABLED", pageSize: num(200), pageToken: token }),
      nothing,
      false,
    ],
    [
      "POST",
      "cloudresourcemanager.googleapis.com",
      `^/v1/projects/${P}:getIamPolicy$`,
      q({}),
      empty,
      false,
    ],
    [
      "GET",
      "firebase.googleapis.com",
      `^/v1beta1/projects/${P}/adminSdkConfig$`,
      q({}),
      nothing,
      false,
    ],
    ["GET", "appengine.googleapis.com", `^/v1/apps/${P}$`, q({}), nothing, false],
    // Cloud Functions: lists, the five functions, and the leftovers' deletes (one at a time, exact case)
    [
      "GET",
      gcf,
      `^/v1/projects/${P}/locations/(?:${R}|-)/functions$`,
      q({ pageToken: token }),
      nothing,
      false,
    ],
    [
      "GET",
      gcf,
      `^/v2/projects/${P}/locations/(?:${R}|-)/functions$`,
      q({ pageToken: token }),
      nothing,
      false,
    ],
    ["GET", gcf, `^/v1/projects/${P}/locations/${R}/functions/${v1names}$`, q({}), nothing, false],
    ["GET", gcf, `^/v2/projects/${P}/locations/${R}/functions/${v2names}$`, q({}), nothing, false],
    [
      "DELETE",
      gcf,
      `^/v1/projects/${P}/locations/${R}/functions/${v1names}$`,
      q({}),
      nothing,
      true,
    ],
    [
      "DELETE",
      gcf,
      `^/v2/projects/${P}/locations/${R}/functions/${v2names}$`,
      q({}),
      nothing,
      true,
    ],
    ["GET", gcf, `^/v1/operations/${OPERATION_ID}$`, q({}), nothing, false],
    [
      "GET",
      gcf,
      `^/v2/projects/${P}/locations/${R}/operations/${OPERATION_ID}$`,
      q({}),
      nothing,
      false,
    ],
    // Cloud Build: the one build of a function that did not become active (a read; the id is read from the
    // function's own list entry)
    [
      "GET",
      "cloudbuild.googleapis.com",
      `^/v1/projects/${esc(projectNumber)}/locations/${R}/builds/${BUILD_ID}$`,
      q({}),
      nothing,
      false,
    ],
    // Cloud Run and Artifact Registry (reads only)
    [
      "GET",
      "run.googleapis.com",
      `^/v2/projects/${P}/locations/(?:${R}|-)/services$`,
      q({ pageToken: token }),
      nothing,
      false,
    ],
    [
      "GET",
      "artifactregistry.googleapis.com",
      `^/v1/projects/${P}/locations/${R}/repositories$`,
      q({ pageToken: token, pageSize: num(100) }),
      nothing,
      false,
    ],
    [
      "GET",
      "artifactregistry.googleapis.com",
      `^/v1/projects/${P}/locations/${R}/repositories/gcf-artifacts$`,
      q({}),
      nothing,
      false,
    ],
    [
      "GET",
      "artifactregistry.googleapis.com",
      `^/v1/projects/${P}/locations/${R}/repositories/gcf-artifacts/packages$`,
      q({ pageToken: token, pageSize: num(100) }),
      nothing,
      false,
    ],
    // Cloud Scheduler
    [
      "GET",
      sched,
      `^/v1/projects/${P}/locations/${R}/jobs$`,
      q({ pageSize: num(500), pageToken: token }),
      nothing,
      false,
    ],
    ["GET", sched, `^/v1/projects/${P}/locations/${R}/jobs/${jobs}$`, q({}), nothing, false],
    ["POST", sched, `^/v1/projects/${P}/locations/${R}/jobs/${jobs}:run$`, q({}), empty, true],
    ["POST", sched, `^/v1/projects/${P}/locations/${R}/jobs/${jobs}:pause$`, q({}), empty, true],
    ["DELETE", sched, `^/v1/projects/${P}/locations/${R}/jobs/${jobs}$`, q({}), nothing, true],
    [
      "POST",
      sched,
      `^/v1/projects/${P}/locations/${R}/jobs$`,
      q({}),
      (json) =>
        typeof json?.name === "string" &&
        new RegExp(`^projects/${P}/locations/${R}/jobs/${extra}$`).test(json.name),
      true,
    ],
    // Pub/Sub: the v1 functions' topics (read, and deleted only after their function is gone), and the
    // run's own pull subscriptions on them
    [
      "GET",
      pubsub,
      `^/v1/projects/${P}/topics$`,
      q({ pageSize: num(1000), pageToken: token }),
      nothing,
      false,
    ],
    [
      "GET",
      pubsub,
      `^/v1/projects/${P}/subscriptions$`,
      q({ pageSize: num(1000), pageToken: token }),
      nothing,
      false,
    ],
    ["GET", pubsub, `^/v1/projects/${P}/topics/${topics}$`, q({}), nothing, false],
    ["DELETE", pubsub, `^/v1/projects/${P}/topics/${topics}$`, q({}), nothing, true],
    [
      "PUT",
      pubsub,
      `^/v1/projects/${P}/subscriptions/${subs}$`,
      q({}),
      (json) =>
        json?.ackDeadlineSeconds === 10 &&
        typeof json.topic === "string" &&
        new RegExp(`^projects/${P}/topics/${topics}$`).test(json.topic) &&
        Object.keys(json).every((k) => ["topic", "ackDeadlineSeconds"].includes(k)),
      true,
    ],
    ["GET", pubsub, `^/v1/projects/${P}/subscriptions/${subs}$`, q({}), nothing, false],
    ["DELETE", pubsub, `^/v1/projects/${P}/subscriptions/${subs}$`, q({}), nothing, true],
    [
      "POST",
      pubsub,
      `^/v1/projects/${P}/subscriptions/${subs}:pull$`,
      q({}),
      (json) =>
        Number.isInteger(json?.maxMessages) &&
        json.maxMessages >= 1 &&
        json.maxMessages <= 10 &&
        Object.keys(json).every((k) => ["maxMessages", "returnImmediately"].includes(k)),
      true,
    ],
    [
      "POST",
      pubsub,
      `^/v1/projects/${P}/subscriptions/${subs}:acknowledge$`,
      q({}),
      (json) =>
        Array.isArray(json?.ackIds) &&
        json.ackIds.length > 0 &&
        json.ackIds.length <= 10 &&
        json.ackIds.every((id) => typeof id === "string" && id.length > 0 && id.length < 4096) &&
        Object.keys(json).length === 1,
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
        json.filter.length < 4000 &&
        json.pageSize <= 200 &&
        json.orderBy === "timestamp asc" &&
        Object.keys(json).every((k) =>
          ["resourceNames", "filter", "orderBy", "pageSize", "pageToken"].includes(k),
        ),
      false,
    ],
  ].map(([method, host, path, keys, body, mutation]) => ({
    method,
    host,
    path: new RegExp(path),
    query: keys,
    body,
    mutation,
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
    return rule;
  }
  return null;
}

export function createGuard(runId, projectNumber) {
  const ruleList = rules(runId, projectNumber);
  return {
    allow: (spec) => matchRule(spec, ruleList) !== null,
    isMutation: (spec) => matchRule(spec, ruleList)?.mutation === true,
  };
}
