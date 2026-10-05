// The preparation packet of the SCHEDULED-FUNCTIONS delivery recording on the sandbox project.
//
// Why it exists: the Firebase CLI enables the APIs a deploy needs (`ensureApiEnabled.ensure`),
// including in `--dry-run`. If the APIs are still disabled, the dry run of the delivery packet is
// a write. This packet enables only those APIs, once, and records what that did, so the delivery
// packet has no API enablement in it. It also reads what the delivery packet needs to know:
// whether the project's `adminSdkConfig` names a `locationId` (which decides whether v1 scheduled
// functions need an App Engine app at all), whether the App Engine app exists, and whether the
// identity can read Cloud Logging.
//
// The only mutation is one `services:batchEnable`. It is never re-sent; an unknown answer is
// settled by reading the services, and stays unknown (a later read-back closes it).
// Importing this module sends nothing and reads no credential.
import { AuthStop, answerClass, createCapture, isUnknownClass, readable } from "./capture.mjs";

export const PROJECT = "fireemu-oracle-sbx";
export const REGION = "us-central1";
export const MAX_REQUESTS = 60;
const esc = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const SERVICEUSAGE = "https://serviceusage.googleapis.com/v1/";

/**
 * The APIs the deploy needs and the sandbox does not have (the sandbox already has cloudscheduler,
 * pubsub and appengine). Chosen from firebase-tools 15.28.2 `deploy/functions/prepare.js`: the
 * standard APIs of a Cloud Functions deploy plus, for a v2 function, Run, Eventarc, Pub/Sub and
 * Storage; Firebase Extensions is needed by every deploy (the SDK always emits an empty extensions section, so the CLI prepares dynamic extensions, which enables the API); Compute Engine creates the
 * default service account the v2 Scheduler job and the Run invoker binding use (the same owner
 * decision as on the events project, ledger 305). Already-enabled ones are not an error.
 */
export const TARGET_SERVICES = Object.freeze([
  "artifactregistry.googleapis.com",
  "cloudbuild.googleapis.com",
  "cloudfunctions.googleapis.com",
  "compute.googleapis.com",
  "eventarc.googleapis.com",
  "firebaseextensions.googleapis.com",
  "run.googleapis.com",
  "storage.googleapis.com",
]);

const OPERATION = /^operations\/[A-Za-z0-9._-]+$/;

// ---- the allowlist ----------------------------------------------------------------------------

export function allowedRequest(spec, projectNumber) {
  const { method, url, json } = spec;
  const exact = (m, u) => method === m && url === u;
  const services = SERVICEUSAGE + "projects/" + projectNumber + "/services";
  const listPage = (base) => {
    if (method !== "GET" || !url.startsWith(base)) return false;
    const query = new URLSearchParams(url.slice(base.length).replace(/^\?/, ""));
    return (
      [...query.keys()].every((k) => ["filter", "pageSize", "pageToken"].includes(k)) &&
      query.get("filter") === "state:ENABLED" &&
      query.get("pageSize") === "200"
    );
  };
  return (
    exact(
      "GET",
      "https://firebaserules.googleapis.com/v1/projects/" + PROJECT + "/releases/cloud.firestore",
    ) ||
    listPage(services) ||
    exact(
      "POST",
      "https://cloudresourcemanager.googleapis.com/v1/projects/" + PROJECT + ":getIamPolicy",
    ) ||
    exact(
      "GET",
      "https://firebase.googleapis.com/v1beta1/projects/" + PROJECT + "/adminSdkConfig",
    ) ||
    exact("GET", "https://appengine.googleapis.com/v1/apps/" + PROJECT) ||
    (exact("POST", "https://logging.googleapis.com/v2/entries:list") &&
      JSON.stringify(json) ===
        JSON.stringify({
          resourceNames: ["projects/" + PROJECT],
          orderBy: "timestamp desc",
          pageSize: 1,
        })) ||
    (exact("POST", services + ":batchEnable") &&
      Array.isArray(json?.serviceIds) &&
      json.serviceIds.length > 0 &&
      json.serviceIds.every((id) => TARGET_SERVICES.includes(id))) ||
    (method === "GET" &&
      url.startsWith(SERVICEUSAGE + "operations/") &&
      OPERATION.test(url.slice(SERVICEUSAGE.length))) ||
    ["https://cloudfunctions.googleapis.com/v1/", "https://cloudfunctions.googleapis.com/v2/"].some(
      (base) => exact("GET", base + "projects/" + PROJECT + "/locations/" + REGION + "/functions"),
    ) ||
    exact(
      "GET",
      "https://run.googleapis.com/v2/projects/" + PROJECT + "/locations/" + REGION + "/services",
    ) ||
    exact(
      "GET",
      "https://artifactregistry.googleapis.com/v1/projects/" +
        PROJECT +
        "/locations/" +
        REGION +
        "/repositories",
    )
  );
}

// ---- judges: pure functions of an answer --------------------------------------------------------

/** The ids of the services an `ENABLED` list names. */
export function enabledServices(answer) {
  if (!(answer?.status === 200 && readable(answer))) return null;
  const list = answer.json.services ?? [];
  if (!Array.isArray(list)) return null;
  return new Set(
    list
      .filter((s) => s?.state === "ENABLED" && typeof s.config?.name === "string")
      .map((s) => s.config.name),
  );
}

export const operationPending = (a) =>
  a?.status === 200 && readable(a) && OPERATION.test(a.json.name ?? "") && a.json.done !== true;
export const operationDone = (a) =>
  a?.status === 200 && readable(a) && OPERATION.test(a.json.name ?? "") && a.json.done === true;
export const operationFailed = (a) => operationDone(a) && !!a.json.error;

/**
 * A Google-managed principal that enabling an API may add: only the known forms. A service agent
 * (`service-<number>@<name>.iam.gserviceaccount.com`), the Cloud Build and Google APIs accounts
 * (`<number>@cloudbuild.gserviceaccount.com`, `<number>@cloudservices.gserviceaccount.com`), the default
 * Compute Engine account (`<number>-compute@developer.gserviceaccount.com`), and the project's own App Engine
 * default account (`<project id>@appspot.gserviceaccount.com`, which Google grants Editor when an API such
 * as Compute Engine is enabled). Any other principal, including a service account of another project whose
 * name merely contains the number, is a reason to review.
 */
export function expectedPrincipal(member, projectNumber) {
  const m = /^serviceAccount:(.+)$/.exec(member);
  if (!m) return false;
  const email = m[1];
  const n = esc(projectNumber);
  return [
    new RegExp(`^service-${n}@[a-z0-9-]+\\.iam\\.gserviceaccount\\.com$`),
    new RegExp(`^${n}@(?:cloudbuild|cloudservices)\\.gserviceaccount\\.com$`),
    new RegExp(`^${n}-compute@developer\\.gserviceaccount\\.com$`),
    new RegExp(`^${esc(PROJECT)}@appspot\\.gserviceaccount\\.com$`),
  ].some((re) => re.test(email));
}

const memberKeys = (policy) =>
  new Set((policy?.bindings ?? []).flatMap((b) => (b.members ?? []).map((m) => b.role + "|" + m)));

/** The difference between two IAM policies, split into allowed and unexpected additions. */
export function iamDiff(before, after, projectNumber) {
  if (!(before?.status === 200 && readable(before) && after?.status === 200 && readable(after)))
    return null;
  const b = memberKeys(before.json);
  const a = memberKeys(after.json);
  const added = [...a].filter((k) => !b.has(k)).toSorted();
  const removed = [...b].filter((k) => !a.has(k)).toSorted();
  const unexpected = added.filter(
    (k) => !expectedPrincipal(k.split("|").slice(1).join("|"), projectNumber),
  );
  return { added, removed, unexpected };
}

export function adminSdkConfigSummary(a) {
  if (!a) return { status: null };
  if (a.status !== 200 || !readable(a)) return { status: a.status };
  return {
    status: 200,
    locationIdPresent: typeof a.json.locationId === "string" && a.json.locationId.length > 0,
    ...(typeof a.json.locationId === "string" ? { locationId: a.json.locationId } : {}),
    projectIdMatches: a.json.projectId === PROJECT,
  };
}

export function appEngineSummary(a) {
  if (!a) return { status: null };
  return { status: a.status, exists: a.status === 200 };
}

export function loggingSummary(a) {
  if (!a) return { status: null };
  return {
    status: a.status,
    canRead: a.status === 200,
    ...(a.status === 200 && readable(a)
      ? { entries: Array.isArray(a.json.entries) ? a.json.entries.length : 0 }
      : {}),
  };
}

// ---- the collector ----------------------------------------------------------------------------

export async function collect({
  projectNumber,
  accessToken,
  save,
  send,
  clock = Date.now,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  budget = MAX_REQUESTS,
}) {
  if (!/^\d{12,13}$/.test(projectNumber ?? "")) throw new Error("invalid project number");
  const { capture, counts, authStop } = createCapture({
    accessToken,
    save,
    send,
    clock,
    maxRequests: budget,
    maxRequestCap: MAX_REQUESTS,
    allow: (spec) => allowedRequest(spec, projectNumber),
    quotaProject: PROJECT,
    timeoutFor: (spec) =>
      spec.method === "POST" && spec.url.endsWith(":batchEnable")
        ? 60000
        : spec.url.includes("/services?")
          ? 30000
          : 10000,
  });
  const unknownMutations = [];
  const incompleteReads = [];
  const read = async (spec) => {
    const answer = await capture(spec);
    // A read is incomplete when it is unknown-class, or an error where an answer was expected. A
    // request that exists to observe something (`observe`) may answer 4xx: that is the data.
    if (isUnknownClass(answer) || (answer.status >= 400 && !spec.observe))
      incompleteReads.push({ id: spec.id, class: answerClass(answer) });
    return answer;
  };
  const out = {
    stage: "preflight",
    requested: [],
    alreadyEnabled: [],
    batchEnable: null,
  };
  const summary = (stage, closureReady) => {
    const known = counts();
    const stop = authStop();
    return {
      outcome: stop
        ? "scheduled-delivery-prepare-auth-stop"
        : "scheduled-delivery-prepare-needs-review",
      ...out,
      stage,
      ...known,
      unknownMutations: unknownMutations.length,
      unknownMutationList: unknownMutations,
      incompleteReads,
      readBackRequired: unknownMutations.length > 0 || stop !== null,
      ...(stop ? { authStop: stop } : {}),
      closureReady:
        closureReady &&
        stop === null &&
        known.unknown === 0 &&
        unknownMutations.length === 0 &&
        incompleteReads.length === 0,
      cleanupVerified: false,
    };
  };
  try {
    return await body();
  } catch (error) {
    if (error instanceof AuthStop) return summary("auth-stop", false);
    throw error;
  }

  async function listEnabled(prefix) {
    // Pages of the ENABLED list, followed up to five times (a page holds 200 services).
    const all = new Set();
    let token = "";
    for (let page = 0; page < 5; page++) {
      const answer = await capture({
        id: prefix + (page ? "-page-" + (page + 1) : ""),
        method: "GET",
        url:
          SERVICEUSAGE +
          "projects/" +
          projectNumber +
          "/services?filter=state:ENABLED&pageSize=200" +
          (token ? "&pageToken=" + encodeURIComponent(token) : ""),
      });
      const set = enabledServices(answer);
      if (!set) {
        incompleteReads.push({ id: prefix, class: answerClass(answer) });
        return null;
      }
      for (const id of set) all.add(id);
      token = answer.json.nextPageToken ?? "";
      if (!token) return all;
    }
    incompleteReads.push({ id: prefix, class: "more-than-five-pages" });
    return null;
  }

  async function body() {
    const identity = await capture({
      id: "identity",
      method: "GET",
      url:
        "https://firebaserules.googleapis.com/v1/projects/" + PROJECT + "/releases/cloud.firestore",
    });
    if (
      identity?.status !== 200 ||
      identity.json?.name !== "projects/" + PROJECT + "/releases/cloud.firestore"
    )
      return summary("preflight", false);
    const before = await listEnabled("services-before");
    if (!before) return summary("preflight", false);
    out.stage = "reads";
    const iamBefore = await read({
      id: "iam-before",
      method: "POST",
      url: "https://cloudresourcemanager.googleapis.com/v1/projects/" + PROJECT + ":getIamPolicy",
      json: {},
    });
    const adminSdk = await read({
      id: "admin-sdk-config",
      method: "GET",
      observe: true,
      url: "https://firebase.googleapis.com/v1beta1/projects/" + PROJECT + "/adminSdkConfig",
    });
    out.adminSdkConfig = adminSdkConfigSummary(adminSdk);
    const appEngine = await read({
      id: "appengine-app",
      method: "GET",
      observe: true,
      url: "https://appengine.googleapis.com/v1/apps/" + PROJECT,
    });
    out.appEngine = appEngineSummary(appEngine);
    const logging = await read({
      id: "logging-read",
      method: "POST",
      observe: true,
      url: "https://logging.googleapis.com/v2/entries:list",
      json: { resourceNames: ["projects/" + PROJECT], orderBy: "timestamp desc", pageSize: 1 },
    });
    out.logging = loggingSummary(logging);

    out.requested = TARGET_SERVICES.filter((id) => !before.has(id));
    out.alreadyEnabled = TARGET_SERVICES.filter((id) => before.has(id));
    if (out.requested.length > 0) {
      out.stage = "enable";
      await save({ id: "issue-enable", state: "issued", serviceIds: out.requested });
      const enable = await capture({
        id: "enable-apis",
        method: "POST",
        url: SERVICEUSAGE + "projects/" + projectNumber + "/services:batchEnable",
        json: { serviceIds: out.requested },
      });
      out.batchEnable = { class: answerClass(enable) };
      if (isUnknownClass(enable)) {
        unknownMutations.push({ id: "enable-apis", class: answerClass(enable) });
      } else if (operationPending(enable)) {
        let operation = enable.json.name;
        let done = false;
        for (let poll = 0; poll < 18 && !done; poll++) {
          if (poll > 0) await sleep(10000);
          const answer = await capture({
            id: "enable-poll-" + (poll + 1),
            method: "GET",
            url: SERVICEUSAGE + operation,
          });
          if (operationFailed(answer)) {
            out.batchEnable.failed = answer.json.error;
            done = true;
          } else if (operationDone(answer)) {
            done = true;
          }
        }
        out.batchEnable.done = done;
      } else if (operationDone(enable)) {
        out.batchEnable.done = true;
      }
    }
    out.stage = "after";
    const after = await listEnabled("services-after");
    const loggingAfter = await read({
      id: "logging-read-after",
      method: "POST",
      observe: true,
      url: "https://logging.googleapis.com/v2/entries:list",
      json: { resourceNames: ["projects/" + PROJECT], orderBy: "timestamp desc", pageSize: 1 },
    });
    out.loggingAfter = loggingSummary(loggingAfter);
    out.loggingEnabledAfter = after ? after.has("logging.googleapis.com") : null;
    const iamAfter = await read({
      id: "iam-after",
      method: "POST",
      url: "https://cloudresourcemanager.googleapis.com/v1/projects/" + PROJECT + ":getIamPolicy",
      json: {},
    });
    out.dependentApis = after
      ? [...after].filter((id) => !before.has(id) && !TARGET_SERVICES.includes(id)).toSorted()
      : null;
    out.missingAfter = after ? out.requested.filter((id) => !after.has(id)) : out.requested;
    out.iam = iamDiff(iamBefore, iamAfter, projectNumber);
    // What the delivery packet will list first: the new APIs answer, and every list is empty.
    const lists = {};
    for (const [id, url] of [
      [
        "functions-v1",
        "https://cloudfunctions.googleapis.com/v1/projects/" +
          PROJECT +
          "/locations/" +
          REGION +
          "/functions",
      ],
      [
        "functions-v2",
        "https://cloudfunctions.googleapis.com/v2/projects/" +
          PROJECT +
          "/locations/" +
          REGION +
          "/functions",
      ],
      [
        "run-services",
        "https://run.googleapis.com/v2/projects/" + PROJECT + "/locations/" + REGION + "/services",
      ],
      [
        "artifact-repositories",
        "https://artifactregistry.googleapis.com/v1/projects/" +
          PROJECT +
          "/locations/" +
          REGION +
          "/repositories",
      ],
    ]) {
      const answer = await read({ id: "list-" + id, method: "GET", observe: true, url });
      lists[id] = answer
        ? {
            status: answer.status,
            empty:
              answer.status === 200 && readable(answer) && Object.keys(answer.json).length === 0,
          }
        : { status: null };
    }
    out.lists = lists;
    const ok =
      after !== null &&
      out.missingAfter.length === 0 &&
      out.iam !== null &&
      out.iam.unexpected.length === 0 &&
      out.iam.removed.length === 0 &&
      // An enable that was sent closes only when its operation reported done without an error: services
      // that read ENABLED while the operation is still pending can be followed by service agents and grants.
      (out.batchEnable === null || (out.batchEnable.done === true && !out.batchEnable.failed));
    return summary("done", ok);
  }
}
