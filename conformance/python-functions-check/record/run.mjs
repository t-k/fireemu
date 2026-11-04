// The orchestrator of the check: preflight, the CLI dry run, one deploy of thirteen functions, readiness, the readbacks,
// the source operations, a bounded wait for the deliveries (Cloud Logging reads), and a cleanup that removes only what
// this run created and reads every name back. It judges delivery only through `judge`; it judges for itself only what
// it must to stay safe: the CLI's result, who owns a name, and whether a name is gone.
//
// Safety rules (the lessons of the FE v5 recorder and the calendar v6 review): every name is journaled as `issued`
// before the request that creates it; a mutation answer is classified, an unknown one is never re-sent and never
// closed; a 401, or a 403 on a write, stops the run; the CLI runs at most once per action; a leftover function is
// deleted through REST once, after a complete fresh list shows it, with no resend.
//
// Settlement (coordinator rulings of 2026-10-05): an unknown CREATE is settled only by an own 2xx read showing the name
// (a direct read, or a 2xx list naming it); a 404 never settles it, so it is listed as unconfirmed and the run cannot
// close. A create confirmed by a 2xx that later reads 404, or whose own DELETE answers 404, or that is missing from a
// list, is not settled in the run either (read-after-write lag): only the read-back at least ten minutes later
// settles it as gone. The one exception is the run's own DELETE that answered 2xx (or a clean CLI delete, for the names
// the CLI made), after which a 404 is the normal end.
import {
  AuthStop,
  answerClass,
  createCapture,
  isUnknownClass,
  readable,
} from "../../scheduled-delivery/capture.mjs";
import {
  READY_MAX_POLLS,
  READY_POLL_SECONDS,
  allActive,
  cliFailed,
  nonePresent,
  summarize,
} from "./deploy.mjs";
import { createGuard, ownPackages } from "./guard.mjs";
import { judge } from "./judge.mjs";
import { errorFilter, frameFilter, listRequest, parseErrors, parseFrames } from "./logs.mjs";
import {
  ALL_FUNCTIONS,
  APP_ENGINE_LOCATION,
  COLLECTION,
  DELIVERY_WINDOW_SECONDS,
  JOB_IDS,
  LOG_DELAY_SECONDS,
  PROJECT,
  PROPAGATION_WAIT_SECONDS,
  QUEUE_IDS,
  REGION,
  REQUIRED_SERVICES,
  isOwnSourceObject,
  sourceBuckets,
  STEP_GAP_SECONDS,
  TOPIC,
  functionName,
  jobName,
  packageIds,
  queueName,
  topicName,
} from "./plan.mjs";
import {
  documentId,
  documentUrl,
  objectName,
  operations,
  storageObjectUrl,
  topicUrl,
  undoOperations,
} from "./script.mjs";

export const NORMAL_CEILING = 300;
export const CLEANUP_CEILING = 200;
export const MAX_REQUESTS = NORMAL_CEILING + CLEANUP_CEILING;
export const LOG_POLL_SECONDS = 60;
const GCF = "https://cloudfunctions.googleapis.com/v2/";
const SCHEDULER = `https://cloudscheduler.googleapis.com/v1/projects/${PROJECT}/locations/${REGION}/jobs`;
const TASKS = `https://cloudtasks.googleapis.com/v2/projects/${PROJECT}/locations/${REGION}/queues`;
const REGISTRY = `https://artifactregistry.googleapis.com/v1/projects/${PROJECT}/locations/${REGION}/repositories/gcf-artifacts/packages`;
const iso = (ms) => new Date(ms).toISOString();

/**
 * A direct read of a name that shows it is gone: a 404 whose parsed error says NOT_FOUND. Google APIs say it as
 * `error.status`; the Cloud Storage JSON API has no `status` and says it as `error.errors[].reason` "notFound".
 */
export const absent = (a) =>
  a?.status === 404 &&
  readable(a) &&
  (a.json.error?.status === "NOT_FOUND" ||
    (a.json.error?.status === undefined &&
      Array.isArray(a.json.error?.errors) &&
      a.json.error.errors.some((e) => e?.reason === "notFound")));

/** The IAM members added and removed between two policy reads (recorded, not judged here). */
export function iamChanges(before, after) {
  const keys = (a) =>
    a?.status === 200 && readable(a)
      ? new Set(
          (a.json.bindings ?? []).flatMap((b) => (b.members ?? []).map((m) => b.role + "|" + m)),
        )
      : null;
  const b = keys(before);
  const a = keys(after);
  if (!b || !a) return null;
  return {
    added: [...a].filter((k) => !b.has(k)).toSorted(),
    removed: [...b].filter((k) => !a.has(k)).toSorted(),
  };
}

class BudgetError extends Error {}

/** The recorded 409 a job DELETE gets right after a run (`sync mutate calls cannot be queued`). */
export const isBusy = (a) =>
  a?.status === 409 &&
  readable(a) &&
  a.json.error?.status === "ABORTED" &&
  a.json.error.message === "sync mutate calls cannot be queued";

const lastSegment = (name) =>
  String(name ?? "")
    .split("/")
    .at(-1);

export async function record({
  runId,
  projectNumber,
  accessToken,
  save,
  send,
  runCli,
  clock = Date.now,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  waits = {},
  normalCeiling = NORMAL_CEILING,
  signal = { aborted: false },
  prepareRequest = null,
}) {
  const wait = {
    propagation: PROPAGATION_WAIT_SECONDS,
    window: DELIVERY_WINDOW_SECONDS,
    logPoll: LOG_POLL_SECONDS,
    logDelay: LOG_DELAY_SECONDS,
    ready: READY_POLL_SECONDS,
    readyPolls: READY_MAX_POLLS,
    gap: STEP_GAP_SECONDS,
    settle: 30,
    busy: 60,
    appEngine: 10,
    appEnginePolls: 30,
    ...waits,
  };
  const pause = (seconds) => sleep(seconds * 1000);
  const guard = createGuard(runId, projectNumber);
  const SERVICES_URL = `https://serviceusage.googleapis.com/v1/projects/${projectNumber}/services?filter=state:ENABLED&pageSize=200`;
  const { capture, counts, authStop } = createCapture({
    accessToken,
    save,
    send,
    clock,
    maxRequests: MAX_REQUESTS,
    maxRequestCap: MAX_REQUESTS,
    allow: guard.allow,
    quotaProject: PROJECT,
    timeoutFor: (spec) => (spec.method === "POST" ? 30_000 : 15_000),
  });
  const out = {
    runId,
    stage: "preflight",
    outcome: "pycheck-needs-review",
    cli: {},
    ready: null,
    operations: {},
    frames: {},
    framesIgnored: {},
    errorsSeen: 0,
    readbacks: {},
    cleanup: { verified: false },
    inventory: {},
    judged: null,
  };
  const unknownMutations = [];
  const incompleteReads = [];
  // Every name this run may create, by label (the labels of the cleanup's read-back), and the evidence about it.
  const NAMES = new Map([
    ...ALL_FUNCTIONS.map((fn) => ["function-" + fn, functionName(fn)]),
    ...JOB_IDS.map((id) => ["job-" + id, jobName(id)]),
    ...QUEUE_IDS.map((id) => ["queue-" + id, queueName(id)]),
    ["topic", topicName(TOPIC)],
  ]);
  const labelOf = new Map([...NAMES].map(([label, name]) => [name, label]));
  const issued = new Set();
  const confirmed = new Set();
  const ownDeleted = new Set();
  const pendingCreates = new Map();
  const cliLabels = new Map();
  let deployUnknown = null;
  let deployWrites = [];
  let created = false;
  let stopped = null;
  let bucket = null;
  const startedAt = clock();
  const frameSeen = new Set();
  const errorSeen = new Set();
  const allFrames = [];
  const allErrors = [];
  const sent = {};
  let polledUntil = startedAt;
  let iamBefore = null;
  let enabledBefore = null;
  let sourceObjectsBefore = null;
  let cliDeleteStarted = false;

  // ---- request helpers -------------------------------------------------------------------------
  const normal = async (spec) => {
    if (signal.aborted && !spec.cleanup) throw new BudgetError("stopped by a signal");
    if (counts().attempted >= normalCeiling && !spec.cleanup)
      throw new BudgetError("the normal request ceiling is reached");
    await prepareRequest?.(spec);
    return capture(spec);
  };
  const noteSeen = (answer) => {
    if (!(answer?.status === 200 && readable(answer))) return;
    const names = [answer.json.name];
    for (const key of ["functions", "jobs", "queues", "topics"])
      if (Array.isArray(answer.json[key]))
        names.push(...answer.json[key].map((item) => item?.name));
    for (const name of names) {
      const label = labelOf.get(name);
      if (label && issued.has(label)) confirmed.add(label);
    }
  };
  const read = async (spec, { observe: observing = false } = {}) => {
    const answer = await normal(observing ? { ...spec, observe: true } : spec);
    if (isUnknownClass(answer) || (answer.status >= 400 && !observing))
      incompleteReads.push({ id: spec.id, class: answerClass(answer) });
    noteSeen(answer);
    return answer;
  };
  const mutate = async (spec) => {
    const answer = await normal(spec);
    if (isUnknownClass(answer)) unknownMutations.push({ id: spec.id, class: answerClass(answer) });
    return answer;
  };
  const cliUnknownClass = (result) =>
    result?.timedOut
      ? "cli-timeout"
      : result?.error
        ? "cli-error"
        : result?.signal
          ? "cli-signal"
          : null;
  const cli = async (action) => {
    let result;
    try {
      result = await runCli({ action });
    } catch (error) {
      unknownMutations.push({ id: "cli-" + action, class: "cli-error" });
      if (action === "deploy") deployUnknown = "cli-error";
      try {
        await save({
          id: "cli-" + action,
          state: "cli-result",
          result: { action, error: String(error?.message) },
          responseAt: iso(clock()),
        });
      } catch {
        // the journal is the thing that failed; the error below is what matters
      }
      throw error;
    }
    const why = cliUnknownClass(result);
    if (why) {
      unknownMutations.push({ id: "cli-" + action, class: why });
      if (action === "deploy") deployUnknown = why;
    }
    return result;
  };
  const cliDeleteClean = () =>
    Boolean(out.cli.delete) && !cliFailed(out.cli.delete) && !cliUnknownClass(out.cli.delete);
  const hostOfLabel = (label) =>
    label.startsWith("function-")
      ? "cloudfunctions"
      : label.startsWith("job-")
        ? "cloudscheduler"
        : label.startsWith("queue-")
          ? "cloudtasks"
          : "pubsub";
  const unconfirmedCreates = () => [
    ...[...pendingCreates.values()].filter((create) => !confirmed.has(create.label)),
    ...(deployUnknown
      ? [...cliLabels]
          .filter(([label]) => !confirmed.has(label))
          .map(([label, name]) => ({ label, id: "cli-deploy", name, class: deployUnknown }))
      : []),
    // A CLI write answered 5xx (or 3xx, or below 200) may have created a name of its kind even though the CLI reported
    // the function errored and failed cleanly: every name of that kind no own 2xx read showed is open.
    ...(deployUnknown
      ? []
      : [...cliLabels]
          .filter(([label]) => !confirmed.has(label))
          .flatMap(([label, name]) => {
            const write = deployWrites.find((w) => w.host === hostOfLabel(label));
            return write ? [{ label, id: "cli-deploy", name, class: "cli-" + write.status }] : [];
          })),
  ];
  const vanishedAfterCreate = () => {
    const gone = out.cleanup.readBack;
    if (!gone) return [];
    return [...confirmed]
      .filter(
        (label) =>
          gone[label] === true &&
          !ownDeleted.has(label) &&
          !(cliLabels.has(label) && cliDeleteClean()),
      )
      .toSorted()
      .map((label) => ({ label, name: NAMES.get(label), class: "vanished-after-create" }));
  };
  const list = async (id, url, key) => {
    const items = [];
    let token = "";
    for (let page = 0; page < 5; page++) {
      const answer = await read({
        id: id + (page ? "-page-" + (page + 1) : ""),
        method: "GET",
        url:
          url +
          (token ? (url.includes("?") ? "&" : "?") + "pageToken=" + encodeURIComponent(token) : ""),
        cleanup: stopped === "cleanup",
      });
      if (!(answer?.status === 200 && readable(answer))) return null;
      items.push(...(answer.json[key] ?? []));
      token = answer.json.nextPageToken ?? "";
      if (!token) return { [key]: items };
    }
    incompleteReads.push({ id, class: "more-than-five-pages" });
    return null;
  };
  const functionLists = async (prefix) => ({
    v2: await list(
      prefix + "-functions-v2",
      GCF + "projects/" + PROJECT + "/locations/-/functions",
      "functions",
    ),
    run: await list(
      prefix + "-run-services",
      "https://run.googleapis.com/v2/projects/" + PROJECT + "/locations/-/services",
      "services",
    ),
  });
  const complete = (lists) => Boolean(lists.v2 && lists.run);

  const open = () => {
    const known = counts();
    const unconfirmed = unconfirmedCreates();
    const vanished = vanishedAfterCreate();
    return {
      unconfirmed,
      vanished,
      blocked:
        authStop() !== null ||
        known.unknown > 0 ||
        unknownMutations.length > 0 ||
        incompleteReads.length > 0 ||
        unconfirmed.length > 0 ||
        vanished.length > 0,
    };
  };
  const summary = (stage, closureReady) => {
    const known = counts();
    const stop = authStop();
    const { unconfirmed, vanished, blocked } = open();
    return {
      ...out,
      stage,
      outcome: stop ? "pycheck-auth-stop" : out.outcome,
      ...known,
      unknownMutations: unknownMutations.length,
      unknownMutationList: unknownMutations,
      unconfirmedCreates: unconfirmed,
      vanishedAfterCreate: vanished,
      incompleteReads,
      readBackRequired:
        unknownMutations.length > 0 ||
        stop !== null ||
        unconfirmed.length > 0 ||
        vanished.length > 0,
      ...(stop ? { authStop: stop } : {}),
      closureReady: closureReady && !blocked,
    };
  };

  // ---- Cloud Logging -------------------------------------------------------------------------------
  async function pollLogs(label, { final = false } = {}) {
    const end = clock();
    const start = final ? startedAt : polledUntil - 5000;
    const window = { start: iso(start), end: iso(end) };
    for (const [kind, filter] of [
      ["frames", frameFilter(window)],
      ["errors", errorFilter(window)],
    ]) {
      let token = "";
      for (let page = 0; page < 5; page++) {
        const answer = await normal({
          ...listRequest({
            id: `logs-${label}-${kind}${page ? "-page-" + (page + 1) : ""}`,
            filter,
            pageToken: token,
          }),
          observe: true,
          cleanup: stopped === "cleanup",
        });
        if (!(answer?.status === 200 && readable(answer))) {
          incompleteReads.push({ id: `logs-${label}-${kind}`, class: answerClass(answer) });
          break;
        }
        const entries = answer.json.entries ?? [];
        if (kind === "frames") {
          const parsed = parseFrames(entries, frameSeen);
          allFrames.push(...parsed.frames);
          for (const [k, n] of Object.entries(parsed.ignored))
            out.framesIgnored[k] = (out.framesIgnored[k] ?? 0) + n;
        } else allErrors.push(...parseErrors(entries, errorSeen));
        token = answer.json.nextPageToken ?? "";
        if (!token) break;
        if (page === 4)
          incompleteReads.push({ id: `logs-${label}-${kind}`, class: "more-than-five-pages" });
      }
    }
    if (!final) polledUntil = end;
  }

  // ---- the phases ------------------------------------------------------------------------------
  async function preflight() {
    const identity = await normal({
      id: "identity",
      method: "GET",
      url: `https://firebaserules.googleapis.com/v1/projects/${PROJECT}/releases/cloud.firestore`,
    });
    if (
      identity?.status !== 200 ||
      identity.json?.name !== `projects/${PROJECT}/releases/cloud.firestore`
    )
      return "identity";
    const services = await normal({ id: "services-before", method: "GET", url: SERVICES_URL });
    const enabled = new Set((services?.json?.services ?? []).map((s) => s.config?.name));
    out.servicesMissing = REQUIRED_SERVICES.filter((id) => !enabled.has(id));
    enabledBefore = [...enabled].toSorted();
    if (!(services?.status === 200 && readable(services)) || out.servicesMissing.length > 0)
      return "services";
    iamBefore = await read({
      id: "iam-before",
      method: "POST",
      url: `https://cloudresourcemanager.googleapis.com/v1/projects/${PROJECT}:getIamPolicy`,
      json: {},
    });
    const sdk = await read(
      {
        id: "admin-sdk-config",
        method: "GET",
        url: `https://firebase.googleapis.com/v1beta1/projects/${PROJECT}/adminSdkConfig`,
      },
      { observe: true },
    );
    if (!(sdk?.status === 200 && readable(sdk)) || typeof sdk.json.storageBucket !== "string")
      return "admin-sdk-config";
    bucket = sdk.json.storageBucket;
    if (![`${PROJECT}.firebasestorage.app`, `${PROJECT}.appspot.com`].includes(bucket))
      return "bucket-name";
    out.bucket = bucket;
    const app = await read(
      {
        id: "appengine-app",
        method: "GET",
        url: `https://appengine.googleapis.com/v1/apps/${PROJECT}`,
      },
      { observe: true },
    );
    out.appEngine = { status: app?.status ?? null };
    // Cloud Scheduler needs the project's App Engine app. When there is none (an own 404 NOT_FOUND), the run creates it
    // after every other check has passed (owner ledger 2226): an irreversible change that stays afterwards.
    if (absent(app)) out.appEngine.missing = true;
    else if (app?.status !== 200) return "appengine";
    const bucketRead = await read(
      { id: "bucket", method: "GET", url: `https://storage.googleapis.com/storage/v1/b/${bucket}` },
      { observe: true },
    );
    if (bucketRead?.status !== 200) return "bucket";
    const before = await functionLists("preflight");
    if (!complete(before)) return "lists";
    const jobs = await list("preflight-jobs", SCHEDULER + "?pageSize=500", "jobs");
    const queues = await list("preflight-queues", TASKS + "?pageSize=500", "queues");
    const topics = await list(
      "preflight-topics",
      `https://pubsub.googleapis.com/v1/projects/${PROJECT}/topics?pageSize=1000`,
      "topics",
    );
    const subs = await list(
      "preflight-subscriptions",
      `https://pubsub.googleapis.com/v1/projects/${PROJECT}/subscriptions?pageSize=1000`,
      "subscriptions",
    );
    const triggers = await list(
      "preflight-triggers",
      `https://eventarc.googleapis.com/v1/projects/${PROJECT}/locations/-/triggers`,
      "triggers",
    );
    const channels = await list(
      "preflight-channels",
      `https://eventarc.googleapis.com/v1/projects/${PROJECT}/locations/${REGION}/channels`,
      "channels",
    );
    const packages = await list("preflight-packages", REGISTRY + "?pageSize=100", "packages");
    const objects = await list(
      "preflight-objects",
      `https://storage.googleapis.com/storage/v1/b/${bucket}/o?prefix=pycheck%2F&versions=true`,
      "items",
    );
    const documents = await list(
      "preflight-documents",
      `https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents/${COLLECTION}?pageSize=100`,
      "documents",
    );
    if (
      ![jobs, queues, topics, subs, triggers, channels, packages, objects, documents].every(Boolean)
    )
      return "lists";
    out.inventory.before = {
      channels: channels.channels.map((c) => lastSegment(c.name)),
      triggers: triggers.triggers.length,
      packages: packages.packages.length,
      subscriptions: subs.subscriptions.length,
    };
    sourceObjectsBefore = await sourceObjects("preflight");
    const ownJobs = jobs.jobs.some((j) => JOB_IDS.includes(lastSegment(j.name)));
    const ownQueues = queues.queues.some((qe) => QUEUE_IDS.includes(lastSegment(qe.name)));
    const ownTopic = topics.topics.some((t) => lastSegment(t.name) === TOPIC);
    const ownPackagesPresent = packages.packages.some((p) =>
      ownPackages().includes(lastSegment(p.name)),
    );
    const ownTriggers = triggers.triggers.some((t) =>
      ALL_FUNCTIONS.some((fn) => String(t.name).includes("/" + fn + "-")),
    );
    if (
      !nonePresent(summarize(before)) ||
      ownJobs ||
      ownQueues ||
      ownTopic ||
      ownPackagesPresent ||
      ownTriggers ||
      objects.items.length ||
      documents.documents.length
    )
      return "namespace";
    await pollLogs("preflight");
    return null;
  }

  /**
   * The object names of the two Gen2 source buckets, or null for a bucket that cannot be read to its end. A bucket that
   * does not exist reads as empty. Read-only; a 403 is data.
   */
  async function sourceObjects(prefix) {
    const found = {};
    for (const bucketName of sourceBuckets(projectNumber)) {
      const label = bucketName.startsWith("gcf-v2-uploads") ? "uploads" : "sources";
      const names = [];
      let token = "";
      found[bucketName] = null;
      for (let page = 0; page < 5; page++) {
        const answer = await read(
          {
            id: `${prefix}-source-objects-${label}${page ? "-page-" + (page + 1) : ""}`,
            method: "GET",
            url:
              `https://storage.googleapis.com/storage/v1/b/${bucketName}/o?maxResults=1000` +
              (token ? "&pageToken=" + encodeURIComponent(token) : ""),
            cleanup: stopped === "cleanup",
          },
          { observe: true },
        );
        if (absent(answer) && page === 0) {
          found[bucketName] = [];
          break;
        }
        if (!(answer?.status === 200 && readable(answer))) {
          incompleteReads.push({ id: `${prefix}-source-objects`, class: answerClass(answer) });
          break;
        }
        names.push(...(answer.json.items ?? []).map((item) => item.name));
        token = answer.json.nextPageToken ?? "";
        if (!token) {
          found[bucketName] = names.toSorted();
          break;
        }
        if (page === 4)
          incompleteReads.push({ id: `${prefix}-source-objects`, class: "more-than-five-pages" });
      }
    }
    return found;
  }

  /**
   * Creates the project's App Engine app when the preflight found none: one request, never re-sent, then the
   * operation is read until it is done and the app is read back. The app is not part of the cleanup (it cannot be
   * deleted and the owner asked to keep it). An unknown answer, or an app that cannot be read afterwards, stays
   * unconfirmed and keeps the run from closing.
   */
  async function ensureAppEngine() {
    if (!out.appEngine.missing) return true;
    const url = "https://appengine.googleapis.com/v1/apps";
    const create = await mutate({
      id: "create-appengine",
      method: "POST",
      url,
      json: { id: PROJECT, locationId: APP_ENGINE_LOCATION },
    });
    out.appEngine.createClass = answerClass(create);
    if (answerClass(create) === "4xx") return false;
    pendingCreates.set("appengine", {
      label: "appengine",
      id: "create-appengine",
      name: "apps/" + PROJECT,
      class: answerClass(create),
    });
    const operation = typeof create?.json?.name === "string" ? create.json : null;
    for (
      let poll = 1;
      operation && create.json.done !== true && poll <= wait.appEnginePolls;
      poll++
    ) {
      await pause(wait.appEngine);
      const op = await read(
        {
          id: `appengine-operation-${poll}`,
          method: "GET",
          url: `https://appengine.googleapis.com/v1/${operation.name}`,
        },
        { observe: true },
      );
      if (op?.json?.done === true) break;
    }
    const app = await read(
      { id: "settle-appengine", method: "GET", url: `${url}/${PROJECT}` },
      { observe: true },
    );
    if (app?.status !== 200 || app.json?.locationId !== APP_ENGINE_LOCATION) return false;
    confirmed.add("appengine");
    out.appEngine.created = true;
    return true;
  }

  async function setup() {
    issued.add("topic");
    await save({
      id: "issue-topic",
      state: "issued",
      kind: "topic",
      name: topicName(TOPIC),
      transport: "rest",
    });
    const answer = await mutate({ id: "create-topic", method: "PUT", url: topicUrl, json: {} });
    if (answerClass(answer) === "2xx") confirmed.add("topic");
    else {
      if (isUnknownClass(answer))
        pendingCreates.set("topic", {
          label: "topic",
          id: "create-topic",
          name: NAMES.get("topic"),
          class: answerClass(answer),
        });
      const settled = await read(
        { id: "settle-topic", method: "GET", url: topicUrl },
        { observe: true },
      );
      if (settled?.status !== 200) return false;
    }
    return true;
  }

  async function deploy() {
    for (const fn of ALL_FUNCTIONS) {
      issued.add("function-" + fn);
      cliLabels.set("function-" + fn, NAMES.get("function-" + fn));
      await save({
        id: "issue-function-" + fn,
        state: "issued",
        kind: "function",
        name: functionName(fn),
        transport: "cli",
      });
    }
    for (const id of JOB_IDS) {
      issued.add("job-" + id);
      cliLabels.set("job-" + id, NAMES.get("job-" + id));
      await save({
        id: "issue-job-" + id,
        state: "issued",
        kind: "job",
        name: jobName(id),
        transport: "cli",
      });
    }
    for (const id of QUEUE_IDS) {
      issued.add("queue-" + id);
      cliLabels.set("queue-" + id, NAMES.get("queue-" + id));
      await save({
        id: "issue-queue-" + id,
        state: "issued",
        kind: "queue",
        name: queueName(id),
        transport: "cli",
      });
    }
    created = true;
    out.cli.deploy = await cli("deploy");
    deployWrites = out.cli.deploy?.unknownWrites ?? [];
    await save({
      id: "cli-deploy",
      state: "cli-result",
      result: out.cli.deploy,
      responseAt: iso(clock()),
    });
    const polls = cliFailed(out.cli.deploy) ? 2 : wait.readyPolls;
    let found = null;
    for (let poll = 1; poll <= polls; poll++) {
      found = await functionLists("ready-" + poll);
      out.ready = complete(found) ? summarize(found) : null;
      if (out.ready && allActive(out.ready)) return true;
      if (poll < polls) await pause(wait.ready);
    }
    return false;
  }

  /** The function, job and queue readbacks: the URI and the identity the tasks need, and what the CLI made. */
  async function readbacks() {
    await pause(wait.propagation);
    const targets = {};
    for (const fn of ALL_FUNCTIONS) {
      const a = await read({
        id: "readback-function-" + fn,
        method: "GET",
        url: GCF + functionName(fn),
      });
      if (a?.status === 200 && readable(a)) {
        out.readbacks[fn] = {
          state: a.json.state ?? null,
          uri: a.json.serviceConfig?.uri ?? null,
          serviceAccount: a.json.serviceConfig?.serviceAccountEmail ?? null,
          eventTrigger: a.json.eventTrigger
            ? {
                eventType: a.json.eventTrigger.eventType ?? null,
                trigger: a.json.eventTrigger.trigger ?? null,
              }
            : null,
        };
        if (a.json.serviceConfig?.uri && a.json.serviceConfig?.serviceAccountEmail)
          targets[fn] = {
            uri: a.json.serviceConfig.uri,
            serviceAccountEmail: a.json.serviceConfig.serviceAccountEmail,
          };
      }
    }
    for (const id of JOB_IDS) {
      const a = await read({ id: "readback-job-" + id, method: "GET", url: SCHEDULER + "/" + id });
      if (a?.status === 200 && readable(a))
        out.readbacks["job-" + id] = {
          state: a.json.state ?? null,
          schedule: a.json.schedule ?? null,
          timeZone: a.json.timeZone ?? null,
          uri: a.json.httpTarget?.uri ?? null,
        };
    }
    for (const id of QUEUE_IDS) {
      const a = await read({ id: "readback-queue-" + id, method: "GET", url: TASKS + "/" + id });
      if (a?.status === 200 && readable(a))
        out.readbacks["queue-" + id] = {
          state: a.json.state ?? null,
          retryConfig: a.json.retryConfig ?? null,
        };
    }
    const triggers = await list(
      "readback-triggers",
      `https://eventarc.googleapis.com/v1/projects/${PROJECT}/locations/-/triggers`,
      "triggers",
    );
    if (triggers)
      out.readbacks.triggers = triggers.triggers.map((t) => lastSegment(t.name)).toSorted();
    return targets;
  }

  async function operate(targets) {
    const list_ = operations({ runId, bucket, targets });
    for (const op of list_) {
      if (op.needs?.length || op.request.json === undefined) {
        out.operations[op.key] = {
          sent: false,
          why: "missing " + (op.needs ?? ["body"]).join(", "),
        };
        continue;
      }
      const label = "op-" + op.key;
      if (op.key === "fs-create") issued.add("document");
      if (op.key === "st-upload") issued.add("object");
      if (op.key === "fs-create")
        await save({
          id: "issue-document",
          state: "issued",
          kind: "document",
          name: documentUrl(documentId(runId)),
          transport: "rest",
        });
      if (op.key === "st-upload")
        await save({
          id: "issue-object",
          state: "issued",
          kind: "object",
          name: objectName(runId),
          transport: "rest",
        });
      const answer = await mutate({ id: label, ...op.request });
      sent[op.key] = { class: answerClass(answer), status: answer?.status ?? null };
      out.operations[op.key] = { sent: true, ...sent[op.key] };
      if (op.key === "fs-create" && answerClass(answer) === "2xx") confirmed.add("document");
      if (op.key === "st-upload" && answerClass(answer) === "2xx") confirmed.add("object");
      if (isUnknownClass(answer) && (op.key === "fs-create" || op.key === "st-upload"))
        pendingCreates.set(op.key, {
          label: op.key === "fs-create" ? "document" : "object",
          id: label,
          name: op.key,
          class: answerClass(answer),
        });
      await pause(wait.gap);
    }
  }

  const expectedFrames = () => {
    const counts_ = {};
    for (const op of operations({
      runId,
      bucket,
      targets: Object.fromEntries(
        ALL_FUNCTIONS.map((fn) => [
          fn,
          { uri: "https://x.run.app", serviceAccountEmail: "a@b.gserviceaccount.com" },
        ]),
      ),
    })) {
      if (!sent[op.key]) continue;
      // Only the raw twins are waited for: they record the delivery before the SDK parses it, so a delivery that happened
      // always shows there, while an SDK function may refuse its event (the whole-second time) and print nothing.
      for (const fn of op.reaches.filter((name) => name.endsWith("raw")))
        counts_[fn] = (counts_[fn] ?? 0) + 1;
    }
    return counts_;
  };
  const framesSeenOf = () => {
    const seen = {};
    for (const { frame } of allFrames) seen[frame.function] = (seen[frame.function] ?? 0) + 1;
    return seen;
  };

  async function observe() {
    const want = expectedFrames();
    const steps = Math.max(1, Math.ceil(wait.window / wait.logPoll));
    for (let step = 1; step <= steps; step++) {
      await pause(Math.min(wait.logPoll, wait.window - (step - 1) * wait.logPoll));
      await pollLogs("observe-" + step);
      const seen = framesSeenOf();
      if (Object.entries(want).every(([fn, n]) => (seen[fn] ?? 0) >= n)) break;
    }
  }

  // ---- cleanup ----------------------------------------------------------------------------------
  async function cliDelete() {
    if (cliDeleteStarted) return;
    cliDeleteStarted = true;
    out.cli.delete = await cli("delete");
    await save({
      id: "cli-delete",
      state: "cli-result",
      result: out.cli.delete,
      responseAt: iso(clock()),
    });
  }

  async function cleanup() {
    stopped = "cleanup";
    const step = async (name, fn) => {
      try {
        return await fn();
      } catch (error) {
        if (error instanceof AuthStop) throw error;
        (out.cleanup.errors ??= []).push({ step: name, message: String(error?.message) });
        out.cleanup.error ??= String(error?.message);
        return undefined;
      }
    };
    // The sources first: the document and the object are the run's, deleted once each by their own request.
    if (bucket !== null) {
      for (const op of undoOperations({ runId, bucket })) {
        const label = op.key === "fs-delete" ? "document" : "object";
        if (!issued.has(label)) continue;
        await step(op.key, async () => {
          const answer = await mutate({ id: "cleanup-" + op.key, ...op.request, cleanup: true });
          if (answerClass(answer) === "2xx") ownDeleted.add(label);
        });
      }
    }
    let found = null;
    const settled = () => complete(found ?? {}) && nonePresent(summarize(found));
    // The CLI delete is for what the CLI deploy may have created; before the deploy there is nothing for it to delete.
    if (cliLabels.size > 0) await step("cli-delete", () => cliDelete());
    await step("project-lists", async () => {
      for (let poll = 1; poll <= 6; poll++) {
        found = await functionLists("cleanup-" + poll);
        if (settled()) break;
        await pause(wait.settle);
      }
    });
    if (complete(found ?? {})) {
      const left = summarize(found);
      for (const fn of ALL_FUNCTIONS) {
        if (!left[fn].present) continue;
        await step("leftover-" + fn, async () => {
          const answer = await mutate({
            id: "leftover-delete-" + fn,
            method: "DELETE",
            url: GCF + functionName(fn),
            cleanup: true,
          });
          if (answerClass(answer) !== "2xx") return;
          const finished = (op) => op?.json?.done === true && !op.json.error;
          let settledBy = finished(answer);
          let pending = "operation-pending";
          if (!settledBy && typeof answer.json?.name === "string" && !answer.json.done) {
            for (let poll = 0; poll < 12; poll++) {
              await pause(10);
              const op = await read(
                {
                  id: `leftover-operation-${fn}-${poll + 1}`,
                  method: "GET",
                  url: GCF + answer.json.name,
                  cleanup: true,
                },
                { observe: true },
              );
              if (op?.json?.done === true) {
                settledBy = finished(op);
                if (!settledBy) pending = "operation-error";
                break;
              }
            }
          } else if (!settledBy && answer.json?.done === true) pending = "operation-error";
          if (settledBy) ownDeleted.add("function-" + fn);
          else unknownMutations.push({ id: "leftover-delete-" + fn, class: pending });
        });
      }
      await step("after-leftovers", async () => {
        for (let poll = 1; poll <= 4; poll++) {
          found = await functionLists("after-leftovers-" + poll);
          if (settled()) break;
          await pause(wait.settle);
        }
      });
    }
    out.cleanup.functionsGone = Boolean(settled());
    // The jobs and queues the CLI makes: a leftover is deleted once, after a fresh list shows it (a busy job waits).
    const jobsLeft = await step("jobs-list", () =>
      list("cleanup-jobs", SCHEDULER + "?pageSize=500", "jobs"),
    );
    for (const j of jobsLeft?.jobs ?? []) {
      const id = lastSegment(j.name);
      if (!JOB_IDS.includes(id)) continue;
      await step("job-" + id, async () => {
        for (let attempt = 0; attempt < 4; attempt++) {
          const answer = await mutate({
            id: `delete-job-${attempt}-${id}`,
            method: "DELETE",
            url: SCHEDULER + "/" + id,
            cleanup: true,
          });
          if (answerClass(answer) === "2xx") return void ownDeleted.add("job-" + id);
          if (isBusy(answer)) await pause(wait.busy);
          else return;
        }
      });
    }
    const queuesLeft = await step("queues-list", () =>
      list("cleanup-queues", TASKS + "?pageSize=500", "queues"),
    );
    for (const qe of queuesLeft?.queues ?? []) {
      const id = lastSegment(qe.name);
      if (!QUEUE_IDS.includes(id)) continue;
      await step("queue-" + id, async () => {
        const answer = await mutate({
          id: "delete-queue-" + id,
          method: "DELETE",
          url: TASKS + "/" + id,
          cleanup: true,
        });
        if (answerClass(answer) === "2xx") ownDeleted.add("queue-" + id);
      });
    }
    // The topic, once its functions are gone (Eventarc deletes its own subscriptions with the triggers).
    if (out.cleanup.functionsGone && issued.has("topic")) {
      await step("topic", async () => {
        const present = await read(
          { id: "topic-present", method: "GET", url: topicUrl, cleanup: true },
          { observe: true },
        );
        if (present?.status !== 200) return;
        const answer = await mutate({
          id: "delete-topic",
          method: "DELETE",
          url: topicUrl,
          cleanup: true,
        });
        if (answerClass(answer) === "2xx") ownDeleted.add("topic");
      });
    }
    // The images the deploy left in Artifact Registry: this run's own packages, found by a fresh list, deleted once.
    const packagesFound = await step("packages-list", () =>
      list("cleanup-packages", REGISTRY + "?pageSize=100", "packages"),
    );
    out.cleanup.packagesDeleted = [];
    for (const item of packagesFound?.packages ?? []) {
      const id = lastSegment(item.name);
      if (!ownPackages().includes(id)) continue;
      await step("package-" + id, async () => {
        const answer = await mutate({
          id: "delete-package-" + id,
          method: "DELETE",
          url: REGISTRY + "/" + id,
          cleanup: true,
        });
        out.cleanup.packagesDeleted.push({
          id,
          class: answerClass(answer),
          status: answer?.status ?? null,
        });
        if (
          answerClass(answer) === "2xx" &&
          typeof answer.json?.name === "string" &&
          answer.json.done !== true
        ) {
          for (let poll = 0; poll < 6; poll++) {
            await pause(10);
            const op = await read(
              {
                id: `package-operation-${id}-${poll + 1}`,
                method: "GET",
                url: "https://artifactregistry.googleapis.com/v1/" + answer.json.name,
                cleanup: true,
              },
              { observe: true },
            );
            if (op?.json?.done === true) break;
          }
        }
      });
    }
    // The deployment's own new objects in the two Gen2 source buckets: found by diffing a fresh list with the preflight's,
    // each deleted once by its exact name, then read back with the other names.
    out.cleanup.sourceObjectsDeleted = [];
    out.cleanup.sourceObjectsSkipped = [];
    await step("source-objects-delete", async () => {
      const now = await sourceObjects("cleanup");
      let n = 0;
      for (const bucketName of sourceBuckets(projectNumber)) {
        const before = sourceObjectsBefore?.[bucketName];
        if (!Array.isArray(before) || !Array.isArray(now[bucketName])) continue;
        for (const name of now[bucketName].filter((x) => !before.includes(x))) {
          if (!isOwnSourceObject(projectNumber, bucketName, name)) {
            out.cleanup.sourceObjectsSkipped.push({ bucket: bucketName, name });
            continue;
          }
          guard.adoptObject(bucketName, name);
          const answer = await mutate({
            id: `delete-source-object-${++n}`,
            method: "DELETE",
            url: `https://storage.googleapis.com/storage/v1/b/${bucketName}/o/${encodeURIComponent(name)}`,
            cleanup: true,
          });
          out.cleanup.sourceObjectsDeleted.push({
            bucket: bucketName,
            name,
            class: answerClass(answer),
            status: answer?.status ?? null,
          });
        }
      }
    });
    // Read every name back directly. Only a direct read of an absence counts; a name that was not read is not absent.
    const names = [
      ...ALL_FUNCTIONS.map((fn) => ["function-" + fn, GCF + functionName(fn)]),
      ...JOB_IDS.map((id) => ["job-" + id, SCHEDULER + "/" + id]),
      ...QUEUE_IDS.map((id) => ["queue-" + id, TASKS + "/" + id]),
      ["topic", topicUrl],
      ["document", documentUrl(documentId(runId))],
      ["object", bucket ? storageObjectUrl(bucket, objectName(runId)) : null],
      ...ALL_FUNCTIONS.flatMap(packageIds).map((id) => ["package-" + id, REGISTRY + "/" + id]),
      ...out.cleanup.sourceObjectsDeleted.map((item, index) => [
        "source-object-" + (index + 1),
        `https://storage.googleapis.com/storage/v1/b/${item.bucket}/o/${encodeURIComponent(item.name)}`,
      ]),
    ].filter(([, url]) => url !== null);
    const readBack = Object.fromEntries(names.map(([label]) => [label, false]));
    out.cleanup.readBack = readBack;
    for (const [label, url] of names) {
      await step("readback-" + label, async () => {
        const answer = await read(
          { id: "readback-gone-" + label, method: "GET", url, cleanup: true },
          { observe: true },
        );
        readBack[label] = absent(answer);
      });
    }
    out.cleanup.listsEmpty = false;
    await step("final-lists", async () => {
      const jobs = await list("final-jobs", SCHEDULER + "?pageSize=500", "jobs");
      const queues = await list("final-queues", TASKS + "?pageSize=500", "queues");
      const topics = await list(
        "final-topics",
        `https://pubsub.googleapis.com/v1/projects/${PROJECT}/topics?pageSize=1000`,
        "topics",
      );
      const subs = await list(
        "final-subscriptions",
        `https://pubsub.googleapis.com/v1/projects/${PROJECT}/subscriptions?pageSize=1000`,
        "subscriptions",
      );
      const triggers = await list(
        "final-triggers",
        `https://eventarc.googleapis.com/v1/projects/${PROJECT}/locations/-/triggers`,
        "triggers",
      );
      const packages = await list("final-packages", REGISTRY + "?pageSize=100", "packages");
      const fns = await functionLists("final");
      out.cleanup.listsEmpty =
        Boolean(jobs && queues && topics && subs && triggers && packages && complete(fns)) &&
        !jobs.jobs.some((x) => JOB_IDS.includes(lastSegment(x.name))) &&
        !queues.queues.some((x) => QUEUE_IDS.includes(lastSegment(x.name))) &&
        !topics.topics.some((x) => lastSegment(x.name) === TOPIC) &&
        subs.subscriptions.length === (out.inventory.before?.subscriptions ?? 0) &&
        !triggers.triggers.some((t) =>
          ALL_FUNCTIONS.some((fn) => String(t.name).includes("/" + fn + "-")),
        ) &&
        !packages.packages.some((x) => ownPackages().includes(lastSegment(x.name))) &&
        nonePresent(summarize(fns));
    });
    out.cleanup.verified =
      out.cleanup.listsEmpty &&
      out.cleanup.sourceObjectsSkipped.length === 0 &&
      Object.values(readBack).every((v) => v === true);
    // Read-only inventory: what the deploy left that this recorder does not delete, and what it changed.
    await step("source-objects", async () => {
      const after = await sourceObjects("inventory");
      out.inventory.sourceObjects = Object.fromEntries(
        sourceBuckets(projectNumber).map((name, index) => {
          const before = sourceObjectsBefore?.[name];
          const now = after[name];
          return [
            index === 0 ? "uploads" : "sources",
            Array.isArray(before) && Array.isArray(now)
              ? {
                  added: now.filter((n) => !before.includes(n)),
                  removed: before.filter((n) => !now.includes(n)),
                }
              : null,
          ];
        }),
      );
    });
    await step("inventory", async () => {
      const channels = await list(
        "inventory-channels",
        `https://eventarc.googleapis.com/v1/projects/${PROJECT}/locations/${REGION}/channels`,
        "channels",
      );
      out.inventory.channelsAfter = channels
        ? channels.channels.map((c) => lastSegment(c.name))
        : null;
      const iamAfter = await read({
        id: "iam-after",
        method: "POST",
        url: `https://cloudresourcemanager.googleapis.com/v1/projects/${PROJECT}:getIamPolicy`,
        json: {},
        cleanup: true,
      });
      out.inventory.iam = iamChanges(iamBefore, iamAfter);
      const after = await read({
        id: "services-after",
        method: "GET",
        url: SERVICES_URL,
        cleanup: true,
      });
      const names_ = new Set((after?.json?.services ?? []).map((svc) => svc.config?.name));
      out.inventory.services =
        after?.status === 200 && readable(after) && enabledBefore
          ? {
              added: [...names_].filter((n) => !enabledBefore.includes(n)).toSorted(),
              removed: enabledBefore.filter((n) => !names_.has(n)),
            }
          : null;
    });
    await step("final-logs", async () => {
      await pause(wait.logDelay);
      await pollLogs("final", { final: true });
    });
  }

  const authStopped = async () => {
    if (created) {
      try {
        await cliDelete();
      } catch {
        // recorded as an unknown CLI answer; nothing more to do without a credential
      }
    }
    return summary("auth-stop", false);
  };
  let operated = false;
  try {
    const problem = await preflight();
    if (problem) {
      out.outcome = "pycheck-stopped-clean";
      out.stoppedBecause = problem;
      return summary("preflight", false);
    }
    out.stage = "dry-run";
    out.cli.dryRun = await cli("dry-run");
    await save({
      id: "cli-dry-run",
      state: "cli-result",
      result: out.cli.dryRun,
      responseAt: iso(clock()),
    });
    if (cliFailed(out.cli.dryRun)) {
      out.outcome = "pycheck-stopped-clean";
      out.stoppedBecause = "the CLI dry run failed";
      return summary("dry-run", false);
    }
    out.stage = "app-engine";
    if (!(await ensureAppEngine())) {
      out.stoppedBecause = "appengine";
      out.outcome = open().blocked ? "pycheck-needs-review" : "pycheck-stopped-clean";
      return summary("app-engine", false);
    }
    out.stage = "setup";
    // The topic is created before the topic is used; a failed create is a clean stop only if nothing was created.
    const topicReady = await setup();
    if (!topicReady) {
      out.stoppedBecause = "the topic could not be created";
      created = issued.has("topic");
    } else {
      out.stage = "deploy";
      const ready = await deploy();
      if (ready) {
        out.stage = "readbacks";
        const targets = await readbacks();
        out.stage = "operations";
        operated = true;
        await operate(targets);
        out.stage = "observe";
        await observe();
      }
    }
  } catch (error) {
    if (error instanceof AuthStop) return authStopped();
    if (!(error instanceof BudgetError)) {
      out.stoppedBecause = String(error?.message);
      if (!created && !issued.size) throw error;
    } else out.stoppedBecause = error.message;
  }
  if (created || issued.size) {
    try {
      out.stage = "cleanup";
      await cleanup();
    } catch (error) {
      if (!(error instanceof AuthStop)) throw error;
      return authStopped();
    }
  }
  for (const entry of allFrames)
    out.frames[entry.frame.function] = (out.frames[entry.frame.function] ?? 0) + 1;
  out.errorsSeen = allErrors.length;
  out.judged = judge({ runId, frames: allFrames, errors: allErrors, sent, mode: "production" });
  const completeRun = operated && !out.stoppedBecause && Object.keys(out.operations).length > 0;
  out.outcome =
    !created && !issued.size
      ? "pycheck-stopped-clean"
      : !out.cleanup.verified
        ? "pycheck-needs-recovery"
        : open().blocked || out.cleanup.errors
          ? "pycheck-needs-review"
          : completeRun
            ? "pycheck-recorded"
            : "pycheck-incomplete-clean";
  out.stage = "done";
  return summary("done", out.cleanup.verified && completeRun && !out.cleanup.errors);
}
