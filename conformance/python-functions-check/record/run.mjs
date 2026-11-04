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
  inventoryDifferences,
  iamUnexpected,
  nonePresent,
  putClass,
  summarize,
} from "./deploy.mjs";
import { createGuard, ownPackages, withoutPublicMember } from "./guard.mjs";
import { judge } from "./judge.mjs";
import { errorFilter, frameFilter, listRequest, parseErrors, parseFrames } from "./logs.mjs";
import {
  ALL_FUNCTIONS,
  CHANNEL,
  COLLECTION,
  DELIVERY_WINDOW_SECONDS,
  JOB_IDS,
  LOG_DELAY_SECONDS,
  PROJECT,
  PROPAGATION_WAIT_SECONDS,
  QUEUE_IDS,
  REGION,
  ENABLE_SERVICES,
  REQUIRED_SERVICES,
  isOwnUploadObject,
  sourceBuckets,
  uploadBucket,
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
  return iamKeyChanges(iamKeys(before), iamKeys(after));
}

/** The `role|member` keys of a policy read (sorted), or `null` when the read is not a readable policy. */
export function iamKeys(answer) {
  return answer?.status === 200 && readable(answer)
    ? [
        ...new Set(
          (answer.json.bindings ?? []).flatMap((b) =>
            (b.members ?? []).map((m) => b.role + "|" + m),
          ),
        ),
      ].toSorted()
    : null;
}

/** The keys added and removed between two sorted key lists, or `null` when either is missing. */
export function iamKeyChanges(before, after) {
  if (!Array.isArray(before) || !Array.isArray(after)) return null;
  return {
    added: after.filter((k) => !before.includes(k)).toSorted(),
    removed: before.filter((k) => !after.includes(k)).toSorted(),
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
    enable: 10,
    enablePolls: 30,
    listAttempts: 10,
    listRetry: 30,
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
  let servicesToEnable = [];
  let sourceObjectsBefore = null;
  let cliDeleteStarted = false;

  // ---- request helpers -------------------------------------------------------------------------
  const normal = async (spec) => {
    if (signal.aborted && !spec.cleanup) throw new BudgetError("stopped by a signal");
    if (counts().attempted >= normalCeiling && !spec.cleanup)
      throw new BudgetError("the normal request ceiling is reached");
    await prepareRequest?.(spec);
    const answer = await capture(spec);
    // A 200, 201 or 202 whose JSON body does not parse says nothing about the effect: it is an unknown answer. An empty
    // 204 is a complete answer.
    if (
      answer &&
      !answer.bodyUnknown &&
      [200, 201, 202].includes(answer.status) &&
      (answer.json === null || answer.json === undefined)
    )
      answer.bodyUnknown = true;
    return answer;
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
    // Every mutating request the CLI sent (from its --debug output) is journaled; one that was retried, unanswered or not
    // answered 2xx is an unknown write that only A2 can close (coordinator ruling R1). firebase-tools' own retries are
    // accepted as CLI behaviour; the at-most-once rule is the recorder's own requests and one CLI call per action. The
    // shared parser's own list (`unknownWrites`) is an unknown write for every action too.
    let ambiguous = null;
    for (const [n, write] of (Array.isArray(result?.unknownWrites)
      ? result.unknownWrites
      : []
    ).entries())
      unknownMutations.push({
        id: `cli-${action}-unknown-write-${n + 1}`,
        class: "cli-unknown-write",
        request: `${write?.method} ${write?.host} ${write?.status}`,
      });
    if (action !== "dry-run" || Array.isArray(result?.cliWrites)) {
      if (!Array.isArray(result?.cliWrites)) {
        ambiguous ??= "cli-log-unreadable";
        unknownMutations.push({ id: "cli-" + action, class: "cli-log-unreadable" });
      } else {
        let n = 0;
        for (const write of result.cliWrites) {
          n += 1;
          try {
            await save({ id: `cli-${action}-write-${n}`, state: "cli-write", action, ...write });
          } catch {
            // A row that could not be journaled is a write nobody can judge afterwards: it stays an open obligation
            // (never closureReady) until a read-back and the coordinator settle it.
            unknownMutations.push({
              id: `cli-${action}-write-${n}`,
              class: "cli-write-unjournaled",
              request: `${write.method} ${write.url}`,
            });
            ambiguous ??= "cli-write-unjournaled";
          }
          if (write.class !== "ok") {
            ambiguous ??= `cli-write-${write.class}`;
            unknownMutations.push({
              id: `cli-${action}-write-${n}`,
              class: `cli-write-${write.class}`,
              request: `${write.method} ${write.url}`,
            });
          }
        }
      }
    }
    // A deploy write that was retried, unanswered, not answered 2xx, not journaled or not readable may have created any
    // name of the deploy whatever the reads show afterwards: every one of them stays an unconfirmed create until an own
    // 2xx read shows it (a 404 never settles it).
    if (action === "deploy" && ambiguous) deployUnknown ??= ambiguous;
    return result;
  };
  const uploadUnconfirmed = [];
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
    ...uploadUnconfirmed,
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
        vanished.length > 0 ||
        out.cleanup.uploadReasons?.length > 0 ||
        out.cleanup.uploadObjectsUnexplained?.length > 0 ||
        out.inventory.differences?.length > 0 ||
        out.inventory.complete === false,
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
    // The project's identity is the recorded read of this project (a 200 with its id, number and an ACTIVE state). The
    // number it returns must be the one the caller named: that number names the buckets whose objects get deleted.
    const project = await normal({
      id: "identity",
      method: "GET",
      url: `https://cloudresourcemanager.googleapis.com/v1/projects/${PROJECT}`,
    });
    if (
      !(project?.status === 200 && readable(project)) ||
      project.json.projectId !== PROJECT ||
      project.json.lifecycleState !== "ACTIVE"
    )
      return "identity";
    if (String(project.json.projectNumber) !== String(projectNumber)) return "project-number";
    // The enabled services are read page by page: a project can have more than one page of them.
    const services = await list("services-before", SERVICES_URL, "services");
    const enabled = new Set((services?.services ?? []).map((s) => s.config?.name));
    out.servicesMissing = REQUIRED_SERVICES.filter((id) => !enabled.has(id));
    servicesToEnable = ENABLE_SERVICES.filter((id) => !enabled.has(id));
    enabledBefore = [...enabled].toSorted();
    if (services === null || out.servicesMissing.length > 0) return "services";
    iamBefore = await read({
      id: "iam-before",
      method: "POST",
      url: `https://cloudresourcemanager.googleapis.com/v1/projects/${PROJECT}:getIamPolicy`,
      json: {},
    });
    // The project IAM is part of the baseline every closure compares with: a policy that cannot be read stops the run
    // before anything is enabled or created.
    if (iamKeys(iamBefore) === null) return "iam";
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
    // Cloud Scheduler needs no App Engine app here (sbx delivered with none): the run never creates one and only records
    // what it finds.
    const app = await read(
      {
        id: "appengine-app",
        method: "GET",
        url: `https://appengine.googleapis.com/v1/apps/${PROJECT}`,
      },
      { observe: true },
    );
    out.appEngine = { status: app?.status ?? null, present: app?.status === 200 };
    const bucketRead = await read(
      { id: "bucket", method: "GET", url: `https://storage.googleapis.com/storage/v1/b/${bucket}` },
      { observe: true },
    );
    if (bucketRead?.status !== 200) return "bucket";
    const before = await functionLists("preflight");
    if (!complete(before)) return "lists";
    // Cloud Scheduler and Cloud Tasks may be disabled here: a request that carries the quota project is refused with 403
    // SERVICE_DISABLED until the API is on, so their lists are read after the enable (below), not here.
    const notifications = await list(
      "preflight-notifications",
      `https://storage.googleapis.com/storage/v1/b/${bucket}/notificationConfigs`,
      "items",
    );
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
      ![notifications, topics, subs, triggers, channels, packages, objects, documents].every(
        Boolean,
      )
    )
      return "lists";
    const names = (items) => items.map((item) => item.name).toSorted();
    out.inventory.before = {
      channels: channels.channels.map((c) => lastSegment(c.name)).toSorted(),
      triggers: names(triggers.triggers),
      packages: names(packages.packages),
      subscriptions: names(subs.subscriptions),
      topics: names(topics.topics),
      services: enabledBefore,
      iam: iamKeys(iamBefore),
      notifications: notifications.items.map((item) => item.id).toSorted(),
    };
    // The inventory every closure compares against must be complete: a bucket that cannot be listed to its end stops the run
    // before anything is enabled or created.
    sourceObjectsBefore = await sourceObjects("preflight");
    if (Object.values(sourceObjectsBefore).some((listed) => !Array.isArray(listed)))
      return "source-buckets";
    out.inventory.before.sourceObjects = {
      uploads: sourceObjectsBefore[sourceBuckets(projectNumber)[0]],
      sources: sourceObjectsBefore[sourceBuckets(projectNumber)[1]],
    };
    const ownTopic = topics.topics.some((t) => lastSegment(t.name) === TOPIC);
    const ownPackagesPresent = packages.packages.some((p) =>
      ownPackages().includes(lastSegment(p.name)),
    );
    const ownTriggers = triggers.triggers.some((t) =>
      ALL_FUNCTIONS.some((fn) => String(t.name).includes("/" + fn + "-")),
    );
    if (
      !nonePresent(summarize(before)) ||
      ownTopic ||
      ownPackagesPresent ||
      ownTriggers ||
      objects.items.length ||
      documents.documents.length
    )
      return "namespace";
    // The CLI creates the Eventarc channel `firebase` when it is missing. If it is missing now, the run owns what the CLI
    // makes: the cleanup deletes the channel once and reads it back (coordinator ruling R6).
    out.channel = { ownedByRun: !out.inventory.before.channels.includes(CHANNEL) };
    await pollLogs("preflight");
    // Every read-only check must have passed before anything is enabled (coordinator ruling R5): a read that failed (an
    // unknown answer, a 4xx or 5xx on a baseline, a log poll that gave no entries list) stops the run here.
    if (incompleteReads.length > 0 || counts().unknown > 0) return "preflight-reads";
    if (!(await enableServices())) return "enable-services";
    // The two lists that could not be read before the enable: read now, with bounded retries while the enable propagates,
    // and checked for the run's own names before the dry run.
    const jobs = await listAfterEnable("preflight-jobs", SCHEDULER + "?pageSize=500", "jobs");
    if (!jobs) return "lists-after-enable";
    const queues = await listAfterEnable("preflight-queues", TASKS + "?pageSize=500", "queues");
    if (!queues) return "lists-after-enable";
    if (
      jobs.jobs.some((j) => JOB_IDS.includes(lastSegment(j.name))) ||
      queues.queues.some((qe) => QUEUE_IDS.includes(lastSegment(qe.name)))
    )
      return "namespace";
    return null;
  }

  const SERVICE_DISABLED = Symbol("service-disabled");
  /** One read of a list in observe mode: the list, `SERVICE_DISABLED` for a 403 of that reason, or null (recorded as incomplete). */
  async function listObserved(id, name, url, key) {
    const items = [];
    let token = "";
    for (let page = 0; page < 5; page++) {
      const answer = await read(
        {
          id: name + (page ? "-page-" + (page + 1) : ""),
          method: "GET",
          url:
            url +
            (token
              ? (url.includes("?") ? "&" : "?") + "pageToken=" + encodeURIComponent(token)
              : ""),
        },
        { observe: true },
      );
      if (
        answer?.status === 403 &&
        readable(answer) &&
        Array.isArray(answer.json.error?.details) &&
        answer.json.error.details.some((d) => d?.reason === "SERVICE_DISABLED")
      )
        return SERVICE_DISABLED;
      if (!(answer?.status === 200 && readable(answer))) {
        incompleteReads.push({ id, class: answerClass(answer) });
        return null;
      }
      items.push(...(answer.json[key] ?? []));
      token = answer.json.nextPageToken ?? "";
      if (!token) return { [key]: items };
    }
    incompleteReads.push({ id, class: "more-than-five-pages" });
    return null;
  }

  /**
   * A list of an API the run has just enabled, read in observe mode: Google answers a request for an API that is not on
   * (or not yet propagated) with 403 SERVICE_DISABLED, which is data here, not an authorization stop. It is read again
   * after `listRetry` seconds, up to `listAttempts` times; any other failure, or a 403 that stays, gives null.
   */
  async function listAfterEnable(id, url, key) {
    for (let attempt = 1; attempt <= wait.listAttempts; attempt++) {
      const found = await listObserved(id, attempt > 1 ? id + "-attempt-" + attempt : id, url, key);
      if (found !== SERVICE_DISABLED) return found;
      if (attempt < wait.listAttempts) await pause(wait.listRetry);
    }
    incompleteReads.push({ id, class: "service-disabled" });
    return null;
  }

  /**
   * Enables exactly the missing ones of the two services this project lacks (coordinator ruling R5), once, after every
   * read-only check passed; reads the operation until it is done and the services list until they show. They stay enabled.
   * An unknown answer is sticky and stops the run.
   */
  async function enableServices() {
    out.servicesEnabled = [];
    if (servicesToEnable.length === 0) return true;
    const answer = await mutate({
      id: "enable-services",
      method: "POST",
      url: `https://serviceusage.googleapis.com/v1/projects/${projectNumber}/services:batchEnable`,
      json: { serviceIds: servicesToEnable },
    });
    out.enable = { serviceIds: servicesToEnable, class: answerClass(answer) };
    if (answerClass(answer) !== "2xx") return false;
    for (
      let poll = 1;
      typeof answer.json?.name === "string" &&
      answer.json.done !== true &&
      poll <= wait.enablePolls;
      poll++
    ) {
      await pause(wait.enable);
      const op = await read(
        {
          id: `enable-operation-${poll}`,
          method: "GET",
          url: `https://serviceusage.googleapis.com/v1/${answer.json.name}`,
        },
        { observe: true },
      );
      if (op?.json?.done === true) break;
    }
    const after = await list("services-after-enable", SERVICES_URL, "services");
    if (after === null) return false;
    const now = new Set(after.services.map((svc) => svc.config?.name));
    out.servicesEnabled = servicesToEnable.filter((id) => now.has(id));
    return out.servicesEnabled.length === servicesToEnable.length;
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
      if (isUnknownClass(answer) && (op.key === "fs-create" || op.key === "st-upload")) {
        const kind = op.key === "fs-create" ? "document" : "object";
        pendingCreates.set(op.key, {
          label: kind,
          id: label,
          name: op.key,
          class: answerClass(answer),
        });
        // An unknown create is settled only by an own read that shows the name (a 404 never settles it).
        const settle = await read(
          {
            id: "settle-" + kind,
            method: "GET",
            url:
              kind === "document"
                ? documentUrl(documentId(runId))
                : storageObjectUrl(bucket, objectName(runId)),
          },
          { observe: true },
        );
        if (settle?.status === 200 && readable(settle)) confirmed.add(kind);
      }
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
    // The CLI gives every HTTP, callable and blocking function's Cloud Run service a public invoker (`allUsers` with
    // `roles/run.invoker`). Each service of the run is read, and that member alone is removed (one write, never re-sent)
    // and read back, before the function is deleted: a delete that fails must not leave a public service. The result
    // keeps what was found, so the check of what the CLI adds is in the recording.
    out.cleanup.invoker = {};
    if (cliLabels.size > 0)
      await step("invoker-removal", async () => {
        const listed = await functionLists("cleanup-invoker");
        const present = new Set((listed.run?.services ?? []).map((svc) => lastSegment(svc.name)));
        for (const fn of ALL_FUNCTIONS.filter((name) => present.has(name))) {
          const url = `https://run.googleapis.com/v2/projects/${PROJECT}/locations/${REGION}/services/${fn}`;
          const policy = await read(
            {
              id: `cleanup-invoker-policy-${fn}`,
              method: "GET",
              url: url + ":getIamPolicy",
              cleanup: true,
            },
            { observe: true },
          );
          if (!(policy?.status === 200 && readable(policy))) {
            out.cleanup.invoker[fn] = { read: answerClass(policy) };
            continue;
          }
          const bindings = Array.isArray(policy.json.bindings) ? policy.json.bindings : [];
          const members = (b) => (Array.isArray(b?.members) ? b.members : []);
          const finding = {
            invokers: bindings
              .filter((b) => b?.role === "roles/run.invoker")
              .flatMap(members)
              .toSorted(),
            allUsers: bindings.some((b) => members(b).includes("allUsers")),
          };
          out.cleanup.invoker[fn] = finding;
          if (!finding.allUsers) continue;
          const plan = withoutPublicMember(policy.json);
          if (!plan.ok) {
            finding.refused = plan.why;
            finding.removed = false;
            continue;
          }
          const answer = await mutate({
            id: `cleanup-remove-invoker-${fn}`,
            method: "POST",
            url: url + ":setIamPolicy",
            json: { policy: plan.policy },
            cleanup: true,
          });
          finding.removeClass = answerClass(answer);
          const back = await read(
            {
              id: `cleanup-invoker-readback-${fn}`,
              method: "GET",
              url: url + ":getIamPolicy",
              cleanup: true,
            },
            { observe: true },
          );
          finding.removed =
            back?.status === 200 &&
            readable(back) &&
            !(back.json.bindings ?? []).some((b) => members(b).includes("allUsers"));
        }
      });
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
    // The deploy's own upload object: the one its generateUploadUrl answer named (read from the CLI log), deleted once by
    // generation and read back below. Any other new object in the upload bucket is reported and keeps the cleanup
    // unverified. The sources bucket (the build's copies) is left alone; the inventory below reports what it gained.
    out.cleanup.uploadObjectsDeleted = [];
    out.cleanup.uploadObjectsUnexplained = [];
    out.cleanup.uploadReasons = [];
    await step("upload-objects", async () => {
      const bucketName = uploadBucket(projectNumber);
      const reasons = out.cleanup.uploadReasons;
      const before = sourceObjectsBefore?.[bucketName];
      const deployed = out.cli.deploy;
      const receipts = new Map();
      if (deployed) {
        if (!Array.isArray(deployed.uploadEvents)) reasons.push("receipt-log-unreadable");
        for (const event of deployed.uploadEvents ?? []) {
          if (event.type === "receipt") {
            if (!isOwnUploadObject(projectNumber, event.bucket, event.object))
              reasons.push("receipt-invalid");
            else if (!receipts.has(event.object) && receipts.size < 3)
              receipts.set(event.object, []);
            else if (!receipts.has(event.object)) reasons.push("too-many-receipts");
          } else if (event.type === "put-status" && event.bucket === bucketName)
            receipts.get(event.object)?.push(event.status);
        }
        if (receipts.size === 0 && Array.isArray(deployed.uploadEvents)) {
          const ended =
            deployed.exitCode !== null && !deployed.timedOut && !deployed.signal && !deployed.error;
          if (!ended) reasons.push("killed-without-receipt");
          else if (deployed.exitCode === 0) reasons.push("no-receipt");
        }
      }
      if (!Array.isArray(before)) reasons.push("upload-baseline-unreadable");
      let n = 0;
      for (const [object, statuses] of receipts) {
        const klass = putClass(statuses);
        if (!Array.isArray(before)) break;
        if (before.includes(object)) {
          reasons.push(`receipt-names-baseline-object:${object}`);
          continue;
        }
        if (klass === "refused") continue;
        n += 1;
        guard.adoptObject(bucketName, object);
        const url = `https://storage.googleapis.com/storage/v1/b/${bucketName}/o/${encodeURIComponent(object)}`;
        const meta = await read(
          {
            id: `upload-object-${n}-metadata`,
            method: "GET",
            url: url + "?fields=bucket,name,generation",
            cleanup: true,
          },
          { observe: true },
        );
        if (absent(meta)) {
          reasons.push(
            `${klass === "confirmed" ? "confirmed-upload-absent" : "receipt-unconfirmed"}:${object}`,
          );
          continue;
        }
        const generation = String(meta?.json?.generation ?? "");
        if (
          !(meta?.status === 200 && readable(meta)) ||
          meta.json.bucket !== bucketName ||
          meta.json.name !== object ||
          !/^\d{1,20}$/.test(generation)
        ) {
          reasons.push(`object-unreadable:${object}`);
          continue;
        }
        const answer = await mutate({
          id: `delete-upload-object-${n}`,
          method: "DELETE",
          url: `${url}?ifGenerationMatch=${generation}`,
          cleanup: true,
        });
        out.cleanup.uploadObjectsDeleted.push({
          bucket: bucketName,
          name: object,
          generation,
          putStatuses: statuses,
          class: answerClass(answer),
          status: answer?.status ?? null,
        });
      }
      const now = (await sourceObjects("cleanup"))[bucketName];
      if (!Array.isArray(now) || !Array.isArray(before)) {
        reasons.push("upload-list-incomplete");
        return;
      }
      const explained = new Set(
        [...receipts]
          .filter(([, statuses]) => putClass(statuses) !== "refused")
          .map(([object]) => object),
      );
      for (const name of now)
        if (!before.includes(name) && !explained.has(name))
          out.cleanup.uploadObjectsUnexplained.push({ bucket: bucketName, name });
    });
    // An upload whose receipt was never confirmed, whose object could not be read, or that left no readable receipt is an
    // unknown create: a 404 or an unchanged inventory never settles it, and only the read-back with a positive read (or a
    // recovery) closes it.
    for (const reason of out.cleanup.uploadReasons) {
      const [kind, ...rest] = reason.split(":");
      if (
        [
          "receipt-unconfirmed",
          "object-unreadable",
          "receipt-log-unreadable",
          "killed-without-receipt",
          "no-receipt",
        ].includes(kind)
      )
        uploadUnconfirmed.push({
          label: "upload-object",
          id: "cli-deploy",
          name: rest.length > 0 ? rest.join(":") : null,
          class: kind,
        });
    }
    // The Eventarc channel `firebase`, when the CLI made it (it was not there at the preflight): deleted once after the
    // functions are gone, its operation read until done; the channel and its managed topic are read back below.
    const channelUrl = `https://eventarc.googleapis.com/v1/projects/${PROJECT}/locations/${REGION}/channels/${CHANNEL}`;
    out.cleanup.channel = { ownedByRun: out.channel?.ownedByRun === true };
    let channelTopicUrl = null;
    if (out.channel?.ownedByRun && out.cleanup.functionsGone)
      await step("channel", async () => {
        const present = await read(
          { id: "channel-present", method: "GET", url: channelUrl, cleanup: true },
          { observe: true },
        );
        if (absent(present)) return void (out.cleanup.channel.absentAlready = true);
        if (!(present?.status === 200 && readable(present))) return;
        const topic = lastSegment(present.json.pubsubTopic);
        if (/^eventarc-channel-us-central1-firebase-[0-9]+$/.test(topic)) {
          out.cleanup.channel.topic = topic;
          channelTopicUrl = `https://pubsub.googleapis.com/v1/projects/${PROJECT}/topics/${topic}`;
        }
        const answer = await mutate({
          id: "delete-channel",
          method: "DELETE",
          url: channelUrl,
          cleanup: true,
        });
        out.cleanup.channel.deleteClass = answerClass(answer);
        if (
          answerClass(answer) === "2xx" &&
          typeof answer.json?.name === "string" &&
          answer.json.done !== true
        )
          for (let poll = 1; poll <= 12; poll++) {
            await pause(10);
            const op = await read(
              {
                id: `channel-operation-${poll}`,
                method: "GET",
                url: `https://eventarc.googleapis.com/v1/${answer.json.name}`,
                cleanup: true,
              },
              { observe: true },
            );
            if (op?.json?.done === true) break;
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
      ...(out.channel?.ownedByRun ? [["channel", channelUrl]] : []),
      ...(channelTopicUrl ? [["channel-topic", channelTopicUrl]] : []),
      ...ALL_FUNCTIONS.flatMap(packageIds).map((id) => ["package-" + id, REGISTRY + "/" + id]),
      ...out.cleanup.uploadObjectsDeleted.map((item, index) => [
        "upload-object-" + (index + 1),
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
    const finalLists = {};
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
      const sorted = (listed, key) => (listed ? listed[key].map((x) => x.name).toSorted() : null);
      finalLists.topics = sorted(topics, "topics");
      finalLists.subscriptions = sorted(subs, "subscriptions");
      finalLists.triggers = sorted(triggers, "triggers");
      finalLists.packages = sorted(packages, "packages");
      out.cleanup.listsEmpty =
        Boolean(jobs && queues && topics && subs && triggers && packages && complete(fns)) &&
        !jobs.jobs.some((x) => JOB_IDS.includes(lastSegment(x.name))) &&
        !queues.queues.some((x) => QUEUE_IDS.includes(lastSegment(x.name))) &&
        !topics.topics.some((x) => lastSegment(x.name) === TOPIC) &&
        !triggers.triggers.some((t) =>
          ALL_FUNCTIONS.some((fn) => String(t.name).includes("/" + fn + "-")),
        ) &&
        !packages.packages.some((x) => ownPackages().includes(lastSegment(x.name))) &&
        nonePresent(summarize(fns));
    });
    // The inventory the run started from, compared by identity with a fresh one: the two Gen2 buckets, the channels, the
    // enabled services (only what this run enabled may have been added) and the project IAM (only service-agent additions).
    // Every difference, and every list that could not be read to its end, keeps the cleanup from being verified.
    await step("inventory", async () => {
      const channels = await list(
        "inventory-channels",
        `https://eventarc.googleapis.com/v1/projects/${PROJECT}/locations/${REGION}/channels`,
        "channels",
      );
      const afterBuckets = await sourceObjects("inventory");
      const iamAfter = await read({
        id: "iam-after",
        method: "POST",
        url: `https://cloudresourcemanager.googleapis.com/v1/projects/${PROJECT}:getIamPolicy`,
        json: {},
        cleanup: true,
      });
      out.inventory.iam = iamChanges(iamBefore, iamAfter);
      const after = await list("services-after", SERVICES_URL, "services");
      const servicesNow = after ? after.services.map((svc) => svc.config?.name).toSorted() : null;
      const notificationsAfter = await list(
        "inventory-notifications",
        `https://storage.googleapis.com/storage/v1/b/${bucket}/notificationConfigs`,
        "items",
      );
      out.inventory.services =
        servicesNow && enabledBefore
          ? {
              added: servicesNow.filter((n) => !enabledBefore.includes(n)).toSorted(),
              removed: enabledBefore.filter((n) => !servicesNow.includes(n)),
            }
          : null;
      out.inventory.sourceObjects = Object.fromEntries(
        sourceBuckets(projectNumber).map((name, index) => {
          const before = sourceObjectsBefore?.[name];
          const now = afterBuckets[name];
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
      out.inventory.channelsAfter = channels
        ? channels.channels.map((c) => lastSegment(c.name)).toSorted()
        : null;
      const compared = inventoryDifferences({
        before: out.inventory.before,
        after: {
          channels: out.inventory.channelsAfter,
          triggers: finalLists.triggers ?? null,
          subscriptions: finalLists.subscriptions ?? null,
          topics: finalLists.topics ?? null,
          packages: finalLists.packages ?? null,
          services: servicesNow,
          notifications: notificationsAfter
            ? notificationsAfter.items.map((item) => item.id).toSorted()
            : null,
          sourceObjects: {
            uploads: afterBuckets[sourceBuckets(projectNumber)[0]],
            sources: afterBuckets[sourceBuckets(projectNumber)[1]],
          },
        },
        enabled: out.servicesEnabled ?? [],
      });
      const iam = iamUnexpected(out.inventory.iam);
      out.inventory.complete = compared.complete && iam.complete;
      out.inventory.missing = compared.missing;
      out.inventory.differences = [
        ...compared.differences,
        ...iam.unexpected.map((what) => ({ kind: "iam", what })),
      ];
    });
    out.cleanup.verified =
      out.cleanup.listsEmpty &&
      out.cleanup.uploadObjectsUnexplained.length === 0 &&
      out.cleanup.uploadReasons.length === 0 &&
      out.inventory.complete === true &&
      out.inventory.differences.length === 0 &&
      Object.values(readBack).every((v) => v === true);
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
      out.outcome = unknownMutations.length > 0 ? "pycheck-needs-review" : "pycheck-stopped-clean";
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
