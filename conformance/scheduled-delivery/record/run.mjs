// The orchestrator of the delivery recording: preflight, the CLI dry run, one deploy of five functions,
// readiness, the readbacks, two observation passes (a forced run of every job, then a natural-fire window with
// Cloud Logging and Pub/Sub reads), and a cleanup that removes only what this run created and reads every name
// back. It records and judges nothing about delivery; it judges only what it must to stay safe: the CLI's
// result, who owns a name, and whether a name is gone.
//
// Safety rules (the lessons of the FE v5 recorder and the calendar v6 review): every name is journaled as
// `issued` before the request that creates it; a mutation answer is classified, an unknown one is never
// re-sent and never closed; a 401, or a 403 on a write, stops the run; the CLI runs at most once per action;
// Gen2 names are compared case-exact; a leftover function is deleted through REST once, after a complete
// fresh list shows it, with no resend.
//
// Settlement (coordinator rulings of 2026-10-05): an unknown CREATE is settled only by an own 2xx read showing the
// name (a direct read, or a 2xx list naming it); a 404 never settles it, so it is listed as unconfirmed and the run
// cannot close. A create confirmed by a 2xx that later reads 404, or whose own DELETE answers 404, or that is
// missing from a list, is not settled in the run either (read-after-write lag): only the read-back at least ten
// minutes later settles it as gone. The one exception is the run's own DELETE that answered 2xx (or a clean CLI
// delete, for the names the CLI made), after which a 404 is the normal end.
import { AuthStop, answerClass, createCapture, isUnknownClass, readable } from "../capture.mjs";
import {
  cliFailed,
  allActive,
  nonePresent,
  summarize,
  READY_MAX_POLLS,
  READY_POLL_SECONDS,
} from "./deploy.mjs";
import { createGuard } from "./guard.mjs";
import {
  frameFilter,
  listRequest,
  parseFrames,
  parseSchedulerEntries,
  schedulerFilter,
} from "./logs.mjs";
import {
  ALL_FUNCTIONS,
  EXTRA_JOBS,
  FUNCTIONS,
  PROJECT,
  REGION,
  extraJobId,
  functionName,
  jobName,
  pullSubscriptionId,
  scheduleId,
  subscriptionName,
  topicName,
} from "./plan.mjs";

export const NORMAL_CEILING = 330;
export const CLEANUP_CEILING = 170;
export const MAX_REQUESTS = NORMAL_CEILING + CLEANUP_CEILING;
export const PASSES = 2;
export const NATURAL_WINDOW_MS = 6 * 60_000;
export const PROPAGATION_WAIT_MS = 60_000;
export const SETTLE_WAIT_MS = 60_000;
export const LOG_POLL_MS = 60_000;
export const FINAL_LOG_WAIT_MS = 120_000;
const REQUIRED_SERVICES = Object.freeze([
  "artifactregistry.googleapis.com",
  "cloudbuild.googleapis.com",
  "cloudfunctions.googleapis.com",
  "cloudscheduler.googleapis.com",
  "compute.googleapis.com",
  "pubsub.googleapis.com",
  "run.googleapis.com",
]);

const GCF = "https://cloudfunctions.googleapis.com/";
const SCHEDULER =
  "https://cloudscheduler.googleapis.com/v1/projects/" + PROJECT + "/locations/" + REGION + "/jobs";
const PUBSUB = "https://pubsub.googleapis.com/v1/projects/" + PROJECT;
const iso = (ms) => new Date(ms).toISOString();

/** A direct read of a name that shows it is gone: a 404 whose parsed error status is NOT_FOUND, in any layout. */
export const absent = (a) =>
  a?.status === 404 && readable(a) && a.json.error?.status === "NOT_FOUND";

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

/** What a Scheduler job readback says about the job, reduced to the fields the recording is about. */
export function jobSummary(json) {
  return {
    state: json.state ?? null,
    schedule: json.schedule ?? null,
    timeZone: json.timeZone ?? null,
    retryConfig: json.retryConfig ?? null,
    attemptDeadline: json.attemptDeadline ?? null,
    target: json.httpTarget ? "http" : json.pubsubTarget ? "pubsub" : null,
    name: json.name ?? null,
  };
}

class BudgetError extends Error {}

/** The recorded 409 a job DELETE gets right after a pause or run (`sync mutate calls cannot be queued`). */
export const isBusy = (a) =>
  a?.status === 409 &&
  readable(a) &&
  a.json.error?.status === "ABORTED" &&
  a.json.error.message === "sync mutate calls cannot be queued";

export async function record({
  runId,
  projectNumber,
  accessToken,
  save,
  send,
  runCli,
  clock = Date.now,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  passes = PASSES,
  naturalWindowMs = NATURAL_WINDOW_MS,
  normalCeiling = NORMAL_CEILING,
  signal = { aborted: false },
  prepareRequest = null,
}) {
  const guard = createGuard(runId, projectNumber);
  const SERVICES_URL =
    "https://serviceusage.googleapis.com/v1/projects/" +
    projectNumber +
    "/services?filter=state:ENABLED&pageSize=200";
  const { capture, counts, authStop } = createCapture({
    accessToken,
    save,
    send,
    clock,
    maxRequests: MAX_REQUESTS,
    maxRequestCap: MAX_REQUESTS,
    allow: guard.allow,
    quotaProject: PROJECT,
    timeoutFor: (spec) => (spec.method === "POST" && spec.url.includes(":run") ? 30_000 : 15_000),
  });
  const out = {
    runId,
    stage: "preflight",
    outcome: "calendar-delivery-needs-review",
    cli: {},
    ready: null,
    passes: [],
    frames: {},
    framesIgnored: {},
    schedulerEntries: 0,
    pulled: {},
    jobs: {},
    cleanup: { verified: false },
    inventory: {},
  };
  const unknownMutations = [];
  const incompleteReads = [];
  // Every name this run may create, by label (the labels of the cleanup's read-back), and the evidence about it.
  const NAMES = new Map([
    ...ALL_FUNCTIONS.map((fn) => ["function-" + fn, functionName(fn)]),
    ...ALL_FUNCTIONS.map((fn) => ["job-" + scheduleId(fn), jobName(scheduleId(fn))]),
    ...FUNCTIONS.v1.map((fn) => ["topic-" + fn, topicName(scheduleId(fn))]),
    ...EXTRA_JOBS.map((job) => [
      "job-" + extraJobId(runId, job.key),
      jobName(extraJobId(runId, job.key)),
    ]),
    ...FUNCTIONS.v1.map((fn) => [
      "subscription-" + fn,
      subscriptionName(pullSubscriptionId(runId, fn)),
    ]),
  ]);
  const labelOf = new Map([...NAMES].map(([label, name]) => [name, label]));
  const issued = new Set(); // labels whose name was journaled as issued
  const confirmed = new Set(); // issued labels an own 2xx showed (a create answer, a direct read or a list)
  const ownDeleted = new Set(); // labels this run's own DELETE answered 2xx for
  const pendingCreates = new Map(); // label -> an unknown REST create answer
  const cliLabels = new Map(); // label -> name, for the names the CLI deploy makes
  let deployUnknown = null; // why the CLI deploy's effect is unknown, if it is
  let deployWrites = []; // CLI writes answered 5xx, 3xx or below 200 (a clean failure can hide such a create)
  let created = false;
  let stopped = null;
  const startedAt = clock();
  const frameSeen = new Set();
  const schedulerSeen = new Set();
  const allFrames = [];
  const allSchedulerEntries = [];
  const pulledMessages = [];
  let polledUntil = startedAt;

  // ---- request helpers -------------------------------------------------------------------------
  const normal = async (spec) => {
    if (signal.aborted && !spec.cleanup) throw new BudgetError("stopped by a signal");
    if (counts().attempted >= normalCeiling && !spec.cleanup)
      throw new BudgetError("the normal request ceiling is reached");
    // Before the request is journaled: a token refresh that fails stops a request that was never sent, and leaves
    // no row that would read as an unknown answer.
    await prepareRequest?.(spec);
    return capture(spec);
  };
  /** An own 2xx read (a direct read, or a list page) that names an issued name confirms that it exists. */
  const noteSeen = (answer) => {
    if (!(answer?.status === 200 && readable(answer))) return;
    const names = [answer.json.name];
    for (const key of ["functions", "jobs", "topics", "subscriptions"])
      if (Array.isArray(answer.json[key]))
        names.push(...answer.json[key].map((item) => item?.name));
    for (const name of names) {
      const label = labelOf.get(name);
      if (label && issued.has(label)) confirmed.add(label);
    }
  };
  const read = async (spec, { observe: observed = false } = {}) => {
    const answer = await normal(observed ? { ...spec, observe: true } : spec);
    if (isUnknownClass(answer) || (answer.status >= 400 && !observed))
      incompleteReads.push({ id: spec.id, class: answerClass(answer) });
    noteSeen(answer);
    return answer;
  };
  const mutate = async (spec) => {
    const answer = await normal(spec);
    if (isUnknownClass(answer)) unknownMutations.push({ id: spec.id, class: answerClass(answer) });
    return answer;
  };
  /** Why a CLI run's effect is unknown: it timed out, was killed, or could not be run at all. */
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
      // The end of the CLI counts for the read-back's ten-minute guard even when it could not be run.
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
  /** A clean CLI delete (exit 0, nothing errored, no timeout or signal) is the run's own delete of the CLI's names. */
  const cliDeleteClean = () =>
    Boolean(out.cli.delete) && !cliFailed(out.cli.delete) && !cliUnknownClass(out.cli.delete);
  const unconfirmedCreates = () => [
    ...[...pendingCreates.values()].filter((create) => !confirmed.has(create.label)),
    ...(deployUnknown
      ? [...cliLabels]
          .filter(([label]) => !confirmed.has(label))
          .map(([label, name]) => ({ label, id: "cli-deploy", name, class: deployUnknown }))
      : []),
    // A CLI write answered 5xx (or 3xx, or below 200) may have created a name of its kind even though the CLI
    // reported the function errored and failed cleanly: every name of that kind no own 2xx read showed is open.
    ...(deployUnknown
      ? []
      : [...cliLabels]
          .filter(([label]) => !confirmed.has(label))
          .flatMap(([label, name]) => {
            const host = label.startsWith("function-")
              ? "cloudfunctions"
              : label.startsWith("job-")
                ? "cloudscheduler"
                : "pubsub";
            const write = deployWrites.find((w) => w.host === host);
            return write ? [{ label, id: "cli-deploy", name, class: "cli-" + write.status }] : [];
          })),
  ];
  /** Confirmed names that ended absent without this run's own 2xx delete: only the read-back can settle them. */
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
  const lists = async (prefix) => ({
    v1: await list(
      prefix + "-functions-v1",
      GCF + "v1/projects/" + PROJECT + "/locations/-/functions",
      "functions",
    ),
    v2: await list(
      prefix + "-functions-v2",
      GCF + "v2/projects/" + PROJECT + "/locations/-/functions",
      "functions",
    ),
    run: await list(
      prefix + "-run-services",
      "https://run.googleapis.com/v2/projects/" + PROJECT + "/locations/-/services",
      "services",
    ),
  });

  /** Everything that keeps a run from closing in the run itself (the read-back may settle some of it). */
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
      outcome: stop ? "calendar-delivery-auth-stop" : out.outcome,
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

  // ---- Cloud Logging and Pub/Sub observation ------------------------------------------------------
  async function pollLogs(label, { final = false } = {}) {
    const end = clock();
    const start = final ? startedAt : polledUntil - 5000;
    const window = { start: iso(start), end: iso(end) };
    for (const [kind, filter] of [
      ["frames", frameFilter(window)],
      ["scheduler", schedulerFilter({ runId, ...window })],
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
        } else {
          allSchedulerEntries.push(...parseSchedulerEntries(entries, schedulerSeen));
        }
        token = answer.json.nextPageToken ?? "";
        if (!token) break;
      }
    }
    if (!final) polledUntil = end;
  }

  async function pullAll(label) {
    for (const fn of FUNCTIONS.v1) {
      const sub = pullSubscriptionId(runId, fn);
      const url = PUBSUB + "/subscriptions/" + sub;
      const answer = await mutate({
        id: `pull-${label}-${fn}`,
        method: "POST",
        url: url + ":pull",
        json: { maxMessages: 10, returnImmediately: true },
      });
      if (!(answer?.status === 200 && readable(answer))) continue;
      const received = answer.json.receivedMessages ?? [];
      if (received.length === 0) continue;
      pulledMessages.push(...received.map((r) => ({ fn, message: r.message })));
      out.pulled[fn] = (out.pulled[fn] ?? 0) + received.length;
      await mutate({
        id: `ack-${label}-${fn}`,
        method: "POST",
        url: url + ":acknowledge",
        json: { ackIds: received.map((r) => r.ackId) },
      });
    }
  }

  async function observe(label, windowMs) {
    const steps = Math.ceil(windowMs / LOG_POLL_MS);
    for (let step = 1; step <= steps; step++) {
      await sleep(Math.min(LOG_POLL_MS, windowMs - (step - 1) * LOG_POLL_MS));
      await pullAll(`${label}-${step}`);
      await pollLogs(`${label}-${step}`);
    }
  }

  const deployedJobIds = ALL_FUNCTIONS.map(scheduleId);
  const extraIds = EXTRA_JOBS.map((job) => extraJobId(runId, job.key));
  let iamBefore = null;
  let enabledBefore = null;
  let cliDeleteStarted = false;
  let extraCreated = [];
  let subsCreated = [];

  // ---- the phases ------------------------------------------------------------------------------
  async function preflight() {
    const identity = await normal({
      id: "identity",
      method: "GET",
      url:
        "https://firebaserules.googleapis.com/v1/projects/" + PROJECT + "/releases/cloud.firestore",
    });
    if (
      identity?.status !== 200 ||
      identity.json?.name !== "projects/" + PROJECT + "/releases/cloud.firestore"
    )
      return "identity";
    const services = await normal({
      id: "services-before",
      method: "GET",
      url: SERVICES_URL,
    });
    const enabled = new Set((services?.json?.services ?? []).map((s) => s.config?.name));
    out.servicesMissing = REQUIRED_SERVICES.filter((id) => !enabled.has(id));
    enabledBefore = [...enabled].toSorted();
    if (!(services?.status === 200 && readable(services)) || out.servicesMissing.length > 0)
      return "services";
    iamBefore = await read({
      id: "iam-before",
      method: "POST",
      url: "https://cloudresourcemanager.googleapis.com/v1/projects/" + PROJECT + ":getIamPolicy",
      json: {},
    });
    const sdk = await read(
      {
        id: "admin-sdk-config",
        method: "GET",
        url: "https://firebase.googleapis.com/v1beta1/projects/" + PROJECT + "/adminSdkConfig",
      },
      { observe: true },
    );
    out.adminSdkConfig = { status: sdk?.status ?? null, locationId: sdk?.json?.locationId ?? null };
    // firebase-tools reads the same config itself to place a v1 job: one that cannot be read is not "no location".
    if (!(sdk?.status === 200 && readable(sdk))) return "admin-sdk-config";
    // Where firebase-tools puts a v1 scheduled job: the App Engine location the project names, "us-central" becoming
    // "us-central1" (`functionsConfig.js` getAppEngineLocation), or us-central1 when the project names none.
    const named = sdk?.json?.locationId;
    if (typeof named === "string" && named.length > 0) {
      out.appEngineLocation = /\d$/.test(named) ? named : named + "1";
      if (out.appEngineLocation !== REGION) return "app-engine-location";
    }
    const app = await read(
      {
        id: "appengine-app",
        method: "GET",
        url: "https://appengine.googleapis.com/v1/apps/" + PROJECT,
      },
      { observe: true },
    );
    out.appEngine = { status: app?.status ?? null };
    const before = await lists("preflight");
    if (!before.v1 || !before.v2 || !before.run) return "lists";
    const summaryBefore = summarize(before);
    const jobs = await list("preflight-jobs", SCHEDULER + "?pageSize=500", "jobs");
    const topics = await list("preflight-topics", PUBSUB + "/topics?pageSize=1000", "topics");
    const subs = await list(
      "preflight-subscriptions",
      PUBSUB + "/subscriptions?pageSize=1000",
      "subscriptions",
    );
    if (!jobs || !topics || !subs) return "lists";
    if (
      !nonePresent(summaryBefore) ||
      jobs.jobs.length ||
      topics.topics.length ||
      subs.subscriptions.length
    )
      return "namespace";
    await pollLogs("preflight");
    return null;
  }

  async function deploy() {
    for (const fn of ALL_FUNCTIONS) {
      for (const label of ["function-" + fn, "job-" + scheduleId(fn)]) {
        issued.add(label);
        cliLabels.set(label, NAMES.get(label));
      }
      await save({
        id: "issue-function-" + fn,
        state: "issued",
        kind: "function",
        name: functionName(fn),
        transport: "cli",
      });
      await save({
        id: "issue-job-" + fn,
        state: "issued",
        kind: "job",
        name: jobName(scheduleId(fn)),
        transport: "cli",
      });
    }
    for (const fn of FUNCTIONS.v1) {
      issued.add("topic-" + fn);
      cliLabels.set("topic-" + fn, NAMES.get("topic-" + fn));
    }
    for (const fn of FUNCTIONS.v1)
      await save({
        id: "issue-topic-" + fn,
        state: "issued",
        kind: "topic",
        name: topicName(scheduleId(fn)),
        transport: "cli",
      });
    created = true;
    out.cli.deploy = await cli("deploy");
    deployWrites = out.cli.deploy?.unknownWrites ?? [];
    await save({
      id: "cli-deploy",
      state: "cli-result",
      result: out.cli.deploy,
      responseAt: iso(clock()),
    });
    const polls = cliFailed(out.cli.deploy) ? 2 : READY_MAX_POLLS;
    let found = null;
    for (let poll = 1; poll <= polls; poll++) {
      found = await lists("ready-" + poll);
      out.ready = found.v1 && found.v2 && found.run ? summarize(found) : null;
      if (out.ready && allActive(out.ready)) return true;
      if (poll < polls) await sleep(READY_POLL_SECONDS * 1000);
    }
    await diagnoseBuilds(found);
    return false;
  }

  /**
   * Why a function did not become active: for each build named by this run's functions whose list entry is not ACTIVE,
   * one GET of that build (its status, failure info and step statuses) and one Cloud Logging read of that build's log
   * lines. A function is listed by both function lists (the v2 list carries first-generation functions too) and
   * functions of one deploy share a build, so a build is read once, whoever names it first; each function still has its
   * own row in `buildDiagnostics`. Reads only; 403 and 404 are data; it judges nothing and never blocks the close (run
   * e0ec2f41: a Gen1 build failed with "Build error details not available" and nothing in the packet could say why).
   */
  async function diagnoseBuilds(found) {
    const entries = [
      ...(found?.v1?.functions ?? []).map((item) => ({ item, active: item.status === "ACTIVE" })),
      ...(found?.v2?.functions ?? []).map((item) => ({ item, active: item.state === "ACTIVE" })),
    ].filter(
      ({ item, active }) => !active && ALL_FUNCTIONS.some((fn) => functionName(fn) === item.name),
    );
    const diagnostics = [];
    const read = new Map();
    const seen = new Set();
    for (const { item } of entries) {
      const fn = String(item.name).split("/").at(-1);
      if (seen.has(fn)) continue;
      seen.add(fn);
      const build =
        /\/builds\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/.exec(
          String(item.buildName ?? item.buildConfig?.build ?? ""),
        );
      if (!build) {
        diagnostics.push({ function: fn, buildId: null });
        continue;
      }
      const buildId = build[1];
      if (!read.has(buildId)) {
        const got = await normal({
          id: "diagnose-build-" + fn,
          method: "GET",
          url: `https://cloudbuild.googleapis.com/v1/projects/${projectNumber}/locations/${REGION}/builds/${buildId}`,
          observe: true,
        });
        const logs = await normal({
          ...listRequest({
            id: "diagnose-build-logs-" + fn,
            filter: `resource.type="build" AND resource.labels.build_id="${buildId}"`,
          }),
          observe: true,
        });
        read.set(buildId, { got, logs });
      }
      const { got, logs } = read.get(buildId);
      const json = got?.status === 200 && readable(got) ? got.json : {};
      diagnostics.push({
        function: fn,
        buildId,
        buildStatus: got?.status ?? null,
        status: json.status ?? null,
        statusDetail: json.statusDetail ?? null,
        failureInfo: json.failureInfo ?? null,
        steps: Array.isArray(json.steps)
          ? json.steps.map((step) => ({ name: step.name ?? null, status: step.status ?? null }))
          : null,
        logsStatus: logs?.status ?? null,
        logEntries:
          logs?.status === 200 && readable(logs) ? (logs.json.entries ?? []).length : null,
      });
    }
    out.buildDiagnostics = diagnostics;
  }

  async function readbacks() {
    await sleep(PROPAGATION_WAIT_MS);
    await read({ id: "readback-jobs", method: "GET", url: SCHEDULER + "?pageSize=500" });
    for (const fn of ALL_FUNCTIONS) {
      const id = scheduleId(fn);
      const job = await read({
        id: "readback-job-" + fn,
        method: "GET",
        url: SCHEDULER + "/" + id,
      });
      if (job?.status === 200 && readable(job)) out.jobs[fn] = jobSummary(job.json);
      const version = FUNCTIONS.v1.includes(fn) ? "v1" : "v2";
      await read({
        id: "readback-function-" + fn,
        method: "GET",
        url: GCF + version + "/" + functionName(fn),
      });
    }
    for (const fn of FUNCTIONS.v1)
      await read({
        id: "readback-topic-" + fn,
        method: "GET",
        url: PUBSUB + "/topics/" + scheduleId(fn),
      });
  }

  async function setup() {
    for (const fn of FUNCTIONS.v1) {
      const id = pullSubscriptionId(runId, fn);
      issued.add("subscription-" + fn);
      await save({
        id: "issue-subscription-" + fn,
        state: "issued",
        kind: "subscription",
        name: subscriptionName(id),
        transport: "rest",
      });
      const answer = await mutate({
        id: "create-subscription-" + fn,
        method: "PUT",
        url: PUBSUB + "/subscriptions/" + id,
        json: { topic: topicName(scheduleId(fn)), ackDeadlineSeconds: 10 },
      });
      if (answerClass(answer) === "2xx") {
        subsCreated.push(fn);
        confirmed.add("subscription-" + fn);
      } else {
        // An unknown create stays unconfirmed until an own 2xx read shows the name; a 404 never settles it.
        if (isUnknownClass(answer))
          pendingCreates.set("subscription-" + fn, {
            label: "subscription-" + fn,
            id: "create-subscription-" + fn,
            name: NAMES.get("subscription-" + fn),
            class: answerClass(answer),
          });
        // An unknown or refused create: settle by a direct read of the name.
        const read1 = await read(
          { id: "settle-subscription-" + fn, method: "GET", url: PUBSUB + "/subscriptions/" + id },
          { observe: true },
        );
        if (read1?.status === 200) subsCreated.push(fn);
      }
    }
    const target = out.jobs.schedRetryV2;
    const deployed = await read({
      id: "extra-target",
      method: "GET",
      url: SCHEDULER + "/" + scheduleId("schedRetryV2"),
    });
    const http = deployed?.json?.httpTarget;
    if (!http) {
      out.extraJobs = { skipped: "the deployed retry job has no HTTP target", target };
      return;
    }
    for (const job of EXTRA_JOBS) {
      const id = extraJobId(runId, job.key);
      issued.add("job-" + id);
      await save({
        id: "issue-extra-" + job.key,
        state: "issued",
        kind: "job",
        name: jobName(id),
        transport: "rest",
      });
      const answer = await mutate({
        id: "create-extra-" + job.key,
        method: "POST",
        url: SCHEDULER,
        json: {
          name: jobName(id),
          schedule: job.schedule,
          timeZone: job.timeZone,
          httpTarget: http,
          retryConfig: job.retryConfig,
          ...(deployed.json.attemptDeadline
            ? { attemptDeadline: deployed.json.attemptDeadline }
            : {}),
        },
      });
      // What production answered to each extra create, in the result (a refusal is a recorded answer, e.g. the
      // retry-count boundary probe `retry5`).
      (out.extraAnswers ??= {})[job.key] = {
        status: answer?.status ?? null,
        class: answerClass(answer),
        message: readable(answer)
          ? String(answer.json.error?.message ?? "").slice(0, 300) || null
          : null,
      };
      if (answerClass(answer) === "2xx") {
        extraCreated.push(job.key);
        confirmed.add("job-" + id);
      } else {
        if (isUnknownClass(answer))
          pendingCreates.set("job-" + id, {
            label: "job-" + id,
            id: "create-extra-" + job.key,
            name: NAMES.get("job-" + id),
            class: answerClass(answer),
          });
        const settled = await read(
          { id: "settle-extra-" + job.key, method: "GET", url: SCHEDULER + "/" + id },
          { observe: true },
        );
        if (settled?.status === 200) extraCreated.push(job.key);
      }
    }
  }

  async function runPass(number) {
    const record_ = { number, forced: [], complete: false };
    const targets = [...deployedJobIds, ...extraCreated.map((key) => extraJobId(runId, key))];
    for (const id of targets) {
      const answer = await mutate({
        id: `run-${number}-${id.replace(/^firebase-schedule-/, "").replace(runId, "run")}`,
        method: "POST",
        url: SCHEDULER + "/" + id + ":run",
        json: {},
      });
      record_.forced.push({ id, class: answerClass(answer), status: answer?.status ?? null });
      await sleep(3000);
    }
    await observe(`pass${number}`, naturalWindowMs);
    record_.complete = true;
    out.passes.push(record_);
  }

  async function pauseAll() {
    const ids = [...deployedJobIds, ...extraCreated.map((key) => extraJobId(runId, key))];
    for (const id of ids)
      await mutate({
        id: "pause-" + id.replace(/^firebase-schedule-/, "").replace(runId, "run"),
        method: "POST",
        url: SCHEDULER + "/" + id + ":pause",
        json: {},
      });
    await sleep(SETTLE_WAIT_MS);
  }

  // ---- cleanup ----------------------------------------------------------------------------------
  /**
   * The one CLI delete. Never repeated: whoever gets here first (the cleanup, or the stop after a rejected
   * credential, whose REST token is no use but whose CLI has its own) runs it and records its result.
   */
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
    // Every step stands alone: a refused request, an exhausted cap or a throw in one of them is recorded and the
    // next step still runs. Only a rejected credential ends the cleanup (and never re-sends anything).
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
    let found = null;
    const settled = () => found?.v1 && found?.v2 && found?.run && nonePresent(summarize(found));
    await step("cli-delete", () => cliDelete());
    await step("project-lists", async () => {
      for (let poll = 1; poll <= 6; poll++) {
        found = await lists("cleanup-" + poll);
        if (settled()) break;
        await sleep(30_000);
      }
    });
    // Leftover functions: once each, after a complete fresh list shows them, case-exact, with no resend.
    if (found?.v1 && found?.v2 && found?.run) {
      const left = summarize(found);
      for (const fn of ALL_FUNCTIONS) {
        if (!left[fn].present) continue;
        await step("leftover-" + fn, async () => {
          const v = FUNCTIONS.v1.includes(fn) ? "v1" : "v2";
          const answer = await mutate({
            id: "leftover-delete-" + fn,
            method: "DELETE",
            url: GCF + v + "/" + functionName(fn),
            cleanup: true,
          });
          if (answerClass(answer) !== "2xx") return;
          // A 2xx settles the delete only as a finished operation without an error: the operation of this DELETE
          // read done, or the answer itself done. An operation that never reads done (or reads done with an error)
          // is an unknown DELETE, sticky until the read-back; a later 404 of the function does not settle it.
          const finished = (op) => op?.json?.done === true && !op.json.error;
          let settledBy = finished(answer);
          let pending = "operation-pending";
          if (!settledBy && typeof answer.json?.name === "string" && !answer.json.done) {
            const operation = answer.json.name.startsWith("operations/")
              ? GCF + "v1/" + answer.json.name
              : GCF + "v2/" + answer.json.name;
            for (let poll = 0; poll < 12; poll++) {
              await sleep(10_000);
              const op = await read(
                {
                  id: `leftover-operation-${fn}-${poll + 1}`,
                  method: "GET",
                  url: operation,
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
          found = await lists("after-leftovers-" + poll);
          if (settled()) break;
          await sleep(30_000);
        }
      });
    }
    out.cleanup.functionsGone = Boolean(settled());
    // The run's own jobs and subscriptions, then the v1 topics (only once their function is gone).
    const jobsLeft = await step("jobs-list", () =>
      list("cleanup-jobs", SCHEDULER + "?pageSize=500", "jobs"),
    );
    for (const job of jobsLeft?.jobs ?? []) {
      const id = String(job.name).split("/").at(-1);
      if (![...deployedJobIds, ...extraIds].includes(id)) continue;
      await step("job-" + id, async () => {
        let deleted = false;
        for (let attempt = 0; attempt < 4 && !deleted; attempt++) {
          const answer = await mutate({
            id: `delete-job-${attempt}-${id.replace(/^firebase-schedule-/, "").replace(runId, "run")}`,
            method: "DELETE",
            url: SCHEDULER + "/" + id,
            cleanup: true,
          });
          if (answerClass(answer) === "2xx") {
            deleted = true;
            ownDeleted.add("job-" + id);
          } else if (isBusy(answer)) await sleep(60_000);
          else break;
        }
      });
    }
    for (const fn of subsCreated) {
      await step("subscription-" + fn, async () => {
        const answer = await mutate({
          id: "delete-subscription-" + fn,
          method: "DELETE",
          url: PUBSUB + "/subscriptions/" + pullSubscriptionId(runId, fn),
          cleanup: true,
        });
        if (answerClass(answer) === "2xx") ownDeleted.add("subscription-" + fn);
      });
    }
    if (out.cleanup.functionsGone) {
      for (const fn of FUNCTIONS.v1) {
        await step("topic-" + fn, async () => {
          const topic = await read(
            {
              id: "topic-present-" + fn,
              method: "GET",
              url: PUBSUB + "/topics/" + scheduleId(fn),
              cleanup: true,
            },
            { observe: true },
          );
          if (topic?.status === 200) {
            const answer = await mutate({
              id: "delete-topic-" + fn,
              method: "DELETE",
              url: PUBSUB + "/topics/" + scheduleId(fn),
              cleanup: true,
            });
            if (answerClass(answer) === "2xx") ownDeleted.add("topic-" + fn);
          }
        });
      }
    }
    // Read every name back directly. Only a direct read of an absence counts; a name that was not read is not absent.
    const names = [
      ...ALL_FUNCTIONS.map((fn) => [
        "function-" + fn,
        GCF + (FUNCTIONS.v1.includes(fn) ? "v1/" : "v2/") + functionName(fn),
      ]),
      ...deployedJobIds.map((id) => ["job-" + id, SCHEDULER + "/" + id]),
      ...extraIds.map((id) => ["job-" + id, SCHEDULER + "/" + id]),
      ...FUNCTIONS.v1.map((fn) => ["topic-" + fn, PUBSUB + "/topics/" + scheduleId(fn)]),
      ...FUNCTIONS.v1.map((fn) => [
        "subscription-" + fn,
        PUBSUB + "/subscriptions/" + pullSubscriptionId(runId, fn),
      ]),
    ];
    const readBack = Object.fromEntries(names.map(([label]) => [label, false]));
    out.cleanup.readBack = readBack;
    for (const [label, url] of names) {
      await step("readback-" + label, async () => {
        const answer = await read(
          {
            id: "readback-gone-" + label.replace(/^job-/, "job-").replace(runId, "run"),
            method: "GET",
            url,
            cleanup: true,
          },
          { observe: true },
        );
        readBack[label] = absent(answer);
      });
    }
    out.cleanup.listsEmpty = false;
    await step("final-lists", async () => {
      const finalLists = {
        jobs: await list("final-jobs", SCHEDULER + "?pageSize=500", "jobs"),
        topics: await list("final-topics", PUBSUB + "/topics?pageSize=1000", "topics"),
        subscriptions: await list(
          "final-subscriptions",
          PUBSUB + "/subscriptions?pageSize=1000",
          "subscriptions",
        ),
      };
      const finalFns = await lists("final");
      out.cleanup.listsEmpty =
        Boolean(finalLists.jobs && finalLists.topics && finalLists.subscriptions) &&
        finalLists.jobs.jobs.length === 0 &&
        finalLists.topics.topics.length === 0 &&
        finalLists.subscriptions.subscriptions.length === 0 &&
        Boolean(finalFns.v1 && finalFns.v2 && finalFns.run) &&
        nonePresent(summarize(finalFns));
    });
    out.cleanup.verified =
      out.cleanup.listsEmpty && Object.values(readBack).every((v) => v === true);
    // Read-only inventory: what the deploy left that this recorder does not delete, and what it changed.
    await step("inventory", async () => {
      const packages = await read(
        {
          id: "inventory-packages",
          method: "GET",
          url:
            "https://artifactregistry.googleapis.com/v1/projects/" +
            PROJECT +
            "/locations/" +
            REGION +
            "/repositories/gcf-artifacts/packages?pageSize=100",
          cleanup: true,
        },
        { observe: true },
      );
      out.inventory.artifactPackages =
        packages?.status === 200
          ? (packages.json.packages ?? []).length
          : (packages?.status ?? null);
    });
    await step("iam-after", async () => {
      const iamAfter = await read({
        id: "iam-after",
        method: "POST",
        url: "https://cloudresourcemanager.googleapis.com/v1/projects/" + PROJECT + ":getIamPolicy",
        json: {},
        cleanup: true,
      });
      out.inventory.iam = iamChanges(iamBefore, iamAfter);
    });
    await step("services-after", async () => {
      const after = await read({
        id: "services-after",
        method: "GET",
        url: SERVICES_URL,
        cleanup: true,
      });
      const names = new Set((after?.json?.services ?? []).map((svc) => svc.config?.name));
      out.inventory.services =
        after?.status === 200 && readable(after) && enabledBefore
          ? {
              added: [...names].filter((n) => !enabledBefore.includes(n)).toSorted(),
              removed: enabledBefore.filter((n) => !names.has(n)),
            }
          : null;
    });
    await step("final-logs", async () => {
      await sleep(FINAL_LOG_WAIT_MS);
      await pollLogs("final", { final: true });
    });
  }

  // ---- the run ----------------------------------------------------------------------------------
  /** A rejected credential: the REST requests end here, but the one CLI delete still runs if a deploy began. */
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
  try {
    const problem = await preflight();
    if (problem) {
      out.outcome = "calendar-delivery-stopped-clean";
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
      out.outcome = "calendar-delivery-stopped-clean";
      out.stoppedBecause = "the CLI dry run failed";
      return summary("dry-run", false);
    }
    out.stage = "deploy";
    const ready = await deploy();
    if (ready) {
      out.stage = "readbacks";
      await readbacks();
      out.stage = "setup";
      await setup();
      for (let number = 1; number <= passes; number++) {
        out.stage = "pass-" + number;
        await runPass(number);
      }
      out.stage = "pause";
      await pauseAll();
    }
  } catch (error) {
    if (error instanceof AuthStop) return authStopped();
    if (!(error instanceof BudgetError)) {
      out.stoppedBecause = String(error?.message);
      if (!created) throw error;
    } else out.stoppedBecause = error.message;
  }
  if (created) {
    try {
      out.stage = "cleanup";
      await cleanup();
    } catch (error) {
      if (!(error instanceof AuthStop)) throw error;
      return authStopped();
    }
  }
  for (const entry of allFrames)
    out.frames[entry.frame.handler] = (out.frames[entry.frame.handler] ?? 0) + 1;
  out.schedulerEntries = allSchedulerEntries.length;
  out.pulledMessages = pulledMessages.length;
  const complete =
    out.passes.length === passes && out.passes.every((p) => p.complete) && !out.stoppedBecause;
  // `recorded` and `incomplete-clean` both say "nothing is left open": a run with an unknown answer, an
  // unconfirmed or vanished create, an unreadable answer or a failed cleanup step is `needs-review`.
  out.outcome = !created
    ? "calendar-delivery-stopped-clean"
    : !out.cleanup.verified
      ? "calendar-delivery-needs-recovery"
      : open().blocked || out.cleanup.errors
        ? "calendar-delivery-needs-review"
        : complete
          ? "calendar-delivery-recorded"
          : "calendar-delivery-incomplete-clean";
  out.stage = "done";
  return summary("done", out.cleanup.verified && complete && !out.cleanup.errors);
}
