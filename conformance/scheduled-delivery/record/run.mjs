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
export const CLEANUP_CEILING = 90;
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
}) {
  const guard = createGuard(runId, projectNumber);
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
    if (counts().attempted >= normalCeiling && !spec.cleanup)
      throw new BudgetError("the normal request ceiling is reached");
    return capture(spec);
  };
  const read = async (spec, { observe: observed = false } = {}) => {
    const answer = await normal(observed ? { ...spec, observe: true } : spec);
    if (isUnknownClass(answer) || (answer.status >= 400 && !observed))
      incompleteReads.push({ id: spec.id, class: answerClass(answer) });
    return answer;
  };
  const mutate = async (spec) => {
    const answer = await normal(spec);
    if (isUnknownClass(answer)) unknownMutations.push({ id: spec.id, class: answerClass(answer) });
    return answer;
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

  const summary = (stage, closureReady) => {
    const known = counts();
    const stop = authStop();
    return {
      ...out,
      stage,
      outcome: stop ? "calendar-delivery-auth-stop" : out.outcome,
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
      url:
        "https://serviceusage.googleapis.com/v1/projects/" +
        projectNumber +
        "/services?filter=state:ENABLED&pageSize=200",
    });
    const enabled = new Set((services?.json?.services ?? []).map((s) => s.config?.name));
    out.servicesMissing = REQUIRED_SERVICES.filter((id) => !enabled.has(id));
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
    for (const fn of FUNCTIONS.v1)
      await save({
        id: "issue-topic-" + fn,
        state: "issued",
        kind: "topic",
        name: topicName(scheduleId(fn)),
        transport: "cli",
      });
    created = true;
    out.cli.deploy = await runCli({ action: "deploy" });
    await save({ id: "cli-deploy", state: "cli-result", result: out.cli.deploy });
    const polls = cliFailed(out.cli.deploy) ? 2 : READY_MAX_POLLS;
    for (let poll = 1; poll <= polls; poll++) {
      const found = await lists("ready-" + poll);
      out.ready = found.v1 && found.v2 && found.run ? summarize(found) : null;
      if (out.ready && allActive(out.ready)) return true;
      if (poll < polls) await sleep(READY_POLL_SECONDS * 1000);
    }
    return false;
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
      if (answerClass(answer) === "2xx") subsCreated.push(fn);
      else {
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
      if (answerClass(answer) === "2xx") extraCreated.push(job.key);
      else {
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
  async function cleanup() {
    stopped = "cleanup";
    if (created) {
      out.cli.delete = await runCli({ action: "delete" });
      await save({ id: "cli-delete", state: "cli-result", result: out.cli.delete });
    }
    let found = null;
    for (let poll = 1; poll <= 6; poll++) {
      found = await lists("cleanup-" + poll);
      if (found.v1 && found.v2 && found.run && nonePresent(summarize(found))) break;
      await sleep(30_000);
    }
    // Leftover functions: once each, after a complete fresh list shows them, case-exact, with no resend.
    if (found?.v1 && found?.v2 && found?.run) {
      const left = summarize(found);
      for (const fn of ALL_FUNCTIONS) {
        if (!left[fn].present) continue;
        const v = FUNCTIONS.v1.includes(fn) ? "v1" : "v2";
        const answer = await mutate({
          id: "leftover-delete-" + fn,
          method: "DELETE",
          url: GCF + v + "/" + functionName(fn),
          cleanup: true,
        });
        if (
          answerClass(answer) === "2xx" &&
          typeof answer.json?.name === "string" &&
          !answer.json.done
        ) {
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
            if (op?.json?.done === true) break;
          }
        }
      }
      for (let poll = 1; poll <= 4; poll++) {
        found = await lists("after-leftovers-" + poll);
        if (found.v1 && found.v2 && found.run && nonePresent(summarize(found))) break;
        await sleep(30_000);
      }
    }
    out.cleanup.functionsGone = Boolean(
      found?.v1 && found?.v2 && found?.run && nonePresent(summarize(found)),
    );
    // The run's own jobs and subscriptions, then the v1 topics (only once their function is gone).
    const jobsLeft = await list("cleanup-jobs", SCHEDULER + "?pageSize=500", "jobs");
    for (const job of jobsLeft?.jobs ?? []) {
      const id = String(job.name).split("/").at(-1);
      if (![...deployedJobIds, ...extraIds].includes(id)) continue;
      let deleted = false;
      for (let attempt = 0; attempt < 4 && !deleted; attempt++) {
        const answer = await mutate({
          id: `delete-job-${attempt}-${id.replace(/^firebase-schedule-/, "").replace(runId, "run")}`,
          method: "DELETE",
          url: SCHEDULER + "/" + id,
          cleanup: true,
        });
        if (answerClass(answer) === "2xx") deleted = true;
        else if (isBusy(answer)) await sleep(60_000);
        else break;
      }
    }
    for (const fn of subsCreated) {
      await mutate({
        id: "delete-subscription-" + fn,
        method: "DELETE",
        url: PUBSUB + "/subscriptions/" + pullSubscriptionId(runId, fn),
        cleanup: true,
      });
    }
    if (out.cleanup.functionsGone) {
      for (const fn of FUNCTIONS.v1) {
        const topic = await read(
          {
            id: "topic-present-" + fn,
            method: "GET",
            url: PUBSUB + "/topics/" + scheduleId(fn),
            cleanup: true,
          },
          { observe: true },
        );
        if (topic?.status === 200)
          await mutate({
            id: "delete-topic-" + fn,
            method: "DELETE",
            url: PUBSUB + "/topics/" + scheduleId(fn),
            cleanup: true,
          });
      }
    }
    // Read every name back directly. Only a direct read of an absence counts.
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
    const readBack = {};
    for (const [label, url] of names) {
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
    }
    out.cleanup.readBack = readBack;
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
    out.cleanup.verified =
      out.cleanup.listsEmpty && Object.values(readBack).every((v) => v === true);
    // Read-only inventory: what the deploy left that this recorder does not delete.
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
      packages?.status === 200 ? (packages.json.packages ?? []).length : (packages?.status ?? null);
    const iamAfter = await read({
      id: "iam-after",
      method: "POST",
      url: "https://cloudresourcemanager.googleapis.com/v1/projects/" + PROJECT + ":getIamPolicy",
      json: {},
      cleanup: true,
    });
    out.inventory.iam = iamChanges(iamBefore, iamAfter);
    await sleep(FINAL_LOG_WAIT_MS);
    await pollLogs("final", { final: true });
  }

  // ---- the run ----------------------------------------------------------------------------------
  try {
    const problem = await preflight();
    if (problem) {
      out.outcome = "calendar-delivery-stopped-clean";
      out.stoppedBecause = problem;
      return summary("preflight", false);
    }
    out.stage = "dry-run";
    out.cli.dryRun = await runCli({ action: "dry-run" });
    await save({ id: "cli-dry-run", state: "cli-result", result: out.cli.dryRun });
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
    if (error instanceof AuthStop) return summary("auth-stop", false);
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
      if (error instanceof AuthStop) return summary("auth-stop", false);
      out.cleanup.error = String(error?.message);
    }
  }
  for (const entry of allFrames)
    out.frames[entry.frame.handler] = (out.frames[entry.frame.handler] ?? 0) + 1;
  out.schedulerEntries = allSchedulerEntries.length;
  out.pulledMessages = pulledMessages.length;
  const complete =
    out.passes.length === passes && out.passes.every((p) => p.complete) && !out.stoppedBecause;
  out.outcome = out.cleanup.verified
    ? complete
      ? "calendar-delivery-recorded"
      : "calendar-delivery-incomplete-clean"
    : "calendar-delivery-needs-recovery";
  out.stage = "done";
  return summary("done", out.cleanup.verified && complete);
}
