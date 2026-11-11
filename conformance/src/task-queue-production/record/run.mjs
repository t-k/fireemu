// The orchestrator of the recording: preflight, the CLI dry run, one deploy of eight task queue functions, readiness, the
// readbacks of the functions, the program (createTask, getTask, deleteTask and queue reads against the run's own queues), a
// bounded wait for the deliveries (Cloud Logging reads), and a cleanup that removes only what this run created and reads
// every name back. It judges delivery only through `judge`; it judges for itself only what it must to stay safe: the CLI's
// result, who owns a name, and whether a name is gone. Adapted from the Python Functions check's run.mjs
// (work/python-functions-check 650824f6c), whose safety rules it keeps.
//
// Safety rules (the lessons of the FE v5 recorder and the calendar v6 review): every name is journaled as `issued`
// before the request that creates it; a mutation answer is classified, an unknown one is never re-sent and never
// closed; a 401, or a 403 on a write that is not a probe of a permission, stops the run; the CLI runs at most once per
// action; a leftover function is deleted through REST once, after a complete fresh list shows it, with no resend.
//
// Settlement (coordinator rulings of 2026-10-05): an unknown CREATE is settled only by an own 2xx read showing the name
// (a direct read, or a 2xx list naming it); a 404 never settles it, so it is listed as unconfirmed and the run cannot
// close. A create confirmed by a 2xx that later reads 404, or whose own DELETE answers 404, or that is missing from a
// list, is not settled in the run either (read-after-write lag): only the read-back at least ten minutes later
// settles it as gone. The one exception is the run's own DELETE that answered 2xx (or a clean CLI delete, for the names
// the CLI made), after which a 404 is the normal end. A task lives only in a queue of the run: an unknown createTask or
// deleteTask is an unknown mutation (the run cannot close) that the read-back settles by proving the queues gone.
import {
  AuthStop,
  answerClass,
  createCapture,
  isUnknownClass,
  readable,
} from "../../../scheduled-delivery/capture.mjs";
import { MAY_FORBID, PROGRAM, materialize, minStarts } from "../corpus.mjs";
import {
  READY_MAX_POLLS,
  READY_POLL_SECONDS,
  allActive,
  cliFailed,
  inventoryDifferences,
  iamPolicyDifferences,
  nonePresent,
  putClass,
  summarize,
  supportedIamPolicy,
} from "./deploy.mjs";
import { createGuard, ownPackages, queueIdsOf } from "./guard.mjs";
import { judge } from "./judge.mjs";
import { errorFilter, frameFilter, listRequest, parseErrors, parseFrames } from "./logs.mjs";
import {
  DELIVERY_WINDOW_SECONDS,
  LOG_DELAY_SECONDS,
  PROJECT,
  PROPAGATION_WAIT_SECONDS,
  REGION,
  REQUIRED_SERVICES,
  ROLE_IDS,
  STEP_GAP_SECONDS,
  functionName,
  functionOfRole,
  functionsOf,
  isOwnUploadObject,
  packageIds,
  queueName,
  sourceBuckets,
  uploadBucket,
} from "../plan.mjs";

export const NORMAL_CEILING = 340;
export const CLEANUP_CEILING = 200;
export const MAX_REQUESTS = NORMAL_CEILING + CLEANUP_CEILING;
export const LOG_POLL_SECONDS = 60;
const GCF = "https://cloudfunctions.googleapis.com/v2/";
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

/**
 * The project IAM policy of a read, without `etag` and `version`, or `null` when the read is not a readable policy of a
 * shape the packet can compare. The whole policy is kept (audit configuration and binding conditions included).
 */
export function iamPolicyOf(answer) {
  if (!(answer?.status === 200 && readable(answer)) || !supportedIamPolicy(answer.json))
    return null;
  return Object.fromEntries(
    Object.entries(answer.json).filter(([key]) => key !== "etag" && key !== "version"),
  );
}

class BudgetError extends Error {}

const lastSegment = (name) =>
  String(name ?? "")
    .split("/")
    .at(-1);

/** What an answer shows, without the raw bytes (the journal holds those). */
const answerSummary = (a) =>
  a === null || a === undefined
    ? null
    : { status: a.status, bodyBytes: a.bodyBytes ?? null, json: a.json ?? null };

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
    ...waits,
  };
  const pause = (seconds) => sleep(seconds * 1000);
  const FNS = functionsOf(runId);
  const QUEUES = queueIdsOf(runId);
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
    outcome: "tq-needs-review",
    cli: {},
    ready: null,
    program: {},
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
  // Every name this run may create by label (the labels of the cleanup's read-back). The functions and queues are the CLI's.
  const NAMES = new Map([
    ...FNS.map((fn) => ["function-" + fn, functionName(fn)]),
    ...FNS.map((fn) => ["queue-" + fn, queueName(fn)]),
  ]);
  const labelOf = new Map([...NAMES].map(([label, name]) => [name, label]));
  const issued = new Set();
  const confirmed = new Set();
  const ownDeleted = new Set();
  const cliLabels = new Map();
  let deployUnknown = null;
  let deployWrites = [];
  let created = false;
  let stopped = null;
  const startedAt = clock();
  const frameSeen = new Set();
  const errorSeen = new Set();
  const allFrames = [];
  const allErrors = [];
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
    for (const key of ["functions", "queues"])
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
  const hostOfLabel = (label) => (label.startsWith("function-") ? "cloudfunctions" : "cloudtasks");
  const unconfirmedCreates = () => [
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
      outcome: stop ? "tq-auth-stop" : out.outcome,
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
      ["frames", frameFilter(window, FNS)],
      ["errors", errorFilter(window, FNS)],
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
          const parsed = parseFrames(entries, FNS, frameSeen);
          allFrames.push(...parsed.frames);
          for (const [k, n] of Object.entries(parsed.ignored))
            out.framesIgnored[k] = (out.framesIgnored[k] ?? 0) + n;
        } else allErrors.push(...parseErrors(entries, FNS, errorSeen));
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
    // The enabled services are read page by page: a project can have more than one page of them. Nothing is enabled: a
    // missing one stops the run.
    const services = await list("services-before", SERVICES_URL, "services");
    const enabled = new Set((services?.services ?? []).map((s) => s.config?.name));
    out.servicesMissing = REQUIRED_SERVICES.filter((id) => !enabled.has(id));
    enabledBefore = [...enabled].toSorted();
    if (services === null || out.servicesMissing.length > 0) return "services";
    iamBefore = await read({
      id: "iam-before",
      method: "POST",
      url: `https://cloudresourcemanager.googleapis.com/v1/projects/${PROJECT}:getIamPolicy`,
      json: {},
    });
    // The project IAM is part of the baseline every closure compares with: a policy that cannot be read stops the run
    // before anything is created.
    if (iamPolicyOf(iamBefore) === null) return "iam";
    const before = await functionLists("preflight");
    if (!complete(before)) return "lists";
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
    if (![queues, topics, subs, triggers, channels, packages].every(Boolean)) return "lists";
    const names = (items) => items.map((item) => item.name).toSorted();
    out.inventory.before = {
      channels: channels.channels.map((c) => lastSegment(c.name)).toSorted(),
      triggers: names(triggers.triggers),
      packages: names(packages.packages),
      subscriptions: names(subs.subscriptions),
      topics: names(topics.topics),
      queues: names(queues.queues),
      services: enabledBefore,
      iam: iamPolicyOf(iamBefore),
    };
    // The inventory every closure compares against must be complete: a bucket that cannot be listed to its end stops the run
    // before anything is created.
    sourceObjectsBefore = await sourceObjects("preflight");
    if (Object.values(sourceObjectsBefore).some((listed) => !Array.isArray(listed)))
      return "source-buckets";
    out.inventory.before.sourceObjects = {
      uploads: sourceObjectsBefore[sourceBuckets(projectNumber)[0]],
      sources: sourceObjectsBefore[sourceBuckets(projectNumber)[1]],
    };
    const ownPackagesPresent = packages.packages.some((p) =>
      ownPackages(runId).includes(lastSegment(p.name)),
    );
    const ownTriggers = triggers.triggers.some((t) =>
      FNS.some((fn) => String(t.name).includes("/" + fn + "-")),
    );
    const ownQueues = queues.queues.some((qe) => QUEUES.includes(lastSegment(qe.name)));
    if (!nonePresent(summarize(before, runId)) || ownPackagesPresent || ownTriggers || ownQueues)
      return "namespace";
    await pollLogs("preflight");
    // Every read-only check must have passed before anything is created: a read that failed (an unknown answer, a 4xx or
    // 5xx on a baseline, a log poll that gave no entries list) stops the run here.
    if (incompleteReads.length > 0 || counts().unknown > 0) return "preflight-reads";
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

  async function deploy() {
    for (const fn of FNS) {
      for (const [kind, label, name] of [
        ["function", "function-" + fn, functionName(fn)],
        ["queue", "queue-" + fn, queueName(fn)],
      ]) {
        issued.add(label);
        cliLabels.set(label, name);
        await save({ id: "issue-" + label, state: "issued", kind, name, transport: "cli" });
      }
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
      out.ready = complete(found) ? summarize(found, runId) : null;
      if (out.ready && allActive(out.ready)) return true;
      if (poll < polls) await pause(wait.ready);
    }
    return false;
  }

  /** The function readbacks: the URI and the identity the tasks need. */
  async function readbacks() {
    await pause(wait.propagation);
    const targets = {};
    for (const role of ROLE_IDS) {
      const fn = functionOfRole(runId, role);
      const a = await read({
        id: "readback-function-" + fn,
        method: "GET",
        url: GCF + functionName(fn),
      });
      if (a?.status === 200 && readable(a)) {
        out.readbacks[fn] = {
          state: a.json.state ?? null,
          uri: a.json.serviceConfig?.uri ?? null,
          taskQueue: a.json.labels ? Object.keys(a.json.labels).toSorted() : [],
        };
        if (a.json.serviceConfig?.uri && a.json.serviceConfig?.serviceAccountEmail)
          targets[role] = {
            uri: a.json.serviceConfig.uri,
            serviceAccountEmail: a.json.serviceConfig.serviceAccountEmail,
          };
      }
    }
    guard.setTargets(targets);
    return targets;
  }

  /** The program: one request per step, in order. A 4xx is an answer; a 5xx or no answer is an unknown mutation. */
  async function runProgram(targets) {
    for (const spec of PROGRAM) {
      if (signal.aborted) throw new BudgetError("stopped by a signal");
      if (spec.pauseBefore) await pause(spec.pauseBefore);
      const request = materialize(spec, { runId, now: clock(), targets });
      const dispatchedAt = clock();
      const mutation = spec.kind === "create" || spec.kind === "delete";
      if (spec.kind === "create")
        await save({
          id: "issue-task-" + spec.key,
          state: "issued",
          kind: "task",
          name: request.json?.task?.name ?? null,
          transport: "rest",
        });
      const id = "step-" + spec.key;
      const answer = mutation
        ? await mutate({ id, ...request, observe: true })
        : await read({ id, ...request }, { observe: true });
      out.program[spec.key] = {
        kind: spec.kind,
        sent: true,
        class: answerClass(answer),
        status: answer?.status ?? null,
        dispatchedAt,
        answeredAt: clock(),
        answer: answerSummary(answer),
      };
      if (
        answer?.status === 403 &&
        !MAY_FORBID.has(spec.key) &&
        spec.kind !== "get-queue" &&
        spec.kind !== "get-task"
      ) {
        out.stoppedBecause = `the step ${spec.key} was answered 403`;
        throw new BudgetError(out.stoppedBecause);
      }
      await pause(wait.gap);
    }
  }

  const expectedStarts = () => {
    const want = {};
    for (const [key, step] of Object.entries(out.program))
      if (step.sent && step.kind === "create" && step.class === "2xx") {
        const n = minStarts(key);
        if (n > 0) want[key] = n;
      }
    return want;
  };
  const startsSeen = () => {
    const seen = {};
    for (const { frame } of allFrames)
      if (frame.kind === "start") seen[frame.case] = (seen[frame.case] ?? 0) + 1;
    return seen;
  };

  async function observe() {
    const want = expectedStarts();
    const steps = Math.max(1, Math.ceil(wait.window / wait.logPoll));
    for (let step = 1; step <= steps; step++) {
      await pause(Math.min(wait.logPoll, wait.window - (step - 1) * wait.logPoll));
      await pollLogs("observe-" + step);
      const seen = startsSeen();
      if (Object.entries(want).every(([key, n]) => (seen[key] ?? 0) >= n)) break;
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
    let found = null;
    const settled = () => complete(found ?? {}) && nonePresent(summarize(found, runId));
    // The public invoker the CLI gives an HTTP function is not expected on a task queue function: each service of the run is
    // read before the function goes, and a public member is recorded as a finding (nothing is written to a policy).
    out.cleanup.invoker = {};
    if (cliLabels.size > 0)
      await step("invoker-read", async () => {
        const listed = await functionLists("cleanup-invoker");
        const present = new Set((listed.run?.services ?? []).map((svc) => lastSegment(svc.name)));
        for (const fn of FNS.filter((name) => present.has(name))) {
          const policy = await read(
            {
              id: `cleanup-invoker-policy-${fn}`,
              method: "GET",
              url: `https://run.googleapis.com/v2/projects/${PROJECT}/locations/${REGION}/services/${fn}:getIamPolicy`,
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
          out.cleanup.invoker[fn] = {
            invokers: bindings
              .filter((b) => b?.role === "roles/run.invoker")
              .flatMap(members)
              .toSorted(),
            allUsers: bindings.some((b) => members(b).includes("allUsers")),
          };
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
      const left = summarize(found, runId);
      for (const fn of FNS) {
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
    // The queues the CLI makes (its function delete removes them): a leftover is deleted once, after a fresh list shows it.
    const queuesLeft = await step("queues-list", () =>
      list("cleanup-queues", TASKS + "?pageSize=500", "queues"),
    );
    for (const qe of queuesLeft?.queues ?? []) {
      const id = lastSegment(qe.name);
      if (!FNS.includes(id)) continue;
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
    // The images the deploy left in Artifact Registry: this run's own packages, found by a fresh list, deleted once.
    const packagesFound = await step("packages-list", () =>
      list("cleanup-packages", REGISTRY + "?pageSize=100", "packages"),
    );
    out.cleanup.packagesDeleted = [];
    for (const item of packagesFound?.packages ?? []) {
      const id = lastSegment(item.name);
      if (!ownPackages(runId).includes(id)) continue;
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
    // Read every name back directly. Only a direct read of an absence counts; a name that was not read is not absent.
    const names = [
      ...FNS.map((fn) => ["function-" + fn, GCF + functionName(fn)]),
      ...QUEUES.map((id) => ["queue-" + id, TASKS + "/" + id]),
      ...FNS.flatMap(packageIds).map((id) => ["package-" + id, REGISTRY + "/" + id]),
      ...out.cleanup.uploadObjectsDeleted.map((item, index) => [
        "upload-object-" + (index + 1),
        `https://storage.googleapis.com/storage/v1/b/${item.bucket}/o/${encodeURIComponent(item.name)}`,
      ]),
    ];
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
      finalLists.queues = sorted(queues, "queues");
      finalLists.topics = sorted(topics, "topics");
      finalLists.subscriptions = sorted(subs, "subscriptions");
      finalLists.triggers = sorted(triggers, "triggers");
      finalLists.packages = sorted(packages, "packages");
      out.cleanup.listsEmpty =
        Boolean(queues && topics && subs && triggers && packages && complete(fns)) &&
        !queues.queues.some((x) => QUEUES.includes(lastSegment(x.name))) &&
        !triggers.triggers.some((t) => FNS.some((fn) => String(t.name).includes("/" + fn + "-"))) &&
        !packages.packages.some((x) => ownPackages(runId).includes(lastSegment(x.name))) &&
        nonePresent(summarize(fns, runId));
    });
    // The inventory the run started from, compared by identity with a fresh one: the two Gen2 buckets, the channels, the
    // enabled services (nothing may have been added: the run enables none) and the project IAM (only service-agent additions).
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
      out.inventory.iam = iamPolicyDifferences(out.inventory.before.iam, iamPolicyOf(iamAfter));
      const after = await list("services-after", SERVICES_URL, "services");
      const servicesNow = after ? after.services.map((svc) => svc.config?.name).toSorted() : null;
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
          queues: finalLists.queues ?? null,
          services: servicesNow,
          sourceObjects: {
            uploads: afterBuckets[sourceBuckets(projectNumber)[0]],
            sources: afterBuckets[sourceBuckets(projectNumber)[1]],
          },
        },
        enabled: [],
        kinds: ["channels", "triggers", "subscriptions", "topics", "packages", "queues"],
      });
      const iam = out.inventory.iam;
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
  let programmed = false;
  try {
    const problem = await preflight();
    if (problem) {
      out.outcome = unknownMutations.length > 0 ? "tq-needs-review" : "tq-stopped-clean";
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
      out.outcome = "tq-stopped-clean";
      out.stoppedBecause = "the CLI dry run failed";
      return summary("dry-run", false);
    }
    out.stage = "deploy";
    const ready = await deploy();
    if (ready) {
      out.stage = "readbacks";
      const targets = await readbacks();
      if (Object.keys(targets).length < ROLE_IDS.length) {
        out.stoppedBecause = "a function readback gave no URL or identity";
      } else {
        out.stage = "program";
        programmed = true;
        await runProgram(targets);
        out.stage = "observe";
        await observe();
      }
    }
  } catch (error) {
    if (error instanceof AuthStop) return authStopped();
    if (!(error instanceof BudgetError)) {
      out.stoppedBecause = String(error?.message);
      if (!created && !issued.size) throw error;
    } else out.stoppedBecause ??= error.message;
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
  out.judged = judge({
    runId,
    program: out.program,
    frames: allFrames,
    errors: allErrors,
    projectNumber,
  });
  const completeRun = programmed && !out.stoppedBecause && Object.keys(out.program).length > 0;
  out.outcome =
    !created && !issued.size
      ? "tq-stopped-clean"
      : !out.cleanup.verified
        ? "tq-needs-recovery"
        : open().blocked || out.cleanup.errors
          ? "tq-needs-review"
          : completeRun
            ? "tq-recorded"
            : "tq-incomplete-clean";
  out.stage = "done";
  return summary("done", out.cleanup.verified && completeRun && !out.cleanup.errors);
}
