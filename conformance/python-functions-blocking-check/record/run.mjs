// The orchestrator of the blocking check: preflight, the CLI dry run, one deploy of one function, readiness, the readbacks
// (the function, its public invoker, the registered trigger), one sign-up, a bounded wait for the frames, and a cleanup that
// removes only what this run created, reads every name back, and compares the Identity Platform configuration with the one
// read before the deploy. A difference is a failed cleanup: the run does not close and the read-back (A2) decides.
//
// Safety rules (the same as the events recorder): every name is journaled as `issued` before the request that creates it; a
// mutation answer is classified, an unknown one is never re-sent and never closed; a 401, or a 403 on a write, stops the run;
// the CLI runs at most once per action; a leftover function is deleted through REST once, after a complete fresh list shows
// it. The recorder never writes the Identity Platform configuration: the CLI registers the trigger on deploy and removes it
// on delete, and this run only reads.
//
// Settlement (coordinator rulings of 2026-10-05): an unknown CREATE settles only by an own 2xx read showing the name; a 404
// never settles it. The sign-up's answer, when unknown, cannot be read back (the account id is unknown), so it stays
// unconfirmed and the account count before and after is the evidence the read-back looks at.
import { createHash } from "node:crypto";
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
  cliFailed,
  isActive,
  iamPolicyDifferences,
  inventoryDifferences,
  isGone,
  putClass,
  summarize,
  supportedIamPolicy,
} from "./deploy.mjs";
import { createGuard, ownPackages, withoutPublicMember } from "./guard.mjs";
import { judge } from "./judge.mjs";
import { errorFilter, frameFilter, listRequest, parseErrors, parseFrames } from "./logs.mjs";
import {
  CONFIG_URL,
  DELIVERY_WINDOW_SECONDS,
  FUNCTION,
  LOG_DELAY_SECONDS,
  PROJECT,
  PROPAGATION_WAIT_SECONDS,
  REGION,
  REQUIRED_SERVICES,
  functionName,
  packageIds,
  isOwnUploadObject,
  sourceBuckets,
  uploadBucket,
} from "./plan.mjs";
import { countAccounts, deleteAccount, emailOf, lookupAccount, signUp } from "./script.mjs";

const BLOCKING_INVENTORY_KINDS = ["triggers", "subscriptions", "topics", "packages"];

export const NORMAL_CEILING = 150;
export const CLEANUP_CEILING = 100;
export const MAX_REQUESTS = NORMAL_CEILING + CLEANUP_CEILING;
export const LOG_POLL_SECONDS = 60;
const GCF = "https://cloudfunctions.googleapis.com/v2/";
const RUN = `https://run.googleapis.com/v2/projects/${PROJECT}/locations/${REGION}/services/${FUNCTION}`;
const REGISTRY = `https://artifactregistry.googleapis.com/v1/projects/${PROJECT}/locations/${REGION}/repositories/gcf-artifacts`;
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

/**
 * The configuration with an empty blocking section (absent, `{}` or an empty `triggers` map) taken out: the CLI may leave
 * any of the three after it removes its trigger, and they mean the same. Every other difference stays one.
 */
export function normalizedConfig(config) {
  if (!isObject(config)) return config;
  const copy = { ...config };
  if (emptyBlocking(copy)) delete copy.blockingFunctions;
  return copy;
}

/** The top-level keys of the Identity Platform configuration that differ between two reads (empty blocking sections being equal), or null when one cannot be compared. */
export function configDifference(before, after) {
  if (!(before?.status === 200 && readable(before) && after?.status === 200 && readable(after)))
    return null;
  const a = normalizedConfig(before.json);
  const b = normalizedConfig(after.json);
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  return [...keys].filter((k) => JSON.stringify(a[k]) !== JSON.stringify(b[k])).toSorted();
}

/**
 * Whether the configuration's blocking section is the empty baseline (coordinator ruling R2): absent, `{}`, or a section
 * with an empty `triggers` map and/or a `forwardInboundCredentials` that forwards nothing (absent, `{}` or all members
 * false). The CLI writes `forwardInboundCredentials` when it registers its trigger and leaves it when it removes it; none of
 * these forms changes what the project does. A trigger left, a member set to true, or any other key is not the baseline.
 */
export const emptyBlocking = (config) => {
  const section = config?.blockingFunctions;
  if (section === undefined) return true;
  if (!isObject(section)) return false;
  if (Object.keys(section).some((key) => key !== "triggers" && key !== "forwardInboundCredentials"))
    return false;
  const triggers = section.triggers;
  if (triggers !== undefined && !(isObject(triggers) && Object.keys(triggers).length === 0))
    return false;
  const forward = section.forwardInboundCredentials;
  return (
    forward === undefined || (isObject(forward) && Object.values(forward).every((v) => v === false))
  );
};
const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/** A digest of a configuration body (the key order of the API's answer), so that the read-back can compare without keeping the body. */
export const configDigest = (config) =>
  createHash("sha256")
    .update(JSON.stringify(normalizedConfig(config)))
    .digest("hex");

class BudgetError extends Error {}

const lastSegment = (name) =>
  String(name ?? "")
    .split("/")
    .at(-1);
const recordsOf = (a) =>
  a?.status === 200 && readable(a) ? Number(a.json.recordsCount ?? 0) : null;

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
    settle: 30,
    operation: 10,
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
  const email = emailOf(runId);
  const out = {
    runId,
    stage: "preflight",
    outcome: "pcblock-needs-review",
    cli: {},
    ready: null,
    readbacks: {},
    signUp: null,
    frames: {},
    framesIgnored: {},
    errorsSeen: 0,
    cleanup: { verified: false },
    inventory: {},
    judged: null,
  };
  const unknownMutations = [];
  const incompleteReads = [];
  const pendingCreates = new Map();
  const confirmed = new Set();
  const ownDeleted = new Set();
  let deployUnknown = null;
  let created = false;
  let stopped = null;
  let functionIssued = false;
  let localId = null;
  const startedAt = clock();
  const frameSeen = new Set();
  const errorSeen = new Set();
  const allFrames = [];
  const allErrors = [];
  let polledUntil = startedAt;
  let iamBefore = null;
  let enabledBefore = null;
  let configBefore = null;
  let accountsBefore = null;
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
  const read = async (spec, { observe: observing = false } = {}) => {
    const answer = await normal(observing ? { ...spec, observe: true } : spec);
    if (isUnknownClass(answer) || (answer.status >= 400 && !observing))
      incompleteReads.push({ id: spec.id, class: answerClass(answer) });
    if (
      answer?.status === 200 &&
      readable(answer) &&
      lastSegment(answer.json.name) === FUNCTION &&
      String(answer.json.name).includes("/functions/")
    )
      confirmed.add("function");
    if (
      answer?.status === 200 &&
      readable(answer) &&
      Array.isArray(answer.json.functions) &&
      answer.json.functions.some((item) => item?.name === functionName())
    )
      confirmed.add("function");
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
    // accepted as CLI behaviour; the at-most-once rule is the recorder's own requests and one CLI call per action.
    // The shared parser's own list (writes to Cloud Functions, Scheduler or Pub/Sub answered 3xx, 5xx or below 200) is honoured
    // too.
    let ambiguous = null;
    for (const [n, write] of (Array.isArray(result?.unknownWrites)
      ? result.unknownWrites
      : []
    ).entries()) {
      ambiguous ??= "cli-unknown-write";
      unknownMutations.push({
        id: `cli-${action}-unknown-write-${n + 1}`,
        class: "cli-unknown-write",
        request: `${write?.method} ${write?.host} ${write?.status}`,
      });
    }
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
            ambiguous ??= "cli-write-unjournaled";
            unknownMutations.push({
              id: `cli-${action}-write-${n}`,
              class: "cli-write-unjournaled",
              request: `${write.method} ${write.url}`,
            });
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
    // A deploy write that was retried, unanswered or not answered 2xx may have created the function whatever the reads show
    // afterwards: the function stays an unconfirmed create until an own read shows it (a 404 never settles it).
    if (action === "deploy" && ambiguous) deployUnknown ??= ambiguous;
    return result;
  };
  const cliDeleteClean = () =>
    Boolean(out.cli.delete) && !cliFailed(out.cli.delete) && !cliUnknownClass(out.cli.delete);
  const uploadUnconfirmed = [];
  const unconfirmedCreates = () => [
    ...[...pendingCreates.values()].filter((create) => !confirmed.has(create.label)),
    ...uploadUnconfirmed,
    ...(deployUnknown && !confirmed.has("function")
      ? [{ label: "function", id: "cli-deploy", name: functionName(), class: deployUnknown }]
      : []),
  ];
  const vanishedAfterCreate = () => {
    const gone = out.cleanup.readBack;
    if (!gone) return [];
    return [...confirmed]
      .filter(
        (label) =>
          gone[label] === true &&
          !ownDeleted.has(label) &&
          !(label === "function" && cliDeleteClean()),
      )
      .toSorted()
      .map((label) => ({ label, class: "vanished-after-create" }));
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
    const unconfirmed = unconfirmedCreates();
    const vanished = vanishedAfterCreate();
    return {
      unconfirmed,
      vanished,
      blocked:
        authStop() !== null ||
        counts().unknown > 0 ||
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
      outcome: stop ? "pcblock-auth-stop" : out.outcome,
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
        out.cleanup.configDifference?.length > 0 ||
        out.cleanup.uploadReasons?.length > 0 ||
        out.cleanup.uploadObjectsUnexplained?.length > 0 ||
        out.inventory.differences?.length > 0 ||
        out.inventory.complete === false ||
        typeof out.cleanup.invoker?.refused === "string",
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

  /** The object names of the two Gen2 source buckets (read-only inventory), or null for one that cannot be read to its end. */
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

  // ---- the phases ------------------------------------------------------------------------------
  async function preflight() {
    const identity = await normal({
      id: "identity",
      method: "GET",
      url: `https://firebase.googleapis.com/v1beta1/projects/${PROJECT}`,
    });
    if (
      !(identity?.status === 200 && readable(identity)) ||
      identity.json.projectId !== PROJECT ||
      String(identity.json.projectNumber) !== String(projectNumber)
    )
      return "identity";
    // The enabled services are read page by page (a project can have more than one page of them).
    const services = await list("services-before", SERVICES_URL, "services");
    if (services === null) return "services";
    const enabled = new Set(services.services.map((s) => s.config?.name));
    out.servicesMissing = REQUIRED_SERVICES.filter((id) => !enabled.has(id));
    enabledBefore = [...enabled].toSorted();
    if (out.servicesMissing.length > 0) return "services";
    iamBefore = await read({
      id: "iam-before",
      method: "POST",
      url: `https://cloudresourcemanager.googleapis.com/v1/projects/${PROJECT}:getIamPolicy`,
      json: {},
    });
    // The project IAM is part of the baseline every closure compares with: a policy that cannot be read stops the run
    // before anything is created.
    if (iamPolicyOf(iamBefore) === null) return "iam";
    configBefore = await read({ id: "config-before", method: "GET", url: CONFIG_URL });
    if (!(configBefore?.status === 200 && readable(configBefore))) return "config";
    if (!emptyBlocking(configBefore.json)) return "blocking-config";
    out.configBefore = {
      sha256: configDigest(configBefore.json),
      blockingFunctions: configBefore.json.blockingFunctions ?? null,
    };
    const count = await read({ ...countAccounts(), id: "accounts-before" });
    accountsBefore = recordsOf(count);
    if (accountsBefore === null) return "accounts";
    const repository = await read(
      { id: "repository", method: "GET", url: REGISTRY },
      { observe: true },
    );
    if (repository?.status !== 200) return "repository";
    const before = await functionLists("preflight");
    if (!complete(before)) return "lists";
    const packages = await list(
      "preflight-packages",
      REGISTRY + "/packages?pageSize=100",
      "packages",
    );
    const triggers = await list(
      "preflight-triggers",
      `https://eventarc.googleapis.com/v1/projects/${PROJECT}/locations/-/triggers`,
      "triggers",
    );
    const subs = await list(
      "preflight-subscriptions",
      `https://pubsub.googleapis.com/v1/projects/${PROJECT}/subscriptions?pageSize=1000`,
      "subscriptions",
    );
    const topics = await list(
      "preflight-topics",
      `https://pubsub.googleapis.com/v1/projects/${PROJECT}/topics?pageSize=1000`,
      "topics",
    );
    if (![packages, triggers, subs, topics].every(Boolean)) return "lists";
    const sortedNames = (listed, key) => listed[key].map((x) => x.name).toSorted();
    out.inventory.before = {
      accounts: accountsBefore,
      iam: iamPolicyOf(iamBefore),
      packages: sortedNames(packages, "packages"),
      triggers: sortedNames(triggers, "triggers"),
      subscriptions: sortedNames(subs, "subscriptions"),
      topics: sortedNames(topics, "topics"),
      services: enabledBefore,
    };
    // The inventory the closure compares against must be complete: a bucket that cannot be listed to its end stops the run
    // before anything is created.
    sourceObjectsBefore = await sourceObjects("preflight");
    if (Object.values(sourceObjectsBefore).some((listed) => !Array.isArray(listed)))
      return "source-buckets";
    out.inventory.before.sourceObjects = {
      uploads: sourceObjectsBefore[sourceBuckets(projectNumber)[0]],
      sources: sourceObjectsBefore[sourceBuckets(projectNumber)[1]],
    };
    const summaryBefore = summarize(before);
    if (
      !isGone(summaryBefore) ||
      packages.packages.some((p) => ownPackages().includes(lastSegment(p.name)))
    )
      return "namespace";
    await pollLogs("preflight");
    // Every read-only check must have passed before anything is created: a read that failed (an unknown answer, a 4xx or
    // 5xx on a baseline, a log poll that gave no entries list) stops the run here.
    if (incompleteReads.length > 0 || counts().unknown > 0) return "preflight-reads";
    return null;
  }

  async function deploy() {
    functionIssued = true;
    await save({
      id: "issue-function",
      state: "issued",
      kind: "function",
      name: functionName(),
      transport: "cli",
    });
    created = true;
    out.cli.deploy = await cli("deploy");
    await save({
      id: "cli-deploy",
      state: "cli-result",
      result: out.cli.deploy,
      responseAt: iso(clock()),
    });
    const polls = cliFailed(out.cli.deploy) ? 2 : wait.readyPolls;
    for (let poll = 1; poll <= polls; poll++) {
      const found = await functionLists("ready-" + poll);
      out.ready = complete(found) ? summarize(found) : null;
      if (out.ready && isActive(out.ready)) return true;
      if (poll < polls) await pause(wait.ready);
    }
    return false;
  }

  /** The function, its service's public invoker, and the trigger the CLI registered in the configuration. */
  async function readbacks() {
    await pause(wait.propagation);
    const fn = await read({ id: "readback-function", method: "GET", url: GCF + functionName() });
    const serviceUri =
      fn?.status === 200 && readable(fn) ? (fn.json.serviceConfig?.uri ?? null) : null;
    if (fn?.status === 200 && readable(fn))
      out.readbacks.function = {
        state: fn.json.state ?? null,
        uri: serviceUri,
        url: typeof fn.json.url === "string" ? fn.json.url : null,
        serviceAccount: fn.json.serviceConfig?.serviceAccountEmail ?? null,
        blockingTrigger: isObject(fn.json.eventTrigger) ? fn.json.eventTrigger : null,
      };
    const policy = await read(
      { id: "readback-invoker", method: "GET", url: RUN + ":getIamPolicy" },
      { observe: true },
    );
    const invoker =
      policy?.status === 200 && readable(policy)
        ? (() => {
            const members = (policy.json.bindings ?? [])
              .filter((b) => b.role === "roles/run.invoker")
              .flatMap((b) => b.members ?? []);
            return { members: members.toSorted(), allUsersInvoker: members.includes("allUsers") };
          })()
        : null;
    const config = await read({ id: "config-after-deploy", method: "GET", url: CONFIG_URL });
    const trigger =
      config?.status === 200 && readable(config)
        ? (config.json.blockingFunctions?.triggers?.[BEFORE_CREATE] ?? null)
        : undefined;
    out.readbacks.invoker = invoker;
    const functionUrl = out.readbacks.function?.url ?? null;
    out.readbacks.registration =
      trigger === undefined ? null : { trigger, serviceUri, functionUrl };
    return {
      serviceUri,
      invoker,
      registration: trigger === undefined ? null : { trigger, serviceUri, functionUrl },
    };
  }

  async function operate() {
    const spec = signUp(runId);
    await save({
      id: "issue-account",
      state: "issued",
      kind: "account",
      name: email,
      transport: "rest",
    });
    // The sign-up carries only the browser API key. A 403 on it is the key's refusal and a 401 never comes from the owner's
    // token, so neither is allowed to stop the run before its cleanup: the 403 is data (`observe`), and the 401's stop is
    // caught here (the run is then not closable, but the cleanup is complete).
    let answer;
    let keyRefused = false;
    try {
      answer = await mutate({ id: "op-sign-up", ...spec, observe: true });
    } catch (error) {
      if (!(error instanceof AuthStop)) throw error;
      answer = { status: 401, json: null };
      keyRefused = true;
    }
    const id = answer?.status === 200 && readable(answer) ? answer.json.localId : null;
    out.signUp = {
      class: answerClass(answer),
      status: answer?.status ?? null,
      localId: typeof id === "string" ? id : null,
      ...(keyRefused ? { keyRefused: true } : {}),
    };
    if (answerClass(answer) === "2xx" && typeof id === "string") {
      localId = id;
      guard.adopt(id);
      confirmed.add("account");
    } else if (answerClass(answer) !== "4xx") {
      // No account id came back although the answer was not a refusal: whether an account exists is unknown.
      pendingCreates.set("account", {
        label: "account",
        id: "op-sign-up",
        name: email,
        class: answerClass(answer),
      });
    }
    return out.signUp;
  }

  async function observe() {
    const steps = Math.max(1, Math.ceil(wait.window / wait.logPoll));
    for (let step = 1; step <= steps; step++) {
      await pause(Math.min(wait.logPoll, wait.window - (step - 1) * wait.logPoll));
      await pollLogs("observe-" + step);
      const kinds = new Set(
        allFrames
          .filter(
            ({ frame }) => frame.request?.token?.email === email || frame.data?.email === email,
          )
          .map(({ frame }) => frame.kind),
      );
      if (kinds.has("blocking-raw") && kinds.has("blocking-sdk")) break;
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
    // The account first: the run's own, by the id its sign-up returned, deleted once.
    if (localId !== null)
      await step("account-delete", async () => {
        const answer = await mutate({
          id: "cleanup-account-delete",
          ...deleteAccount(localId),
          cleanup: true,
        });
        if (answerClass(answer) === "2xx") ownDeleted.add("account");
      });
    // The CLI gives a blocking function's Cloud Run service a public invoker (`allUsers` with `roles/run.invoker`). The
    // service's policy is read, that member alone is removed (one write, never re-sent) and read back, before the function
    // is deleted: a delete that fails must not leave a public service. The result keeps what was found.
    out.cleanup.invoker = null;
    if (created)
      await step("invoker-removal", async () => {
        const policy = await read(
          {
            id: "cleanup-invoker-policy",
            method: "GET",
            url: RUN + ":getIamPolicy",
            cleanup: true,
          },
          { observe: true },
        );
        if (!(policy?.status === 200 && readable(policy))) {
          out.cleanup.invoker = { read: answerClass(policy) };
          return;
        }
        const bindings = Array.isArray(policy.json.bindings) ? policy.json.bindings : [];
        const members = (b) => (Array.isArray(b?.members) ? b.members : []);
        const found = {
          invokers: bindings
            .filter((b) => b?.role === "roles/run.invoker")
            .flatMap(members)
            .toSorted(),
          allUsers: bindings.some((b) => members(b).includes("allUsers")),
        };
        out.cleanup.invoker = found;
        if (!found.allUsers) return;
        const plan = withoutPublicMember(policy.json);
        if (!plan.ok) {
          found.refused = plan.why;
          found.removed = false;
          return;
        }
        const answer = await mutate({
          id: "cleanup-remove-invoker",
          method: "POST",
          url: RUN + ":setIamPolicy",
          json: { policy: plan.policy },
          cleanup: true,
        });
        found.removeClass = answerClass(answer);
        const back = await read(
          {
            id: "cleanup-invoker-readback",
            method: "GET",
            url: RUN + ":getIamPolicy",
            cleanup: true,
          },
          { observe: true },
        );
        found.removed =
          back?.status === 200 &&
          readable(back) &&
          !(back.json.bindings ?? []).some((b) => members(b).includes("allUsers"));
      });
    if (created) await step("cli-delete", () => cliDelete());
    let found = null;
    const settled = () => complete(found ?? {}) && isGone(summarize(found));
    await step("project-lists", async () => {
      for (let poll = 1; poll <= 6; poll++) {
        found = await functionLists("cleanup-" + poll);
        if (settled()) break;
        await pause(wait.settle);
      }
    });
    if (complete(found ?? {}) && summarize(found).present) {
      await step("leftover-function", async () => {
        const answer = await mutate({
          id: "leftover-delete-function",
          method: "DELETE",
          url: GCF + functionName(),
          cleanup: true,
        });
        if (answerClass(answer) !== "2xx") return;
        const finished = (op) => op?.json?.done === true && !op.json.error;
        let settledBy = finished(answer);
        let pending = "operation-pending";
        if (!settledBy && typeof answer.json?.name === "string" && !answer.json.done) {
          for (let poll = 0; poll < 12; poll++) {
            await pause(wait.operation);
            const op = await read(
              {
                id: `leftover-operation-${poll + 1}`,
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
        if (settledBy) ownDeleted.add("function");
        else unknownMutations.push({ id: "leftover-delete-function", class: pending });
      });
      await step("after-leftover", async () => {
        for (let poll = 1; poll <= 4; poll++) {
          found = await functionLists("after-leftover-" + poll);
          if (settled()) break;
          await pause(wait.settle);
        }
      });
    }
    out.cleanup.functionGone = Boolean(settled());
    // The function's images: this run's own two ids, found by a fresh list, deleted once.
    const packagesFound = await step("packages-list", () =>
      list("cleanup-packages", REGISTRY + "/packages?pageSize=100", "packages"),
    );
    out.cleanup.packagesDeleted = [];
    for (const item of packagesFound?.packages ?? []) {
      const id = lastSegment(item.name);
      if (!ownPackages().includes(id)) continue;
      await step("package-" + id, async () => {
        const answer = await mutate({
          id: "delete-package-" + id,
          method: "DELETE",
          url: REGISTRY + "/packages/" + id,
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
            await pause(wait.operation);
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
    // An upload whose receipt was never confirmed, whose object could not be read, or that left no readable receipt is an unknown
    // create: a 404 or an unchanged inventory never settles it, and only the read-back with a positive read (or a recovery)
    // closes it.
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
      ["function", GCF + functionName(), "get"],
      ...packageIds().map((id) => ["package-" + id, REGISTRY + "/packages/" + id, "get"]),
      ...out.cleanup.uploadObjectsDeleted.map((item, index) => [
        "upload-object-" + (index + 1),
        `https://storage.googleapis.com/storage/v1/b/${item.bucket}/o/${encodeURIComponent(item.name)}`,
        "get",
      ]),
    ];
    const readBack = Object.fromEntries([
      ...names.map(([label]) => [label, false]),
      ...(localId === null ? [] : [["account", false]]),
    ]);
    out.cleanup.readBack = readBack;
    for (const [label, url] of names)
      await step("readback-" + label, async () => {
        const answer = await read(
          { id: "readback-gone-" + label, method: "GET", url, cleanup: true },
          { observe: true },
        );
        readBack[label] = absent(answer);
      });
    if (localId !== null)
      await step("readback-account", async () => {
        const answer = await read(
          { id: "readback-gone-account", ...lookupAccount(localId), cleanup: true },
          { observe: true },
        );
        readBack.account =
          answer?.status === 200 && readable(answer) && (answer.json.users ?? []).length === 0;
      });
    out.cleanup.listsEmpty = false;
    const finalLists = {};
    await step("final-lists", async () => {
      const fns = await functionLists("final");
      const packages = await list(
        "final-packages",
        REGISTRY + "/packages?pageSize=100",
        "packages",
      );
      const triggers = await list(
        "final-triggers",
        `https://eventarc.googleapis.com/v1/projects/${PROJECT}/locations/-/triggers`,
        "triggers",
      );
      const subs = await list(
        "final-subscriptions",
        `https://pubsub.googleapis.com/v1/projects/${PROJECT}/subscriptions?pageSize=1000`,
        "subscriptions",
      );
      const topics = await list(
        "final-topics",
        `https://pubsub.googleapis.com/v1/projects/${PROJECT}/topics?pageSize=1000`,
        "topics",
      );
      const sorted = (listed, key) => (listed ? listed[key].map((x) => x.name).toSorted() : null);
      finalLists.packages = sorted(packages, "packages");
      finalLists.triggers = sorted(triggers, "triggers");
      finalLists.subscriptions = sorted(subs, "subscriptions");
      finalLists.topics = sorted(topics, "topics");
      out.cleanup.listsEmpty =
        Boolean(complete(fns) && packages) &&
        isGone(summarize(fns)) &&
        !packages.packages.some((x) => ownPackages().includes(lastSegment(x.name)));
    });
    // The configuration, read once more: any difference from the one read before the deploy is a failed cleanup.
    out.cleanup.configDifference = null;
    await step("config-after", async () => {
      const after = await read({
        id: "config-after",
        method: "GET",
        url: CONFIG_URL,
        cleanup: true,
      });
      out.cleanup.configDifference = configDifference(configBefore, after);
      out.cleanup.configAfterEmptyBlocking =
        after?.status === 200 && readable(after) ? emptyBlocking(after.json) : null;
      if (after?.status === 200 && readable(after))
        out.cleanup.blockingForm = {
          before: JSON.stringify(configBefore.json.blockingFunctions ?? null),
          after: JSON.stringify(after.json.blockingFunctions ?? null),
        };
    });
    await step("accounts-after", async () => {
      const count = await read({ ...countAccounts(), id: "accounts-after", cleanup: true });
      out.cleanup.accountsBefore = accountsBefore;
      out.cleanup.accountsAfter = recordsOf(count);
    });
    const accountsSame = out.cleanup.accountsAfter === accountsBefore && accountsBefore !== null;
    out.cleanup.configRestored =
      Array.isArray(out.cleanup.configDifference) &&
      out.cleanup.configDifference.length === 0 &&
      out.cleanup.configAfterEmptyBlocking === true;
    // The inventory the run started from, compared by identity with a fresh one: the two Gen2 buckets, the Eventarc triggers,
    // the Pub/Sub topics and subscriptions, the images, the enabled services (none may be added) and the project IAM (only
    // service-agent additions). Every difference, and every list that could not be read to its end, keeps the cleanup from
    // being verified.
    await step("inventory", async () => {
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
      const compared = inventoryDifferences({
        before: out.inventory.before,
        after: {
          triggers: finalLists.triggers ?? null,
          subscriptions: finalLists.subscriptions ?? null,
          topics: finalLists.topics ?? null,
          packages: finalLists.packages ?? null,
          services: servicesNow,
          sourceObjects: {
            uploads: afterBuckets[sourceBuckets(projectNumber)[0]],
            sources: afterBuckets[sourceBuckets(projectNumber)[1]],
          },
        },
        kinds: BLOCKING_INVENTORY_KINDS,
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
      Object.values(readBack).every((v) => v === true) &&
      out.cleanup.configRestored &&
      accountsSame &&
      !out.cleanup.invoker?.refused;
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
  let observations = {};
  try {
    const problem = await preflight();
    if (problem) {
      out.outcome = "pcblock-stopped-clean";
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
      out.outcome = "pcblock-stopped-clean";
      out.stoppedBecause = "the CLI dry run failed";
      return summary("dry-run", false);
    }
    out.stage = "deploy";
    const ready = await deploy();
    if (ready) {
      out.stage = "readbacks";
      observations = await readbacks();
      out.stage = "sign-up";
      operated = true;
      await operate();
      out.stage = "observe";
      await observe();
    }
  } catch (error) {
    if (error instanceof AuthStop) return authStopped();
    if (!(error instanceof BudgetError)) {
      out.stoppedBecause = String(error?.message);
      if (!created && !functionIssued) throw error;
    } else out.stoppedBecause = error.message;
  }
  if (created || functionIssued || localId !== null) {
    try {
      out.stage = "cleanup";
      await cleanup();
    } catch (error) {
      if (!(error instanceof AuthStop)) throw error;
      return authStopped();
    }
  }
  for (const entry of allFrames)
    out.frames[entry.frame.kind] = (out.frames[entry.frame.kind] ?? 0) + 1;
  out.errorsSeen = allErrors.length;
  out.judged = judge({
    email,
    localId,
    frames: allFrames,
    errors: allErrors,
    mode: "production",
    observed: {
      signUp: out.signUp,
      registration: observations.registration ?? null,
      invoker: observations.invoker ?? null,
    },
  });
  const completeRun = operated && !out.stoppedBecause && out.signUp !== null;
  out.outcome =
    !created && !functionIssued && localId === null
      ? "pcblock-stopped-clean"
      : !out.cleanup.verified
        ? "pcblock-needs-recovery"
        : open().blocked || out.cleanup.errors
          ? "pcblock-needs-review"
          : completeRun
            ? "pcblock-recorded"
            : "pcblock-incomplete-clean";
  out.stage = "done";
  return summary("done", out.cleanup.verified && completeRun && !out.cleanup.errors);
}

const BEFORE_CREATE = "beforeCreate";
