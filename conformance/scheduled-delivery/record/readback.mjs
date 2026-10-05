// The read-only read-back of a finished (or interrupted) run: every name the run may have created, read directly,
// and every list, with the same allowlist as the recording and every mutation refused. It sends nothing but GETs.
// It is the separate, later read (at least ten minutes after the run's last request) that an unknown answer needs
// before a close row. It judges only absence: a direct read that answers 404 NOT_FOUND.
import { AuthStop, createCapture, readable } from "../capture.mjs";
import { nonePresent, summarize } from "./deploy.mjs";
import { createGuard } from "./guard.mjs";
import {
  ALL_FUNCTIONS,
  EXTRA_JOBS,
  FUNCTIONS,
  PROJECT,
  REGION,
  extraJobId,
  functionName,
  pullSubscriptionId,
  scheduleId,
} from "./plan.mjs";
import { absent } from "./run.mjs";

export const READBACK_MAX_REQUESTS = 60;
export const SETTLE_MS = 10 * 60 * 1000;

const GCF = "https://cloudfunctions.googleapis.com/";
const SCHEDULER =
  "https://cloudscheduler.googleapis.com/v1/projects/" + PROJECT + "/locations/" + REGION + "/jobs";
const PUBSUB = "https://pubsub.googleapis.com/v1/projects/" + PROJECT;

/** Every name of the run with the URL that reads it directly. */
export const readbackNames = (runId) => [
  ...ALL_FUNCTIONS.map((fn) => [
    "function-" + fn,
    GCF + (FUNCTIONS.v1.includes(fn) ? "v1/" : "v2/") + functionName(fn),
  ]),
  ...ALL_FUNCTIONS.map((fn) => ["job-" + fn, SCHEDULER + "/" + scheduleId(fn)]),
  ...EXTRA_JOBS.map((job) => ["job-" + job.key, SCHEDULER + "/" + extraJobId(runId, job.key)]),
  ...FUNCTIONS.v1.map((fn) => ["topic-" + fn, PUBSUB + "/topics/" + scheduleId(fn)]),
  ...FUNCTIONS.v1.map((fn) => [
    "subscription-" + fn,
    PUBSUB + "/subscriptions/" + pullSubscriptionId(runId, fn),
  ]),
];

/** The read-back's allowlist: the recording's, narrowed to GETs that are not mutations. */
export function readbackAllow(runId, projectNumber) {
  const guard = createGuard(runId, projectNumber);
  return (spec) => spec.method === "GET" && guard.allow(spec) && !guard.isMutation(spec);
}

export async function readbackRun({
  runId,
  projectNumber,
  accessToken,
  save,
  send,
  clock = Date.now,
}) {
  const { capture, counts, authStop } = createCapture({
    accessToken,
    save,
    send,
    clock,
    maxRequests: READBACK_MAX_REQUESTS,
    maxRequestCap: READBACK_MAX_REQUESTS,
    // Only reads: a request the recording's allowlist knows as a mutation is refused here.
    allow: readbackAllow(runId, projectNumber),
    quotaProject: PROJECT,
    timeoutFor: () => 15_000,
  });
  const out = { runId, names: {}, lists: {}, incompleteReads: [], authStop: null };
  const unreadable = (id, answer) =>
    out.incompleteReads.push({ id, status: answer?.status ?? null });
  const list = async (id, url, key) => {
    const items = [];
    let token = "";
    for (let page = 0; page < 5; page++) {
      const answer = await capture({
        id: id + (page ? "-page-" + (page + 1) : ""),
        method: "GET",
        url:
          url +
          (token ? (url.includes("?") ? "&" : "?") + "pageToken=" + encodeURIComponent(token) : ""),
      });
      if (!(answer?.status === 200 && readable(answer))) {
        unreadable(id, answer);
        return null;
      }
      items.push(...(answer.json[key] ?? []));
      token = answer.json.nextPageToken ?? "";
      if (!token) return { [key]: items };
    }
    out.incompleteReads.push({ id, status: "more-than-five-pages" });
    return null;
  };
  try {
    for (const [label, url] of readbackNames(runId)) {
      const answer = await capture({ id: "readback-" + label, method: "GET", url });
      out.names[label] = { status: answer?.status ?? null, absent: absent(answer) };
    }
    const found = {
      v1: await list(
        "list-functions-v1",
        GCF + "v1/projects/" + PROJECT + "/locations/-/functions",
        "functions",
      ),
      v2: await list(
        "list-functions-v2",
        GCF + "v2/projects/" + PROJECT + "/locations/-/functions",
        "functions",
      ),
      run: await list(
        "list-run-services",
        "https://run.googleapis.com/v2/projects/" + PROJECT + "/locations/-/services",
        "services",
      ),
    };
    out.lists.functionsAndServices =
      Boolean(found.v1 && found.v2 && found.run) && nonePresent(summarize(found));
    const jobs = await list("list-jobs", SCHEDULER + "?pageSize=500", "jobs");
    const topics = await list("list-topics", PUBSUB + "/topics?pageSize=1000", "topics");
    const subs = await list(
      "list-subscriptions",
      PUBSUB + "/subscriptions?pageSize=1000",
      "subscriptions",
    );
    const own = (items, ids) =>
      items.map((item) => String(item.name).split("/").at(-1)).filter((id) => ids.includes(id));
    const jobIds = [
      ...ALL_FUNCTIONS.map(scheduleId),
      ...EXTRA_JOBS.map((j) => extraJobId(runId, j.key)),
    ];
    out.lists.jobs = jobs ? own(jobs.jobs, jobIds) : null;
    out.lists.topics = topics ? own(topics.topics, FUNCTIONS.v1.map(scheduleId)) : null;
    out.lists.subscriptions = subs
      ? own(
          subs.subscriptions,
          FUNCTIONS.v1.map((fn) => pullSubscriptionId(runId, fn)),
        )
      : null;
  } catch (error) {
    if (!(error instanceof AuthStop)) throw error;
  }
  const stop = authStop();
  const known = counts();
  out.attempted = known.attempted;
  out.unknown = known.unknown;
  if (stop) out.authStop = stop;
  const namesGone =
    Object.keys(out.names).length === readbackNames(runId).length &&
    Object.values(out.names).every((n) => n.absent === true);
  const listsGone =
    out.lists.functionsAndServices === true &&
    [out.lists.jobs, out.lists.topics, out.lists.subscriptions].every(
      (l) => Array.isArray(l) && l.length === 0,
    );
  out.allAbsent =
    namesGone &&
    listsGone &&
    stop === null &&
    known.unknown === 0 &&
    out.incompleteReads.length === 0;
  return out;
}
