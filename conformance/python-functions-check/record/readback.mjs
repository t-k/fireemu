// The read-only read-back of a finished (or interrupted) run: every name the run may have created, read directly, and
// every list, with the same allowlist as the recording and every mutation refused. It sends nothing but GETs. It is the
// separate, later read (at least ten minutes after the run's last request) that an unknown answer needs before a close
// row. It judges only absence: a direct read that answers 404 NOT_FOUND. It never settles an unknown CREATE (a 404
// proves nothing about whether the create happened); the command that runs it reads the run's own result for the
// unconfirmed creates and refuses to close while any exist.
import { AuthStop, createCapture, readable } from "../../scheduled-delivery/capture.mjs";
import { nonePresent, summarize } from "./deploy.mjs";
import { createGuard, ownPackages } from "./guard.mjs";
import {
  ALL_FUNCTIONS,
  COLLECTION,
  JOB_IDS,
  PROJECT,
  QUEUE_IDS,
  REGION,
  TOPIC,
  functionName,
  packageIds,
} from "./plan.mjs";
import { absent } from "./run.mjs";
import { documentId, documentUrl, objectName, storageObjectUrl, topicUrl } from "./script.mjs";

export const READBACK_MAX_REQUESTS = 80;
export const SETTLE_MS = 10 * 60 * 1000;

const GCF = "https://cloudfunctions.googleapis.com/v2/";
const SCHEDULER = `https://cloudscheduler.googleapis.com/v1/projects/${PROJECT}/locations/${REGION}/jobs`;
const TASKS = `https://cloudtasks.googleapis.com/v2/projects/${PROJECT}/locations/${REGION}/queues`;
const REGISTRY = `https://artifactregistry.googleapis.com/v1/projects/${PROJECT}/locations/${REGION}/repositories/gcf-artifacts/packages`;

/** Every name of the run with the URL that reads it directly. The object needs the bucket the run recorded. */
export const readbackNames = (runId, bucket) => [
  ...ALL_FUNCTIONS.map((fn) => ["function-" + fn, GCF + functionName(fn)]),
  ...JOB_IDS.map((id) => ["job-" + id, SCHEDULER + "/" + id]),
  ...QUEUE_IDS.map((id) => ["queue-" + id, TASKS + "/" + id]),
  ["topic", topicUrl],
  ["document", documentUrl(documentId(runId))],
  ...(bucket ? [["object", storageObjectUrl(bucket, objectName(runId))]] : []),
  ...ALL_FUNCTIONS.flatMap(packageIds).map((id) => ["package-" + id, REGISTRY + "/" + id]),
];

/** The read-back's allowlist: the recording's, narrowed to GETs that are not mutations. */
export function readbackAllow(runId, projectNumber) {
  const guard = createGuard(runId, projectNumber);
  return (spec) => spec.method === "GET" && guard.allow(spec) && !guard.isMutation(spec);
}

export async function readbackRun({
  runId,
  projectNumber,
  bucket = null,
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
    allow: readbackAllow(runId, projectNumber),
    quotaProject: PROJECT,
    timeoutFor: () => 15_000,
  });
  const out = { runId, names: {}, lists: {}, incompleteReads: [], authStop: null };
  if (!bucket) out.incompleteReads.push({ id: "bucket", status: "unknown" });
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
        out.incompleteReads.push({ id, status: answer?.status ?? null });
        return null;
      }
      items.push(...(answer.json[key] ?? []));
      token = answer.json.nextPageToken ?? "";
      if (!token) return { [key]: items };
    }
    out.incompleteReads.push({ id, status: "more-than-five-pages" });
    return null;
  };
  const last = (item) => String(item.name).split("/").at(-1);
  try {
    for (const [label, url] of readbackNames(runId, bucket)) {
      const answer = await capture({ id: "readback-" + label, method: "GET", url });
      out.names[label] = { status: answer?.status ?? null, absent: absent(answer) };
    }
    const found = {
      v2: await list(
        "list-functions-v2",
        GCF + "projects/" + PROJECT + "/locations/-/functions",
        "functions",
      ),
      run: await list(
        "list-run-services",
        "https://run.googleapis.com/v2/projects/" + PROJECT + "/locations/-/services",
        "services",
      ),
    };
    out.lists.functionsAndServices =
      Boolean(found.v2 && found.run) && nonePresent(summarize(found));
    const jobs = await list("list-jobs", SCHEDULER + "?pageSize=500", "jobs");
    const queues = await list("list-queues", TASKS + "?pageSize=500", "queues");
    const topics = await list(
      "list-topics",
      `https://pubsub.googleapis.com/v1/projects/${PROJECT}/topics?pageSize=1000`,
      "topics",
    );
    const packages = await list("list-packages", REGISTRY + "?pageSize=100", "packages");
    const triggers = await list(
      "list-triggers",
      `https://eventarc.googleapis.com/v1/projects/${PROJECT}/locations/-/triggers`,
      "triggers",
    );
    out.lists.jobs = jobs ? jobs.jobs.map(last).filter((id) => JOB_IDS.includes(id)) : null;
    out.lists.queues = queues
      ? queues.queues.map(last).filter((id) => QUEUE_IDS.includes(id))
      : null;
    out.lists.topics = topics ? topics.topics.map(last).filter((id) => id === TOPIC) : null;
    out.lists.packages = packages
      ? packages.packages.map(last).filter((id) => ownPackages().includes(id))
      : null;
    out.lists.triggers = triggers
      ? triggers.triggers
          .map(last)
          .filter((id) => ALL_FUNCTIONS.some((fn) => id.startsWith(fn + "-")))
      : null;
    if (bucket) {
      const objects = await list(
        "list-objects",
        `https://storage.googleapis.com/storage/v1/b/${bucket}/o?prefix=pycheck%2F&versions=true`,
        "items",
      );
      out.lists.objects = objects ? objects.items.map((item) => item.name) : null;
      const documents = await list(
        "list-documents",
        `https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents/${COLLECTION}?pageSize=100`,
        "documents",
      );
      out.lists.documents = documents ? documents.documents.map(last) : null;
    }
  } catch (error) {
    if (!(error instanceof AuthStop)) throw error;
  }
  const stop = authStop();
  const known = counts();
  out.attempted = known.attempted;
  out.unknown = known.unknown;
  if (stop) out.authStop = stop;
  const namesGone =
    Object.keys(out.names).length === readbackNames(runId, bucket).length &&
    Object.values(out.names).every((n) => n.absent === true);
  const listsGone =
    out.lists.functionsAndServices === true &&
    ["jobs", "queues", "topics", "packages", "triggers", "objects", "documents"].every(
      (key) => Array.isArray(out.lists[key]) && out.lists[key].length === 0,
    );
  out.allAbsent =
    namesGone &&
    listsGone &&
    stop === null &&
    known.unknown === 0 &&
    out.incompleteReads.length === 0;
  return out;
}
