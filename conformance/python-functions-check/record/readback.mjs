// The read-only read-back of a finished (or interrupted) run: every name the run may have created, read directly, and
// every list, with the same allowlist as the recording and every mutation refused. It sends nothing but GETs. It is the
// separate, later read (at least ten minutes after the run's last request) that an unknown answer needs before a close
// row. It judges only absence: a direct read that answers 404 NOT_FOUND. It never settles an unknown CREATE (a 404
// proves nothing about whether the create happened); the command that runs it reads the run's own result for the
// unconfirmed creates and refuses to close while any exist.
import { AuthStop, createCapture, readable } from "../../scheduled-delivery/capture.mjs";
import { iamPolicyDifferences, inventoryDifferences, nonePresent, summarize } from "./deploy.mjs";
import { createGuard, ownPackages } from "./guard.mjs";
import {
  ALL_FUNCTIONS,
  COLLECTION,
  JOB_IDS,
  PROJECT,
  QUEUE_IDS,
  REGION,
  CHANNEL,
  TOPIC,
  sourceBuckets,
  functionName,
  packageIds,
} from "./plan.mjs";
import { absent, iamPolicyOf } from "./run.mjs";
import { documentId, documentUrl, objectName, storageObjectUrl, topicUrl } from "./script.mjs";

export const READBACK_MAX_REQUESTS = 130;
export const SETTLE_MS = 10 * 60 * 1000;

const GCF = "https://cloudfunctions.googleapis.com/v2/";
const SCHEDULER = `https://cloudscheduler.googleapis.com/v1/projects/${PROJECT}/locations/${REGION}/jobs`;
const TASKS = `https://cloudtasks.googleapis.com/v2/projects/${PROJECT}/locations/${REGION}/queues`;
const CHANNEL_URL = `https://eventarc.googleapis.com/v1/projects/${PROJECT}/locations/${REGION}/channels/${CHANNEL}`;
const REGISTRY = `https://artifactregistry.googleapis.com/v1/projects/${PROJECT}/locations/${REGION}/repositories/gcf-artifacts/packages`;

/** Every name of the run with the URL that reads it directly. The object needs the bucket the run recorded. */
/** The source objects the run deleted, as `{ bucket, name }` entries from its result, kept only when they are well formed. */
export const uploadObjectEntries = (list) =>
  (Array.isArray(list) ? list : []).filter(
    (item) => typeof item?.bucket === "string" && typeof item?.name === "string",
  );

export const readbackNames = (runId, bucket, uploadObjects = [], channel = {}) => [
  ...ALL_FUNCTIONS.map((fn) => ["function-" + fn, GCF + functionName(fn)]),
  ...JOB_IDS.map((id) => ["job-" + id, SCHEDULER + "/" + id]),
  ...QUEUE_IDS.map((id) => ["queue-" + id, TASKS + "/" + id]),
  ["topic", topicUrl],
  ["document", documentUrl(documentId(runId))],
  ...(bucket ? [["object", storageObjectUrl(bucket, objectName(runId))]] : []),
  ...(channel?.ownedByRun
    ? [
        ["channel", CHANNEL_URL],
        ...(typeof channel.topic === "string" &&
        /^eventarc-channel-us-central1-firebase-[0-9]+$/.test(channel.topic)
          ? [
              [
                "channel-topic",
                `https://pubsub.googleapis.com/v1/projects/${PROJECT}/topics/${channel.topic}`,
              ],
            ]
          : []),
      ]
    : []),
  ...ALL_FUNCTIONS.flatMap(packageIds).map((id) => ["package-" + id, REGISTRY + "/" + id]),
  ...uploadObjectEntries(uploadObjects).map((item, index) => [
    "upload-object-" + (index + 1),
    `https://storage.googleapis.com/storage/v1/b/${item.bucket}/o/${encodeURIComponent(item.name)}`,
  ]),
];

const IAM_READ = `https://cloudresourcemanager.googleapis.com/v1/projects/${PROJECT}:getIamPolicy`;

/**
 * The read-back's allowlist: the recording's, narrowed to GETs that are not mutations, and the one project IAM policy read
 * (a POST that changes nothing).
 */
export function readbackAllow(runId, projectNumber, uploadObjects = []) {
  const guard = createGuard(runId, projectNumber);
  for (const item of uploadObjectEntries(uploadObjects)) guard.adoptObject(item.bucket, item.name);
  return (spec) =>
    (spec.method === "GET" || (spec.method === "POST" && spec.url === IAM_READ)) &&
    guard.allow(spec) &&
    !guard.isMutation(spec);
}

export async function readbackRun({
  runId,
  projectNumber,
  bucket = null,
  uploadObjects = [],
  baseline = null,
  enabled = [],
  channel = {},
  carried = [],
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
    allow: readbackAllow(runId, projectNumber, uploadObjects),
    quotaProject: PROJECT,
    timeoutFor: () => 15_000,
  });
  const out = { runId, names: {}, lists: {}, incompleteReads: [], authStop: null, carried };
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
    for (const [label, url] of readbackNames(runId, bucket, uploadObjects, channel)) {
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
    // The inventory the run started from, compared by identity with a fresh one (the closure rule of the recording).
    const subs = await list(
      "list-subscriptions",
      `https://pubsub.googleapis.com/v1/projects/${PROJECT}/subscriptions?pageSize=1000`,
      "subscriptions",
    );
    const channels = await list(
      "list-channels",
      `https://eventarc.googleapis.com/v1/projects/${PROJECT}/locations/${REGION}/channels`,
      "channels",
    );
    const services = await list(
      "list-services",
      `https://serviceusage.googleapis.com/v1/projects/${projectNumber}/services?filter=state:ENABLED&pageSize=200`,
      "services",
    );
    const iamNow = await capture({ id: "read-iam", method: "POST", url: IAM_READ, json: {} });
    const notifications = bucket
      ? await list(
          "list-notifications",
          `https://storage.googleapis.com/storage/v1/b/${bucket}/notificationConfigs`,
          "items",
        )
      : null;
    const bucketNames = {};
    for (const [index, name] of sourceBuckets(projectNumber).entries()) {
      const label = index === 0 ? "uploads" : "sources";
      const listed = await list(
        "list-" + label,
        `https://storage.googleapis.com/storage/v1/b/${name}/o?maxResults=1000`,
        "items",
      );
      bucketNames[label] = listed ? listed.items.map((item) => item.name).toSorted() : null;
    }
    const names = (listed, key) =>
      listed ? listed[key].map((item) => item.name).toSorted() : null;
    const after = {
      channels: channels ? channels.channels.map(last).toSorted() : null,
      triggers: names(triggers, "triggers"),
      subscriptions: names(subs, "subscriptions"),
      topics: names(topics, "topics"),
      packages: names(packages, "packages"),
      services: services ? services.services.map((svc) => svc.config?.name).toSorted() : null,
      notifications: notifications ? notifications.items.map((item) => item.id).toSorted() : null,
      sourceObjects: bucketNames,
    };
    if (baseline) {
      const compared = inventoryDifferences({ before: baseline, after, enabled });
      // Project IAM may only have gained service-account members since the preflight.
      const iam = iamPolicyDifferences(baseline.iam, iamPolicyOf(iamNow));
      out.inventory = {
        baseline: true,
        complete: compared.complete && iam.complete,
        missing: [...compared.missing, ...(iam.complete ? [] : ["iam"])],
        differences: [
          ...compared.differences,
          ...iam.unexpected.map((what) => ({ kind: "iam", what })),
        ],
      };
    } else
      out.inventory = { baseline: false, complete: false, missing: ["baseline"], differences: [] };
  } catch (error) {
    if (!(error instanceof AuthStop)) throw error;
  }
  const stop = authStop();
  const known = counts();
  out.attempted = known.attempted;
  out.unknown = known.unknown;
  if (stop) out.authStop = stop;
  const namesGone =
    Object.keys(out.names).length === readbackNames(runId, bucket, uploadObjects, channel).length &&
    Object.values(out.names).every((n) => n.absent === true);
  const listsGone =
    out.lists.functionsAndServices === true &&
    ["jobs", "queues", "topics", "packages", "triggers", "objects", "documents"].every(
      (key) => Array.isArray(out.lists[key]) && out.lists[key].length === 0,
    );
  const inventoryClean =
    out.inventory?.baseline === true &&
    out.inventory.complete === true &&
    out.inventory.differences.length === 0;
  // Every obligation the run left open (an unconfirmed upload, an unexplained object, a difference or an unreadable part of
  // its inventory, a configuration it could not restore) is carried: a read-back that finds nothing there cannot settle it.
  const carriedClear = Array.isArray(carried) && carried.length === 0;
  out.allAbsent =
    carriedClear &&
    namesGone &&
    listsGone &&
    inventoryClean &&
    stop === null &&
    known.unknown === 0 &&
    out.incompleteReads.length === 0;
  return out;
}
