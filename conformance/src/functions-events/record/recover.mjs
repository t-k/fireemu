// The recovery of the v4 run that ended needs-recovery: REST only, no CLI, exact names (recover-targets.mjs).
//   1. for each of the two functions, one at a time: GET it; if a fresh 200 shows it, DELETE it once and poll the
//      operation to done before the next;
//   2. then the Pub/Sub objects (subscriptions first, then the topic): GET; if a fresh 200 shows one, DELETE it once;
//   3. read everything back in both regions: the function, Run and Eventarc lists, the project's subscription and
//      topic lists, the two gcf-artifacts repositories and the primary bucket.
// A DELETE is never retried. An answer that settles nothing (5xx, timeout, 3xx, unreadable) stops the deletes and goes
// to the read-backs; the outcome is then needs-review. Absence is settled only by a 404 of the resource itself or by a
// complete list that does not show it.

import {
  FUNCTION_TARGETS,
  RECOVERY_REGIONS,
  SUBSCRIPTION_TARGETS,
  TOPIC_TARGETS,
} from "./recover-targets.mjs";
import { PRIMARY_BUCKET, PROJECT } from "./script.mjs";

export const OPERATION_POLL_SECONDS = 10;
export const OPERATION_MAX_POLLS = 30;
export const MAX_PAGES = 5;

const spec = (id, method, url, { mutation = false, expect = [200] } = {}) => ({
  id,
  role: "recovery",
  method,
  url,
  auth: "oauth",
  mutation,
  expect,
});
const fnName = (t) => `projects/${PROJECT}/locations/${t.region}/functions/${t.id}`;
const OPERATION = new RegExp(
  `^projects/${PROJECT}/locations/(?:${RECOVERY_REGIONS.join("|")})/operations/[A-Za-z0-9_-]{1,128}$`,
);
const summary = (answer) => ({ status: answer.status ?? null, kind: answer.kind });
const lastSegment = (name) =>
  String(name ?? "")
    .split("/")
    .at(-1);

/** One list of a region, read to the end (at most MAX_PAGES pages); `complete` says whether it was. */
async function readPages(transport, id, url, key) {
  const items = [];
  let page;
  for (let i = 0; i < MAX_PAGES; i += 1) {
    const answer = await transport.request(
      spec(
        id,
        "GET",
        page ? `${url}${url.includes("?") ? "&" : "?"}pageToken=${encodeURIComponent(page)}` : url,
      ),
    );
    if (answer.kind !== "success") return { items, complete: false, status: answer.status ?? null };
    items.push(...(answer.json?.[key] ?? []));
    page = answer.json?.nextPageToken;
    if (!page) return { items, complete: true, status: answer.status };
  }
  return { items, complete: false, status: 200 };
}

const LIST_KINDS = {
  "functions-v1": (r) => [
    `https://cloudfunctions.googleapis.com/v1/projects/${PROJECT}/locations/${r}/functions`,
    "functions",
  ],
  "functions-v2": (r) => [
    `https://cloudfunctions.googleapis.com/v2/projects/${PROJECT}/locations/${r}/functions`,
    "functions",
  ],
  "run-services": (r) => [
    `https://run.googleapis.com/v2/projects/${PROJECT}/locations/${r}/services`,
    "services",
  ],
  "eventarc-triggers": (r) => [
    `https://eventarc.googleapis.com/v1/projects/${PROJECT}/locations/${r}/triggers`,
    "triggers",
  ],
};

/**
 * What the read-backs show, as a pure judgement over the lists. Every list of every region must be complete and
 * empty (the region was empty before the run: the preflight demands it), no Pub/Sub subscription or topic of
 * Eventarc (name starting `eventarc-`) may remain, and neither may a topic of the run (`fe-events-`).
 */
export function residue({ lists, subscriptions, topics }) {
  const remaining = [];
  let complete = true;
  for (const [key, list] of Object.entries(lists)) {
    if (!list.complete) complete = false;
    for (const item of list.items) remaining.push(`${key}: ${lastSegment(item.name)}`);
  }
  for (const [label, list, owned] of [
    ["subscription", subscriptions, (id) => id.startsWith("eventarc-")],
    ["topic", topics, (id) => id.startsWith("eventarc-") || id.startsWith("fe-events-")],
  ]) {
    if (!list.complete) complete = false;
    for (const item of list.items)
      if (owned(lastSegment(item.name))) remaining.push(`${label}: ${lastSegment(item.name)}`);
  }
  return { complete, remaining, settled: complete && remaining.length === 0 };
}

async function deleteFunction({ transport, sleep, record, target }) {
  const key = `${target.region}/${target.id}`;
  const step = { resource: `function ${key}` };
  record.steps.push(step);
  const url = `https://cloudfunctions.googleapis.com/v2/${fnName(target)}`;
  const got = await transport.request(
    spec(`get-function-${target.region}-${target.id}`, "GET", url, { expect: [200, 404] }),
  );
  step.get = summary(got);
  if (got.status === 404 && got.kind === "refusal") {
    step.result = "absent";
    return { stop: false };
  }
  if (got.kind !== "success" || got.status !== 200 || got.json?.name !== fnName(target)) {
    step.result = "unsettled";
    record.problems.push(`${key}: the read did not show the function nor a 404`);
    return { stop: false };
  }
  step.state = got.json.state ?? null;
  const deleted = await transport.request(
    spec(`delete-function-${target.region}-${target.id}`, "DELETE", url, { mutation: true }),
  );
  step.delete = summary(deleted);
  record.deletes += 1;
  if (deleted.kind !== "success") {
    step.result = "delete-unsettled";
    record.problems.push(`${key}: the delete answered ${deleted.status ?? "nothing"}`);
    return { stop: deleted.kind === "unknown" };
  }
  const operation = deleted.json?.name;
  if (typeof operation !== "string" || !OPERATION.test(operation)) {
    step.result = "no-operation";
    record.problems.push(`${key}: the delete answer names no operation of this project`);
    return { stop: true };
  }
  step.operation = operation;
  for (let poll = 1; poll <= OPERATION_MAX_POLLS; poll += 1) {
    const answer = await transport.request(
      spec(
        `poll-operation-${target.region}-${target.id}-${poll}`,
        "GET",
        `https://cloudfunctions.googleapis.com/v2/${operation}`,
      ),
    );
    step.polls = poll;
    if (answer.kind === "success" && answer.json?.done === true) {
      step.operationError = answer.json.error ?? null;
      step.result = answer.json.error ? "operation-failed" : "deleted";
      if (answer.json.error)
        record.problems.push(`${key}: the delete operation ended with an error`);
      return { stop: false };
    }
    if (poll < OPERATION_MAX_POLLS) await sleep(OPERATION_POLL_SECONDS);
  }
  step.result = "operation-pending";
  record.problems.push(
    `${key}: the delete operation was not done after ${OPERATION_MAX_POLLS} polls`,
  );
  return { stop: false };
}

async function deletePubSub({ transport, record, kind, id }) {
  const step = { resource: `${kind} ${id}` };
  record.steps.push(step);
  const url = `https://pubsub.googleapis.com/v1/projects/${PROJECT}/${kind}s/${id}`;
  const expectedName = `projects/${PROJECT}/${kind}s/${id}`;
  const got = await transport.request(
    spec(`get-${kind}-${id}`, "GET", url, { expect: [200, 404] }),
  );
  step.get = summary(got);
  if (got.status === 404 && got.kind === "refusal") {
    step.result = "absent";
    return { stop: false };
  }
  if (got.kind !== "success" || got.status !== 200 || got.json?.name !== expectedName) {
    step.result = "unsettled";
    record.problems.push(`${kind} ${id}: the read did not show it nor a 404`);
    return { stop: false };
  }
  const deleted = await transport.request(
    spec(`delete-${kind}-${id}`, "DELETE", url, { mutation: true }),
  );
  step.delete = summary(deleted);
  record.deletes += 1;
  step.result = deleted.kind === "success" ? "deleted" : "delete-unsettled";
  if (deleted.kind !== "success")
    record.problems.push(`${kind} ${id}: the delete answered ${deleted.status ?? "nothing"}`);
  return { stop: deleted.kind === "unknown" };
}

/** `recover({ transport, sleep, log })`: runs the three parts and returns `{ outcome, record }`. */
export async function recover({ transport, sleep, log = () => {} }) {
  const record = {
    schemaVersion: 1,
    kind: "functions-events-recovery",
    project: PROJECT,
    steps: [],
    deletes: 0,
    problems: [],
    readbacks: null,
  };
  let stop = false;
  for (const target of FUNCTION_TARGETS) {
    if (stop) break;
    log(`function ${target.region}/${target.id}`);
    ({ stop } = await deleteFunction({ transport, sleep, record, target }));
  }
  const pubsub = [
    ...SUBSCRIPTION_TARGETS.map((id) => ({ kind: "subscription", id })),
    ...TOPIC_TARGETS.map((id) => ({ kind: "topic", id })),
  ];
  for (const target of pubsub) {
    if (stop) break;
    log(`${target.kind} ${target.id}`);
    ({ stop } = await deletePubSub({ transport, record, ...target }));
  }
  log("read-backs");
  const lists = {};
  for (const region of RECOVERY_REGIONS)
    for (const [kind, build] of Object.entries(LIST_KINDS)) {
      const [url, key] = build(region);
      lists[`${kind} ${region}`] = await readPages(
        transport,
        `readback-${kind}-${region}`,
        url,
        key,
      );
    }
  const subscriptions = await readPages(
    transport,
    "readback-subscriptions",
    `https://pubsub.googleapis.com/v1/projects/${PROJECT}/subscriptions?pageSize=100`,
    "subscriptions",
  );
  const topics = await readPages(
    transport,
    "readback-topics",
    `https://pubsub.googleapis.com/v1/projects/${PROJECT}/topics?pageSize=100`,
    "topics",
  );
  const repositories = {};
  for (const region of RECOVERY_REGIONS) {
    const answer = await transport.request(
      spec(
        `readback-repository-${region}`,
        "GET",
        `https://artifactregistry.googleapis.com/v1/projects/${PROJECT}/locations/${region}/repositories/gcf-artifacts`,
        { expect: [200, 404] },
      ),
    );
    repositories[region] = {
      ...summary(answer),
      cleanupPolicies: answer.json?.cleanupPolicies
        ? Object.keys(answer.json.cleanupPolicies)
        : null,
    };
  }
  const bucket = await transport.request(
    spec(
      "readback-primary-bucket",
      "GET",
      `https://storage.googleapis.com/storage/v1/b/${PRIMARY_BUCKET}`,
      { expect: [200, 404] },
    ),
  );
  record.readbacks = {
    lists: Object.fromEntries(
      Object.entries(lists).map(([k, v]) => [
        k,
        { count: v.items.length, complete: v.complete, status: v.status },
      ]),
    ),
    subscriptions: { count: subscriptions.items.length, complete: subscriptions.complete },
    topics: { count: topics.items.length, complete: topics.complete },
    repositories,
    primaryBucket: { ...summary(bucket), versioning: bucket.json?.versioning ?? null },
  };
  const left = residue({ lists, subscriptions, topics });
  record.residue = left;
  const outcome = left.settled && record.problems.length === 0 ? "recovered" : "needs-review";
  return { outcome, record };
}
