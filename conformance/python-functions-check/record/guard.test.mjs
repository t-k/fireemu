// The allowlist: every request the check sends is allowed and classified, and anything outside the run's own names,
// shapes and projects is refused (the allowlist is what keeps a bug in the recorder from touching anything else).
import assert from "node:assert/strict";
import test from "node:test";
import { createGuard, matchRule, ownPackages, rules } from "./guard.mjs";
import {
  ALL_FUNCTIONS,
  JOB_IDS,
  PROJECT,
  QUEUE_IDS,
  TOPIC,
  packageIds,
  runMarker,
} from "./plan.mjs";
import { listRequest, frameFilter } from "./logs.mjs";
import {
  documentId,
  documentUrl,
  objectName,
  operations,
  storageObjectUrl,
  topicUrl,
  undoOperations,
} from "./script.mjs";

const RUN = "0123456789abcdef";
const NUMBER = "123456789012";
const BUCKET = PROJECT + ".firebasestorage.app";
const guard = createGuard(RUN, NUMBER);
const targets = Object.fromEntries(
  ALL_FUNCTIONS.map((fn) => [
    fn,
    {
      uri: `https://${fn}-abc-uc.a.run.app`,
      serviceAccountEmail: "1-compute@developer.gserviceaccount.com",
    },
  ]),
);
const R = `https://cloudfunctions.googleapis.com/v2/projects/${PROJECT}/locations/us-central1`;
const get = (url) => ({ method: "GET", url });

test("every source operation is allowed and is a mutation", () => {
  const ops = operations({ runId: RUN, bucket: BUCKET, targets });
  assert.equal(ops.length, 11);
  for (const op of ops) {
    assert.equal(guard.allow({ id: op.key, ...op.request }), true, op.key);
    assert.equal(guard.isMutation({ id: op.key, ...op.request }), true, op.key);
  }
  for (const op of undoOperations({ runId: RUN, bucket: BUCKET })) {
    assert.equal(guard.allow({ id: op.key, ...op.request }), true, op.key);
    assert.equal(guard.isMutation(op.request), true);
  }
});

test("the setup, readbacks, lists and cleanup requests are allowed, and only the deletes and creates are mutations", () => {
  const mutating = [
    { method: "PUT", url: topicUrl, json: {} },
    { method: "DELETE", url: topicUrl },
    { method: "DELETE", url: `${R}/functions/pcps` },
    {
      method: "DELETE",
      url: `https://cloudscheduler.googleapis.com/v1/projects/${PROJECT}/locations/us-central1/jobs/${JOB_IDS[0]}`,
    },
    {
      method: "DELETE",
      url: `https://cloudtasks.googleapis.com/v2/projects/${PROJECT}/locations/us-central1/queues/${QUEUE_IDS[0]}`,
    },
    ...ownPackages().map((id) => ({
      method: "DELETE",
      url: `https://artifactregistry.googleapis.com/v1/projects/${PROJECT}/locations/us-central1/repositories/gcf-artifacts/packages/${id}`,
    })),
  ];
  for (const spec of mutating) {
    assert.equal(guard.allow(spec), true, spec.method + " " + spec.url);
    assert.equal(guard.isMutation(spec), true, spec.method + " " + spec.url);
  }
  const reads = [
    `https://firebaserules.googleapis.com/v1/projects/${PROJECT}/releases/cloud.firestore`,
    `https://serviceusage.googleapis.com/v1/projects/${NUMBER}/services?filter=state:ENABLED&pageSize=200`,
    `https://firebase.googleapis.com/v1beta1/projects/${PROJECT}/adminSdkConfig`,
    `https://appengine.googleapis.com/v1/apps/${PROJECT}`,
    `${R}/functions`,
    `https://cloudfunctions.googleapis.com/v2/projects/${PROJECT}/locations/-/functions?pageToken=abc`,
    `${R}/functions/pcps`,
    `${R}/operations/operation-1234-abcd`,
    `https://run.googleapis.com/v2/projects/${PROJECT}/locations/-/services`,
    `https://eventarc.googleapis.com/v1/projects/${PROJECT}/locations/-/triggers`,
    `https://eventarc.googleapis.com/v1/projects/${PROJECT}/locations/us-central1/channels`,
    `https://artifactregistry.googleapis.com/v1/projects/${PROJECT}/locations/us-central1/repositories/gcf-artifacts/packages?pageSize=100`,
    `https://cloudscheduler.googleapis.com/v1/projects/${PROJECT}/locations/us-central1/jobs?pageSize=500`,
    `https://cloudtasks.googleapis.com/v2/projects/${PROJECT}/locations/us-central1/queues?pageSize=500`,
    `https://pubsub.googleapis.com/v1/projects/${PROJECT}/topics?pageSize=1000`,
    `https://pubsub.googleapis.com/v1/projects/${PROJECT}/subscriptions?pageSize=1000`,
    topicUrl,
    `https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents/pycheck-src?pageSize=100`,
    documentUrl(documentId(RUN)),
    `https://storage.googleapis.com/storage/v1/b/${BUCKET}`,
    `https://storage.googleapis.com/storage/v1/b/${BUCKET}/o?prefix=pycheck%2F&versions=true`,
    storageObjectUrl(BUCKET, objectName(RUN)),
  ];
  for (const url of reads) {
    assert.equal(guard.allow(get(url)), true, url);
    assert.equal(guard.isMutation(get(url)), false, url);
  }
  const iam = {
    method: "POST",
    url: `https://cloudresourcemanager.googleapis.com/v1/projects/${PROJECT}:getIamPolicy`,
    json: {},
  };
  assert.equal(guard.allow(iam), true);
  assert.equal(guard.isMutation(iam), false);
  const logs = listRequest({
    id: "x",
    filter: frameFilter({ start: "2026-11-05T00:00:00Z", end: "2026-11-05T00:01:00Z" }),
  });
  assert.equal(guard.allow(logs), true);
  assert.equal(guard.isMutation(logs), false);
});

const REFUSED = [
  [
    "another project",
    get(
      `https://cloudfunctions.googleapis.com/v2/projects/other/locations/us-central1/functions/pcps`,
    ),
  ],
  ["another function name", get(`${R}/functions/somethingelse`)],
  [
    "another region",
    get(
      `https://cloudfunctions.googleapis.com/v2/projects/${PROJECT}/locations/europe-west1/functions/pcps`,
    ),
  ],
  ["deleting another function", { method: "DELETE", url: `${R}/functions/somethingelse` }],
  [
    "deleting by a v1 URL",
    {
      method: "DELETE",
      url: `https://cloudfunctions.googleapis.com/v1/projects/${PROJECT}/locations/us-central1/functions/pcps`,
    },
  ],
  ["creating a function", { method: "POST", url: `${R}/functions?functionId=pcps`, json: {} }],
  ["a function delete with a body", { method: "DELETE", url: `${R}/functions/pcps`, json: {} }],
  ["a function delete with a query", { method: "DELETE", url: `${R}/functions/pcps?force=true` }],
  [
    "creating a job",
    {
      method: "POST",
      url: `https://cloudscheduler.googleapis.com/v1/projects/${PROJECT}/locations/us-central1/jobs`,
      json: { name: "x" },
    },
  ],
  [
    "running another job",
    {
      method: "POST",
      url: `https://cloudscheduler.googleapis.com/v1/projects/${PROJECT}/locations/us-central1/jobs/other-job:run`,
      json: {},
    },
  ],
  [
    "pausing a job",
    {
      method: "POST",
      url: `https://cloudscheduler.googleapis.com/v1/projects/${PROJECT}/locations/us-central1/jobs/${JOB_IDS[0]}:pause`,
      json: {},
    },
  ],
  [
    "creating a queue",
    {
      method: "POST",
      url: `https://cloudtasks.googleapis.com/v2/projects/${PROJECT}/locations/us-central1/queues`,
      json: {},
    },
  ],
  [
    "deleting another queue",
    {
      method: "DELETE",
      url: `https://cloudtasks.googleapis.com/v2/projects/${PROJECT}/locations/us-central1/queues/other`,
    },
  ],
  [
    "deleting another topic",
    { method: "DELETE", url: `https://pubsub.googleapis.com/v1/projects/${PROJECT}/topics/other` },
  ],
  [
    "publishing to another topic",
    {
      method: "POST",
      url: `https://pubsub.googleapis.com/v1/projects/${PROJECT}/topics/other:publish`,
      json: { messages: [{ data: "eA==", attributes: { run: runMarker(RUN) } }] },
    },
  ],
  [
    "a publish of another run",
    {
      method: "POST",
      url: `${topicUrl}:publish`,
      json: { messages: [{ data: "eA==", attributes: { run: "pcrun-ffffffffffffffff" } }] },
    },
  ],
  [
    "two messages in one publish",
    {
      method: "POST",
      url: `${topicUrl}:publish`,
      json: {
        messages: [
          { data: "eA==", attributes: { run: runMarker(RUN) } },
          { data: "eA==", attributes: { run: runMarker(RUN) } },
        ],
      },
    },
  ],
  ["a topic put with a body", { method: "PUT", url: topicUrl, json: { labels: { a: "b" } } }],
  [
    "deleting another image",
    {
      method: "DELETE",
      url: `https://artifactregistry.googleapis.com/v1/projects/${PROJECT}/locations/us-central1/repositories/gcf-artifacts/packages/someone-else`,
    },
  ],
  [
    "deleting the repository",
    {
      method: "DELETE",
      url: `https://artifactregistry.googleapis.com/v1/projects/${PROJECT}/locations/us-central1/repositories/gcf-artifacts`,
    },
  ],
  [
    "another document",
    get(
      `https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents/pycheck-src/pcrun-ffffffffffffffff-a`,
    ),
  ],
  [
    "another collection",
    get(
      `https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents/users`,
    ),
  ],
  ["deleting another document", { method: "DELETE", url: documentUrl("pcrun-ffffffffffffffff-a") }],
  [
    "another database",
    get(
      `https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/other/documents/pycheck-src`,
    ),
  ],
  ["another object", { method: "DELETE", url: storageObjectUrl(BUCKET, "pycheck/other.json") }],
  ["another bucket", get("https://storage.googleapis.com/storage/v1/b/someone-elses-bucket")],
  [
    "an upload to another name",
    {
      method: "POST",
      url: `https://storage.googleapis.com/upload/storage/v1/b/${BUCKET}/o?uploadType=media&name=other.json`,
      json: { run: runMarker(RUN) },
    },
  ],
  [
    "an event on another channel",
    {
      method: "POST",
      url: `https://eventarcpublishing.googleapis.com/v1/projects/${PROJECT}/locations/us-central1/channels/other:publishEvents`,
      json: { events: [] },
    },
  ],
  [
    "deleting a channel",
    {
      method: "DELETE",
      url: `https://eventarc.googleapis.com/v1/projects/${PROJECT}/locations/us-central1/channels/firebase`,
    },
  ],
  [
    "deleting a trigger",
    {
      method: "DELETE",
      url: `https://eventarc.googleapis.com/v1/projects/${PROJECT}/locations/us-central1/triggers/pcps-123`,
    },
  ],
  [
    "setting an IAM policy",
    {
      method: "POST",
      url: `https://cloudresourcemanager.googleapis.com/v1/projects/${PROJECT}:setIamPolicy`,
      json: { policy: {} },
    },
  ],
  [
    "enabling a service",
    {
      method: "POST",
      url: `https://serviceusage.googleapis.com/v1/projects/${NUMBER}/services/pubsub.googleapis.com:enable`,
      json: {},
    },
  ],
  [
    "a service list of another project number",
    get(
      `https://serviceusage.googleapis.com/v1/projects/999999999999/services?filter=state:ENABLED&pageSize=200`,
    ),
  ],
  [
    "a log filter that is not a string",
    {
      method: "POST",
      url: "https://logging.googleapis.com/v2/entries:list",
      json: {
        resourceNames: ["projects/" + PROJECT],
        filter: 5,
        orderBy: "timestamp asc",
        pageSize: 10,
      },
    },
  ],
  [
    "a log read of another project",
    {
      method: "POST",
      url: "https://logging.googleapis.com/v2/entries:list",
      json: {
        resourceNames: ["projects/other"],
        filter: "x",
        orderBy: "timestamp asc",
        pageSize: 10,
      },
    },
  ],
  [
    "a log read with extra fields",
    {
      method: "POST",
      url: "https://logging.googleapis.com/v2/entries:list",
      json: {
        resourceNames: ["projects/" + PROJECT],
        filter: "x",
        orderBy: "timestamp asc",
        pageSize: 10,
        extra: 1,
      },
    },
  ],
  [
    "a log delete",
    { method: "DELETE", url: `https://logging.googleapis.com/v2/projects/${PROJECT}/logs/x` },
  ],
  [
    "http",
    get(
      `http://cloudfunctions.googleapis.com/v2/projects/${PROJECT}/locations/us-central1/functions`,
    ),
  ],
  [
    "a port",
    get(
      `https://cloudfunctions.googleapis.com:8443/v2/projects/${PROJECT}/locations/us-central1/functions`,
    ),
  ],
  [
    "user info",
    get(
      `https://user:pw@cloudfunctions.googleapis.com/v2/projects/${PROJECT}/locations/us-central1/functions`,
    ),
  ],
  ["a fragment", get(`${R}/functions#x`)],
  ["a repeated query key", get(`${R}/functions?pageToken=a&pageToken=b`)],
  ["an unknown query key", get(`${R}/functions?filter=x`)],
  ["a body on a read", { method: "GET", url: `${R}/functions`, json: {} }],
  [
    "a host that merely contains an allowed one",
    get(
      `https://cloudfunctions.googleapis.com.evil.example/v2/projects/${PROJECT}/locations/us-central1/functions`,
    ),
  ],
  ["a malformed URL", get("not a url")],
  ["an unknown method", { method: "PATCH", url: `${R}/functions/pcps`, json: {} }],
];
for (const [name, spec] of REFUSED)
  test(`refused: ${name}`, () => assert.equal(guard.allow(spec), false));

test("a task is refused unless it is the callable body for a run.app address and a service account, with this run's marker", () => {
  const base = operations({ runId: RUN, bucket: BUCKET, targets }).find(
    (op) => op.key === "task-pctask",
  ).request;
  const url = base.url;
  const withHttp = (edit) => {
    const json = JSON.parse(JSON.stringify(base.json));
    edit(json.task.httpRequest);
    return { method: "POST", url, json };
  };
  assert.equal(guard.allow(base), true);
  assert.equal(guard.allow(withHttp((h) => (h.url = "https://evil.example/"))), false);
  assert.equal(guard.allow(withHttp((h) => (h.httpMethod = "GET"))), false);
  assert.equal(
    guard.allow(withHttp((h) => (h.body = Buffer.from("no marker").toString("base64")))),
    false,
  );
  assert.equal(
    guard.allow(withHttp((h) => (h.oidcToken.serviceAccountEmail = "a@evil.example"))),
    false,
  );
  assert.equal(guard.allow(withHttp((h) => (h.oidcToken.extra = 1))), false);
  assert.equal(guard.allow(withHttp((h) => (h.extra = 1))), false);
  assert.equal(guard.allow(withHttp((h) => (h.body = 5))), false);
  assert.equal(
    guard.allow({ method: "POST", url: url.replace("/pctask/", "/other/"), json: base.json }),
    false,
  );
  assert.equal(
    guard.allow({
      method: "POST",
      url,
      json: { task: { httpRequest: base.json.task.httpRequest, name: "x" } },
    }),
    false,
  );
});

test("a source request of another run is refused", () => {
  const other = createGuard("ffffffffffffffff", NUMBER);
  for (const op of operations({ runId: RUN, bucket: BUCKET, targets }))
    if (
      ["fs-create", "fs-update", "st-upload", "ps-plain", "ea-fraction", "task-pctask"].includes(
        op.key,
      )
    )
      assert.equal(other.allow(op.request), false, op.key);
});

test("the own images are exactly the two ids of each of the thirteen functions", () => {
  assert.equal(ownPackages().length, ALL_FUNCTIONS.length * 2);
  assert.deepEqual(ownPackages(), ALL_FUNCTIONS.flatMap(packageIds));
  for (const id of ownPackages())
    assert.match(id, /^fireemu--oracle--events__us--central1__pc[a-z]+(%2Fcache)?$/);
});

test("matchRule returns nothing for a request no rule matches, and the rule list is stable", () => {
  assert.equal(matchRule(get("https://example.com/"), rules(RUN, NUMBER)), null);
  assert.ok(rules(RUN, NUMBER).length > 40);
  assert.equal(TOPIC, "pycheck-orders");
});
