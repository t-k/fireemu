// The plan and the script: names, the run marker, the operations and what each reaches.
import assert from "node:assert/strict";
import test from "node:test";
import {
  ENABLE_SERVICES,
  ALL_FUNCTIONS,
  FAMILIES,
  JOB_IDS,
  QUEUE_IDS,
  REQUIRED_SERVICES,
  RUN_ID,
  functionName,
  jobId,
  packageId,
  packageIds,
  runMarker,
} from "./plan.mjs";
import {
  EVENT_TIMES,
  customEvent,
  documentId,
  objectName,
  operations,
  taskBody,
  undoOperations,
} from "./script.mjs";

const RUN = "0123456789abcdef";

test("the thirteen functions are the seven SDK ones and the six raw twins, with Gen2-safe names", () => {
  assert.equal(ALL_FUNCTIONS.length, 13);
  assert.equal(new Set(ALL_FUNCTIONS).size, 13);
  for (const fn of ALL_FUNCTIONS)
    assert.match(fn, /^[a-z][a-z0-9]{1,30}$/, "no underscore or upper case: " + fn);
  for (const family of Object.values(FAMILIES)) assert.ok(ALL_FUNCTIONS.includes(family.sdk));
  assert.equal(ALL_FUNCTIONS.filter((fn) => fn.endsWith("raw")).length, 6);
});

test("the run marker accepts exactly sixteen lower-case hexadecimal digits", () => {
  assert.equal(runMarker(RUN), "pcrun-" + RUN);
  for (const bad of [
    "",
    "0123456789ABCDEF",
    "0123456789abcde",
    "0123456789abcdef0",
    "0123456789abcdeg",
    undefined,
    null,
    5,
  ])
    assert.throws(() => runMarker(bad), /invalid run ID/);
  assert.equal(RUN_ID.test(RUN), true);
});

test("names: the job, the queue, the image and its cache sibling", () => {
  assert.equal(jobId("pcsch"), "firebase-schedule-pcsch-us-central1");
  assert.deepEqual(JOB_IDS, [
    "firebase-schedule-pcsch-us-central1",
    "firebase-schedule-pcschraw-us-central1",
  ]);
  assert.deepEqual(QUEUE_IDS, ["pctask", "pctaskraw"]);
  assert.equal(packageId("pcps"), "fireemu--oracle--events__us--central1__pcps");
  assert.deepEqual(packageIds("pcps"), [packageId("pcps"), packageId("pcps") + "%2Fcache"]);
  assert.equal(
    functionName("pcps"),
    "projects/fireemu-oracle-events/locations/us-central1/functions/pcps",
  );
});

test("the required services cover everything the run touches, and the two the run may enable are not among them", () => {
  for (const id of [
    "eventarcpublishing",
    "artifactregistry",
    "pubsub",
    "firestore",
    "storage",
    "cloudbilling",
    "compute",
    "firebaseextensions",
  ])
    assert.ok(REQUIRED_SERVICES.includes(id + ".googleapis.com"), id);
  assert.deepEqual(ENABLE_SERVICES, ["cloudscheduler.googleapis.com", "cloudtasks.googleapis.com"]);
  for (const id of ENABLE_SERVICES) assert.ok(!REQUIRED_SERVICES.includes(id), id);
});

const targets = Object.fromEntries(
  ALL_FUNCTIONS.map((fn) => [
    fn,
    { uri: `https://${fn}-x.run.app`, serviceAccountEmail: "s@p.iam.gserviceaccount.com" },
  ]),
);

test("eleven operations in a fixed order, each reaching the functions of its family", () => {
  const ops = operations({ runId: RUN, bucket: "b", targets });
  assert.deepEqual(
    ops.map((o) => o.key),
    [
      "fs-create",
      "fs-update",
      "ps-plain",
      "ps-ordered",
      "st-upload",
      "ea-fraction",
      "ea-whole",
      "sched-pcsch",
      "sched-pcschraw",
      "task-pctask",
      "task-pctaskraw",
    ],
  );
  const reached = new Set(ops.flatMap((o) => o.reaches));
  for (const fn of ALL_FUNCTIONS) assert.ok(reached.has(fn), fn + " is reached by some operation");
  assert.deepEqual(ops.find((o) => o.key === "fs-update").reaches, ["pcfsu"]);
  assert.deepEqual(
    ops.find((o) => o.key === "ps-ordered").request.json.messages[0].orderingKey,
    "pycheck-key",
  );
  assert.equal(
    ops.find((o) => o.key === "ps-plain").request.json.messages[0].orderingKey,
    undefined,
  );
});

const strings = (value) =>
  typeof value === "string"
    ? [value, Buffer.from(value, "base64").toString("utf8")]
    : value && typeof value === "object"
      ? Object.values(value).flatMap(strings)
      : [];

test("every payload carries the run marker so a frame can be tied to its run", () => {
  const marker = runMarker(RUN);
  for (const op of operations({ runId: RUN, bucket: "b", targets })) {
    if (op.family === "scheduler") continue;
    const haystack = [op.request.url, ...strings(op.request.json)].join("\n");
    assert.ok(haystack.includes(marker), op.key);
  }
  assert.ok(documentId(RUN).includes(marker) && objectName(RUN).includes(marker));
});

test("the two Eventarc times are the fractional and the whole-second form", () => {
  assert.equal(EVENT_TIMES.fraction, "2026-01-01T00:00:02.500Z");
  assert.equal(EVENT_TIMES.whole, "2026-01-01T00:00:02Z");
  assert.equal(
    customEvent({ runId: RUN, label: "whole", time: EVENT_TIMES.whole }).attributes.time
      .ceTimestamp,
    EVENT_TIMES.whole,
  );
});

test("a task operation without its target is marked as needing it and has no body", () => {
  const ops = operations({ runId: RUN, bucket: "b", targets: {} });
  const task = ops.find((o) => o.key === "task-pctask");
  assert.deepEqual(task.needs, ["task-target:pctask"]);
  assert.equal(task.request.json, undefined);
  const body = taskBody({ runId: RUN, label: "pctask", ...targets.pctask });
  assert.equal(body.task.httpRequest.oidcToken.audience, targets.pctask.uri);
  assert.deepEqual(JSON.parse(Buffer.from(body.task.httpRequest.body, "base64").toString()), {
    data: { run: runMarker(RUN), label: "pctask" },
  });
});

test("the undo operations delete exactly the document and the object", () => {
  const undo = undoOperations({ runId: RUN, bucket: "b" });
  assert.deepEqual(
    undo.map((u) => u.key),
    ["fs-delete", "st-delete"],
  );
  assert.ok(
    undo.every(
      (u) =>
        u.request.method === "DELETE" && decodeURIComponent(u.request.url).includes(runMarker(RUN)),
    ),
  );
});
