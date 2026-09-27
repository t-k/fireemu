import assert from "node:assert/strict";
import test from "node:test";
import { buildCorpus } from "./storage-object/corpus.mjs";

const bucket = "example.firebasestorage.app";
const prefix = "owned/firebase-resumable-run/";
const corpus = () => buildCorpus({ bucket, prefix });
const recipe = () =>
  corpus().recipes.find((row) => row.id === "storage-object/firebase/resumable-upload");
const byId = (row) =>
  Object.fromEntries([...row.steps, ...row.cleanup].map((step) => [step.id, step]));
const sessionReference = (name, initiateStep) => ({
  kind: "firebase-resumable-url",
  initiateStep,
  expectedOrigin: "https://firebasestorage.googleapis.com",
  expectedPath: `/v0/b/${bucket}/o`,
  expectedName: name,
  secretHandling: "private-only",
});

test("completion, wrong-offset and cancellation own separate names", () => {
  const row = recipe();
  assert.ok(row);
  assert.deepEqual(row.objects, [
    `${prefix}firebase/resumable.bin`,
    `${prefix}firebase/resumable-wrong-offset.bin`,
    `${prefix}firebase/resumable-cancel.bin`,
  ]);
  assert.deepEqual(
    row.preflight.map((step) => step.id),
    [
      "baseline-firebase-0",
      "baseline-gcs-0",
      "baseline-firebase-1",
      "baseline-gcs-1",
      "baseline-firebase-2",
      "baseline-gcs-2",
    ],
  );
  assert.deepEqual(
    row.steps.map((step) => step.id),
    [
      "initiate",
      "query-initial",
      "chunk-0",
      "query-progress",
      "finish",
      "after-gcs-metadata",
      "after-gcs-media",
      "after-firebase-metadata",
      "after-firebase-media",
      "initiate-wrong",
      "query-wrong-initial",
      "wrong-offset",
      "after-wrong-offset-gcs-metadata",
      "after-wrong-offset-gcs-media",
      "after-wrong-offset-firebase-metadata",
      "after-wrong-offset-firebase-media",
      "query-wrong-after",
      "cancel-wrong-active",
      "query-after-cancel-wrong",
      "after-cancel-wrong-gcs-metadata",
      "after-cancel-wrong-gcs-media",
      "after-cancel-wrong-firebase-metadata",
      "after-cancel-wrong-firebase-media",
      "initiate-cancel",
      "cancel-session",
      "query-cancelled-session",
      "after-cancel-gcs-metadata",
      "after-cancel-gcs-media",
      "after-cancel-firebase-metadata",
      "after-cancel-firebase-media",
    ],
  );
  assert.deepEqual(
    row.cleanup.map((step) => step.id),
    [
      "cancel-unconfirmed-firebase-session",
      "query-cancelled-firebase-session",
      "cancel-unconfirmed-wrong-session",
      "query-cancelled-wrong-session",
      "recancel-unconfirmed-cancel-session",
      "query-after-recancel-session",
      "cleanup-delete-0",
      "cleanup-firebase-absence-0",
      "cleanup-gcs-absence-0",
      "cleanup-delete-1",
      "cleanup-firebase-absence-1",
      "cleanup-gcs-absence-1",
      "cleanup-delete-2",
      "cleanup-firebase-absence-2",
      "cleanup-gcs-absence-2",
    ],
  );
  assert.ok(
    [...row.preflight, ...row.steps, ...row.cleanup].every((step) =>
      row.objects.includes(step.objectName),
    ),
  );
});

test("all three initiations use SDK resumable start shape above the chunk threshold", () => {
  const row = recipe();
  const steps = byId(row);
  for (const [index, id] of ["initiate", "initiate-wrong", "initiate-cancel"].entries()) {
    const step = steps[id];
    assert.equal(step.dialect, "firebase");
    assert.equal(step.method, "POST");
    assert.equal(step.path, `/v0/b/${bucket}/o`);
    assert.deepEqual(step.query, { name: row.objects[index] });
    assert.deepEqual(step.headers, {
      "x-goog-upload-protocol": "resumable",
      "x-goog-upload-command": "start",
      "x-goog-upload-header-content-length": "262147",
      "x-goog-upload-header-content-type": "application/octet-stream",
      "content-type": "application/json; charset=utf-8",
    });
    assert.equal(step.body.json.name, row.objects[index]);
    assert.equal(step.credential, "admin");
  }
  assert.equal(row.sessionUriHandling, "private-only");
  assert.equal(row.sendAuthorized, false);
  assert.equal(row.cleanupAuthorized, false);
});

test("the successful session queries after its first chunk before finalizing", () => {
  const row = recipe();
  const steps = byId(row);
  for (const id of ["query-initial", "chunk-0", "query-progress", "finish"]) {
    assert.equal(steps[id].method, "POST");
    assert.equal(steps[id].path, undefined);
    assert.deepEqual(steps[id].sessionUriReference, sessionReference(row.objects[0], "initiate"));
  }
  assert.deepEqual(steps["query-initial"].continuation, {
    afterStep: "initiate",
    status: 200,
    uploadStatus: "active",
    sessionUrlRequired: true,
  });
  assert.equal(steps["chunk-0"].headers["x-goog-upload-command"], "upload");
  assert.equal(steps["chunk-0"].headers["x-goog-upload-offset"], "0");
  assert.equal(Buffer.from(steps["chunk-0"].body.base64, "base64").length, 262144);
  assert.deepEqual(steps["query-progress"].continuation, {
    afterStep: "chunk-0",
    status: 200,
    uploadStatus: "active",
  });
  assert.deepEqual(steps.finish.continuation, {
    afterStep: "query-progress",
    status: 200,
    uploadStatus: "active",
    receivedBytes: 262144,
  });
  assert.equal(steps.finish.headers["x-goog-upload-command"], "upload, finalize");
  assert.equal(steps.finish.headers["x-goog-upload-offset"], "262144");
  assert.deepEqual(Buffer.from(steps.finish.body.base64, "base64"), Buffer.from([0, 1, 255]));
  assert.ok(row.steps.slice(0, 9).every((step) => step.objectName === row.objects[0]));
});

test("a separate wrong-offset session retains absence and status observations", () => {
  const row = recipe();
  const steps = byId(row);
  for (const id of ["query-wrong-initial", "wrong-offset", "query-wrong-after"]) {
    assert.deepEqual(
      steps[id].sessionUriReference,
      sessionReference(row.objects[1], "initiate-wrong"),
    );
  }
  assert.deepEqual(steps["wrong-offset"].continuation, {
    afterStep: "query-wrong-initial",
    status: 200,
    uploadStatus: "active",
    receivedBytes: 0,
  });
  assert.equal(steps["wrong-offset"].headers["x-goog-upload-offset"], "1");
  assert.deepEqual(steps["wrong-offset"].responseExpectation, { statusClass: "4xx" });
  for (const id of [
    "after-wrong-offset-gcs-metadata",
    "after-wrong-offset-gcs-media",
    "after-wrong-offset-firebase-metadata",
    "after-wrong-offset-firebase-media",
  ]) {
    assert.equal(steps[id].objectName, row.objects[1]);
    assert.deepEqual(steps[id].responseExpectation, { status: 404 });
  }
  assert.deepEqual(steps["query-wrong-after"].continuation, {
    afterStep: "wrong-offset",
    requestAttempted: true,
  });
  assert.deepEqual(steps["query-wrong-after"].responseExpectation, { receivedBytes: 0 });
  assert.deepEqual(steps["cancel-wrong-active"].continuation, {
    afterStep: "query-wrong-after",
    status: 200,
    uploadStatus: "active",
  });
  assert.equal(steps["cancel-wrong-active"].headers["x-goog-upload-command"], "cancel");
  assert.deepEqual(steps["query-after-cancel-wrong"].continuation, {
    afterStep: "cancel-wrong-active",
    requestAttempted: true,
  });
  for (const id of [
    "after-cancel-wrong-gcs-metadata",
    "after-cancel-wrong-gcs-media",
    "after-cancel-wrong-firebase-metadata",
    "after-cancel-wrong-firebase-media",
  ])
    assert.deepEqual(steps[id].responseExpectation, { status: 404 });
  assert.ok(row.steps.slice(9, 23).every((step) => step.objectName === row.objects[1]));
});

test("normal cancellation and uncertain-session cleanup remain separate and non-sending", () => {
  const row = recipe();
  const steps = byId(row);
  for (const id of ["cancel-session", "query-cancelled-session"]) {
    assert.deepEqual(
      steps[id].sessionUriReference,
      sessionReference(row.objects[2], "initiate-cancel"),
    );
  }
  assert.equal(steps["cancel-session"].headers["x-goog-upload-command"], "cancel");
  assert.deepEqual(steps["query-cancelled-session"].continuation, {
    afterStep: "cancel-session",
    requestAttempted: true,
  });
  for (const id of [
    "after-cancel-gcs-metadata",
    "after-cancel-gcs-media",
    "after-cancel-firebase-metadata",
    "after-cancel-firebase-media",
  ])
    assert.deepEqual(steps[id].responseExpectation, { status: 404 });
  assert.deepEqual(
    steps["cancel-unconfirmed-firebase-session"].sessionUriReference,
    sessionReference(row.objects[0], "initiate"),
  );
  assert.deepEqual(
    steps["cancel-unconfirmed-wrong-session"].sessionUriReference,
    sessionReference(row.objects[1], "initiate-wrong"),
  );
  assert.equal(
    steps["cancel-unconfirmed-wrong-session"].continuation.cancellationUnconfirmed,
    true,
  );
  assert.deepEqual(
    steps["recancel-unconfirmed-cancel-session"].sessionUriReference,
    sessionReference(row.objects[2], "initiate-cancel"),
  );
  assert.equal(
    steps["recancel-unconfirmed-cancel-session"].continuation.cancellationUnconfirmed,
    true,
  );
  assert.equal(
    steps["recancel-unconfirmed-cancel-session"].headers["x-goog-upload-command"],
    "cancel",
  );
  assert.equal(row.cleanup[6].method, "DELETE");
  assert.equal(row.sendAuthorized, false);
  assert.equal(row.cleanupAuthorized, false);
  assert.ok(!JSON.stringify(row).includes("upload_id="));
});
