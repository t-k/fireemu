import assert from "node:assert/strict";
import test from "node:test";
import { buildCorpus } from "./storage-object/corpus.mjs";

const bucket = "example.firebasestorage.app";
const prefix = "owned/resumable-run/";
const corpus = () => buildCorpus({ bucket, prefix });
const recipe = () =>
  corpus().recipes.find((row) => row.id === "storage-object/gcs/resumable-upload");

test("GCS resumable recipe owns one name with preflight, final readbacks and cleanup", () => {
  const row = recipe();
  assert.ok(row);
  const name = `${prefix}gcs/resumable.bin`;
  assert.deepEqual(row.objects, [name]);
  assert.deepEqual(
    row.preflight.map((step) => step.id),
    ["baseline-firebase", "baseline-gcs"],
  );
  assert.deepEqual(
    row.steps.map((step) => step.id),
    [
      "initiate",
      "chunk-0",
      "query-progress",
      "finish",
      "after-gcs-metadata",
      "after-gcs-media",
      "after-firebase-metadata",
      "after-firebase-media",
    ],
  );
  assert.deepEqual(
    row.cleanup.map((step) => step.method),
    ["DELETE", "PUT", "DELETE", "GET", "GET"],
  );
  assert.ok(
    [...row.preflight, ...row.steps, ...row.cleanup].every((step) => step.objectName === name),
  );
});

test("initiation uses guarded GCS JSON insert and captures the private Location", () => {
  const row = recipe();
  const initiate = row.steps[0];
  assert.equal(initiate.dialect, "gcs");
  assert.equal(initiate.method, "POST");
  assert.equal(initiate.path, `/upload/storage/v1/b/${bucket}/o`);
  assert.deepEqual(initiate.query, {
    uploadType: "resumable",
    name: row.objects[0],
    ifGenerationMatch: "0",
  });
  assert.equal(initiate.headers["content-type"], "application/json");
  assert.equal(initiate.headers["x-upload-content-type"], "application/octet-stream");
  assert.equal(initiate.headers["x-upload-content-length"], "262147");
  assert.equal(initiate.body.json.name, row.objects[0]);
  assert.equal(initiate.responseCapture.headers, "all");
  assert.equal(row.sessionUriHandling, "private-only");
});

test("session requests use one typed opaque Location reference and bounded chunks", () => {
  const row = recipe();
  const [initiate, chunk, status, finish] = row.steps;
  for (const step of [chunk, status, finish]) {
    assert.equal(step.method, "PUT");
    assert.equal(step.path, undefined);
    assert.deepEqual(step.sessionUriReference, {
      kind: "gcs-resumable-location",
      initiateStep: initiate.id,
      expectedOrigin: "https://storage.googleapis.com",
      expectedPath: `/upload/storage/v1/b/${bucket}/o`,
      expectedName: row.objects[0],
      secretHandling: "private-only",
    });
    assert.equal(step.credential, "admin");
  }
  assert.equal(chunk.headers["content-range"], "bytes 0-262143/262147");
  assert.equal(chunk.headers["content-length"], "262144");
  assert.equal(Buffer.from(chunk.body.base64, "base64").length, 262144);
  assert.deepEqual(chunk.continuation, {
    afterStep: "initiate",
    status: 200,
    locationRequired: true,
  });
  assert.equal(status.headers["content-range"], "bytes */262147");
  assert.equal(status.headers["content-length"], "0");
  assert.deepEqual(status.continuation, { afterStep: "chunk-0", status: 308 });
  assert.equal(finish.headers["content-range"], "bytes 262144-262146/262147");
  assert.equal(finish.headers["content-length"], "3");
  assert.deepEqual(Buffer.from(finish.body.base64, "base64"), Buffer.from([0, 1, 255]));
  assert.deepEqual(finish.continuation, {
    afterStep: "query-progress",
    status: 308,
    range: "bytes=0-262143",
  });
});

test("an unconfirmed session has a private cancellation and status check before object cleanup", () => {
  const row = recipe();
  const [cancel, verify, objectDelete] = row.cleanup;
  assert.deepEqual(
    row.cleanup.map((step) => step.id),
    [
      "cancel-unconfirmed-session",
      "verify-session-cancelled",
      "cleanup-delete",
      "cleanup-firebase-absence",
      "cleanup-gcs-absence",
    ],
  );
  assert.deepEqual(
    [cancel.method, verify.method, objectDelete.method],
    ["DELETE", "PUT", "DELETE"],
  );
  for (const step of [cancel, verify]) {
    assert.equal(step.path, undefined);
    assert.deepEqual(step.sessionUriReference, row.steps[1].sessionUriReference);
    assert.deepEqual(step.query, {});
    assert.equal(step.credential, "admin");
    assert.equal(step.headers["content-length"], "0");
  }
  assert.deepEqual(cancel.continuation, {
    afterStep: "initiate",
    status: 200,
    completionUnconfirmed: true,
    locationRequired: true,
  });
  assert.deepEqual(cancel.responseExpectation, { status: 499 });
  assert.equal(cancel.body, undefined);
  assert.deepEqual(verify.headers, {
    "content-length": "0",
    "content-range": "bytes */262147",
  });
  assert.deepEqual(verify.continuation, { afterStep: cancel.id, status: 499 });
  assert.deepEqual(verify.responseExpectation, { statusClass: "4xx" });
  assert.equal(row.cleanupAuthorized, false);
  assert.equal(row.sendAuthorized, false);
});

test("the declaration never embeds a session token or grants a send", () => {
  const row = recipe();
  assert.equal(row.sendAuthorized, false);
  assert.equal(row.cleanupAuthorized, false);
  assert.ok(!JSON.stringify(row).includes("upload_id="));
  assert.ok(!JSON.stringify(row).includes("sessionUri:"));
  assert.ok(
    corpus().remainingObligations.includes("resumable-session-uri-resolution-and-progress"),
  );
  assert.ok(corpus().remainingObligations.includes("resumable-session-cancellation"));
});
