import assert from "node:assert/strict";
import test from "node:test";
import { buildCorpus } from "./storage-object/corpus.mjs";

const bucket = "example.firebasestorage.app";
const prefix = "owned/token-run/";
const corpus = () => buildCorpus({ bucket, prefix });
const recipe = () =>
  corpus().recipes.find((row) => row.id === "storage-object/firebase/download-tokens");

test("download-token recipe stays within one owned object and declares its complete sequence", () => {
  const row = recipe();
  const name = `${prefix}firebase/tokens.bin`;
  assert.deepEqual(row.objects, [name]);
  assert.deepEqual(
    row.preflight.map((step) => step.id),
    ["baseline-firebase", "baseline-gcs"],
  );
  assert.deepEqual(
    row.steps.map((step) => step.id),
    [
      "upload",
      "after-upload-gcs-metadata",
      "after-upload-gcs-media",
      "after-upload-firebase-metadata",
      "after-upload-firebase-media",
      "create-token",
      "metadata-with-token",
      "metadata-with-token-again",
      "download-with-token",
      "download-with-token-again",
      "delete-token",
      "download-with-deleted-token",
      "after-delete-gcs-metadata",
      "after-delete-gcs-media",
      "after-delete-firebase-metadata",
      "after-delete-firebase-media",
    ],
  );
  assert.deepEqual(
    row.cleanup.map((step) => step.id),
    ["cleanup-delete", "cleanup-firebase-absence", "cleanup-gcs-absence"],
  );
  assert.ok(
    [...row.preflight, ...row.steps, ...row.cleanup].every((step) => step.objectName === name),
  );
  assert.equal(row.sendAuthorized, false);
  assert.equal(row.cleanupAuthorized, false);
});

test("token mutations require owner while token-bearing downloads carry no Authorization header", () => {
  const row = recipe();
  const byId = Object.fromEntries(row.steps.map((step) => [step.id, step]));
  assert.equal(byId.upload.method, "POST");
  assert.equal(byId.upload.credential, "admin");
  assert.deepEqual(byId["create-token"].query, { create_token: "true" });
  assert.equal(
    byId["create-token"].path,
    `/v0/b/${bucket}/o/${encodeURIComponent(row.objects[0])}`,
  );
  assert.equal(byId["create-token"].method, "POST");
  assert.equal(byId["create-token"].credential, "admin");
  assert.equal(byId["delete-token"].method, "POST");
  assert.equal(
    byId["delete-token"].path,
    `/v0/b/${bucket}/o/${encodeURIComponent(row.objects[0])}`,
  );
  assert.equal(byId["delete-token"].credential, "admin");
  for (const id of [
    "download-with-token",
    "download-with-token-again",
    "download-with-deleted-token",
  ]) {
    const step = byId[id];
    assert.equal(step.method, "GET");
    assert.equal(step.dialect, "firebase");
    assert.equal(step.credential, "none");
    assert.equal(step.query.alt, "media");
    assert.deepEqual(step.headers, {});
  }
});

test("every token use shares one typed private reference and has no literal token", () => {
  const row = recipe();
  const byId = Object.fromEntries(row.steps.map((step) => [step.id, step]));
  const expected = {
    kind: "firebase-download-token",
    fromStep: "create-token",
    priorStep: "after-upload-firebase-metadata",
    field: "downloadTokens",
    selection: "exactly-one-new",
    secretHandling: "private-only",
  };
  for (const id of [
    "download-with-token",
    "download-with-token-again",
    "delete-token",
    "download-with-deleted-token",
  ]) {
    const step = byId[id];
    assert.deepEqual(step.query[id === "delete-token" ? "delete_token" : "token"], expected);
  }
  assert.equal(row.tokenHandling, "private-only");
  assert.equal(row.tokenResolutionImplemented, false);
  assert.ok(!JSON.stringify(row).includes("00000000-0000-4000-8000-000000000000"));
});

test("token recipe increments only static request counts and leaves runtime obligations", () => {
  const value = corpus();
  assert.equal(value.recipes.length, 24);
  assert.equal(value.requestsPerRecording, 1888);
  assert.equal(value.remainingRecipeIds.length, 2);
  assert.ok(value.remainingObligations.includes("download-token-provenance-and-authorization"));
});
