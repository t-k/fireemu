// Production's answers to the object routes (recorded/stage3-v9-answers.json, from the STORAGE-RULES
// stage 3 v9 recording on the same bucket), replayed through the recorder's own readback, ownership,
// cleanup, session-completion and list judges. Nothing here sends a request.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { createLocalStorageSender } from "./storage-object/sender.mjs";
import { buildStage3DraftPlan } from "./storage-object/stage3-plan.mjs";

const recorded = JSON.parse(
  readFileSync(
    new URL("./storage-object/recorded/stage3-v9-answers.json", import.meta.url),
    "utf8",
  ),
);
const BUCKET = "fireemu-oracle-query.firebasestorage.app";
const ORIGIN = "http://127.0.0.1:9199";
const plan = buildStage3DraftPlan({
  projectId: "fireemu-oracle-query",
  bucket: BUCKET,
  runIds: ["recordone", "recordtwo"],
});
const prefix = plan.recordings[0].prefix;
const name = `${prefix}simple/object.bin`;

/** A recorded answer as a Response, with this run's object name in place of the recorded one. */
function answer(key, { generation } = {}) {
  const row = recorded.answers[key];
  assert.ok(row, key);
  let body = row.body
    .replaceAll("{{nameEncoded}}", encodeURIComponent(name))
    .replaceAll("{{name}}", name);
  if (generation !== undefined)
    body = body.replace(/"generation": "\d+"/, `"generation": "${generation}"`);
  return new Response(row.status === 204 ? null : body, {
    status: row.status,
    headers: row.headers,
  });
}
const bodyOf = (key) =>
  recorded.answers[key].body.replaceAll("{{nameEncoded}}", "x").replaceAll("{{name}}", name);
const generationOf = (key) => JSON.parse(bodyOf(key)).generation;
const mediaSha = (key) =>
  createHash("sha256").update(Buffer.from(recorded.answers[key].body)).digest("hex");

const gcsPath = `/storage/v1/b/${BUCKET}/o/${encodeURIComponent(name)}`;

function makeSender(production) {
  const sent = [];
  const sender = createLocalStorageSender({
    plan,
    origin: ORIGIN,
    credentials: { admin: "Bearer owner" },
    onStart: async () => {},
    onReserve: async () => {},
    onJournal: async () => {},
    fetchImpl: async (href, init) => {
      const url = new URL(href);
      sent.push({
        method: init.method,
        path: url.pathname,
        query: Object.fromEntries(url.searchParams),
      });
      if (init.method === "GET" && url.pathname === `/storage/v1/b/${BUCKET}/o`)
        return answer("gcsList0");
      return production(init.method, url);
    },
  });
  return { sender, sent };
}

const gcsRead = (url) =>
  url.searchParams.get("alt") === "media" ? "gcsMedia200" : "gcsMetadata200";

test("GCS: the upload answer, the metadata and media readbacks, the ownership proof, the conditional delete and the two absence reads, as production answered them", async () => {
  let deleted = false;
  const { sender, sent } = makeSender((method, url) => {
    if (method === "POST") return answer("gcsUpload200");
    if (method === "DELETE") {
      deleted = true;
      return answer("gcsDelete204");
    }
    if (deleted)
      return answer(url.searchParams.get("alt") === "media" ? "gcsMedia404" : "gcsMetadata404");
    return answer(gcsRead(url));
  });
  await sender.start();
  await sender.admitNamespace();
  sender.admitObject(name);
  await sender.sendStep({
    id: "upload",
    dialect: "gcs",
    method: "POST",
    objectName: name,
    path: `/upload/storage/v1/b/${BUCKET}/o`,
    query: { uploadType: "media", name, ifGenerationMatch: "0" },
    body: { base64: "dGVzdA==" },
  });
  for (const [id, query] of [
    ["metadata", {}],
    ["media", { alt: "media" }],
  ])
    await sender.sendStep({
      id,
      dialect: "gcs",
      method: "GET",
      objectName: name,
      path: gcsPath,
      query,
    });
  const generation = sender.confirmOwned({
    name,
    uploadOperationId: "upload",
    metadataOperationId: "metadata",
    mediaOperationId: "media",
    expectedBytesSha256: mediaSha("gcsMedia200"),
  });
  assert.match(generation, /^[1-9][0-9]{0,19}$/);
  sender.beginCleanup();
  const deletion = await sender.cleanupOwned({
    name,
    metadataOperationId: "metadata",
    mediaOperationId: "media",
    operationId: "cleanup",
  });
  assert.equal(deletion.status, 204);
  assert.deepEqual(sender.unresolved(), []);
  await sender.verifyRunEmpty();
  const del = sent.find((request) => request.method === "DELETE");
  assert.deepEqual(del.query, { ifGenerationMatch: generation });
});

test("Firebase: the simple upload answer is an owned upload once the GCS readbacks agree with it", async () => {
  const uploaded = generationOf("firebaseUpload200");
  const { sender } = makeSender((method, url) => {
    if (method === "POST") return answer("firebaseUpload200");
    // The GCS readbacks of the object the Firebase upload created.
    return url.searchParams.get("alt") === "media"
      ? answer("gcsMedia200")
      : answer("gcsMetadata200", { generation: uploaded });
  });
  await sender.start();
  await sender.admitNamespace();
  sender.admitObject(name);
  await sender.sendStep({
    id: "upload",
    dialect: "firebase",
    method: "POST",
    objectName: name,
    path: `/v0/b/${BUCKET}/o`,
    query: { name },
    headers: { "content-type": "text/plain" },
    body: { base64: "dGVzdA==" },
  });
  for (const [id, query] of [
    ["metadata", {}],
    ["media", { alt: "media" }],
  ])
    await sender.sendStep({
      id,
      dialect: "gcs",
      method: "GET",
      objectName: name,
      path: gcsPath,
      query,
    });
  assert.equal(
    sender.confirmOwned({
      name,
      uploadOperationId: "upload",
      metadataOperationId: "metadata",
      mediaOperationId: "media",
      expectedBytesSha256: mediaSha("gcsMedia200"),
    }),
    uploaded,
  );
});

test("the recorded GCS and Firebase metadata both carry the identity the readback judge needs", () => {
  for (const key of [
    "gcsUpload200",
    "gcsMetadata200",
    "gcsPatch200",
    "firebaseUpload200",
    "firebaseMultipart200",
    "firebaseMetadata200",
    "firebasePatch200",
    "firebaseCreateToken200",
    "firebaseSessionFinalize200",
    "firebaseSessionVerify200",
  ]) {
    const body = JSON.parse(bodyOf(key));
    assert.equal(body.bucket, BUCKET, key);
    assert.equal(body.name, name, key);
    assert.match(body.generation, /^[1-9][0-9]{0,19}$/, key);
  }
});

test("the recorded Firebase session completion carries `x-goog-upload-status: final`, as the session judge requires", () => {
  for (const key of ["firebaseSessionFinalize200", "firebaseSessionVerify200"])
    assert.equal(recorded.answers[key].headers["x-goog-upload-status"], "final", key);
  assert.equal(recorded.answers.firebaseSessionStart200.headers["x-goog-upload-status"], "active");
  assert.equal(
    recorded.answers.firebaseSessionVerify200.headers["x-goog-upload-size-received"],
    "4",
  );
});

test("the recorded deletes and absence answers are the statuses the cleanup judges require", () => {
  assert.equal(recorded.answers.gcsDelete204.status, 204);
  assert.equal(recorded.answers.firebaseDelete204.status, 204);
  assert.equal(recorded.answers.gcsDelete404.status, 404);
  assert.equal(recorded.answers.firebaseDelete404.status, 404);
  assert.equal(recorded.answers.gcsMetadata404.status, 404);
  assert.equal(recorded.answers.gcsMedia404.status, 404);
  assert.equal(recorded.answers.firebaseMetadata404.status, 404);
  assert.equal(recorded.answers.firebase403.status, 403);
  // The bucket without a release answers a media read 400: an absence judge that took 404 only
  // would stop on it, which is why the recorder pins the release.
  assert.equal(recorded.answers.firebaseNoRelease400Media.status, 400);
});
