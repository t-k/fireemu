// The answers production gave to the probe (recorded/probe-v2.json), replayed through the
// recorder's own session, list and absence judges. A judge fitted to the local runtime's answers
// can pass every local test and still stop on the first real one; these tests hold the judges to
// what production actually answered. Nothing here sends a request.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { buildCorpus } from "./storage-object/corpus.mjs";
import { createLocalStorageSender } from "./storage-object/sender.mjs";
import { buildStage3DraftPlan } from "./storage-object/stage3-plan.mjs";

const recorded = JSON.parse(
  readFileSync(new URL("./storage-object/recorded/probe-v2.json", import.meta.url), "utf8"),
);
const BUCKET = "fireemu-oracle-query.firebasestorage.app";
const ORIGIN = "http://127.0.0.1:9199";

const answer = (id) => {
  const row = recorded.answers[id];
  assert.ok(row, id);
  return new Response(row.status === 204 ? null : row.body, {
    status: row.status,
    headers: row.headers,
  });
};

/** The recorded session URL shapes, with this run's bucket, name and a made-up session ID. */
const gcsLocation = (name, id = "AbC-1_x") =>
  recorded.sessionUrlShapes.gcsLocation
    .replace("https://storage.googleapis.com", ORIGIN)
    .replace("<bucket>", BUCKET)
    .replace("<name>", encodeURIComponent(name))
    .replace("<id>", id);
const firebaseUrl = (name, id = "Qz-9_y") =>
  recorded.sessionUrlShapes.firebaseUploadUrl
    .replace("https://firebasestorage.googleapis.com", ORIGIN)
    .replace("<bucket>", BUCKET)
    .replace("<name>", encodeURIComponent(name))
    .replace("<id>", id);

function setup(recipeId) {
  const plan = buildStage3DraftPlan({
    projectId: "fireemu-oracle-query",
    bucket: BUCKET,
    runIds: ["recordone", "recordtwo"],
  });
  const recipe = buildCorpus({ bucket: BUCKET, prefix: plan.recordings[0].prefix }).recipes.find(
    (row) => row.id === recipeId,
  );
  return { plan, recipe };
}

function makeSender({ plan, production }) {
  const sent = [];
  const sender = createLocalStorageSender({
    plan,
    origin: ORIGIN,
    credentials: { admin: "Bearer owner" },
    onStart: async () => {},
    onReserve: async () => {},
    onJournal: async () => {},
    fetchImpl: async (href, init) => {
      const request = { href, method: init.method, headers: init.headers };
      sent.push(request);
      return production(request, new URL(href));
    },
  });
  return { sender, sent };
}

const isCollection = (url) => url.pathname.endsWith("/o");
const isFirebase = (url) => url.pathname.startsWith("/v0/");
const isMedia = (url) => url.searchParams.get("alt") === "media";

/** Absence reads and lists, as production answered them. */
function readAnswer(url) {
  if (isCollection(url)) return answer(isFirebase(url) ? "firebase-list-owner" : "gcs-list-owner");
  if (isFirebase(url)) return answer("firebase-metadata-owner");
  return answer(isMedia(url) ? "gcs-media-owner" : "gcs-metadata-owner");
}

async function readAbsent(sender, name) {
  const ids = [];
  for (const dialect of ["gcs", "firebase"])
    for (const kind of ["metadata", "media"]) {
      const id = `${dialect}-${kind}`;
      ids.push(id);
      await sender.sendStep({
        id,
        objectName: name,
        dialect,
        method: "GET",
        credential: "admin",
        path: `/${dialect === "gcs" ? "storage/v1" : "v0"}/b/${BUCKET}/o/${encodeURIComponent(name)}`,
        query: kind === "media" ? { alt: "media" } : {},
      });
    }
  return ids;
}

/** Replay the GCS session as production answered it; `tweak` changes one answer. */
async function replayGcs({ location, afterCancel } = {}) {
  const { plan, recipe } = setup("storage-object/gcs/resumable-upload");
  const name = recipe.objects[0];
  let cancelled = false;
  const { sender, sent } = makeSender({
    plan,
    production: (request, url) => {
      if (request.method === "GET") return readAnswer(url);
      if (request.method === "POST") {
        const start = answer("gcs-session-start");
        const headers = new Headers(start.headers);
        headers.set("location", location ? location(gcsLocation(name)) : gcsLocation(name));
        return new Response(start.body, { status: start.status, headers });
      }
      if (request.method === "DELETE") {
        cancelled = true;
        return answer("gcs-session-cancel");
      }
      return cancelled && afterCancel
        ? afterCancel()
        : answer(cancelled ? "gcs-session-status-after-cancel" : "gcs-session-status");
    },
  });
  await sender.start();
  await sender.admitNamespace();
  sender.admitObject(name);
  await sender.sendStep(recipe.steps[0]);
  return { sender, sent, recipe, name };
}

async function confirmGcs({ sender, recipe, name }) {
  sender.bindSession({ recipe, initiateOperationId: "initiate" });
  sender.beginCleanup();
  const cancel = await sender.sendSessionStep({ recipe, cleanupIndex: 0 });
  const verify = await sender.sendSessionStep({ recipe, cleanupIndex: 1 });
  const ids = await readAbsent(sender, name);
  await sender.confirmCancelledSession({
    name,
    cancelOperationId: "cancel-unconfirmed-session",
    queryOperationId: "verify-session-cancelled",
    readbackOperationIds: ids,
  });
  return { cancel, verify };
}

test("GCS: the session URL production returned is accepted, and its cancellation is confirmed by production's own answers", async () => {
  const run = await replayGcs();
  const { sender, sent, name } = run;
  const { cancel, verify } = await confirmGcs(run);
  assert.equal(cancel.status, 499);
  assert.equal(verify.status, 499, "production answers the status after a cancel with 499 again");
  assert.deepEqual(sender.unresolved(), []);
  assert.equal(sender.sessionSnapshot({ name }).cancelled, true);
  // The continuation requests go to the session URL production named, `ifGenerationMatch` included.
  const continuation = sent.filter((row) => ["DELETE", "PUT"].includes(row.method));
  assert.equal(continuation.length, 2);
  for (const row of continuation) assert.equal(row.href, gcsLocation(name));
});

/** Replay the Firebase session as production answered it; the options change one answer. */
async function replayFirebase({ afterCancel } = {}) {
  const { plan, recipe } = setup("storage-object/firebase/resumable-upload");
  const name = recipe.objects.find((row) => row.endsWith("resumable-cancel.bin"));
  const started = new Set();
  let cancelled = false;
  const { sender, sent } = makeSender({
    plan,
    production: (request, url) => {
      if (request.method === "GET") return readAnswer(url);
      const command = request.headers["x-goog-upload-command"];
      if (command === "start") {
        started.add(url.searchParams.get("name"));
        const start = answer("firebase-session-start");
        const headers = new Headers(start.headers);
        headers.set("x-goog-upload-url", firebaseUrl(name));
        headers.set("x-goog-upload-control-url", firebaseUrl(name));
        return new Response(start.body, { status: start.status, headers });
      }
      if (command === "cancel") {
        cancelled = true;
        return answer("firebase-session-cancel");
      }
      return cancelled && afterCancel
        ? afterCancel()
        : answer(cancelled ? "firebase-session-query-after-cancel" : "firebase-session-query");
    },
  });
  await sender.start();
  await sender.admitNamespace();
  sender.admitObject(name);
  const steps = new Map(recipe.steps.map((step, stepIndex) => [step.id, { step, stepIndex }]));
  await sender.sendStep(steps.get("initiate-cancel").step);
  return { sender, sent, recipe, name, steps };
}

async function confirmFirebase({ sender, recipe, name, steps }) {
  sender.bindSession({ recipe, initiateOperationId: "initiate-cancel" });
  const cancel = await sender.sendSessionStep({
    recipe,
    stepIndex: steps.get("cancel-session").stepIndex,
  });
  const query = await sender.sendSessionStep({
    recipe,
    stepIndex: steps.get("query-cancelled-session").stepIndex,
  });
  const ids = await readAbsent(sender, name);
  await sender.confirmCancelledSession({
    name,
    cancelOperationId: "cancel-session",
    queryOperationId: "query-cancelled-session",
    readbackOperationIds: ids,
  });
  return { cancel, query };
}

test("Firebase: the session URL production returned is accepted, and a cancelled session is confirmed by production's own answers", async () => {
  const run = await replayFirebase();
  const { sender, sent, name } = run;
  const { cancel, query } = await confirmFirebase(run);
  assert.equal(cancel.status, 200);
  assert.equal(query.status, 200);
  assert.equal(query.headers["x-goog-upload-status"], "cancelled");
  assert.equal(
    "x-goog-upload-size-received" in query.headers,
    false,
    "production sends no size after a cancel",
  );
  assert.deepEqual(sender.unresolved(), []);
  assert.equal(sender.sessionSnapshot({ name }).cancelled, true);
  assert.equal(sent.filter((row) => row.headers["x-goog-upload-command"] === "query").length, 1);
});

// ---- what the judges still refuse -----------------------------------------------------------------------

test("GCS: a session URL with a key the initiate never declared, or another value for one it did, is refused", async () => {
  for (const [label, location] of [
    ["an unknown key", (url) => `${url}&foo=1`],
    [
      "another generation match",
      (url) => url.replace("ifGenerationMatch=0", "ifGenerationMatch=1"),
    ],
    ["a repeated upload_id", (url) => `${url}&upload_id=other`],
    ["no upload_id", (url) => url.replace(/&upload_id=[^&]+/, "")],
    ["another name", (url) => url.replace(/name=[^&]+/, "name=other")],
  ]) {
    const run = await replayGcs({ location });
    assert.throws(
      () => run.sender.bindSession({ recipe: run.recipe, initiateOperationId: "initiate" }),
      /invalid local session URI/,
      label,
    );
  }
});

test("GCS: a session URL without the echoed `ifGenerationMatch` (the local runtime's form) is still accepted", async () => {
  const run = await replayGcs({ location: (url) => url.replace("&ifGenerationMatch=0", "") });
  const { cancel } = await confirmGcs(run);
  assert.equal(cancel.status, 499);
});

test("GCS: a session still answering after its cancel is not confirmed cancelled", async () => {
  for (const status of [200, 308, 500]) {
    const run = await replayGcs({ afterCancel: () => new Response(null, { status }) });
    await assert.rejects(confirmGcs(run), (error) =>
      /error|terminal|4xx|cancell/i.test(error.message),
    );
    assert.equal(run.sender.unresolved().length, 1);
    assert.equal(run.sender.sessionSnapshot({ name: run.name }).cancelled, false);
  }
});

test("GCS: 400, 404 and 499 after a cancel all say the session is gone", async () => {
  for (const status of [400, 404, 499]) {
    const run = await replayGcs({ afterCancel: () => new Response("{}", { status }) });
    await confirmGcs(run);
    assert.equal(run.sender.sessionSnapshot({ name: run.name }).cancelled, true, `${status}`);
  }
});

test("Firebase: a query after the cancel that is not `cancelled`, or that still counts bytes, is refused", async () => {
  for (const [label, afterCancel] of [
    [
      "active",
      () =>
        new Response(null, {
          status: 200,
          headers: { "x-goog-upload-status": "active", "x-goog-upload-size-received": "0" },
        }),
    ],
    ["no status", () => new Response(null, { status: 200 })],
    [
      "bytes received",
      () =>
        new Response(null, {
          status: 200,
          headers: { "x-goog-upload-status": "cancelled", "x-goog-upload-size-received": "5" },
        }),
    ],
    [
      "not 200",
      () => new Response(null, { status: 404, headers: { "x-goog-upload-status": "cancelled" } }),
    ],
  ]) {
    const run = await replayFirebase({ afterCancel });
    await assert.rejects(confirmFirebase(run), undefined, label);
    assert.equal(run.sender.unresolved().length, 1, label);
    assert.equal(run.sender.sessionSnapshot({ name: run.name }).cancelled, false, label);
  }
});

test("Firebase: `cancelled` with an explicit size of 0 (the local runtime's form) is still accepted", async () => {
  const run = await replayFirebase({
    afterCancel: () =>
      new Response(null, {
        status: 200,
        headers: { "x-goog-upload-status": "cancelled", "x-goog-upload-size-received": "0" },
      }),
  });
  await confirmFirebase(run);
  assert.equal(run.sender.sessionSnapshot({ name: run.name }).cancelled, true);
});

test("the owner accounts:lookup of an absent email, as production answered it, proves the account absent", async () => {
  const { createLocalAuthState } = await import("./storage-object/local-auth-state.mjs");
  const { buildAuthCorpus } = await import("./storage-object/auth-corpus.mjs");
  const plan = buildStage3DraftPlan({
    projectId: "fireemu-oracle-query",
    bucket: BUCKET,
    runIds: ["recordone", "recordtwo"],
  });
  const recipe = buildAuthCorpus({
    projectId: "fireemu-oracle-query",
    bucket: BUCKET,
    runId: "recordone",
  }).recipes[0];
  const lookup = recorded.answers["identity-owner-lookup"];
  const seen = [];
  const state = createLocalAuthState({
    plan,
    apiKey: "storage-object-local-key",
    password: "synthetic-password-0123456789",
    request: async (operationId, path, query, options) => {
      seen.push({ operationId, path, owner: options.owner });
      return { status: lookup.status, raw: Buffer.from(lookup.body), headers: lookup.headers };
    },
    onJournal: async () => {},
  });
  await state.send({ recipe, stepIndex: 0 });
  assert.equal(seen.length, 1);
  assert.equal(seen[0].owner, true);
  assert.match(seen[0].path, /accounts:lookup$/);
  // A body that names a user is not an absence.
  const present = createLocalAuthState({
    plan,
    apiKey: "storage-object-local-key",
    password: "synthetic-password-0123456789",
    request: async () => ({
      status: 200,
      raw: Buffer.from(
        '{"kind":"identitytoolkit#GetAccountInfoResponse","users":[{"localId":"u"}]}',
      ),
      headers: {},
    }),
    onJournal: async () => {},
  });
  await assert.rejects(present.send({ recipe, stepIndex: 0 }), /absence is not proved/);
});

test("production's answers to the absence reads are the statuses the recorder's judges expect", () => {
  const a = recorded.answers;
  // Owner reads of an absent object: 404 in both dialects; the two media bodies differ in shape.
  for (const id of [
    "gcs-metadata-owner",
    "gcs-media-owner",
    "firebase-metadata-owner",
    "firebase-media-owner",
  ])
    assert.equal(a[id].status, 404, id);
  assert.match(a["gcs-media-owner"].headers["content-type"], /^text\/html/);
  assert.match(a["gcs-metadata-owner"].headers["content-type"], /^application\/json/);
  assert.deepEqual(JSON.parse(a["firebase-metadata-owner"].body), {
    error: { code: 404, message: "Not Found." },
  });
  // Without a credential the fixed Rules refuse: 403, not 404 (a denied read is a 4xx that is not 404).
  for (const id of ["firebase-metadata-none", "firebase-media-none"]) {
    assert.equal(a[id].status, 403, id);
    assert.deepEqual(JSON.parse(a[id].body), {
      error: { code: 403, message: "Permission denied." },
    });
  }
});
