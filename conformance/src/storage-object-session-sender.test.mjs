import assert from "node:assert/strict";
import test from "node:test";
import { buildCorpus } from "./storage-object/corpus.mjs";
import { createLocalStorageSender } from "./storage-object/sender.mjs";
import { buildStage3DraftPlan } from "./storage-object/stage3-plan.mjs";

async function fixture({
  locationChange = (uri) => uri,
  range = "bytes=0-262143",
  chunkStatus = 308,
  cancelStatus = 499,
  initialBody = "",
  cancellationChangesState = true,
  absenceListBody = { items: [] },
} = {}) {
  const bucket = "example.appspot.com",
    origin = "http://127.0.0.1:9199";
  const plan = buildStage3DraftPlan({
    projectId: "example-project",
    bucket,
    runIds: ["recordone", "recordtwo"],
  });
  const recipe = buildCorpus({ bucket, prefix: plan.recordings[0].prefix }).recipes.find(
    (row) => row.id === "storage-object/gcs/resumable-upload",
  );
  const reservations = [],
    journal = [],
    sent = [];
  const location = `${origin}/upload/storage/v1/b/${bucket}/o?name=${encodeURIComponent(recipe.objects[0])}&uploadType=resumable&upload_id=private_session`;
  let cancelled = false;
  let lists = 0;
  const sender = createLocalStorageSender({
    plan,
    origin,
    credentials: { admin: "Bearer owner" },
    onStart: async () => {},
    onReserve: async (row) => reservations.push(row),
    onJournal: async (row) => journal.push(row),
    fetchImpl: async (href, init) => {
      sent.push({ href, method: init.method, headers: init.headers });
      if (init.method === "GET")
        return new URL(href).pathname.endsWith("/o")
          ? Response.json(++lists === 1 ? { items: [] } : absenceListBody)
          : Response.json({ error: "absent" }, { status: 404 });
      if (init.method === "POST")
        return new Response(initialBody || null, {
          status: 200,
          headers: { location: locationChange(location) },
        });
      assert.equal(href, location);
      assert.equal(init.headers.authorization, "Bearer owner");
      if (init.method === "DELETE") {
        cancelled = cancellationChangesState && cancelStatus === 499;
        return new Response(null, { status: cancelStatus });
      }
      return new Response(null, { status: cancelled ? 400 : chunkStatus, headers: { range } });
    },
  });
  await sender.start();
  await sender.admitNamespace();
  sender.admitObject(recipe.objects[0]);
  await sender.sendStep(recipe.steps[0]);
  return { sender, recipe, reservations, journal, sent };
}

async function readAbsentSessionObject(run) {
  const name = run.recipe.objects[0],
    ids = [];
  for (const dialect of ["gcs", "firebase"])
    for (const kind of ["metadata", "media"]) {
      const id = `${dialect}-${kind}`;
      ids.push(id);
      await run.sender.sendStep({
        id,
        objectName: name,
        dialect,
        method: "GET",
        credential: "admin",
        path: `/${dialect === "gcs" ? "storage/v1" : "v0"}/b/example.appspot.com/o/${encodeURIComponent(name)}`,
        query: kind === "media" ? { alt: "media" } : {},
      });
    }
  return ids;
}

test("a captured local session shares reservation and ownership journal with Storage requests", async () => {
  const run = await fixture();
  const binding = run.sender.bindSession({ recipe: run.recipe, initiateOperationId: "initiate" });
  assert.match(binding.sessionUriSha256, /^[a-f0-9]{64}$/);
  assert.equal(JSON.stringify(binding).includes("private_session"), false);
  await run.sender.sendSessionStep({ recipe: run.recipe, stepIndex: 1 });
  assert.equal(run.sender.snapshot().total, 3);
  assert.equal(run.reservations.length, 3);
  assert.equal(run.journal.length, 2);
  assert.equal(run.journal[1].continuationOf, "initiate");
});

test("the local runtime's literal OK initiation body preserves the other shape gates", async () => {
  const run = await fixture({ initialBody: "OK" });
  run.sender.bindSession({ recipe: run.recipe, initiateOperationId: "initiate" });
  await run.sender.sendSessionStep({ recipe: run.recipe, stepIndex: 1 });
  assert.equal(run.sent.length, 3);
  const invalid = await fixture({ initialBody: "unrecognized response" });
  assert.throws(() =>
    invalid.sender.bindSession({ recipe: invalid.recipe, initiateOperationId: "initiate" }),
  );
});

test("a refused chunk and object 404 cannot discharge a still-active session", async () => {
  const run = await fixture({ chunkStatus: 400 });
  run.sender.bindSession({ recipe: run.recipe, initiateOperationId: "initiate" });
  await run.sender.sendSessionStep({ recipe: run.recipe, stepIndex: 1 });
  const name = run.recipe.objects[0];
  for (const [id, query] of [
    ["refused-metadata", {}],
    ["refused-media", { alt: "media" }],
  ])
    await run.sender.sendStep({
      id,
      objectName: name,
      dialect: "gcs",
      method: "GET",
      credential: "admin",
      path: `/storage/v1/b/example.appspot.com/o/${encodeURIComponent(name)}`,
      query,
    });
  await assert.rejects(
    run.sender.confirmAbsent({
      name,
      mutationOperationId: "chunk-0",
      metadataOperationId: "refused-metadata",
      mediaOperationId: "refused-media",
    }),
  );
  assert.equal(run.sender.unresolved().length, 1);
});

test("terminal cancellation and four fresh absence reads can discharge the owned session", async () => {
  const run = await fixture();
  run.sender.bindSession({ recipe: run.recipe, initiateOperationId: "initiate" });
  await run.sender.sendSessionStep({ recipe: run.recipe, stepIndex: 1 });
  run.sender.beginCleanup();
  await run.sender.sendSessionStep({ recipe: run.recipe, cleanupIndex: 0 });
  await run.sender.sendSessionStep({ recipe: run.recipe, cleanupIndex: 1 });
  const name = run.recipe.objects[0],
    ids = [];
  for (const dialect of ["gcs", "firebase"])
    for (const kind of ["metadata", "media"]) {
      const id = `${dialect}-${kind}`;
      ids.push(id);
      await run.sender.sendStep({
        id,
        objectName: name,
        dialect,
        method: "GET",
        credential: "admin",
        path: `/${dialect === "gcs" ? "storage/v1" : "v0"}/b/example.appspot.com/o/${encodeURIComponent(name)}`,
        query: kind === "media" ? { alt: "media" } : {},
      });
    }
  await run.sender.confirmCancelledSession({
    name,
    cancelOperationId: "cancel-unconfirmed-session",
    queryOperationId: "verify-session-cancelled",
    readbackOperationIds: ids,
  });
  assert.deepEqual(run.sender.unresolved(), []);
  await run.sender.verifyRunEmpty();
  run.sender.close();
  assert.equal(run.sender.snapshot().mode, "closed");
});

test("an unsupported cancellation keeps session responsibility and blocks its dependent poll", async () => {
  const run = await fixture({ cancelStatus: 501 });
  run.sender.bindSession({ recipe: run.recipe, initiateOperationId: "initiate" });
  run.sender.beginCleanup();
  await run.sender.sendSessionStep({ recipe: run.recipe, cleanupIndex: 0 });
  await assert.rejects(run.sender.sendSessionStep({ recipe: run.recipe, cleanupIndex: 1 }));
  assert.equal(run.sender.unresolved().length, 1);
  await assert.rejects(run.sender.verifyRunEmpty());
});

test("object 404 cannot substitute for the terminal query of an active session", async () => {
  const run = await fixture({ cancellationChangesState: false });
  run.sender.bindSession({ recipe: run.recipe, initiateOperationId: "initiate" });
  run.sender.beginCleanup();
  await run.sender.sendSessionStep({ recipe: run.recipe, cleanupIndex: 0 });
  const name = run.recipe.objects[0];
  await run.sender.sendStep({
    id: "forged-terminal-query",
    objectName: name,
    dialect: "gcs",
    method: "GET",
    credential: "admin",
    path: `/storage/v1/b/example.appspot.com/o/${encodeURIComponent(name)}`,
    query: {},
    continuation: { afterStep: "cancel-unconfirmed-session" },
  });
  const ids = await readAbsentSessionObject(run);
  await assert.rejects(
    run.sender.confirmCancelledSession({
      name,
      cancelOperationId: "cancel-unconfirmed-session",
      queryOperationId: "forged-terminal-query",
      readbackOperationIds: ids,
    }),
  );
  const actual = await run.sender.sendSessionStep({ recipe: run.recipe, cleanupIndex: 1 });
  assert.equal(actual.status, 308);
  assert.equal(run.sender.unresolved().length, 1);
});

test("malformed or incomplete prefix lists preserve cancelled-session responsibility", async () => {
  for (const absenceListBody of [
    null,
    [],
    {},
    { error: { code: 200 } },
    { items: null },
    { items: {} },
    { items: [null] },
    { items: [{ name: "outside", bucket: "example.appspot.com" }] },
    { items: [{ name: "storage-object/recordone/session", bucket: "another.appspot.com" }] },
    { items: [], nextPageToken: "pending" },
    { items: [], nextPageToken: false },
    { items: [], nextPageToken: "" },
    { items: [], prefixes: ["hidden/"] },
  ]) {
    const run = await fixture({ absenceListBody });
    run.sender.bindSession({ recipe: run.recipe, initiateOperationId: "initiate" });
    run.sender.beginCleanup();
    await run.sender.sendSessionStep({ recipe: run.recipe, cleanupIndex: 0 });
    await run.sender.sendSessionStep({ recipe: run.recipe, cleanupIndex: 1 });
    const ids = await readAbsentSessionObject(run);
    await assert.rejects(
      run.sender.confirmCancelledSession({
        name: run.recipe.objects[0],
        cancelOperationId: "cancel-unconfirmed-session",
        queryOperationId: "verify-session-cancelled",
        readbackOperationIds: ids,
      }),
    );
    assert.equal(run.sender.unresolved().length, 1);
    assert.equal(run.sender.sessionSnapshot({ name: run.recipe.objects[0] }).cancelled, false);
  }
});

test("the final namespace proof rejects a malformed successful list response", async () => {
  const plan = buildStage3DraftPlan({
    projectId: "example-project",
    bucket: "example.appspot.com",
    runIds: ["recordone", "recordtwo"],
  });
  let lists = 0;
  const sender = createLocalStorageSender({
    plan,
    origin: "http://127.0.0.1:9199",
    credentials: { admin: "Bearer owner" },
    onStart: async () => {},
    onReserve: async () => {},
    onJournal: async () => {},
    fetchImpl: async () => Response.json(++lists === 1 ? { items: [] } : null),
  });
  await sender.start();
  await sender.admitNamespace();
  await assert.rejects(sender.verifyRunEmpty());
});

test("off-origin, foreign-name and ambiguous session URLs cannot supply a follow-up request", async () => {
  for (const locationChange of [
    (uri) => uri.replace("http://127.0.0.1:9199", "https://storage.googleapis.com"),
    (uri) => uri.replace("9199", "9200"),
    (uri) => uri + "&upload_id=another",
    (uri) => uri + "&extra=value",
    (uri) => uri.replace("recordone", "recordtwo"),
    (uri) => uri.replace("/upload/storage/", "/storage/"),
    (uri) => uri + "#fragment",
  ]) {
    const run = await fixture({ locationChange });
    assert.throws(() =>
      run.sender.bindSession({ recipe: run.recipe, initiateOperationId: "initiate" }),
    );
    await assert.rejects(run.sender.sendSessionStep({ recipe: run.recipe, stepIndex: 1 }));
    assert.equal(run.sent.length, 2);
    assert.equal(run.sender.unresolved().length, 1);
  }
});

test("a progress answer that differs from the declared range is captured, not judged: the final bytes are still sent and the session stays unresolved", async () => {
  // Production's answers to a chunk and to a progress query have not been recorded, so the recorder
  // sends the next declared request whatever the last answer was. Ownership is still proved only
  // by an owned readback, so the session is not discharged.
  const run = await fixture({ range: "bytes=0-7" });
  run.sender.bindSession({ recipe: run.recipe, initiateOperationId: "initiate" });
  await run.sender.sendSessionStep({ recipe: run.recipe, stepIndex: 1 });
  await run.sender.sendSessionStep({ recipe: run.recipe, stepIndex: 2 });
  const finish = await run.sender.sendSessionStep({ recipe: run.recipe, stepIndex: 3 });
  assert.equal(finish.status, 308, "the answer is returned as it came");
  assert.equal(run.sent.length, 5);
  assert.equal(run.sender.unresolved().length, 1);
});

test("a refused chunk does not stop the progress query after it, and is captured", async () => {
  const run = await fixture({ chunkStatus: 400 });
  run.sender.bindSession({ recipe: run.recipe, initiateOperationId: "initiate" });
  const chunk = await run.sender.sendSessionStep({ recipe: run.recipe, stepIndex: 1 });
  assert.equal(chunk.status, 400);
  const progress = await run.sender.sendSessionStep({ recipe: run.recipe, stepIndex: 2 });
  assert.equal(progress.status, 400);
  assert.equal(run.sender.unresolved().length, 1);
});

test("a changed declaration cannot reuse a captured session capability", async () => {
  const run = await fixture();
  run.sender.bindSession({ recipe: run.recipe, initiateOperationId: "initiate" });
  const changed = structuredClone(run.recipe);
  changed.steps[1].headers["content-range"] = "bytes 7-262150/262147";
  await assert.rejects(run.sender.sendSessionStep({ recipe: changed, stepIndex: 1 }));
  assert.equal(run.sent.length, 2);
});
