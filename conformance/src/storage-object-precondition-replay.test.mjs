import assert from "node:assert/strict";
import test from "node:test";
import { buildCorpus } from "./storage-object/corpus.mjs";
import { replayLocalPreconditions } from "./storage-object/precondition-replay.mjs";
import { createLocalStorageSender } from "./storage-object/sender.mjs";
import { buildStage3DraftPlan } from "./storage-object/stage3-plan.mjs";

function fixture({
  failThirdUpload = false,
  driftDuringCleanup = false,
  driftOnRead = false,
  singleRead = false,
  occupied = false,
  driftBeforeSubject = false,
} = {}) {
  const bucket = "example.appspot.com";
  const plan = buildStage3DraftPlan({
    projectId: "example-project",
    bucket,
    runIds: ["recordone", "recordtwo"],
  });
  let recipe = buildCorpus({ bucket, prefix: plan.recordings[0].prefix }).recipes.find(
    (row) => row.id === "storage-object/gcs/generation-preconditions",
  );
  if (singleRead) {
    const name = recipe.steps.find(
      (row) => row.id === "metadata-read-ifGenerationMatch-current",
    ).objectName;
    recipe = {
      ...recipe,
      objects: [name],
      preflight: recipe.preflight.filter((row) => row.objectName === name),
      steps: recipe.steps.filter((row) => row.objectName === name),
      cleanup: recipe.cleanup.filter((row) => row.objectName === name),
    };
  }
  const objects = new Map(),
    captures = [],
    deleted = [];
  let posts = 0,
    cleanup = false;
  const sender = createLocalStorageSender({
    plan,
    origin: "http://127.0.0.1:9199",
    credentials: { admin: "Bearer owner" },
    onStart: async () => {},
    onReserve: async () => {},
    onJournal: async () => {},
    fetchImpl: async (href, init) => {
      const url = new URL(href);
      if (init.method === "GET" && url.pathname === `/storage/v1/b/${bucket}/o`)
        return Response.json({
          items: occupied
            ? [{ bucket, name: `${plan.recordings[0].prefix}foreign.bin` }]
            : [...objects.values()].map((row) => row.metadata),
        });
      const name = url.searchParams.get("name") ?? decodeURIComponent(url.pathname.split("/o/")[1]);
      if (init.method === "POST") {
        posts++;
        if (failThirdUpload && posts === 3) {
          cleanup = true;
          throw new Error("uncertain transport");
        }
        const metadata = {
          kind: "storage#object",
          bucket,
          name,
          generation: `${9007199254740993n + BigInt(posts)}`,
          metageneration: "1",
        };
        objects.set(name, { metadata, bytes: Buffer.from(init.body) });
        return Response.json(metadata);
      }
      const object = objects.get(name);
      if (driftDuringCleanup && cleanup && object) object.bytes = Buffer.from("changed");
      if (
        driftOnRead &&
        init.method === "GET" &&
        url.searchParams.has("ifGenerationMatch") &&
        object
      )
        object.metadata.metageneration = "2";
      if (init.method === "DELETE") {
        assert.equal(url.searchParams.get("ifGenerationMatch"), object.metadata.generation);
        deleted.push(name);
        objects.delete(name);
        return new Response(null, { status: 204 });
      }
      if (!object) return Response.json({ error: "missing" }, { status: 404 });
      if (url.searchParams.get("alt") === "media") return new Response(object.bytes);
      if (driftBeforeSubject && url.pathname.startsWith("/storage/v1/") && posts === 1)
        object.metadata.generation = "9007199254740999";
      const metadata = { ...object.metadata };
      if (url.pathname.startsWith("/v0/")) delete metadata.kind;
      return Response.json(metadata);
    },
  });
  return {
    bucket,
    recipe,
    sender,
    captures,
    deleted,
    objects,
    run: () =>
      replayLocalPreconditions({
        bucket,
        recipe,
        sender,
        onCapture: async (row) => captures.push(row),
      }),
  };
}
test("an uncertain later upload still cleans earlier confirmed owned objects", async () => {
  const run = fixture({ failThirdUpload: true });
  const result = await run.run();
  assert.equal(result.status, "LOCAL_NEEDS_RECOVERY");
  assert.equal(run.deleted.length, 1);
  assert.equal(run.objects.size, 0);
  assert.equal(result.unresolved.length, 1);
  assert.ok(run.captures.length > 0);
});
test("fresh cleanup reads refuse drift that a subject's old readbacks would miss", async () => {
  const run = fixture({ failThirdUpload: true, driftDuringCleanup: true });
  const result = await run.run();
  assert.equal(result.status, "LOCAL_NEEDS_RECOVERY");
  assert.equal(run.deleted.length, 0);
  assert.equal(run.objects.size, 1);
  assert.equal(result.unresolved.length, 2);
  assert.ok(result.cleanupFailures.length > 0);
});
test("a nominal GET changing only metadata is detected and its raw readbacks are retained", async () => {
  const run = fixture({ singleRead: true, driftOnRead: true });
  const result = await run.run();
  assert.equal(result.status, "LOCAL_BLOCKED");
  assert.equal(result.failure.reason, "READ_STATE_CHANGED");
  assert.ok(
    run.captures.some(
      (row) => row.operationId === "metadata-read-ifGenerationMatch-current-after-gcs-metadata",
    ),
  );
  assert.equal(run.deleted.length, 1);
  assert.equal(run.objects.size, 0);
});
test("unchanged complete reads finish with fresh owned cleanup and final absence", async () => {
  const run = fixture({ singleRead: true });
  const result = await run.run();
  assert.equal(result.status, "LOCAL_COMPLETE");
  assert.deepEqual(result.unresolved, []);
  assert.equal(run.deleted.length, 1);
  assert.equal(run.sender.snapshot().mode, "closed");
});

test("an occupied initial namespace stops after its single counted read", async () => {
  const run = fixture({ occupied: true });
  const result = await run.run();
  assert.equal(result.status, "LOCAL_BLOCKED");
  assert.equal(result.requests, 1);
  assert.equal(run.deleted.length, 0);
});

test("a prerequisite generation must match the independent confirmed ownership", async () => {
  const run = fixture({ driftBeforeSubject: true });
  const result = await run.run();
  assert.equal(result.status, "LOCAL_NEEDS_RECOVERY");
  assert.ok(result.failure);
  assert.equal(run.deleted.length, 0);
  assert.equal(
    run.captures.some((row) => row.operationId === "upload-ifGenerationMatch-current"),
    false,
  );
});
