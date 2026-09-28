import assert from "node:assert/strict";
import test from "node:test";
import { spawnSync } from "node:child_process";
import { replayLocalBasic } from "./storage-object/basic-replay.mjs";
import { replayLocalAdmin } from "./storage-object/admin-replay.mjs";
import { buildCorpus } from "./storage-object/corpus.mjs";
import { createLocalStorageSender } from "./storage-object/sender.mjs";
import { buildStage3DraftPlan } from "./storage-object/stage3-plan.mjs";

function fixture({
  recipeId = "storage-object/firebase/simple-upload",
  driftBeforeCleanup = false,
  occupied = false,
} = {}) {
  const plan = buildStage3DraftPlan({
    projectId: "example-project",
    bucket: "example.appspot.com",
    runIds: ["recordone", "recordtwo"],
  });
  const recipe = buildCorpus({
    bucket: plan.bucket,
    prefix: plan.recordings[0].prefix,
  }).recipes.find((row) => row.id === recipeId);
  const objects = new Map(),
    reservations = [],
    deleted = [],
    events = [];
  let generation = 9007199254740993n;
  let sender;
  sender = createLocalStorageSender({
    plan,
    origin: "http://127.0.0.1:9199",
    credentials: { admin: "Bearer owner" },
    onStart: async () => events.push("started"),
    onReserve: async (row) => {
      reservations.push(row);
      events.push("reserved");
    },
    onJournal: async () => events.push("journal"),
    fetchImpl: async (href, init) => {
      events.push("wire");
      const url = new URL(href);
      if (url.pathname === `/storage/v1/b/${plan.bucket}/o` && init.method === "GET")
        return Response.json({
          items: occupied
            ? [{ bucket: plan.bucket, name: `${plan.recordings[0].prefix}foreign.bin` }]
            : [...objects.values()].map((row) => row.metadata),
        });
      const name = url.searchParams.get("name") ?? decodeURIComponent(url.pathname.split("/o/")[1]);
      if (init.method === "POST") {
        const bytes = Buffer.from(init.body);
        const metadata = {
          kind: "storage#object",
          bucket: plan.bucket,
          name,
          generation: `${generation++}`,
          metageneration: "1",
          size: `${bytes.length}`,
        };
        objects.set(name, { bytes, metadata });
        return Response.json(metadata);
      }
      const object = objects.get(name);
      if (driftBeforeCleanup && sender.snapshot().mode === "cleanup" && object) {
        object.bytes = Buffer.from("changed-by-another-writer");
        object.metadata.generation = "9007199254740999";
      }
      if (init.method === "DELETE") {
        assert.ok(object);
        if (
          sender.snapshot().mode === "cleanup" &&
          url.searchParams.get("ifGenerationMatch") !== object.metadata.generation
        )
          return Response.json({ error: "precondition failed" }, { status: 412 });
        deleted.push(name);
        objects.delete(name);
        return new Response(null, { status: 204 });
      }
      if (!object) return Response.json({ error: "missing" }, { status: 404 });
      if (url.searchParams.get("alt") === "media") return new Response(object.bytes);
      return Response.json(object.metadata);
    },
  });
  return { sender, recipe, bucket: plan.bucket, objects, reservations, deleted, events };
}

test("the extracted basic replay retains counted admission, fresh ownership and final absence", async () => {
  const f = fixture();
  const result = await replayLocalBasic(f);
  assert.equal(result.status, "LOCAL_COMPLETE");
  assert.equal(result.requests, 12);
  assert.equal(f.objects.size, 0);
  assert.equal(f.deleted.length, 1);
  assert.equal(f.sender.snapshot().mode, "closed");
  assert.deepEqual(f.sender.unresolved(), []);
  assert.equal(f.events[0], "started");
  assert.deepEqual(
    f.reservations.map((row) => row.sequence),
    Array.from({ length: 12 }, (_, i) => i + 1),
  );
});

test("extraction preserves a conditional refusal after another writer replaces the owned generation", async () => {
  const f = fixture({ driftBeforeCleanup: true });
  await assert.rejects(replayLocalBasic(f), /conditional delete was not confirmed/);
  assert.equal(f.deleted.length, 0);
  assert.equal(f.objects.size, 1);
  assert.equal(f.sender.unresolved().length, 1);
});

test("an occupied namespace stops an extracted replay before any write or deletion", async () => {
  const f = fixture({ occupied: true });
  await assert.rejects(replayLocalBasic(f), /occupied run prefix/);
  assert.equal(f.reservations.length, 1);
  assert.equal(f.objects.size, 0);
  assert.equal(f.deleted.length, 0);
});

test("the extracted admin replay retains both dialects, subject deletion and final absence", async () => {
  const f = fixture({ recipeId: "storage-object/auth/admin" });
  const result = await replayLocalAdmin(f);
  assert.equal(result.status, "LOCAL_COMPLETE");
  assert.equal(result.credentialProof, "LOCAL_STUB_ONLY");
  assert.equal(result.requests, 32);
  assert.equal(f.objects.size, 0);
  assert.equal(f.deleted.length, 2);
  assert.deepEqual(f.sender.unresolved(), []);
});

test("all six replay modules import with no environment, output or transport side effects", () => {
  const modules = ["basic", "independent", "list", "admin", "object-name", "download-token"];
  const urls = modules.map(
    (name) => new URL(`./storage-object/${name}-replay.mjs`, import.meta.url).href,
  );
  const code = `globalThis.fetch = () => { throw new Error("unexpected transport"); }; process.stdout.write = () => { throw new Error("unexpected output"); }; for (const url of ${JSON.stringify(urls)}) await import(url);`;
  const result = spawnSync(process.execPath, ["--input-type=module", "--eval", code], {
    env: {},
    encoding: "utf8",
    timeout: 10_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "");
});
