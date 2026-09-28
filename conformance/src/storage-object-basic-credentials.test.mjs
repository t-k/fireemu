import assert from "node:assert/strict";
import test from "node:test";
import { replayLocalBasic } from "./storage-object/basic-replay.mjs";
import { buildCorpus } from "./storage-object/corpus.mjs";
import { createLocalStorageSender } from "./storage-object/sender.mjs";
import { buildStage3DraftPlan } from "./storage-object/stage3-plan.mjs";

function fixture(recipeId) {
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
    requests = [];
  let generation = 1n;
  const sender = createLocalStorageSender({
    plan,
    origin: "http://127.0.0.1:9199",
    credentials: { admin: "Bearer fixture-owner" },
    onStart: async () => {},
    onReserve: async () => {},
    onJournal: async () => {},
    fetchImpl: async (href, init) => {
      const url = new URL(href);
      requests.push({
        operationId: init.operationId,
        authorization: init.headers.authorization,
        method: init.method,
      });
      if (init.operationId === "anonymous-media")
        assert.equal(
          init.headers.authorization,
          undefined,
          "a declared anonymous read must carry no owner credential",
        );
      else
        assert.equal(
          init.headers.authorization,
          "Bearer fixture-owner",
          `owner readback ${init.operationId} must carry its declared credential`,
        );
      if (
        init.method === "GET" &&
        [`/storage/v1/b/${plan.bucket}/o`, `/v0/b/${plan.bucket}/o`].includes(url.pathname)
      ) {
        const prefix = url.searchParams.get("prefix");
        return Response.json({
          kind: "storage#objects",
          items: [...objects.values()]
            .map((row) => row.metadata)
            .filter((row) => row.name.startsWith(prefix)),
        });
      }
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
          contentType: "application/octet-stream",
        };
        objects.set(name, { bytes, metadata });
        return Response.json(metadata);
      }
      const object = objects.get(name);
      if (!object)
        return Response.json(
          { error: { code: 404, message: "fixture missing object" } },
          { status: 404 },
        );
      if (init.method === "PATCH") {
        Object.assign(object.metadata, JSON.parse(Buffer.from(init.body).toString("utf8")));
        object.metadata.metageneration = `${BigInt(object.metadata.metageneration) + 1n}`;
        return Response.json(object.metadata);
      }
      if (init.method === "DELETE") {
        if (url.searchParams.has("ifGenerationMatch"))
          assert.equal(url.searchParams.get("ifGenerationMatch"), object.metadata.generation);
        objects.delete(name);
        return new Response(null, { status: 204 });
      }
      if (url.searchParams.get("alt") === "media") return new Response(object.bytes);
      return Response.json(object.metadata);
    },
  });
  return { sender, recipe, bucket: plan.bucket, requests, objects };
}

test("overwrite ownership readbacks carry the explicit owner credential", async () => {
  const f = fixture("storage-object/firebase/overwrite");
  const result = await replayLocalBasic(f);
  assert.equal(result.status, "LOCAL_COMPLETE");
  const supplemental = f.requests.filter((row) => row.operationId.startsWith("supplemental-"));
  assert.equal(supplemental.length, 2);
  assert.ok(supplemental.every((row) => row.authorization === "Bearer fixture-owner"));
  assert.equal(f.objects.size, 0);
});

test("cross-dialect post-delete media confirmation carries the explicit owner credential", async () => {
  const f = fixture("storage-object/cross-dialect/state");
  const result = await replayLocalBasic(f);
  assert.equal(result.status, "LOCAL_COMPLETE");
  const supplemental = f.requests.filter((row) => row.operationId.startsWith("supplemental-"));
  assert.equal(supplemental.length, 1);
  assert.equal(supplemental[0].authorization, "Bearer fixture-owner");
  assert.equal(f.objects.size, 0);
});

test("simple upload completes through the unchanged declared owner requests", async () => {
  const f = fixture("storage-object/firebase/simple-upload");
  assert.equal((await replayLocalBasic(f)).status, "LOCAL_COMPLETE");
  assert.equal(f.objects.size, 0);
});

test("a declared anonymous media read is not promoted to the owner credential", async () => {
  const f = fixture("storage-object/firebase/simple-upload");
  await f.sender.start();
  await f.sender.admitNamespace();
  const name = f.recipe.objects[0];
  f.sender.admitObject(name);
  await f.sender.sendStep(f.recipe.steps[0]);
  const response = await f.sender.sendStep({
    id: "anonymous-media",
    dialect: "firebase",
    method: "GET",
    objectName: name,
    path: `/v0/b/${f.bucket}/o/${encodeURIComponent(name)}`,
    query: { alt: "media" },
    credential: "none",
  });
  assert.equal(response.status, 200);
  assert.deepEqual(response.raw, Buffer.from(f.recipe.steps[0].body.base64, "base64"));
  assert.equal(f.requests.at(-1).authorization, undefined);
});
