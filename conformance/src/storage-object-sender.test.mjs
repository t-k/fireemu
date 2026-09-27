import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { createLocalStorageSender, validateStorageRoute } from "./storage-object/sender.mjs";
import { buildCorpus } from "./storage-object/corpus.mjs";
import { buildStage3DraftPlan } from "./storage-object/stage3-plan.mjs";

const plan = () =>
  buildStage3DraftPlan({
    projectId: "example-project",
    bucket: "example.appspot.com",
    runIds: ["recordone", "recordtwo"],
  });
const prefix = "storage-object/recordone/";
const name = `${prefix}simple/object.bin`;

test("all 1,888 base declarations have an owned route or an explicit session reference", () => {
  const corpus = buildCorpus({ bucket: "example.appspot.com", prefix });
  const counts = { direct: 0, session: 0 };
  for (const recipe of corpus.recipes) {
    for (const step of [...recipe.preflight, ...recipe.steps, ...recipe.cleanup]) {
      const route = validateStorageRoute(step, { bucket: "example.appspot.com", prefix });
      counts[route]++;
    }
  }
  assert.deepEqual(counts, { direct: 1866, session: 22 });
});

test("collection requests use a scoped prefix without inventing an object name", () => {
  const boundary = { bucket: "example.appspot.com", prefix };
  const list = {
    id: "list",
    dialect: "gcs",
    method: "GET",
    collection: true,
    scopePrefix: `${prefix}errors/object-name/`,
    path: "/storage/v1/b/example.appspot.com/o",
    query: { prefix: `${prefix}errors/object-name/list\n` },
  };
  assert.equal(validateStorageRoute(list, boundary), "direct");
  for (const changed of [
    { ...list, objectName: `${prefix}fake.bin` },
    { ...list, query: { prefix: "storage-object/recordtwo/" } },
    { ...list, scopePrefix: "storage-object/recordtwo/" },
    { ...list, method: "DELETE" },
    { ...list, path: "/storage/v1/b/example.appspot.com/o/outside" },
  ])
    assert.throws(() => validateStorageRoute(changed, boundary));
});

function fixture() {
  const events = [];
  let fetchCalls = 0;
  const sender = createLocalStorageSender({
    plan: plan(),
    origin: "http://127.0.0.1:9199",
    fetchImpl: async (url, init) => {
      fetchCalls++;
      events.push(`fetch:${init.method}:${new URL(url).pathname}`);
      return new Response(JSON.stringify({ items: [] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
    onStart: async () => events.push("started"),
    onReserve: async ({ operationId }) => events.push(`reserve:${operationId}`),
    onJournal: async ({ operationId }) => events.push(`journal:${operationId}`),
  });
  return {
    sender,
    events,
    get fetchCalls() {
      return fetchCalls;
    },
  };
}

test("the only fetch path reserves every attempt after started", async () => {
  const run = fixture();
  await assert.rejects(
    run.sender.sendStep({
      id: "read",
      dialect: "gcs",
      method: "GET",
      objectName: name,
      path: `/storage/v1/b/example.appspot.com/o/${encodeURIComponent(name)}`,
      query: {},
    }),
    /started/i,
  );
  assert.equal(run.fetchCalls, 0);
  await run.sender.start();
  await run.sender.admitNamespace();
  run.sender.admitObject(name);
  await run.sender.sendStep({
    id: "read",
    dialect: "gcs",
    method: "GET",
    objectName: name,
    path: `/storage/v1/b/example.appspot.com/o/${encodeURIComponent(name)}`,
    query: {},
  });
  assert.equal(run.fetchCalls, 2);
  assert.equal(run.sender.snapshot().total, 2);
  assert.deepEqual(run.events.slice(0, 3), [
    "started",
    "reserve:initial-prefix-list",
    "fetch:GET:/storage/v1/b/example.appspot.com/o",
  ]);
  assert.ok(
    run.events.indexOf("reserve:read") <
      run.events.findIndex((event) =>
        event.startsWith("fetch:GET:/storage/v1/b/example.appspot.com/o/"),
      ),
  );
});

test("the ownership journal is written before a mutation is fetched", async () => {
  const run = fixture();
  await run.sender.start();
  await run.sender.admitNamespace();
  run.sender.admitObject(name);
  await run.sender.sendStep({
    id: "upload",
    dialect: "gcs",
    method: "POST",
    objectName: name,
    path: "/upload/storage/v1/b/example.appspot.com/o",
    query: { uploadType: "media", name, ifGenerationMatch: "0" },
    headers: { "content-type": "application/octet-stream" },
    body: { base64: "YQ==" },
  });
  assert.ok(run.events.indexOf("reserve:upload") < run.events.indexOf("journal:upload"));
  assert.ok(
    run.events.indexOf("journal:upload") <
      run.events.findIndex((event) => event.startsWith("fetch:POST:")),
  );
  assert.equal(run.sender.snapshot().total, run.fetchCalls);
});

test("a failed journal and an outside-prefix cleanup never reach fetch", async () => {
  const run = fixture();
  await run.sender.start();
  await run.sender.admitNamespace();
  run.sender.admitObject(name);
  const outside = "storage-object/recordtwo/simple/object.bin";
  await assert.rejects(
    run.sender.sendStep({
      id: "outside",
      dialect: "gcs",
      method: "DELETE",
      objectName: outside,
      path: `/storage/v1/b/example.appspot.com/o/${encodeURIComponent(outside)}`,
      query: {},
    }),
    /prefix/i,
  );
  assert.equal(run.fetchCalls, 1);
  assert.throws(
    () =>
      createLocalStorageSender({
        plan: plan(),
        origin: "https://storage.googleapis.com",
        fetchImpl: async () => new Response(),
      }),
    /loopback/i,
  );
  let calls = 0;
  const failing = createLocalStorageSender({
    plan: plan(),
    origin: "http://127.0.0.1:9199",
    fetchImpl: async () => {
      calls++;
      return new Response('{"items":[]}', { status: 200 });
    },
    onStart: async () => {},
    onReserve: async () => {},
    onJournal: async () => {
      throw new Error("journal unavailable");
    },
  });
  await failing.start();
  await failing.admitNamespace();
  failing.admitObject(name);
  await assert.rejects(
    failing.sendStep({
      id: "upload",
      dialect: "gcs",
      method: "POST",
      objectName: name,
      path: "/upload/storage/v1/b/example.appspot.com/o",
      query: { uploadType: "media", name, ifGenerationMatch: "0" },
      body: { base64: "YQ==" },
    }),
    /journal unavailable/,
  );
  assert.equal(calls, 1);
  assert.equal(failing.snapshot().total, 2);
});

test("a bound upload is deleted only at its owned generation with counted absence readbacks", async () => {
  const events = [];
  const body = Buffer.from("a");
  const digest = createHash("sha256").update(body).digest("hex");
  const object = { bucket: "example.appspot.com", name, generation: "123" };
  let present = false;
  let fetchCalls = 0;
  const sender = createLocalStorageSender({
    plan: plan(),
    origin: "http://127.0.0.1:9199",
    fetchImpl: async (href, init) => {
      fetchCalls++;
      const url = new URL(href);
      events.push(`fetch:${init.method}:${url.searchParams.get("ifGenerationMatch") ?? ""}`);
      if (url.pathname === "/storage/v1/b/example.appspot.com/o")
        return Response.json({ items: [] });
      if (init.method === "POST") {
        present = true;
        return Response.json(object);
      }
      if (init.method === "DELETE") {
        assert.equal(url.searchParams.get("ifGenerationMatch"), "123");
        present = false;
        return new Response(null, { status: 204 });
      }
      if (!present) return Response.json({ error: "missing" }, { status: 404 });
      if (url.searchParams.get("alt") === "media") return new Response(body);
      return Response.json(object);
    },
    onStart: async () => events.push("started"),
    onReserve: async ({ operationId }) => events.push(`reserve:${operationId}`),
    onJournal: async ({ operationId }) => events.push(`journal:${operationId}`),
  });
  await sender.start();
  await sender.admitNamespace();
  sender.admitObject(name);
  await sender.sendStep({
    id: "upload",
    dialect: "gcs",
    method: "POST",
    objectName: name,
    path: "/upload/storage/v1/b/example.appspot.com/o",
    query: { uploadType: "media", name, ifGenerationMatch: "0" },
    body: { base64: "YQ==" },
  });
  await sender.sendStep({
    id: "metadata",
    dialect: "gcs",
    method: "GET",
    objectName: name,
    path: `/storage/v1/b/example.appspot.com/o/${encodeURIComponent(name)}`,
    query: {},
  });
  await sender.sendStep({
    id: "media",
    dialect: "gcs",
    method: "GET",
    objectName: name,
    path: `/storage/v1/b/example.appspot.com/o/${encodeURIComponent(name)}`,
    query: { alt: "media" },
  });
  await sender.sendStep({
    id: "range",
    dialect: "gcs",
    method: "GET",
    objectName: name,
    path: `/storage/v1/b/example.appspot.com/o/${encodeURIComponent(name)}`,
    query: { alt: "media" },
    headers: { range: "bytes=0-0" },
  });
  assert.throws(
    () =>
      sender.confirmOwned({
        name,
        uploadOperationId: "upload",
        metadataOperationId: "metadata",
        mediaOperationId: "range",
        expectedBytesSha256: digest,
      }),
    /readbacks|range/i,
  );
  assert.throws(
    () =>
      sender.confirmOwned({
        name,
        uploadOperationId: "upload",
        metadataOperationId: "metadata",
        mediaOperationId: "media",
        expectedBytesSha256: "b".repeat(64),
      }),
    /bytes/i,
  );
  assert.equal(
    sender.confirmOwned({
      name,
      uploadOperationId: "upload",
      metadataOperationId: "metadata",
      mediaOperationId: "media",
      expectedBytesSha256: digest,
    }),
    "123",
  );
  sender.beginCleanup();
  await assert.rejects(
    sender.cleanupOwned({
      name: "storage-object/recordtwo/x",
      metadataOperationId: "metadata",
      mediaOperationId: "media",
      operationId: "outside",
    }),
    /prefix/i,
  );
  const deleted = await sender.cleanupOwned({
    name,
    metadataOperationId: "metadata",
    mediaOperationId: "media",
    operationId: "cleanup",
  });
  assert.equal(deleted.status, 204);
  assert.equal(sender.unresolved().length, 0);
  await sender.verifyRunEmpty();
  assert.equal(sender.snapshot().total, fetchCalls);
  assert.ok(events.indexOf("reserve:cleanup") < events.indexOf("journal:cleanup"));
  assert.ok(events.indexOf("journal:cleanup") < events.indexOf("fetch:DELETE:123"));
});
