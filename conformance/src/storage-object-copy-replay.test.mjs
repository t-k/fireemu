import assert from "node:assert/strict";
import test from "node:test";
import { buildCorpus } from "./storage-object/corpus.mjs";
import { replayLocalCopyRewrite } from "./storage-object/copy-replay.mjs";
import { createLocalStorageSender } from "./storage-object/sender.mjs";
import { buildStage3DraftPlan } from "./storage-object/stage3-plan.mjs";

function fixture({
  partialCalls = 0,
  failContinuation = false,
  badProgress = false,
  exceptionIncludesUrl = false,
  refusedRewrite = false,
  firebaseFirstReadBump = false,
} = {}) {
  const bucket = "example.appspot.com";
  const plan = buildStage3DraftPlan({
    projectId: "example-project",
    bucket,
    runIds: ["recordone", "recordtwo"],
  });
  const recipe = buildCorpus({ bucket, prefix: plan.recordings[0].prefix }).recipes.find(
    (row) => row.id === "storage-object/gcs/copy-rewrite",
  );
  const objects = new Map(),
    captures = [],
    reservations = [],
    deleted = [],
    transfers = [];
  let generation = 9007199254740993n,
    rewriteCalls = 0;
  const sender = createLocalStorageSender({
    plan,
    origin: "http://127.0.0.1:9199",
    credentials: { admin: "Bearer owner" },
    onStart: async () => {},
    onReserve: async (row) => reservations.push(row),
    onJournal: async () => {},
    fetchImpl: async (href, init) => {
      const url = new URL(href);
      if (init.method === "GET" && url.pathname === `/storage/v1/b/${bucket}/o`)
        return Response.json({ items: [...objects.values()].map((row) => row.metadata) });
      const root = url.pathname.includes("/o/")
        ? url.pathname.slice(url.pathname.indexOf("/o/") + 3)
        : undefined;
      const name = url.searchParams.get("name") ?? decodeURIComponent(root?.split("/")[0]);
      const make = (target, bytes, extra = {}) => {
        const metadata = {
          kind: "storage#object",
          bucket,
          name: target,
          generation: `${generation++}`,
          metageneration: "1",
          size: `${bytes.length}`,
          ...extra,
        };
        objects.set(target, { metadata, bytes });
        return metadata;
      };
      if (root?.includes("/copyTo/") || root?.includes("/rewriteTo/")) {
        const destination = decodeURIComponent(root.split("/o/")[1]);
        const source = objects.get(name);
        transfers.push({ href, name, destination });
        if (!source) return Response.json({ error: "missing source" }, { status: 404 });
        if (objects.has(destination)) return Response.json({ error: "occupied" }, { status: 412 });
        if (root.includes("/copyTo/")) {
          assert.equal(url.searchParams.get("ifSourceGenerationMatch"), source.metadata.generation);
          assert.equal(
            url.searchParams.get("ifSourceMetagenerationMatch"),
            source.metadata.metageneration,
          );
          return Response.json(
            make(destination, source.bytes, { metadata: source.metadata.metadata }),
          );
        }
        rewriteCalls++;
        if (failContinuation && rewriteCalls === 2)
          throw new Error(
            exceptionIncludesUrl ? `failed fetch ${href}` : "uncertain rewrite transport",
          );
        if (refusedRewrite) return Response.json({ error: "refused rewrite" }, { status: 412 });
        if (rewriteCalls > 1)
          assert.equal(url.searchParams.get("rewriteToken"), `private-token-${rewriteCalls - 1}`);
        if (rewriteCalls <= partialCalls)
          return Response.json({
            kind: "storage#rewriteResponse",
            done: false,
            objectSize: "5",
            totalBytesRewritten: badProgress ? "6" : "2",
            rewriteToken: `private-token-${rewriteCalls}`,
          });
        return Response.json({
          kind: "storage#rewriteResponse",
          done: true,
          objectSize: "5",
          totalBytesRewritten: "5",
          resource: make(destination, source.bytes, {
            contentType: "text/plain",
            metadata: { marker: "rewrite-override" },
          }),
        });
      }
      if (init.method === "POST") return Response.json(make(name, Buffer.from(init.body)));
      const object = objects.get(name);
      if (!object) return Response.json({ error: "missing" }, { status: 404 });
      if (init.method === "PATCH") {
        Object.assign(object.metadata, JSON.parse(init.body));
        object.metadata.metageneration = `${BigInt(object.metadata.metageneration) + 1n}`;
        return Response.json(object.metadata);
      }
      if (init.method === "DELETE") {
        assert.equal(url.searchParams.get("ifGenerationMatch"), object.metadata.generation);
        deleted.push(name);
        objects.delete(name);
        return new Response(null, { status: 204 });
      }
      if (url.searchParams.get("alt") === "media") return new Response(object.bytes);
      if (firebaseFirstReadBump && url.pathname.startsWith("/v0/") && !object.firebaseRead) {
        object.firebaseRead = true;
        object.metadata.metageneration = `${BigInt(object.metadata.metageneration) + 1n}`;
        object.metadata.metadata = {
          ...object.metadata.metadata,
          firebaseStorageDownloadTokens: "fixture-token",
        };
      }
      const metadata = { ...object.metadata };
      if (url.pathname.startsWith("/v0/")) {
        delete metadata.kind;
        metadata.downloadTokens = metadata.metadata?.firebaseStorageDownloadTokens
          ? ["fixture-token"]
          : [];
      }
      return Response.json(metadata);
    },
  });
  return {
    sender,
    objects,
    captures,
    reservations,
    deleted,
    transfers,
    run: () =>
      replayLocalCopyRewrite({
        sender,
        recipe,
        bucket,
        onCapture: async (row) => captures.push(row),
      }),
  };
}

test("copy and a completed rewrite bind their response resources before fresh owned cleanup", async () => {
  const run = fixture();
  const result = await run.run();
  assert.equal(result.status, "LOCAL_COMPLETE");
  assert.equal(result.rewriteAttempts, 1);
  assert.equal(run.deleted.length, 5);
  assert.equal(run.objects.size, 0);
  assert.deepEqual(result.unresolved, []);
  assert.equal(result.requests, run.reservations.length);
  assert.equal(run.transfers.length, 6);
});

test("a continuation consumes the same counter and uses only the captured preceding token", async () => {
  const run = fixture({ partialCalls: 1 });
  const result = await run.run();
  assert.equal(result.status, "LOCAL_COMPLETE");
  assert.equal(result.rewriteAttempts, 2);
  assert.ok(run.captures.some((row) => row.operationId === "rewrite-1"));
  assert.equal(result.requests, run.reservations.length);
});

test("uncertain rewrite continuation retains the pending target and cleans only confirmed source and copy", async () => {
  const run = fixture({ partialCalls: 1, failContinuation: true });
  const result = await run.run();
  assert.equal(result.status, "LOCAL_NEEDS_RECOVERY");
  assert.equal(run.deleted.length, 2);
  assert.equal(result.unresolved.length, 1);
  assert.ok(result.unresolved[0].endsWith("/rewritten.bin"));
  assert.equal(run.sender.snapshot().mode, "cleanup");
});

test("eight incomplete rewrite replies stop without another send or an unowned delete", async () => {
  const run = fixture({ partialCalls: 8 });
  const result = await run.run();
  assert.equal(result.status, "LOCAL_NEEDS_RECOVERY");
  assert.equal(result.rewriteAttempts, 8);
  assert.equal(result.failure.reason, "INCOMPLETE_REWRITE");
  assert.equal(run.deleted.length, 2);
  assert.equal(result.unresolved.length, 1);
});

test("invalid rewrite progress is captured and stops before a continuation", async () => {
  const run = fixture({ partialCalls: 1, badProgress: true });
  const result = await run.run();
  assert.equal(result.status, "LOCAL_NEEDS_RECOVERY");
  assert.equal(result.failure.reason, "INVALID_PROGRESS");
  assert.equal(run.transfers.length, 2);
  assert.ok(run.captures.some((row) => row.operationId === "rewrite-0"));
  assert.equal(run.deleted.length, 2);
});

test("an arbitrary transport exception cannot publish the private continuation token", async () => {
  const run = fixture({ partialCalls: 1, failContinuation: true, exceptionIncludesUrl: true });
  const result = await run.run();
  assert.equal(result.status, "LOCAL_NEEDS_RECOVERY");
  assert.equal(JSON.stringify(result).includes("private-token-1"), false);
  assert.equal(result.failure.reason, "LOCAL_REQUEST_OR_PROOF_FAILED");
});

test("a refused first rewrite is followed by bound absence and cleanup rather than an uncertain target", async () => {
  const run = fixture({ refusedRewrite: true });
  const result = await run.run();
  assert.equal(result.status, "LOCAL_BLOCKED");
  assert.equal(result.failure.reason, "REWRITE_REFUSED");
  assert.equal(result.rewriteAttempts, 1);
  assert.equal(run.deleted.length, 2);
  assert.deepEqual(result.unresolved, []);
  assert.equal(run.sender.snapshot().mode, "closed");
});

test("the first Firebase metadata mutation stays observable while transfers use the later GCS metageneration", async () => {
  const run = fixture({ firebaseFirstReadBump: true });
  const result = await run.run();
  assert.equal(result.status, "LOCAL_COMPLETE");
  assert.deepEqual(
    result.firstFirebaseMetadataRead.map((row) => row.metageneration),
    ["2", "3", "3"],
  );
  assert.deepEqual(
    result.firstFirebaseMetadataRead.map((row) => row.hasDownloadToken),
    [false, true, true],
  );
  assert.equal(JSON.stringify(result).includes("fixture-token"), false);
});
