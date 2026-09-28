import assert from "node:assert/strict";
import test from "node:test";
import { spawnSync } from "node:child_process";
import { replayLocalBasic } from "./storage-object/basic-replay.mjs";
import { replayLocalAdmin } from "./storage-object/admin-replay.mjs";
import { replayLocalList } from "./storage-object/list-replay.mjs";
import { buildCorpus } from "./storage-object/corpus.mjs";
import { createLocalStorageSender } from "./storage-object/sender.mjs";
import { buildStage3DraftPlan } from "./storage-object/stage3-plan.mjs";

function fixture({
  recipeId = "storage-object/firebase/simple-upload",
  driftBeforeCleanup = false,
  occupied = false,
  localListGapStatus = null,
  localListGapReason = "invalid",
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
      if (
        [`/storage/v1/b/${plan.bucket}/o`, `/v0/b/${plan.bucket}/o`].includes(url.pathname) &&
        init.method === "GET"
      ) {
        const parameter = ["startOffset", "matchGlob"].find((key) => url.searchParams.has(key));
        if (parameter && localListGapStatus !== null) {
          const message = `unsupported JSON API list parameter: ${parameter}`;
          return Response.json(
            {
              error: {
                code: localListGapStatus,
                message,
                errors: [{ domain: "global", message, reason: localListGapReason }],
              },
            },
            { status: localListGapStatus },
          );
        }
        const scope = url.searchParams.get("prefix");
        const delimiter = url.searchParams.get("delimiter");
        const entries = new Map();
        for (const row of objects.values()) {
          if (!row.metadata.name.startsWith(scope)) continue;
          const suffix = row.metadata.name.slice(scope.length);
          const boundary = delimiter ? suffix.indexOf(delimiter) : -1;
          if (boundary >= 0) {
            const name = `${scope}${suffix.slice(0, boundary + delimiter.length)}`;
            entries.set(name, { prefix: name });
          } else entries.set(row.metadata.name, { item: row.metadata });
        }
        const sorted = [...entries].toSorted(([a], [b]) => a.localeCompare(b));
        const offset = Number(url.searchParams.get("pageToken") ?? 0);
        const limit = Number(url.searchParams.get("maxResults")) || 1000;
        const page = sorted.slice(offset, offset + limit).map(([, value]) => value);
        return Response.json({
          items: occupied
            ? [{ bucket: plan.bucket, name: `${plan.recordings[0].prefix}foreign.bin` }]
            : page.flatMap((row) => (row.item ? [row.item] : [])),
          prefixes: page.flatMap((row) => (row.prefix ? [row.prefix] : [])),
          ...(offset + limit < sorted.length ? { nextPageToken: `${offset + limit}` } : {}),
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

test("explicit local list gap admission records both candidates and retains pagination and owned cleanup", async () => {
  const f = fixture({ recipeId: "storage-object/gcs/list", localListGapStatus: 400 });
  const captures = [];
  const result = await replayLocalList({
    ...f,
    allowKnownLocalListGaps: true,
    onCapture: async (row) => captures.push(row),
  });
  assert.equal(result.status, "LOCAL_COMPLETE");
  assert.deepEqual(
    result.localDifferenceCandidates.map(({ stepId, status, parameter }) => ({
      stepId,
      status,
      parameter,
    })),
    [
      { stepId: "offset-filter", status: 400, parameter: "startOffset" },
      { stepId: "glob-filter", status: 400, parameter: "matchGlob" },
    ],
  );
  assert.ok(
    result.localDifferenceCandidates.every((row) => row.compatibility === "UNOBSERVED_PRODUCTION"),
  );
  assert.equal(result.pageEvaluation.status, "MATCHED_SUPPLIED_PAGES");
  assert.equal(result.requests, 73);
  assert.equal(f.deleted.length, 6);
  assert.equal(f.objects.size, 0);
  assert.deepEqual(result.unresolved, []);
  assert.deepEqual(
    captures.filter((row) => row.status === 400).map((row) => row.stepId),
    ["offset-filter", "glob-filter"],
  );
});

test("known local list gaps require opt-in and never admit authorization errors", async () => {
  for (const [status, allowKnownLocalListGaps] of [
    [400, false],
    [401, true],
    [403, true],
    [500, true],
  ]) {
    const f = fixture({ recipeId: "storage-object/gcs/list", localListGapStatus: status });
    await assert.rejects(
      replayLocalList({ ...f, allowKnownLocalListGaps, onCapture: async () => {} }),
      /list response was not 200/,
    );
    assert.equal(f.deleted.length, 0);
    assert.equal(f.sender.unresolved().length, 6);
    assert.equal(f.reservations.at(-1).operationId, "offset-filter");
  }
});

test("local list gap admission cannot excuse another error body, altered query or undeclared step", async () => {
  for (const variation of ["error-body", "query", "step"]) {
    const f = fixture({
      recipeId: "storage-object/gcs/list",
      localListGapStatus: 400,
      ...(variation === "error-body" ? { localListGapReason: "permissionDenied" } : {}),
    });
    const step = f.recipe.steps.find((row) => row.id === "offset-filter");
    if (variation === "query") step.query.startOffset += "changed";
    if (variation === "step") step.id = "unregistered-filter";
    await assert.rejects(
      replayLocalList({ ...f, allowKnownLocalListGaps: true, onCapture: async () => {} }),
      /list response was not 200/,
    );
    assert.equal(f.deleted.length, 0);
    assert.equal(f.sender.unresolved().length, 6);
    assert.equal(f.reservations.at(-1).operationId, step.id);
  }
});

test("local list gap admission requires capture before start and stops if capture fails", async () => {
  const missing = fixture({ recipeId: "storage-object/gcs/list", localListGapStatus: 400 });
  await assert.rejects(
    replayLocalList({ ...missing, allowKnownLocalListGaps: true }),
    /capture writer is required/,
  );
  assert.equal(missing.reservations.length, 0);
  assert.equal(missing.sender.snapshot().mode, "not-started");
  const failed = fixture({ recipeId: "storage-object/gcs/list", localListGapStatus: 400 });
  await assert.rejects(
    replayLocalList({
      ...failed,
      allowKnownLocalListGaps: true,
      onCapture: async ({ stepId }) => {
        if (stepId === "offset-filter") throw new Error("capture fsync failed");
      },
    }),
    /capture fsync failed/,
  );
  assert.equal(failed.reservations.at(-1).operationId, "offset-filter");
  assert.equal(failed.deleted.length, 0);
  assert.equal(failed.sender.unresolved().length, 6);
});
