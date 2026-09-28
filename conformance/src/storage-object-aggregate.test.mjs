import assert from "node:assert/strict";
import test from "node:test";
import {
  isLocalAggregateResultComplete,
  localAggregateRecipeIds,
  replayLocalAggregate,
} from "./storage-object/aggregate-replay.mjs";
import { buildStage3DraftPlan } from "./storage-object/stage3-plan.mjs";

const rulesSource =
  "rules_version = '2';\nservice firebase.storage {\n  match /b/{bucket}/o {\n    match /storage-object/{run}/{allPaths=**} {\n      allow read, write: if request.auth != null && request.auth.token.email == 'storage-object@example.com';\n    }\n  }\n}\n";
function fixture({
  rulesChanged = false,
  uploadFailure = false,
  haltAtUpload = false,
  haltAfterMediaRead = false,
  finishFailure = false,
  startFailure = false,
} = {}) {
  const plan = buildStage3DraftPlan({
    projectId: "example-project",
    bucket: "example.appspot.com",
    runIds: ["recordone", "recordtwo"],
  });
  const events = [],
    requests = [],
    objects = new Map();
  let factories = 0,
    closes = 0,
    providerCalls = 0,
    halted = false;
  const wire = {
    snapshot: () => ({
      attempts: requests.length,
      active: false,
      busy: false,
      halted,
      closed: closes > 0,
      readAfterHaltBytes: 0,
    }),
    close: async () => {
      closes++;
    },
    fetch: async (href, init) => {
      providerCalls++;
      assert.equal(halted, false, "no new transport after halt");
      requests.push({ href, ...init });
      const url = new URL(href);
      if (url.pathname === "/v1/storage/rules")
        return Response.json({
          loaded: true,
          targeted: false,
          source: rulesChanged ? "changed" : rulesSource,
        });
      if (url.pathname === `/storage/v1/b/${plan.bucket}/o`)
        return Response.json({
          kind: "storage#objects",
          items: [...objects.values()].map((row) => row.metadata),
        });
      const name = url.searchParams.get("name") ?? decodeURIComponent(url.pathname.split("/o/")[1]);
      if (init.method === "POST") {
        if (haltAtUpload) {
          halted = true;
          throw new Error("WIRE_RESPONSE_CAP_EXCEEDED");
        }
        if (uploadFailure) throw new Error("unconfirmed upload response loss");
        const bytes = Buffer.from(init.body);
        const metadata = {
          bucket: plan.bucket,
          name,
          generation: "1",
          metageneration: "1",
          size: `${bytes.length}`,
        };
        objects.set(name, { bytes, metadata });
        return Response.json(metadata);
      }
      const object = objects.get(name);
      if (init.method === "DELETE") {
        assert.equal(url.searchParams.get("ifGenerationMatch"), object.metadata.generation);
        objects.delete(name);
        return new Response(null, { status: 204 });
      }
      if (!object) return Response.json({ error: "missing" }, { status: 404 });
      if (haltAfterMediaRead && url.searchParams.get("alt") === "media") halted = true;
      return url.searchParams.get("alt") === "media"
        ? new Response(object.bytes)
        : Response.json(object.metadata);
    },
  };
  const options = {
    plan,
    storageOrigin: "http://127.0.0.1:9199",
    authOrigin: "http://127.0.0.1:9099",
    localControl: { origin: "http://127.0.0.1:9198", token: "synthetic-control-token" },
    localAuth: { apiKey: "storage-object-local-key", password: "synthetic-local-password" },
    credentials: { admin: "Bearer owner" },
    captureDirectory: "/unused-local-fixture",
    wireFactory: () => {
      factories++;
      return wire;
    },
    onStart: async (row) => {
      if (startFailure) throw new Error("start writer failed");
      events.push({ type: "started", ...row });
    },
    onReserve: async (row) => events.push({ type: "reserved", ...row }),
    onRecipeBegin: async (row) => events.push({ type: "recipe-begin", ...row }),
    onRecipeFinish: async (row) => {
      if (finishFailure) throw new Error("finish writer failed");
      events.push({ type: "recipe-finish", ...row });
    },
    onJournal: async (row) => events.push({ type: "journal", ...row }),
    onCapture: async (row) => events.push({ type: "response", ...row }),
    onByteReserve: async () => {},
  };
  return {
    options,
    events,
    requests,
    objects,
    factories: () => factories,
    closes: () => closes,
    providerCalls: () => providerCalls,
  };
}

test("the fixed aggregate registry contains exactly all 26 canonical recipes for each recording", () => {
  const f = fixture();
  const first = localAggregateRecipeIds(f.options.plan, 0);
  const second = localAggregateRecipeIds(f.options.plan, 1);
  assert.equal(first.length, 26);
  assert.equal(new Set(first).size, 26);
  assert.deepEqual(second, first);
  assert.equal(first[0], "storage-object/firebase/simple-upload");
  assert.ok(first.includes("storage-object/errors/authorization"));
  assert.ok(first.includes("storage-object/auth/firebase-id-token"));
  assert.ok(Object.isFrozen(first));
  assert.throws(() => localAggregateRecipeIds(f.options.plan, 2), /recording/);
});

test("clean blocked results and incomplete terminal records cannot receive completion credit", () => {
  const complete = {
    status: "LOCAL_COMPLETE",
    recipeId: "storage-object/firebase/simple-upload",
    requests: 13,
    cleanupFailures: [],
    unresolved: [],
  };
  const accepts = (result) => isLocalAggregateResultComplete(result, complete.recipeId, 13);
  assert.equal(accepts(complete), true);
  for (const status of ["LOCAL_BLOCKED", "LOCAL_NEEDS_RECOVERY"])
    assert.equal(accepts({ ...complete, status }), false);
  assert.equal(accepts({ ...complete, cleanupFailures: ["failed"] }), false);
  assert.equal(accepts({ ...complete, unresolved: ["owned"] }), false);
  assert.equal(accepts({ ...complete, cleanupFailures: undefined }), false);
  assert.equal(accepts({ ...complete, unresolved: undefined }), false);
  assert.equal(accepts({ ...complete, recipeId: "different" }), false);
  assert.equal(accepts({ ...complete, requests: 12 }), false);
  assert.equal(isLocalAggregateResultComplete(complete, complete.recipeId, NaN), false);
});

test("changed plan pins, off-origin routes and adapter overrides reject before counter or wire creation", async () => {
  for (const variation of ["plan", "origin", "adapter"]) {
    const f = fixture();
    if (variation === "plan") f.options.plan.recordings[0].corpusDigest = "0".repeat(64);
    if (variation === "origin") f.options.storageOrigin = "https://storage.googleapis.com";
    if (variation === "adapter") f.options.recipeReplays = {};
    await assert.rejects(replayLocalAggregate(f.options));
    assert.equal(f.factories(), 0);
    assert.equal(f.requests.length, 0);
    assert.equal(f.events.length, 0);
  }
});

test("a changed fixed Rules readback stops before the first recipe and closes the one wire provider", async () => {
  const f = fixture({ rulesChanged: true });
  const result = await replayLocalAggregate(f.options);
  assert.notEqual(result.status, "LOCAL_COMPLETE");
  assert.equal(f.factories(), 1);
  assert.equal(f.closes(), 1);
  assert.equal(f.requests.length, 1);
  assert.equal(result.counter.total, 1);
  assert.deepEqual(result.counter.completedRecipes, [0, 0]);
  assert.equal(f.events.filter((row) => row.type === "recipe-begin").length, 0);
});

test("an unconfirmed failed subject cannot advance to another recipe or recording", async () => {
  const f = fixture({ uploadFailure: true });
  const result = await replayLocalAggregate(f.options);
  assert.equal(result.status, "LOCAL_NEEDS_RECOVERY");
  assert.deepEqual(result.counter.completedRecipes, [0, 0]);
  assert.equal(f.factories(), 1);
  assert.equal(f.closes(), 1);
  assert.equal(f.requests.length, 5);
  assert.equal(f.events.filter((row) => row.type === "started").length, 1);
  assert.equal(f.events.filter((row) => row.type === "recipe-begin").length, 1);
  assert.equal(f.events.filter((row) => row.type === "recipe-finish").length, 0);
  assert.equal(result.unresolved.length, 1);
  assert.ok(!f.requests.some((row) => row.method === "DELETE"));
});

test("actual wire halt prevents every subsequent transport and retains responsibility", async () => {
  const f = fixture({ haltAtUpload: true });
  const result = await replayLocalAggregate(f.options);
  assert.equal(result.status, "LOCAL_NEEDS_RECOVERY");
  assert.equal(f.requests.length, 5);
  assert.equal(result.wire.halted, true);
  assert.equal(result.wire.closed, true);
  assert.equal(result.unresolved.length, 1);
  assert.deepEqual(result.counter.completedRecipes, [0, 0]);
});

test("wire halt after an owned readback prevents even invoking exception cleanup transport", async () => {
  const f = fixture({ haltAfterMediaRead: true });
  const result = await replayLocalAggregate(f.options);
  assert.equal(result.status, "LOCAL_NEEDS_RECOVERY");
  assert.equal(result.wire.halted, true);
  assert.equal(f.requests.length, 7);
  assert.equal(f.providerCalls(), 7);
  assert.deepEqual(result.counter.completedRecipes, [0, 0]);
  assert.equal(f.events.filter((row) => row.type === "recipe-begin").length, 1);
  assert.equal(result.unresolved.length, 1);
  assert.ok(!f.requests.some((row) => row.method === "DELETE"));
});

test("a failed durable recipe completion stops despite successful cleanup", async () => {
  const f = fixture({ finishFailure: true });
  const result = await replayLocalAggregate(f.options);
  assert.equal(result.status, "LOCAL_BLOCKED");
  assert.deepEqual(result.unresolved, []);
  assert.equal(f.objects.size, 0);
  assert.deepEqual(result.counter.completedRecipes, [0, 0]);
  assert.equal(f.events.filter((row) => row.type === "recipe-begin").length, 1);
  assert.equal(f.events.filter((row) => row.type === "recipe-finish").length, 0);
  assert.equal(f.closes(), 1);
  assert.equal(f.requests.length, 13);
});

test("completion waits for the actual replay result to be durably recorded", async () => {
  const f = fixture({ finishFailure: true });
  const entered = Promise.withResolvers(),
    durable = Promise.withResolvers(),
    writer = f.options.onJournal;
  f.options.onJournal = async (row) => {
    if (row.type === "aggregate-recipe-result") {
      entered.resolve();
      await durable.promise;
    }
    await writer(row);
  };
  const run = replayLocalAggregate(f.options);
  try {
    await entered.promise;
    assert.equal(f.requests.length, 13);
    assert.equal(f.events.filter((row) => row.type === "recipe-begin").length, 1);
    assert.equal(f.events.filter((row) => row.type === "recipe-finish").length, 0);
    assert.equal(f.closes(), 0);
  } finally {
    durable.resolve();
  }
  const result = await run;
  assert.equal(result.status, "LOCAL_BLOCKED");
  assert.deepEqual(result.counter.completedRecipes, [0, 0]);
  assert.equal(f.closes(), 1);
});

test("a failed started writer issues no request and closes the unused wire", async () => {
  const f = fixture({ startFailure: true });
  const result = await replayLocalAggregate(f.options);
  assert.equal(result.status, "LOCAL_BLOCKED");
  assert.equal(f.requests.length, 0);
  assert.equal(result.counter.total, 0);
  assert.equal(f.factories(), 1);
  assert.equal(f.closes(), 1);
});
