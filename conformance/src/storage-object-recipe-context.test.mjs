import assert from "node:assert/strict";
import test from "node:test";
import {
  createStage3RequestCounter,
  claimStage3RecipeContext,
} from "./storage-object/request-counter.mjs";
import { createLocalStorageSender, verifyLocalRecipeTerminal } from "./storage-object/sender.mjs";
import { buildStage3DraftPlan } from "./storage-object/stage3-plan.mjs";
import { buildAuthCorpus } from "./storage-object/auth-corpus.mjs";

function fixture(recipeId = "storage-object/firebase/simple-upload") {
  const recipeIds = Array.isArray(recipeId) ? recipeId : [recipeId];
  const plan = buildStage3DraftPlan({
    projectId: "example-project",
    bucket: "example.appspot.com",
    runIds: ["recordone", "recordtwo"],
  });
  for (const row of plan.recordings) row.declaredRecipeCount = recipeIds.length;
  const events = [],
    wire = [],
    senders = new Map();
  let failTerminal = false;
  const counter = createStage3RequestCounter(plan, {
    onStart: async (row) => events.push({ type: "started", ...row }),
    onReserve: async (row) => events.push({ type: "reserved", ...row }),
    recipeLifecycle: {
      recipeIds,
      onBegin: async (row) => events.push({ type: "recipe-begin", ...row }),
      onFinish: async (row) => events.push({ type: "recipe-finish", ...row }),
      verifyTerminal: (proof) => verifyLocalRecipeTerminal(senders.get(proof.recipeToken), proof),
    },
  });
  const makeSender = (recipeToken, options = {}) => {
    const sender = createLocalStorageSender({
      plan,
      recipeToken,
      origin: "http://127.0.0.1:9199",
      credentials: { admin: "Bearer owner" },
      fetchImpl: async (href, init) => {
        wire.push({ href, operationId: init.operationId, phase: init.accountingPhase });
        if (new URL(href).pathname.endsWith("/accounts:lookup"))
          return Response.json({ kind: "identitytoolkit#GetAccountInfoResponse", users: [] });
        if (init.method === "POST")
          return Response.json({
            bucket: plan.bucket,
            name: new URL(href).searchParams.get("name"),
            generation: "1",
            size: "1",
          });
        return Response.json({ kind: "storage#objects", items: [] });
      },
      onJournal: async (row) => {
        if (failTerminal && row.type === "recipe-terminal")
          throw new Error("terminal fsync failed");
        events.push({ type: "journal", ...row });
      },
      ...options,
    });
    senders.set(recipeToken, sender);
    return sender;
  };
  return {
    plan,
    counter,
    events,
    wire,
    makeSender,
    failTerminal: () => {
      failTerminal = true;
    },
  };
}

async function finishEmpty(f, token, options) {
  const sender = f.makeSender(token, options);
  await sender.start();
  await sender.admitNamespace();
  sender.beginCleanup();
  await sender.verifyRunEmpty();
  sender.close();
  await f.counter.finishRecipe(token);
  return sender;
}

test("scoped senders share one started row, sequence and phase budget across two prefixes", async () => {
  const f = fixture();
  await f.counter.start();
  const firstToken = await f.counter.beginRecipe("storage-object/firebase/simple-upload");
  const first = await finishEmpty(f, firstToken);
  assert.equal(first.snapshot().mode, "closed");
  assert.equal(f.counter.snapshot().mode, "cleanup");
  f.counter.nextRecording();
  const secondToken = await f.counter.beginRecipe("storage-object/firebase/simple-upload");
  const second = await finishEmpty(f, secondToken);
  f.counter.close();
  assert.equal(second.snapshot().total, 4);
  assert.deepEqual(f.counter.snapshot().recordings, [
    { subject: 1, cleanup: 1 },
    { subject: 1, cleanup: 1 },
  ]);
  assert.equal(f.events.filter((row) => row.type === "started").length, 1);
  assert.deepEqual(
    f.events.filter((row) => row.type === "reserved").map((row) => row.sequence),
    [1, 2, 3, 4],
  );
  assert.equal(new Set(f.wire.map((row) => row.operationId)).size, 4);
  assert.deepEqual(
    f.wire.map((row) => new URL(row.href).searchParams.get("prefix")),
    [
      "storage-object/recordone/",
      "storage-object/recordone/",
      "storage-object/recordtwo/",
      "storage-object/recordtwo/",
    ],
  );
  assert.deepEqual(
    f.wire.map((row) => row.operationId),
    f.events.filter((row) => row.type === "reserved").map((row) => row.operationId),
  );
  assert.deepEqual(
    f.events.filter((row) => row.type === "reserved").map((row) => row.semanticOperationId),
    ["initial-prefix-list", "final-prefix-list", "initial-prefix-list", "final-prefix-list"],
  );
  assert.ok(
    f.events.findIndex((row) => row.type === "recipe-terminal") <
      f.events.findIndex((row) => row.type === "recipe-finish"),
  );
});

test("two recipes per recording retain shared counts and distinct operation namespaces", async () => {
  const ids = ["storage-object/firebase/simple-upload", "storage-object/errors/missing"];
  const f = fixture(ids);
  await f.counter.start();
  for (let recording = 0; recording < 2; recording++) {
    for (const id of ids) await finishEmpty(f, await f.counter.beginRecipe(id));
    if (recording === 0) f.counter.nextRecording();
  }
  f.counter.close();
  assert.equal(f.events.filter((row) => row.type === "started").length, 1);
  assert.equal(f.events.filter((row) => row.type === "recipe-finish").length, 4);
  assert.equal(f.counter.snapshot().total, 8);
  assert.deepEqual(f.counter.snapshot().recordings, [
    { subject: 2, cleanup: 2 },
    { subject: 2, cleanup: 2 },
  ]);
  assert.deepEqual(f.counter.snapshot().completedRecipes, [2, 2]);
  assert.equal(new Set(f.wire.map((row) => row.operationId)).size, 8);
  assert.match(f.wire[2].operationId, /^r1\/p2\//);
  assert.match(f.wire[6].operationId, /^r2\/p2\//);
});

test("opaque contexts reject forged tokens, a changed plan, duplicate claims and expired capabilities", async () => {
  const f = fixture();
  await f.counter.start();
  assert.throws(() => claimStage3RecipeContext(Object.freeze({}), f.plan), /recipe capability/);
  const token = await f.counter.beginRecipe("storage-object/firebase/simple-upload");
  const changed = structuredClone(f.plan);
  changed.bucket = "other.appspot.com";
  assert.throws(() => claimStage3RecipeContext(token, changed), /plan/);
  const context = claimStage3RecipeContext(token, f.plan);
  assert.equal(context.prefix, "storage-object/recordone/");
  assert.throws(() => claimStage3RecipeContext(token, f.plan), /claimed/);
  await context.counter.start();
  context.counter.beginCleanup();
  context.counter.close();
  await assert.rejects(
    context.counter.send("late", async () => assert.fail("wire")),
    /closed/,
  );
  assert.equal(f.wire.length, 0);
  await assert.rejects(f.counter.finishRecipe(token), /terminal proof/);
});

test("a scoped sender cannot close or finish without fresh, durable final absence", async () => {
  const f = fixture();
  await f.counter.start();
  const token = await f.counter.beginRecipe("storage-object/firebase/simple-upload");
  const sender = f.makeSender(token);
  await sender.start();
  await sender.admitNamespace();
  sender.beginCleanup();
  assert.throws(() => sender.close(), /terminal proof/);
  await assert.rejects(f.counter.finishRecipe(token), /terminal proof/);
  await sender.verifyRunEmpty();
  await f.counter.send("later-controller-read", async () => {}, token);
  assert.throws(() => sender.close(), /terminal proof/);
  await assert.rejects(f.counter.finishRecipe(token), /terminal proof/);
  assert.deepEqual(f.counter.snapshot().completedRecipes, [0, 0]);
});

test("a failed terminal journal retains the active recipe and does not admit the next subject", async () => {
  const f = fixture();
  await f.counter.start();
  const token = await f.counter.beginRecipe("storage-object/firebase/simple-upload");
  const sender = f.makeSender(token);
  await sender.start();
  await sender.admitNamespace();
  sender.beginCleanup();
  f.failTerminal();
  await assert.rejects(sender.verifyRunEmpty(), /terminal fsync failed/);
  assert.throws(() => sender.close(), /terminal proof/);
  await assert.rejects(f.counter.finishRecipe(token), /terminal proof/);
  assert.throws(() => f.counter.nextRecording(), /incomplete/);
});

test("a pending mutation prevents final absence and keeps ownership responsibility", async () => {
  const f = fixture();
  await f.counter.start();
  const token = await f.counter.beginRecipe("storage-object/firebase/simple-upload");
  const sender = f.makeSender(token);
  await sender.start();
  await sender.admitNamespace();
  const name = "storage-object/recordone/simple/object.bin";
  sender.admitObject(name);
  await sender.sendStep({
    id: "upload",
    dialect: "gcs",
    method: "POST",
    objectName: name,
    path: `/upload/storage/v1/b/${f.plan.bucket}/o`,
    query: { name, uploadType: "media" },
    credential: "admin",
    body: { base64: "YQ==" },
  });
  sender.beginCleanup();
  const requests = f.wire.length;
  await assert.rejects(sender.verifyRunEmpty(), /unresolved/);
  assert.equal(f.wire.length, requests);
  assert.deepEqual(sender.unresolved(), [name]);
  assert.throws(() => sender.close(), /terminal proof/);
  await assert.rejects(f.counter.finishRecipe(token), /terminal proof/);
});

test("scoped senders cannot advance recordings, enter recovery or borrow another sender's proof", async () => {
  const f = fixture();
  await f.counter.start();
  const token = await f.counter.beginRecipe("storage-object/firebase/simple-upload");
  const sender = f.makeSender(token);
  await sender.start();
  assert.throws(() => sender.nextRecording(), /controller/);
  assert.throws(() => sender.enterRecovery(), /controller/);
  assert.equal(verifyLocalRecipeTerminal({ ...sender }, { recipeToken: token }), false);
  assert.ok(Object.isFrozen(sender));
  assert.throws(() => {
    sender.verifyRunEmpty = async () => true;
  }, TypeError);
});

test("recording two local Auth uses its own canonical run and account identities", async () => {
  const id = "storage-object/auth/firebase-id-token";
  const f = fixture(id);
  await f.counter.start();
  await finishEmpty(f, await f.counter.beginRecipe(id));
  f.counter.nextRecording();
  const token = await f.counter.beginRecipe(id);
  const sender = f.makeSender(token, {
    authOrigin: "http://127.0.0.1:9099",
    localAuth: { apiKey: "storage-object-local-key", password: "local-only-password-for-test" },
  });
  await sender.start();
  await sender.admitNamespace();
  const firstRecipe = buildAuthCorpus({
    projectId: f.plan.projectId,
    bucket: f.plan.bucket,
    runId: "recordone",
  }).recipes[1];
  const secondRecipe = buildAuthCorpus({
    projectId: f.plan.projectId,
    bucket: f.plan.bucket,
    runId: "recordtwo",
  }).recipes[1];
  const before = f.wire.length;
  await assert.rejects(
    sender.sendAuthStep({ recipe: firstRecipe, stepIndex: 0 }),
    /declaration differs/,
  );
  assert.equal(f.wire.length, before);
  await sender.sendAuthStep({ recipe: secondRecipe, stepIndex: 0 });
  assert.equal(f.wire.at(-1).phase, "subject");
  assert.match(f.wire.at(-1).operationId, /^r2\/p1\//);
});

test("terminal evidence is immutable before the durable writer receives it", async () => {
  const f = fixture();
  await f.counter.start();
  const token = await f.counter.beginRecipe("storage-object/firebase/simple-upload");
  let attempts = 0;
  const sender = f.makeSender(token, {
    onJournal: async (row) => {
      if (row.type === "recipe-terminal") {
        attempts++;
        row.prefix = "storage-object/foreignrun/";
      }
    },
  });
  await sender.start();
  await sender.admitNamespace();
  sender.beginCleanup();
  await assert.rejects(sender.verifyRunEmpty(), TypeError);
  assert.equal(attempts, 1);
  assert.throws(() => sender.close(), /terminal proof/);
  await assert.rejects(f.counter.finishRecipe(token), /terminal proof/);
});
