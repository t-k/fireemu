import assert from "node:assert/strict";
import test from "node:test";
import { buildProductionStage3DraftPlan } from "./storage-object/stage3-plan.mjs";
import { createStage3RequestCounter } from "./storage-object/request-counter.mjs";
const module = await import("./storage-object/production-controls.mjs").catch((error) => {
  if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
  return {};
});
const plan = buildProductionStage3DraftPlan({
  projectId: "example-project",
  bucket: "example.appspot.com",
  runIds: ["recordone", "recordtwo"],
});
function inventory() {
  assert.equal(
    typeof module.buildProductionControlInventory,
    "function",
    "production control inventory is missing",
  );
  return module.buildProductionControlInventory(plan);
}

test("all 171 control slots declare recording, phase and placement with exact 47/31/46 caps", () => {
  const rows = inventory();
  assert.equal(rows.length, 171);
  assert.equal(new Set(rows.map((row) => row.id)).size, 171);
  for (const recording of [1, 2]) {
    assert.equal(
      rows.filter((row) => row.recording === recording && row.phase === "subject").length,
      47,
    );
    assert.equal(
      rows.filter((row) => row.recording === recording && row.phase === "cleanup").length,
      recording === 1 ? 31 : 46,
    );
  }
  for (const row of rows) {
    assert.equal(Object.isFrozen(row), true);
    assert.ok(row.recipeId === null || row.recipeId.startsWith("storage-object/"));
    assert.ok(["recording-initial", "recipe", "recording-final"].includes(row.placement));
    if (row.id.includes("rules-before-")) {
      assert.equal(row.phase, "subject");
      assert.equal(row.placement, "recipe");
      assert.ok(row.recipeId);
    }
    if (row.id.includes("rules-delete-")) {
      assert.equal(row.recording, 2);
      assert.equal(row.phase, "cleanup");
      assert.equal(row.recipeId, null);
    }
  }
  assert.equal(rows.filter((row) => row.kind === "bucket-config").length, 4);
  assert.equal(rows.filter((row) => row.kind === "auth-refresh").length, 8);
  assert.equal(
    rows.some((row) => row.kind === "auth-signin"),
    false,
  );
  assert.equal(rows.filter((row) => row.id.includes("rules-delete-")).length, 15);
});

function setup(recipeLifecycle) {
  const rows = inventory(),
    starts = [],
    reserves = [],
    calls = [],
    proofs = [];
  const counter = createStage3RequestCounter(plan, {
    onStart: async (row) => starts.push(row),
    onReserve: async (row) => reserves.push(row),
    recipeLifecycle,
  });
  const dispatcher = module.createProductionControlDispatcher({
    plan,
    counter,
    wire: Object.freeze({
      fetchControl: async (...args) => {
        calls.push(args);
        return { status: 200, arrayBuffer: async () => Buffer.from("{}") };
      },
    }),
    onProof: async (row) => proofs.push(row),
  });
  return { rows, starts, reserves, calls, proofs, counter, dispatcher };
}

test("phase and recording mismatches cannot consume a slot or reserve or dispatch", async () => {
  const f = setup();
  await f.counter.start();
  const cleanup = f.rows.find((row) => row.recording === 1 && row.phase === "cleanup");
  const second = f.rows.find(
    (row) => row.recording === 2 && row.recipeId === null && row.phase === "subject",
  );
  for (const row of [cleanup, second])
    await assert.rejects(f.dispatcher.send(row.id), /control context/);
  assert.equal(f.reserves.length, 0);
  assert.equal(f.calls.length, 0);
  assert.equal(f.dispatcher.snapshot().attempted, 0);
  const first = f.rows.find(
    (row) => row.recording === 1 && row.recipeId === null && row.phase === "subject",
  );
  await f.dispatcher.send(first.id, { body: "grant_type=refresh_token" });
  await assert.rejects(f.dispatcher.send(first.id), /already attempted/);
  assert.equal(f.calls.length, 1);
  assert.equal(f.reserves.length, 1);
  assert.equal(f.proofs.length, 1);
  assert.equal(f.counter.snapshot().total, 1);
});

test("recipe control slots require the matching active capability and placement", async () => {
  const recipeId = "storage-object/errors/authorization";
  const ids = Array.from({ length: 26 }, (_, i) =>
    i === 0 ? recipeId : `storage-object/fixture-${i}`,
  );
  const f = setup({
    recipeIds: ids,
    onBegin: async () => {},
    onFinish: async () => {},
    verifyTerminal: async () => true,
  });
  await f.counter.start();
  const slot = f.rows.find(
    (row) => row.recording === 1 && row.recipeId === recipeId && row.id.includes("rules-before-"),
  );
  await assert.rejects(f.dispatcher.send(slot.id), /control context/);
  const token = await f.counter.beginRecipe(recipeId);
  await assert.rejects(f.dispatcher.send(slot.id), /recipe capability/);
  assert.equal(f.calls.length, 0);
  assert.equal(f.reserves.length, 0);
  assert.equal(f.dispatcher.snapshot().attempted, 0);
  await f.dispatcher.send(slot.id, { recipeToken: token });
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0][0], 1);
  assert.equal(f.calls[0][3].accountingPhase, "subject");
  f.counter.beginCleanup(token);
  const before = f.rows.find(
    (row) =>
      row.recording === 1 &&
      row.recipeId === recipeId &&
      row.id.includes("rules-before-") &&
      row.id !== slot.id,
  );
  await assert.rejects(f.dispatcher.send(before.id, { recipeToken: token }), /control context/);
  assert.equal(f.calls.length, 1);
});

test("a valid capability for another recipe cannot authorize a control slot", async () => {
  const ids = Array.from({ length: 26 }, (_, index) =>
    index === 0 ? "storage-object/auth/firebase-id-token" : `storage-object/fixture-${index}`,
  );
  const f = setup({
    recipeIds: ids,
    onBegin: async () => {},
    onFinish: async () => {},
    verifyTerminal: async () => true,
  });
  await f.counter.start();
  const token = await f.counter.beginRecipe(ids[0]);
  const row = f.rows.find(
    (item) =>
      item.recording === 1 &&
      item.recipeId === "storage-object/errors/authorization" &&
      item.phase === "subject",
  );
  await assert.rejects(f.dispatcher.send(row.id, { recipeToken: token }), /control context/);
  assert.equal(f.reserves.length, 0);
  assert.equal(f.calls.length, 0);
});

test("recording-final controls require all 26 recipe completions", async () => {
  const ids = Array.from({ length: 26 }, (_, index) => `storage-object/fixture-${index}`);
  const f = setup({
    recipeIds: ids,
    onBegin: async () => {},
    onFinish: async () => {},
    verifyTerminal: async () => true,
  });
  await f.counter.start();
  f.counter.beginCleanup();
  const row = f.rows.find((item) => item.recording === 1 && item.placement === "recording-final");
  await assert.rejects(f.dispatcher.send(row.id), /control context/);
  assert.equal(f.calls.length, 0);
  for (const id of ids) {
    const token = await f.counter.beginRecipe(id);
    f.counter.beginCleanup(token);
    await f.counter.finishRecipe(token);
  }
  await f.dispatcher.send(row.id);
  assert.equal(f.reserves.length, 1);
  assert.equal(f.calls.length, 1);
});

test("a later counter request cannot change the control proof reservation sequence", async () => {
  inventory();
  const reserves = [],
    proofs = [];
  let releaseBody, bodyStarted;
  const waiting = new Promise((resolve) => {
    bodyStarted = resolve;
  });
  const body = new Promise((resolve) => {
    releaseBody = resolve;
  });
  const counter = createStage3RequestCounter(plan, {
    onStart: async () => {},
    onReserve: async (row) => reserves.push(row),
  });
  const dispatcher = module.createProductionControlDispatcher({
    plan,
    counter,
    wire: Object.freeze({
      fetchControl: async () => ({
        status: 200,
        arrayBuffer: async () => {
          bodyStarted();
          return await body;
        },
      }),
    }),
    onProof: async (row) => proofs.push(row),
  });
  await counter.start();
  const id = inventory().find(
    (row) => row.recording === 1 && row.recipeId === null && row.phase === "subject",
  ).id;
  const pending = dispatcher.send(id);
  await waiting;
  await counter.send("another-counter-operation", async () => {});
  releaseBody(Buffer.from("{}"));
  await pending;
  assert.equal(reserves[0].sequence, 1);
  assert.equal(reserves[1].sequence, 2);
  assert.equal(proofs[0].sequence, 1);
  assert.equal(proofs[0].operationId, reserves[0].operationId);
  assert.equal(counter.snapshot().total, 2);
});

test("failed reservation or durable proof is not retried and no raw body reaches proof writer", async () => {
  for (const fail of ["reserve", "proof"]) {
    let calls = 0;
    const proofs = [];
    inventory();
    const counter = createStage3RequestCounter(plan, {
      onStart: async () => {},
      onReserve: async () => {
        if (fail === "reserve") throw new Error("SYNTHETIC_RESERVATION_SECRET");
      },
    });
    const dispatcher = module.createProductionControlDispatcher({
      plan,
      counter,
      wire: Object.freeze({
        fetchControl: async () => {
          calls++;
          return {
            status: 200,
            arrayBuffer: async () => Buffer.from('{"token":"SYNTHETIC_RESPONSE_SECRET"}'),
          };
        },
      }),
      onProof: async (row) => {
        proofs.push(row);
        if (fail === "proof") throw new Error("SYNTHETIC_PROOF_SECRET");
      },
    });
    await counter.start();
    const id = inventory().find(
      (row) => row.recording === 1 && row.phase === "subject" && row.recipeId === null,
    ).id;
    await assert.rejects(dispatcher.send(id), /^Error: production control failed$/);
    await assert.rejects(dispatcher.send(id), /halted/);
    const otherId = inventory().find(
      (row) =>
        row.recording === 1 && row.phase === "subject" && row.recipeId === null && row.id !== id,
    ).id;
    await assert.rejects(dispatcher.send(otherId), /halted/);
    assert.equal(calls, fail === "reserve" ? 0 : 1);
    assert.equal(JSON.stringify(proofs).includes("SYNTHETIC_RESPONSE_SECRET"), false);
    if (proofs.length) {
      assert.equal(proofs[0].bodyByteLength, 37);
      assert.match(proofs[0].bodySha256, /^[a-f0-9]{64}$/);
      assert.equal(Object.isFrozen(proofs[0]), true);
    }
  }
});
