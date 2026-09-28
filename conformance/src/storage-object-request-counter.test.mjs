import assert from "node:assert/strict";
import { test } from "node:test";
import { createStage3RequestCounter } from "./storage-object/request-counter.mjs";
import { buildStage3DraftPlan } from "./storage-object/stage3-plan.mjs";

const makePlan = () =>
  buildStage3DraftPlan({
    projectId: "example-project",
    bucket: "example.appspot.com",
    runIds: ["recordone", "recordtwo"],
  });

test("no remote dispatch occurs before a durable started row and each attempt is reserved first", async () => {
  const events = [];
  const counter = createStage3RequestCounter(makePlan(), {
    onStart: async () => events.push("started"),
    onReserve: async (entry) => events.push(`reserved:${entry.sequence}:${entry.operationId}`),
  });
  let calls = 0;
  await assert.rejects(
    counter.send("auth-signup", async () => {
      calls++;
    }),
    /started/i,
  );
  assert.equal(calls, 0);
  await counter.start();
  await assert.rejects(
    counter.send("auth-signup", async () => {
      events.push("wire");
      calls++;
      throw new Error("transport failed after dispatch");
    }),
    /transport failed/,
  );
  assert.deepEqual(events, ["started", "reserved:1:auth-signup", "wire"]);
  assert.equal(calls, 1);
  assert.equal(counter.snapshot().total, 1);
});

test("an envelope that cannot carry both recordings is rejected before started or wire", async () => {
  const plan = makePlan();
  plan.maxRequests = 4999;
  let started = 0;
  const counter = createStage3RequestCounter(plan, {
    onStart: async () => started++,
    onReserve: async () => {},
  });
  await assert.rejects(counter.start(), /two recordings|total cap/i);
  assert.equal(started, 0);
  assert.equal(counter.snapshot().total, 0);
});

test("subject cannot consume cleanup or recovery reserves, and the total cap holds", async () => {
  const counter = createStage3RequestCounter(makePlan(), {
    onStart: async () => {},
    onReserve: async () => {},
  });
  let calls = 0;
  const send = () => counter.send("bounded-request", async () => calls++);
  await counter.start();
  for (let index = 0; index < 2000; index++) await send();
  await assert.rejects(send(), /subject cap/i);
  assert.equal(calls, 2000);
  counter.beginCleanup();
  for (let index = 0; index < 1000; index++) await send();
  await assert.rejects(send(), /cleanup cap/i);
  counter.nextRecording();
  for (let index = 0; index < 2000; index++) await send();
  counter.beginCleanup();
  for (let index = 0; index < 1000; index++) await send();
  counter.enterRecovery();
  for (let index = 0; index < 600; index++) await send();
  await assert.rejects(send(), /recovery cap|total cap/i);
  assert.equal(calls, 6600);
  assert.deepEqual(counter.snapshot().recordings, [
    { subject: 2000, cleanup: 1000 },
    { subject: 2000, cleanup: 1000 },
  ]);
  assert.equal(counter.snapshot().recovery, 600);
  assert.equal(counter.snapshot().total, 6600);
});

test("journal failure prevents dispatch and concurrent requests cannot race the counter", async () => {
  const failed = createStage3RequestCounter(makePlan(), {
    onStart: async () => {},
    onReserve: async () => {
      throw new Error("journal unavailable");
    },
  });
  await failed.start();
  let calls = 0;
  await assert.rejects(
    failed.send("first", async () => calls++),
    /journal unavailable/,
  );
  assert.equal(calls, 0);
  assert.equal(failed.snapshot().total, 0);

  let release;
  const counter = createStage3RequestCounter(makePlan(), {
    onStart: async () => {},
    onReserve: async () =>
      new Promise((resolve) => {
        release = resolve;
      }),
  });
  await counter.start();
  const first = counter.send("first", async () => calls++);
  await assert.rejects(
    counter.send("second", async () => calls++),
    /concurrent/i,
  );
  release();
  await first;
  assert.equal(calls, 1);
  assert.equal(counter.snapshot().total, 1);
});

for (const [label, delta] of [
  ["reservation below the estimate", { maxUsdReservation: 0.299999 }],
  ["estimate below the full quote", { estimatedUsd: 0.287299 }],
  ["invalid reservation", { maxUsdReservation: NaN }],
  ["invalid estimate", { estimatedUsd: Infinity }],
  ["unbounded ingress", { maxResponseBytes: Number.MAX_SAFE_INTEGER }],
]) {
  test(`${label} cannot write started or reach transport`, async () => {
    let started = 0,
      wire = 0;
    const counter = createStage3RequestCounter(
      { ...makePlan(), ...delta },
      {
        onStart: async () => started++,
        onReserve: async () => {},
      },
    );
    await assert.rejects(counter.start(), /budget|reservation|estimate|bound/);
    await assert.rejects(
      counter.send("blocked", async () => wire++),
      /started/,
    );
    assert.equal(started, 0);
    assert.equal(wire, 0);
  });
}

test("an exact estimate-sized reservation admits, and caller changes cannot raise fixed limits", async () => {
  const plan = { ...makePlan(), maxUsdReservation: 0.3 };
  let started;
  const counter = createStage3RequestCounter(plan, {
    onStart: async (row) => {
      started = row;
    },
    onReserve: async () => {},
  });
  plan.maxUsdReservation = Infinity;
  plan.estimatedUsd = NaN;
  plan.recordings[0].subjectCapRequests = 9000;
  await counter.start();
  assert.equal(started.maxUsdReservation, 0.3);
  assert.equal(started.estimatedUsd, 0.3);
  for (let i = 0; i < 2000; i++) await counter.send("bounded", async () => {});
  await assert.rejects(
    counter.send("extra", async () => assert.fail("wire")),
    /subject cap/,
  );
});

function recipeCounter(overrides = {}) {
  const plan = makePlan();
  for (const recording of plan.recordings) recording.declaredRecipeCount = 2;
  const events = [];
  let terminal = true;
  const counter = createStage3RequestCounter(plan, {
    onStart: async () => events.push({ type: "started" }),
    onReserve: async (row) => events.push({ type: "reserved", ...row }),
    recipeLifecycle: {
      recipeIds: ["storage-object/first", "storage-object/second"],
      onBegin: async (row) => events.push({ type: "recipe-begin", ...row }),
      onFinish: async (row) => events.push({ type: "recipe-finish", ...row }),
      verifyTerminal: async () => terminal,
      ...overrides,
    },
  });
  return {
    counter,
    events,
    setTerminal: (value) => {
      terminal = value;
    },
  };
}

async function finishEmptyRecipe(counter, recipeId) {
  const token = await counter.beginRecipe(recipeId);
  await counter.send("subject", async () => {}, token);
  counter.beginCleanup(token);
  await counter.send("cleanup", async () => {}, token);
  await counter.finishRecipe(token);
  return token;
}

test("one counter keeps global sequence and recording phases through four recipe completions", async () => {
  const { counter, events } = recipeCounter();
  await counter.start();
  for (let recording = 0; recording < 2; recording++) {
    for (const id of ["storage-object/first", "storage-object/second"])
      await finishEmptyRecipe(counter, id);
    if (recording === 0) counter.nextRecording();
  }
  counter.close();
  assert.equal(events.filter((e) => e.type === "started").length, 1);
  assert.equal(events.filter((e) => e.type === "recipe-finish").length, 4);
  assert.deepEqual(
    events.filter((e) => e.type === "reserved").map((e) => e.sequence),
    [1, 2, 3, 4, 5, 6, 7, 8],
  );
  assert.deepEqual(counter.snapshot().recordings, [
    { subject: 2, cleanup: 2 },
    { subject: 2, cleanup: 2 },
  ]);
  assert.equal(counter.snapshot().total, 8);
  assert.equal(counter.snapshot().mode, "closed");
  assert.deepEqual(
    events.filter((e) => e.type === "recipe-begin").map((e) => e.prefix),
    [
      "storage-object/recordone/",
      "storage-object/recordone/",
      "storage-object/recordtwo/",
      "storage-object/recordtwo/",
    ],
  );
});

test("recipe order, unfinished cleanup and incomplete recording cannot admit new subjects", async () => {
  const { counter } = recipeCounter();
  await counter.start();
  await assert.rejects(counter.beginRecipe("storage-object/second"), /recipe order/);
  const token = await counter.beginRecipe("storage-object/first");
  await assert.rejects(counter.beginRecipe("storage-object/second"), /active recipe/);
  assert.throws(() => counter.nextRecording(), /incomplete recording/);
  await assert.rejects(counter.finishRecipe(token), /cleanup/);
  assert.throws(() => counter.close(), /incomplete recording|cannot close/);
});

test("a stale or foreign capability cannot dispatch, clean up or finish another recipe", async () => {
  const { counter } = recipeCounter();
  await counter.start();
  const stale = await finishEmptyRecipe(counter, "storage-object/first");
  const current = await counter.beginRecipe("storage-object/second");
  for (const token of [stale, {}, null]) {
    await assert.rejects(
      counter.send("extra", async () => assert.fail("wire"), token),
      /recipe capability/,
    );
    assert.throws(() => counter.beginCleanup(token), /recipe capability/);
    await assert.rejects(counter.finishRecipe(token), /recipe capability/);
  }
  await counter.send("valid", async () => {}, current);
  assert.equal(counter.snapshot().total, 3);
});

for (const [label, terminal] of [
  ["absent", false],
  ["untyped", { clean: true }],
]) {
  test(`a ${label} terminal proof keeps the recipe and cleanup responsibility active`, async () => {
    const { counter, setTerminal, events } = recipeCounter();
    await counter.start();
    const token = await counter.beginRecipe("storage-object/first");
    counter.beginCleanup(token);
    setTerminal(terminal);
    await assert.rejects(counter.finishRecipe(token), /terminal proof/);
    assert.equal(events.filter((e) => e.type === "recipe-finish").length, 0);
    await assert.rejects(counter.beginRecipe("storage-object/second"), /active recipe/);
    assert.equal(counter.snapshot().mode, "cleanup");
  });
}

test("a failed terminal writer cannot mark completion or resume subject", async () => {
  const { counter } = recipeCounter({
    onFinish: async () => {
      throw new Error("receipt failed");
    },
  });
  await counter.start();
  const token = await counter.beginRecipe("storage-object/first");
  counter.beginCleanup(token);
  await assert.rejects(counter.finishRecipe(token), /receipt failed/);
  await assert.rejects(counter.beginRecipe("storage-object/second"), /active recipe/);
  assert.equal(counter.snapshot().mode, "cleanup");
});

test("a failed recipe-begin writer cannot leave cleanup or create a new capability", async () => {
  let begins = 0;
  const { counter } = recipeCounter({
    onBegin: async () => {
      if (++begins > 1) throw new Error("begin failed");
    },
  });
  await counter.start();
  await finishEmptyRecipe(counter, "storage-object/first");
  await assert.rejects(counter.beginRecipe("storage-object/second"), /begin failed/);
  assert.equal(counter.snapshot().mode, "cleanup");
  assert.equal(counter.snapshot().total, 2);
});

test("proof verification is exclusive and cannot race a new request or phase", async () => {
  let release;
  const { counter } = recipeCounter({
    verifyTerminal: () =>
      new Promise((resolve) => {
        release = resolve;
      }),
  });
  await counter.start();
  const token = await counter.beginRecipe("storage-object/first");
  counter.beginCleanup(token);
  const finish = counter.finishRecipe(token);
  await assert.rejects(
    counter.send("race", async () => assert.fail("wire"), token),
    /concurrent/,
  );
  assert.throws(() => counter.nextRecording(), /incomplete recording|cannot start/);
  release(true);
  await finish;
  await assert.rejects(counter.finishRecipe(token), /recipe capability/);
});

test("subject and cleanup totals persist across recipes without borrowing protected capacity", async () => {
  const { counter } = recipeCounter();
  await counter.start();
  const first = await counter.beginRecipe("storage-object/first");
  for (let i = 0; i < 2000; i++) await counter.send("subject", async () => {}, first);
  await assert.rejects(
    counter.send("one-more", async () => assert.fail("wire"), first),
    /subject cap/,
  );
  counter.beginCleanup(first);
  for (let i = 0; i < 999; i++) await counter.send("cleanup", async () => {}, first);
  await counter.finishRecipe(first);
  const second = await counter.beginRecipe("storage-object/second");
  await assert.rejects(
    counter.send("borrow", async () => assert.fail("wire"), second),
    /subject cap/,
  );
  counter.beginCleanup(second);
  await counter.send("last-cleanup", async () => {}, second);
  await assert.rejects(
    counter.send("one-more", async () => assert.fail("wire"), second),
    /cleanup cap/,
  );
  assert.deepEqual(counter.snapshot().recordings[0], { subject: 2000, cleanup: 1000 });
});

test("auxiliary requests before and between recipes share the same recording capacity", async () => {
  const { counter } = recipeCounter();
  await counter.start();
  await counter.send("oauth-slot", async () => {});
  await finishEmptyRecipe(counter, "storage-object/first");
  await counter.send("rules-readback", async () => {});
  await finishEmptyRecipe(counter, "storage-object/second");
  assert.deepEqual(counter.snapshot().recordings[0], { subject: 3, cleanup: 3 });
  assert.equal(counter.snapshot().total, 6);
});

test("invalid or duplicate recipe registries reject before durable started", () => {
  for (const recipeIds of [
    [],
    ["storage-object/first", "storage-object/first"],
    ["bad id"],
    ["storage-object/first"],
  ])
    assert.throws(() => recipeCounter({ recipeIds }), /recipe lifecycle/);
});

test("completing every recipe cannot open an omitted or extra recipe in that recording", async () => {
  const { counter } = recipeCounter();
  await counter.start();
  await finishEmptyRecipe(counter, "storage-object/first");
  await finishEmptyRecipe(counter, "storage-object/second");
  await assert.rejects(counter.beginRecipe(), /recipe order/);
  await assert.rejects(counter.beginRecipe("storage-object/extra"), /recipe order/);
  assert.equal(counter.snapshot().mode, "cleanup");
  assert.equal(counter.snapshot().total, 4);
});

test("terminal verification receives immutable identity and cannot rewrite the durable receipt", async () => {
  let received;
  const { counter, events } = recipeCounter({
    verifyTerminal: async (proof) => {
      assert.throws(() => {
        proof.recipeId = "storage-object/extra";
      }, TypeError);
      assert.throws(() => {
        proof.sequence = 9000;
      }, TypeError);
      received = proof;
      return true;
    },
  });
  await counter.start();
  await finishEmptyRecipe(counter, "storage-object/first");
  assert.equal(received.recipeId, "storage-object/first");
  const receipt = events.find((e) => e.type === "recipe-finish");
  assert.equal(receipt.recipeId, "storage-object/first");
  assert.equal(receipt.lastSequence, 2);
});

test("a thrown terminal verifier cannot record completion or resume a new subject", async () => {
  const { counter, events } = recipeCounter({
    verifyTerminal: async () => {
      throw new Error("proof failed");
    },
  });
  await counter.start();
  const token = await counter.beginRecipe("storage-object/first");
  counter.beginCleanup(token);
  await assert.rejects(counter.finishRecipe(token), /proof failed/);
  await assert.rejects(counter.beginRecipe("storage-object/second"), /active recipe/);
  assert.equal(events.filter((e) => e.type === "recipe-finish").length, 0);
});

test("a clean first recipe alone cannot advance the recording or close the aggregate", async () => {
  const { counter, events } = recipeCounter();
  await counter.start();
  await finishEmptyRecipe(counter, "storage-object/first");
  assert.throws(() => counter.nextRecording(), /incomplete recording/);
  assert.throws(() => counter.close(), /incomplete recording/);
  await finishEmptyRecipe(counter, "storage-object/second");
  assert.deepEqual(
    events.filter((e) => e.type === "recipe-begin").map((e) => e.prefix),
    ["storage-object/recordone/", "storage-object/recordone/"],
  );
});

for (const withRecipe of [false, true]) {
  test(`recovery cannot close an incomplete aggregate: active recipe ${withRecipe}`, async () => {
    const { counter, setTerminal, events } = recipeCounter();
    setTerminal(false);
    await counter.start();
    if (withRecipe) await counter.beginRecipe("storage-object/first");
    counter.enterRecovery();
    assert.throws(() => counter.close(), /incomplete recording/);
    assert.equal(counter.snapshot().mode, "recovery");
    assert.deepEqual(counter.snapshot().completedRecipes, [0, 0]);
    assert.equal(events.filter((e) => e.type === "recipe-finish").length, 0);
    await assert.rejects(counter.beginRecipe("storage-object/first"), /cannot start/);
  });
}

test("legacy recovery closure remains available without a recipe lifecycle", async () => {
  const counter = createStage3RequestCounter(makePlan(), {
    onStart: async () => {},
    onReserve: async () => {},
  });
  await counter.start();
  counter.enterRecovery();
  counter.close();
  assert.equal(counter.snapshot().mode, "closed");
});
