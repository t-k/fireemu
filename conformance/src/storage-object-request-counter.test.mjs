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
