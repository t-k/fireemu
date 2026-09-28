import assert from "node:assert/strict";
import test from "node:test";
import * as plans from "./storage-object/stage3-plan.mjs";
import { createStage3RequestCounter } from "./storage-object/request-counter.mjs";

const input = {
  projectId: "example-project",
  bucket: "example.appspot.com",
  runIds: ["recordone", "recordtwo"],
};
function plan() {
  assert.equal(
    typeof plans.buildProductionStage3DraftPlan,
    "function",
    "production draft builder is missing",
  );
  return plans.buildProductionStage3DraftPlan(input);
}

test("the production draft reserves 6000 requests with separate recovery and two fresh recording admissions", () => {
  const value = plan();
  assert.equal(value.status, "PRODUCTION_DRAFT_NO_SEND");
  assert.equal(value.maxRequests, 6000);
  assert.equal(value.recoveryReserveRequests, 0);
  assert.equal(value.recoveryPolicy, "SEPARATE_REVIEWED_PACKET");
  assert.equal(value.recordingAdmission, "FRESH_PER_RECORDING_30_MINUTES");
  assert.equal(value.sendAuthorized, false);
  assert.equal(value.budgetStatus, "PROPOSED_NOT_APPROVED");
  assert.deepEqual(value.recordings, plans.buildStage3DraftPlan(input).recordings);
});

test("each production recording requires its own durable start and cannot borrow phase or recovery capacity", async () => {
  const starts = [],
    reservations = [];
  const counter = createStage3RequestCounter(plan(), {
    onStart: async (row) => starts.push(row),
    onReserve: async (row) => reservations.push(row),
  });
  let attempts = 0;
  const send = () => counter.send("bounded-fixture-attempt", async () => attempts++);
  await assert.rejects(counter.startNextProductionRecording(), /second recording/);
  await counter.start();
  await assert.rejects(counter.startNextProductionRecording(), /second recording/);
  for (let index = 0; index < 2000; index++) await send();
  await assert.rejects(send(), /subject cap/);
  counter.beginCleanup();
  for (let index = 0; index < 1000; index++) await send();
  await assert.rejects(send(), /cleanup cap/);
  assert.throws(() => counter.nextRecording(), /fresh production recording/);
  assert.throws(() => counter.close(), /both production recordings/);
  assert.throws(() => counter.enterRecovery(), /separate reviewed packet/);
  await counter.startNextProductionRecording();
  for (let index = 0; index < 2000; index++) await send();
  await assert.rejects(send(), /subject cap/);
  counter.beginCleanup();
  for (let index = 0; index < 1000; index++) await send();
  await assert.rejects(send(), /cleanup cap|total cap/);
  assert.throws(() => counter.enterRecovery(), /separate reviewed packet/);
  await assert.rejects(counter.startNextProductionRecording(), /second recording/);
  counter.close();
  assert.equal(attempts, 6000);
  assert.equal(reservations.length, attempts);
  assert.deepEqual(counter.snapshot().recordings, [
    { subject: 2000, cleanup: 1000 },
    { subject: 2000, cleanup: 1000 },
  ]);
  assert.equal(counter.snapshot().recovery, 0);
  assert.equal(counter.snapshot().mode, "closed");
  assert.equal(starts.length, 2);
  for (const [index, row] of starts.entries()) {
    assert.equal(row.recording, index + 1);
    assert.equal(row.runId, input.runIds[index]);
    assert.equal(row.prefix, `storage-object/${row.runId}/`);
    assert.equal(row.recordings, 1);
    assert.equal(row.maxRequests, 3000);
    assert.equal(row.taskMaxRequests, 6000);
    assert.equal(row.subjectCapRequests, 2000);
    assert.equal(row.cleanupReserveRequests, 1000);
  }
});

test("a pending or failed second admission cannot dispatch or switch recording state", async () => {
  let starts = 0,
    reserves = 0,
    rejectStart;
  const counter = createStage3RequestCounter(plan(), {
    onStart: async () => {
      if (++starts === 2)
        await new Promise((resolve, reject) => {
          rejectStart = reject;
        });
    },
    onReserve: async () => reserves++,
  });
  await counter.start();
  counter.beginCleanup();
  const pending = counter.startNextProductionRecording();
  const rejected = assert.rejects(pending, /fixture admission failed/);
  await assert.rejects(
    counter.send("forbidden-during-start", async () => assert.fail("must not dispatch")),
    /concurrent/,
  );
  assert.equal(reserves, 0);
  rejectStart(new Error("fixture admission failed"));
  await rejected;
  await assert.rejects(
    counter.send("forbidden-after-failed-start", async () => assert.fail("must not dispatch")),
    /admission failed/,
  );
  assert.equal(counter.snapshot().total, 0);
  assert.equal(reserves, 0);
  assert.deepEqual(counter.snapshot().recordings, [
    { subject: 0, cleanup: 0 },
    { subject: 0, cleanup: 0 },
  ]);
  assert.equal(counter.snapshot().mode, "cleanup");
  await assert.rejects(counter.startNextProductionRecording(), /second recording/);
  assert.equal(starts, 2);
});

test("altered production envelopes reject before either start callback or HTTP attempt", async () => {
  for (const change of [
    { maxRequests: 6600, recoveryReserveRequests: 600 },
    { sendAuthorized: true },
    { recordingAdmission: "ONE_SHARED_START" },
    { maxRequestBytes: 64 * 1024 * 1024 },
  ]) {
    let starts = 0;
    const counter = createStage3RequestCounter(
      { ...plan(), ...change },
      {
        onStart: async () => starts++,
        onReserve: async () => {},
      },
    );
    await assert.rejects(counter.start(), /production plan|two-recording|total cap/);
    assert.equal(starts, 0);
    assert.equal(counter.snapshot().total, 0);
  }
});

test("an uncertain first durable start cannot be attempted twice", async () => {
  let starts = 0,
    reserves = 0;
  const counter = createStage3RequestCounter(plan(), {
    onStart: async () => {
      starts++;
      throw new Error("fixture start persistence failed");
    },
    onReserve: async () => reserves++,
  });
  await assert.rejects(counter.start(), /fixture start persistence failed/);
  await assert.rejects(counter.start(), /already attempted/);
  await assert.rejects(
    counter.send("forbidden-after-start", async () => assert.fail("must not dispatch")),
    /started/,
  );
  assert.equal(starts, 1);
  assert.equal(reserves, 0);
  assert.equal(counter.snapshot().mode, "not-started");
});
