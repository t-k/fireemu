import assert from "node:assert/strict";
import test from "node:test";
import { createStage3RequestCounter } from "./storage-rules/request-counter.mjs";

function counter(limits = { maxRequests: 4, recoveryReserve: 2 }) {
  const events = [];
  const value = createStage3RequestCounter({
    ...limits,
    onStarted: async (row) => events.push(["started", row]),
    onReserve: async (row) => events.push(["reserve", row]),
    onTerminal: async (row) => events.push(["terminal", row]),
  });
  return { value, events };
}

test("stage 3 counts preflight after the started row and writes a terminal on refusal", async () => {
  const { value, events } = counter();
  await assert.rejects(value.send("preflight/release", async () => 404), /started/);
  await value.start({ runId: "run-a" });
  const result = await value.send("preflight/release", async () => {
    assert.deepEqual(events.map(([type]) => type), ["started", "reserve"]);
    return 404;
  });
  assert.equal(result, 404);
  await value.finish("preflight-failed");
  assert.deepEqual(events.map(([type]) => type), ["started", "reserve", "terminal"]);
  assert.equal(events[1][1].attempt, 1);
  assert.equal(events[2][1].requests, 1);
  assert.equal(events[2][1].outcome, "preflight-failed");
  await assert.rejects(value.send("subject/after-close", async () => 200), /closed/);
});

test("normal requests cannot borrow the protected recovery reserve", async () => {
  const { value, events } = counter();
  await value.start({ runId: "run-a" });
  await value.send("preflight/a", async () => 200);
  await value.send("subject/a", async () => 200);
  await assert.rejects(value.send("subject/over-cap", async () => 200), /normal cap/);
  value.enterRecovery();
  await value.send("recovery/a", async () => 200);
  await value.send("recovery/b", async () => 200);
  await assert.rejects(value.send("recovery/over-cap", async () => 200), /recovery cap/);
  await value.finish("needs-recovery");
  assert.equal(events.at(-1)[1].requests, 4);
  assert.deepEqual(events.filter(([type]) => type === "reserve").map(([, row]) => row.phase), [
    "normal", "normal", "recovery", "recovery",
  ]);
});

test("an uncertain send enters recovery and cannot be repeated", async () => {
  const { value } = counter();
  await value.start({ runId: "run-a" });
  await assert.rejects(value.send("subject/uncertain", async () => {
    throw new Error("connection reset");
  }), /connection reset/);
  assert.equal(value.snapshot().mode, "recovery");
  await assert.rejects(value.send("subject/uncertain", async () => 200), /duplicate/);
  await value.send("recovery/readback", async () => 200);
  assert.equal(value.snapshot().requests, 2);
});

test("a failed durable reservation or concurrent dispatch blocks new traffic", async () => {
  const blocked = createStage3RequestCounter({
    maxRequests: 4,
    recoveryReserve: 2,
    onStarted: async () => {},
    onReserve: async () => { throw new Error("fsync failed"); },
    onTerminal: async () => {},
  });
  await blocked.start({ runId: "run-a" });
  let dispatched = false;
  await assert.rejects(blocked.send("preflight/a", async () => { dispatched = true; }), /fsync failed/);
  assert.equal(dispatched, false);
  assert.equal(blocked.snapshot().mode, "journal-uncertain");
  await assert.rejects(blocked.send("preflight/b", async () => 200), /journal/);

  const { value } = counter();
  await value.start({ runId: "run-b" });
  let release;
  const pending = value.send("subject/a", () => new Promise((resolve) => { release = resolve; }));
  await new Promise((resolve) => setImmediate(resolve));
  await assert.rejects(value.send("subject/b", async () => 200), /concurrent/);
  release(200);
  assert.equal(await pending, 200);
});

test("uncertain started or terminal writes fail closed and limits cannot grow", async () => {
  assert.throws(() => createStage3RequestCounter({
    maxRequests: 6806,
    recoveryReserve: 2000,
    onStarted: async () => {},
    onReserve: async () => {},
    onTerminal: async () => {},
  }), /envelope/);
  const badStart = createStage3RequestCounter({
    maxRequests: 4,
    recoveryReserve: 2,
    onStarted: async () => { throw new Error("started fsync failed"); },
    onReserve: async () => {},
    onTerminal: async () => {},
  });
  await assert.rejects(badStart.start({ runId: "run-a" }), /started fsync failed/);
  assert.equal(badStart.snapshot().mode, "journal-uncertain");
  await assert.rejects(badStart.send("preflight/a", async () => 200), /journal/);

  const badTerminal = createStage3RequestCounter({
    maxRequests: 4,
    recoveryReserve: 2,
    onStarted: async () => {},
    onReserve: async () => {},
    onTerminal: async () => { throw new Error("terminal fsync failed"); },
  });
  await badTerminal.start({ runId: "run-b" });
  await badTerminal.send("preflight/a", async () => 200);
  await assert.rejects(badTerminal.finish("preflight-failed"), /terminal fsync failed/);
  assert.equal(badTerminal.snapshot().mode, "journal-uncertain");
  await assert.rejects(badTerminal.send("preflight/b", async () => 200), /journal/);
});
