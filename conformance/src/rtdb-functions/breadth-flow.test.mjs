import test from "node:test";
import assert from "node:assert/strict";
import { runBreadth } from "./breadth-flow.mjs";
import { makeWorld } from "./breadth-flow.fake.mjs";

test("runs T1 writes and cleans owned resources in order", async () => {
  const world = makeWorld();
  const result = await runBreadth(world.deps);
  assert.equal(result.outcome, "stopped-needs-review");
  assert.ok(result.reasons.includes("no frames read"));
  assert.equal(world.events.filter((e) => e.startsWith("write ")).length, 12);
  assert.ok(world.events.indexOf("close sdk") < world.events.indexOf("cleanup user"));
  assert.deepEqual(
    world.events.filter((e) => e.startsWith("cleanup ")),
    [
      "cleanup g9WrittenV2Retry",
      "cleanup g9WrittenV1Retry",
      "cleanup g9WrittenV2",
      "cleanup user",
      "cleanup inventory",
      "cleanup rtdb",
    ],
  );
});

test("optional refusal continues but an unknown deploy stops", async () => {
  const optional = makeWorld({ failure: "g9WrittenV2", kind: "refused" });
  await runBreadth(optional.deps);
  assert.equal(optional.events.filter((e) => e.startsWith("write ")).length, 12);
  const unknown = makeWorld({ failure: "g9WrittenV2", kind: "unknown" });
  const result = await runBreadth(unknown.deps);
  assert.equal(unknown.events.filter((e) => e.startsWith("write ")).length, 0);
  assert.equal(result.residual, true);
});

test("preflight failure creates nothing", async () => {
  const world = makeWorld({ preflightFails: true });
  await runBreadth(world.deps);
  assert.deepEqual(world.events, ["preflight", "close sdk"]);
});

test("stops tail after all deployed handlers arrive and thirty seconds of quiet", async () => {
  const world = makeWorld({ allFrames: true });
  const result = await runBreadth(world.deps);
  assert.equal(result.logs.reads, 7);
  assert.equal(world.deps.clock.now(), 405000);
});

test("waits the full tail if retry success is missing", async () => {
  const world = makeWorld({ allFrames: true, missingRetrySuccess: true });
  const result = await runBreadth(world.deps);
  assert.equal(result.logs.reads, 14);
});

test("cleans resources when report evaluation fails", async () => {
  const world = makeWorld();
  Object.defineProperty(world.deps.auth, "uid", {
    get() {
      throw Error("report failure");
    },
  });
  const result = await runBreadth(world.deps);
  assert.ok(result.reasons.includes("report failure"));
  assert.ok(world.events.includes("cleanup rtdb"));
});

test("a refused required deployment stops observation", async () => {
  const world = makeWorld({ failure: "g9WrittenV2Retry", kind: "refused" });
  const result = await runBreadth(world.deps);
  assert.ok(result.reasons.includes("deploy failed"));
  assert.equal(world.events.filter((e) => e.startsWith("write ")).length, 0);
});

test("an incomplete log read remains incomplete after later successful reads", async () => {
  const world = makeWorld();
  let reads = 0;
  world.deps.logs.read = async () => ({
    frames: [],
    entries: 0,
    ignored: {},
    complete: ++reads > 1,
  });
  const result = await runBreadth(world.deps);
  assert.ok(reads > 1);
  assert.equal(result.logs.incomplete, true);
  assert.ok(result.reasons.includes("a Cloud Logging read was incomplete"));
});
