import test from "node:test";
import assert from "node:assert/strict";
import { runBreadth } from "./breadth-flow.mjs";
import { makeWorld } from "./kinds-world.fake.mjs";
import { STEPS } from "./kinds-sequence.mjs";

const idOf = (f) => f.event.params?.id ?? f.event.context?.params?.id;
const writes = (world) => world.events.filter((e) => e.startsWith("write ")).map((e) => e.slice(6));

test("runs the 21 writes in order and cleans owned resources in order", async () => {
  const world = makeWorld();
  const result = await runBreadth(world.deps);
  assert.equal(result.outcome, "stopped-needs-review");
  assert.ok(result.reasons.includes("no frames read"));
  assert.deepEqual(
    writes(world),
    STEPS.map((s) => s.id),
  );
  assert.ok(world.events.indexOf("close sdk") < world.events.indexOf("cleanup user"));
  assert.deepEqual(
    world.events.filter((e) => e.startsWith("cleanup ")),
    [
      "cleanup k9CreatedV2",
      "cleanup k9UpdatedV2",
      "cleanup k9DeletedV2",
      "cleanup k9CreatedV1",
      "cleanup k9UpdatedV1",
      "cleanup k9DeletedV1",
      "cleanup k9AnyWrittenV2",
      "cleanup k9GroupWrittenV2",
      "cleanup user",
      "cleanup inventory",
      "cleanup rtdb",
    ],
  );
  assert.deepEqual(
    world.events.filter((e) => e.startsWith("deploy ")).map((e) => e.slice(7)),
    [
      "k9CreatedV2",
      "k9UpdatedV2",
      "k9DeletedV2",
      "k9CreatedV1",
      "k9UpdatedV1",
      "k9DeletedV1",
      "k9AnyWrittenV2",
      "k9GroupWrittenV2",
    ],
  );
});

test("every expected delivery arrives: recorded, and the tail ends after thirty quiet seconds", async () => {
  const world = makeWorld({ frames: "all" });
  const result = await runBreadth(world.deps);
  assert.deepEqual(result.reasons, []);
  assert.equal(result.outcome, "recorded");
  // 300 s propagation, 21 writes of 6 s, then the first read after the frames arrive plus 30 s quiet
  assert.ok(world.deps.clock.now() < 300000 + 21 * 6000 + 210000);
  assert.ok(world.deps.clock.now() >= 300000 + 21 * 6000 + 30000);
});

test("the tail runs to its end while an expected delivery is missing", async () => {
  const world = makeWorld({
    frames: "all",
    drop: (f) => f.handler === "k9DeletedV1" && idOf(f) === "b2",
  });
  const result = await runBreadth(world.deps);
  assert.deepEqual(result.reasons, ["missing delivery: k4 k9DeletedV1 ga/b2"]);
  assert.equal(world.deps.clock.now(), 300000 + 21 * 6000 + 210000);
});

test("a missing delivery on an observation-only step neither holds the tail nor is a reason", async () => {
  const world = makeWorld({
    frames: "all",
    drop: (f) => idOf(f) === "l2" || idOf(f) === "l3",
  });
  const result = await runBreadth(world.deps);
  assert.deepEqual(result.reasons, []);
  assert.ok(world.deps.clock.now() < 300000 + 21 * 6000 + 210000);
});

test("a refused optional deploy continues without it; a refused required deploy stops", async () => {
  const optional = makeWorld({ failure: "k9GroupWrittenV2", kind: "refused", frames: "all" });
  const result = await runBreadth(optional.deps);
  assert.equal(writes(optional).length, 21);
  assert.deepEqual(result.reasons, []);
  assert.equal(result.outcome, "recorded");
  const required = makeWorld({ failure: "k9CreatedV2", kind: "refused" });
  const stopped = await runBreadth(required.deps);
  assert.ok(stopped.reasons.includes("deploy failed"));
  assert.equal(writes(required).length, 0);
});

test("an unknown deploy stops everything and leaves the create unresolved", async () => {
  const world = makeWorld({ failure: "k9AnyWrittenV2", kind: "unknown" });
  const result = await runBreadth(world.deps);
  assert.equal(writes(world).length, 0);
  assert.equal(result.residual, true);
  assert.ok(result.reasons.includes("k9AnyWrittenV2 create remains unknown"));
});

test("the SDK steps go to the SDK and the others to the REST client", async () => {
  const world = makeWorld();
  const seen = [];
  world.deps.rtdb.write = async (step) => (
    seen.push(["rtdb", step.id]),
    { outcome: "ok", status: 200 }
  );
  world.deps.sdk.write = async (id) => (seen.push(["sdk", id]), { outcome: "ok", status: 200 });
  await runBreadth(world.deps);
  assert.deepEqual(
    seen.filter(([who]) => who === "sdk").map(([, id]) => id),
    ["k18", "k19", "k20", "k21"],
  );
  assert.equal(seen.filter(([who]) => who === "rtdb").length, 17);
});

test("a write that is not answered ok stops the run and is named", async () => {
  const world = makeWorld({ frames: "all" });
  const write = world.deps.rtdb.write;
  world.deps.rtdb.write = async (step) =>
    step.id === "k5" ? { outcome: "refused", status: 400 } : write(step);
  const result = await runBreadth(world.deps);
  assert.deepEqual(writes(world), ["k1", "k2", "k3", "k4"]);
  assert.ok(result.reasons.includes("write k5 refused"));
  assert.ok(result.reasons.includes("write k5 was not answered ok"));
  assert.equal(result.outcome, "stopped-needs-review");
  // the run still cleans up what it started
  assert.ok(world.events.includes("cleanup rtdb"));
  assert.ok(world.events.includes("cleanup k9GroupWrittenV2"));
});

test("a signal before the first deploy deploys nothing and still cleans up", async () => {
  const world = makeWorld();
  world.deps.abort.stopped = true;
  const result = await runBreadth(world.deps);
  assert.ok(result.reasons.includes("signal before deploy"));
  assert.equal(world.events.filter((e) => e.startsWith("deploy ")).length, 0);
  assert.equal(writes(world).length, 0);
  assert.ok(world.events.includes("cleanup rtdb"));
  assert.ok(world.events.includes("cleanup user"));
});

test("an RTDB cleanup that is not closed leaves the run residual", async () => {
  const world = makeWorld();
  world.deps.rtdb.cleanup = async () => ({
    closed: false,
    errors: ["unexpected: x"],
    unresolved: [],
  });
  const result = await runBreadth(world.deps);
  assert.equal(result.residual, true);
  assert.ok(result.reasons.includes("RTDB cleanup unresolved"));
});

test("a handler that was not deployed does not hold the tail", async () => {
  const world = makeWorld({ failure: "k9AnyWrittenV2", kind: "refused", frames: "all" });
  const result = await runBreadth(world.deps);
  assert.deepEqual(result.reasons, []);
  assert.ok(world.deps.clock.now() < 300000 + 21 * 6000 + 210000);
  assert.ok(world.deps.clock.now() >= 300000 + 21 * 6000 + 30000);
});
