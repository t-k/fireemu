import test from "node:test";
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { runBreadth } from "./breadth-flow.mjs";
import { KINDS_SCENARIO, KINDS_V2_SCENARIO, KINDS_V2_STEP_IDS } from "./kinds-scenario.mjs";
import { MASKED_NONCE } from "./kinds-mask.mjs";
import { FIXTURE_HANDLERS } from "./kinds-frames.mjs";
import { BLOB_SIZES, buildSteps, observe } from "./kinds-sequence.mjs";
import { makeWorld } from "./kinds-world.fake.mjs";

const writes = (world) => world.events.filter((e) => e.startsWith("write ")).map((e) => e.slice(6));

test("packet v2 has the user writes k15 to k21 in the first packet's order, then the payload ladder", () => {
  const steps = KINDS_V2_SCENARIO.buildSteps(MASKED_NONCE);
  assert.deepEqual(
    steps.map((s) => s.id),
    ["k15", "k16", "k17", "k18", "k19", "k20", "k21", "k22", "k23", "k24", "k25"],
  );
  const main = steps.slice(0, 7);
  assert.deepEqual(
    main.map((s) => s.id),
    [...KINDS_V2_STEP_IDS],
  );
  assert.deepEqual(
    main.map((s) => s.context),
    ["user-rest", "user-rest", "user-rest", "user-sdk", "user-sdk", "user-sdk", "user-sdk"],
  );
  // the main steps are the first packet's, byte for byte: same method, path, body and extras
  const first = buildSteps(MASKED_NONCE).filter((s) => KINDS_V2_STEP_IDS.includes(s.id));
  assert.deepEqual(main, first);
  // the main steps are judged; the ladder, after them, is observation-only through the admin REST client
  assert.ok(main.every((s) => s.observeOnly !== true));
  assert.ok(steps.slice(7).every((s) => s.observeOnly === true && s.context === "admin"));
  assert.deepEqual(KINDS_V2_SCENARIO.sdk.ids, ["k18", "k19", "k20", "k21"]);
});

test("the ladder steps around the documented 1 MB, each in its own group so no event adds to another", () => {
  const rungs = KINDS_V2_SCENARIO.buildSteps(MASKED_NONCE).slice(7);
  assert.deepEqual(
    rungs.map((s) => s.id),
    ["k22", "k23", "k24", "k25"],
  );
  const groups = rungs.map((s) => s.path.split("/")[1]);
  assert.equal(new Set(groups).size, 4);
  assert.ok(groups.every((g) => !["ga", "gb", "gp", "gl", "gc", "gs"].includes(g)));
  assert.ok(rungs.every((s) => s.method === "PUT" && s.path.split("/")[2] === "items"));
  // the event of a create is the delta {"items":{id:leaf}} (the node before is null): the size of the
  // largest event of the write, the group handler's
  const sizes = rungs.map((s) => {
    const [, group, , id] = s.path.split("/");
    void group;
    return JSON.stringify({ items: { [id]: s.body } }).length;
  });
  const [repeat, below, above, far] = sizes;
  // the k12 value of the first recording again: the same 600 KiB blob
  assert.equal(rungs[0].body.blob.length, BLOB_SIZES.medium);
  assert.ok(repeat > 614_400 && repeat < 614_400 + 100, `the k12 shape again: ${repeat}`);
  assert.ok(below < 1_000_000 && below > 949_000 && below < 951_000, `about 0.95 MB: ${below}`);
  // above both readings of "1 MB" (1,000,000 and 1,048,576 bytes), for the leaf's own event as well
  const leaf = (s) => JSON.stringify(s.body).length;
  assert.ok(leaf(rungs[2]) > 1_048_576 && above < 1_100_000, `about 1.05 MB: ${above}`);
  assert.ok(far > 1_450_000 && far < 1_550_000, `about 1.5 MB: ${far}`);
  // distinct blob lengths: the frames of one rung cannot be taken for another's
  assert.equal(new Set(rungs.map((s) => s.body.blob.length)).size, 4);
  assert.equal(new Set(rungs.map((s) => s.body.value)).size, 4);
});

test("packet v2 shares the first packet's fixture, handlers, pins, limits and judge", () => {
  for (const key of [
    "codebase",
    "config",
    "fixtureDir",
    "pins",
    "prefix",
    "handlers",
    "targets",
    "limits",
    "ceilings",
    "windows",
    "observe",
    "judge",
    "complete",
    "rulesFor",
    "claims",
    "sdk",
  ])
    assert.equal(KINDS_V2_SCENARIO[key], KINDS_SCENARIO[key], key);
  assert.equal(KINDS_V2_SCENARIO.id, "kinds2");
  assert.equal(KINDS_V2_SCENARIO.runDirPrefix, "kinds2");
  assert.notEqual(KINDS_V2_SCENARIO.runDirPrefix, KINDS_SCENARIO.runDirPrefix);
});

test("packet v2 expects 31 judged deliveries from 8 item transitions and 7 group transitions, and up to 16 more on the ladder", () => {
  const allSteps = KINDS_V2_SCENARIO.buildSteps(MASKED_NONCE);
  const steps = allSteps.slice(0, 7);
  const report = observe({ steps });
  const ladder = observe({ steps: allSteps }).steps.slice(7);
  // each rung is one create: three item handlers and the group handler, observation-only
  assert.deepEqual(
    ladder.map((step) =>
      [...step.leaves, ...step.groups]
        .flatMap((entry) => Object.values(entry.handlers).map((seen) => seen.expected))
        .reduce((a, b) => a + b, 0),
    ),
    [4, 4, 4, 4],
  );
  const expected = { created: 0, updated: 0, deleted: 0, any: 0, group: 0 };
  const bump = (name, n) => {
    const key = name.includes("Created")
      ? "created"
      : name.includes("Updated")
        ? "updated"
        : name.includes("Deleted")
          ? "deleted"
          : name.includes("Any")
            ? "any"
            : "group";
    expected[key] += n;
  };
  for (const step of report.steps) {
    for (const entry of [...step.leaves, ...step.groups])
      for (const [name, seen] of Object.entries(entry.handlers)) bump(name, seen.expected);
  }
  assert.deepEqual(expected, { created: 8, updated: 4, deleted: 4, any: 8, group: 7 });
  assert.equal(
    Object.values(expected).reduce((a, b) => a + b, 0),
    31,
  );
  // the same transitions as in the first packet's model for the same steps
  const full = observe({ steps: buildSteps(MASKED_NONCE) });
  for (const step of report.steps) {
    const same = full.steps.find((s) => s.id === step.id);
    assert.deepEqual(
      step.leaves.map((l) => [l.group, l.id, l.kind]),
      same.leaves.map((l) => [l.group, l.id, l.kind]),
      step.id,
    );
    assert.deepEqual(
      step.groups.map((g) => g.group),
      same.groups.map((g) => g.group),
      step.id,
    );
  }
  assert.equal(FIXTURE_HANDLERS.length, 8);
});

test("the shared flow sends k15 to k25 and every expected delivery makes it recorded", async () => {
  const world = makeWorld({ frames: "all", scenario: KINDS_V2_SCENARIO });
  const result = await runBreadth(world.deps);
  assert.deepEqual(result.reasons, []);
  assert.equal(result.outcome, "recorded");
  assert.deepEqual(writes(world), [...KINDS_V2_STEP_IDS, "k22", "k23", "k24", "k25"]);
  assert.ok(world.deps.clock.now() < 300000 + 11 * 6000 + 210000);
  assert.equal(result.report.totals.frames, 47);
  assert.equal(result.report.totals.unattributed, 0);
});

test("a refused rung is recorded and the run goes on to the next rung; the refused rung has no delivery", async () => {
  const world = makeWorld({
    frames: "all",
    scenario: KINDS_V2_SCENARIO,
    refuse: (step) => ["k24", "k25"].includes(step.id),
    drop: (f) => {
      const params = f.generation === 1 ? f.event.context.params : f.event.params;
      return ["gq3", "gq4"].includes(params.group);
    },
  });
  const result = await runBreadth(world.deps);
  assert.deepEqual(result.reasons, []);
  assert.equal(result.outcome, "recorded");
  assert.deepEqual(writes(world), [...KINDS_V2_STEP_IDS, "k22", "k23", "k24", "k25"]);
  assert.equal(result.report.steps.find((s) => s.id === "k24").write.outcome, "refused");
  assert.equal(result.report.totals.frames, 39);
  assert.ok(world.events.indexOf("cleanup user") > world.events.indexOf("write k25"));
});

test("a rung that is refused and still delivered is a reason; a refused judged write still stops the run", async () => {
  const delivered = makeWorld({
    frames: "all",
    scenario: KINDS_V2_SCENARIO,
    refuse: (step) => step.id === "k24",
  });
  const result = await runBreadth(delivered.deps);
  assert.ok(
    result.reasons.some((r) => r.startsWith("unexpected delivery: k24")),
    result.reasons.join("|"),
  );
  assert.equal(result.outcome, "stopped-needs-review");
  const stopped = makeWorld({ scenario: KINDS_V2_SCENARIO, refuse: (step) => step.id === "k16" });
  const second = await runBreadth(stopped.deps);
  assert.deepEqual(writes(stopped), ["k15", "k16"]);
  assert.ok(second.reasons.includes("write k16 refused"));
});

test("an unknown answer to a rung still stops the run", async () => {
  const world = makeWorld({ scenario: KINDS_V2_SCENARIO });
  const write = world.deps.rtdb.write;
  world.deps.rtdb.write = async (step) =>
    step.id === "k23" ? (await write(step), { outcome: "unknown", status: 504 }) : write(step);
  const result = await runBreadth(world.deps);
  assert.deepEqual(writes(world), [...KINDS_V2_STEP_IDS, "k22", "k23"]);
  assert.ok(result.reasons.includes("write k23 unknown"));
});

test("a missing delivery on a judged v2 write is a reason", async () => {
  const world = makeWorld({
    frames: "all",
    scenario: KINDS_V2_SCENARIO,
    drop: (f) => f.handler === "k9DeletedV1",
  });
  const result = await runBreadth(world.deps);
  assert.equal(result.outcome, "stopped-needs-review");
  assert.ok(result.reasons.some((r) => r.startsWith("missing delivery: k17 k9DeletedV1")));
});

test("the v2 entry records the v2 scenario and no other", () => {
  const source = readFileSync(new URL("./kinds2-record.mjs", import.meta.url), "utf8");
  assert.match(source, /recordBreadth\(KINDS_V2_SCENARIO\)/u);
  assert.doesNotMatch(source, /KINDS_SCENARIO/u);
});
