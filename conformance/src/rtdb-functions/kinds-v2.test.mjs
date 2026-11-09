import test from "node:test";
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { runBreadth } from "./breadth-flow.mjs";
import { KINDS_SCENARIO, KINDS_V2_SCENARIO, KINDS_V2_STEP_IDS } from "./kinds-scenario.mjs";
import { MASKED_NONCE } from "./kinds-mask.mjs";
import { FIXTURE_HANDLERS } from "./kinds-frames.mjs";
import { buildSteps, observe } from "./kinds-sequence.mjs";
import { makeWorld } from "./kinds-world.fake.mjs";

const writes = (world) => world.events.filter((e) => e.startsWith("write ")).map((e) => e.slice(6));

test("packet v2 has exactly the user writes k15 to k21, in the first packet's order", () => {
  const steps = KINDS_V2_SCENARIO.buildSteps(MASKED_NONCE);
  assert.deepEqual(
    steps.map((s) => s.id),
    ["k15", "k16", "k17", "k18", "k19", "k20", "k21"],
  );
  assert.deepEqual(
    steps.map((s) => s.id),
    [...KINDS_V2_STEP_IDS],
  );
  assert.deepEqual(
    steps.map((s) => s.context),
    ["user-rest", "user-rest", "user-rest", "user-sdk", "user-sdk", "user-sdk", "user-sdk"],
  );
  // the steps are the first packet's, byte for byte: same method, path, body and extras
  const first = buildSteps(MASKED_NONCE).filter((s) => KINDS_V2_STEP_IDS.includes(s.id));
  assert.deepEqual(steps, first);
  // no oversized payload and no observation-only step is left
  assert.equal(JSON.stringify(steps).includes("xxxx"), false);
  assert.ok(steps.every((s) => s.observeOnly !== true));
  assert.deepEqual(KINDS_V2_SCENARIO.sdk.ids, ["k18", "k19", "k20", "k21"]);
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

test("packet v2 expects 31 deliveries from 8 item transitions and 7 group transitions", () => {
  const steps = KINDS_V2_SCENARIO.buildSteps(MASKED_NONCE);
  const report = observe({ steps });
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

test("the shared flow sends only k15 to k21 and every expected delivery makes it recorded", async () => {
  const world = makeWorld({ frames: "all", scenario: KINDS_V2_SCENARIO });
  const result = await runBreadth(world.deps);
  assert.deepEqual(result.reasons, []);
  assert.equal(result.outcome, "recorded");
  assert.deepEqual(writes(world), [...KINDS_V2_STEP_IDS]);
  assert.ok(world.deps.clock.now() < 300000 + 7 * 6000 + 210000);
  assert.equal(result.report.totals.frames, 31);
  assert.equal(result.report.totals.unattributed, 0);
});

test("a missing delivery on a v2 write is a reason: nothing is observation-only any more", async () => {
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
