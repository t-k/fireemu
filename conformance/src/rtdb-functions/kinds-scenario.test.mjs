import test from "node:test";
import assert from "node:assert/strict";
import { FIXTURE_HANDLERS } from "./kinds-frames.mjs";
import { KINDS_SCENARIO, complete } from "./kinds-scenario.mjs";
import { buildSteps, observe } from "./kinds-sequence.mjs";
import { TARGETS } from "./kinds-targets.mjs";
import { perfectFrames } from "./kinds-world.fake.mjs";

const steps = buildSteps("N");
const names = (list) => FIXTURE_HANDLERS.map((h) => h.name).filter((n) => list.includes(n));
const everyone = FIXTURE_HANDLERS.map((h) => h.name);
const result = (incomplete = false) => ({ logs: { incomplete } });
const finished = ({
  only = everyone,
  deployed = TARGETS,
  drop = () => false,
  incomplete = false,
} = {}) => {
  const frames = perfectFrames(steps, names(only)).filter((f) => !drop(f));
  return complete({
    report: observe({ writes: {}, frames, steps }),
    deployed,
    result: result(incomplete),
  });
};
const idOf = (f) => f.event.params?.id ?? f.event.context?.params?.id;

test("complete when every deployed handler delivered everything it is expected for", () => {
  assert.equal(finished(), true);
});

test("incomplete log reads are never complete", () => {
  assert.equal(finished({ incomplete: true }), false);
});

test("a missing leaf delivery or a missing group delivery is not complete", () => {
  assert.equal(finished({ drop: (f) => f.handler === "k9DeletedV1" && idOf(f) === "b2" }), false);
  assert.equal(
    finished({ drop: (f) => f.handler === "k9AnyWrittenV2" && idOf(f) === "c1" }),
    false,
  );
  assert.equal(
    finished({ drop: (f) => f.handler === "k9GroupWrittenV2" && f.event.params.group === "gb" }),
    false,
  );
});

test("a handler that was not deployed is not waited for", () => {
  const without = (name) => ({
    only: everyone.filter((n) => n !== name),
    deployed: TARGETS.filter((t) => t.functionName !== name),
  });
  assert.equal(finished(without("k9GroupWrittenV2")), true);
  assert.equal(finished(without("k9AnyWrittenV2")), true);
  // undeployed in the report but still counted as deployed: not complete
  assert.equal(finished({ only: everyone.filter((n) => n !== "k9GroupWrittenV2") }), false);
  assert.equal(finished({ only: everyone.filter((n) => n !== "k9AnyWrittenV2") }), false);
});

test("observation-only steps are not waited for; judged steps are", () => {
  assert.equal(finished({ drop: (f) => ["l1", "l2", "l3"].includes(idOf(f)) }), true);
  assert.equal(finished({ drop: (f) => f.handler === "k9UpdatedV2" && idOf(f) === "p1" }), true);
  assert.equal(finished({ drop: (f) => idOf(f) === "p2" }), false);
  assert.equal(
    finished({ drop: (f) => ["s1", "s3"].includes(idOf(f)) && f.handler === "k9DeletedV1" }),
    false,
  );
});

test("the scenario hands the shared flow its own hooks and files", () => {
  assert.equal(KINDS_SCENARIO.complete, complete);
  assert.equal(KINDS_SCENARIO.config, "firebase-kinds.json");
  assert.equal(KINDS_SCENARIO.fixtureDir, "fixtures-kinds");
  assert.equal(KINDS_SCENARIO.runDirPrefix, "kinds");
  assert.equal(KINDS_SCENARIO.codebase, "rtdb-kinds-oracle");
  assert.equal(KINDS_SCENARIO.prefix, "k9-rtdb");
  assert.equal(KINDS_SCENARIO.targets.length, 8);
  assert.equal(KINDS_SCENARIO.handlers.length, 8);
  assert.equal(typeof KINDS_SCENARIO.judge, "function");
  assert.equal(typeof KINDS_SCENARIO.observe, "function");
  assert.equal(KINDS_SCENARIO.buildSteps("n").length, 21);
  assert.ok(Object.isFrozen(KINDS_SCENARIO));
});
