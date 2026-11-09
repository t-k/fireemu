import test from "node:test";
import assert from "node:assert/strict";
import { parseFrames, runLocal, scenarioFor } from "./kinds-local-run.mjs";
import { KINDS_SCENARIO, KINDS_V2_SCENARIO } from "./kinds-scenario.mjs";

test("frames are read from the daemon output, a cut line is not a frame", () => {
  const output = [
    "2026-11-08T00:00:00Z INFO starting",
    `2026-11-08T00:00:01Z functions: G9_FRAME ${JSON.stringify({ handler: "k9CreatedV2", seq: 1 })}`,
    "G9_FRAME not json",
    `G9_FRAME ${JSON.stringify({ handler: "k9DeletedV1", seq: 2 })}`,
    'G9_FRAME {"handler":"cut',
    "",
  ].join("\n");
  assert.deepEqual(parseFrames(output), [
    { handler: "k9CreatedV2", seq: 1 },
    { handler: "k9DeletedV1", seq: 2 },
  ]);
  assert.deepEqual(parseFrames(""), []);
});

test("the local run refuses an unknown profile before it starts anything", async () => {
  await assert.rejects(
    runLocal({ fireemu: "/nonexistent", profile: "other", out: "/nonexistent/out" }),
    /--profile is strict or emulator/,
  );
});

test("the local run sends all 21 steps unless packet v2 is asked for", () => {
  assert.equal(scenarioFor("all"), KINDS_SCENARIO);
  assert.equal(scenarioFor(undefined), KINDS_SCENARIO);
  assert.equal(scenarioFor("v2"), KINDS_V2_SCENARIO);
  assert.equal(scenarioFor("v2").buildSteps("n").length, 7);
  assert.equal(scenarioFor("all").buildSteps("n").length, 21);
});
