import test from "node:test";
import { readFile } from "node:fs/promises";
import { breadthCli } from "./breadth-wiring.mjs";
import assert from "node:assert/strict";
import { CODEBASE, TARGETS } from "./breadth-targets.mjs";

test("T1 deploys the retry handlers before the optional baseline", () => {
  assert.equal(CODEBASE, "rtdb-breadth-oracle");
  assert.deepEqual(
    TARGETS.map(({ functionName, generation, required }) => ({
      functionName,
      generation,
      required,
    })),
    [
      { functionName: "g9WrittenV2Retry", generation: "gcfv2", required: true },
      { functionName: "g9WrittenV1Retry", generation: "gcfv1", required: true },
      { functionName: "g9WrittenV2", generation: "gcfv2", required: false },
    ],
  );
});

test("breadth config selects the breadth fixture and codebase", async () => {
  const config = JSON.parse(await readFile(new URL("./firebase-breadth.json", import.meta.url)));
  assert.deepEqual(config.functions, { source: "fixtures-breadth", codebase: CODEBASE });
});

test("deploy CLI selects breadth config and refuses other functions", async () => {
  const calls = [];
  const run = breadthCli(async (...args) => calls.push(args));
  for (const target of TARGETS) {
    await run(["deploy", "--only", `functions:${CODEBASE}:${target.functionName}`]);
  }
  assert.equal(calls.length, 3);
  for (const [args] of calls) {
    assert.ok(args.includes("firebase-breadth.json"));
    assert.ok(
      TARGETS.some((target) => args.includes(`functions:${CODEBASE}:${target.functionName}`)),
    );
  }
  await assert.rejects(run(["deploy", "--only", `functions:${CODEBASE}:cv14WrittenV2`]));
  assert.equal(calls.length, 3);
});
