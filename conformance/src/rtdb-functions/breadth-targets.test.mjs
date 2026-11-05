import test from "node:test";
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
