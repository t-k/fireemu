import test from "node:test";
import assert from "node:assert/strict";
import { BREADTH_LIMITS } from "./breadth-wiring.mjs";

test("T1 request limits are pinned for three functions", () => {
  assert.deepEqual(BREADTH_LIMITS, {
    cliDeploy: 3,
    upload: 15,
    token: 12,
    control: 38,
    cleanup: 70,
    logs: 40,
    inventory: 100,
    userClient: 6,
    browserHttp: 40,
    browserWs: 4,
  });
});
