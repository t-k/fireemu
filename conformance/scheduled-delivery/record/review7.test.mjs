// Ruling of 2026-10-05 (coordinator) for the third delivery run (packet r6): a Gen1 retry probe. The Gen1 function
// `schedRetryV1` declares `retryConfig({retryCount: 1})` and always fails, so that the recording shows whether Cloud
// Scheduler or Pub/Sub ever delivers a failed Gen1 handler's message twice (run 2 showed one invocation per occurrence
// for a job with no count). Everything else of run 2 is repeated, so each condition gets its second observation.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  ALL_FUNCTIONS,
  DECLARED,
  FUNCTIONS,
  jobIds,
  pullSubscriptionId,
  scheduleId,
} from "./plan.mjs";
import { record } from "./run.mjs";
import { NUMBER, createWorld } from "./world.mjs";

const RUN = "0123456789abcdef";
const FIXTURE = fileURLToPath(new URL("../fixture/index.js", import.meta.url));

test("the plan names the probe as a sixth function, a Gen1 one with a retry count of 1", () => {
  assert.deepEqual([...FUNCTIONS.v1], ["schedOkV1", "schedFailV1", "schedRetryV1"]);
  assert.equal(ALL_FUNCTIONS.length, 6);
  assert.deepEqual(DECLARED.schedRetryV1, {
    platform: "gcfv1",
    schedule: "every 5 minutes",
    retryConfig: {
      retryCount: 1,
      minBackoffDuration: null,
      maxBackoffDuration: null,
      maxDoublings: null,
      maxRetryDuration: null,
    },
  });
  assert.ok(jobIds(RUN).includes(scheduleId("schedRetryV1")));
  assert.equal(pullSubscriptionId(RUN, "schedRetryV1"), "fe-sd-" + RUN + "-pull-schedretryv1");
});

test("the fixture exports the probe: Gen1, retryCount 1, always failing, one frame per call", () => {
  const source = readFileSync(FIXTURE, "utf8");
  const start = source.indexOf("exports.schedRetryV1");
  assert.ok(start > 0);
  const block = source.slice(start);
  assert.match(block, /\.pubsub\.schedule\("every 5 minutes"\)/);
  assert.match(block, /\.retryConfig\(\{ retryCount: 1 \}\)/);
  assert.match(block, /frameV1\("schedRetryV1", args, \{ failing: true \}\)/);
  assert.match(block, /throw new Error/);
});

test("a clean run deploys six functions, makes three topics and pull subscriptions, forces ten jobs a pass, and the guard allows each", async () => {
  const world = createWorld();
  const journal = [];
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "test-token",
    save: async (row) => journal.push(row),
    send: world.send,
    runCli: (o) => world.runCli(o),
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
    passes: 1,
    naturalWindowMs: 60_000,
  });
  assert.equal(result.closureReady, true);
  const ids = new Set(journal.map((r) => r.id));
  assert.ok(ids.has("create-subscription-schedRetryV1"));
  assert.ok(ids.has("readback-topic-schedRetryV1"));
  assert.ok(ids.has("run-1-schedRetryV1-us-central1"));
  const forced = result.passes[0].forced.map((f) => f.id);
  assert.ok(forced.includes(scheduleId("schedRetryV1")));
  assert.equal(forced.length, 10);
});
