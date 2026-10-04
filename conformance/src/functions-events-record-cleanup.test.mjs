import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { runCleanup } from "./functions-events/record/cleanup.mjs";
import { createTransport } from "./functions-events/record/rest.mjs";
import { CONTROL_BUCKET, PRIMARY_BUCKET } from "./functions-events/record/script.mjs";
import { createWorld } from "./functions-events-record-world.mjs";

function setup() {
  let t = Date.UTC(2026, 9, 4);
  const world = createWorld({ now: () => t });
  const directory = mkdtempSync(join(tmpdir(), "fe-clean-"));
  const transport = createTransport({
    directory,
    ceiling: 1000,
    token: async () => "t",
    apiKey: "k",
    fetch: world.fetch,
  });
  const slept = [];
  const cliCalls = [];
  const cli = async (action) => {
    cliCalls.push(action);
    world.undeploy();
    return { action, exitCode: 0 };
  };
  const sleep = async (seconds) => slept.push(seconds);
  return { world, transport, cli, cliCalls, sleep, slept };
}
const put = (world, key, versions) => world.objects.set(key, versions);

test("a clean world is verified, the CLI delete runs once, and the control bucket and topics are gone", async () => {
  const { world, transport, cli, cliCalls, sleep } = setup();
  world.deploy();
  world.topics.add("fe-events-primary").add("fe-events-control");
  world.buckets.set(CONTROL_BUCKET, { versioning: false });
  const result = await runCleanup({ transport, cli, sleep, ran: { deployStarted: true } });
  assert.deepEqual(result.problems, []);
  assert.equal(result.verified, true);
  assert.deepEqual(cliCalls, ["delete"]);
  assert.equal(world.buckets.has(CONTROL_BUCKET), false);
  assert.equal(world.topics.size, 0);
});

test("leftover objects (every generation), markers and versioning are removed and reported", async () => {
  const { world, transport, cli, sleep } = setup();
  world.deploy();
  world.buckets.get(PRIMARY_BUCKET).versioning = true;
  put(world, `${PRIMARY_BUCKET}/fe-events/e1.txt`, [
    { generation: "1", live: false },
    { generation: "2", live: true },
  ]);
  put(world, `${PRIMARY_BUCKET}/other/e2.txt`, [{ generation: "3", live: true }]);
  world.docs.set("fe_events_retry_markers/abc", { documentPath: { stringValue: "x" } });
  const result = await runCleanup({ transport, cli, sleep, ran: { deployStarted: true } });
  assert.equal(result.verified, true, JSON.stringify(result.problems));
  assert.equal(result.steps.markers.found, 1);
  assert.equal(result.steps["objects-primary"].removed, 3);
  assert.equal(result.steps.versioning.restored, true);
  assert.equal(world.buckets.get(PRIMARY_BUCKET).versioning, false);
});

test("a run that never started the deploy sends no CLI delete", async () => {
  const { transport, cli, cliCalls, sleep } = setup();
  const result = await runCleanup({ transport, cli, sleep, ran: { deployStarted: false } });
  assert.deepEqual(cliCalls, []);
  assert.equal(result.steps.functions.skipped.includes("never started"), true);
});

test("functions that stay listed after the delete make the run needs-recovery, with six polls and no second delete", async () => {
  const { world, transport, sleep, slept } = setup();
  world.deploy();
  const cliCalls = [];
  const cli = async (action) => {
    cliCalls.push(action);
    return { action, exitCode: 0 };
  };
  const result = await runCleanup({ transport, cli, sleep, ran: { deployStarted: true } });
  assert.equal(result.verified, false);
  assert.ok(result.problems.some((p) => p.startsWith("functions:")));
  assert.deepEqual(cliCalls, ["delete"]);
  assert.equal(slept.filter((s) => s === 30).length, 5);
});

test("an unreadable object list is a problem, never an empty bucket", async () => {
  const { world, transport, cli, sleep } = setup();
  world.failures.push({
    match: (m, u) => u.includes(`/b/${PRIMARY_BUCKET}/o?versions=true`),
    status: 503,
  });
  const result = await runCleanup({ transport, cli, sleep, ran: { deployStarted: false } });
  assert.equal(result.verified, false);
  assert.ok(result.problems.some((p) => p.startsWith("objects-primary")));
});

test("a delete that gets no answer is not counted as removed and is not retried", async () => {
  const { world, transport, cli, sleep } = setup();
  put(world, `${PRIMARY_BUCKET}/fe-events/e1.txt`, [{ generation: "1", live: true }]);
  world.failures.push({ match: (m) => m === "DELETE", error: "TimeoutError" });
  const result = await runCleanup({ transport, cli, sleep, ran: { deployStarted: false } });
  assert.equal(result.verified, false);
  assert.equal(
    world.requests.filter((r) => r.method === "DELETE" && r.url.includes("fe-events%2Fe1.txt"))
      .length,
    1,
  );
});
