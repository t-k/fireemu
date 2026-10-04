import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createTransport } from "./functions-events/record/rest.mjs";
import { CLEANUP_CEILING, NORMAL_CEILING, record } from "./functions-events/record/run.mjs";
import { SCENARIO_ORDER, passSummary, buildPass } from "./functions-events/record/script.mjs";
import { createWorld } from "./functions-events-record-world.mjs";

function setup({ ceiling = 1000, world: worldOptions = {} } = {}) {
  const clock = { t: Date.UTC(2026, 9, 4, 0, 0, 0) };
  const world = createWorld({ now: () => clock.t, ...worldOptions });
  const directory = mkdtempSync(join(tmpdir(), "fe-run-"));
  const transport = createTransport({ directory, ceiling, token: async () => "t", apiKey: "k", fetch: world.fetch, now: () => clock.t });
  const calls = [];
  const cli = async (action) => {
    calls.push(action);
    if (action === "deploy") world.deploy();
    else world.undeploy();
    return { action, exitCode: 0 };
  };
  let n = 0;
  const deps = {
    transport,
    cli,
    sleep: async (seconds) => {
      clock.t += seconds * 1000;
    },
    now: () => clock.t,
    newId: (role) => `e${String(++n).padStart(5, "0")}${role}`,
    corpusDigest: "0".repeat(64),
  };
  return { clock, world, transport, calls, deps, directory };
}

test("a full run records two passes of every scenario, captures the deliveries, and ends verified", async () => {
  const { deps, world, calls } = setup();
  const { outcome, run } = await record(deps);
  assert.equal(outcome, "recorded", JSON.stringify([run.stops, run.cleanup?.problems]));
  assert.deepEqual(calls, ["deploy", "delete"]);
  assert.equal(run.passes.length, 2);
  for (const pass of run.passes) assert.deepEqual(pass.operations.map((o) => o.scenarioId), SCENARIO_ORDER);
  assert.ok(run.frames.length > 40, `${run.frames.length} frames`);
  assert.equal(run.frames.length, world.entries.length, "every delivered frame was captured once");
  assert.equal(new Set(run.frames.map((f) => f.insertId)).size, run.frames.length);
  assert.equal(run.cleanup.verified, true);
  assert.equal(world.deployed, false);
});

test("the request count stays inside the ceiling the design gives", async () => {
  const { deps, transport } = setup();
  const { run } = await record(deps);
  assert.ok(run.requestsSent <= CLEANUP_CEILING, `${run.requestsSent}`);
  assert.ok(run.requestsSent >= 300, `${run.requestsSent}`);
  const writes = passSummary(buildPass({ pass: 1, newId: (r) => r })).mutations * 2;
  assert.ok(writes === 116);
});

test("the source results follow what the calls returned, and a refusal is recorded as a refusal", async () => {
  const { deps } = setup();
  const { run } = await record(deps);
  const byId = Object.fromEntries(run.passes[0].operations.map((o) => [o.scenarioId, o]));
  assert.equal(byId["fs-create"].sourceResult, "typed-success");
  assert.equal(byId["storage-failed-upload"].sourceResult, "typed-refusal");
  assert.equal(byId["storage-delete-missing"].sourceResult, "typed-refusal");
  assert.equal(byId["auth-signup"].matchKey.value.startsWith("signup-"), true);
  assert.equal(byId["pubsub-publish"].matchKey.value.startsWith("msg-"), true);
});

test("inside the noop window the world delivered no write for the same-value write, though the seed and the cleanup did", async () => {
  const { deps } = setup();
  const { run } = await record(deps);
  const op = run.passes[0].operations.find((o) => o.scenarioId === "fs-noop");
  const start = Date.parse(op.endedAt);
  const forDocument = run.frames.filter((f) => f.handler === "fsWrittenV2" && JSON.stringify(f.frame).includes(op.matchKey.value));
  assert.equal(forDocument.length, 2, "the seed create and the cleanup delete");
  const inWindow = forDocument.filter((f) => Date.parse(f.logTimestamp) > start && Date.parse(f.logTimestamp) < start + op.windowSeconds * 1000);
  assert.equal(inWindow.length, 0);
});

test("a failed preflight stops clean: nothing is created, deployed or deleted", async () => {
  const { deps, calls, world } = setup();
  world.topics.add("fe-events-primary");
  const { outcome, run } = await record(deps);
  assert.equal(outcome, "stopped-clean");
  assert.deepEqual(calls, []);
  assert.ok(run.preflight.problems.length > 0);
  assert.ok(!world.requests.some((r) => ["POST", "PUT", "PATCH", "DELETE"].includes(r.method) && !r.url.includes(":getIamPolicy") && !r.url.includes("oauth2")));
});

test("a deploy that never becomes ready skips the passes and still cleans up with the one delete", async () => {
  const { deps, calls, world } = setup();
  deps.cli = async (action) => {
    calls.push(action);
    return { action, exitCode: 1 };
  };
  const { outcome, run } = await record(deps);
  assert.equal(outcome, "incomplete-clean");
  assert.equal(run.passes.length, 0);
  assert.deepEqual(calls, ["deploy", "delete"]);
  assert.ok(run.stops.some((s) => s.includes("did not become active")));
});

test("a stop signal ends the passes at the next step, and the cleanup still runs", async () => {
  const { deps, calls } = setup();
  const signal = { aborted: false };
  const original = deps.sleep;
  let sleeps = 0;
  deps.sleep = async (s) => {
    sleeps += 1;
    if (sleeps === 80) signal.aborted = true;
    return original(s);
  };
  const { outcome, run } = await record({ ...deps, signal });
  assert.equal(outcome, "incomplete-clean");
  assert.ok(run.passes[0].operations.length < SCENARIO_ORDER.length);
  assert.deepEqual(calls, ["deploy", "delete"]);
  assert.ok(run.stops.some((s) => s.includes("stop signal")));
});

test("the request ceiling stops the passes, and the cleanup still has its own allowance", async () => {
  const tight = setup();
  tight.transport.setCeiling = (n) => {
    tight.transport.state.ceiling = n === NORMAL_CEILING ? 150 : n;
  };
  const result = await record(tight.deps);
  assert.equal(result.outcome, "incomplete-clean", JSON.stringify(result.run.stops));
  assert.ok(result.run.stops.some((s) => s.includes("BudgetExhausted")));
  assert.deepEqual(tight.calls, ["deploy", "delete"]);
  assert.equal(result.run.cleanup.verified, true);
  assert.ok(result.run.requestsSent <= CLEANUP_CEILING);
});

test("a cleanup that cannot verify the functions gone ends needs-recovery and never sends a second delete", async () => {
  const { deps, calls, world } = setup();
  deps.cli = async (action) => {
    calls.push(action);
    if (action === "deploy") world.deploy();
    return { action, exitCode: 0 };
  };
  const { outcome, run } = await record(deps);
  assert.equal(outcome, "needs-recovery");
  assert.equal(calls.filter((a) => a === "delete").length, 1);
  assert.ok(run.cleanup.problems.some((p) => p.startsWith("functions:")));
});
