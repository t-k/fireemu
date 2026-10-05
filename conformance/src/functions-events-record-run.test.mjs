import assert from "node:assert/strict";
import test from "node:test";

import { createTransport } from "./functions-events/record/rest.mjs";
import { CLEANUP_CEILING, NORMAL_CEILING, record } from "./functions-events/record/run.mjs";
import { SCENARIO_ORDER, passSummary, buildPass } from "./functions-events/record/script.mjs";
import { createWorld } from "./functions-events-record-world.mjs";
import { tempDir } from "./test-tmpdir.mjs";

function setup({ ceiling = 1000, world: worldOptions = {} } = {}) {
  const clock = { t: Date.UTC(2026, 9, 4, 0, 0, 0) };
  const world = createWorld({ now: () => clock.t, ...worldOptions });
  const directory = tempDir("fe-run-");
  const transport = createTransport({
    directory,
    ceiling,
    token: async () => "t",
    apiKey: "k",
    fetch: world.fetch,
    now: () => clock.t,
  });
  const calls = [];
  const cli = async (action) => {
    calls.push(action);
    if (action === "deploy") world.deploy();
    else if (action === "delete") world.undeploy();
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
  assert.deepEqual(calls, ["dry-run", "deploy", "delete"]);
  assert.equal(run.passes.length, 2);
  for (const pass of run.passes)
    assert.deepEqual(
      pass.operations.filter((o) => o.role === "subject").map((o) => o.scenarioId),
      SCENARIO_ORDER,
    );
  assert.ok(run.frames.length > 40, `${run.frames.length} frames`);
  assert.equal(run.frames.length, world.entries.length, "every delivered frame was captured once");
  assert.equal(new Set(run.frames.map((f) => f.insertId)).size, run.frames.length);
  assert.equal(run.cleanup.verified, true);
  assert.equal(world.deployed, false);
});

test("the request count stays inside the ceiling the design gives", async () => {
  const { deps } = setup();
  const { run } = await record(deps);
  assert.ok(run.requestsSent <= CLEANUP_CEILING, `${run.requestsSent}`);
  assert.ok(run.requestsSent >= 250 && run.requestsSent <= 420, `${run.requestsSent}`);
  const writes = passSummary(buildPass({ pass: 1, newId: (r) => r })).mutations * 2;
  assert.ok(writes === 124);
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
  const forDocument = run.frames.filter(
    (f) => f.handler === "fsWrittenV2" && JSON.stringify(f.frame).includes(op.matchKey.value),
  );
  assert.equal(forDocument.length, 2, "the seed create and the cleanup delete");
  const inWindow = forDocument.filter(
    (f) =>
      Date.parse(f.logTimestamp) > start &&
      Date.parse(f.logTimestamp) < start + op.windowSeconds * 1000,
  );
  assert.equal(inWindow.length, 0);
});

test("a failed preflight stops clean: nothing is created, deployed or deleted", async () => {
  const { deps, calls, world } = setup();
  world.topics.add("fe-events-primary");
  const { outcome, run } = await record(deps);
  assert.equal(outcome, "stopped-clean");
  assert.deepEqual(calls, []);
  assert.ok(run.preflight.problems.length > 0);
  assert.equal(run.deploy.dryRun, null, "no dry run was attempted");
  assert.ok(
    !world.requests.some(
      (r) =>
        ["POST", "PUT", "PATCH", "DELETE"].includes(r.method) &&
        !r.url.includes(":getIamPolicy") &&
        !r.url.includes(":runQuery") &&
        !r.url.includes("oauth2"),
    ),
  );
});

test("a deploy that never becomes ready skips the passes and still cleans up with the one delete", async () => {
  const { deps, calls } = setup();
  deps.cli = async (action) => {
    calls.push(action);
    return { action, exitCode: action === "dry-run" ? 0 : 1 };
  };
  const { outcome, run } = await record(deps);
  assert.equal(outcome, "incomplete-clean");
  assert.equal(run.passes.length, 0);
  assert.deepEqual(calls, ["dry-run", "deploy", "delete"]);
  assert.ok(run.stops.some((s) => s.includes("did not become active")));
});

test("a stop signal ends the passes at the next step, and the cleanup still runs", async () => {
  const { deps, calls } = setup();
  const signal = { aborted: false };
  const original = deps.sleep;
  let sleeps = 0;
  deps.sleep = async (s) => {
    sleeps += 1;
    if (sleeps === 40) signal.aborted = true;
    return original(s);
  };
  const { outcome, run } = await record({ ...deps, signal });
  assert.equal(outcome, "incomplete-clean");
  assert.ok(run.passes[0].operations.length < SCENARIO_ORDER.length);
  assert.deepEqual(calls, ["dry-run", "deploy", "delete"]);
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
  assert.deepEqual(tight.calls, ["dry-run", "deploy", "delete"]);
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

test("the run says which IAM bindings the deploy added or removed, with user accounts redacted", async () => {
  const { deps, world } = setup();
  const original = deps.cli;
  deps.cli = async (action) => {
    if (action === "deploy") world.extraIam = true;
    return original(action);
  };
  const { run } = await record(deps);
  const step = run.cleanup.steps.inventory;
  assert.deepEqual(step.iamDiff, {
    added: ["roles/pubsub.publisher serviceAccount:gcs-agent@example"],
    removed: [],
  });
  assert.ok(run.preflight.iamBefore.every((p) => !p.includes("@example.com")));
  assert.ok(Array.isArray(step.iamAfter));
});

test("an error before anything is created sends no delete at all", async () => {
  const { deps, world } = setup();
  world.failures.push({
    match: (m, u) => u.includes("cloudresourcemanager"),
    error: "TimeoutError",
  });
  const { outcome, run } = await record(deps);
  assert.equal(outcome, "stopped-clean");
  assert.ok(run.preflight.problems.length > 0);
  assert.ok(!world.requests.some((r) => r.method === "DELETE"));
});

test("a resource that cannot be created stops before the deploy and the cleanup still runs", async () => {
  const { deps, world, calls } = setup();
  world.failures.push({
    match: (m, u) => m === "PUT" && u.includes("fe-events-primary"),
    status: 503,
  });
  const { outcome, run } = await record(deps);
  assert.equal(outcome, "incomplete-clean");
  assert.deepEqual(calls, ["dry-run"]);
  assert.ok(run.stops.some((s) => s.includes("could not be created")));
  assert.equal(run.cleanup.verified, true);
});

const gone = (world) => ({
  documents: [...world.docs.keys()].filter((path) => !path.startsWith("fe_events_retry_markers/")),
  markers: [...world.docs.keys()].filter((path) => path.startsWith("fe_events_retry_markers/")),
  users: [...world.users.keys()],
  objects: [...world.objects.values()].flat().length,
});

test("a step's unknown Firestore DELETE is swept by the final cleanup: the world is empty when the run says recorded", async () => {
  const { deps, world } = setup();
  world.failures.push({
    match: (m, u) => m === "DELETE" && u.includes("/documents/fe_events_primary/"),
    status: 503,
    times: 1,
  });
  const { outcome, run } = await record(deps);
  assert.equal(outcome, "recorded", JSON.stringify([run.stops, run.cleanup?.problems]));
  assert.deepEqual(gone(world), { documents: [], markers: [], users: [], objects: 0 });
  assert.equal(run.cleanup.steps.documents.removed >= 1, true);
});

test("a step's unknown accounts:delete is swept: no Auth user of the run is left", async () => {
  const { deps, world } = setup();
  world.failures.push({ match: (m, u) => u.endsWith("/accounts:delete"), status: 503, times: 1 });
  const { outcome } = await record(deps);
  assert.equal(outcome, "recorded");
  assert.deepEqual(gone(world).users, []);
});

test("a sign-up whose answer was lost (the user exists) does not end the recording: the step is recorded unknown, the next steps run, the user is swept by email", async () => {
  const { deps, world } = setup();
  world.failures.push({
    match: (m, u) => u.includes("accounts:signUp"),
    status: 503,
    times: 1,
    after: true,
  });
  const { outcome, run } = await record(deps);
  assert.equal(outcome, "incomplete-clean");
  assert.equal(run.passes.length, 2);
  assert.equal(run.passes[1].operations.length > 20, true, "pass 2 still ran in full");
  const failed = run.passes[0].operations.find((o) => o.error);
  assert.match(failed.error, /placeholder idToken/);
  assert.equal(failed.sourceResult, "unknown");
  assert.deepEqual(gone(world), { documents: [], markers: [], users: [], objects: 0 });
  assert.ok(run.stops.some((s) => s.includes("fs-auth-client")));
});

const writes = (world) =>
  world.requests
    .filter((r) => ["POST", "PUT", "PATCH", "DELETE"].includes(r.method))
    .filter(
      (r) =>
        !r.url.includes(":getIamPolicy") &&
        !r.url.includes(":runQuery") &&
        !r.url.includes("oauth2"),
    );

test("the CLI dry run comes after the preflight and before anything is created", async () => {
  const { deps, world, calls } = setup();
  const seen = [];
  const cli = deps.cli;
  deps.cli = async (action) => {
    if (action === "dry-run")
      seen.push({ writes: writes(world).length, requests: world.requests.length });
    return cli(action);
  };
  const { outcome, run } = await record(deps);
  assert.equal(outcome, "recorded");
  assert.deepEqual(calls, ["dry-run", "deploy", "delete"]);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].writes, 0, "nothing was written before the dry run");
  assert.equal(run.deploy.dryRun.exitCode, 0, "the dry run is in the run record");
  assert.ok(seen[0].requests > 0, "the preflight reads came first");
});

for (const [label, answer] of [
  ["exits non-zero", { exitCode: 1 }],
  ["times out", { exitCode: null, timedOut: true }],
  ["times out and still exits 0 after the SIGTERM", { exitCode: 0, timedOut: true }],
  ["gives no exit code", {}],
]) {
  test(`a CLI dry run that ${label} stops clean: nothing is created, deployed or deleted`, async () => {
    const { deps, world, calls } = setup();
    deps.cli = async (action) => {
      calls.push(action);
      return { action, ...answer };
    };
    const { outcome, run } = await record(deps);
    assert.equal(outcome, "stopped-clean");
    assert.deepEqual(calls, ["dry-run"]);
    assert.equal(writes(world).length, 0);
    assert.ok(run.stops.some((s) => s.includes("dry run failed")));
    assert.equal(run.cleanup, null);
    assert.equal(run.passes.length, 0);
    assert.equal(run.deploy.cli, null);
  });
}

test("a CLI dry run that cannot even start stops clean with nothing written", async () => {
  const { deps, world } = setup();
  deps.cli = async () => {
    throw new Error("spawn failed");
  };
  const { outcome, run } = await record(deps);
  assert.equal(outcome, "stopped-clean");
  assert.equal(writes(world).length, 0);
  assert.ok(run.stops.some((s) => s.includes("spawn failed")));
});

test("a stop signal during the dry run stops clean before anything is created", async () => {
  const { deps, world, calls } = setup();
  const signal = { aborted: false };
  const cli = deps.cli;
  deps.cli = async (action) => {
    if (action === "dry-run") signal.aborted = true;
    return cli(action);
  };
  const { outcome, run } = await record({ ...deps, signal });
  assert.equal(outcome, "stopped-clean");
  assert.deepEqual(calls, ["dry-run"]);
  assert.equal(writes(world).length, 0);
  assert.ok(run.stops.some((s) => s.includes("after the dry run")));
});

test("a stop signal before anything is created stops clean: no resource, no CLI, no delete", async () => {
  const { deps, world, calls } = setup();
  const { outcome } = await record({ ...deps, signal: { aborted: true } });
  assert.equal(outcome, "stopped-clean");
  assert.deepEqual(calls, []);
  assert.ok(!world.requests.some((r) => ["PUT", "DELETE", "PATCH"].includes(r.method)));
});

test("a stop signal during setup cleans up without a deploy", async () => {
  const { deps, world, calls } = setup();
  const signal = { aborted: false };
  world.hooks.push((method, url) => {
    if (method === "PUT" && url.includes("fe-events-primary")) signal.aborted = true;
  });
  const { outcome, run } = await record({ ...deps, signal });
  assert.equal(outcome, "incomplete-clean");
  assert.deepEqual(calls, ["dry-run"]);
  assert.ok(run.stops.some((s) => s.includes("before the deploy")));
  assert.equal(world.topics.size, 0);
});

test("a stop signal while the deploy settles skips the passes and runs the one CLI delete", async () => {
  const { deps, world, calls } = setup();
  const signal = { aborted: false };
  const cli = deps.cli;
  deps.cli = async (action) => {
    if (action === "deploy") signal.aborted = true;
    return cli(action);
  };
  const { outcome, run } = await record({ ...deps, signal });
  assert.equal(outcome, "incomplete-clean");
  assert.deepEqual(calls, ["dry-run", "deploy", "delete"]);
  assert.equal(run.passes.length, 0);
  assert.equal(world.deployed, false);
});

test("a deploy whose CLI failed reads readiness at most twice before the cleanup", async () => {
  const { deps, world } = setup();
  deps.cli = async (action) => ({ action, exitCode: action === "deploy" ? 1 : 0 });
  const { run } = await record(deps);
  assert.equal(run.deploy.readiness.polls, 2);
  assert.ok(
    world.requests.filter(
      (r) =>
        r.url.includes("/v1/") && r.url.includes("cloudfunctions") && r.url.endsWith("/functions"),
    ).length <= 4,
  );
});

test("capture polls that fail do not lose frames: the last read covers the whole run", async () => {
  const { deps, world } = setup();
  world.failures.push({ match: (m, u) => u.includes("entries:list"), status: 503, times: 6 });
  const { run } = await record(deps);
  assert.equal(run.frames.length, world.entries.length);
  assert.ok(run.capture.incompletePolls >= 6);
});

test("a log page asks for at most 200 entries", async () => {
  const { deps, world } = setup();
  const sizes = [];
  world.hooks.push((method, url, init) => {
    if (url.includes("entries:list")) sizes.push(JSON.parse(init.body).pageSize);
  });
  await record(deps);
  assert.ok(sizes.length > 0 && sizes.every((n) => n <= 200));
});

test("a deploy that exits 0 but says N Functions Errored is a failed CLI: readiness is read at most twice", async () => {
  const { deps } = setup();
  deps.cli = async (action) => ({ action, exitCode: 0, errored: action === "deploy" ? 1 : 0 });
  const { run } = await record(deps);
  assert.equal(run.deploy.readiness.polls, 2);
  const clean = setup();
  clean.deps.cli = async (action) => ({ action, exitCode: 0, errored: 0 });
  const { run: other } = await record(clean.deps);
  assert.ok(other.deploy.readiness.polls > 2, "a clean summary leaves the full polling");
});

test("a dry run that exits 0 but names errored functions stops clean, nothing created", async () => {
  const { deps, calls, world } = setup();
  deps.cli = async (action) => {
    calls.push(action);
    return { action, exitCode: 0, errored: 2 };
  };
  const { outcome, run } = await record(deps);
  assert.equal(outcome, "stopped-clean");
  assert.deepEqual(calls, ["dry-run"]);
  assert.ok(run.stops.some((s) => s.includes("dry run failed")));
  assert.ok(!world.requests.some((r) => r.method === "PUT" || r.method === "DELETE"));
});

test("the v4 run's cleanup case end to end: the CLI delete leaves storageArchivedV2, the REST delete takes it, the run ends verified", async () => {
  const { deps, world, calls } = setup();
  deps.cli = async (action) => {
    calls.push(action);
    if (action === "deploy") world.deploy();
    else if (action === "delete") world.undeploy({ stuck: ["storageArchivedV2"] });
    return { action, exitCode: 0, errored: action === "delete" ? 1 : 0 };
  };
  const { outcome, run } = await record(deps);
  assert.equal(outcome, "recorded", JSON.stringify([run.stops, run.cleanup?.problems]));
  assert.deepEqual(calls, ["dry-run", "deploy", "delete"], "no second CLI delete");
  assert.deepEqual(world.restDeletes, ["storageArchivedV2"]);
  assert.equal(run.cleanup.verified, true);
  assert.equal(run.cleanup.steps.functions.cli.errored, 1);
});
