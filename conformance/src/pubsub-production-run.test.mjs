import assert from "node:assert/strict";
import { mkdtempSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createCapture } from "./pubsub-production/capture.mjs";
import { StopClean, must } from "./pubsub-production/cases/support.mjs";
import { createClient, newPushState } from "./pubsub-production/client.mjs";
import { createOwnership } from "./pubsub-production/names.mjs";
import { DEFAULT_MAX_REQUESTS, main, parseArgs, summarize } from "./pubsub-production/record.mjs";
import { exitCodeOf, plannedRequests, runCases, selectCases } from "./pubsub-production/runner.mjs";
import { CASES } from "./pubsub-production/cases/index.mjs";

const RUN = "0123456789ab";

test("the arguments: an emulator target needs a host, a production target a project, both an out dir", () => {
  const emulator = parseArgs(["--target", "emulator", "--out", "o"], {
    PUBSUB_EMULATOR_HOST: "127.0.0.1:8085",
  });
  assert.equal(emulator.production, false);
  assert.equal(emulator.host, "127.0.0.1:8085");
  assert.match(emulator.runId, /^[0-9a-f]{12}$/);
  assert.equal(emulator.maxRequests, 850);
  assert.deepEqual(emulator.transports, ["rest", "grpc"]);
  assert.throws(() => parseArgs(["--target", "emulator", "--out", "o"], {}), /emulator-host/);
  assert.throws(() => parseArgs(["--target", "production", "--out", "o"]), /--project is required/);
  assert.throws(
    () => parseArgs(["--target", "production", "--project", "p-1234"]),
    /--out is required/,
  );
  assert.throws(() => parseArgs(["--out", "o"]), /--target/);
  const production = parseArgs([
    "--target",
    "production",
    "--project",
    "sandbox-project",
    "--out",
    "o",
    "--max-requests",
    "50",
    "--only",
    "lifecycle,names",
    "--transports",
    "grpc",
    "--run-id",
    RUN,
    "--service-agent-project-number",
    "123",
    "--quota-project",
    "q-1",
  ]);
  assert.equal(production.production, true);
  assert.deepEqual(
    [production.maxRequests, production.only, production.transports, production.runId],
    [50, ["lifecycle", "names"], ["grpc"], RUN],
  );
  assert.equal(
    production.serviceAgent,
    "serviceAccount:service-123@gcp-sa-pubsub.iam.gserviceaccount.com",
  );
  assert.equal(production.quotaProject, "q-1");
});

test("bad arguments are refused", () => {
  const base = ["--target", "production", "--project", "sandbox-project", "--out", "o"];
  for (const [extra, pattern] of [
    [["--max-requests", "0"], /positive integer/],
    [["--max-requests", "x"], /positive integer/],
    [["--run-id", "xyz"], /12 hex/],
    [["--transports", "rest,http"], /transports/],
    [["--service-agent-project-number", "12a"], /digits/],
    [["--nope", "1"], /unknown option --nope/],
    [["--only"], /needs a value/],
    [["stray"], /unexpected argument/],
    [["--cleanup-only"], /12 hex/],
  ])
    assert.throws(() => parseArgs([...base, ...extra]), pattern, extra.join(" "));
  const cleanupOnly = parseArgs([...base, "--cleanup-only", "--run-id", RUN]);
  assert.equal(cleanupOnly.cleanupOnly, true);
});

test("the selected cases keep the order of the list, and an unknown case is refused", () => {
  assert.deepEqual(
    selectCases(["names", "lifecycle"]).map((item) => item.id),
    ["lifecycle", "names"],
  );
  assert.throws(() => selectCases(["nope"]), /unknown case nope/);
  assert.equal(selectCases().length, CASES.length);
  assert.equal(new Set(CASES.map((item) => item.id)).size, CASES.length);
  assert.equal(new Set(CASES.map((item) => item.short)).size, CASES.length);
  assert.equal(CASES.at(-1).id, "dead-letter-forwarding", "the case that can stop the run is last");
});

/** A transport answering every request, remembering and capturing them like the real ones do. */
function fakeTransport(name, capture, answer) {
  const calls = [];
  const fallback =
    name === "rest"
      ? () => ({ status: 200, body: {}, unknown: false })
      : () => ({ code: "OK", body: {}, unknown: false });
  const send = async (call) => {
    calls.push(call);
    capture.record({ case: call.label.case, op: call.op });
    return (answer ?? fallback)(call);
  };
  return name === "rest" ? { name, calls, request: send } : { name, calls, call: send };
}

function setup(cases, { restAnswer, options = {}, stopping = () => false } = {}) {
  const ownership = createOwnership({ project: "demo-project", runId: RUN });
  const pushState = newPushState();
  const notes = [];
  const journal = { write: (entry) => notes.push(entry), close() {} };
  const capture = createCapture({ journal, now: () => new Date(0) });
  const transports = {
    rest: fakeTransport("rest", capture, restAnswer),
    grpc: fakeTransport("grpc", capture),
  };
  const cleanupTransport = fakeTransport("rest", capture, (call) =>
    call.method === "GET" && /\/(topics|subscriptions|snapshots)(\?|$)/.test(call.path)
      ? { status: 200, body: {}, unknown: false }
      : { status: 404, body: { error: { status: "NOT_FOUND" } }, unknown: false },
  );
  const cleanupRest = createClient({
    transport: cleanupTransport,
    ownership,
    pushState,
    caseId: "cleanup",
  });
  const run = () =>
    runCases({
      cases,
      transports,
      cleanupRest,
      ownership,
      pushState,
      capture,
      options: { production: false, ...options },
      sleep: async () => {},
      isStopping: stopping,
    });
  return { run, transports, notes, ownership, capture };
}

test("a case runs once for each transport, with names that carry the prefix and differ by transport", async () => {
  const seen = [];
  const item = {
    id: "demo",
    short: "dm",
    requests: 1,
    async run(ctx) {
      const topic = ctx.name("topics", "t");
      seen.push([ctx.transport, topic, ctx.maxKeyLength]);
      must(await ctx.client.createTopic(topic), "createTopic");
    },
  };
  const { run, transports } = setup([item]);
  const summary = await run();
  assert.deepEqual(
    summary.cases.map((c) => [c.id, c.transport, c.outcome, c.requests]),
    [
      ["demo", "rest", "completed", 1],
      ["demo", "grpc", "completed", 1],
    ],
  );
  assert.deepEqual(
    seen.map(([t]) => t),
    ["rest", "grpc"],
  );
  assert.notEqual(seen[0][1], seen[1][1]);
  for (const [, name, max] of seen) {
    assert.match(name, /^projects\/demo-project\/topics\/fe0123456789ab-dm-[rg]-t$/);
    assert.equal(
      255 - (name.split("/").pop().length - 1),
      max,
      "the longest key still fits in an ID",
    );
  }
  assert.equal(transports.rest.calls.length, 1);
  assert.equal(transports.grpc.calls.length, 1);
  assert.equal(summary.stopped, null);
  assert.equal(exitCodeOf(summary), 0);
});

test("a probe name is registered before it is sent and differs by transport", async () => {
  const item = {
    id: "probe",
    short: "pb",
    requests: 1,
    async run(ctx) {
      const name = ctx.probe("topics", "goog-x");
      assert.ok(name.endsWith(ctx.transport === "rest" ? "goog-x-r" : "goog-x-g"));
      await ctx.client.createTopic(name);
      const both = ctx.probe("topics", { rest: "ab", grpc: "ac" });
      assert.ok(both.endsWith(ctx.transport === "rest" ? "/ab" : "/ac"));
    },
  };
  const { run, ownership } = setup([item]);
  await run();
  assert.equal(ownership.probes().length, 4);
});

test("a step that did not answer as needed aborts the case, not the run", async () => {
  const failing = {
    id: "a",
    short: "a1",
    requests: 1,
    async run(ctx) {
      must(await ctx.client.getTopic(ctx.name("topics", "x")), "getTopic");
    },
  };
  const after = {
    id: "b",
    short: "b1",
    requests: 1,
    async run(ctx) {
      await ctx.client.getTopic(ctx.name("topics", "y"));
    },
  };
  const { run } = setup([failing, after], {
    restAnswer: (call) =>
      call.op === "getTopic" && call.path.includes("-a1-")
        ? { status: 404, body: {}, unknown: false }
        : { status: 200, body: {}, unknown: false },
  });
  const summary = await run();
  assert.deepEqual(
    summary.cases.map((c) => [c.id, c.transport, c.outcome]),
    [
      ["a", "rest", "aborted"],
      ["a", "grpc", "completed"],
      ["b", "rest", "completed"],
      ["b", "grpc", "completed"],
    ],
  );
  assert.match(summary.cases[0].reason, /getTopic did not succeed \(NOT_FOUND\)/);
  assert.equal(summary.stopped, null);
});

test("a case that throws is recorded with its error name and the run goes on", async () => {
  const broken = {
    id: "x",
    short: "x1",
    requests: 1,
    async run() {
      throw new TypeError("boom");
    },
  };
  const fine = {
    id: "y",
    short: "y1",
    requests: 1,
    async run(ctx) {
      await ctx.client.getTopic(ctx.name("topics", "y"));
    },
  };
  const { run } = setup([broken, fine]);
  const summary = await run();
  assert.equal(summary.cases[0].outcome, "error");
  assert.equal(summary.cases[0].reason, "TypeError: boom");
  assert.deepEqual(
    summary.cases.slice(2).map((c) => c.outcome),
    ["completed", "completed"],
  );
});

test("a StopClean stops the run after cleaning up, with its own exit code; a spent budget has another", async () => {
  const stopping = {
    id: "s",
    short: "s1",
    requests: 1,
    async run() {
      throw new StopClean("the service agent is missing");
    },
  };
  const never = {
    id: "n",
    short: "n1",
    requests: 1,
    async run() {
      throw new Error("must not run");
    },
  };
  const { run } = setup([stopping, never]);
  const summary = await run();
  assert.deepEqual(
    summary.cases.map((c) => c.outcome),
    ["stopped"],
  );
  assert.equal(summary.cases[0].reason, "the service agent is missing");
  assert.equal(summary.cases[0].reason, "the service agent is missing");
  assert.equal(summary.stopped, "the service agent is missing");
  assert.ok(summary.cleanup);
  assert.equal(exitCodeOf(summary), 3);
  assert.equal(
    exitCodeOf({
      stopped: "the request budget of 5 is spent",
      cleanup: { leftover: [], errors: [] },
    }),
    4,
  );
  assert.equal(exitCodeOf({ stopped: null, cleanup: { leftover: ["x"], errors: [] } }), 1);
  assert.equal(exitCodeOf({ stopped: null, cleanup: { leftover: [], errors: ["e"] } }), 1);
});

test("a signal between cases stops the run, and a sleep during one is refused", async () => {
  let stop = false;
  const first = {
    id: "f",
    short: "f1",
    requests: 1,
    async run(ctx) {
      await ctx.client.getTopic(ctx.name("topics", "f"));
      stop = true;
      await ctx.sleep(1000);
    },
  };
  const second = {
    id: "g",
    short: "g1",
    requests: 1,
    async run() {
      throw new Error("must not run");
    },
  };
  const { run } = setup([first, second], { stopping: () => stop });
  const summary = await run();
  assert.deepEqual(
    summary.cases.map((c) => c.outcome),
    ["stopped"],
  );
  assert.equal(summary.stopped, "stopped by a signal");
  const between = setup([second], { stopping: () => true });
  const result = await between.run();
  assert.deepEqual(result.cases, []);
  assert.equal(result.stopped, "signal");
});

test("the dead-letter case stops clean on production without a service agent, before it sends anything", async () => {
  const item = CASES.at(-1);
  const { run, transports } = setup([item], { options: { production: true } });
  const summary = await run();
  assert.equal(summary.cases[0].outcome, "stopped");
  assert.match(summary.stopped, /service agent project number was not supplied/);
  assert.equal(transports.rest.calls.length, 0);
});

test("a run is closable only with no unknown answer, no stop and a clean cleanup; the unknown ones are listed", () => {
  const journal = { write() {} };
  const clean = { stopped: null, cleanup: { deleted: [], leftover: [], errors: [] }, cases: [] };
  const options = { runId: RUN, target: "emulator", project: "demo-project" };
  const none = createCapture({ journal });
  none.record({ case: "a/rest", step: "01", op: "getTopic" });
  const ready = summarize({ options, capture: none, summary: clean });
  assert.equal(ready.closureReady, true);
  assert.deepEqual([ready.requests, ready.unknownAnswers, ready.unknowns], [1, 0, []]);
  const some = createCapture({ journal });
  some.record({ case: "a/rest", step: "01", op: "createTopic", unknown: true });
  some.record({ case: "a/grpc", step: "02", op: "publish", unknown: true });
  const unsettled = summarize({ options, capture: some, summary: clean });
  assert.equal(unsettled.closureReady, false);
  assert.deepEqual(unsettled.unknowns, [
    { n: 1, case: "a/rest", step: "01", op: "createTopic" },
    { n: 2, case: "a/grpc", step: "02", op: "publish" },
  ]);
  for (const summary of [
    { ...clean, stopped: "x" },
    { ...clean, cleanup: { ...clean.cleanup, leftover: ["x"] } },
    { ...clean, cleanup: { ...clean.cleanup, errors: ["x"] } },
  ])
    assert.equal(summarize({ options, capture: none, summary }).closureReady, false);
  // The list is bounded, the count is not.
  const many = createCapture({ journal });
  for (let i = 0; i < 150; i += 1)
    many.record({ case: "a/rest", step: "01", op: "x", unknown: true });
  assert.equal(many.unknownCount(), 150);
  assert.equal(many.unknowns().length, 100);
});

test("every case declares a ceiling, the whole set fits the default budget, and a smaller budget is refused before anything starts", async () => {
  assert.ok(CASES.every((item) => Number.isInteger(item.requests) && item.requests > 0));
  assert.equal(
    plannedRequests(CASES),
    CASES.reduce((sum, item) => sum + item.requests * 2, 0),
  );
  assert.equal(plannedRequests(CASES, ["rest"]), plannedRequests(CASES) / 2);
  assert.ok(plannedRequests(CASES) <= DEFAULT_MAX_REQUESTS);
  const errors = [];
  const io = { stdout: { write: () => true }, stderr: { write: (text) => errors.push(text) } };
  const out = join(mkdtempSync(join(tmpdir(), "pubsub-plan-")), "o");
  const code = await main(
    [
      "--target",
      "emulator",
      "--emulator-host",
      "127.0.0.1:1",
      "--out",
      out,
      "--max-requests",
      "100",
    ],
    {},
    io,
  );
  assert.equal(code, 2);
  assert.match(errors.join(""), /may send \d+ requests, over --max-requests 100/);
  assert.throws(() => readdirSync(out), "nothing was created");
  const unknown = await main(
    ["--target", "emulator", "--emulator-host", "127.0.0.1:1", "--out", out, "--only", "nope"],
    {},
    io,
  );
  assert.equal(unknown, 2);
});

test("a case that sends more than it declared is flagged in the summary", async () => {
  const item = {
    id: "over",
    short: "ov",
    requests: 1,
    async run(ctx) {
      await ctx.client.getTopic(ctx.name("topics", "a"));
      await ctx.client.getTopic(ctx.name("topics", "b"));
    },
  };
  const { run } = setup([item]);
  const summary = await run();
  assert.deepEqual(
    summary.cases.map((c) => [c.requests, c.overDeclared]),
    [
      [2, 1],
      [2, 1],
    ],
  );
  const fine = setup([{ ...item, requests: 2 }]);
  assert.equal((await fine.run()).cases[0].overDeclared, undefined);
});
