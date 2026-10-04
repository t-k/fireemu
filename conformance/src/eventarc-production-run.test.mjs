import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createCapture } from "./pubsub-production/capture.mjs";
import { CASES } from "./eventarc-production/cases/index.mjs";
import { StopClean } from "./eventarc-production/cases/support.mjs";
import { serviceState } from "./eventarc-production/cases/service.mjs";
import { createClient } from "./eventarc-production/client.mjs";
import { createOwnership } from "./eventarc-production/names.mjs";
import {
  CLEANUP_BUDGET,
  DEFAULT_MAX_REQUESTS,
  main,
  parseArgs,
  summarize,
} from "./eventarc-production/record.mjs";
import {
  assertBudgetCovers,
  exitCodeOf,
  plannedRequests,
  runCases,
  selectCases,
} from "./eventarc-production/runner.mjs";

const RUN = "0123456789ab";
const fixture = (name) =>
  JSON.parse(
    readFileSync(
      new URL(`./eventarc-production/fixtures/preflight-002/${name}`, import.meta.url),
      "utf8",
    ),
  );

test("the arguments: an emulator target needs a host, a production target a project, both an out dir", () => {
  const emulator = parseArgs(["--target", "emulator", "--out", "o"], {
    CLOUD_EVENTARC_EMULATOR_HOST: "http://127.0.0.1:9299",
  });
  assert.deepEqual(
    [emulator.production, emulator.host, emulator.publishPrefix, emulator.location],
    [false, "http://127.0.0.1:9299", "", "us-central1"],
  );
  assert.match(emulator.runId, /^[0-9a-f]{12}$/);
  assert.equal(emulator.maxRequests, DEFAULT_MAX_REQUESTS);
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
    "service-state,auth-errors",
    "--run-id",
    RUN,
    "--project-number",
    "123456",
    "--location",
    "europe-west1",
  ]);
  assert.deepEqual(
    [
      production.production,
      production.publishPrefix,
      production.usageProject,
      production.maxRequests,
      production.only,
      production.runId,
      production.location,
    ],
    [true, "/v1", "123456", 50, ["service-state", "auth-errors"], RUN, "europe-west1"],
  );
  assert.equal(
    parseArgs(["--target", "production", "--project", "sandbox-project", "--out", "o"])
      .usageProject,
    "sandbox-project",
  );
});

test("bad arguments are refused, and the numbers have their values", () => {
  const base = ["--target", "production", "--project", "sandbox-project", "--out", "o"];
  for (const [extra, pattern] of [
    [["--max-requests", "0"], /positive integer/],
    [["--max-requests", "x"], /positive integer/],
    [["--run-id", "xyz"], /12 hex/],
    [["--project-number", "12a"], /digits/],
    [["--location", "Nowhere 1"], /not a location/],
    [["--nope", "1"], /unknown option --nope/],
    [["--only"], /needs a value/],
    [["stray"], /unexpected argument/],
    [["--cleanup-only"], /12 hex/],
  ])
    assert.throws(() => parseArgs([...base, ...extra]), pattern, extra.join(" "));
  assert.equal(parseArgs([...base, "--cleanup-only", "--run-id", RUN]).cleanupOnly, true);
  assert.equal(parseArgs([...base, "--max-requests", "1"]).maxRequests, 1);
  assert.equal(parseArgs([...base, "--project-number", "1".repeat(20)]).usageProject.length, 20);
  assert.throws(() => parseArgs([...base, "--project-number", "1".repeat(21)]), /digits/);
  assert.equal(DEFAULT_MAX_REQUESTS, 140);
  assert.equal(CLEANUP_BUDGET, 60);
});

test("the cases are unique, in the order that records the disabled state first, and fit the default budget", () => {
  assert.equal(CASES[0].id, "service-state");
  assert.equal(new Set(CASES.map((item) => item.id)).size, CASES.length);
  assert.equal(new Set(CASES.map((item) => item.short)).size, CASES.length);
  assert.ok(CASES.every((item) => Number.isInteger(item.requests) && item.requests > 0));
  assert.ok(plannedRequests(CASES) <= DEFAULT_MAX_REQUESTS);
  assert.deepEqual(
    selectCases(["auth-errors", "service-state"]).map((item) => item.id),
    ["service-state", "auth-errors"],
  );
  assert.throws(() => selectCases(["nope"]), /unknown case nope/);
  assertBudgetCovers([{ requests: 10 }, { requests: 5 }], 15);
  assert.throws(
    () => assertBudgetCovers([{ requests: 10 }, { requests: 5 }], 14),
    /may send 15 requests, over --max-requests 14/,
  );
});

function setup(cases, { answer, options = {}, stopping } = {}) {
  const ownership = createOwnership({ project: "demo-project", runId: RUN });
  const notes = [];
  const capture = createCapture({
    journal: { write: (entry) => notes.push(entry) },
    now: () => new Date(0),
  });
  const calls = [];
  const transport = (host) => ({
    name: "rest",
    request: async (call) => {
      calls.push({ host, ...call });
      capture.record({ case: call.label.case, op: call.op });
      return (answer ?? (() => ({ status: 200, body: {}, unknown: false })))({ host, ...call });
    },
  });
  const transports = {
    eventarc: transport("eventarc"),
    publishing: transport("publishing"),
    usage: transport("usage"),
  };
  const cleanupClient = createClient({
    transports: {
      eventarc: {
        name: "rest",
        request: async ({ path }) => ({
          status: 200,
          body: path.includes("/channels?") ? {} : { error: { status: "NOT_FOUND" } },
          unknown: false,
        }),
      },
    },
    ownership,
    caseId: "cleanup",
    usageProject: "p",
  });
  const run = () =>
    runCases({
      cases,
      transports,
      cleanupClient,
      ownership,
      capture,
      options: {
        production: false,
        location: "us-central1",
        usageProject: "p",
        publishPrefix: "/v1",
        ...options,
      },
      sleep: async () => {},
      isStopping: stopping,
    });
  return { run, calls, notes, ownership };
}

test("a case gets names that carry the prefix, probes registered before they are sent, and notes under its own id", async () => {
  const seen = [];
  const item = {
    id: "demo",
    short: "dm",
    requests: 2,
    async run(ctx) {
      seen.push(
        ctx.channel("k"),
        ctx.probe("goog-x"),
        ctx.probe("nowhere", { location: "no-such-location1", listable: false }),
      );
      await ctx.client.getChannel(ctx.channel("k"));
      await ctx.client.createChannel(ctx.project, ctx.location, "goog-x", {});
      ctx.note("hello", { n: 1 });
    },
  };
  const { run, calls, notes, ownership } = setup([item]);
  const summary = await run();
  assert.deepEqual(seen, [
    "projects/demo-project/locations/us-central1/channels/fe0123456789ab-dm-k",
    "projects/demo-project/locations/us-central1/channels/goog-x",
    "projects/demo-project/locations/no-such-location1/channels/nowhere",
  ]);
  assert.deepEqual(summary.cases, [{ id: "demo", outcome: "completed", requests: 2 }]);
  assert.equal(calls.length, 2);
  assert.deepEqual(ownership.locations(), ["us-central1"]);
  assert.deepEqual(
    notes.filter((n) => n.note === "hello").map((n) => [n.case, n.n]),
    [["demo", 1]],
  );
  assert.equal(exitCodeOf(summary), 0);
});

test("an error in a case is recorded and the run goes on; StopClean stops after cleaning up; a ceiling that was passed is flagged", async () => {
  const broken = {
    id: "x",
    short: "x1",
    requests: 1,
    async run() {
      throw new TypeError("boom");
    },
  };
  const over = {
    id: "o",
    short: "o1",
    requests: 1,
    async run(ctx) {
      await ctx.client.getChannel(ctx.channel("a"));
      await ctx.client.getChannel(ctx.channel("b"));
    },
  };
  const stop = {
    id: "s",
    short: "s1",
    requests: 1,
    async run() {
      throw new StopClean("stop here");
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
  const { run } = setup([broken, over, stop, never]);
  const summary = await run();
  assert.deepEqual(
    summary.cases.map((c) => [c.id, c.outcome, c.reason ?? null, c.overDeclared ?? null]),
    [
      ["x", "error", "TypeError: boom", null],
      ["o", "completed", null, 1],
      ["s", "stopped", "stop here", null],
    ],
  );
  assert.equal(summary.stopped, "stop here");
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
  const summary = await setup([first, second], { stopping: () => stop }).run();
  assert.deepEqual(
    summary.cases.map((c) => c.outcome),
    ["stopped"],
  );
  assert.equal(summary.stopped, "stopped by a signal");
  const none = await setup([second], { stopping: () => true }).run();
  assert.deepEqual([none.cases, none.stopped], [[], "signal"]);
});

test("replay on the recorded service body: DISABLED takes the disabled branch in order, ENABLED records only the state", async () => {
  const recorded = fixture("service-eventarcpublishing.json");
  const service = JSON.parse(recorded.body);
  assert.equal(service.state, "DISABLED");
  const firebase = fixture("channel-firebase-404.json");
  let enabled = false;
  const answer = ({ host, method, path }) => {
    if (host === "usage" && path.includes("/operations/"))
      return { status: 200, body: { name: "operations/acat.x", done: true }, unknown: false };
    if (host === "usage" && method === "GET")
      return {
        status: 200,
        body: enabled ? { ...service, state: "ENABLED" } : service,
        unknown: false,
      };
    if (host === "usage" && path.endsWith(":enable")) {
      enabled = true;
      return { status: 200, body: { name: "operations/acat.x", done: false }, unknown: false };
    }
    if (host === "usage")
      return { status: 200, body: { name: "operations/acat.x", done: true }, unknown: false };
    if (path.endsWith("/channels/firebase"))
      return { status: firebase.status, body: JSON.parse(firebase.body), unknown: false };
    return { status: 404, body: { error: { status: "NOT_FOUND" } }, unknown: false };
  };
  const disabled = setup([serviceState], { answer, options: { usageProject: "123456789012" } });
  const summary = await disabled.run();
  assert.deepEqual(
    disabled.calls.map((c) => `${c.method} ${c.host} ${c.op}`),
    [
      "GET usage getService",
      "POST publishing publishEvents",
      "GET eventarc getChannel",
      "POST publishing publishEvents",
      "GET eventarc getChannel",
      "GET eventarc listChannels",
      "POST usage enableService",
      "GET usage getOperation",
      "GET usage getService",
      "POST publishing publishEvents",
    ],
  );
  assert.match(
    disabled.calls[1].path,
    /\/v1\/projects\/demo-project\/locations\/us-central1\/channels\/fe0123456789ab-sv-never-created:publishEvents$/,
  );
  assert.ok(
    disabled.calls[3].path.endsWith("/channels/firebase:publishEvents"),
    "the default channel only after it was read as absent",
  );
  assert.equal(
    disabled.calls[0].path,
    `/v1/projects/123456789012/services/eventarcpublishing.googleapis.com`,
  );
  assert.equal(summary.cases[0].requests, 10);
  assert.ok(
    disabled.notes.some(
      (n) =>
        n.note === "service-state" && n.before === "DISABLED" && n.disabledStateRecorded === true,
    ),
  );
  // Already enabled: the state and one publish, nothing is enabled again.
  const already = setup([serviceState], {
    answer: ({ host, method }) =>
      host === "usage" && method === "GET"
        ? { status: 200, body: { ...service, state: "ENABLED" }, unknown: false }
        : { status: 404, body: { error: { status: "NOT_FOUND" } }, unknown: false },
  });
  await already.run();
  assert.deepEqual(
    already.calls.map((c) => c.op),
    ["getService", "publishEvents"],
  );
  // The default channel exists: nothing is published to it.
  const exists = setup([serviceState], {
    answer: ({ host, method, path }) =>
      host === "usage" && method === "GET"
        ? { status: 200, body: service, unknown: false }
        : path.endsWith("/channels/firebase")
          ? { status: 200, body: { name: "x" }, unknown: false }
          : { status: 200, body: { name: "operations/o", done: true }, unknown: false },
  });
  await exists.run();
  assert.equal(
    exists.calls.some((c) => c.op === "publishEvents" && c.path.includes("/channels/firebase:")),
    false,
  );
});

test("a run is closable only with no unknown answer, no stop and a clean cleanup", () => {
  const clean = { stopped: null, cleanup: { deleted: [], leftover: [], errors: [] }, cases: [] };
  const options = { runId: RUN, target: "emulator", project: "demo-project" };
  const capture = createCapture({ journal: { write() {} } });
  capture.record({ case: "a", step: "01", op: "getChannel" });
  assert.equal(summarize({ options, capture, summary: clean }).closureReady, true);
  capture.record({ case: "a", step: "02", op: "publishEvents", unknown: true });
  const unsettled = summarize({ options, capture, summary: clean });
  assert.deepEqual(
    [unsettled.closureReady, unsettled.unknownAnswers, unsettled.unknowns],
    [false, 1, [{ n: 2, case: "a", step: "02", op: "publishEvents" }]],
  );
  for (const summary of [
    { ...clean, stopped: "x" },
    { ...clean, cleanup: { ...clean.cleanup, leftover: ["x"] } },
    { ...clean, cleanup: { ...clean.cleanup, errors: ["x"] } },
  ])
    assert.equal(
      summarize({ options, capture: createCapture({ journal: { write() {} } }), summary })
        .closureReady,
      false,
    );
});

async function emptyServer() {
  const seen = [];
  const server = createServer((request, response) => {
    seen.push({
      method: request.method,
      url: request.url,
      authorization: request.headers.authorization,
    });
    response.setHeader("content-type", "application/json");
    if (request.method === "GET" && /\/channels\?/.test(request.url)) return response.end("{}");
    response.statusCode = 404;
    response.end('{"error":{"status":"NOT_FOUND"}}');
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { seen, host: `http://127.0.0.1:${server.address().port}`, close: () => server.close() };
}
const io = (errors = []) => ({
  stdout: { write: () => true },
  stderr: { write: (text) => errors.push(text) },
});

test("main: a usage error exits 2, a budget below the plan is refused before anything is created, and a signal-free cleanup-only run writes its files", async (t) => {
  const service = await emptyServer();
  t.after(service.close);
  const errors = [];
  const out = join(mkdtempSync(join(tmpdir(), "eventarc-main-")), "a", "b");
  assert.equal(await main(["--target", "nope", "--out", out], {}, io(errors)), 2);
  assert.match(errors.join(""), /--target must be emulator or production/);
  assert.equal(
    await main(
      [
        "--target",
        "emulator",
        "--emulator-host",
        service.host,
        "--out",
        out,
        "--max-requests",
        "10",
      ],
      {},
      io(errors),
    ),
    2,
  );
  assert.match(errors.join(""), /may send \d+ requests, over --max-requests 10/);
  assert.equal(
    await main(
      ["--target", "emulator", "--emulator-host", service.host, "--out", out, "--only", "nope"],
      {},
      io(errors),
    ),
    2,
  );
  assert.throws(() => readdirSync(out), "nothing was created");
  const code = await main(
    [
      "--target",
      "emulator",
      "--emulator-host",
      service.host,
      "--out",
      out,
      "--cleanup-only",
      "--run-id",
      RUN,
    ],
    {},
    io(),
  );
  assert.equal(code, 0);
  assert.deepEqual(readdirSync(out).toSorted(), [`capture-${RUN}.jsonl`, `summary-${RUN}.json`]);
  const summary = JSON.parse(readFileSync(join(out, `summary-${RUN}.json`), "utf8"));
  assert.deepEqual(
    [summary.closureReady, summary.requests, summary.cleanup.listed],
    [true, 1, ["us-central1"]],
  );
  assert.ok(service.seen.every((entry) => entry.authorization === undefined));
});

test("main: a case run through the SDK and the transports, against a service that has nothing, completes and cleans up", async (t) => {
  const service = await emptyServer();
  t.after(service.close);
  const out = join(mkdtempSync(join(tmpdir(), "eventarc-main-")), "o");
  const code = await main(
    [
      "--target",
      "emulator",
      "--emulator-host",
      service.host,
      "--out",
      out,
      "--only",
      "auth-errors,admin-sdk-publish",
      "--run-id",
      RUN,
    ],
    {},
    io(),
  );
  const summary = JSON.parse(readFileSync(join(out, `summary-${RUN}.json`), "utf8"));
  assert.deepEqual(
    summary.cases.map((c) => [c.id, c.outcome]),
    [
      ["admin-sdk-publish", "completed"],
      ["auth-errors", "completed"],
    ],
  );
  assert.equal(code, 0);
  const lines = readFileSync(join(out, `capture-${RUN}.jsonl`), "utf8")
    .trim()
    .split("\n")
    .map((l) => JSON.parse(l));
  assert.ok(lines.some((l) => l.op === "sdk.publishEvents" && l.response.status === 404));
  assert.ok(
    lines.some((l) => l.note === "sdk-outcome" && l.name === "missing-source" && l.requests === 0),
  );
});
