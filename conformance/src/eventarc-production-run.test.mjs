import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createCapture } from "./pubsub-production/capture.mjs";
import { CASES } from "./eventarc-production/cases/index.mjs";
import { StopClean } from "./eventarc-production/cases/support.mjs";
import { preconditions } from "./eventarc-production/cases/service.mjs";
import { createClient } from "./eventarc-production/client.mjs";
import { createOwnership } from "./eventarc-production/names.mjs";
import { createWorld } from "./eventarc-production/testing/world.mjs";
import { serveWorld } from "./eventarc-production/testing/world-server.mjs";
import {
  CLEANUP_BUDGET,
  DEFAULT_MAX_REQUESTS,
  main,
  parseArgs,
  summarize,
  probesToRegister,
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
    [["--cleanup-only", "--run-id", RUN], /needs --from-capture/],
    [
      ["--cleanup-only", "--run-id", RUN, "--from-capture", "/x/capture-ffffffffffff.jsonl"],
      /must be capture-<run ID>\.jsonl of that run/,
    ],
    [["--from-capture", `/x/capture-${RUN}.jsonl`], /is for --cleanup-only/],
  ])
    assert.throws(() => parseArgs([...base, ...extra]), pattern, extra.join(" "));
  // The later run works in the recording's directory, so that it sees the ledgers of every earlier one.
  assert.throws(
    () =>
      parseArgs([
        ...base,
        "--cleanup-only",
        "--run-id",
        RUN,
        "--from-capture",
        `/x/y/capture-${RUN}.jsonl`,
      ]),
    /--out must be the directory of --from-capture/,
  );
  assert.throws(
    () =>
      parseArgs([
        "--target",
        "production",
        "--project",
        "sandbox-project",
        "--out",
        "/x/y/a2-1",
        "--cleanup-only",
        "--run-id",
        RUN,
        "--from-capture",
        `/x/y/capture-${RUN}.jsonl`,
      ]),
    /--out must be the directory of --from-capture/,
  );
  const later = parseArgs([
    "--target",
    "production",
    "--project",
    "sandbox-project",
    "--out",
    "/x/y/",
    "--cleanup-only",
    "--run-id",
    RUN,
    "--from-capture",
    `/x/y/capture-${RUN}.jsonl`,
  ]);
  assert.deepEqual([later.cleanupOnly, later.ledgerPath], [true, `/x/y/issued-${RUN}.jsonl`]);
  assert.equal(parseArgs([...base, "--max-requests", "1"]).maxRequests, 1);
  assert.equal(parseArgs([...base, "--project-number", "1".repeat(20)]).usageProject.length, 20);
  assert.throws(() => parseArgs([...base, "--project-number", "1".repeat(21)]), /digits/);
  assert.equal(DEFAULT_MAX_REQUESTS, 400);
  assert.equal(CLEANUP_BUDGET, 450);
});

test("the cases are unique, start with the preconditions and the create probe, and fit the default budget", () => {
  assert.deepEqual(
    CASES.slice(0, 2).map((item) => item.id),
    ["preconditions", "create-probe"],
  );
  assert.equal(new Set(CASES.map((item) => item.id)).size, CASES.length);
  assert.equal(new Set(CASES.map((item) => item.short)).size, CASES.length);
  assert.ok(CASES.every((item) => Number.isInteger(item.requests) && item.requests > 0));
  assert.ok(plannedRequests(CASES) <= DEFAULT_MAX_REQUESTS);
  assert.deepEqual(
    selectCases(["auth-errors", "preconditions"]).map((item) => item.id),
    ["preconditions", "auth-errors"],
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
        request: async ({ path }) =>
          path.includes("/channels?")
            ? { status: 200, body: {}, unknown: false }
            : { status: 404, body: { error: { status: "NOT_FOUND" } }, unknown: false },
      },
    },
    ownership,
    caseId: "cleanup",
    usageProject: "p",
  });
  const run = ({ sleep: sleepOverride } = {}) =>
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
      sleep: sleepOverride ?? (async () => {}),
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
      await ctx.client.createChannel(ctx.project, ctx.location, "goog-x");
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

test("an error in a case is recorded and the run goes on; StopClean stops after cleaning up; a ceiling is a maximum", async () => {
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
    summary.cases.map((c) => [c.id, c.outcome, c.reason ?? null, c.requests]),
    [
      ["x", "error", "TypeError: boom", 0],
      ["o", "limit", "the case reached its limit of 1 requests", 1],
      ["s", "stopped", "stop here", 0],
    ],
  );
  assert.deepEqual(summary.limited, ["o"]);
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

test("replay on the recorded service body: DISABLED stops the run with nothing sent that changes anything, ENABLED lets it go on", async () => {
  const recorded = fixture("service-eventarcpublishing.json");
  const service = JSON.parse(recorded.body);
  assert.equal(service.state, "DISABLED");
  const firebase = fixture("channel-firebase-404.json");
  const answer =
    (state) =>
    ({ host, path }) => {
      if (host === "usage")
        return { status: 200, body: { ...service, state }, unknown: false };
      if (path.endsWith("/channels/firebase"))
        return { status: firebase.status, body: JSON.parse(firebase.body), unknown: false };
      return { status: 404, body: { error: { status: "NOT_FOUND" } }, unknown: false };
    };
  const disabled = setup([preconditions], { answer: answer("DISABLED"), options: { usageProject: "123456789012" } });
  const stopped = await disabled.run();
  assert.deepEqual(
    stopped.cases.map((c) => [c.outcome, c.reason]),
    [["stopped", "the publishing API is DISABLED: stage B does not enable it, nothing was created"]],
  );
  assert.deepEqual(
    disabled.calls.map((c) => `${c.method} ${c.host} ${c.op}`),
    ["GET usage getService"],
  );
  assert.equal(disabled.calls[0].path, "/v1/projects/123456789012/services/eventarcpublishing.googleapis.com");
  const enabled = setup([preconditions], { answer: answer("ENABLED") });
  const summary = await enabled.run();
  assert.deepEqual(
    summary.cases.map((c) => c.outcome),
    ["completed"],
  );
  assert.deepEqual(
    enabled.calls.map((c) => `${c.method} ${c.host} ${c.op}`),
    ["GET usage getService", "GET eventarc getChannel"],
  );
  assert.ok(
    enabled.notes.some((n) => n.note === "default-channel" && n.absent === true && n.status === 404),
    "the recorded 404 of the default channel is read as absent",
  );
});

test("a run is closable only with no unknown answer, no stop and a clean cleanup", () => {
  const clean = {
    stopped: null,
    limited: [],
    cleanup: { deleted: [], leftover: [], errors: [], unsettled: [] },
    cases: [],
  };
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
    { ...clean, cleanup: { ...clean.cleanup, unsettled: ["x"] } },
    { ...clean, limited: ["x"] },
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

test("main: a usage error exits 2, a budget below the plan is refused before anything is created", async (t) => {
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
});

for (const [label, extra] of [
  ["a channel with no state", {}],
  ["a channel that stays PENDING", { withState: true, stuckPending: true }],
]) {
  test(`main: the whole recording through the real transport and the SDK, against the model of the service (${label}), sends only well-formed writes and cleans up`, async (t) => {
    const world = createWorld({ project: "demo-fireemu-eventarc", ...extra });
    const service = await serveWorld(world);
    t.after(service.close);
    const out = join(mkdtempSync(join(tmpdir(), "eventarc-main-")), "o");
    const code = await main(
      ["--target", "emulator", "--emulator-host", service.host, "--out", out, "--run-id", RUN],
      {},
      io(),
      { now: Date.now, sleep: async () => {} },
    );
    const summary = JSON.parse(readFileSync(join(out, `summary-${RUN}.json`), "utf8"));
    assert.deepEqual(
      summary.cases.map((c) => [c.id, c.outcome]),
      CASES.map((item) => [item.id, "completed"]),
    );
    assert.equal(code, 0);
    assert.equal(summary.closureReady, true);
    // The model refused no creation for its shape, and no publish except the two probes that send no
    // events on purpose (an empty list and a body without the member).
    assert.deepEqual(
      world.refusals.map((refusal) => refusal.kind),
      ["publish-no-events", "publish-no-events"],
    );
    // Nothing of the run is left, and every case stayed inside its ceiling.
    assert.deepEqual(
      [...world.channels.keys()].filter((name) => name.includes(`/fe${RUN}-`)),
      [],
    );
    for (const entry of summary.cases)
      assert.ok(entry.requests <= CASES.find((item) => item.id === entry.id).requests, entry.id);
    const lines = readFileSync(join(out, `capture-${RUN}.jsonl`), "utf8")
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l));
    // The raw bytes of every answer are in the capture.
    const exchanges = lines.filter((l) => l.response?.status !== undefined);
    assert.ok(exchanges.length > 100);
    assert.ok(
      exchanges.every(
        (l) =>
          typeof l.response.bodyBase64 === "string" || Array.isArray(l.response.bodyBase64Parts),
      ),
    );
    assert.ok(exchanges.every((l) => /^[0-9a-f]{64}$/.test(l.response.bodySha256)));
    assert.ok(lines.some((l) => l.op === "sdk.publishEvents" && l.response.status === 200));
    assert.ok(
      lines.some((l) => l.note === "sdk-outcome" && l.name === "missing-source" && l.requests === 0),
    );
    // The create probe came first and every creation carried its channel's name.
    const creates = lines.filter((l) => l.op === "createChannel");
    assert.ok(creates.length > 5);
    for (const line of creates) {
      const [, parent, id] = /^(.*)\/channels\?channelId=(.*)$/.exec(line.request.path.replace(/^\/v1\//, ""));
      if (line.tokenMode === "default") assert.equal(line.request.body.name, `${parent}/channels/${id}`);
    }
  });
}

/** The most requests a case sends against five kinds of service, with no ceiling in the way. */
async function worstCase(item) {
  const operation = {
    name: "projects/demo-project/locations/us-central1/operations/op-1",
    done: false,
  };
  const modes = {
    // Everything answers 200 with an empty body.
    empty: () => ({ status: 200, body: {}, unknown: false }),
    // Everything is refused as missing.
    missing: () => ({ status: 404, body: { error: { status: "NOT_FOUND" } }, unknown: false }),
    // Every answer is an unknown one.
    unknown: () => ({ status: 503, body: {}, unknown: true }),
    // Every change is a long-running operation that never finishes, and the API is disabled.
    pending: (call) =>
      call.op === "getService"
        ? { status: 200, body: { state: "DISABLED" }, unknown: false }
        : call.method === "GET" && call.op !== "getOperation"
          ? { status: 404, body: { error: { status: "NOT_FOUND" } }, unknown: false }
          : { status: 200, body: operation, unknown: false },
    // The API is DISABLED for good, the lists are complete and the operations finish: the state polls run out.
    stuck: (call) =>
      call.op === "getService"
        ? { status: 200, body: { state: "DISABLED" }, unknown: false }
        : call.op === "listEnabledServices"
          ? { status: 200, body: { services: [] }, unknown: false }
          : call.method === "GET" && call.op !== "getOperation"
            ? { status: 404, body: { error: { status: "NOT_FOUND" } }, unknown: false }
            : { status: 200, body: { name: "x", done: true }, unknown: false },
    // Every channel exists and every operation finishes.
    exists: (call) =>
      call.op === "getService"
        ? { status: 200, body: { state: "DISABLED" }, unknown: false }
        : { status: 200, body: { name: "x", done: true }, unknown: false },
  };
  let worst = 0;
  for (const answer of Object.values(modes)) {
    const { run } = setup([{ ...item, requests: Infinity }], { answer: (call) => answer(call) });
    const summary = await run();
    worst = Math.max(worst, ...summary.cases.map((entry) => entry.requests));
  }
  return worst;
}

test("every case's ceiling covers the most it can send against a service that answers empty, missing, unknown, pending or existing", async () => {
  const measured = {};
  for (const item of CASES) measured[item.id] = await worstCase(item);
  const over = Object.entries(measured).filter(
    ([id, worst]) => worst > CASES.find((item) => item.id === id).requests,
  );
  assert.deepEqual(over, [], `measured worst cases: ${JSON.stringify(measured)}`);
});

test("a production run sends the quota project of the run on every request and the capture notes it; an emulator run sends none", () => {
  const base = ["--target", "production", "--project", "sandbox-project", "--out", "o"];
  assert.equal(parseArgs(base).quotaProject, "sandbox-project");
  assert.equal(parseArgs([...base, "--quota-project", "other-1234"]).quotaProject, "other-1234");
  assert.equal(
    parseArgs(["--target", "emulator", "--out", "o", "--emulator-host", "127.0.0.1:1"])
      .quotaProject,
    undefined,
  );
});

test("a later run registers as probes only the names whose creation or deletion may have happened, and never a name the run owns by prefix", () => {
  const ownership = createOwnership({ project: "demo-project", runId: "0123456789ab" });
  const channel = (id) => `projects/demo-project/locations/us-central1/channels/${id}`;
  const item = (creates, deletes = [], open = []) => ({ creates, deletes, open });
  const state = new Map([
    [channel("goog-0123456789ab"), item(["ok"])],
    [channel("1-0123456789ab"), item(["conflict"])],
    [channel("nowhere-0123456789ab"), item(["unknown"])],
    [channel("a0"), item([], [], ["delete"])],
    [channel("zz-0123456789ab"), item(["error"])],
    [channel("fe0123456789ab-cl-c1"), item(["ok"], ["ok"])],
  ]);
  assert.deepEqual(probesToRegister(state, ownership), [
    channel("goog-0123456789ab"),
    channel("nowhere-0123456789ab"),
    channel("a0"),
  ]);
});
