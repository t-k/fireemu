import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  BudgetExceeded,
  OMIT_ABOVE,
  createCapture,
  sanitize,
} from "./pubsub-production/capture.mjs";
import { CaseAbort, pullMessages } from "./pubsub-production/cases/support.mjs";
import { cleanup } from "./pubsub-production/cleanup.mjs";
import {
  PushPublishRefused,
  createClient,
  newPushState,
  restCode,
} from "./pubsub-production/client.mjs";
import { responseFromWire } from "./pubsub-production/grpc.mjs";
import { createOwnership } from "./pubsub-production/names.mjs";
import {
  CLEANUP_BUDGET,
  DEFAULT_MAX_REQUESTS,
  main,
  parseArgs,
} from "./pubsub-production/record.mjs";
import { createRest } from "./pubsub-production/rest.mjs";
import { runCases } from "./pubsub-production/runner.mjs";
import { createTokenProvider } from "./pubsub-production/token.mjs";
import { createBudget } from "./pubsub-production/capture.mjs";

const RUN = "0123456789ab";

test("the error classes carry their names, which the summary prints", () => {
  assert.equal(new BudgetExceeded(3).name, "BudgetExceeded");
  assert.equal(new PushPublishRefused("projects/p/topics/t").name, "PushPublishRefused");
  assert.equal(new CaseAbort("x", { code: "OK" }).name, "CaseAbort");
});

test("a string is omitted above exactly OMIT_ABOVE characters, and exchanges with an unknown answer are counted", () => {
  assert.equal(OMIT_ABOVE, 4096);
  assert.equal(sanitize("x".repeat(4096)), "x".repeat(4096));
  assert.ok(sanitize("x".repeat(4097)).omitted);
  const capture = createCapture({ journal: { write() {} } });
  assert.equal(capture.unknownCount(), 0);
  capture.record({ case: "a", unknown: false });
  capture.record({ case: "a" });
  assert.equal(capture.unknownCount(), 0);
  capture.record({ case: "a", unknown: true });
  assert.equal(capture.unknownCount(), 1);
  capture.record({ case: "a", unknown: true });
  assert.equal(capture.unknownCount(), 2);
});

test("the REST code of a status: 299 is a success, 300 is not, and an unlisted client error is UNKNOWN", () => {
  assert.equal(restCode(299, {}), "OK");
  assert.equal(restCode(300, {}), "UNKNOWN");
  assert.equal(restCode(199, {}), "UNKNOWN");
  assert.equal(restCode(200, {}), "OK");
});

test("a REST status answers by its range: 299 and 400 are answers, 300 and 399 are not", async () => {
  const unknownOf = async (status) => {
    const rest = createRest({
      base: "http://127.0.0.1:1",
      budget: createBudget(1),
      capture: createCapture({ journal: { write() {} } }),
      fetchImpl: async () => ({ status, text: async () => "{}" }),
    });
    return (await rest.request({ label: {}, op: "x", method: "GET", path: "/a" })).unknown;
  };
  for (const [status, unknown] of [
    [299, false],
    [300, true],
    [399, true],
    [400, false],
  ])
    assert.equal(await unknownOf(status), unknown, String(status));
});

test("a wire object under a time key without seconds is left as it is", () => {
  assert.deepEqual(responseFromWire({ time: { nanos: 5 } }), { time: { nanos: 5 } });
  assert.deepEqual(responseFromWire({ ttl: { nanos: 5 } }), { ttl: { nanos: 5 } });
});

test("the project of a run is an ID of 6 to 30 characters", () => {
  const make = (project) => createOwnership({ project, runId: RUN });
  make("abcde-f");
  make("a".repeat(5) + "b");
  assert.throws(() => make("abcde"), /not a project ID/);
  make("a" + "b".repeat(28) + "c");
  assert.throws(() => make("a" + "b".repeat(29) + "c"), /not a project ID/);
  const ownership = make("demo-project");
  assert.deepEqual(ownership.issued(), []);
  const name = ownership.resource("topics", "t");
  assert.deepEqual(ownership.issued(), [name]);
});

test("the token is cached for 40 minutes, gcloud is given a bounded output, and a refresh restarts the clock", async () => {
  const TOKEN = "ya29.a0AfH6SMBsecretsecretsecretsecretsecret";
  const options = [];
  let clock = 5_000_000;
  const provider = createTokenProvider({
    execFile: async (_file, _args, option) => (options.push(option), TOKEN),
    now: () => clock,
  });
  await provider.get();
  clock += 40 * 60 * 1000 - 1;
  await provider.get();
  assert.equal(provider.calls(), 1);
  clock += 1;
  await provider.get();
  assert.equal(provider.calls(), 2);
  clock += 1000;
  await provider.get();
  assert.equal(provider.calls(), 2, "the refresh time was kept, so it is still cached");
  assert.equal(options[0].maxBuffer, 64 * 1024);
});

test("the budgets and the options have their numbers", () => {
  assert.equal(DEFAULT_MAX_REQUESTS, 1026);
  assert.equal(CLEANUP_BUDGET, 600);
  const base = ["--target", "production", "--project", "sandbox-project", "--out", "o"];
  assert.equal(parseArgs([...base, "--max-requests", "1"]).maxRequests, 1);
  assert.throws(() => parseArgs([...base, "--max-requests", "-1"]), /positive/);
  assert.deepEqual(parseArgs([...base, "--transports", "rest,grpc"]).transports, ["rest", "grpc"]);
  assert.deepEqual(parseArgs([...base, "--transports", "rest"]).transports, ["rest"]);
  assert.throws(() => parseArgs([...base, "--transports", "grpc,x"]), /transports/);
  const digits = (n) => ["--service-agent-project-number", "1".repeat(n)];
  assert.ok(parseArgs([...base, ...digits(20)]).serviceAgent);
  assert.ok(parseArgs([...base, ...digits(1)]).serviceAgent);
  assert.throws(() => parseArgs([...base, ...digits(21)]), /digits/);
  assert.throws(
    () => parseArgs([...base, "--service-agent-project-number", ""]),
    /needs a value|digits/,
  );
});

/** A service that has nothing, whose lists can be made endless. */
function emptyService({ endless = false } = {}) {
  const calls = [];
  const transport = {
    name: "rest",
    async request({ method, path }) {
      calls.push(`${method} ${path}`);
      if (method === "GET" && /\/(topics|subscriptions|snapshots)\?/.test(path))
        return { status: 200, body: endless ? { nextPageToken: "more" } : {}, unknown: false };
      return { status: 404, body: { error: { status: "NOT_FOUND" } }, unknown: false };
    },
  };
  const ownership = createOwnership({ project: "demo-project", runId: RUN });
  return {
    calls,
    ownership,
    client: createClient({ transport, ownership, pushState: newPushState(), caseId: "cleanup" }),
  };
}

test("the cleanup lists with pages of 100, one request per kind when the list ends, and at most 50 pages", async () => {
  const sleeps = [];
  const sleep = async (ms) => sleeps.push(ms);
  const done = emptyService();
  await cleanup({ client: done.client, ownership: done.ownership, project: "demo-project", sleep });
  assert.equal(done.calls.length, 3);
  assert.ok(done.calls.every((call) => call.includes("pageSize=100")));
  const endless = emptyService({ endless: true });
  await cleanup({
    client: endless.client,
    ownership: endless.ownership,
    project: "demo-project",
    sleep,
  });
  assert.equal(endless.calls.length, 150, "50 pages for each of three kinds");
  assert.ok(endless.calls[1].includes("pageToken=more"));
});

test("the read-back waits two seconds between its three attempts", async () => {
  const live = new Set();
  const ownership = createOwnership({ project: "demo-project", runId: RUN });
  const name = ownership.resource("topics", "stubborn");
  live.add(name);
  const gets = [];
  const transport = {
    name: "rest",
    async request({ method, path }) {
      if (method === "GET" && /\/topics\?/.test(path))
        return { status: 200, body: { topics: [{ name }] }, unknown: false };
      if (method === "GET" && /\/(subscriptions|snapshots)\?/.test(path))
        return { status: 200, body: {}, unknown: false };
      if (method === "GET") gets.push(path);
      return method === "GET"
        ? { status: 200, body: { name }, unknown: false }
        : { status: 200, body: {}, unknown: false };
    },
  };
  const client = createClient({
    transport,
    ownership,
    pushState: newPushState(),
    caseId: "cleanup",
  });
  const sleeps = [];
  const report = await cleanup({
    client,
    ownership,
    project: "demo-project",
    sleep: async (ms) => sleeps.push(ms),
  });
  assert.deepEqual(report.leftover, [name]);
  assert.equal(gets.length, 3);
  assert.deepEqual(sleeps, [2000, 2000]);
});

test("a pull that reaches its count does not wait, and a waiting pull gets the default five attempts", async () => {
  const sleeps = [];
  const calls = [];
  const client = {
    pull: async (_s, body) => (
      calls.push(body),
      { ok: true, body: { receivedMessages: [{ ackId: "a" }] } }
    ),
  };
  const received = await pullMessages({ client, sleep: async (ms) => sleeps.push(ms) }, "s", 1, {
    immediately: true,
  });
  assert.equal(received.length, 1);
  assert.deepEqual(sleeps, [], "done after the first pull");
  const empty = {
    pull: async (_s, body) => (calls.push(body), { ok: true, body: {} }),
    with: () => empty,
  };
  calls.length = 0;
  await pullMessages({ client: empty, sleep: async () => {} }, "s", 1);
  assert.equal(calls.length, 5);
});

/** A server that has no Pub/Sub resources: every list is empty, everything else is NOT_FOUND. */
async function emptyServer({ onFirstRequest } = {}) {
  const seen = [];
  let first = true;
  const server = createServer((request, response) => {
    if (first) {
      first = false;
      onFirstRequest?.();
    }
    seen.push({
      method: request.method,
      url: request.url,
      authorization: request.headers.authorization,
    });
    response.setHeader("content-type", "application/json");
    if (request.method === "GET" && /\/(topics|subscriptions|snapshots)\?/.test(request.url))
      return response.end("{}");
    response.statusCode = 404;
    response.end('{"error":{"status":"NOT_FOUND"}}');
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { seen, host: `127.0.0.1:${server.address().port}`, close: () => server.close() };
}

test("main: a usage error exits 2 on stderr and creates nothing", async () => {
  const out = join(mkdtempSync(join(tmpdir(), "pubsub-main-")), "o");
  const written = [];
  const io = {
    stdout: { write: () => true },
    stderr: { write: (text) => written.push(String(text)) },
  };
  const code = await main(["--target", "nope", "--out", out], {}, io);
  assert.equal(code, 2);
  assert.match(written.join(""), /--target must be emulator or production/);
  assert.throws(() => readdirSync(out));
});

test("main: definite REST refusal aborts; gRPC transport ambiguity stays unconfirmed after cleanup", async (t) => {
  const service = await emptyServer();
  t.after(service.close);
  const out = join(mkdtempSync(join(tmpdir(), "pubsub-main-")), "o");
  const io = { stdout: { write: () => true }, stderr: { write: () => true } };
  const code = await main(
    [
      "--target",
      "emulator",
      "--emulator-host",
      service.host,
      "--out",
      out,
      "--only",
      "lifecycle",
      "--run-id",
      RUN,
    ],
    {},
    io,
  );
  const summary = JSON.parse(readFileSync(join(out, `summary-${RUN}.json`), "utf8"));
  assert.deepEqual(
    summary.cases.map((item) => [item.transport, item.outcome]),
    [
      ["rest", "aborted"],
      ["grpc", "aborted"],
    ],
  );
  assert.equal(code, 1);
  assert.equal(summary.closureReady, false);
  assert.equal(summary.cleanup.unconfirmed.length, 1);
  assert.equal(summary.stopped, null);
});

test("runCases without a stop check runs every case, and a spent budget is its own outcome with its message", async () => {
  const ownership = createOwnership({ project: "demo-project", runId: RUN });
  const capture = createCapture({ journal: { write() {} } });
  const list = { name: "rest", request: async () => ({ status: 200, body: {}, unknown: false }) };
  const cleanupRest = createClient({
    transport: list,
    ownership,
    pushState: newPushState(),
    caseId: "cleanup",
  });
  const item = {
    id: "spent",
    short: "sp",
    requests: 1,
    async run() {
      throw new BudgetExceeded(5);
    },
  };
  const notes = [];
  const journal = { write: (entry) => notes.push(entry) };
  const summary = await runCases({
    cases: [item],
    transports: { rest: list, grpc: list },
    cleanupRest,
    ownership,
    pushState: newPushState(),
    capture: createCapture({ journal }),
    options: { production: false },
    sleep: async () => {},
  });
  assert.equal(capture.count(), 0);
  assert.deepEqual(
    summary.cases.map((c) => [c.outcome, c.reason]),
    [["budget", "the request budget of 5 is spent"]],
  );
  assert.equal(summary.stopped, "the request budget of 5 is spent");
  assert.deepEqual(
    notes
      .map((note) => note.note)
      .filter(Boolean)
      .slice(0, 2),
    ["case-start", "case-end"],
  );
  assert.equal(notes.find((note) => note.note === "case-end").outcome, "budget");
  assert.equal(notes.find((note) => note.note === "case-start").case, "spent/rest");
});

test("main: a signal during a case run stops it between cases, after which the cleanup still runs", async (t) => {
  const service = await emptyServer({
    onFirstRequest: () => {
      // The handlers are registered once each; emitting both leaves none behind.
      process.emit("SIGTERM");
      process.emit("SIGINT");
    },
  });
  t.after(service.close);
  const out = join(mkdtempSync(join(tmpdir(), "pubsub-main-")), "o");
  const io = { stdout: { write: () => true }, stderr: { write: () => true } };
  await main(
    [
      "--target",
      "emulator",
      "--emulator-host",
      service.host,
      "--out",
      out,
      "--only",
      "lifecycle",
      "--run-id",
      RUN,
    ],
    {},
    io,
  );
  const summary = JSON.parse(readFileSync(join(out, `summary-${RUN}.json`), "utf8"));
  assert.equal(summary.stopped, "signal");
  assert.deepEqual(
    summary.cases.map((item) => item.transport),
    ["rest"],
  );
  assert.equal(summary.closureReady, false);
  assert.ok(summary.requests > 2, "the cleanup ran after the stop");
});

test("run as a program, a usage error exits 2 and names the option", () => {
  const result = spawnSync(
    process.execPath,
    ["src/pubsub-production/record.mjs", "--target", "nope", "--out", "x"],
    {
      encoding: "utf8",
    },
  );
  assert.equal(result.status, 2);
  assert.match(result.stderr, /--target must be emulator or production/);
});
