import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createOwnership } from "./eventarc-production/names.mjs";
import { CaseLimit } from "./eventarc-production/runner.mjs";
import { main, parseArgs } from "./eventarc-production/record.mjs";
import {
  CE_TYPE,
  baseAttributes,
  cloudEvent,
  createOwnedChannel,
  waitOperation,
  without,
  withoutAttribute,
} from "./eventarc-production/cases/support.mjs";
import { runCases } from "./eventarc-production/runner.mjs";
import { createCapture } from "./pubsub-production/capture.mjs";
import { createClient } from "./eventarc-production/client.mjs";

const RUN = "0123456789ab";

test("the project of a run is an ID of 6 to 30 characters and a channel ID is at most 63 characters", () => {
  const make = (project) => createOwnership({ project, runId: RUN });
  make("abcdef");
  make("abcde-f");
  assert.throws(() => make("abcde"), /not a project ID/);
  make(`a${"b".repeat(28)}c`);
  assert.throws(() => make(`a${"b".repeat(29)}c`), /not a project ID/);
  const own = make("demo-project");
  const longest = "k".repeat(63 - own.prefix.length);
  assert.equal(own.channel("us-central1", longest).split("/").at(-1).length, 63);
  assert.throws(() => own.channel("us-central1", `${longest}k`), /not a usable channel ID/);
});

test("the event helpers: a unique id with the run's prefix, members removed, attributes removed", () => {
  const ctx = { ownership: { prefix: "fe0123456789ab-", runId: RUN } };
  const first = cloudEvent(ctx);
  const second = cloudEvent(ctx);
  assert.notEqual(first.id, second.id);
  assert.match(first.id, /^fe0123456789ab-evt-\d+$/);
  assert.equal(Number(second.id.split("-").at(-1)) - Number(first.id.split("-").at(-1)), 1);
  assert.equal(first["@type"], CE_TYPE);
  assert.deepEqual(Object.keys(without(first, "id", "type")).includes("id"), false);
  assert.equal(without(first, "id").type, first.type);
  const trimmed = withoutAttribute(first, "time");
  assert.deepEqual(Object.keys(trimmed.attributes), ["datacontenttype"]);
  assert.deepEqual(Object.keys(first.attributes).toSorted(), ["datacontenttype", "time"]);
  assert.deepEqual(baseAttributes("text/plain", "2026-10-05T00:00:00Z"), {
    time: { ceTimestamp: "2026-10-05T00:00:00Z" },
    datacontenttype: { ceString: "text/plain" },
  });
  assert.equal(
    cloudEvent(ctx, { textData: "x", attributes: baseAttributes("text/plain") }).attributes
      .datacontenttype.ceString,
    "text/plain",
  );
});

function fakeCtx(replies) {
  const sleeps = [];
  const reads = [];
  const settled = [];
  return {
    sleeps,
    reads,
    settled,
    ctx: {
      project: "demo-project",
      location: "us-central1",
      channel: (key) => `projects/demo-project/locations/us-central1/channels/fe-${key}`,
      sleep: async (ms) => sleeps.push(ms),
      client: {
        getOperation: async (host, name) => (
          reads.push([host, name]),
          replies.shift() ?? { ok: true, body: { name, done: false } }
        ),
        createChannel: async () => replies.created,
        settleOperation: (name, action, operation, operationName) =>
          settled.push([name, action, operation, operationName]),
      },
    },
  };
}

test("waiting for an operation: no wait for what is done or refused, one read each two seconds, at most 10 reads, and the outcome settles the ledger", async () => {
  const done = fakeCtx([]);
  const ready = { ok: true, body: { name: "operations/o", done: true } };
  assert.equal(await waitOperation(done.ctx, "eventarc", ready), ready);
  const refused = { ok: false, body: { name: "operations/o" } };
  assert.equal(await waitOperation(done.ctx, "eventarc", refused), refused);
  const unnamed = { ok: true, body: {} };
  assert.equal(await waitOperation(done.ctx, "eventarc", unnamed), unnamed);
  assert.equal(await waitOperation(done.ctx, "eventarc", undefined), undefined);
  assert.deepEqual(done.reads, []);
  const pending = { ok: true, body: { name: "operations/o", done: false } };
  const never = fakeCtx([]);
  await waitOperation(never.ctx, "usage", pending);
  assert.equal(never.reads.length, 10);
  assert.deepEqual(never.sleeps, Array(9).fill(2000));
  assert.deepEqual(never.reads[0], ["usage", "operations/o"]);
  const few = fakeCtx([
    { ok: true, body: { name: "operations/o", done: false } },
    { ok: true, body: { name: "operations/o", done: true } },
  ]);
  const last = await waitOperation(few.ctx, "eventarc", pending, { attempts: 5 });
  assert.equal(few.reads.length, 2);
  assert.equal(last.body.done, true);
  const failed = fakeCtx([{ ok: false, code: "UNAVAILABLE", body: {} }]);
  assert.equal((await waitOperation(failed.ctx, "eventarc", pending)).ok, false);
  assert.equal(failed.reads.length, 1);
  const limited = fakeCtx([]);
  await waitOperation(limited.ctx, "eventarc", pending, { attempts: 3 });
  assert.equal(limited.reads.length, 3);
  // With `settle`, the last read is written into the ledger, but only for a request that was accepted.
  const settling = fakeCtx([{ ok: true, body: { name: "operations/o", done: true } }]);
  const finished = await waitOperation(settling.ctx, "eventarc", pending, {
    settle: { name: "c", action: "create" },
  });
  assert.deepEqual(
    settling.settled,
    [["c", "create", finished, "operations/o"]],
    "the settlement names the operation the creation was answered with",
  );
  const immediate = fakeCtx([]);
  await waitOperation(immediate.ctx, "eventarc", ready, {
    settle: { name: "c", action: "delete" },
  });
  assert.deepEqual(immediate.settled, [["c", "delete", ready, "operations/o"]]);
  await waitOperation(immediate.ctx, "eventarc", refused, {
    settle: { name: "c", action: "create" },
  });
  assert.equal(immediate.settled.length, 1, "a refused request has nothing to settle");
});

test("an owned channel is proven only when the creation's operation is done without an error, and the outcome is written into the ledger", async () => {
  const outcome = async (created, settledReply) => {
    const { ctx, settled } = fakeCtx([settledReply]);
    ctx.client.createChannel = async () => created;
    const name = await createOwnedChannel(ctx, "k");
    return { name, settled };
  };
  const op = (extra = {}) => ({ ok: true, body: { name: "operations/o", done: true, ...extra } });
  const wanted = "projects/demo-project/locations/us-central1/channels/fe-k";
  assert.equal((await outcome(op(), op())).name, wanted);
  assert.equal((await outcome({ ok: false, body: {} }, op())).name, null);
  assert.equal((await outcome(op({ done: false }), { ok: false, body: {} })).name, null);
  assert.equal((await outcome(op({ done: false }), op({ error: { code: 3 } }))).name, null);
  assert.equal((await outcome(op({ error: { code: 3 } }), op())).name, null);
  // A creation that is still pending when the reads stop is not proven either.
  assert.equal(
    (await outcome(op({ done: false }), { ok: true, body: { name: "operations/o", done: false } }))
      .name,
    null,
  );
  const { settled } = await outcome(op({ done: false }), op());
  assert.equal(settled.length, 1);
  assert.deepEqual(settled[0].slice(0, 2), [wanted, "create"]);
});

test("a case's notes carry its id, a probe is listed by default, and the outcomes carry their reasons", async () => {
  const ownership = createOwnership({ project: "demo-project", runId: RUN });
  const notes = [];
  const capture = createCapture({ journal: { write: (entry) => notes.push(entry) } });
  const transport = {
    name: "rest",
    request: async () => ({ status: 200, body: {}, unknown: false }),
  };
  const cases = [
    {
      id: "a",
      short: "a1",
      requests: 1,
      async run(ctx) {
        ctx.probe("some-probe");
        await ctx.client.getChannel(ctx.channel("k"));
      },
    },
    {
      id: "b",
      short: "b1",
      requests: 1,
      async run() {
        throw new CaseLimit(1);
      },
    },
  ];
  const summary = await runCases({
    cases,
    transports: { eventarc: transport, publishing: transport, usage: transport },
    cleanupClient: createClient({
      transports: {
        eventarc: {
          name: "rest",
          request: async (call) =>
            call.path.includes("/channels?")
              ? { status: 200, body: {}, unknown: false }
              : { status: 404, body: { error: { status: "NOT_FOUND" } }, unknown: false },
        },
      },
      ownership,
      caseId: "cleanup",
      usageProject: "p",
    }),
    ownership,
    capture,
    options: {
      production: false,
      location: "us-central1",
      usageProject: "p",
      publishPrefix: "/v1",
    },
    sleep: async () => {},
  });
  assert.deepEqual(ownership.locations(), ["us-central1"], "the probe's location is listed");
  assert.deepEqual(
    notes.filter((n) => n.note).map((n) => [n.note, n.case]),
    [
      ["case-start", "a"],
      ["case-end", "a"],
      ["case-start", "b"],
      ["case-end", "b"],
    ],
  );
  assert.deepEqual(
    summary.cases.map((c) => [c.outcome, c.reason ?? null]),
    [
      ["completed", null],
      ["limit", "the case reached its limit of 1 requests"],
    ],
  );
  const reasons = [[new (class extends Error {})("plain"), "error"]];
  assert.equal(reasons.length, 1);
});

test("the options: one digit is a project number, a location has 2 to 41 characters, and a program run exits with the usage code", () => {
  const base = ["--target", "production", "--project", "sandbox-project", "--out", "o"];
  assert.equal(parseArgs([...base, "--project-number", "1"]).usageProject, "1");
  assert.throws(() => parseArgs([...base, "--project-number", ""]), /needs a value|digits/);
  assert.equal(parseArgs([...base, "--location", "ab"]).location, "ab");
  assert.throws(() => parseArgs([...base, "--location", "a"]), /not a location/);
  assert.equal(parseArgs([...base, "--location", `a${"b".repeat(40)}`]).location.length, 41);
  assert.throws(() => parseArgs([...base, "--location", `a${"b".repeat(41)}`]), /not a location/);
  const result = spawnSync(
    process.execPath,
    [
      fileURLToPath(new URL("./eventarc-production/record.mjs", import.meta.url)),
      "--target",
      "nope",
      "--out",
      "x",
    ],
    { encoding: "utf8" },
  );
  assert.equal(result.status, 2);
  assert.match(result.stderr, /--target must be emulator or production/);
});

async function emptyServer({ onFirstRequest } = {}) {
  let first = true;
  const server = createServer((request, response) => {
    if (first) {
      first = false;
      onFirstRequest?.();
    }
    response.setHeader("content-type", "application/json");
    if (request.method === "GET" && /\/channels\?/.test(request.url)) return response.end("{}");
    response.statusCode = 404;
    response.end('{"error":{"status":"NOT_FOUND"}}');
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { host: `http://127.0.0.1:${server.address().port}`, close: () => server.close() };
}

test("main: a signal during a case run stops it between cases, after which the cleanup still runs, and the run's notes are written", async (t) => {
  const service = await emptyServer({
    onFirstRequest: () => (process.emit("SIGTERM"), process.emit("SIGINT")),
  });
  t.after(service.close);
  const out = join(mkdtempSync(join(tmpdir(), "eventarc-main-")), "o");
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
      "service-state,auth-errors",
      "--run-id",
      RUN,
    ],
    {},
    io,
  );
  const summary = JSON.parse(readFileSync(join(out, `summary-${RUN}.json`), "utf8"));
  assert.equal(summary.stopped, "signal");
  assert.deepEqual(
    summary.cases.map((c) => c.id),
    ["service-state"],
  );
  const lines = readFileSync(join(out, `capture-${RUN}.jsonl`), "utf8")
    .trim()
    .split("\n")
    .map((l) => JSON.parse(l));
  assert.deepEqual(
    [lines[0].note, lines[0].cleanupOnly, lines.at(-1).note, lines.at(-1).stopped],
    ["run-start", false, "run-end", "signal"],
  );
});
