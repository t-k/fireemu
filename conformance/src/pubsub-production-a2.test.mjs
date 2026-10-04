import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createClient, newPushState } from "./pubsub-production/client.mjs";
import {
  createLedger,
  kindOf,
  maybeCreated,
  maybeDeleting,
  readLedger,
} from "./pubsub-production/ledger.mjs";
import { createOwnership } from "./pubsub-production/names.mjs";
import { MIN_A2_WAIT_MS, main } from "./pubsub-production/record.mjs";
import { runCases } from "./pubsub-production/runner.mjs";
import { createCapture } from "./pubsub-production/capture.mjs";
import { names } from "./pubsub-production/cases/lifecycle.mjs";

const RUN = "0123456789ab";
const PROJECT = "demo-fireemu-pubsub";
const T0 = Date.parse("2026-10-05T10:00:00.000Z");
const topic = (id) => `projects/${PROJECT}/topics/${id}`;
const mine = (key) => topic(`fe${RUN}-${key}`);

test("the kind of an answer, the ledger lines written before and after a request, and a request that was never answered", () => {
  assert.equal(kindOf({ ok: true }), "ok");
  assert.equal(kindOf({ ok: false, code: "ALREADY_EXISTS" }), "conflict");
  assert.equal(kindOf({ ok: false, code: "INVALID_ARGUMENT" }), "error");
  assert.equal(kindOf({ ok: false, code: "UNKNOWN", unknown: true }), "unknown");
  assert.equal(kindOf({ ok: true, unknown: true }), "unknown");
  const lines = [];
  const ledger = createLedger({
    journal: { write: (line) => lines.push(line) },
    now: () => new Date(T0),
  });
  ledger.sent({ name: "a", action: "create", transport: "rest" });
  assert.deepEqual(
    lines.map((l) => l.phase),
    ["sent"],
  );
  assert.deepEqual([...ledger.state().get("a").open], ["create"]);
  assert.equal(maybeCreated(ledger.state().get("a")), true, "sent and not answered may exist");
  ledger.answered({ name: "a", action: "create", transport: "rest", kind: "conflict" });
  assert.deepEqual(ledger.state().get("a"), { creates: ["conflict"], deletes: [], open: [] });
  assert.equal(maybeCreated(ledger.state().get("a")), false);
  assert.equal(maybeDeleting(ledger.state().get("a")), false);
  assert.deepEqual(lines[1], {
    at: "2026-10-05T10:00:00.000Z",
    phase: "answered",
    name: "a",
    action: "create",
    transport: "rest",
    kind: "conflict",
  });
  ledger.sent({ name: "a", action: "delete", transport: "rest" });
  assert.equal(maybeDeleting(ledger.state().get("a")), true);
  const other = [];
  const shared = ledger.withJournal({ write: (line) => other.push(line) });
  shared.sent({ name: "b", action: "create", transport: "grpc" });
  assert.equal(ledger.state().has("b"), true, "the view is shared");
  assert.deepEqual([lines.length, other.length], [3, 1], "new lines go to the other journal only");
});

test("a ledger file is read back with a request that was sent and never answered counted as unknown", () => {
  const dir = mkdtempSync(join(tmpdir(), "pubsub-ledger-"));
  const path = join(dir, "issued.jsonl");
  const row = (phase, name, action, kind) =>
    JSON.stringify({ at: "x", phase, name, action, transport: "rest", ...(kind ? { kind } : {}) });
  writeFileSync(
    path,
    [
      row("sent", "a", "create"),
      row("answered", "a", "create", "ok"),
      row("sent", "b", "create"),
      row("sent", "c", "delete"),
      "",
      row("sent", "d", "create"),
      row("answered", "d", "create", "error"),
    ].join("\n"),
  );
  const state = readLedger(path).state();
  assert.deepEqual(state.get("a"), { creates: ["ok"], deletes: [], open: [] });
  assert.deepEqual(state.get("b"), { creates: ["unknown"], deletes: [], open: [] });
  assert.deepEqual(state.get("c"), { creates: [], deletes: ["unknown"], open: [] });
  assert.equal(maybeCreated(state.get("d")), false);
  assert.equal(maybeCreated(state.get("b")), true);
  assert.equal(maybeDeleting(state.get("c")), true);
});

function fakeRest(reply) {
  const calls = [];
  return { name: "rest", calls, request: async (call) => (calls.push(call), reply(call)) };
}

test("the client writes the ledger line before the request is sent and the kind after it, for creations and deletions only", async () => {
  const own = createOwnership({ project: "demo-project", runId: RUN });
  const name = own.resource("topics", "t");
  const seen = [];
  const ledger = createLedger({ journal: { write: (line) => seen.push(line.phase) } });
  const transport = fakeRest(() => {
    seen.push("transport");
    return { status: 409, body: { error: { status: "ALREADY_EXISTS" } }, unknown: false };
  });
  const client = createClient({
    transport,
    ownership: own,
    pushState: newPushState(),
    caseId: "c",
    ledger,
  });
  await client.createTopic(name);
  await client.getTopic(name);
  assert.deepEqual(
    seen,
    ["sent", "transport", "answered", "transport"],
    "a read is not in the ledger",
  );
  assert.deepEqual(ledger.state().get(name).creates, ["conflict"]);
  const kinds = [];
  for (const [reply, expected] of [
    [{ status: 200, body: {}, unknown: false }, "ok"],
    [{ status: 400, body: { error: { status: "INVALID_ARGUMENT" } }, unknown: false }, "error"],
    [{ status: 503, body: {}, unknown: true }, "unknown"],
    [{ status: 200, body: { raw: "<html>" }, unknown: true }, "unknown"],
  ]) {
    const fresh = createLedger();
    const c = createClient({
      transport: fakeRest(() => reply),
      ownership: own,
      pushState: newPushState(),
      caseId: "c",
      ledger: fresh,
    });
    await c.deleteTopic(name);
    kinds.push([fresh.state().get(name).deletes[0], expected]);
  }
  for (const [got, expected] of kinds) assert.equal(got, expected);
  // A 2xx whose body is unreadable is not ok.
  const unreadable = createClient({
    transport: fakeRest(() => ({ status: 200, body: { raw: "<html>" }, unknown: true })),
    ownership: own,
    pushState: newPushState(),
    caseId: "c",
  });
  assert.equal((await unreadable.getTopic(name)).ok, false);
});

test("the probe IDs of the names case come from the run, differ between runs and transports, and a 3-character one that exists is not created", async () => {
  const idsOf = async (runId, existing = new Set()) => {
    const own = createOwnership({ project: "demo-project", runId });
    const ledger = createLedger();
    const sent = [];
    const answer = (call) => {
      sent.push(`${call.method} ${call.path}`);
      const id = (call.path ?? "").split("/").at(-1);
      if (call.method === "PUT") return { status: 200, body: {}, unknown: false };
      if (call.method === "GET" && existing.has(id))
        return { status: 200, body: {}, unknown: false };
      return { status: 404, body: { error: { status: "NOT_FOUND" } }, unknown: false };
    };
    const rest = { name: "rest", request: async (call) => answer(call) };
    const grpc = {
      name: "grpc",
      call: async (call) => {
        sent.push(`${call.method} ${JSON.stringify(call.request)}`);
        return {
          code: call.method === "CreateTopic" ? "OK" : "NOT_FOUND",
          body: {},
          unknown: false,
        };
      },
    };
    const capture = createCapture({ journal: { write() {} } });
    const summary = await runCases({
      cases: [names],
      transports: { rest, grpc },
      cleanupRest: createClient({
        transport: {
          name: "rest",
          request: async () => ({ status: 200, body: {}, unknown: false }),
        },
        ownership: own,
        pushState: newPushState(),
        caseId: "cleanup",
        ledger,
      }),
      ownership: own,
      pushState: newPushState(),
      capture,
      options: { production: false },
      sleep: async () => {},
      ledger,
    });
    return {
      probes: own.probes().filter((name) => /\/(x|y)[0-9a-f]{2}$/.test(name)),
      summary,
      sent,
    };
  };
  const first = await idsOf(RUN);
  const second = await idsOf("fedcba987654");
  assert.deepEqual(first.probes, [
    topic("x01").replace(PROJECT, "demo-project"),
    topic("y23").replace(PROJECT, "demo-project"),
  ]);
  assert.deepEqual(second.probes, [
    `projects/demo-project/topics/xfe`,
    `projects/demo-project/topics/ydc`,
  ]);
  // The first run's REST probe exists already: it is read, not created, and stays out of the ledger as a creation.
  const existing = await idsOf(RUN, new Set(["x01"]));
  assert.equal(
    existing.sent.some((line) => line.startsWith("PUT") && line.endsWith("/topics/x01")),
    false,
  );
  assert.equal(
    first.sent.some((line) => line.startsWith("PUT") && line.endsWith("/topics/x01")),
    true,
  );
});

/** An emulator that lists nothing (a lagging list) but answers a read of a name and deletes one. */
async function service({ live = [], stuck = [] }) {
  const present = new Set(live);
  const seen = [];
  const server = createServer((request, response) => {
    const path = decodeURIComponent(request.url.split("?")[0].replace(/^\/v1\//, ""));
    seen.push(`${request.method} ${path}`);
    response.setHeader("content-type", "application/json");
    if (
      request.method === "GET" &&
      /^projects\/[^/]+\/(topics|subscriptions|snapshots)$/.test(path)
    )
      return response.end("{}");
    if (request.method === "GET" && present.has(path))
      return response.end(JSON.stringify({ name: path }));
    if (request.method === "DELETE" && present.has(path)) {
      if (!stuck.includes(path)) present.delete(path);
      return response.end("{}");
    }
    response.statusCode = 404;
    response.end('{"error":{"status":"NOT_FOUND"}}');
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    seen,
    names: present,
    host: `127.0.0.1:${server.address().port}`,
    close: () => server.close(),
  };
}

/** The recording's output directory: a capture whose last line is at T0 and a ledger of the given rows. */
function recording(rows) {
  const dir = mkdtempSync(join(tmpdir(), "pubsub-a2-"));
  writeFileSync(
    join(dir, `capture-${RUN}.jsonl`),
    `${JSON.stringify({ at: new Date(T0 - 1000).toISOString(), note: "run-start" })}\n${JSON.stringify({ at: new Date(T0).toISOString(), note: "run-end" })}\n`,
  );
  const lines = rows.flatMap(([name, action, kind]) => [
    { at: "x", phase: "sent", name, action, transport: "rest" },
    ...(kind ? [{ at: "x", phase: "answered", name, action, transport: "rest", kind }] : []),
  ]);
  writeFileSync(
    join(dir, `issued-${RUN}.jsonl`),
    lines.map((l) => JSON.stringify(l)).join("\n") + "\n",
  );
  return dir;
}
const io = (errors = []) => ({
  stdout: { write: () => true },
  stderr: { write: (text) => errors.push(text) },
});
const a2 = (dir, host, out = dir) => [
  "--target",
  "emulator",
  "--emulator-host",
  host,
  "--project",
  PROJECT,
  "--out",
  out,
  "--cleanup-only",
  "--run-id",
  RUN,
  "--from-capture",
  join(dir, `capture-${RUN}.jsonl`),
];
const summaryOf = (dir) => {
  const file = readdirSync(dir).find((name) => /^summary-.*-a2-.*\.json$/.test(name));
  return JSON.parse(readFileSync(join(dir, file), "utf8"));
};

test("the later run refuses to start before ten minutes, and without the ledger of the recording", async (t) => {
  const svc = await service({});
  t.after(svc.close);
  const dir = recording([]);
  const errors = [];
  assert.equal(
    await main(a2(dir, svc.host), {}, io(errors), { now: () => T0 + MIN_A2_WAIT_MS - 1000 }),
    2,
  );
  assert.match(errors.join(""), /at least 10 minutes after the recording \(599 s so far\)/);
  assert.deepEqual(
    readdirSync(dir).toSorted(),
    [`capture-${RUN}.jsonl`, `issued-${RUN}.jsonl`],
    "nothing was written",
  );
  assert.equal(svc.seen.length, 0);
  const empty = mkdtempSync(join(tmpdir(), "pubsub-a2-"));
  writeFileSync(join(empty, `capture-${RUN}.jsonl`), "");
  const missing = [];
  assert.equal(
    await main(a2(empty, svc.host), {}, io(missing), { now: () => T0 + MIN_A2_WAIT_MS }),
    2,
  );
  assert.match(missing.join(""), /ENOENT|no such file/);
  assert.equal(MIN_A2_WAIT_MS, 600_000);
});

test("the later run works in the recording's own directory and settles by name: an unknown create that is absent, one that exists, an unknown delete, and a refused probe", async (t) => {
  const absent = mine("unknown-absent");
  const present = mine("unknown-present");
  const created = mine("created");
  const deleting = mine("deleting");
  const probeOk = topic("x01");
  const probeConflict = topic("x02");
  const svc = await service({ live: [present, created, probeOk, probeConflict] });
  t.after(svc.close);
  const dir = recording([
    [absent, "create", "unknown"],
    [present, "create", "unknown"],
    [created, "create", "ok"],
    [deleting, "create", "ok"],
    [deleting, "delete", "unknown"],
    [probeOk, "create", "ok"],
    [probeConflict, "create", "conflict"],
  ]);
  const before = readFileSync(join(dir, `capture-${RUN}.jsonl`), "utf8");
  const code = await main(a2(dir, svc.host), {}, io(), { now: () => T0 + MIN_A2_WAIT_MS });
  assert.equal(code, 0);
  const summary = summaryOf(dir);
  assert.deepEqual(
    [
      summary.closureReady,
      summary.cleanup.unsettled,
      summary.cleanup.leftover,
      summary.cleanup.errors,
    ],
    [true, [], [], []],
  );
  assert.deepEqual(summary.cleanup.deleted.toSorted(), [created, present, probeOk].toSorted());
  assert.deepEqual(summary.cleanup.alreadyGone.toSorted(), [absent, deleting].toSorted());
  assert.equal(
    readFileSync(join(dir, `capture-${RUN}.jsonl`), "utf8"),
    before,
    "the recording's capture is untouched",
  );
  assert.ok(readdirSync(dir).some((name) => /^capture-.*-a2-\d{8}T\d{6}Z\.jsonl$/.test(name)));
  assert.ok(readdirSync(dir).some((name) => /^issued-.*-a2-\d{8}T\d{6}Z\.jsonl$/.test(name)));
  assert.equal(svc.names.has(probeConflict), true, "a probe that answered 409 was never ours");
  assert.equal(
    svc.seen.some((line) => line.endsWith("/x02")),
    false,
  );
  assert.deepEqual(
    svc.seen.filter((line) => line.startsWith("DELETE")).toSorted(),
    [`DELETE ${created}`, `DELETE ${present}`, `DELETE ${probeOk}`].toSorted(),
  );
});

test("the later run is not closable while a name stays, and reports it", async (t) => {
  const stuck = mine("stuck");
  const svc = await service({ live: [stuck], stuck: [stuck] });
  t.after(svc.close);
  const dir = recording([[stuck, "create", "ok"]]);
  const out = join(mkdtempSync(join(tmpdir(), "pubsub-a2-out-")), "a2");
  mkdirSync(out, { recursive: true });
  const code = await main(a2(dir, svc.host, out), {}, io(), { now: () => T0 + MIN_A2_WAIT_MS });
  assert.equal(code, 1);
  const summary = summaryOf(out);
  assert.deepEqual(
    [summary.closureReady, summary.cleanup.leftover, summary.cleanup.unsettled],
    [false, [stuck], [stuck]],
  );
});
