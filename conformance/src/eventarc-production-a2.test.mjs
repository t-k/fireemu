import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import test from "node:test";
import { createClient } from "./eventarc-production/client.mjs";
import { createLedger } from "./pubsub-production/ledger.mjs";
import { createOwnership } from "./eventarc-production/names.mjs";
import { MIN_A2_WAIT_MS, main } from "./eventarc-production/record.mjs";

const RUN = "0123456789ab";
const PROJECT = "demo-fireemu-eventarc";
const T0 = Date.parse("2026-10-05T10:00:00.000Z");
const channel = (id, location = "us-central1") =>
  `projects/${PROJECT}/locations/${location}/channels/${id}`;
const mine = (key) => channel(`fe${RUN}-${key}`);

test("the client writes the ledger line before a channel creation or deletion is sent and the kind after it, and a read is not in the ledger", async () => {
  const own = createOwnership({ project: "demo-project", runId: RUN });
  const name = own.channel("us-central1", "t");
  const seen = [];
  const ledger = createLedger({ journal: { write: (line) => seen.push(line.phase) } });
  const transport = {
    name: "rest",
    request: async () => (
      seen.push("transport"),
      { status: 409, body: { error: { status: "ALREADY_EXISTS" } }, unknown: false }
    ),
  };
  const client = createClient({
    transports: { eventarc: transport },
    ownership: own,
    caseId: "c",
    usageProject: "p",
    ledger,
  });
  await client.createChannel("demo-project", "us-central1", name.split("/").at(-1), {});
  await client.getChannel(name);
  assert.deepEqual(seen, ["sent", "transport", "answered", "transport"]);
  assert.deepEqual(ledger.state().get(name).creates, ["conflict"]);
  for (const [reply, expected] of [
    [{ status: 200, body: { name: "operations/o", done: true }, unknown: false }, "ok"],
    [
      { status: 200, body: { name: "operations/o", done: false }, unknown: false },
      "unknown@operations/o",
    ],
    [
      {
        status: 200,
        body: { name: "operations/o", done: true, error: { code: 6 } },
        unknown: false,
      },
      "unknown@operations/o",
    ],
    [{ status: 200, body: {}, unknown: false }, "unknown"],
    [{ status: 400, body: { error: { status: "INVALID_ARGUMENT" } }, unknown: false }, "error"],
    [{ status: 503, body: {}, unknown: true }, "unknown"],
    [{ status: 200, body: { raw: "<html>" }, unknown: true }, "unknown"],
  ]) {
    const fresh = createLedger();
    const c = createClient({
      transports: { eventarc: { name: "rest", request: async () => reply } },
      ownership: own,
      caseId: "c",
      usageProject: "p",
      ledger: fresh,
    });
    const answer = await c.deleteChannel(name);
    assert.equal(fresh.state().get(name).deletes[0], expected);
    assert.equal(answer.ok, reply.status === 200 && !reply.unknown, "an unreadable 2xx is not ok");
  }
});

/** An Eventarc that lists nothing (a late list) but answers a read of a channel and deletes one. */
async function service({ live = [], stuck = [] }) {
  const present = new Set(live);
  const seen = [];
  const server = createServer((request, response) => {
    const path = decodeURIComponent(request.url.split("?")[0].replace(/^\/v1\//, ""));
    seen.push(`${request.method} ${path}`);
    response.setHeader("content-type", "application/json");
    if (request.method === "GET" && path.endsWith("/channels")) return response.end("{}");
    if (request.method === "GET" && path.includes("/operations/"))
      return response.end(JSON.stringify({ name: path, done: true }));
    if (request.method === "GET" && present.has(path))
      return response.end(JSON.stringify({ name: path }));
    if (request.method === "DELETE" && present.has(path)) {
      if (!stuck.includes(path)) present.delete(path);
      return response.end(
        JSON.stringify({
          name: `projects/${PROJECT}/locations/us-central1/operations/op-1`,
          done: false,
        }),
      );
    }
    response.statusCode = 404;
    response.end('{"error":{"status":"NOT_FOUND"}}');
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    seen,
    present,
    host: `http://127.0.0.1:${server.address().port}`,
    close: () => server.close(),
  };
}

function recording(rows) {
  const dir = mkdtempSync(join(tmpdir(), "eventarc-a2-"));
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
const io = (errors = [], out = []) => ({
  stdout: { write: (text) => (out.push(text), true) },
  stderr: { write: (text) => errors.push(text) },
});
const deps = (extra = {}) => ({ now: () => T0 + MIN_A2_WAIT_MS, sleep: async () => {}, ...extra });
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
const summaryOf = (dir) =>
  JSON.parse(
    readFileSync(
      join(
        dir,
        readdirSync(dir).find((name) => /^summary-.*-a2-.*\.json$/.test(name)),
      ),
      "utf8",
    ),
  );

test("the later run refuses to start before ten minutes, and without the ledger of the recording", async (t) => {
  const svc = await service({});
  t.after(svc.close);
  const dir = recording([]);
  const errors = [];
  assert.equal(
    await main(a2(dir, svc.host), {}, io(errors), deps({ now: () => T0 + MIN_A2_WAIT_MS - 1000 })),
    2,
  );
  assert.match(
    errors.join(""),
    /at least 10 minutes after the recording and the earlier later runs \(599 s so far\)/,
  );
  assert.deepEqual(readdirSync(dir).toSorted(), [`capture-${RUN}.jsonl`, `issued-${RUN}.jsonl`]);
  assert.equal(svc.seen.length, 0);
  const empty = mkdtempSync(join(tmpdir(), "eventarc-a2-"));
  writeFileSync(join(empty, `capture-${RUN}.jsonl`), "");
  const missing = [];
  assert.equal(await main(a2(empty, svc.host), {}, io(missing), deps()), 2);
  assert.match(missing.join(""), /ENOENT|no such file/);
  assert.equal(MIN_A2_WAIT_MS, 600_000);
});

test("the later run works in the recording's own directory and settles by name: an unknown create that is absent, one that exists, an unknown delete, and a probe that was a conflict", async (t) => {
  const absent = mine("unknown-absent");
  const absentOperation = `projects/${PROJECT}/locations/us-central1/operations/op-absent`;
  const present = mine("unknown-present");
  const created = mine("created");
  const deleting = mine("deleting");
  const probeOk = channel("probe-ok");
  const probeConflict = channel("probe-taken");
  const svc = await service({ live: [present, created, probeOk, probeConflict] });
  t.after(svc.close);
  const dir = recording([
    [absent, "create", `unknown@${absentOperation}`],
    [present, "create", "unknown"],
    [created, "create", "ok"],
    [deleting, "create", "ok"],
    [deleting, "delete", "unknown"],
    [probeOk, "create", "ok"],
    [probeConflict, "create", "conflict"],
  ]);
  const before = readFileSync(join(dir, `capture-${RUN}.jsonl`), "utf8");
  assert.equal(await main(a2(dir, svc.host), {}, io(), deps()), 0);
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
  const a2Capture = readdirSync(dir).find((name) =>
    /^capture-.*-a2-\d{8}T\d{6}Z\.jsonl$/.test(name),
  );
  const lines = readFileSync(join(dir, a2Capture), "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  assert.equal(lines[0].note, "run-start");
  assert.equal(lines[0].cleanupOnly, true);
  assert.deepEqual([lines.at(-1).note, lines.at(-1).stopped], ["run-end", null]);
  assert.ok(readdirSync(dir).some((name) => /^issued-.*-a2-\d{8}T\d{6}Z\.jsonl$/.test(name)));
  assert.equal(svc.present.has(probeConflict), true, "a probe that answered 409 was never ours");
  assert.equal(
    svc.seen.some((line) => line.endsWith("/probe-taken")),
    false,
  );
  assert.deepEqual(
    svc.seen.filter((line) => line.startsWith("DELETE")).toSorted(),
    [`DELETE ${created}`, `DELETE ${present}`, `DELETE ${probeOk}`].toSorted(),
  );
});

test("the later run is not closable while a channel stays, and reports it", async (t) => {
  const stuck = mine("stuck");
  const svc = await service({ live: [stuck], stuck: [stuck] });
  t.after(svc.close);
  const dir = recording([[stuck, "create", "ok"]]);
  assert.equal(await main(a2(dir, svc.host), {}, io(), deps()), 1);
  const summary = summaryOf(dir);
  assert.deepEqual(
    [summary.closureReady, summary.cleanup.leftover, summary.cleanup.unsettled],
    [false, [stuck], [stuck]],
  );
});

test("the later run lists the location of the run, so a prefixed channel the ledger does not name is found and deleted", async (t) => {
  const unnamed = mine("listed-only");
  // This server lists the channel, which the ledger does not name.
  const present = new Set([unnamed]);
  const seen = [];
  const server = createServer((request, response) => {
    const path = decodeURIComponent(request.url.split("?")[0].replace(/^\/v1\//, ""));
    seen.push(`${request.method} ${path}`);
    response.setHeader("content-type", "application/json");
    if (request.method === "GET" && path.endsWith("/channels"))
      return response.end(JSON.stringify({ channels: [...present].map((name) => ({ name })) }));
    if (request.method === "GET" && path.includes("/operations/"))
      return response.end(JSON.stringify({ name: path, done: true }));
    if (request.method === "GET" && present.has(path))
      return response.end(JSON.stringify({ name: path }));
    if (request.method === "DELETE" && present.has(path)) {
      present.delete(path);
      return response.end(
        JSON.stringify({
          name: `projects/${PROJECT}/locations/us-central1/operations/op-1`,
          done: true,
        }),
      );
    }
    response.statusCode = 404;
    response.end('{"error":{"status":"NOT_FOUND"}}');
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  const dir = recording([]);
  const host = `http://127.0.0.1:${server.address().port}`;
  assert.equal(await main(a2(dir, host), {}, io(), deps()), 0);
  assert.deepEqual(summaryOf(dir).cleanup.deleted, [unnamed]);
  assert.equal(present.size, 0);
});

test("the later run never lists a location that cannot exist, and a probe there is settled by its own recorded 404", async () => {
  const nowhere = channel(`nowhere-${RUN}`, "no-such-location1");
  const svc = await service({});
  const dir = recording([
    [nowhere, "create", `unknown@projects/${PROJECT}/locations/no-such-location1/operations/op-n`],
  ]);
  const code = await main(a2(dir, svc.host), {}, io(), deps());
  svc.close();
  assert.equal(code, 0);
  assert.equal(
    svc.seen.some(
      (line) => line.includes("no-such-location1/channels") && !line.includes(`nowhere-${RUN}`),
    ),
    false,
    "that location was not listed",
  );
  const summary = summaryOf(dir);
  assert.deepEqual(
    [summary.closureReady, summary.cleanup.unsettled, summary.cleanup.listed],
    [true, [], ["us-central1"]],
  );
});

test("the ledgers of the earlier later runs are read too: a channel an earlier later run sent a deletion for is not deleted again", async () => {
  const name = mine("deleted-before");
  const svc = await service({ live: [name], stuck: [name] });
  const dir = recording([
    [name, "create", "ok"],
    [name, "delete", "unknown"],
  ]);
  // The first later run sent one DELETE for it.
  writeFileSync(
    join(dir, `issued-${RUN}-a2-20261005T101500Z.jsonl`),
    `${JSON.stringify({ at: "x", phase: "sent", name, action: "delete", transport: "rest" })}\n${JSON.stringify({ at: "x", phase: "answered", name, action: "delete", transport: "rest", kind: "unknown" })}\n`,
  );
  const code = await main(a2(dir, svc.host), {}, io(), deps());
  svc.close();
  assert.equal(code, 1);
  assert.equal(
    svc.seen.some((line) => line.startsWith("DELETE")),
    false,
    "no DELETE was sent",
  );
  const summary = summaryOf(dir);
  assert.deepEqual([summary.cleanup.leftover, summary.closureReady], [[name], false]);
});

test("the capture notes the quota project of a request that carried the header, and the later run lists only the run's location", async () => {
  const svc = await service({});
  const dir = recording([]);
  await main(a2(dir, svc.host), {}, io(), deps());
  svc.close();
  const a2Capture = readdirSync(dir).find((name) =>
    /^capture-.*-a2-\d{8}T\d{6}Z\.jsonl$/.test(name),
  );
  const entries = readFileSync(join(dir, a2Capture), "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line))
    .filter((entry) => entry.op);
  assert.ok(entries.length > 0);
  // Against an emulator no quota project is sent: the field is absent.
  assert.ok(entries.every((entry) => entry.quotaProject === undefined));
});

test("S3-v2: the later run reads a pending creation's operation first; absence alone does not settle an unknown creation", async (t) => {
  const taken = channel("probe-taken");
  const plain = mine("plain-unknown");
  const operation = (key) => `projects/${PROJECT}/locations/us-central1/operations/op-${key}`;
  // An operation that ends with ALREADY_EXISTS settles its creation: nothing was created.
  const svc = await service({ live: [taken] });
  const empty = await service({});
  t.after(() => (svc.close(), empty.close()));
  const dir = recording([[taken, "create", `unknown@${operation("taken")}`]]);
  const origin = svc.seen.length;
  // This service says every operation is done without an error: the creation is confirmed, and a probe
  // that is there is ours to delete.
  assert.equal(await main(a2(dir, svc.host), {}, io(), deps()), 0);
  const first = svc.seen.slice(origin)[0];
  assert.match(
    first,
    /^GET projects\/demo-fireemu-eventarc\/locations\/us-central1\/operations\/op-taken$/,
  );
  assert.equal(summaryOf(dir).closureReady, true);
  // An unknown creation with no operation to read, absent: not closable, reported as unconfirmed.
  const second = recording([[plain, "create", "unknown"]]);
  // The exit code says nothing was left or refused; the summary says it is not closable.
  const printed = [];
  assert.equal(await main(a2(second, empty.host), {}, io([], printed), deps()), 0);
  const line = JSON.parse(printed.join(""));
  assert.deepEqual(
    [line.closureReady, line.cleanup.unsettled, line.cleanup.unconfirmed],
    [false, [plain], [plain]],
    "the line the operator reads names the unconfirmed creation",
  );
  const summary = summaryOf(second);
  assert.deepEqual(
    [summary.closureReady, summary.cleanup.unsettled, summary.cleanup.unconfirmed],
    [false, [plain], [plain]],
  );
  assert.deepEqual(summary.cleanup.settled, []);
});

test("S1-v2: the later run refuses an --out that is not the recording's directory, so that it sees every earlier later run", async (t) => {
  const svc = await service({});
  t.after(svc.close);
  const dir = recording([]);
  const elsewhere = join(mkdtempSync(join(tmpdir(), "eventarc-a2-out-")), "a2-1");
  const errors = [];
  assert.equal(await main(a2(dir, svc.host, elsewhere), {}, io(errors), deps()), 2);
  assert.match(errors.join(""), /--out must be the directory of --from-capture/);
  assert.equal(svc.seen.length, 0);
  assert.equal(readdirSync(dir).length, 2, "nothing was written beside the recording");
  assert.throws(() => readdirSync(elsewhere), /ENOENT/, "and nothing was created elsewhere");
  // The same directory spelled another way is accepted.
  assert.equal(await main(a2(dir, svc.host, `${dir}/`), {}, io(), deps()), 0);
  assert.equal(
    await main(
      a2(dir, svc.host, join(dir, "..", basename(dir))),
      {},
      io(),
      deps({ now: () => T0 + 2 * MIN_A2_WAIT_MS + 1000 }),
    ),
    0,
  );
});

test("S1-v2: a second later run sees the first one's deletion and does not send it again", async (t) => {
  const name = mine("stuck-after-delete");
  const svc = await service({ live: [name], stuck: [name] });
  t.after(svc.close);
  const dir = recording([
    [name, "create", "ok"],
    [name, "delete", "unknown"],
  ]);
  assert.equal(await main(a2(dir, svc.host), {}, io(), deps()), 1);
  assert.equal(svc.seen.filter((line) => line.startsWith("DELETE")).length, 1);
  // The second later run, in the same directory, starts ten minutes after the first.
  const later = deps({ now: () => T0 + 2 * MIN_A2_WAIT_MS + 2000 });
  assert.equal(await main(a2(dir, svc.host), {}, io(), later), 1);
  assert.equal(
    svc.seen.filter((line) => line.startsWith("DELETE")).length,
    1,
    "the first later run's DELETE is not repeated",
  );
});

test("S2-v2: the ten minutes are counted from the newest capture of the run, a later run's included", async (t) => {
  const svc = await service({});
  t.after(svc.close);
  const dir = recording([]);
  const first = new Date(T0 + MIN_A2_WAIT_MS + 5000).toISOString();
  writeFileSync(
    join(dir, `capture-${RUN}-a2-20261005T101000Z.jsonl`),
    `${JSON.stringify({ at: first, note: "run-end" })}\n`,
  );
  const errors = [];
  const tooSoon = deps({ now: () => T0 + MIN_A2_WAIT_MS + 5000 + MIN_A2_WAIT_MS - 1000 });
  assert.equal(await main(a2(dir, svc.host), {}, io(errors), tooSoon), 2);
  assert.match(
    errors.join(""),
    /at least 10 minutes after the recording and the earlier later runs \(599 s so far\)/,
  );
  assert.equal(svc.seen.length, 0);
  const enough = deps({ now: () => T0 + MIN_A2_WAIT_MS + 5000 + MIN_A2_WAIT_MS });
  assert.equal(await main(a2(dir, svc.host), {}, io(), enough), 0);
  // The captures of another run in the directory do not count.
  const other = "ffffffffffff";
  writeFileSync(
    join(dir, `capture-${other}-a2-20261005T130000Z.jsonl`),
    `${JSON.stringify({ at: new Date(T0 + 99 * MIN_A2_WAIT_MS).toISOString(), note: "x" })}\n`,
  );
  const next = deps({ now: () => T0 + 3 * MIN_A2_WAIT_MS + 6000 });
  assert.equal(await main(a2(dir, svc.host), {}, io(), next), 0);
});
