import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { main, preflight } from "./run.mjs";
import { createWorld, virtualClock } from "./world.mjs";

const id = "abcdef123456";
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "nc-run-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.writeFileSync(
    path.join(root, "lock"),
    JSON.stringify({ pid: process.pid, packetId: "PUBSUB-NEGCACHE" }),
  );
  fs.writeFileSync(path.join(root, "packet"), "packet");
  return root;
}

test("preflight accepts only admitted inputs", (t) => {
  const root = fixture(t),
    args = { mode: "record", runId: id, out: "out", lock: "lock", packet: "packet" };
  assert.doesNotThrow(() => preflight({}, args, { root }));
  for (const env of [
    { GOOGLE_APPLICATION_CREDENTIALS: "x" },
    { FIREBASE_TOKEN: "x" },
    { CLOUDSDK_TEST: "x" },
  ])
    assert.throws(() => preflight(env, args, { root }));
  for (const change of [
    { runId: "ABCDEF123456" },
    { lock: "missing" },
    { packet: "missing" },
    { out: "lock" },
  ])
    assert.throws(() => preflight({}, { ...args, ...change }, { root }));
  fs.writeFileSync(path.join(root, "bad"), "{}");
  assert.throws(() => preflight({}, { ...args, lock: "bad" }, { root }));
});

test("plan and local baseline", async () => {
  let output;
  assert.equal(
    await main(["plan"], {
      print: (v) => {
        output = v;
      },
    }),
    0,
  );
  assert.equal(output.cells, 33);
  assert.equal(output.scheduledRequests, 200);
  assert.equal(
    await main(["local", "--run-id", id], {
      print: (v) => {
        output = v;
      },
    }),
    0,
  );
  assert.equal(output.closureReady, true);
  assert.equal(output.answers.ttl.verdict, "window");
  await assert.rejects(main(["plan", "--extra", "x"]));
});

test("record writes private capture and summary, including stopped recordings", async (t) => {
  const root = fixture(t);
  for (const [out, faults, expected] of [
    ["clean", new Map(), 0],
    ["stopped", new Map([[1, "timeout"]]), 2],
  ]) {
    const clock = virtualClock();
    const transport = createWorld({ clock, faults });
    let output;
    const code = await main(
      ["record", "--run-id", id, "--out", out, "--lock", "lock", "--packet", "packet"],
      {
        root,
        env: {},
        token: "fake",
        sourceHead: "test",
        clock,
        transport,
        print: (v) => {
          output = v;
        },
      },
    );
    assert.equal(code, expected);
    assert.equal(output.runId, id);
    for (const name of [`capture-${id}.jsonl`, `summary-${id}.json`])
      assert.equal(fs.statSync(path.join(root, out, name)).mode & 0o777, 0o600);
    if (expected === 2) assert.ok(output.stopped);
  }
});

test("A2 age gate and complete or partial lists", async (t) => {
  const root = fixture(t),
    from = path.join(root, "original");
  fs.mkdirSync(from);
  const name = `projects/fireemu-oracle-idp/subscriptions/fireemu-observe-${id}-nc-a1-x`;
  fs.writeFileSync(
    path.join(from, `summary-${id}.json`),
    JSON.stringify({ runId: id, open: [{ name, status: "live" }] }),
  );
  fs.writeFileSync(
    path.join(from, `capture-${id}.jsonl`),
    JSON.stringify({ event: "request", at: new Date(1000000).toISOString() }) + "\n",
  );
  const args = (out) => [
    "a2",
    "--run-id",
    id,
    "--from",
    "original",
    "--out",
    out,
    "--lock",
    "lock",
  ];
  let calls = 0,
    output;
  const deps = {
    root,
    env: {},
    token: "fake",
    now: () => 1000001,
    print: (v) => {
      output = v;
    },
    transport: {
      send: async () => {
        calls++;
        return { status: 200, bodyText: "{}" };
      },
    },
  };
  await assert.rejects(main(args("young"), deps), /ten minutes/);
  assert.equal(calls, 0);
  deps.now = () => 1600000;
  assert.equal(await main(args("settled"), deps), 0);
  assert.deepEqual(output.settled, [name]);
  deps.transport.send = async (request) => ({
    status: 200,
    bodyText:
      request.list === "subscription" ? JSON.stringify({ subscriptions: [{ name }] }) : "{}",
  });
  assert.equal(await main(args("present"), deps), 2);
  assert.deepEqual(output.stillPresent, [name]);
  deps.transport.send = async () => ({ status: 200, bodyText: '{"nextPageToken":"next"}' });
  assert.equal(await main(args("partial"), deps), 2);
  assert.deepEqual(output.unreadable, [name]);
});

test("preflight refuses each input with its own reason", (t) => {
  const root = fixture(t);
  const args = { mode: "record", runId: id, out: "out", lock: "lock", packet: "packet" };
  const refuses = (env, change, pattern, deps = {}) =>
    assert.throws(() => preflight(env, { ...args, ...change }, { root, ...deps }), pattern);
  refuses({ GOOGLE_APPLICATION_CREDENTIALS: "x" }, {}, /credential environment/);
  refuses({ CLOUDSDK_CORE_PROJECT: "x" }, {}, /credential environment/);
  assert.doesNotThrow(() =>
    preflight(
      { GOOGLE_APPLICATION_CREDENTIALS: undefined, CLOUDSDK_X: undefined, OTHER: "1" },
      args,
      { root },
    ),
  );
  refuses({}, { runId: "abcdef12345" }, /12 lowercase hex/);
  refuses({}, { runId: "abcdef1234567" }, /12 lowercase hex/);
  refuses({}, { runId: undefined }, /12 lowercase hex/);
  refuses({}, { out: undefined }, /output directory must be new/);
  refuses({}, { out: "lock" }, /output directory must be new/);
  refuses({}, { lock: "missing" }, /lock file must exist/);
  refuses({}, {}, /lock ownership/, { pid: process.pid + 1 });
  fs.writeFileSync(
    path.join(root, "other"),
    JSON.stringify({ pid: process.pid, packetId: "SOMETHING-ELSE" }),
  );
  refuses({}, { lock: "other" }, /lock ownership/);
  refuses({}, { packet: "missing" }, /packet file must exist/);
  refuses({}, { packet: "." }, /packet file must exist/);
  refuses({}, { packet: undefined }, /packet file required/);
  assert.doesNotThrow(() => preflight({}, { ...args, mode: "a2", packet: undefined }, { root }));
});

test("options: unknown modes and options, duplicates, missing values and a bad run id are refused", async () => {
  const quiet = { print() {} };
  await assert.rejects(main(["nope"], quiet), /unknown mode/);
  await assert.rejects(main(["plan", "--x", "1"], quiet), /unknown or incomplete option/);
  await assert.rejects(main(["local", "--run-id"], quiet), /unknown or incomplete option/);
  await assert.rejects(
    main(["local", "--run-id", "--world-params"], quiet),
    /unknown or incomplete option/,
  );
  await assert.rejects(main(["local", "--run-id", id, "--run-id", id], quiet), /duplicate option/);
  await assert.rejects(main(["local"], quiet), /missing --run-id/);
  await assert.rejects(main(["local", "--run-id", "ABC"], quiet), /12 lowercase hex/);
  await assert.rejects(main(["record", "--run-id", id], quiet), /missing --out/);
  await assert.rejects(
    main(["local", "--run-id", id, "--out", "x"], quiet),
    /unknown or incomplete option/,
  );
});

test("record: a signal stops the recording once, the cleanup still runs, the summary says so", async (t) => {
  const root = fixture(t);
  const clock = virtualClock(1000000);
  const world = createWorld({ clock });
  let seen = 0;
  const transport = {
    send: async (request, meta) => {
      if (++seen === 12) {
        process.emit("SIGTERM");
        process.emit("SIGTERM");
      }
      return world.send(request, meta);
    },
  };
  let output;
  const code = await main(
    ["record", "--run-id", id, "--out", "out", "--lock", "lock", "--packet", "packet"],
    {
      root,
      env: {},
      token: "fake",
      clock,
      transport,
      sourceHead: "h",
      print: (v) => {
        output = v;
      },
    },
  );
  assert.equal(code, 2);
  assert.equal(output.stopped, "signal");
  assert.ok(output.closureReady);
  const text = fs.readFileSync(path.join(root, "out", `summary-${id}.json`), "utf8");
  assert.ok(text.endsWith("}\n"));
  assert.equal(JSON.parse(text).stopped, "signal");
  assert.equal(process.listenerCount("SIGTERM") >= 0, true);
});

test("a2: list validation refuses malformed pages and stops after five pages", async (t) => {
  const root = fixture(t);
  const from = path.join(root, "original");
  fs.mkdirSync(from);
  const name = `projects/fireemu-oracle-idp/subscriptions/fireemu-observe-${id}-nc-a1-x`;
  fs.writeFileSync(
    path.join(from, `summary-${id}.json`),
    JSON.stringify({ runId: id, open: [{ name, status: "live" }] }),
  );
  fs.writeFileSync(
    path.join(from, `capture-${id}.jsonl`),
    JSON.stringify({ event: "request", at: new Date(1000000).toISOString() }) + "\n",
  );
  let n = 0;
  const run = async (reply) => {
    let output;
    const sent = [];
    const code = await main(
      ["a2", "--run-id", id, "--from", "original", "--out", `o${++n}`, "--lock", "lock"],
      {
        root,
        env: {},
        token: "t",
        now: () => 1700000000,
        print: (v) => {
          output = v;
        },
        transport: {
          send: async (request, meta) => {
            sent.push(meta);
            return reply(request);
          },
        },
      },
    );
    return { code, output, sent };
  };
  const body = (value) => ({ status: 200, bodyText: JSON.stringify(value) });
  const bad = [
    { status: 199, bodyText: "{}" },
    { status: 300, bodyText: "{}" },
    { status: 200, bodyText: "nope" },
    body([]),
    body(null),
    body({ subscriptions: "x" }),
    body({ subscriptions: [{ name: 5 }] }),
    body({ nextPageToken: 5 }),
  ];
  for (const reply of bad) {
    const { code, output } = await run(() => reply);
    assert.equal(code, 2, JSON.stringify(reply));
    assert.deepEqual(output.unreadable, [name]);
  }
  const paged = await run(() => body({ nextPageToken: "more" }));
  assert.equal(paged.sent.length, 15, "five pages for each of three kinds");
  assert.ok(paged.sent.every((m) => m.timeoutMs === 10000 && m.connPolicy === "pool"));
  const complete = await run(() => body({}));
  assert.equal(complete.code, 0);
  assert.equal(complete.sent.length, 3);
  const written = fs.readFileSync(path.join(root, `o${n}`, `a2-${id}.json`), "utf8");
  assert.ok(written.endsWith("}\n"));
  const withForeign = await run((request) =>
    body(
      request.list === "subscription"
        ? {
            subscriptions: [
              { name },
              { name: "projects/fireemu-oracle-idp/subscriptions/not-ours" },
            ],
          }
        : {},
    ),
  );
  assert.deepEqual(withForeign.output.stillPresent, [name]);
  const file = JSON.parse(fs.readFileSync(path.join(root, `o${n}`, `a2-${id}.json`), "utf8"));
  assert.deepEqual(file.lists.subscription, { complete: true, names: [name], foreign: 1 });
});

test("local: a recording that stops exits 2, and the token is requested with a 30 s limit", async (t) => {
  let output;
  const code = await main(
    ["local", "--run-id", id, "--world-params", JSON.stringify({ faults: { 10: "timeout" } })],
    {
      print: (v) => {
        output = v;
      },
    },
  );
  assert.equal(code, 2);
  assert.equal(output.stopped, "unknown create");
  const root = fixture(t);
  const clock = virtualClock(1000000);
  const world = createWorld({ clock });
  let limit;
  await main(["record", "--run-id", id, "--out", "out", "--lock", "lock", "--packet", "packet"], {
    root,
    env: {},
    clock,
    transport: world,
    sourceHead: "h",
    print() {},
    createCredentials: () => async (arg) => {
      limit = arg.timeoutMs;
      return "fake";
    },
  });
  assert.equal(limit, 30000);
});

test("prelist: read-only, clean only when every LIST is complete and holds no observation resource", async (t) => {
  const root = fixture(t);
  let n = 0;
  const run = async (reply) => {
    let output;
    const sent = [];
    const code = await main(["prelist", "--run-id", id, "--out", `p${++n}`, "--lock", "lock"], {
      root,
      env: {},
      token: "t",
      print: (v) => {
        output = v;
      },
      transport: {
        send: async (request, meta) => {
          sent.push(request);
          return reply(request, meta);
        },
      },
    });
    return { code, output, sent };
  };
  const ok = (value) => ({ status: 200, bodyText: JSON.stringify(value) });
  const clean = await run(() => ok({}));
  assert.equal(clean.code, 0);
  assert.equal(clean.output.clean, true);
  assert.ok(
    clean.sent.every((r) => r.method === "GET" && r.list),
    "only LISTs",
  );
  assert.equal(clean.sent.length, 3);
  const foreignOnly = await run((r) =>
    ok(
      r.list === "topic"
        ? { topics: [{ name: "projects/fireemu-oracle-idp/topics/baseline" }] }
        : {},
    ),
  );
  assert.equal(foreignOnly.code, 0, "other names are counted, not a failure");
  assert.equal(foreignOnly.output.lists.topic.foreign, 1);
  const leftover = await run((r) =>
    ok(
      r.list === "subscription"
        ? {
            subscriptions: [
              {
                name: "projects/fireemu-oracle-idp/subscriptions/fireemu-observe-0123456789ab-nc-a1-x",
              },
            ],
          }
        : {},
    ),
  );
  assert.equal(leftover.code, 2);
  assert.equal(leftover.output.lists.subscription.names.length, 1);
  assert.equal((await run(() => ({ status: 500, bodyText: "{}" }))).code, 2);
  assert.equal((await run(() => ok({ nextPageToken: "more" }))).code, 2);
  const written = JSON.parse(
    fs.readFileSync(path.join(root, `p${n}`, `prelist-${id}.json`), "utf8"),
  );
  assert.equal(written.lists.snapshot.complete, false);
  await assert.rejects(
    main(["prelist", "--run-id", id, "--out", "p1", "--lock", "lock"], {
      root,
      env: {},
      token: "t",
      transport: { send: async () => ok({}) },
    }),
    /output directory must be new/,
  );
});

test("a2 exits 2 when an unconfirmed create is shown by a complete LIST, and reports it", async (t) => {
  const root = fixture(t);
  const from = path.join(root, "original");
  fs.mkdirSync(from);
  const name = `projects/fireemu-oracle-idp/subscriptions/fireemu-observe-${id}-nc-a1-x`;
  fs.writeFileSync(
    path.join(from, `summary-${id}.json`),
    JSON.stringify({ runId: id, open: [{ name, status: "unconfirmed-create" }] }),
  );
  fs.writeFileSync(
    path.join(from, `capture-${id}.jsonl`),
    JSON.stringify({ event: "request", at: new Date(1000000).toISOString() }) + "\n",
  );
  let output;
  const code = await main(
    ["a2", "--run-id", id, "--from", "original", "--out", "o", "--lock", "lock"],
    {
      root,
      env: {},
      token: "t",
      now: () => 2000000,
      print: (v) => {
        output = v;
      },
      transport: {
        send: async (r) => ({
          status: 200,
          bodyText: JSON.stringify(r.list === "subscription" ? { subscriptions: [{ name }] } : {}),
        }),
      },
    },
  );
  assert.equal(code, 2);
  assert.deepEqual(output.presentUnconfirmed, [name]);
  assert.deepEqual(output.unconfirmed, []);
});

test("S7: a token older than the limit is replaced at a cell boundary, a static token never", async (t) => {
  const root = fixture(t);
  const clock = virtualClock(1000000);
  const world = createWorld({ clock });
  const issued = [];
  const used = new Set();
  const transport = {
    send: async (request, meta) => {
      used.add(issued.length);
      return world.send(request, meta);
    },
  };
  const create = () => async () => (issued.push(clock.now()), `token-${issued.length}`);
  const code = await main(
    ["record", "--run-id", id, "--out", "out", "--lock", "lock", "--packet", "packet"],
    {
      root,
      env: {},
      clock,
      transport,
      sourceHead: "h",
      print() {},
      tokenRefreshMs: 120000,
      createCredentials: create,
    },
  );
  assert.equal(code, 0);
  assert.ok(issued.length >= 4, `refreshed ${issued.length} times`);
  assert.ok(
    issued.slice(1).every((at, i) => at - issued[i] > 120000),
    "each refresh is later than the limit after the previous token",
  );
  // A static token is never replaced.
  const root2 = fixture(t);
  let calls = 0;
  await main(["record", "--run-id", id, "--out", "out", "--lock", "lock", "--packet", "packet"], {
    root: root2,
    env: {},
    clock: virtualClock(5),
    transport: createWorld({ clock: virtualClock(5) }),
    sourceHead: "h",
    print() {},
    tokenRefreshMs: 1,
    token: "static",
    createCredentials: () => (calls++, async () => "x"),
  }).catch(() => {});
  assert.equal(calls, 0);
});

const START = 1000000;
async function recordWith(t, { tokenRefreshMs, jumpAt, jumpMs }) {
  const root = fixture(t);
  const clock = virtualClock(START);
  const world = createWorld({ clock });
  const issued = [];
  let sent = 0;
  const transport = {
    send: async (request, meta) => {
      if (++sent === jumpAt) await clock.sleep(jumpMs);
      return world.send(request, meta);
    },
  };
  const create = () => async () => (issued.push(clock.now()), "token");
  await main(["record", "--run-id", id, "--out", "out", "--lock", "lock", "--packet", "packet"], {
    root,
    env: {},
    clock,
    transport,
    sourceHead: "h",
    print() {},
    tokenRefreshMs,
    createCredentials: create,
  });
  const rows = fs
    .readFileSync(path.join(root, "out", `capture-${id}.jsonl`), "utf8")
    .trim()
    .split("\n")
    .map(JSON.parse);
  const starts = [];
  for (const row of rows)
    if (row.event === "request" && row.step === 0 && row.cell !== "setup" && row.cell !== "cleanup")
      starts.push(row.startedAt);
  return { issued, starts };
}

test("S7: the refresh is exactly 'older than the limit' at a cell boundary, and the limit is 30 minutes by default", async (t) => {
  // A limit equal to a boundary's age does not refresh there; it refreshes at the next boundary.
  const probe = await recordWith(t, { tokenRefreshMs: 1e12 });
  assert.equal(probe.issued.length, 1);
  const boundary = probe.starts[5];
  const exact = await recordWith(t, { tokenRefreshMs: boundary - START });
  assert.ok(!exact.issued.includes(boundary), "equal age does not refresh");
  assert.equal(
    exact.issued[1],
    exact.starts.find((s) => s > boundary),
  );
  // Default limit: a 29 minute jump after the first request makes the first refresh the first boundary older than 30 minutes.
  const jumped = await recordWith(t, { jumpAt: 2, jumpMs: 29 * 60 * 1000 });
  const expected = jumped.starts.find((s) => s - START > 30 * 60 * 1000);
  assert.ok(expected !== undefined);
  assert.equal(jumped.issued[1], expected);
});

test("M1: main(record) with a refresh that fails: exit 2, the summary is written, the cleanup ran, the world is empty", async (t) => {
  const root = fixture(t);
  const clock = virtualClock(1000000);
  const world = createWorld({ clock });
  let calls = 0;
  let output;
  const code = await main(
    ["record", "--run-id", id, "--out", "out", "--lock", "lock", "--packet", "packet"],
    {
      root,
      env: {},
      clock,
      transport: world,
      sourceHead: "h",
      tokenRefreshMs: 60000,
      print: (v) => {
        output = v;
      },
      createCredentials: () => async () => {
        if (++calls > 1) throw new Error("credential retrieval failed");
        return "token";
      },
    },
  );
  assert.equal(code, 2);
  assert.equal(output.stopped, "token refresh failed");
  assert.ok(output.closureReady);
  assert.ok(Object.values(world.state).every((m) => m.size === 0));
  const summary = JSON.parse(fs.readFileSync(path.join(root, "out", `summary-${id}.json`), "utf8"));
  assert.equal(summary.stopped, "token refresh failed");
});

test("a2 of a run whose summary is missing says where to rebuild it from", async (t) => {
  const root = fixture(t);
  fs.mkdirSync(path.join(root, "original"));
  await assert.rejects(
    main(["a2", "--run-id", id, "--from", "original", "--out", "o", "--lock", "lock"], {
      root,
      env: {},
      token: "t",
      transport: { send: async () => ({}) },
    }),
    new RegExp(`summary-${id}.json is missing.*capture-${id}.jsonl`),
  );
});

test("program selection defaults to v4, selects v5 for plan/local, and refuses unsupported programs", async () => {
  for (const [args, cells, requests] of [
    [[], 33, 200],
    [["--program", "v4"], 33, 200],
    [["--program", "v5"], 44, 177],
  ]) {
    let output;
    assert.equal(
      await main(["plan", ...args], {
        print: (v) => {
          output = v;
        },
      }),
      0,
    );
    assert.equal(output.cells, cells);
    assert.equal(output.scheduledRequests, requests);
  }
  let output;
  assert.equal(
    await main(["local", "--run-id", id, "--program", "v5"], {
      print: (v) => {
        output = v;
      },
    }),
    0,
  );
  assert.equal(output.closureReady, true);
  assert.deepEqual(output.invalid, {});
  assert.equal(output.answers.deleteArms, "no");
  assert.ok(output.answers.windowEdge);
  await assert.rejects(main(["plan", "--program", "v6"]), /unknown program/);
  await assert.rejects(main(["plan", "--program"]), /incomplete option/);
  await assert.rejects(main(["plan", "--program", "v5", "--program", "v4"]), /duplicate option/);
});

test("record selects v5 with the existing injected world, journal and cleanup", async (t) => {
  const root = fixture(t);
  const clock = virtualClock();
  const transport = createWorld({ clock });
  let output;
  const code = await main(
    [
      "record",
      "--run-id",
      id,
      "--out",
      "v5",
      "--lock",
      "lock",
      "--packet",
      "packet",
      "--program",
      "v5",
    ],
    {
      root,
      env: {},
      token: "fake",
      sourceHead: "test",
      clock,
      transport,
      print: (v) => {
        output = v;
      },
    },
  );
  assert.equal(code, 0);
  assert.equal(output.records.length, 44);
  assert.equal(output.records[2].id, "DA1");
  assert.equal(output.closureReady, true);
  assert.ok(Object.values(transport.state).every((resources) => resources.size === 0));
  const saved = JSON.parse(fs.readFileSync(path.join(root, "v5", `summary-${id}.json`), "utf8"));
  assert.deepEqual(saved.answers, output.answers);
  assert.deepEqual(saved.invalid, {});
  assert.equal(saved.answers.calibration.latencyClassesHold, true);
});
