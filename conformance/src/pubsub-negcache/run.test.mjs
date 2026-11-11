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
  assert.equal(output.cells, 30);
  assert.equal(output.scheduledRequests, 189);
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
