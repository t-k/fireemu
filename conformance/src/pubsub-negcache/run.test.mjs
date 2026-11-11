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
