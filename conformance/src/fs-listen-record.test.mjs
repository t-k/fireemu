import assert from "node:assert/strict";
import { test } from "node:test";

import { checkProject, newRunId, parseArgs, recordNative } from "./fs-listen/record.mjs";

test("a recording may address only the sandbox that owns its kind", () => {
  checkProject("native", "fireemu-oracle-txn");
  checkProject("sdk", "fireemu-oracle-query");
  for (const [kind, project] of [
    ["native", "fireemu-oracle-query"],
    ["sdk", "fireemu-oracle-txn"],
    ["native", "fireemu-35fe6"],
    ["sdk", "fireemu-35fe6"],
    ["native", "fireemu-oracle-idp"],
    ["native", ""],
    ["other", "fireemu-oracle-txn"],
  ])
    assert.throws(() => checkProject(kind, project), /may address only/, `${kind} ${project}`);
});

test("parseArgs reads a command and --name value pairs, and refuses a stray word", () => {
  assert.deepEqual(parseArgs(["native", "--target", "local", "--out", "f.json"]), {
    command: "native",
    target: "local",
    out: "f.json",
  });
  assert.throws(() => parseArgs(["native", "stray"]), /unexpected argument stray/);
});

test("newRunId is a lower-case document id that differs between moments", () => {
  assert.match(newRunId(1_700_000_000_000), /^n[0-9a-z]+$/);
  assert.notEqual(newRunId(1_700_000_000_000), newRunId(1_700_000_000_001));
});

/** A clock only sleeping moves, so a wait that nothing satisfies runs out at once. */
function fakeClock() {
  const state = { t: 0 };
  return {
    sleep: async (ms) => {
      state.t += ms;
    },
    now: () => state.t,
  };
}

/** A client whose first write fails: the programs end in errors, the cleanup must still run. */
function failingClient() {
  const calls = [];
  return {
    calls,
    async commit({ writes }) {
      calls.push(["commit", writes.length]);
      if (calls.filter(([name]) => name === "commit").length === 1) throw new Error("boom");
    },
    async beginTransaction() {
      return Buffer.from("t");
    },
    openStream() {
      return { frames: [], ended: () => ({ reason: "ended" }), send() {}, async close() {} };
    },
    async missing(names) {
      calls.push(["missing", names.length]);
      return names.map((name) => ({ name, exists: false }));
    },
    async listIds() {
      calls.push(["list"]);
      return [];
    },
  };
}

test("recordNative reports a failing program and still cleans up and reads back", async () => {
  const client = failingClient();
  const recording = await recordNative({ client, project: "p", run: "r1", clock: fakeClock() });
  assert.equal(recording.version, 1);
  assert.equal(recording.kind, "native");
  assert.ok(Object.keys(recording.errors).length > 0);
  assert.ok(
    client.calls.some(([name]) => name === "missing"),
    "the read-back ran",
  );
  assert.equal(recording.cleanup.complete, true);
  assert.equal(typeof recording.cleanup.deleted, "number");
});

test("recordNative marks the cleanup incomplete when the read-back itself fails", async () => {
  const client = failingClient();
  client.missing = async () => {
    throw new Error("read-back unavailable");
  };
  const recording = await recordNative({ client, project: "p", run: "r1", clock: fakeClock() });
  assert.equal(recording.cleanup.complete, false);
  assert.match(recording.cleanup.error, /read-back unavailable/);
});

test("parseArgs: no arguments is an empty command; a flag without a value has none; the last one wins", () => {
  assert.deepEqual(parseArgs([]), { command: undefined });
  assert.deepEqual(parseArgs(["sdk", "--out"]), { command: "sdk", out: undefined });
  assert.deepEqual(parseArgs(["sdk", "--out", "a", "--out", "b"]), { command: "sdk", out: "b" });
  assert.throws(() => parseArgs(["sdk", "--out", "a", "stray", "b"]), /unexpected argument stray/);
  assert.throws(() => parseArgs(["sdk", "-o", "a"]), /unexpected argument -o/);
});

test("checkProject names the one project a kind may address", () => {
  // The allowed lists hold one project each, so the message shows exactly that one.
  assert.throws(
    () => checkProject("native", "x"),
    (error) => !error.message.includes(","),
  );

  assert.throws(
    () => checkProject("native", "x"),
    /native recordings may address only fireemu-oracle-txn$/,
  );
  assert.throws(
    () => checkProject("sdk", "x"),
    /sdk recordings may address only fireemu-oracle-query$/,
  );
});

test("newRunId: the same moment gives the same id, and the default is now", () => {
  assert.equal(newRunId(36), "n10");
  assert.equal(newRunId(0), "n0");
  assert.match(newRunId(), /^n[0-9a-z]{8,}$/);
});

test("recordNative returns a recording with its facts and a clean cleanup on a client that holds nothing", async () => {
  const client = failingClient();
  const before = Date.now();
  const recording = await recordNative({ client, project: "p", run: "r1", clock: fakeClock() });
  assert.equal(recording.node, process.version);
  assert.ok(Date.parse(recording.startedAt) >= before - 1000);
  assert.equal(typeof recording.requests, "number");
  assert.ok(recording.requests > 0);
  assert.deepEqual(recording.cleanup.stillPresent, []);
  assert.equal(recording.cleanup.deleted, 0);
  assert.ok(recording.cleanup.checked > 0);
  assert.ok(
    client.calls.some(([name]) => name === "list"),
    "the run's prefix is swept",
  );
});

test("recordNative runs the programs on the clock it is given", async () => {
  const reads = [];
  await recordNative({
    client: failingClient(),
    project: "p",
    run: "r1",
    clock: {
      sleep: async () => {},
      now: () => {
        reads.push(1);
        return reads.length * 1000;
      },
    },
  });
  assert.ok(reads.length > 0, "the supplied clock is read");
});

test("recordNative reports a cleanup failure by its message, or by the value when it has none", async () => {
  const withMissing = async (thrown) => {
    const client = failingClient();
    client.missing = async () => {
      throw thrown;
    };
    return recordNative({ client, project: "p", run: "r1", clock: fakeClock() });
  };
  assert.deepEqual((await withMissing(new Error("gone"))).cleanup, {
    complete: false,
    error: "gone",
  });
  assert.deepEqual((await withMissing("plain text")).cleanup, {
    complete: false,
    error: "plain text",
  });
});
