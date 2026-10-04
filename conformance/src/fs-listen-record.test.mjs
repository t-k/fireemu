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
  const recording = await recordNative({ client, project: "p", run: "r1" });
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
  const recording = await recordNative({ client, project: "p", run: "r1" });
  assert.equal(recording.cleanup.complete, false);
  assert.match(recording.cleanup.error, /read-back unavailable/);
});
