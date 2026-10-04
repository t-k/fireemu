import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { test } from "node:test";

import {
  conditionsOf,
  projectEvent,
  ranOut,
  recordSdk,
  rowsFromReceipt,
  runDriver,
  sweepDocuments,
} from "./fs-listen/sdk-record.mjs";

test("every SDK case maps to exactly one closure condition", () => {
  const expected = {
    "FS-LISTEN-SDK-101": "document-event-order",
    "FS-LISTEN-SDK-101C": "document-event-order",
    "FS-LISTEN-SDK-102C": "pending-writes",
    "FS-LISTEN-SDK-103": "query-change-order",
    "FS-LISTEN-SDK-103L": "query-change-order",
    "FS-LISTEN-SDK-103T": "query-change-order",
    "FS-LISTEN-SDK-104C": "reconnect-resume",
    "FS-LISTEN-SDK-105": "unsubscribe",
    "FS-LISTEN-SDK-106N": "initial-unauthenticated-refusal",
    "FS-LISTEN-SDK-107C": "default-subscription",
    "FS-LISTEN-SDK-108": "cross-principal-rules",
    "FS-LISTEN-SDK-108C": "cross-principal-rules",
    "FS-LISTEN-SDK-111": "existence-filter-reconnect",
  };
  for (const [id, condition] of Object.entries(expected))
    assert.deepEqual(conditionsOf(id), [`FS-LISTEN-SDK/${condition}`], id);
  assert.throws(() => conditionsOf("FS-LISTEN-SDK-999"), /no condition/);
});

test("ranOut recognises the failures that mean a wait did not finish", () => {
  for (const f of [
    "step-timeout",
    "deadline-exceeded",
    "snapshot-budget-exhausted",
    "budget-exceeded:reads",
  ])
    assert.equal(ranOut([f]), true, f);
  assert.equal(ranOut([]), false);
  assert.equal(ranOut(["unsubscribe-failed:primary"]), false);
});

test("rowsFromReceipt keys rows by case and carries the observation, not the verdict", () => {
  const rows = rowsFromReceipt({
    cases: [
      {
        caseId: "FS-LISTEN-SDK-101",
        comparedFields: null,
        observed: [{ docs: ["alpha"] }],
        failures: [],
        invariantViolations: [],
      },
      {
        caseId: "FS-LISTEN-SDK-105",
        comparedFields: null,
        observed: [],
        failures: ["step-timeout"],
        invariantViolations: [{ invariant: "x" }],
      },
    ],
  });
  assert.deepEqual(Object.keys(rows), ["sdk/101", "sdk/105"]);
  assert.equal(rows["sdk/101"].timedOut, false);
  assert.equal(rows["sdk/105"].timedOut, true);
  assert.deepEqual(rows["sdk/101"].observed, [{ docs: ["alpha"] }]);
  assert.deepEqual(rows["sdk/105"].conditions, ["FS-LISTEN-SDK/unsubscribe"]);
});

test("projectEvent keeps the compared fields and the cache transitions, nothing else", () => {
  const event = {
    listener: "primary",
    docs: ["a"],
    fromCache: true,
    hasPendingWrites: false,
    fromCacheTransitions: [true, false],
  };
  assert.deepEqual(projectEvent(event, ["listener", "docs"]), {
    listener: "primary",
    docs: ["a"],
    fromCacheTransitions: [true, false],
  });
  assert.deepEqual(projectEvent(event, null), event);
  assert.deepEqual(projectEvent(event, ["fromCache"]), {
    fromCache: true,
    fromCacheTransitions: [true, false],
  });
});

test("rowsFromReceipt projects each event to its case's compared fields", () => {
  const rows = rowsFromReceipt({
    cases: [
      {
        caseId: "FS-LISTEN-SDK-101",
        comparedFields: ["docs"],
        observed: [{ docs: ["alpha"], fromCache: true }],
        failures: [],
        invariantViolations: [],
      },
    ],
  });
  assert.deepEqual(rows["sdk/101"].observed, [{ docs: ["alpha"] }]);
});

test("sweepDocuments deletes the run's documents and the accounts' owner documents, then reads back", async () => {
  const present = new Set([
    "projects/p/databases/(default)/documents/conf_listen/r1-alpha",
    "projects/p/databases/(default)/documents/conf_rules_owner/uB",
  ]);
  const client = {
    async listIds() {
      return ["projects/p/databases/(default)/documents/conf_listen/r1-alpha"];
    },
    async missing(names) {
      return names.map((name) => ({ name, exists: present.has(name) }));
    },
    async commit({ writes }) {
      for (const w of writes) present.delete(w.delete);
    },
  };
  const report = await sweepDocuments({
    client,
    project: "p",
    run: "r1",
    accounts: { a: { uid: "uA" }, b: { uid: "uB" } },
  });
  assert.deepEqual(report, { complete: true, deleted: 2, stillPresent: 0, checked: 3 });
  assert.equal(present.size, 0);
  const stubborn = {
    ...client,
    async commit() {},
    async listIds() {
      return [];
    },
  };
  present.add("projects/p/databases/(default)/documents/conf_rules_owner/uB");
  const bad = await sweepDocuments({
    client: stubborn,
    project: "p",
    run: "r1",
    accounts: { b: { uid: "uB" } },
  });
  assert.equal(bad.complete, false);
});

test("recordSdk: a driver that fails leaves an error row and still cleans up the accounts", async () => {
  const calls = [];
  const fetchStub = async (url) => {
    calls.push(url.split("/").at(-1));
    return { status: 200, json: async () => ({ localId: `u${calls.length}` }) };
  };
  const realFetch = globalThis.fetch;
  globalThis.fetch = fetchStub;
  try {
    const recording = await recordSdk({
      target: {
        kind: "local",
        project: "demo",
        firestore: { host: "127.0.0.1", port: 1 },
        auth: "http://127.0.0.1:2",
      },
      run: "r1",
      runDriverImpl: async () => {
        throw new Error("driver exploded");
      },
    });
    assert.equal(recording.errors["sdk/run"], "driver exploded");
    assert.equal(recording.cleanup.complete, false);
    assert.deepEqual(recording.rows, {});
    assert.ok(
      calls.includes("accounts:delete"),
      "the accounts are deleted even though the driver failed",
    );
  } finally {
    globalThis.fetch = realFetch;
  }
});

/** A child process stand-in: stdout lines are fed by the test, stdin is captured. */
function fakeChild() {
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stdin = new PassThrough();
  child.written = [];
  child.stdin.on("data", (chunk) => child.written.push(String(chunk)));
  child.killed = [];
  child.kill = (signal) => {
    child.killed.push(signal);
    child.emit("close", null);
  };
  child.say = (event) => child.stdout.write(`${JSON.stringify(event)}\n`);
  child.end = (code) => setImmediate(() => child.emit("close", code));
  return child;
}

test("runDriver sends its input as one line and resolves with the receipt and the wire counts", async () => {
  const child = fakeChild();
  const pending = runDriver({
    config: { mode: "local" },
    input: { run: "r1" },
    spawnImpl: (cmd, args, options) => {
      assert.equal(cmd, process.execPath);
      assert.match(args[0], /sdk-driver\.mjs$/);
      assert.equal(JSON.parse(options.env.AFC_SDK_CONFIG).mode, "local");
      return child;
    },
  });
  child.say({ event: "wire", n: 1 });
  child.say({ event: "wire", n: 2 });
  child.say({ event: "connection", n: 1 });
  child.stdout.write("not json\n");
  child.say({ event: "receipt", receipt: { cases: [] } });
  child.end(0);
  const out = await pending;
  assert.deepEqual(out, { receipt: { cases: [] }, wire: 2, connections: 1, refused: undefined });
  assert.deepEqual(child.written, ['{"run":"r1"}\n']);
});

test("runDriver rejects with the driver's own reason when no receipt came", async () => {
  const a = fakeChild();
  const pa = runDriver({ config: {}, input: {}, spawnImpl: () => a });
  a.say({ event: "driver-error", message: "kaboom" });
  a.end(1);
  await assert.rejects(pa, /ended \(1\) without a receipt: kaboom/);
  const b = fakeChild();
  const pb = runDriver({ config: {}, input: {}, spawnImpl: () => b });
  b.say({ event: "wire-refused", reason: "request cap 1500 reached" });
  b.end(3);
  await assert.rejects(pb, /without a receipt: request cap 1500 reached/);
  const c = fakeChild();
  const pc = runDriver({ config: {}, input: {}, spawnImpl: () => c });
  c.end(0);
  await assert.rejects(pc, /without a receipt: no reason/);
});

test("runDriver kills a driver that outlives its deadline", async () => {
  const child = fakeChild();
  const pending = runDriver({ config: {}, input: {}, timeoutMs: 10, spawnImpl: () => child });
  await assert.rejects(pending, /without a receipt/);
  assert.deepEqual(child.killed, ["SIGKILL"]);
});

test("recordSdk: a clean run keeps the receipt's rows and counts, and the cleanup is complete only when every part is", async () => {
  const receipt = (extra = {}) => ({
    thrown: null,
    cleanup: { complete: true },
    teardown: [{ client: "primary", closed: true }],
    cases: [
      {
        caseId: "FS-LISTEN-SDK-101",
        comparedFields: null,
        observed: [],
        failures: [],
        invariantViolations: [],
      },
    ],
    ...extra,
  });
  const native = (stillPresent = false) => ({
    close() {},
    async listIds() {
      return [];
    },
    async missing(names) {
      return names.map((name) => ({ name, exists: stillPresent }));
    },
    async commit() {},
  });
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url) => ({
    status: 200,
    json: async () => (url.endsWith("/accounts") ? { localId: `u${Math.random()}` } : {}),
  });
  const target = {
    kind: "local",
    project: "demo",
    firestore: { host: "127.0.0.1", port: 1 },
    auth: "http://127.0.0.1:2",
  };
  try {
    const run = (driverReceipt, nativeClient) =>
      recordSdk({
        target,
        run: "r1",
        runDriverImpl: async () => ({ receipt: driverReceipt, wire: 7, connections: 3 }),
        makeNative: () => nativeClient,
      });
    const clean = await run(receipt(), native());
    assert.equal(clean.requests, 7);
    assert.equal(clean.connections, 3);
    assert.equal(clean.kind, "sdk");
    assert.equal(clean.version, 1);
    assert.deepEqual(Object.keys(clean.rows), ["sdk/101"]);
    assert.deepEqual(clean.errors, {});
    assert.equal(clean.cleanup.complete, true);
    assert.equal(clean.cleanup.clientsClosed, true);
    assert.deepEqual(clean.cleanup.sdk, { complete: true });
    // Each part alone makes the cleanup incomplete.
    assert.equal(
      (await run(receipt({ cleanup: { complete: false } }), native())).cleanup.complete,
      false,
    );
    assert.equal((await run(receipt(), native(true))).cleanup.complete, false);
    assert.equal(
      (await run(receipt({ teardown: [{ client: "primary", closed: false }] }), native())).cleanup
        .complete,
      false,
    );
    const thrown = await run(receipt({ thrown: "boom" }), native());
    assert.equal(thrown.errors["sdk/driver"], "boom");
  } finally {
    globalThis.fetch = realFetch;
  }
});
