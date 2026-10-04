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

/** Runs recordSdk against a stub driver and records everything it was asked. */
async function recordWith(target, { driver, native, status = 200 } = {}) {
  const fetched = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const body = JSON.parse(init.body);
    fetched.push({ url, headers: init.headers, body });
    return {
      status,
      json: async () => (url.endsWith("/accounts") ? { localId: `u-${body.email}` } : {}),
    };
  };
  const drove = [];
  const nativeCalls = [];
  try {
    const recording = await recordSdk({
      target,
      run: "r1",
      log: (line) => drove.push(line),
      runDriverImpl: async (request) => {
        drove.push(request);
        return (
          driver ?? {
            receipt: { thrown: null, cleanup: { complete: true }, teardown: [], cases: [] },
            wire: 0,
            connections: 0,
          }
        );
      },
      makeNative: (options) => {
        nativeCalls.push(options);
        return (
          native ?? {
            close() {},
            async listIds() {
              return [];
            },
            async missing(names) {
              return names.map((name) => ({ name, exists: false }));
            },
            async commit() {},
          }
        );
      },
    });
    return { recording, fetched, drove, nativeCalls };
  } finally {
    globalThis.fetch = realFetch;
  }
}

test("recordSdk against production: the accounts use the token, the driver gets the web config and the caps", async () => {
  const web = { apiKey: "k", authDomain: "d", projectId: "fireemu-oracle-query" };
  const { fetched, drove, nativeCalls } = await recordWith({
    kind: "production",
    project: "fireemu-oracle-query",
    token: "TOK",
    web,
  });
  assert.ok(fetched.length >= 4);
  for (const { url, headers } of fetched) {
    assert.match(
      url,
      /^https:\/\/identitytoolkit\.googleapis\.com\/v1\/projects\/fireemu-oracle-query\/accounts/,
    );
    assert.equal(headers.authorization, "Bearer TOK");
    assert.equal(headers["x-goog-user-project"], "fireemu-oracle-query");
  }
  assert.deepEqual(fetched[0].body.email, "fsl-r1-a@example.com");
  assert.deepEqual(fetched[1].body.email, "fsl-r1-b@example.com");
  assert.deepEqual(nativeCalls, [
    { project: "fireemu-oracle-query", target: { kind: "production" }, token: "TOK" },
  ]);
  const request = drove.find((entry) => entry.config);
  assert.deepEqual(request.config, { mode: "production", wireCap: 1500, connectionCap: 200, web });
  assert.deepEqual(Object.keys(request.input), ["run", "accounts"]);
  assert.equal(request.input.run, "r1");
  assert.equal(request.input.accounts.a.uid, "u-fsl-r1-a@example.com");
  assert.equal(request.input.accounts.b.email, "fsl-r1-b@example.com");
  assert.ok(drove.includes("accounts created"));
});

test("recordSdk against fireemu: the accounts use the local owner, the driver gets the emulator addresses", async () => {
  const target = {
    kind: "local",
    project: "demo",
    firestore: { host: "127.0.0.1", port: 11 },
    auth: "http://127.0.0.1:22",
  };
  const { fetched, drove, nativeCalls } = await recordWith(target);
  for (const { url, headers } of fetched) {
    assert.ok(
      url.startsWith(
        "http://127.0.0.1:22/identitytoolkit.googleapis.com/v1/projects/demo/accounts",
      ),
      url,
    );
    assert.deepEqual(headers, {
      "content-type": "application/json",
      authorization: "Bearer owner",
    });
  }
  assert.deepEqual(nativeCalls, [
    { project: "demo", target: { kind: "local", host: "127.0.0.1", port: 11 }, token: undefined },
  ]);
  const { config } = drove.find((entry) => entry.config);
  assert.deepEqual(config, {
    mode: "local",
    wireCap: 1500,
    connectionCap: 200,
    web: { apiKey: "fake-api-key", projectId: "demo", authDomain: "localhost" },
    authEmulator: "http://127.0.0.1:22",
    firestoreEmulator: { host: "127.0.0.1", port: 11 },
  });
});

test("recordSdk: a sweep or an account cleanup that fails is reported, not thrown", async () => {
  const target = {
    kind: "local",
    project: "demo",
    firestore: { host: "h", port: 1 },
    auth: "http://a",
  };
  const broken = {
    close() {},
    async listIds() {
      throw new Error("list refused");
    },
  };
  const swept = await recordWith(target, { native: broken });
  assert.deepEqual(swept.recording.cleanup.documents, { complete: false, error: "list refused" });
  assert.equal(swept.recording.cleanup.complete, false);
  const rejected = await recordWith(target, { status: 400 });
  assert.match(rejected.recording.errors["sdk/run"], /account a was not created: refused 400/);
  assert.equal(rejected.recording.cleanup.accounts.complete, true);
});

test("recordSdk: a thrown value that is not an Error is still reported as text", async () => {
  const target = {
    kind: "local",
    project: "demo",
    firestore: { host: "h", port: 1 },
    auth: "http://a",
  };
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => ({ status: 200, json: async () => ({ localId: "u" }) });
  try {
    const recording = await recordSdk({
      target,
      run: "r1",
      runDriverImpl: async () => {
        throw "plain text";
      },
      makeNative: () => ({
        close() {},
        async listIds() {
          throw "no list";
        },
      }),
    });
    assert.equal(recording.errors["sdk/run"], "plain text");
    assert.equal(recording.cleanup.documents.error, "no list");
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("sweepDocuments asks for the run's prefix, deletes nothing when nothing is there, and passes a failed delete on", async () => {
  const asked = [];
  const commits = [];
  const client = {
    async listIds(request) {
      asked.push(request);
      return [];
    },
    async missing(names) {
      return names.map((name) => ({ name, exists: false }));
    },
    async commit(request) {
      commits.push(request);
    },
  };
  const report = await sweepDocuments({ client, project: "p", run: "r1", accounts: {} });
  assert.deepEqual(asked, [
    {
      parent: "projects/p/databases/(default)/documents",
      collectionId: "conf_listen",
      prefix: "r1",
    },
  ]);
  assert.deepEqual(commits, []);
  assert.deepEqual(report, { complete: true, deleted: 0, stillPresent: 0, checked: 0 });
  const present = new Set(["projects/p/databases/(default)/documents/conf_rules_owner/uB"]);
  const failing = {
    ...client,
    async missing(names) {
      return names.map((name) => ({ name, exists: present.has(name) }));
    },
    async commit() {
      await Promise.resolve();
      throw new Error("delete refused");
    },
  };
  await assert.rejects(
    sweepDocuments({ client: failing, project: "p", run: "r1", accounts: { b: { uid: "uB" } } }),
    /delete refused/,
  );
});

test("runDriver: the process is spawned with piped output and inherited errors; other events change nothing; the deadline is 20 minutes", async (t) => {
  const child = fakeChild();
  let options;
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const pending = runDriver({
    config: {},
    input: {},
    spawnImpl: (cmd, args, o) => {
      options = o;
      return child;
    },
  });
  assert.deepEqual(options.stdio, ["pipe", "pipe", "inherit"]);
  child.say({ event: "something-else" });
  child.say({ event: "receipt", receipt: { cases: [] } });
  await new Promise((resolve) => setImmediate(resolve));
  t.mock.timers.tick(20 * 60_000 - 1);
  assert.deepEqual(child.killed, []);
  child.end(0);
  const out = await pending;
  assert.equal(out.refused, undefined);
  assert.equal(out.wire, 0);
  const late = fakeChild();
  const waiting = runDriver({ config: {}, input: {}, spawnImpl: () => late });
  t.mock.timers.tick(20 * 60_000);
  await assert.rejects(waiting, /without a receipt/);
  assert.deepEqual(late.killed, ["SIGKILL"]);
});

test("recordSdk: what it records when the driver fails, and that it closes the native client and names the SDK", async () => {
  const target = {
    kind: "local",
    project: "demo",
    firestore: { host: "h", port: 1 },
    auth: "http://a",
  };
  let closed = 0;
  const native = {
    close() {
      closed += 1;
    },
    async listIds() {
      return [];
    },
    async missing(names) {
      return names.map((name) => ({ name, exists: false }));
    },
    async commit() {},
  };
  const failed = await recordWith(target, { native, driver: undefined });
  assert.equal(closed, 1);
  assert.equal(failed.recording.sdk, "firebase 12.18.0");
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => ({ status: 200, json: async () => ({ localId: "u" }) });
  try {
    const out = await recordSdk({
      target,
      run: "r1",
      runDriverImpl: async () => {
        throw new Error("no driver");
      },
      makeNative: () => native,
    });
    assert.equal(out.requests, 0);
    assert.equal(out.connections, 0);
    assert.equal(out.cleanup.clientsClosed, false);
    assert.equal(out.cleanup.sdk, null);
    assert.deepEqual(out.rows, {});
    assert.equal(closed, 2);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("recordSdk: an account cleanup that throws is reported, with the message or the value", async () => {
  const target = {
    kind: "local",
    project: "demo",
    firestore: { host: "h", port: 1 },
    auth: "http://a",
  };
  const native = {
    close() {},
    async listIds() {
      return [];
    },
    async missing(names) {
      return names.map((name) => ({ name, exists: false }));
    },
    async commit() {},
  };
  const realFetch = globalThis.fetch;
  try {
    for (const [thrown, expected] of [
      [new Error("odd status"), "odd status"],
      ["plain", "plain"],
    ]) {
      globalThis.fetch = async (url) =>
        url.endsWith("/accounts")
          ? { status: 200, json: async () => ({ localId: "u" }) }
          : {
              get status() {
                throw thrown;
              },
            };
      const out = await recordSdk({
        target,
        run: "r1",
        runDriverImpl: async () => ({
          receipt: { thrown: null, cleanup: { complete: true }, teardown: [], cases: [] },
          wire: 0,
          connections: 0,
        }),
        makeNative: () => native,
      });
      assert.deepEqual(out.cleanup.accounts, { complete: false, error: expected });
      assert.equal(out.cleanup.complete, false);
    }
  } finally {
    globalThis.fetch = realFetch;
  }
});
