import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { test } from "node:test";
import { tempDir } from "./test-tmpdir.mjs";

import { sdkCases } from "./fs-listen/sdk-cases.mjs";

import {
  conditionsOf,
  issuedSdkNames,
  loadApiKey,
  preflightKey,
  projectEvent,
  ranOut,
  recordSdk,
  rowsFromReceipt,
  runDriver,
  sweepDocuments,
  unknownWrites,
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

test("rowsFromReceipt preserves callback boundaries, order, metadata and change indexes", () => {
  for (const baselineAt of [0, 1, 2]) {
    const rawEvents = [
      {
        listener: "primary",
        docs: ["alpha"],
        fromCache: true,
        hasPendingWrites: false,
        changes: [{ type: "added", doc: "alpha", oldIndex: -1, newIndex: 0 }],
      },
      {
        listener: "primary",
        docs: ["alpha"],
        fromCache: false,
        hasPendingWrites: false,
        changes: [],
      },
      {
        listener: "primary",
        docs: ["beta", "alpha"],
        fromCache: false,
        hasPendingWrites: true,
        changes: [
          { type: "added", doc: "beta", oldIndex: -1, newIndex: 0 },
          { type: "modified", doc: "alpha", oldIndex: 0, newIndex: 1 },
        ],
      },
    ];
    const row = rowsFromReceipt({
      cases: [
        {
          caseId: "FS-LISTEN-SDK-111",
          comparedFields: ["docs"],
          observed: [{ docs: ["beta", "alpha"] }],
          rawEvents,
          rawEventCount: 3,
          baselineAt,
        },
      ],
    })["sdk/111"];
    assert.deepEqual(row.rawEvents, rawEvents);
    assert.equal(row.rawEventCount, 3);
    assert.equal(row.baselineAt, baselineAt);
    assert.deepEqual(row.observed, [{ docs: ["beta", "alpha"] }]);
  }
});

test("rowsFromReceipt distinguishes missing callback evidence from an observed empty stream", () => {
  for (const extra of [
    {},
    { rawEvents: null, rawEventCount: null, baselineAt: null },
    { rawEvents: {}, rawEventCount: -1, baselineAt: -1 },
    { rawEvents: "missing", rawEventCount: 1.5, baselineAt: "0" },
  ]) {
    const row = rowsFromReceipt({ cases: [{ caseId: "FS-LISTEN-SDK-111", ...extra }] })["sdk/111"];
    for (const field of ["rawEvents", "rawEventCount", "baselineAt"])
      assert.equal(Object.hasOwn(row, field), false, field);
  }
  const row = rowsFromReceipt({
    cases: [{ caseId: "FS-LISTEN-SDK-111", rawEvents: [], rawEventCount: 0, baselineAt: 0 }],
  })["sdk/111"];
  assert.deepEqual(row.rawEvents, []);
  assert.equal(row.rawEventCount, 0);
  assert.equal(row.baselineAt, 0);
});

test("sweepDocuments reads each issued name, deletes what is there and reads back", async () => {
  const root = "projects/p/databases/(default)/documents";
  const present = new Set([`${root}/conf_listen/r1-alpha`, `${root}/conf_rules_owner/uB`]);
  const log = { commits: [], lists: [] };
  const client = {
    async listIds(request) {
      log.lists.push(request);
      return [];
    },
    async missing(names) {
      return names.map((name) => ({ name, exists: present.has(name) }));
    },
    async commit({ writes }) {
      log.commits.push(writes.map((w) => w.delete));
      for (const w of writes) present.delete(w.delete);
    },
  };
  const accounts = { a: { uid: "uA" }, b: { uid: "uB" } };
  const report = await sweepDocuments({ client, project: "p", run: "r1", accounts });
  assert.equal(report.complete, true);
  assert.equal(report.deleted, 2);
  assert.equal(report.checked, 7);
  assert.equal(present.size, 0);
  assert.deepEqual(log.commits, [[`${root}/conf_listen/r1-alpha`, `${root}/conf_rules_owner/uB`]]);
  // The prefix listing only looks for strays, in both collections the cases write to.
  assert.deepEqual(
    log.lists.map((l) => l.collectionId),
    ["conf_listen", "conf_rules_owner"],
  );
  assert.ok(log.lists.every((l) => l.prefix === "r1" && l.parent === root));
  // A stray (run-prefixed, never issued) is reported and not deleted.
  const stray = `${root}/conf_listen/r1-stray`;
  present.add(stray);
  const withStray = await sweepDocuments({
    client: {
      ...client,
      async listIds(r) {
        return r.collectionId === "conf_listen" ? [stray] : [];
      },
    },
    project: "p",
    run: "r1",
    accounts,
  });
  assert.deepEqual(withStray.strays, [stray]);
  assert.equal(withStray.complete, false);
  assert.ok(present.has(stray));
});

test("issuedSdkNames lists the run's five public names and the accounts' owner documents", () => {
  const names = issuedSdkNames({
    project: "p",
    run: "r1",
    accounts: { a: { uid: "uA" }, b: { uid: "uB" }, c: {} },
  });
  const root = "projects/p/databases/(default)/documents";
  assert.deepEqual(names, [
    ...["alpha", "beta", "gamma", "delta", "absent"].map((d) => `${root}/conf_listen/r1-${d}`),
    `${root}/conf_rules_owner/uA`,
    `${root}/conf_rules_owner/uB`,
  ]);
  assert.equal(issuedSdkNames({ project: "p", run: "r1", accounts: {} }).length, 5);
});

test("unknownWrites is true for any case with a step that threw, and for nothing else", () => {
  const receipt = (failures) => ({ cases: [{ failures: [] }, { failures }] });
  assert.equal(unknownWrites(receipt(["step-threw:unavailable"])), true);
  assert.equal(unknownWrites(receipt(["x", "step-threw:x"])), true);
  assert.equal(
    unknownWrites(receipt(["step-timeout", "deadline-exceeded", "unsubscribe-failed:p"])),
    false,
  );
  assert.equal(unknownWrites(receipt([])), false);
  assert.equal(unknownWrites({ cases: [] }), false);
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
  assert.deepEqual(out, {
    receipt: { cases: [] },
    wire: 2,
    connections: 1,
    refused: undefined,
    diagnostics: [],
  });
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
    cases: completeCases(),
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
    assert.deepEqual(
      Object.keys(clean.rows),
      sdkCases().map((c) => `sdk/${c.caseId.replace("FS-LISTEN-SDK-", "")}`),
    );
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
      preflightImpl: async () => {},
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
    async missing(names) {
      return names.map((name) => ({ name, exists: false }));
    },
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
        async missing(names) {
          return names.map((name) => ({ name, exists: false }));
        },
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
    assert.equal(out.cleanup.writesKnown, false);
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

const KEY = "AIzaSyTestKeyTestKeyTestKeyTestKey01";
const NUMBER = "123456789012";

/** A fetch answering the two preflight reads; either answer can be replaced. */
function preflightFetch({
  toolkit = [200, { projectId: NUMBER }],
  crm = [
    200,
    { projectId: "fireemu-oracle-query", projectNumber: NUMBER, lifecycleState: "ACTIVE" },
  ],
} = {}) {
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    calls.push({ url, headers: init.headers ?? {}, init });
    const [status, json] = url.startsWith("https://identitytoolkit.googleapis.com/")
      ? toolkit
      : crm;
    return { status, json: async () => json };
  };
  return { calls, fetchImpl };
}
const preflight = (fetchStub, extra = {}) =>
  preflightKey({
    apiKey: KEY,
    project: "fireemu-oracle-query",
    token: "TOK",
    fetchImpl: fetchStub.fetchImpl,
    ...extra,
  });

test("preflightKey binds the key to the project: the toolkit's project number must equal the project's own", async () => {
  const stub = preflightFetch();
  assert.deepEqual(await preflight(stub), { projectNumber: NUMBER });
  assert.equal(stub.calls.length, 2);
  const toolkit = stub.calls.find((c) =>
    c.url.startsWith("https://identitytoolkit.googleapis.com/"),
  );
  assert.equal(
    toolkit.url,
    `https://identitytoolkit.googleapis.com/v1/projects?key=${encodeURIComponent(KEY)}`,
  );
  const crm = stub.calls.find((c) =>
    c.url.startsWith("https://cloudresourcemanager.googleapis.com/"),
  );
  assert.equal(
    crm.url,
    "https://cloudresourcemanager.googleapis.com/v1/projects/fireemu-oracle-query",
  );
  assert.equal(crm.headers.authorization, "Bearer TOK");
  assert.equal(crm.headers["x-goog-user-project"], "fireemu-oracle-query");
  assert.equal(toolkit.headers.authorization, undefined, "the key read carries no credential");
});

test("preflightKey fails closed on a different project, a missing value or any unreadable answer", async () => {
  const refuses = async (stub, pattern) => {
    await assert.rejects(preflight(stub), pattern);
  };
  await refuses(
    preflightFetch({ toolkit: [200, { projectId: "999999999999" }] }),
    /belongs to a different project/,
  );
  await refuses(preflightFetch({ toolkit: [200, {}] }), /no project number/);
  await refuses(preflightFetch({ toolkit: [200, { projectId: "" }] }), /no project number/);
  await refuses(
    preflightFetch({ toolkit: [200, { projectId: 123456789012 }] }),
    /no project number/,
  );
  await refuses(
    preflightFetch({ toolkit: [200, { projectId: "not-a-number" }] }),
    /no project number/,
  );
  await refuses(
    preflightFetch({ crm: [200, { projectId: "fireemu-oracle-query" }] }),
    /no project number/,
  );
  await refuses(
    preflightFetch({ crm: [200, { projectId: "other", projectNumber: NUMBER }] }),
    /is not the project/,
  );
  await refuses(
    preflightFetch({ crm: [200, { projectId: "fireemu-oracle-query", projectNumber: NUMBER }] }),
    /is not ACTIVE/,
  );
  await refuses(
    preflightFetch({
      crm: [
        200,
        {
          projectId: "fireemu-oracle-query",
          projectNumber: NUMBER,
          lifecycleState: "DELETE_REQUESTED",
        },
      ],
    }),
    /is not ACTIVE/,
  );
  await refuses(preflightFetch({ toolkit: [400, { error: {} }] }), /key read failed/);
  await refuses(preflightFetch({ toolkit: [403, {}] }), /key read failed/);
  await refuses(preflightFetch({ crm: [403, {}] }), /project read failed/);
  await refuses(preflightFetch({ crm: [500, {}] }), /project read failed/);
  await assert.rejects(
    preflight({
      fetchImpl: async () => {
        throw new Error("network");
      },
    }),
    /key read failed/,
  );
  await assert.rejects(
    preflight({
      fetchImpl: async () => ({
        status: 200,
        json: async () => {
          throw new Error("bad json");
        },
      }),
    }),
    /unreadable/,
  );
});

test("a preflight failure never prints the key or the project numbers", async () => {
  const cases = [
    preflightFetch({ toolkit: [200, { projectId: "999999999999" }] }),
    preflightFetch({ crm: [200, { projectId: "other", projectNumber: NUMBER }] }),
    preflightFetch({ toolkit: [403, {}] }),
  ];
  for (const stub of cases) {
    try {
      await preflight(stub);
      assert.fail("should refuse");
    } catch (error) {
      assert.ok(!error.message.includes(KEY), error.message);
      assert.ok(
        !error.message.includes(NUMBER) && !error.message.includes("999999999999"),
        error.message,
      );
    }
  }
});

test("loadApiKey reads one key from a file only the owner can read", async () => {
  const stat = (mode) => async () => ({ mode, isFile: () => true });
  const read = (text) => async () => text;
  assert.equal(await loadApiKey("f", { stat: stat(0o100600), readFile: read(`${KEY}\n`) }), KEY);
  assert.equal(await loadApiKey("f", { stat: stat(0o100400), readFile: read(KEY) }), KEY);
  await assert.rejects(
    loadApiKey("f", { stat: stat(0o100644), readFile: read(KEY) }),
    /readable by others/,
  );
  await assert.rejects(
    loadApiKey("f", { stat: stat(0o100660), readFile: read(KEY) }),
    /readable by others/,
  );
  await assert.rejects(
    loadApiKey("f", { stat: stat(0o100604), readFile: read(KEY) }),
    /readable by others/,
  );
  await assert.rejects(
    loadApiKey("f", {
      stat: async () => ({ mode: 0o100600, isFile: () => false }),
      readFile: read(KEY),
    }),
    /not a file/,
  );
  for (const text of [
    "",
    "\n",
    "short",
    "has space in it key key key key",
    `{"apiKey":"${KEY}"}`,
    `${KEY}\n${KEY}`,
  ])
    await assert.rejects(
      loadApiKey("f", { stat: stat(0o100600), readFile: read(text) }),
      /does not hold one API key/,
      JSON.stringify(text),
    );
});

test("recordSdk against production stops on a failed key preflight before any account or request, and asks with its own key, project and token", async () => {
  const web = { apiKey: KEY, authDomain: "d", projectId: "fireemu-oracle-query" };
  const target = { kind: "production", project: "fireemu-oracle-query", token: "TOK", web };
  let asked;
  const realFetch = globalThis.fetch;
  let fetched = 0;
  globalThis.fetch = async () => {
    fetched += 1;
    return { status: 200, json: async () => ({ localId: "u" }) };
  };
  let drove = 0;
  let madeNative = 0;
  try {
    await assert.rejects(
      recordSdk({
        target,
        run: "r1",
        preflightImpl: async (request) => {
          asked = request;
          throw new Error("the API key belongs to a different project");
        },
        runDriverImpl: async () => {
          drove += 1;
        },
        makeNative: () => {
          madeNative += 1;
        },
      }),
      /different project/,
    );
    const { onRequest, ...rest } = asked;
    assert.deepEqual(rest, { apiKey: KEY, project: "fireemu-oracle-query", token: "TOK" });
    assert.equal(typeof onRequest, "function");
    assert.deepEqual([fetched, drove, madeNative], [0, 0, 0]);
    // A local target is not preflighted.
    let localAsked = false;
    await recordSdk({
      target: {
        kind: "local",
        project: "demo",
        firestore: { host: "h", port: 1 },
        auth: "http://a",
      },
      run: "r1",
      preflightImpl: async () => {
        localAsked = true;
      },
      runDriverImpl: async () => ({
        receipt: { thrown: null, cleanup: { complete: true }, teardown: [], cases: [] },
        wire: 0,
        connections: 0,
      }),
      makeNative: () => ({
        close() {},
        async listIds() {
          return [];
        },
        async missing() {
          return [];
        },
        async commit() {},
      }),
    });
    assert.equal(localAsked, false);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("both preflight reads are plain GETs that do not follow a redirect and have a live deadline", async () => {
  const stub = preflightFetch();
  await preflight(stub);
  await new Promise((resolve) => setTimeout(resolve, 20));
  for (const { init } of stub.calls) {
    assert.equal(init.method, "GET");
    assert.equal(init.redirect, "manual");
    assert.equal(init.signal.aborted, false, "a deadline of 0 would have passed by now");
  }
  // A redirect answer is not a 200, so it is a failed read.
  await assert.rejects(
    preflight(preflightFetch({ toolkit: [302, {}] })),
    /key read failed \(status 302\)/,
  );
});

test("loadApiKey on a real file: the owner-only file is read as text, a group-readable one is refused", async () => {
  const { chmod, writeFile } = await import("node:fs/promises");
  const { join } = await import("node:path");
  const dir = tempDir("fs-listen-key-");
  const file = join(dir, "key");
  await writeFile(file, `${KEY}\n`);
  await chmod(file, 0o600);
  assert.equal(await loadApiKey(file), KEY);
  await chmod(file, 0o640);
  await assert.rejects(loadApiKey(file), /readable by others/);
  await assert.rejects(loadApiKey(dir), /not a file/);
  await assert.rejects(loadApiKey(join(dir, "missing")), /ENOENT/);
});

test("the key preflight accepts the answers production recorded for both reads", async () => {
  const shapes = JSON.parse(
    readFileSync(new URL("./fs-listen/data/preflight-shapes.json", import.meta.url), "utf8"),
  );
  const toolkit = shapes.identityToolkitProjectsWithKey;
  const crm = shapes.resourceManagerProject;
  const run = (a, b, project = crm.body.projectId) =>
    preflightKey({
      apiKey: KEY,
      project,
      token: "TOK",
      fetchImpl: async (url) => {
        const answer = url.startsWith("https://identitytoolkit.googleapis.com/") ? a : b;
        return { status: answer.status, json: async () => structuredClone(answer.body) };
      },
    });
  assert.deepEqual(await run(toolkit, crm), { projectNumber: crm.body.projectNumber });
  // The members the check reads are strings in the recorded shape: a number-typed projectId fails.
  assert.equal(typeof toolkit.body.projectId, "string");
  assert.equal(typeof crm.body.projectNumber, "string");
  assert.equal(toolkit.body.projectId, crm.body.projectNumber);
  await assert.rejects(
    run({ ...toolkit, body: { ...toolkit.body, projectId: crm.body.projectId } }, crm),
    /no project number/,
  );
  await assert.rejects(run(toolkit, crm, "another-project"), /is not the project/);
});

test("recordSdk: a case whose step threw makes the cleanup incomplete even when every read comes back clean", async () => {
  const target = {
    kind: "local",
    project: "demo",
    firestore: { host: "h", port: 1 },
    auth: "http://a",
  };
  const receipt = (failures) => ({
    thrown: null,
    cleanup: { complete: true },
    teardown: [{ client: "primary", closed: true }],
    cases: completeCases(failures),
  });
  const clean = await recordWith(target, {
    driver: { receipt: receipt([]), wire: 1, connections: 1 },
  });
  assert.equal(clean.recording.cleanup.writesKnown, true);
  assert.equal(clean.recording.cleanup.complete, true);
  const threw = await recordWith(target, {
    driver: { receipt: receipt(["step-threw:unavailable"]), wire: 1, connections: 1 },
  });
  assert.equal(threw.recording.cleanup.writesKnown, false);
  assert.equal(threw.recording.cleanup.complete, false);
});

const PROD = {
  kind: "production",
  project: "fireemu-oracle-query",
  token: "TOK",
  web: { apiKey: "k", authDomain: "d", projectId: "fireemu-oracle-query" },
};
/** One record per case of the catalog, as a complete driver receipt carries; `firstFailures` is the first case's. */
const completeCases = (firstFailures = []) =>
  sdkCases().map((c, i) => ({
    caseId: c.caseId,
    comparedFields: null,
    observed: [],
    failures: i === 0 ? firstFailures : [],
    invariantViolations: [],
  }));

const OKDRIVER = {
  receipt: { thrown: null, cleanup: { complete: true }, teardown: [], cases: completeCases() },
  wire: 5,
  connections: 1,
};
const emptyNative = (extra = {}) => ({
  close() {},
  async listIds() {
    return [];
  },
  async missing(names) {
    return names.map((name) => ({ name, exists: false }));
  },
  async commit() {},
  ...extra,
});

test("ledger 330: a non-empty conf_listen before the run stops it before any account is made, and nothing is deleted", async () => {
  const commits = [];
  const { recording, fetched, drove } = await recordWith(PROD, {
    native: emptyNative({
      listIds: async () => ["projects/p/databases/(default)/documents/conf_listen/someone-else"],
      commit: async (request) => commits.push(request),
    }),
  });
  assert.deepEqual(fetched, [], "no account was made");
  assert.equal(
    drove.some((entry) => entry.config),
    false,
    "the driver never started",
  );
  assert.match(recording.errors["sdk/run"], /conf_listen is not empty before the run/);
  assert.equal(recording.cleanup.complete, false);
  assert.deepEqual(commits, []);
});

test("ledger 330: documents left in conf_listen after the sweep make the cleanup incomplete and are named, not deleted", async () => {
  const left = "projects/p/databases/(default)/documents/conf_listen/stray";
  let listed = 0;
  const commits = [];
  const { recording } = await recordWith(PROD, {
    driver: OKDRIVER,
    native: emptyNative({
      listIds: async ({ prefix }) => (prefix === "" && ++listed === 2 ? [left] : []),
      commit: async (request) => commits.push(request),
    }),
  });
  assert.equal(listed, 2, "listed once before and once after");
  assert.equal(recording.cleanup.complete, false);
  assert.deepEqual(recording.cleanup.documents.confListenLeft, [left]);
  assert.deepEqual(commits, []);
  // Empty before and after: complete.
  const clean = await recordWith(PROD, { driver: OKDRIVER });
  assert.equal(clean.recording.cleanup.documents.confListenLeft, undefined);
  assert.equal(clean.recording.cleanup.complete, true);
});

test("a local recording does not list conf_listen (the emulator starts empty)", async () => {
  const { recording } = await recordWith(
    { kind: "local", project: "demo", firestore: { host: "h", port: 1 }, auth: "http://a" },
    {
      driver: OKDRIVER,
      native: emptyNative({
        listIds: async ({ prefix }) => {
          if (prefix === "") throw new Error("must not list the whole collection");
          return [];
        },
      }),
    },
  );
  assert.equal(recording.cleanup.complete, true);
  assert.equal(recording.productionRequests, null);
});

test("productionRequests counts the preflight, the accounts' calls, the native client's calls and the wire records", async () => {
  const { recording } = await recordWith(PROD, {
    driver: OKDRIVER,
    native: emptyNative({ requestCount: () => 7 }),
  });
  // preflight (recordWith's is a no-op): 0; accounts: 2 creates + 2 deletes + 2 lookups = 6;
  // native: 7; wire: 5.
  assert.equal(recording.productionRequests, 0 + 6 + 7 + 5);
  assert.equal(recording.run, "r1");
  assert.match(recording.endedAt, /^\d{4}-\d\d-\d\dT/);
});

test("the preflight's reads are counted even when it throws, and a driver that dies still reports its wire count", async () => {
  const counted = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => ({ status: 200, json: async () => ({ localId: "u" }) });
  try {
    const { recording } = await (async () => {
      const recorded = await recordSdk({
        target: PROD,
        run: "r1",
        preflightImpl: async ({ onRequest }) => {
          onRequest();
          onRequest();
          counted.push("preflight");
        },
        runDriverImpl: async () => {
          throw Object.assign(new Error("died"), { wire: 11 });
        },
        makeNative: () => emptyNative(),
      });
      return { recording: recorded };
    })();
    assert.equal(recording.productionRequests, 2 + 6 + 0 + 11);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("the SDK run journals the names the cases may write before the driver starts, and an end line with the request count", async () => {
  const lines = [];
  const journal = { append: (record) => lines.push(record), close() {} };
  let linesAtDriver;
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => ({
    status: 200,
    json: async () =>
      url.endsWith("/accounts") ? { localId: `u-${JSON.parse(init.body).email}` } : {},
  });
  try {
    await recordSdk({
      target: PROD,
      run: "r1",
      journal,
      preflightImpl: async () => {},
      runDriverImpl: async () => {
        linesAtDriver = lines.map((line) => line.type);
        return OKDRIVER;
      },
      makeNative: () => emptyNative(),
    });
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.ok(linesAtDriver.includes("names"), "the names were journaled before the driver ran");
  const names = lines.find((line) => line.type === "names").names.map((n) => n.name);
  assert.ok(names.some((name) => name.endsWith("/conf_listen/r1-alpha")));
  assert.ok(names.some((name) => name.includes("/conf_rules_owner/u-fsl-r1-a@example.com")));
  assert.equal(lines.at(-1).type, "end");
  assert.equal(typeof lines.at(-1).productionRequests, "number");
  assert.equal(lines.filter((l) => l.type === "account" && l.phase === "before").length, 2);
});

test("runDriver's rejection carries the wire and connection counts it saw", async () => {
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stdin = new PassThrough();
  child.kill = () => {};
  const promise = runDriver({ config: {}, input: {}, spawnImpl: () => child });
  child.stdout.write('{"event":"wire"}\n{"event":"wire"}\n{"event":"connection"}\n');
  await new Promise((resolve) => setTimeout(resolve, 10));
  child.emit("close", 1);
  await assert.rejects(promise, (error) => error.wire === 2 && error.connections === 1);
});

test("preflightKey reports each read through onRequest when it starts, even one that fails", async () => {
  let counted = 0;
  const onRequest = () => {
    counted += 1;
  };
  await preflight(preflightFetch(), { onRequest });
  assert.equal(counted, 2);
  counted = 0;
  await assert.rejects(preflight(preflightFetch({ toolkit: [500, {}] }), { onRequest }));
  assert.equal(counted, 1, "the read that failed was counted, the second never started");
});

test("productionRequests: an early stop counts only what was sent; a driver without a wire count adds none", async () => {
  // Stopped by a non-empty conf_listen: 0 preflight + 0 accounts + 1 native list + 0 wire... and the sweep.
  let natives = 0;
  const { recording } = await recordWith(PROD, {
    native: emptyNative({
      requestCount: () => 3,
      listIds: async () => ["projects/p/databases/(default)/documents/conf_listen/x"],
    }),
  });
  assert.equal(recording.productionRequests, 3);
  assert.equal(natives, 0);
  // A driver result with no wire field, and a driver error with none either.
  const noWire = await recordWith(PROD, {
    driver: { receipt: OKDRIVER.receipt, connections: 0 },
    native: emptyNative(),
  });
  assert.equal(noWire.recording.productionRequests, 6);
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => ({ status: 200, json: async () => ({ localId: "u" }) });
  try {
    const died = await recordSdk({
      target: PROD,
      run: "r1",
      preflightImpl: async () => {},
      runDriverImpl: async () => {
        throw new Error("died");
      },
      makeNative: () => emptyNative(),
    });
    assert.equal(died.productionRequests, 6);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("a native client without a request counter adds nothing to productionRequests", async () => {
  const { recording } = await recordWith(PROD, { driver: OKDRIVER, native: emptyNative() });
  assert.equal(recording.productionRequests, 6 + 5);
});

test("the journaled names are marked as to be created, before the driver, with the journal's phase", async () => {
  const lines = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => ({
    status: 200,
    json: async () =>
      url.endsWith("/accounts") ? { localId: `u-${JSON.parse(init.body).email}` } : {},
  });
  try {
    await recordSdk({
      target: PROD,
      run: "r1",
      journal: { append: (record) => lines.push(record), close() {} },
      preflightImpl: async () => {},
      runDriverImpl: async () => OKDRIVER,
      makeNative: () => emptyNative(),
    });
  } finally {
    globalThis.fetch = realFetch;
  }
  const names = lines.find((line) => line.type === "names");
  assert.equal(names.phase, "before");
  assert.ok(names.names.every((entry) => entry.op === "create"));
  // These are names the SDK cases may write, not creates the recorder sent: the A2 read-back
  // must not read a missing answer line as an unknown create.
  assert.equal(names.maybe, true);
});

// ---- the A2 read-back of an SDK run whose writes are not known ----

/** Runs recordSdk with a fake accounts API and returns the journal lines it wrote. */
async function sdkJournal(runDriverImpl) {
  const lines = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => ({
    status: 200,
    json: async () =>
      url.endsWith("/accounts") ? { localId: `u-${JSON.parse(init.body).email}` } : {},
  });
  try {
    await recordSdk({
      target: PROD,
      run: "r1",
      journal: { append: (record) => lines.push(record), close() {} },
      preflightImpl: async () => {},
      runDriverImpl,
      makeNative: () => emptyNative(),
    });
  } finally {
    globalThis.fetch = realFetch;
  }
  return lines;
}

const a2 = async (lines) => {
  const { readbackJournal } = await import("./fs-listen/journal.mjs");
  const text = [{ type: "run", runId: "r1", kind: "sdk", project: "p", envelopeId: "E" }, ...lines]
    .map((line) => JSON.stringify(line))
    .join("\n");
  return readbackJournal({
    text,
    client: { missing: async (names) => names.map((name) => ({ name, exists: false })) },
    accountClient: { lookup: async () => [] },
  });
};

const THREW = {
  receipt: {
    thrown: null,
    cleanup: { complete: true },
    teardown: [{ client: "primary", closed: true }],
    cases: [
      {
        caseId: "FS-LISTEN-SDK-101",
        comparedFields: null,
        observed: [],
        failures: ["step-threw:unavailable"],
        invariantViolations: [],
      },
    ],
  },
  wire: 5,
  connections: 1,
};

test("an SDK run whose writes are not known cannot be settled at A2 by finding its names absent: they are unconfirmed", async () => {
  const lines = await sdkJournal(async () => THREW);
  const after = lines.find((line) => line.type === "names" && line.phase === "after");
  assert.equal(after.outcome, "unknown");
  assert.notEqual(after.maybe, true);
  const before = lines.find((line) => line.type === "names" && line.phase === "before");
  assert.deepEqual(after.names, before.names, "every name the cases may have written");
  assert.ok(after.names.length > 0 && after.names.every((n) => n.op === "create"));
  assert.ok(lines.indexOf(after) < lines.findIndex((l) => l.type === "end"), "before the end line");
  const report = await a2(lines);
  assert.equal(report.clean, false);
  assert.deepEqual(report.unconfirmed.toSorted(), before.names.map((n) => n.name).toSorted());
});

test("an SDK run whose driver died without a receipt, or threw, is just as unknown", async () => {
  const dead = await sdkJournal(async () => {
    throw new Error("driver died");
  });
  assert.equal(dead.filter((l) => l.type === "names" && l.phase === "after").length, 1);
  assert.equal((await a2(dead)).clean, false);
  const noReceipt = await sdkJournal(async () => ({ wire: 1, connections: 1 }));
  assert.equal(noReceipt.filter((l) => l.type === "names" && l.phase === "after").length, 1);
  assert.equal((await a2(noReceipt)).clean, false);
});

test("an SDK run whose writes are all known closes its may-exist names with a known line, and settles at A2 when they are absent", async () => {
  const lines = await sdkJournal(async () => OKDRIVER);
  const before = lines.find((l) => l.type === "names" && l.phase === "before");
  const closing = lines.filter((l) => l.type === "names" && l.phase === "after");
  assert.equal(closing.length, 1);
  assert.equal(closing[0].outcome, "known");
  assert.deepEqual(closing[0].names, before.names);
  assert.ok(lines.indexOf(closing[0]) < lines.findIndex((l) => l.type === "end"));
  const report = await a2(lines);
  assert.equal(report.clean, true);
  assert.deepEqual(report.unconfirmed, []);
  // The same run cut after the may-exist line (the recorder killed while the driver ran) is unconfirmed.
  const cut = lines.slice(0, lines.indexOf(before) + 1);
  const crashed = await a2(cut);
  assert.equal(crashed.clean, false);
  assert.deepEqual(crashed.unconfirmed.toSorted(), before.names.map((n) => n.name).toSorted());
});

test("an SDK run that stops before any name is journaled journals no answer for names either", async () => {
  const lines = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => ({ status: 400, json: async () => ({}) });
  try {
    await recordSdk({
      target: PROD,
      run: "r1",
      journal: { append: (record) => lines.push(record), close() {} },
      preflightImpl: async () => {},
      runDriverImpl: async () => OKDRIVER,
      makeNative: () => emptyNative(),
    });
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.equal(lines.filter((l) => l.type === "names").length, 0);
});

test("writesKnown needs a receipt, no thrown value, every case of the catalog recorded, and no step that threw", async () => {
  const full = (patch = {}) => ({
    receipt: {
      thrown: null,
      cleanup: { complete: true },
      teardown: [{ client: "primary", closed: true }],
      cases: completeCases(),
      ...patch,
    },
    wire: 5,
    connections: 1,
  });
  const known = async (driver) =>
    (await sdkJournal(async () => driver)).findLast(
      (l) => l.type === "names" && l.phase === "after",
    );
  assert.equal((await known(full())).outcome, "known");
  // The driver or the collector threw: a case that threw after its steps loses its record and its step-threw.
  assert.equal((await known(full({ thrown: "unsubscribe-failed" }))).outcome, "unknown");
  // One case record missing, with nothing recorded as thrown.
  const missing = completeCases().slice(1);
  assert.equal((await known(full({ cases: missing }))).outcome, "unknown");
  // Too many records is no better than too few.
  assert.equal(
    (await known(full({ cases: [...completeCases(), completeCases()[0]] }))).outcome,
    "unknown",
  );
  // A step that threw.
  const threw = completeCases();
  threw[3].failures = ["step-threw:unavailable"];
  assert.equal((await known(full({ cases: threw }))).outcome, "unknown");
  // And the recording says the same: writesKnown false, cleanup incomplete.
  for (const patch of [{ thrown: "x" }, { cases: missing }]) {
    const { recording } = await recordWith(PROD, { driver: full(patch) });
    assert.equal(recording.cleanup.writesKnown, false);
    assert.equal(recording.cleanup.complete, false);
  }
  const { recording } = await recordWith(PROD, { driver: full() });
  assert.equal(recording.cleanup.writesKnown, true);
});

test("a receipt that is malformed fails closed without throwing: the names close unknown, the accounts are still cleaned up and a recording is returned", async () => {
  for (const receipt of [
    { thrown: null },
    { thrown: null, cases: "none", teardown: [], cleanup: { complete: true } },
    { thrown: null, cases: [{ caseId: "FS-LISTEN-SDK-101" }], teardown: [], cleanup: {} },
  ]) {
    const lines = [];
    const urls = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = async (url, init) => {
      urls.push(url);
      return {
        status: 200,
        json: async () =>
          url.endsWith("/accounts") ? { localId: `u-${JSON.parse(init.body).email}` } : {},
      };
    };
    let recording;
    try {
      recording = await recordSdk({
        target: PROD,
        run: "r1",
        journal: { append: (record) => lines.push(record), close() {} },
        preflightImpl: async () => {},
        runDriverImpl: async () => ({ receipt, wire: 1, connections: 1 }),
        makeNative: () => emptyNative(),
      });
    } finally {
      globalThis.fetch = realFetch;
    }
    const closing = lines.findLast((l) => l.type === "names" && l.phase === "after");
    assert.equal(closing.outcome, "unknown", JSON.stringify(receipt));
    assert.equal(recording.cleanup.writesKnown, false);
    assert.equal(recording.cleanup.complete, false);
    assert.ok(
      urls.some((u) => u.includes("accounts:delete")),
      "the accounts were deleted",
    );
    assert.equal((await a2(lines)).clean, false);
  }
});

test("the cases of a receipt must be the catalog's, each once: the right count with a duplicate and a missing case is unknown", async () => {
  const records = completeCases();
  const duplicated = [...records.slice(0, -1), records[0]];
  const closing = async (cases) =>
    (
      await sdkJournal(async () => ({ ...OKDRIVER, receipt: { ...OKDRIVER.receipt, cases } }))
    ).findLast((l) => l.type === "names" && l.phase === "after");
  assert.equal(duplicated.length, records.length);
  assert.equal((await closing(duplicated)).outcome, "unknown");
  assert.equal((await closing(records)).outcome, "known");
  // The same cases in another order are the same cases.
  assert.equal((await closing(records.toReversed())).outcome, "known");
  // A record without a failures list says nothing about its steps: unknown.
  const noFailures = completeCases();
  delete noFailures[2].failures;
  assert.equal((await closing(noFailures)).outcome, "unknown");
});

test("any thrown value that is not null makes the writes unknown, the empty string included", async () => {
  const closing = async (thrown) =>
    (
      await sdkJournal(async () => ({ ...OKDRIVER, receipt: { ...OKDRIVER.receipt, thrown } }))
    ).findLast((l) => l.type === "names" && l.phase === "after");
  assert.equal((await closing("")).outcome, "unknown");
  assert.equal((await closing("x")).outcome, "unknown");
  assert.equal((await closing(0)).outcome, "unknown");
  assert.equal((await closing(null)).outcome, "known");
  assert.equal((await closing(undefined)).outcome, "known");
  // The recording names the thrown value, also when it is empty.
  const { recording } = await recordWith(PROD, {
    driver: { ...OKDRIVER, receipt: { ...OKDRIVER.receipt, thrown: "" } },
  });
  assert.equal(recording.errors["sdk/driver"], "");
});

test("rowsFromReceipt keeps what a record says, skips a record that is not one, and fills in nothing it was not told", () => {
  const rows = rowsFromReceipt({
    cases: [
      {
        caseId: "FS-LISTEN-SDK-101",
        comparedFields: null,
        observed: [{ a: 1 }],
        failures: ["step-timeout"],
        invariantViolations: ["order"],
      },
      { caseId: "FS-LISTEN-SDK-102" },
      null,
      { observed: [] },
      { caseId: 7 },
    ],
  });
  assert.deepEqual(Object.keys(rows), ["sdk/101", "sdk/102"]);
  assert.deepEqual(rows["sdk/101"].invariantViolations, ["order"]);
  assert.deepEqual(rows["sdk/101"].failures, ["step-timeout"]);
  assert.deepEqual(rows["sdk/101"].observed, [{ a: 1 }]);
  assert.equal(rows["sdk/101"].timedOut, true);
  assert.deepEqual(rows["sdk/102"], {
    conditions: rows["sdk/102"].conditions,
    observed: [],
    failures: [],
    invariantViolations: [],
    end: null,
    timedOut: false,
  });
  assert.deepEqual(rowsFromReceipt({}), {});
  assert.deepEqual(rowsFromReceipt(undefined), {});
});

test("preflightKey with an origin reads the key as a browser at that origin would and needs its domain in the project's authorized domains", async () => {
  const origin = "http://localhost:47853";
  const stub = preflightFetch({
    toolkit: [200, { projectId: NUMBER, authorizedDomains: ["localhost", "demo.web.app"] }],
  });
  assert.deepEqual(await preflight(stub, { origin }), { projectNumber: NUMBER });
  const toolkit = stub.calls.find((c) =>
    c.url.startsWith("https://identitytoolkit.googleapis.com/"),
  );
  assert.equal(toolkit.headers.referer, `${origin}/`);
  const crm = stub.calls.find((c) =>
    c.url.startsWith("https://cloudresourcemanager.googleapis.com/"),
  );
  assert.equal("referer" in crm.headers, false, "the owner's read carries no referer");
  // Without an origin nothing changes: no referer, no domain check.
  const plain = preflightFetch({ toolkit: [200, { projectId: NUMBER, authorizedDomains: [] }] });
  await preflight(plain);
  assert.equal(
    "referer" in
      plain.calls.find((c) => c.url.startsWith("https://identitytoolkit.googleapis.com/")).headers,
    false,
  );
});

test("preflightKey with an origin stops, without naming the key, when the origin's domain is not authorized or the list is unreadable", async () => {
  const origin = "http://localhost:47853";
  const bad = [
    { projectId: NUMBER, authorizedDomains: ["demo.firebaseapp.com", "demo.web.app"] },
    { projectId: NUMBER, authorizedDomains: [] },
    { projectId: NUMBER, authorizedDomains: ["127.0.0.1"] },
    { projectId: NUMBER, authorizedDomains: ["xlocalhost", "localhost.evil.test"] },
    { projectId: NUMBER },
    { projectId: NUMBER, authorizedDomains: "localhost" },
    { projectId: NUMBER, authorizedDomains: [null, 7] },
  ];
  for (const body of bad) {
    await assert.rejects(
      preflight(preflightFetch({ toolkit: [200, body] }), { origin }),
      (error) =>
        /authorized domains/.test(error.message) &&
        !error.message.includes(KEY) &&
        !error.message.includes(NUMBER),
      JSON.stringify(body),
    );
  }
  // The recorded answer lists localhost.
  const recorded = JSON.parse(
    readFileSync(new URL("./fs-listen/data/preflight-shapes.json", import.meta.url), "utf8"),
  ).identityToolkitProjectsWithKey.body;
  assert.ok(recorded.authorizedDomains.includes("localhost"));
});

test("runDriver keeps what the page reported besides the counts (a failed request, a page error; at most 50), on success and on failure", async () => {
  const child = fakeChild();
  const pending = runDriver({ config: {}, input: {}, spawnImpl: () => child });
  child.say({ event: "request-failed", host: "h", path: "/p", reason: "net::ERR" });
  child.say({ event: "page-error", message: "m" });
  child.say({ event: "wire" });
  for (let i = 0; i < 60; i += 1) child.say({ event: "page-error", message: `e${i}` });
  child.say({ event: "receipt", receipt: {} });
  child.end(0);
  const out = await pending;
  assert.equal(out.diagnostics.length, 50);
  assert.deepEqual(out.diagnostics[0], {
    event: "request-failed",
    host: "h",
    path: "/p",
    reason: "net::ERR",
  });
  assert.equal(out.diagnostics[1].event, "page-error");
  const failing = fakeChild();
  const rejected = runDriver({ config: {}, input: {}, spawnImpl: () => failing });
  failing.say({ event: "request-failed", host: "h", path: "/q", reason: "x" });
  failing.end(1);
  await assert.rejects(rejected, (error) => error.diagnostics.length === 1);
});

test("runDriver starts the script it is given", async () => {
  const child = fakeChild();
  let started;
  const pending = runDriver({
    config: {},
    input: {},
    script: "/some/other-driver.mjs",
    spawnImpl: (cmd, args) => {
      started = args;
      return child;
    },
  });
  child.say({ event: "receipt", receipt: {} });
  child.end(0);
  await pending;
  assert.deepEqual(started, ["/some/other-driver.mjs"]);
});
