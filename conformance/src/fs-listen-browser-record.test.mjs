import assert from "node:assert/strict";
import { test } from "node:test";

import {
  CONNECTION_CAP,
  DRIVER_TIMEOUT_MS,
  WIRE_CAP,
  browserRows,
  namesOf,
  recordBrowser,
  transportProblems,
} from "./fs-listen/browser-record.mjs";
import {
  EXPECTED_CI,
  MODES,
  MODE_SETTINGS,
  MODE_SUFFIX,
  modeRun,
} from "./fs-listen/browser-modes.mjs";

const PROD = {
  kind: "production",
  project: "fireemu-oracle-query",
  token: "TOK",
  originPort: 47853,
  web: { apiKey: "k", authDomain: "d", projectId: "fireemu-oracle-query" },
};
const LOCAL = {
  kind: "local",
  project: "demo",
  originPort: 47853,
  firestore: { host: "127.0.0.1", port: 8080 },
  auth: "http://127.0.0.1:9099",
};

test("the modes: two WebChannel transports, each with its settings, its CI and a run id of its own", () => {
  assert.deepEqual(MODES, ["long-polling", "streaming"]);
  assert.deepEqual(MODE_SETTINGS["long-polling"], { experimentalForceLongPolling: true });
  assert.deepEqual(MODE_SETTINGS.streaming, {
    experimentalForceLongPolling: false,
    experimentalAutoDetectLongPolling: false,
  });
  assert.deepEqual(EXPECTED_CI, { "long-polling": "1", streaming: "0" });
  assert.deepEqual(MODE_SUFFIX, { "long-polling": "l", streaming: "s" });
  assert.equal(modeRun("nabc", "long-polling"), "nabcl");
  assert.equal(modeRun("nabc", "streaming"), "nabcs");
  assert.throws(() => modeRun("nabc", "websocket"), /unknown browser transport mode/);
});

test("transportProblems: the mode is shown by its own CI on the backchannel and by no other, the forward channel's missing CI is ignored", () => {
  assert.deepEqual(transportProblems("long-polling", { ci: { 1: 455, none: 326 } }), []);
  assert.deepEqual(transportProblems("streaming", { ci: { 0: 6, none: 326 } }), []);
  assert.deepEqual(transportProblems("streaming", { ci: { 0: 6, 1: 2 } }), [
    "streaming: a Listen channel request carried CI=1",
  ]);
  assert.deepEqual(transportProblems("long-polling", { ci: { none: 3 } }), [
    "long-polling: no Listen channel request with CI=1",
  ]);
  assert.deepEqual(transportProblems("long-polling", { ci: { 0: 4, 1: 1 } }), [
    "long-polling: a Listen channel request carried CI=0",
  ]);
  assert.equal(transportProblems("streaming", {}).length, 1);
  assert.equal(transportProblems("streaming", undefined).length, 1);
  assert.equal(transportProblems("streaming", { ci: { 0: 0 } }).length, 1);
});

const caseRecord = (caseId, extra = {}) => ({
  caseId,
  role: "case",
  comparison: "x",
  complete: true,
  failures: [],
  observed: [{ a: 1 }],
  comparedFields: ["a"],
  invariantViolations: [],
  listenersClosed: true,
  rawEventCount: 1,
  ...extra,
});
const modeReceipt = (extra = {}) => ({
  thrown: null,
  cleanup: { complete: true },
  cleanupPasses: [],
  budget: {},
  cases: [caseRecord("FS-LISTEN-SDK-101"), caseRecord("FS-LISTEN-SDK-104C")],
  teardown: [
    { client: "primary", closed: true },
    { client: "witness", closed: true },
  ],
  ...extra,
});
const transport = (mode, extra = {}) => ({
  requests: 10,
  listenChannel: 5,
  ci: { [EXPECTED_CI[mode]]: 3, none: 2 },
  connections: 4,
  ...extra,
});
const modeResult = (mode, run, receipt = modeReceipt(), t = transport(mode)) => ({
  mode,
  run: modeRun(run, mode),
  receipt,
  transport: t,
});

test("browserRows prefixes each row with its transport and skips a mode with no receipt", () => {
  const rows = browserRows({
    "long-polling": modeResult("long-polling", "r"),
    streaming: { mode: "streaming", error: "x" },
  });
  assert.deepEqual(Object.keys(rows), [
    "browser-long-polling/sdk/101",
    "browser-long-polling/sdk/104C",
  ]);
  assert.deepEqual(rows["browser-long-polling/sdk/101"].conditions, [
    "FS-LISTEN-SDK/document-event-order",
  ]);
  assert.deepEqual(browserRows({}), {});
});

test("namesOf lists each mode's five public documents once and the owner documents once", () => {
  const accounts = { a: { uid: "ua" }, b: { uid: "ub" } };
  const names = namesOf({ project: "p", run: "r", modes: MODES, accounts });
  const root = "projects/p/databases/(default)/documents";
  assert.equal(names.length, 5 + 5 + 2);
  assert.ok(names.includes(`${root}/conf_listen/rl-alpha`));
  assert.ok(names.includes(`${root}/conf_listen/rs-absent`));
  assert.equal(names.filter((n) => n.includes("conf_rules_owner/ua")).length, 1);
  assert.equal(namesOf({ project: "p", run: "r", modes: ["streaming"], accounts }).length, 5 + 2);
});

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

/** Runs recordBrowser with the account routes answered by a stub fetch. */
async function record(target, { driver, native, preflight, journal, modes } = {}) {
  const fetched = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const body = JSON.parse(init.body);
    fetched.push({ url, body });
    return {
      status: 200,
      json: async () => (url.endsWith("/accounts") ? { localId: `u-${body.email}` } : {}),
    };
  };
  const driven = [];
  const preflights = [];
  try {
    const recording = await recordBrowser({
      target,
      run: "r1",
      modes,
      journal,
      preflightImpl: async (request) => {
        preflights.push(request);
        request.onRequest?.();
        request.onRequest?.();
        await preflight?.(request);
      },
      runDriverImpl: async (request) => {
        driven.push(request);
        if (typeof driver === "function") return driver(request);
        return (
          driver ?? {
            receipt: {
              sdkVersion: "12.18.0",
              modes: {
                "long-polling": modeResult("long-polling", "r1"),
                streaming: modeResult("streaming", "r1"),
              },
            },
            wire: 100,
            connections: 7,
            diagnostics: [{ event: "page-error", message: "m" }],
          }
        );
      },
      makeNative: () => native ?? emptyNative(),
    });
    return { recording, fetched, driven, preflights };
  } finally {
    globalThis.fetch = realFetch;
  }
}

test("a clean production recording: rows of both modes, bounded driver, preflight with the origin, exact request count", async () => {
  const { recording, driven, preflights } = await record(PROD, {
    native: emptyNative({ requestCount: () => 11 }),
  });
  assert.equal(recording.kind, "browser");
  assert.equal(recording.run, "r1");
  assert.deepEqual(recording.modes, MODES);
  assert.equal(recording.cleanup.complete, true);
  assert.deepEqual(recording.errors, {});
  assert.equal(Object.keys(recording.rows).length, 4);
  assert.equal(recording.requests, 100);
  assert.equal(recording.connections, 7);
  // preflight 2 + accounts (2 creates, 2 deletes, 2 lookups) 6 + native 11 + wire 100.
  assert.equal(recording.productionRequests, 2 + 6 + 11 + 100);
  assert.equal(preflights.length, 1);
  assert.equal(preflights[0].origin, "http://localhost:47853");
  assert.equal(preflights[0].apiKey, "k");
  assert.equal(driven.length, 1);
  const [{ config, input }] = driven;
  assert.equal(config.mode, "production");
  assert.equal(config.wireCap, WIRE_CAP);
  assert.equal(config.connectionCap, CONNECTION_CAP);
  assert.equal(config.originPort, 47853);
  assert.deepEqual(config.web, PROD.web);
  assert.deepEqual(input.modes, MODES);
  assert.equal(input.run, "r1");
  assert.equal(input.accounts.a.uid, "u-fsl-r1-a@example.com");
  assert.deepEqual(recording.diagnostics, [{ event: "page-error", message: "m" }]);
  assert.deepEqual(Object.keys(recording.transport), MODES);
  assert.equal(recording.transport.streaming.run, "r1s");
  assert.equal(recording.issued.length, 12);
  assert.equal(DRIVER_TIMEOUT_MS, 50 * 60_000);
});

test("a local recording is not preflighted and has no production request count", async () => {
  const { recording, preflights, driven } = await record(LOCAL);
  assert.deepEqual(preflights, []);
  assert.equal(recording.productionRequests, null);
  assert.equal(driven[0].config.mode, "local");
  assert.equal(driven[0].config.authEmulator, LOCAL.auth);
  assert.deepEqual(driven[0].config.firestoreEmulator, LOCAL.firestore);
  assert.equal(driven[0].config.web.apiKey, "fake-api-key");
});

test("one mode only: its row prefix, its sweep and its transport", async () => {
  const swept = [];
  const { recording } = await record(LOCAL, {
    modes: ["streaming"],
    driver: {
      receipt: { modes: { streaming: modeResult("streaming", "r1") } },
      wire: 1,
      connections: 1,
    },
    native: emptyNative({
      listIds: async ({ prefix }) => {
        swept.push(prefix);
        return [];
      },
    }),
  });
  assert.deepEqual(Object.keys(recording.rows), [
    "browser-streaming/sdk/101",
    "browser-streaming/sdk/104C",
  ]);
  assert.deepEqual(Object.keys(recording.cleanup.documents.modes), ["streaming"]);
  assert.ok(swept.every((prefix) => prefix === "r1s"));
  assert.equal(recording.cleanup.complete, true);
});

test("the names the run may write are journaled before the driver starts, and an end line follows", async () => {
  const lines = [];
  let typesAtDriver;
  await record(PROD, {
    journal: { append: (entry) => lines.push(entry), close() {} },
    driver: async () => {
      typesAtDriver = lines.map((line) => line.type);
      return { receipt: { modes: {} }, wire: 0, connections: 0 };
    },
  });
  assert.ok(typesAtDriver.includes("names"), "journaled before the driver ran");
  const names = lines.find((line) => line.type === "names");
  assert.equal(names.phase, "before");
  assert.equal(names.names.length, 12);
  assert.ok(names.names.every((n) => n.op === "create"));
  assert.equal(lines.at(-1).type, "end");
  assert.equal(typeof lines.at(-1).productionRequests, "number");
});

test("a mode that failed, or has no result, is an error and an incomplete cleanup; the other mode's rows stay", async () => {
  for (const modes of [
    {
      "long-polling": modeResult("long-polling", "r1"),
      streaming: { mode: "streaming", error: "browser run exceeded its deadline" },
    },
    { "long-polling": modeResult("long-polling", "r1") },
  ]) {
    const { recording } = await record(PROD, {
      driver: { receipt: { modes }, wire: 3, connections: 1 },
    });
    assert.match(recording.errors["browser/streaming"], /deadline|no result/);
    assert.equal(recording.cleanup.complete, false);
    assert.equal(recording.cleanup.clientsClosed, false);
    assert.equal(recording.cleanup.writesKnown, false);
    assert.deepEqual(
      Object.keys(recording.rows).filter((k) => k.startsWith("browser-streaming")),
      [],
    );
    assert.equal(
      Object.keys(recording.rows).filter((k) => k.startsWith("browser-long-polling")).length,
      2,
    );
  }
});

test("a mode whose receipt threw, whose clients did not close, whose cleanup is incomplete or whose writes threw is not clean", async () => {
  const cases = [
    [
      modeReceipt({ thrown: "permission-denied" }),
      (r) => assert.equal(r.errors["browser/streaming/driver"], "permission-denied"),
    ],
    [
      modeReceipt({ teardown: [{ client: "primary", closed: false }] }),
      (r) => assert.equal(r.cleanup.clientsClosed, false),
    ],
    [
      modeReceipt({ cleanup: { complete: false } }),
      (r) => assert.equal(r.cleanup.sdk.complete, false),
    ],
    [
      modeReceipt({ cases: [caseRecord("FS-LISTEN-SDK-101", { failures: ["step-threw:x"] })] }),
      (r) => assert.equal(r.cleanup.writesKnown, false),
    ],
  ];
  for (const [receipt, check] of cases) {
    const { recording } = await record(PROD, {
      driver: {
        receipt: {
          modes: {
            "long-polling": modeResult("long-polling", "r1"),
            streaming: modeResult("streaming", "r1", receipt),
          },
        },
        wire: 1,
        connections: 1,
      },
    });
    check(recording);
    // A thrown case is an error of the recording (the comparer refuses it); the other three make
    // the cleanup itself incomplete.
    if (!recording.errors["browser/streaming/driver"])
      assert.equal(recording.cleanup.complete, false);
  }
});

test("a mode whose transport evidence does not show the mode is an error", async () => {
  const { recording } = await record(PROD, {
    driver: {
      receipt: {
        modes: {
          "long-polling": modeResult(
            "long-polling",
            "r1",
            modeReceipt(),
            transport("long-polling", { ci: { none: 9 } }),
          ),
          streaming: modeResult("streaming", "r1"),
        },
      },
      wire: 1,
      connections: 1,
    },
  });
  assert.match(
    recording.errors["browser/long-polling/transport"],
    /no Listen channel request with CI=1/,
  );
  assert.equal("browser/streaming/transport" in recording.errors, false);
});

test("ledger 330: a non-empty conf_listen stops a production recording before any account, a leftover makes the cleanup incomplete, a local run does not look", async () => {
  const commits = [];
  const blocked = await record(PROD, {
    native: emptyNative({
      listIds: async () => ["projects/p/databases/(default)/documents/conf_listen/x"],
      commit: async (request) => commits.push(request),
    }),
  });
  assert.deepEqual(blocked.fetched, []);
  assert.deepEqual(blocked.driven, []);
  assert.match(blocked.recording.errors["browser/run"], /conf_listen is not empty before the run/);
  assert.equal(blocked.recording.cleanup.complete, false);
  assert.deepEqual(commits, []);
  let listed = 0;
  const left = await record(PROD, {
    native: emptyNative({
      listIds: async ({ prefix }) => (prefix === "" && ++listed === 2 ? ["left"] : []),
    }),
  });
  assert.deepEqual(left.recording.cleanup.documents.confListenLeft, ["left"]);
  assert.equal(left.recording.cleanup.complete, false);
  const local = await record(LOCAL, {
    native: emptyNative({
      listIds: async ({ prefix }) => {
        if (prefix === "") throw new Error("must not list");
        return [];
      },
    }),
  });
  assert.equal(local.recording.cleanup.complete, true);
});

test("a failed preflight stops everything before an account is made", async () => {
  const fetchedBefore = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    fetchedBefore.push(1);
    return { status: 200, json: async () => ({}) };
  };
  try {
    await assert.rejects(
      recordBrowser({
        target: PROD,
        run: "r1",
        preflightImpl: async () => {
          throw new Error("the origin's domain is not among the project's authorized domains");
        },
        runDriverImpl: async () => {
          throw new Error("must not run");
        },
        makeNative: () => {
          throw new Error("must not be made");
        },
      }),
      /authorized domains/,
    );
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.deepEqual(fetchedBefore, []);
});

test("a driver that dies reports what it saw: its wire count and its diagnostics", async () => {
  const { recording } = await record(PROD, {
    driver: undefined,
  });
  assert.equal(recording.requests, 100);
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => ({
    status: 200,
    json: async () =>
      url.endsWith("/accounts") ? { localId: `u-${JSON.parse(init.body).email}` } : {},
  });
  try {
    const died = await recordBrowser({
      target: LOCAL,
      run: "r1",
      runDriverImpl: async () => {
        throw Object.assign(new Error("died"), {
          wire: 12,
          diagnostics: [{ event: "page-error" }],
        });
      },
      makeNative: () => emptyNative(),
    });
    assert.equal(died.requests, 12);
    assert.match(died.errors["browser/run"], /died/);
    assert.deepEqual(died.diagnostics, [{ event: "page-error" }]);
    assert.equal(died.cleanup.complete, false);
  } finally {
    globalThis.fetch = realFetch;
  }
});
