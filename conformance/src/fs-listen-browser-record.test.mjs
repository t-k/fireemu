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
  L3_IDS,
  L3_PHASES,
} from "./fs-listen/browser-modes.mjs";
import { sdkCases } from "./fs-listen/sdk-cases.mjs";

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
  // One record per case of the catalog, as a complete browser receipt carries.
  cases: [
    ...sdkCases().map((c) => caseRecord(c.caseId)),
    ...L3_IDS.map((id) =>
      caseRecord(`FS-LISTEN-SDK-${id}`, {
        observed: [
          {
            phases: L3_PHASES[id].map((phase) => ({
              phase,
              failures: [],
              errors: [],
              snapshots: [
                {
                  docs: ["alpha", "beta"],
                  fromCache: phase.endsWith("offline"),
                  hasPendingWrites: false,
                },
              ],
            })),
          },
        ],
      }),
    ),
  ],
  l3: {
    seeds: [
      { name: "alpha", acknowledged: true },
      { name: "beta", acknowledged: true },
    ],
    phases: [
      "control-start",
      "before-reload",
      "after-reload",
      "before-close",
      "replacement",
      "control-end",
      "warm",
      "restarted-offline",
      "restarted-online",
      "cold-offline",
      "cold-online",
    ].map((phase) => ({
      phase,
      failures: [],
      snapshots: [
        { docs: ["alpha", "beta"], fromCache: phase.endsWith("offline"), hasPendingWrites: false },
      ],
      errors: [],
    })),
    cleanup: { complete: true },
  },
  teardown: [
    { client: "primary", closed: true },
    { client: "witness", closed: true },
  ],
  ...extra,
});
/** The row ids a complete receipt gives one mode: one `sdk/<id>` per case of the catalog. */
const catalogRows = (prefix) => [
  ...sdkCases().map((c) => `${prefix}/sdk/${c.caseId.replace("FS-LISTEN-SDK-", "")}`),
  ...L3_IDS.map((id) => `${prefix}/sdk/${id}`),
];

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
  assert.deepEqual(Object.keys(rows), catalogRows("browser-long-polling"));
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

const emptyNative = (extra = {}) => {
  const deleted = new Set();
  return {
    close() {},
    async listIds() {
      return [];
    },
    async missing(names) {
      return names.map((name) => ({
        name,
        exists: /-(alpha|beta)$/.test(name) && !deleted.has(name),
      }));
    },
    async commit({ writes }) {
      for (const write of writes) deleted.add(write.delete);
    },
    ...extra,
  };
};

/** Runs recordBrowser with the account routes answered by a stub fetch. */
async function record(target, { driver, native, preflight, journal, modes, log } = {}) {
  const fetched = [];
  const nativeOptions = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const body = JSON.parse(init.body);
    fetched.push({ url, body, headers: init.headers });
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
      log,
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
      makeNative: (options) => {
        nativeOptions.push(options);
        return native ?? emptyNative();
      },
    });
    return { recording, fetched, driven, preflights, nativeOptions };
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
  assert.equal(Object.keys(recording.rows).length, 2 * (sdkCases().length + L3_IDS.length));
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
  assert.deepEqual(Object.keys(recording.rows), catalogRows("browser-streaming"));
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
      sdkCases().length + L3_IDS.length,
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
      missing: async (names) => names.map((name) => ({ name, exists: false })),
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

test("the bounds of a browser recording are the ones the packet states", () => {
  assert.equal(WIRE_CAP, 3000, "browser wire requests per mode (measured locally: 940 and 447)");
  assert.equal(CONNECTION_CAP, 300, "connections (measured locally: 14 per mode)");
});

test("the account calls go to the target's Identity Toolkit with the target's credentials", async () => {
  const prod = await record(PROD);
  assert.equal(prod.fetched.length, 6);
  for (const { url, headers } of prod.fetched) {
    assert.match(
      url,
      /^https:\/\/identitytoolkit\.googleapis\.com\/v1\/projects\/fireemu-oracle-query\/accounts/,
    );
    assert.equal(headers.authorization, "Bearer TOK");
    assert.equal(headers["x-goog-user-project"], "fireemu-oracle-query");
  }
  assert.deepEqual(
    prod.fetched.slice(0, 2).map((f) => f.body.email),
    ["fsl-r1-a@example.com", "fsl-r1-b@example.com"],
  );
  const local = await record(LOCAL);
  for (const { url, headers } of local.fetched) {
    assert.match(
      url,
      /^http:\/\/127\.0\.0\.1:9099\/identitytoolkit\.googleapis\.com\/v1\/projects\/demo\/accounts/,
    );
    assert.equal(headers.authorization, "Bearer owner");
    assert.equal("x-goog-user-project" in headers, false);
  }
});

test("the native client is made for the target: production over TLS with the token, local on the emulator's port", async () => {
  const prod = await record(PROD);
  assert.deepEqual(prod.nativeOptions, [
    { project: "fireemu-oracle-query", target: { kind: "production" }, token: "TOK" },
  ]);
  const local = await record(LOCAL);
  assert.deepEqual(local.nativeOptions, [
    { project: "demo", target: { kind: "local", host: "127.0.0.1", port: 8080 }, token: undefined },
  ]);
});

test("the driver's local configuration: a fake key for a local page, the emulators' addresses, nothing of them for production", async () => {
  const local = await record(LOCAL);
  assert.deepEqual(local.driven[0].config.web, {
    apiKey: "fake-api-key",
    projectId: "demo",
    authDomain: "localhost",
  });
  assert.equal(local.driven[0].config.authEmulator, "http://127.0.0.1:9099");
  const prod = await record(PROD);
  assert.equal("authEmulator" in prod.driven[0].config, false);
  assert.equal("firestoreEmulator" in prod.driven[0].config, false);
});

test("the run says when the accounts exist, and the recording carries its version, SDK and counts", async () => {
  const logs = [];
  const { recording } = await record(LOCAL, { log: (line) => logs.push(line) });
  assert.deepEqual(logs, ["accounts created"]);
  assert.equal(recording.version, 1);
  assert.equal(recording.sdk, "firebase 12.18.0");
  assert.equal(recording.connections, 7);
  const noVersion = await record(LOCAL, {
    driver: { receipt: { modes: {} }, wire: 0 },
  });
  assert.equal(
    noVersion.recording.sdk,
    "firebase 12.18.0",
    "the pinned version when the receipt names none",
  );
  assert.equal(noVersion.recording.connections, 0);
  const named = await record(LOCAL, {
    driver: { receipt: { sdkVersion: "12.99.0", modes: {} }, wire: 0, connections: 2 },
  });
  assert.equal(named.recording.sdk, "firebase 12.99.0");
  assert.equal(named.recording.connections, 2);
});

test("request counts: a native client without a counter adds none, a driver result without a wire count adds none", async () => {
  const { recording } = await record(PROD, {
    driver: { receipt: { modes: {} }, connections: 0 },
    native: emptyNative(),
  });
  assert.equal(recording.requests, 0);
  assert.equal(recording.productionRequests, 2 + 6);
});

test("a thrown value that is not an Error is reported as text, with the wire count it carried or none", async () => {
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => ({
    status: 200,
    json: async () =>
      url.endsWith("/accounts") ? { localId: `u-${JSON.parse(init.body).email}` } : {},
  });
  try {
    for (const [thrown, wire] of [
      ["plain text", 0],
      [{ wire: 9 }, 9],
    ]) {
      const out = await recordBrowser({
        target: LOCAL,
        run: "r1",
        runDriverImpl: async () => {
          throw thrown;
        },
        makeNative: () => emptyNative(),
      });
      assert.equal(
        out.errors["browser/run"],
        typeof thrown === "string" ? "plain text" : "[object Object]",
      );
      assert.equal(out.requests, wire);
      assert.deepEqual(out.diagnostics, []);
    }
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("a sweep that finds a stray, or fails, makes the cleanup incomplete and says why; the native client is closed either way", async () => {
  let closed = 0;
  const stray = await record(LOCAL, {
    native: emptyNative({
      close: () => (closed += 1),
      listIds: async ({ prefix }) =>
        prefix === "r1l"
          ? [`projects/demo/databases/(default)/documents/conf_listen/r1l-stray`]
          : [],
    }),
  });
  assert.equal(stray.recording.cleanup.documents.complete, false);
  assert.equal(stray.recording.cleanup.documents.modes["long-polling"].complete, false);
  assert.equal(stray.recording.cleanup.documents.modes.streaming.complete, true);
  assert.equal(stray.recording.cleanup.complete, false);
  assert.equal(closed, 1);
  const failing = await record(LOCAL, {
    native: emptyNative({
      close: () => (closed += 1),
      missing: async () => {
        throw new Error("read failed");
      },
    }),
  });
  assert.equal(failing.recording.cleanup.documents.complete, false);
  assert.equal(failing.recording.cleanup.documents.error, "read failed");
  assert.equal(failing.recording.cleanup.complete, false);
  assert.equal(closed, 2);
  const nonError = await record(LOCAL, {
    native: emptyNative({
      missing: async () => {
        throw "bare text";
      },
    }),
  });
  assert.equal(nonError.recording.cleanup.documents.error, "bare text");
});

test("an account cleanup that throws is reported, with the message or the value", async () => {
  for (const [thrown, expected] of [
    [new Error("journal full"), "journal full"],
    ["bare", "bare"],
  ]) {
    const out = await record(LOCAL, {
      journal: {
        append(entry) {
          if (entry.type === "account-delete") throw thrown;
        },
        close() {},
      },
    });
    assert.equal(out.recording.cleanup.accounts.complete, false);
    assert.equal(out.recording.cleanup.accounts.error, expected);
    assert.equal(out.recording.cleanup.complete, false);
  }
});

test("a mode result is usable only with a receipt and no error: an error beside a receipt, and a missing receipt, are both errors", async () => {
  const withBoth = { ...modeResult("streaming", "r1"), error: "page crashed" };
  const noReceipt = { mode: "streaming", run: "r1s" };
  for (const [result, message] of [
    [withBoth, "page crashed"],
    [noReceipt, "no result for this mode"],
  ]) {
    const { recording } = await record(LOCAL, {
      driver: {
        receipt: { modes: { "long-polling": modeResult("long-polling", "r1"), streaming: result } },
        wire: 1,
        connections: 1,
      },
    });
    assert.equal(recording.errors["browser/streaming"], message);
    assert.equal(recording.cleanup.sdk.complete, false);
    assert.equal(recording.cleanup.complete, false);
  }
});

test("two transport problems of a mode are both kept", async () => {
  const { recording } = await record(PROD, {
    driver: {
      receipt: {
        modes: {
          "long-polling": modeResult(
            "long-polling",
            "r1",
            modeReceipt(),
            transport("long-polling", { ci: { 0: 2, 7: 1 } }),
          ),
          streaming: modeResult("streaming", "r1"),
        },
      },
      wire: 1,
      connections: 1,
    },
  });
  assert.equal(
    recording.errors["browser/long-polling/transport"],
    "long-polling: no Listen channel request with CI=1; long-polling: a Listen channel request carried CI=0; long-polling: a Listen channel request carried CI=7",
  );
});

test("runBrowserDriver starts the browser driver with the recording's timeout and passes the caller's options through", async () => {
  const { runBrowserDriver } = await import("./fs-listen/browser-record.mjs");
  const { EventEmitter } = await import("node:events");
  const { PassThrough } = await import("node:stream");
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stdin = new PassThrough();
  child.kill = () => {};
  let seen;
  const pending = runBrowserDriver({
    config: { c: 1 },
    input: { i: 1 },
    spawnImpl: (cmd, args, options) => {
      seen = { cmd, args, options };
      return child;
    },
  });
  child.stdout.write(JSON.stringify({ event: "receipt", receipt: { ok: true } }) + "\n");
  await new Promise((resolve) => setTimeout(resolve, 5));
  child.emit("close", 0);
  const out = await pending;
  assert.equal(seen.cmd, process.execPath);
  assert.match(seen.args[0], /\/fs-listen\/browser-driver\.mjs$/);
  assert.deepEqual(JSON.parse(seen.options.env.AFC_SDK_CONFIG), { c: 1 });
  assert.deepEqual(out.receipt, { ok: true });
});

// ---- the A2 read-back of a browser run whose writes are not known (the same rule as the SDK part) ----

const browserA2 = async (lines) => {
  const { readbackJournal } = await import("./fs-listen/journal.mjs");
  const text = [
    { type: "run", runId: "r1", kind: "browser", project: "fireemu-oracle-query" },
    ...lines,
  ]
    .map((line) => JSON.stringify(line))
    .join("\n");
  return readbackJournal({
    text,
    client: { missing: async (names) => names.map((name) => ({ name, exists: false })) },
    accountClient: { lookup: async () => [] },
  });
};

test("a browser run whose writes are all known closes its may-exist names with a known line and settles at A2 when they are absent; cut after the maybe line it is unconfirmed", async () => {
  const lines = [];
  await record(PROD, { journal: { append: (entry) => lines.push(entry), close() {} } });
  const before = lines.find((line) => line.type === "names" && line.phase === "before");
  assert.equal(before.maybe, true);
  const closing = lines.filter((l) => l.type === "names" && l.phase === "after");
  assert.equal(closing.length, 1);
  assert.equal(closing[0].outcome, "known");
  assert.deepEqual(closing[0].names, before.names);
  assert.ok(lines.indexOf(closing[0]) < lines.findIndex((l) => l.type === "end"));
  const report = await browserA2(lines);
  assert.equal(report.clean, true);
  assert.deepEqual(report.unconfirmed, []);
  // The recorder killed while the driver ran: the journal ends at the maybe line.
  const crashed = await browserA2(lines.slice(0, lines.indexOf(before) + 1));
  assert.equal(crashed.clean, false);
  assert.equal(crashed.unconfirmed.length, 12);
});

test("a browser run whose writes are not known (a mode failed or had no result, a step threw, the receipt threw or lost a case record, the driver died) closes its names unknown, so absence at A2 does not settle them", async () => {
  const threw = modeReceipt();
  threw.cases[0] = { ...threw.cases[0], failures: ["step-threw:unavailable"] };
  const lostRecord = modeReceipt({ cases: modeReceipt().cases.slice(1) });
  for (const modes of [
    {
      "long-polling": modeResult("long-polling", "r1"),
      streaming: { mode: "streaming", error: "browser run exceeded its deadline" },
    },
    { "long-polling": modeResult("long-polling", "r1") },
    {
      "long-polling": modeResult("long-polling", "r1", threw),
      streaming: modeResult("streaming", "r1"),
    },
    {
      "long-polling": modeResult(
        "long-polling",
        "r1",
        modeReceipt({ thrown: "unsubscribe-failed" }),
      ),
      streaming: modeResult("streaming", "r1"),
    },
    {
      "long-polling": modeResult("long-polling", "r1"),
      streaming: modeResult("streaming", "r1", lostRecord),
    },
  ]) {
    const lines = [];
    await record(PROD, {
      journal: { append: (entry) => lines.push(entry), close() {} },
      driver: { receipt: { modes }, wire: 3, connections: 1 },
    });
    const before = lines.find((l) => l.type === "names" && l.phase === "before");
    const after = lines.find((l) => l.type === "names" && l.phase === "after");
    assert.equal(after.outcome, "unknown");
    assert.notEqual(after.maybe, true);
    assert.deepEqual(after.names, before.names);
    assert.ok(lines.indexOf(after) < lines.findIndex((l) => l.type === "end"));
    const report = await browserA2(lines);
    assert.equal(report.clean, false);
    assert.equal(report.unconfirmed.length, 12);
  }
  // A driver that threw leaves no receipt at all: the same.
  const lines = [];
  await record(PROD, {
    journal: { append: (entry) => lines.push(entry), close() {} },
    driver: async () => {
      throw new Error("browser died");
    },
  });
  assert.equal(lines.filter((l) => l.type === "names" && l.phase === "after").length, 1);
  assert.equal(lines.findLast((l) => l.type === "names").outcome, "unknown");
  assert.equal((await browserA2(lines)).clean, false);
});

test("a browser run that stops before its names are journaled journals no closing line either", async () => {
  const lines = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => ({ status: 400, json: async () => ({}) });
  try {
    await recordBrowser({
      target: PROD,
      run: "r1",
      journal: { append: (entry) => lines.push(entry), close() {} },
      preflightImpl: async () => {},
      runDriverImpl: async () => ({ receipt: { modes: {} }, wire: 0, connections: 0 }),
      makeNative: () => emptyNative(),
    });
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.equal(lines.filter((l) => l.type === "names").length, 0);
});

test("confirmed L3 seeds that read absent remain unsettled in the recording", async () => {
  const out = await record(PROD, {
    native: emptyNative({
      missing: async (names) => names.map((name) => ({ name, exists: false })),
    }),
  });
  assert.equal(out.recording.cleanup.complete, false);
  assert.equal(out.recording.cleanup.documents.modes.streaming.unsettled.length, 2);
  assert.equal(out.recording.cleanup.documents.modes["long-polling"].unsettled.length, 2);
});

test("only acknowledged alpha and beta seeds become confirmed writes", async () => {
  for (const seeds of [
    [{ name: "alpha", acknowledged: false }],
    [{ name: "other", acknowledged: true }],
    [null],
  ]) {
    const { recording } = await record(LOCAL, {
      modes: ["streaming"],
      driver: {
        receipt: {
          modes: { streaming: modeResult("streaming", "r1", modeReceipt({ l3: { seeds } })) },
        },
      },
      native: emptyNative({
        missing: async (names) => names.map((name) => ({ name, exists: false })),
      }),
    });
    assert.equal(recording.cleanup.documents.complete, true);
    assert.deepEqual(recording.cleanup.documents.modes.streaming.unsettled, []);
  }
});

test("browserRows carries callback evidence separately for each transport", () => {
  const rawEvents = [
    { docs: ["alpha"], fromCache: true, hasPendingWrites: false, changes: [] },
    { docs: ["alpha"], fromCache: false, hasPendingWrites: false, changes: [] },
  ];
  const rows = browserRows({
    "long-polling": {
      receipt: {
        cases: [caseRecord("FS-LISTEN-SDK-111", { rawEvents, rawEventCount: 2, baselineAt: 1 })],
      },
    },
    streaming: { receipt: { cases: [caseRecord("FS-LISTEN-SDK-111")] } },
  });
  assert.deepEqual(rows["browser-long-polling/sdk/111"].rawEvents, rawEvents);
  assert.equal(rows["browser-long-polling/sdk/111"].baselineAt, 1);
  assert.equal(rows["browser-long-polling/sdk/111"].rawEventCount, 2);
  assert.equal(Object.hasOwn(rows["browser-streaming/sdk/111"], "rawEvents"), false);
  assert.equal(Object.hasOwn(rows["browser-streaming/sdk/111"], "baselineAt"), false);
});
