import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  CLEANUP_LIMITS,
  CLEANUP_MS,
  DEADLINE_MS,
  LIMITS,
  buildReceipt,
  runPaths,
  runSdkCatalog,
  teardownClients,
} from "./fs-listen/sdk-run.mjs";

const accounts = {
  a: { email: "a@example.com", password: "pa", uid: "ua" },
  b: { email: "b@example.com", password: "pb", uid: "ub" },
};

test("the paths of a run: five public documents named with the run id, and the two owner documents", () => {
  assert.deepEqual(runPaths("r1", accounts), {
    run: "conf_listen",
    alpha: "conf_listen/r1-alpha",
    beta: "conf_listen/r1-beta",
    gamma: "conf_listen/r1-gamma",
    delta: "conf_listen/r1-delta",
    absent: "conf_listen/r1-absent",
    private: "conf_rules_owner/ua",
    privateB: "conf_rules_owner/ub",
  });
});

test("the bounds of a recording", () => {
  assert.deepEqual(LIMITS, {
    reads: 900,
    writes: 120,
    deletes: 120,
    snapshots: 300,
    listeners: 60,
  });
  assert.deepEqual(CLEANUP_LIMITS, {
    reads: 300,
    writes: 0,
    deletes: 150,
    snapshots: 0,
    listeners: 0,
  });
  assert.equal(DEADLINE_MS, 15 * 60_000);
  assert.equal(CLEANUP_MS, 3 * 60_000);
});

const record = (caseId, extra = {}) => ({
  caseId,
  role: "case",
  comparison: "x",
  complete: true,
  failures: [],
  observed: [{ a: 1 }],
  comparedFields: ["a"],
  invariantViolations: [],
  listenersClosed: true,
  rawEventCount: 3,
  secret: "must not appear",
  ...extra,
});

test("buildReceipt keeps the fields of a case record and nothing else, and falls back when there is no outcome", () => {
  const budget = { snapshot: () => ({ reads: 1 }) };
  const receipt = buildReceipt({
    thrown: null,
    outcome: {
      thrown: "late",
      cleanup: { complete: true },
      cleanupPasses: [1],
      caseRecords: [record("c1")],
    },
    budget,
    teardown: [{ client: "primary", closed: true }],
  });
  assert.equal(receipt.thrown, "late");
  assert.deepEqual(receipt.cleanup, { complete: true });
  assert.deepEqual(receipt.cleanupPasses, [1]);
  assert.deepEqual(receipt.budget, { reads: 1 });
  assert.equal("secret" in receipt.cases[0], false);
  assert.equal(receipt.cases[0].rawEventCount, 3);
  assert.deepEqual(Object.keys(receipt.cases[0]).toSorted(), [
    "caseId",
    "comparedFields",
    "comparison",
    "complete",
    "failures",
    "invariantViolations",
    "listenersClosed",
    "observed",
    "rawEventCount",
    "role",
  ]);
  // The driver's own thrown wins over the outcome's; no outcome gives an incomplete cleanup.
  const empty = buildReceipt({ thrown: "boom", outcome: undefined, budget, teardown: [] });
  assert.equal(empty.thrown, "boom");
  assert.deepEqual(empty.cleanup, { complete: false });
  assert.deepEqual(empty.cleanupPasses, []);
  assert.deepEqual(empty.cases, []);
  assert.equal(
    buildReceipt({ thrown: null, outcome: undefined, budget, teardown: [] }).thrown,
    null,
  );
});

test("teardownClients closes every client and says which could not be closed", async () => {
  const calls = [];
  const sdk = {
    async terminate(db) {
      calls.push(["terminate", db]);
      if (db === "bad") throw new Error("x");
    },
    async deleteApp(app) {
      calls.push(["deleteApp", app]);
    },
  };
  const out = await teardownClients(sdk, {
    primary: { db: "d1", app: "a1" },
    witness: { db: "bad", app: "a2" },
  });
  assert.deepEqual(out, [
    { client: "primary", closed: true },
    { client: "witness", closed: false },
  ]);
  assert.deepEqual(calls, [
    ["terminate", "d1"],
    ["deleteApp", "a1"],
    ["terminate", "bad"],
  ]);
});

/** A collector that records the options of the run it is given. */
function fakeCollector(seen, { fail } = {}) {
  return {
    createBudget: (options) => {
      seen.budgets.push(options);
      return { snapshot: () => ({ kind: "budget" }) };
    },
    createRecoveryBudget: (options) => {
      seen.recovery.push(options);
      return { snapshot: () => ({ kind: "recovery" }) };
    },
    runCatalog: async (deps, options) => {
      seen.run = { deps, options };
      if (fail) throw Object.assign(new Error("m"), { code: fail });
      return { caseRecords: [record("c1")], cleanup: { complete: true }, cleanupPasses: [] };
    },
  };
}

test("runSdkCatalog signs the second principal in, runs the catalog with the run's paths and closes the clients", async () => {
  const seen = { budgets: [], recovery: [] };
  const calls = [];
  const sdk = {
    signInWithEmailAndPassword: async (auth, email, password) =>
      calls.push(["signIn", auth, email, password]),
    terminate: async (db) => calls.push(["terminate", db]),
    deleteApp: async (app) => calls.push(["deleteApp", app]),
  };
  const clients = {
    primary: { db: "d1", app: "a1", auth: "x1" },
    witness: { db: "d2", app: "a2", auth: "x2" },
    secondary: { db: "d3", app: "a3", auth: "x3" },
  };
  const deps = { marker: true };
  const receipt = await runSdkCatalog({
    sdk,
    collector: fakeCollector(seen),
    clients,
    deps,
    run: "r1",
    accounts,
    cases: [{ caseId: "c1" }],
    now: () => 5,
  });
  assert.deepEqual(calls[0], ["signIn", "x3", "b@example.com", "pb"]);
  assert.equal(seen.run.deps, deps);
  const { options } = seen.run;
  assert.deepEqual(options.catalog, { cases: [{ caseId: "c1" }] });
  assert.equal(options.nonce, "r1");
  assert.equal(options.client, "primary");
  assert.deepEqual(options.clientFor, { privateB: "secondary" });
  assert.equal(
    "private" in options.paths,
    false,
    "the read-only private document is not cleaned up",
  );
  assert.equal(options.paths.privateB, "conf_rules_owner/ub");
  const context = options.contextFor();
  assert.equal(context.nonce, "r1");
  assert.equal(context.client, "primary");
  assert.deepEqual(context.clients, {
    primary: "primary",
    witness: "witness",
    secondary: "secondary",
  });
  assert.equal(context.stepTimeoutMs, 20_000);
  assert.equal(context.pollMs, 100);
  assert.equal(context.paths.private, "conf_rules_owner/ua");
  assert.equal(context.nameOf("conf_listen/r1-alpha"), "alpha");
  assert.equal(context.nameOf("conf_listen/other"), "<other>");
  assert.equal(context.budget, options.budget);
  assert.deepEqual(seen.budgets[0].limits, LIMITS);
  assert.equal(seen.budgets[0].deadlineMs, DEADLINE_MS);
  assert.equal(seen.budgets[0].now(), 5);
  assert.deepEqual(seen.recovery[0].limits, CLEANUP_LIMITS);
  assert.equal(seen.recovery[0].deadlineMs, CLEANUP_MS);
  assert.deepEqual(
    receipt.teardown.map((t) => t.closed),
    [true, true, true],
  );
  assert.equal(receipt.thrown, null);
  assert.equal(receipt.cases.length, 1);
  assert.deepEqual(receipt.budget, { kind: "budget" });
});

test("runSdkCatalog reports what the collector threw by its code or message, and still closes the clients", async () => {
  for (const [thrown, expected] of [[{ code: "permission-denied" }, "permission-denied"]]) {
    const seen = { budgets: [], recovery: [] };
    const closed = [];
    const receipt = await runSdkCatalog({
      sdk: {
        signInWithEmailAndPassword: async () => {},
        terminate: async (db) => closed.push(db),
        deleteApp: async () => {},
      },
      collector: fakeCollector(seen, { fail: thrown.code }),
      clients: { primary: { db: "d1" }, secondary: { db: "d3", auth: "x" } },
      deps: {},
      run: "r1",
      accounts,
      cases: [],
      now: () => 0,
    });
    assert.equal(receipt.thrown, expected);
    assert.deepEqual(closed, ["d1", "d3"]);
    assert.deepEqual(receipt.cleanup, { complete: false });
  }
  // A failed sign-in of the second principal is reported the same way and nothing runs.
  const seen = { budgets: [], recovery: [] };
  const receipt = await runSdkCatalog({
    sdk: {
      signInWithEmailAndPassword: async () => {
        throw new Error("no sign-in");
      },
      terminate: async () => {},
      deleteApp: async () => {},
    },
    collector: fakeCollector(seen),
    clients: { primary: { db: "d1" }, secondary: { db: "d3", auth: "x" } },
    deps: {},
    run: "r1",
    accounts,
    cases: [],
    now: () => 0,
  });
  assert.equal(receipt.thrown, "no sign-in");
  assert.equal(seen.run, undefined);
});

test("sdk-run.mjs and the core import nothing, so a page can load them", () => {
  for (const file of ["sdk-run.mjs", "sdk-deps-core.mjs"]) {
    const source = readFileSync(new URL(`./fs-listen/${file}`, import.meta.url), "utf8");
    const imports = source.match(/^\s*import\s.*$/gm) ?? [];
    for (const line of imports)
      assert.match(line, /from "\.\/sdk-deps-core\.mjs"/, `${file}: ${line}`);
    assert.equal(/node:/.test(source), false);
  }
});
