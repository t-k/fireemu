// The production sequence of the Secure Token body recording, with every effect faked: what is
// refused before anything is written, the ledger lines, the stop signal, and what may reach a file.

import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import { scanFixture } from "./auth-account/fixture-scan.mjs";
import { ROWS, corpusDigest } from "./securetoken-body/corpus.mjs";
import { fixtureText, publicRecording, recordProduction } from "./securetoken-body/record.mjs";
import { ceilings, nextRun, recordWith } from "./securetoken-body/recording.mjs";
import { NUMBER } from "./securetoken-body/test-support.mjs";
import { createWorld } from "./securetoken-body/test-world.mjs";
import { tempDir } from "./test-tmpdir.mjs";

const ENV = { FIREEMU_SANDBOX_LEDGER: "/ledger", FIREEMU_SECURETOKEN_PRIVATE_DIR: "/private" };
const WEB = { apiKey: "AIza-fake-key-for-tests", projectNumber: NUMBER };

function deps(overrides = {}) {
  const fake = createWorld({ project: "fireemu-oracle-idp", number: NUMBER });
  const writes = new Map();
  const ledger = [];
  const calls = [];
  const dir = tempDir("stb-rec-");
  const d = {
    calls,
    writes,
    ledger,
    world: fake.world,
    now: () => Date.parse("2026-11-08T12:00:00Z"),
    readLedger: async () => overrides.ledgerText ?? "",
    appendLedger: async (_path, text) => ledger.push(JSON.parse(text)),
    assertCleanTree: async () => {
      calls.push("clean");
      if (overrides.dirty) throw new Error("record-production needs a clean tree");
    },
    gitSha: async () => "a".repeat(40),
    harnessDigest: async () => "b".repeat(64),
    assertIgnored: async () => {},
    makeRunDir: async () => {},
    writeRunFile: async (_dir, name, text) => writes.set(name, text),
    clockOffset: async () => 0.01,
    sandboxWebConfig: async () => WEB,
    productionTarget: async () => ({ kind: "production" }),
    preflight: async () => ({ report: { fake: true }, problems: overrides.problems ?? [] }),
    recordOnce: async (n, _web, { shouldStop }) => {
      calls.push(`record-${n}`);
      // A run records twice; a third start is a loop that does not end, and fails here, not by timeout.
      if (calls.filter((c) => c.startsWith("record-")).length > 2)
        throw new Error("a third recording was started");
      return recordWith(
        { kind: "local", origin: "http://127.0.0.1:1", projectNumber: NUMBER },
        dir,
        n,
        {
          transport: fake.fetch,
          sleep: async () => {},
          pollMs: 0,
          shouldStop,
        },
      );
    },
    readFixture: async () => undefined,
    writeFixture: async (text) => writes.set("FIXTURE", text),
    scanFixture,
    installSignals: async (handler) => {
      d.signal = handler;
    },
    log: () => {},
    warn: (text) => calls.push(`warn:${text.slice(0, 40)}`),
    ...overrides.deps,
  };
  return d;
}

test("a clean production run records twice, writes the fixture and two ledger lines", async () => {
  const d = deps();
  const result = await recordProduction(ENV, d);
  assert.deepEqual(result, { outcome: "recorded", exitCode: 0 });
  assert.deepEqual(
    d.calls.filter((c) => c.startsWith("record-")),
    ["record-1", "record-2"],
  );
  assert.equal(d.ledger.length, 2);
  assert.equal(d.ledger[0].event, "started");
  assert.equal(d.ledger[0].taskId, "SECURETOKEN-BODY");
  const end = d.ledger[1];
  assert.equal(end.outcome, "recorded");
  assert.equal(end.closureReady, true);
  assert.equal(end.recordings, 2);
  assert.equal(end.corpusDigest, corpusDigest());
  assert.equal(end.requests, 2 * (24 + 23));
  assert.equal(end.project, "fireemu-oracle-idp");
  const fixture = JSON.parse(d.writes.get("FIXTURE"));
  assert.equal(fixture.recordings.length, 2);
  assert.equal(Object.keys(fixture.recordings[0].rows).length, ROWS.length);
  assert.ok(
    d.writes.has("recording-1.json") &&
      d.writes.has("recording-2.json") &&
      d.writes.has("meta.json"),
  );
  assert.equal(d.world.accounts.size + d.world.tenants.size, 0);
});

test("no file holds a token, the key, the project number or the project id", async () => {
  const d = deps();
  await recordProduction(ENV, d);
  // The ledger line names the project by design; no other file may.
  const everything = [...d.writes.values()].join("\n");
  const ledgerText = JSON.stringify(d.ledger);
  for (const token of d.world.tokens.keys()) assert.ok(!ledgerText.includes(token));
  for (const token of d.world.tokens.keys()) assert.ok(!everything.includes(token));
  for (const secret of [WEB.apiKey, "fireemu-stb-Password-1"])
    assert.ok(!everything.includes(secret), `leaked: ${secret}`);
  for (const needle of ["fireemu-oracle-idp", NUMBER, WEB.apiKey]) {
    assert.ok(!everything.includes(needle), `leaked: ${needle}`);
  }
  assert.ok(!/eyJ[A-Za-z0-9_-]{5,}/.test(everything));
  assert.ok(!everything.includes('"secrets"'));
});

test("every refusal comes before the first write", async () => {
  for (const [name, overrides, pattern] of [
    ["a dirty tree", { dirty: true }, /clean tree/],
    [
      "a recent abort",
      {
        ledgerText: `${JSON.stringify({ ts: "2026-11-08T11:30:00Z", taskId: "SECURETOKEN-BODY", outcome: "needs-recovery" })}\n`,
      },
      /wait an hour/,
    ],
    ["a preflight problem", { problems: ["1 tenant(s) exist"] }, /preflight: 1 tenant/],
  ]) {
    const d = deps(overrides);
    await assert.rejects(recordProduction(ENV, d), pattern, name);
    assert.equal(d.ledger.length, 0, name);
    assert.equal(d.writes.size, 0, name);
    assert.ok(!d.calls.some((c) => c.startsWith("record-")), name);
  }
  await assert.rejects(recordProduction({}, deps()), /required/);
  await assert.rejects(recordProduction({ FIREEMU_SANDBOX_LEDGER: "/l" }, deps()), /required/);
});

test("a recording that stops fatally ends the run aborted, with no fixture", async () => {
  const d = deps({ deps: {} });
  d.world.tenants.set("old", { id: "old", name: "projects/1/tenants/old", displayName: "old-one" });
  d.world.tenancy = true;
  const result = await recordProduction(ENV, d);
  assert.equal(result.exitCode, 1);
  assert.equal(result.outcome, "aborted-fatal");
  assert.ok(!d.writes.has("FIXTURE"));
  assert.deepEqual(
    d.calls.filter((c) => c.startsWith("record-")),
    ["record-1"],
  );
  assert.equal(d.ledger.at(-1).outcome, "aborted-fatal");
  assert.match(d.ledger.at(-1).error, /tenant\(s\) exist/);
});

test("a cleanup error makes the run needs-recovery and names it in the ledger", async () => {
  const d = deps();
  d.world.accounts.set("zzz", { localId: "zzz" }); // a project account the run did not make
  const result = await recordProduction(ENV, d);
  assert.equal(result.outcome, "needs-recovery");
  assert.equal(result.exitCode, 1);
  assert.ok(!d.writes.has("FIXTURE"));
  const end = d.ledger.at(-1);
  assert.equal(end.closureReady, false);
  assert.ok(end.cleanupErrors.some((e) => e.includes("account audit")));
});

test("a token that reaches a recording is caught by the scan and nothing is written", async () => {
  const d = deps({
    deps: {
      recordOnce: async () => ({
        run: "1",
        rows: { x: { status: 200, body: { id_token: "eyJhbGciOiJSUzI1NiJ9.e30.sig" } } },
        requests: 1,
        harnessRequests: 1,
        cleanupErrors: [],
        unknowns: [],
        closureReady: true,
        secrets: [],
      }),
    },
  });
  const result = await recordProduction(ENV, d);
  assert.equal(result.outcome, "aborted");
  assert.match(result.error, /contains a token/);
  assert.ok(![...d.writes.values()].some((t) => t.includes("eyJ")));
  assert.ok(!d.writes.has("FIXTURE"));
  assert.equal(d.ledger.at(-1).closureReady, false);
});

test("a resolved secret in a recording is caught even when it is not token-shaped", async () => {
  const d = deps({
    deps: {
      recordOnce: async () => ({
        run: "1",
        rows: { x: { status: 400, note: "refresh-secret-value" } },
        requests: 1,
        harnessRequests: 1,
        cleanupErrors: [],
        unknowns: [],
        closureReady: true,
        secrets: ["refresh-secret-value"],
      }),
    },
  });
  const result = await recordProduction(ENV, d);
  assert.equal(result.outcome, "aborted");
  assert.ok(![...d.writes.values()].some((t) => t.includes("refresh-secret-value")));
});

test("a signal before the second recording stops the run cleanly", async () => {
  const d = deps();
  const original = d.recordOnce;
  d.recordOnce = async (n, web, options) => {
    const recording = await original(n, web, options);
    d.signal("SIGTERM");
    return recording;
  };
  const result = await recordProduction(ENV, d);
  assert.equal(result.outcome, "aborted-fatal");
  assert.deepEqual(
    d.calls.filter((c) => c.startsWith("record-")),
    ["record-1"],
  );
  assert.match(result.error, /stopped by a signal/);
  assert.ok(!d.writes.has("FIXTURE"));
  assert.equal(d.ledger.at(-1).recordings, 1);
  assert.equal(d.ledger.at(-1).closureReady, false);
});

test("the fixture holds rows only, with the digests that bind it", () => {
  const text = fixtureText({
    recordings: [
      { run: "9", rows: { a: 1 }, requests: 5, secrets: ["x"] },
      { run: "8", rows: { a: 2 } },
    ],
    meta: { sha: "s", corpusDigest: "c", harness: "h", startedAt: "t" },
  });
  const fixture = JSON.parse(text);
  assert.deepEqual(fixture.recordings, [{ rows: { a: 1 } }, { rows: { a: 2 } }]);
  assert.deepEqual([fixture.gitSha, fixture.corpusDigest, fixture.harnessDigest], ["s", "c", "h"]);
  assert.ok(text.endsWith("\n"));
  assert.deepEqual(publicRecording({ a: 1, secrets: ["x"] }), { a: 1 });
});

test("run ids never repeat within a process, even inside one second", () => {
  const now = Date.parse("2026-11-08T12:00:00Z");
  const seen = new Set();
  let previous = 0;
  for (let i = 0; i < 50; i += 1) {
    const run = nextRun(now);
    assert.match(run, /^\d{10}$/);
    assert.ok(!seen.has(run));
    assert.ok(Number(run) > previous);
    seen.add(run);
    previous = Number(run);
  }
  // A later clock moves the id forward; an earlier one cannot move it back.
  assert.ok(Number(nextRun(now + 3_600_000)) >= Number(previous));
  assert.ok(Number(nextRun(0)) > previous);
});

test("the ceilings leave room for the rows and the harness of a recording that polls", () => {
  assert.deepEqual(ceilings(), { maxRequests: ROWS.length, maxHarnessRequests: 160 });
  assert.equal(ceilings([1, 2, 3]).maxRequests, 3);
});

// ---- order, exact lines and the fixture text ----------------------------------------------------

/** Wraps every effect so that it finishes a tick after it starts, records itself, and fails the test if another starts meanwhile. */
function slowly(d) {
  const events = [];
  let running = null;
  const slow = {};
  for (const [name, fn] of Object.entries(d)) {
    if (typeof fn !== "function" || ["recordOnce", "warn", "log", "now"].includes(name)) {
      slow[name] = fn;
      continue;
    }
    slow[name] = async (...args) => {
      if (running) events.push(`OVERLAP ${running} / ${name}`);
      running = name;
      await new Promise((resolve) => setImmediate(resolve));
      const value = await fn(...args);
      events.push(name === "writeRunFile" ? `${name}:${args[1]}` : name);
      running = null;
      return value;
    };
  }
  return { slow, events };
}

test("the effects run one at a time, in the order that makes every refusal come first", async () => {
  const d = deps();
  const { slow, events } = slowly(d);
  const result = await recordProduction(ENV, slow);
  assert.equal(result.outcome, "recorded");
  assert.deepEqual(
    events.filter((e) => e.startsWith("OVERLAP")),
    [],
  );
  const head = events.slice(0, events.indexOf("installSignals") + 1);
  assert.deepEqual(head, [
    "assertCleanTree",
    "readLedger",
    "sandboxWebConfig",
    "productionTarget",
    "preflight",
    "gitSha",
    "harnessDigest",
    "clockOffset",
    "assertIgnored",
    "makeRunDir",
    "appendLedger",
    "installSignals",
  ]);
  // Then each recording is scanned before it is written, then the meta, the scan and write of the fixture, and the closing line.
  assert.deepEqual(events.slice(head.length), [
    "scanFixture",
    "writeRunFile:recording-1.json",
    "scanFixture",
    "writeRunFile:recording-2.json",
    "writeRunFile:meta.json",
    "scanFixture",
    "writeFixture",
    "appendLedger",
  ]);
});

test("a refusal by preflight names every problem, and the run directory has no colon", async () => {
  const d = deps({ problems: ["a tenant exists", "an account exists"] });
  await assert.rejects(
    recordProduction(ENV, d),
    /^Error: preflight: a tenant exists; an account exists$/,
  );
  const ok = deps();
  const dirs = [];
  ok.assertIgnored = async (dir) => dirs.push(["ignored", dir]);
  ok.makeRunDir = async (dir) => dirs.push(["made", dir]);
  await recordProduction(ENV, ok);
  assert.deepEqual(dirs[0], ["ignored", "/private"]);
  assert.deepEqual(dirs[1], ["made", "/private/securetoken-body-2026-11-08T120000.000Z"]);
});

test("the fixture is two-space JSON that says what it is", () => {
  const text = fixtureText({
    recordings: [{ rows: { a: 1 } }, { rows: { a: 2 } }],
    meta: { sha: "s", corpusDigest: "c", harness: "h", startedAt: "2026-11-08T12:00:00.000Z" },
  });
  assert.ok(text.startsWith('{\n  "version": 1,\n  "recordedAgainst": {\n    "target": '));
  const fixture = JSON.parse(text);
  assert.equal(fixture.version, 1);
  assert.equal(fixture.recordedAgainst.task, "SECURETOKEN-BODY");
  assert.match(
    fixture.recordedAgainst.target,
    /Identity Toolkit and Secure Token REST, Identity Platform sandbox/,
  );
  assert.match(
    fixture.recordedAgainst.target,
    /multi-tenancy switched on for each recording and restored/,
  );
  assert.match(
    fixture.recordedAgainst.note,
    /^Tokens, the API key, the project id and its number never appear\./,
  );
  assert.match(fixture.recordedAgainst.note, /user_id is the run's own account \(a, b or t\)\.$/);
  assert.equal(fixture.recordedAt, "2026-11-08T12:00:00.000Z");
  assert.equal(fixture.recordings.length, 2);
});

// ---- signals, aborts and what is said about them ------------------------------------------------

const stub = (extra = {}) => ({
  run: "1",
  rows: {},
  requests: 3,
  harnessRequests: 4,
  cleanupErrors: [],
  unknowns: [],
  closureReady: true,
  secrets: [],
  ...extra,
});

test("a signal says what happens next once, and says that cleanup is not interrupted the second time", async () => {
  const d = deps();
  const warnings = [];
  d.warn = (text) => warnings.push(text);
  let seen;
  d.recordOnce = async (n, _web, options) => {
    if (n === 1) {
      d.signal("SIGINT");
      d.signal("SIGTERM");
      seen = options;
    }
    return stub();
  };
  const result = await recordProduction(ENV, d);
  assert.equal(result.outcome, "aborted-fatal");
  assert.deepEqual(warnings, [
    "SIGINT: stopping at the next step; cleanup follows",
    "SIGTERM again: cleanup is running and is not interrupted. A kill -9 now leaves accounts, a tenant and the multi-tenancy switch for hand cleanup (see the private run directory).",
  ]);
  assert.equal(seen.runDir, "/private/securetoken-body-2026-11-08T120000.000Z");
  assert.equal(typeof seen.shouldStop, "function");
  assert.equal(seen.shouldStop(), true);
});

test("shouldStop is false until a signal arrives", async () => {
  const d = deps();
  const observed = [];
  d.recordOnce = async (n, _web, options) => {
    observed.push(options.shouldStop());
    return stub();
  };
  await recordProduction(ENV, d);
  assert.deepEqual(observed, [false, false]);
});

test("a recording that fails ends the run aborted, or aborted-fatal when it says so", async () => {
  for (const [fatal, outcome] of [
    [false, "aborted"],
    [true, "aborted-fatal"],
  ]) {
    const d = deps();
    d.recordOnce = async () => stub({ failure: "it broke", fatal });
    const result = await recordProduction(ENV, d);
    assert.deepEqual(result, { outcome, exitCode: 1, error: "it broke" });
    assert.equal(d.ledger.at(-1).outcome, outcome);
    assert.equal(d.ledger.at(-1).error, "it broke");
    assert.equal(d.ledger.at(-1).recordings, 1);
    assert.equal(d.ledger.at(-1).closureReady, false);
  }
});

test("a recording that throws is aborted; a partial recording it carries is kept in the count", async () => {
  const d = deps();
  d.recordOnce = async () => {
    throw Object.assign(new Error("lost the sandbox"), {
      fatal: true,
      partial: stub({ requests: 10, harnessRequests: 5 }),
    });
  };
  const result = await recordProduction(ENV, d);
  assert.deepEqual(result, { outcome: "aborted-fatal", exitCode: 1, error: "lost the sandbox" });
  assert.equal(d.ledger.at(-1).requests, 15);
  assert.equal(d.ledger.at(-1).recordings, 1);
  // A plain string and an error without the flag are both read as an abort, with the text kept.
  const e = deps();
  e.recordOnce = async () => {
    throw "a plain string";
  };
  const second = await recordProduction(ENV, e);
  assert.deepEqual(second, { outcome: "aborted", exitCode: 1, error: "a plain string" });
  assert.equal(e.ledger.at(-1).recordings, 0);
});

test("meta.json says how the run ended, in two-space JSON, and what was cleaned or not is warned about", async () => {
  const d = deps();
  const warnings = [];
  d.warn = (text) => warnings.push(text);
  d.recordOnce = async () =>
    stub({
      cleanupErrors: ["account a: gone wrong"],
      unknowns: [{ call: "delete account:stb-1-a", answer: "server-error" }],
      closureReady: false,
    });
  await recordProduction(ENV, d);
  const text = d.writes.get("meta.json");
  assert.ok(text.startsWith('{\n  "sha": '));
  const meta = JSON.parse(text);
  assert.equal(meta.outcome, "needs-recovery");
  assert.match(meta.error, /recording 1 is not closure-ready/);
  assert.equal(meta.sha, "a".repeat(40));
  assert.equal(meta.harness, "b".repeat(64));
  assert.equal(meta.corpusDigest, corpusDigest());
  assert.deepEqual(meta.preflight, { fake: true });
  assert.equal(meta.clockOffsetSeconds, 0.01);
  assert.equal(meta.startedAt, "2026-11-08T12:00:00.000Z");
  assert.equal(
    warnings.at(-1),
    "NOT CLOSURE-READY on fireemu-oracle-idp:\n  account a: gone wrong\n  unknown answer to delete account:stb-1-a: server-error",
  );
});

test("an error thrown while the fixture is written is reported with where the recordings are kept", async () => {
  const d = deps();
  d.writeFixture = async () => {
    throw new Error("disk full");
  };
  const result = await recordProduction(ENV, d);
  assert.equal(result.outcome, "not-written");
  assert.equal(
    result.error,
    "disk full (recordings kept in /private/securetoken-body-2026-11-08T120000.000Z)",
  );
  assert.equal(d.ledger.at(-1).error, result.error);
  assert.equal(d.ledger.at(-1).outcome, "not-written");
});

test("a run id is the second of the clock when it can be, and one more than the last when it cannot", () => {
  const far = Date.parse("2100-01-01T00:00:00Z");
  assert.equal(nextRun(far), String(Math.floor(far / 1000)));
  assert.equal(nextRun(far), String(Math.floor(far / 1000) + 1));
  assert.equal(nextRun(far + 999), String(Math.floor(far / 1000) + 2));
  assert.equal(nextRun(far + 5000), String(Math.floor(far / 1000) + 5));
});

test("a recording releases its ownership ledger, so the same directory can be used again", async () => {
  const dir = tempDir("stb-lock-");
  const fake = createWorld({ project: "fireemu-oracle-idp", number: NUMBER });
  const options = { transport: fake.fetch, sleep: async () => {}, pollMs: 0 };
  const target = { kind: "local", origin: "http://127.0.0.1:1", projectNumber: NUMBER };
  const first = await recordWith(target, dir, 1, options);
  assert.equal(first.closureReady, true);
  assert.ok(existsSync(join(dir, "issued-1.jsonl")));
  assert.ok(!existsSync(join(dir, "issued-1.jsonl.lock")));
  assert.ok(existsSync(join(dir, "journal-1.jsonl")));
  // Even a recording that throws releases it.
  const failing = {
    ...options,
    transport: () => {
      throw new Error("no network");
    },
  };
  await recordWith(target, dir, 2, failing);
  assert.ok(!existsSync(join(dir, "issued-2.jsonl.lock")));
});

test("it records exactly twice, numbered 1 and 2, and says what it recorded", async () => {
  const d = deps();
  const logs = [];
  d.log = (text) => logs.push(text);
  const original = d.recordOnce;
  const numbers = [];
  d.recordOnce = async (n, web, options) => {
    numbers.push(n);
    if (numbers.length > 2) throw new Error("a third recording was started");
    return original(n, web, options);
  };
  const result = await recordProduction(ENV, d);
  assert.deepEqual(result, { outcome: "recorded", exitCode: 0 });
  assert.deepEqual(numbers, [1, 2]);
  assert.equal(logs.length, 1);
  assert.equal(logs[0], JSON.stringify({ rows: ROWS.length, requests: 2 * (24 + 23) }, null, 2));
});

test("the closing ledger line carries unknowns, cleanup errors and an error only when there are some", async () => {
  const clean = deps();
  await recordProduction(ENV, clean);
  const end = clean.ledger.at(-1);
  for (const key of ["unknowns", "cleanupErrors", "error"]) assert.equal(key in end, false, key);
  assert.deepEqual(Object.keys(end).toSorted(), [
    "closureReady",
    "corpusDigest",
    "estimatedUsd",
    "gitSha",
    "outcome",
    "project",
    "recordings",
    "requests",
    "rows",
    "taskId",
    "ts",
  ]);
  const only = (extra) => {
    const d = deps();
    d.recordOnce = async () => stub(extra);
    return d;
  };
  const withUnknown = only({
    unknowns: [{ call: "delete x", answer: "server-error" }],
    closureReady: false,
  });
  await recordProduction(ENV, withUnknown);
  assert.deepEqual(withUnknown.ledger.at(-1).unknowns, [
    { call: "delete x", answer: "server-error" },
  ]);
  assert.equal("cleanupErrors" in withUnknown.ledger.at(-1), false);
  const withCleanup = only({ cleanupErrors: ["tenant: x"], closureReady: false });
  await recordProduction(ENV, withCleanup);
  assert.deepEqual(withCleanup.ledger.at(-1).cleanupErrors, ["tenant: x"]);
  assert.equal("unknowns" in withCleanup.ledger.at(-1), false);
  assert.equal(
    withCleanup.ledger.at(-1).error,
    "recording 1 is not closure-ready; recording 2 is not started",
  );
});

// ---- a recording that is not closure-ready ends the run -----------------------------------------

test("a recording that is not closure-ready is the last one: recording 2 is never started", async () => {
  const cases = {
    "an unknown delete": { unknowns: [{ call: "delete account:stb-1-a", answer: "server-error" }] },
    "a cleanup error": { cleanupErrors: ["account audit: 1 project-level account(s) remain"] },
    "an open name without either": {},
  };
  for (const [name, extra] of Object.entries(cases)) {
    const d = deps();
    const numbers = [];
    d.recordOnce = async (n) => {
      numbers.push(n);
      return stub({ ...extra, closureReady: false });
    };
    const warnings = [];
    d.warn = (text) => warnings.push(text);
    const result = await recordProduction(ENV, d);
    assert.deepEqual(numbers, [1], name);
    assert.equal(result.outcome, "needs-recovery", name);
    assert.equal(result.exitCode, 1, name);
    assert.match(
      result.error,
      /recording 1 is not closure-ready; recording 2 is not started/,
      name,
    );
    assert.ok(!d.writes.has("FIXTURE"), name);
    assert.ok(d.writes.has("recording-1.json") && !d.writes.has("recording-2.json"), name);
    const end = d.ledger.at(-1);
    assert.equal(end.outcome, "needs-recovery", name);
    assert.equal(end.recordings, 1, name);
    assert.equal(end.closureReady, false, name);
    assert.equal(end.error, result.error, name);
  }
});

test("a switch-back that fails after recording 1 stops the run with tenancy left on and no second recording", async () => {
  const d = deps();
  d.world.tenancy = false;
  let patches = 0;
  const original = d.recordOnce;
  const faulty = createWorld({
    project: "fireemu-oracle-idp",
    number: NUMBER,
    tenancy: false,
    faults: [
      (req) => (req.method === "PATCH" && ++patches === 2 ? { status: 503, json: {} } : undefined),
    ],
  });
  const dir = tempDir("stb-sb-");
  const numbers = [];
  d.recordOnce = async (n, _web, { shouldStop }) => {
    numbers.push(n);
    return recordWith(
      { kind: "local", origin: "http://127.0.0.1:1", projectNumber: NUMBER },
      dir,
      n,
      {
        transport: faulty.fetch,
        sleep: async () => {},
        pollMs: 0,
        shouldStop,
      },
    );
  };
  void original;
  const result = await recordProduction(ENV, d);
  assert.deepEqual(numbers, [1]);
  assert.equal(result.outcome, "needs-recovery");
  assert.equal(faulty.world.tenancy, true);
  const recording = JSON.parse(d.writes.get("recording-1.json"));
  assert.deepEqual(recording.tenancy, { before: false, switchedOn: true, restored: false });
  assert.ok(recording.cleanupErrors.some((e) => e.startsWith("restore multi-tenancy")));
  assert.equal(d.ledger.at(-1).recordings, 1);
  assert.equal(d.ledger.at(-1).closureReady, false);
});

test("a closure-ready recording still lets the second one run", async () => {
  const d = deps();
  const numbers = [];
  d.recordOnce = async (n) => (numbers.push(n), stub());
  const result = await recordProduction(ENV, d);
  assert.deepEqual(numbers, [1, 2]);
  assert.equal(result.outcome, "recorded");
});

test("a failed recording that left a name open is needs-recovery, and meta.json says what the ledger says", async () => {
  const cases = [
    [
      "a failure with an open name and nothing else",
      stub({ failure: "it broke", fatal: true, closureReady: false }),
      "needs-recovery",
    ],
    [
      "a failure with a cleanup error",
      stub({ failure: "it broke", closureReady: false, cleanupErrors: ["x"] }),
      "needs-recovery",
    ],
    [
      "a failure after a clean close",
      stub({ failure: "it broke", fatal: true, closureReady: true }),
      "aborted-fatal",
    ],
    [
      "a clean close with a settled unknown answer",
      stub({ unknowns: [{ call: "create x", answer: "server-error" }], closureReady: true }),
      "needs-recovery",
    ],
  ];
  for (const [name, recording, outcome] of cases) {
    const d = deps();
    d.recordOnce = async () => recording;
    const result = await recordProduction(ENV, d);
    assert.equal(result.outcome, outcome, name);
    assert.equal(d.ledger.at(-1).outcome, outcome, name);
    assert.equal(JSON.parse(d.writes.get("meta.json")).outcome, outcome, name);
  }
});
