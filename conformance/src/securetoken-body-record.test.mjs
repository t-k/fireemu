// The production sequence of the Secure Token body recording, with every effect faked: what is
// refused before anything is written, the ledger lines, the stop signal, and what may reach a file.

import assert from "node:assert/strict";
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
