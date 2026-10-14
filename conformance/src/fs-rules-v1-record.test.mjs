import assert from "node:assert/strict";
import { test } from "node:test";

import { scanFixture } from "./auth-account/fixture-scan.mjs";
import { createContext, SANDBOX_PROJECT } from "./fs-rules/harness.mjs";
import { PRINCIPALS, PROGRAMS } from "./fs-rules-v1/corpus.mjs";
import { ceilings, TASK_ID } from "./fs-rules-v1/judge.mjs";
import { preflight } from "./fs-rules-v1/preflight.mjs";
import { recordProduction } from "./fs-rules-v1/record.mjs";
import { runCorpus } from "./fs-rules-v1/session.mjs";
import { createClock, createWorld } from "./fs-rules-v1/test-world.mjs";

const NOW = Date.parse("2026-10-14T12:00:00Z");
const API_KEY = "AIzaFs3TestKeyNotReal";
const NUMBER = "555500000001";
const WEB = { apiKey: API_KEY, projectNumber: NUMBER, projectId: SANDBOX_PROJECT };
const TARGET = {
  kind: "production",
  adminToken: "ya29.owner-test-token",
  apiKey: API_KEY,
  quotaProject: SANDBOX_PROJECT,
  projectNumber: NUMBER,
};
const ENV = {
  FIREEMU_SANDBOX_LEDGER: "/ledger/sandbox.jsonl",
  FIREEMU_FS3_PRIVATE_DIR: "/private/fs3",
  FS3_NO_AUTH_RECORDING: new Date(NOW - 5 * 60_000).toISOString(),
};
const CLEAN_REPORT = {
  failedReads: [],
  projectAccounts: 0,
  anonymousEnabled: true,
  rulesets: 0,
  otherLanesRecently: [],
  openRuns: [],
  releases: [],
  databases: ["(default)"],
  defaultHasDocuments: false,
};

/** Fake effects that log every call in order; `override` replaces any of them. */
function fakeDeps(override = {}) {
  const calls = [];
  const files = new Map();
  const ledger = { text: override.ledgerText ?? "" };
  const state = { fixture: undefined, handler: undefined, warnings: [], logs: [] };
  const note =
    (name, fn) =>
    async (...args) => {
      calls.push(name);
      return fn(...args);
    };
  const deps = {
    now: () => NOW,
    readLedger: note("readLedger", async () => ledger.text),
    appendLedger: note("appendLedger", async (_path, text) => {
      ledger.text += text;
    }),
    assertCleanTree: note("assertCleanTree", async () => {}),
    gitSha: note("gitSha", async () => "a".repeat(40)),
    harnessDigest: () => "h".repeat(64),
    assertIgnored: note("assertIgnored", async () => {}),
    makeRunDir: note("makeRunDir", async () => {}),
    writeRunFile: note("writeRunFile", async (dir, name, text) => {
      files.set(`${dir}/${name}`, text);
    }),
    clockOffset: note("clockOffset", async () => 0.01),
    sandboxWebConfig: note("sandboxWebConfig", async () => WEB),
    productionTarget: note("productionTarget", async () => TARGET),
    preflight: note("preflight", async () => ({ report: CLEAN_REPORT, problems: [] })),
    recordOnce: note("recordOnce", async () => {
      throw new Error("recordOnce not set");
    }),
    readFixture: note("readFixture", async () => state.fixture),
    writeFixture: note("writeFixture", async (text) => {
      state.fixture = text;
    }),
    scanFixture: note("scanFixture", (text, secrets) => scanFixture(text, secrets)),
    installSignals: note("installSignals", (handler) => {
      state.handler = handler;
    }),
    log: (text) => state.logs.push(text),
    warn: (text) => state.warnings.push(text),
    ...override.deps,
  };
  return { deps, calls, files, ledger, state };
}

/** A recording shaped like runCorpus's, with the same rows in both. */
const recording = (extra = {}) => ({
  context: { run: "1", startedMs: 1 },
  results: Object.fromEntries(
    PROGRAMS.map((p) => [
      p.id,
      {
        steps: Object.fromEntries(
          p.steps.map((s) => [s.id, s.publish ? { compiled: true } : { status: 200, body: [] }]),
        ),
      },
    ]),
  ),
  failures: [],
  cleanupErrors: [],
  publications: [{}, {}],
  diagnostics: {},
  unknowns: [],
  closureReady: true,
  requests: 76,
  harnessRequests: 300,
  ...extra,
});

const lines = (ledger) =>
  ledger.text
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l));

// ---- the sequence ---------------------------------------------------------------------------

test("a clean recording: refusals first, started line before any recording, one fixture, a final line", async () => {
  const fake = fakeDeps({ deps: { recordOnce: undefined } });
  fake.deps.recordOnce = async () => {
    fake.calls.push("recordOnce");
    return recording();
  };
  const result = await recordProduction(ENV, fake.deps);
  assert.deepEqual(result, { outcome: "recorded", exitCode: 0 });
  const order = (name) => fake.calls.indexOf(name);
  // Nothing that touches production or a file runs before the offline refusals.
  for (const before of ["assertCleanTree", "readLedger", "sandboxWebConfig"])
    assert.ok(order(before) < order("productionTarget"), before);
  assert.ok(order("productionTarget") < order("preflight"));
  assert.ok(
    order("preflight") < order("assertIgnored") && order("preflight") < order("makeRunDir"),
  );
  const firstLedgerWrite = order("appendLedger");
  assert.ok(order("preflight") < firstLedgerWrite && firstLedgerWrite < order("recordOnce"));
  assert.equal(fake.calls.filter((c) => c === "recordOnce").length, 2);
  assert.ok(order("writeFixture") > fake.calls.lastIndexOf("recordOnce"));
  assert.equal(fake.calls.at(-1), "appendLedger", "the final ledger line is the last effect");
  const [started, final] = lines(fake.ledger);
  assert.equal(started.event, "started");
  assert.equal(started.taskId, TASK_ID);
  assert.equal(started.project, SANDBOX_PROJECT);
  assert.equal(final.outcome, "recorded");
  assert.equal(final.closureReady, true);
  assert.equal(final.requests, 2 * (76 + 300));
  assert.ok(final.estimatedUsd < 0.05);
  assert.equal(final.database, "(default)");
  assert.equal(final.publications, 4);
  assert.ok(fake.state.fixture.includes('"fs-rules-v1/recursive-wildcard/v1"'));
  assert.ok(!fake.state.fixture.includes(API_KEY));
  assert.ok(
    fake.files.has("/private/fs3/" + [...fake.files.keys()][0].split("/").at(-2) + "/meta.json"),
  );
});

test("every offline refusal comes before any request to production or any file", async () => {
  const cases = [
    [{ ...ENV, FIREEMU_SANDBOX_LEDGER: undefined }, {}, /FIREEMU_SANDBOX_LEDGER/],
    [{ ...ENV, FIREEMU_FS3_PRIVATE_DIR: undefined }, {}, /FIREEMU_FS3_PRIVATE_DIR/],
    [
      { ...ENV },
      {
        assertCleanTree: async () => {
          throw new Error("needs a clean tree");
        },
      },
      /clean tree/,
    ],
    [{ ...ENV, FS3_NO_AUTH_RECORDING: undefined }, {}, /FS3_NO_AUTH_RECORDING/],
    [
      { ...ENV, FS3_NO_AUTH_RECORDING: new Date(NOW - 2 * 3_600_000).toISOString() },
      {},
      /FS3_NO_AUTH_RECORDING/,
    ],
    [{ ...ENV, FS3_PROGRAMS: "no-such" }, {}, /no program matches/],
    [
      { ...ENV },
      {
        sandboxWebConfig: async () => {
          throw new Error("web config is not the sandbox project");
        },
      },
      /not the sandbox project/,
    ],
  ];
  for (const [env, deps, pattern] of cases) {
    const fake = fakeDeps({ deps });
    await assert.rejects(recordProduction(env, fake.deps), pattern);
    for (const effect of [
      "productionTarget",
      "preflight",
      "recordOnce",
      "appendLedger",
      "makeRunDir",
      "writeFixture",
    ])
      assert.ok(!fake.calls.includes(effect), `${effect} ran before ${pattern}`);
  }
});

test("a recent abort or recovery blocks the next recording before it touches production", async () => {
  for (const outcome of ["aborted-fatal", "needs-recovery"]) {
    const ledgerText = `${JSON.stringify({ ts: new Date(NOW - 10 * 60_000).toISOString(), project: SANDBOX_PROJECT, taskId: TASK_ID, outcome })}\n`;
    const fake = fakeDeps({ ledgerText });
    await assert.rejects(recordProduction(ENV, fake.deps), new RegExp(`ended ${outcome}`));
    assert.ok(!fake.calls.includes("productionTarget"));
  }
});

test("a sandbox that is not as the lanes leave it stops the recording with nothing written", async () => {
  const fake = fakeDeps({
    deps: {
      preflight: async () => ({
        report: { ...CLEAN_REPORT, releases: ["cloud.firestore"] },
        problems: ["release(s) exist: cloud.firestore"],
      }),
    },
  });
  await assert.rejects(recordProduction(ENV, fake.deps), /preflight: release\(s\) exist/);
  for (const effect of [
    "recordOnce",
    "appendLedger",
    "makeRunDir",
    "assertIgnored",
    "writeFixture",
    "gitSha",
  ])
    assert.ok(!fake.calls.includes(effect), effect);
  assert.equal(fake.ledger.text, "");
});

// ---- failures -------------------------------------------------------------------------------

test("a recording that throws still gets its final ledger line, and no fixture", async () => {
  const fake = fakeDeps();
  fake.deps.recordOnce = async () => {
    throw Object.assign(new Error("harness request ceiling 900 reached"), {
      fatal: true,
      partial: recording({ requests: 3, harnessRequests: 900 }),
    });
  };
  const result = await recordProduction(ENV, fake.deps);
  assert.equal(result.outcome, "aborted-fatal");
  assert.equal(result.exitCode, 1);
  assert.match(result.error, /ceiling 900/);
  const [, final] = lines(fake.ledger);
  assert.equal(final.outcome, "aborted-fatal");
  assert.equal(final.requests, 903);
  assert.equal(final.closureReady, true);
  assert.equal(fake.state.fixture, undefined);
  assert.ok([...fake.files.keys()].some((k) => k.endsWith("recording-1-partial.json")));
  assert.ok([...fake.files.keys()].some((k) => k.endsWith("meta.json")));
});

test("a cleanup error or an unknown answer makes the run needs-recovery, not closure-ready", async () => {
  const cases = [
    recording({ cleanupErrors: ["audit: a release remains"], closureReady: false }),
    recording({ unknowns: [{ call: "delete release", answer: "HTTP 503" }], closureReady: false }),
  ];
  for (const bad of cases) {
    const fake = fakeDeps();
    fake.deps.recordOnce = async () => bad;
    const result = await recordProduction(ENV, fake.deps);
    assert.equal(result.outcome, "needs-recovery");
    assert.equal(result.exitCode, 1);
    const [, final] = lines(fake.ledger);
    assert.equal(final.outcome, "needs-recovery");
    assert.equal(final.closureReady, false);
    assert.equal(fake.state.fixture, undefined, "no fixture from a run that left something behind");
    assert.match(fake.state.warnings.join("\n"), /NOT CLOSURE-READY/);
    // The next recording is refused for an hour.
    const next = fakeDeps({ ledgerText: fake.ledger.text });
    await assert.rejects(recordProduction(ENV, next.deps), /ended needs-recovery/);
  }
});

test("a stop signal ends the recording after cleanup and starts no second one", async () => {
  const fake = fakeDeps();
  let started = 0;
  fake.deps.recordOnce = async (_programs, _web, { shouldStop }) => {
    started += 1;
    assert.equal(shouldStop(), false);
    fake.state.handler("SIGINT");
    assert.equal(shouldStop(), true);
    fake.state.handler("SIGINT");
    throw Object.assign(new Error("stopped by a signal"), { fatal: true, partial: recording() });
  };
  const result = await recordProduction(ENV, fake.deps);
  assert.equal(started, 1);
  assert.equal(result.outcome, "aborted-fatal");
  assert.match(fake.state.warnings[0], /SIGINT: stopping at the next step/);
  assert.match(fake.state.warnings[1], /SIGINT again: cleanup is running and is not interrupted/);
  assert.equal(fake.state.fixture, undefined);
});

test("a signal between the two recordings stops before the second", async () => {
  const fake = fakeDeps();
  let started = 0;
  fake.deps.recordOnce = async () => {
    started += 1;
    fake.state.handler("SIGTERM");
    return recording();
  };
  const result = await recordProduction(ENV, fake.deps);
  assert.equal(started, 1);
  assert.equal(result.outcome, "aborted-fatal");
  assert.equal(result.exitCode, 1);
  assert.equal(fake.state.fixture, undefined);
});

test("a fixture the secret scan refuses is not written, and the run says where the recordings are", async () => {
  const fake = fakeDeps();
  fake.deps.recordOnce = async () =>
    recording({
      results: {
        ...recording().results,
        [PROGRAMS[0].id]: { steps: { x: { status: 200, body: { leak: API_KEY } } } },
      },
    });
  const result = await recordProduction(ENV, fake.deps);
  assert.equal(result.outcome, "not-written");
  assert.match(result.error, /secret or a sandbox identifier.*recordings kept in/);
  assert.equal(fake.state.fixture, undefined);
  assert.equal(lines(fake.ledger).at(-1).outcome, "not-written");
});

test("a failing fixture write still leaves the final ledger line", async () => {
  const fake = fakeDeps({
    deps: {
      writeFixture: async () => {
        throw new Error("disk full");
      },
    },
  });
  fake.deps.recordOnce = async () => recording();
  const result = await recordProduction(ENV, fake.deps);
  assert.equal(result.outcome, "not-written");
  assert.equal(lines(fake.ledger).at(-1).outcome, "not-written");
});

test("a program failure is recorded, the fixture is written and the exit code is 1", async () => {
  const fake = fakeDeps();
  fake.deps.recordOnce = async () => recording({ failures: [{ program: "p", error: "x" }] });
  const result = await recordProduction(ENV, fake.deps);
  assert.equal(result.outcome, "recorded-with-program-failures");
  assert.equal(result.exitCode, 1);
  assert.ok(fake.state.fixture);
});

test("rows that differ between the two recordings are kept as the second answer", async () => {
  const fake = fakeDeps();
  let n = 0;
  fake.deps.recordOnce = async () => {
    n += 1;
    const base = recording();
    if (n === 2) base.results[PROGRAMS[0].id].steps["group-none"] = { status: 403, body: [] };
    return base;
  };
  await recordProduction(ENV, fake.deps);
  const fixture = JSON.parse(fake.state.fixture);
  assert.deepEqual(fixture.programs[PROGRAMS[0].id].second, {
    "group-none": { status: 403, body: [] },
  });
});

test("the recording runs the real session against a fake production end to end", async () => {
  const worlds = [];
  const fake = fakeDeps();
  fake.deps.recordOnce = async (programs, _web, { shouldStop }) => {
    const { world, fetchImpl, grpc } = createWorld({ v1Group: "deny" });
    worlds.push(world);
    const clock = createClock();
    const ctx = createContext({ run: "1790000000000", startedMs: clock.now(), target: TARGET });
    return runCorpus(
      { programs, principals: PRINCIPALS },
      ctx,
      { fetchImpl, grpc, sleep: clock.sleep, now: clock.now },
      { ...ceilings(programs), shouldStop },
    );
  };
  const result = await recordProduction(ENV, fake.deps);
  assert.deepEqual(result, { outcome: "recorded", exitCode: 0 });
  for (const world of worlds)
    assert.equal(
      world.releases.size + world.rulesets.size + world.accounts.size + world.documents.size,
      0,
    );
  const fixture = JSON.parse(fake.state.fixture);
  assert.equal(
    fixture.programs["fs-rules-v1/recursive-wildcard/v1"].steps["group-none"].status,
    403,
  );
  assert.equal(fixture.programs["fs-rules-v1/path-wildcard/v1"].diagnostics.status, 400);
  assert.equal(lines(fake.ledger).at(-1).closureReady, true);
  assert.ok(!fake.state.fixture.includes(SANDBOX_PROJECT));
});

// ---- the preflight --------------------------------------------------------------------------

async function runPreflight(prepare) {
  const { world, fetchImpl } = createWorld();
  prepare?.(world);
  const result = await preflight(TARGET, "", { now: NOW, fetchImpl });
  return { ...result, world };
}

test("the preflight of a sandbox as the lanes leave it finds no problem and creates nothing", async () => {
  const { report, problems, world } = await runPreflight();
  assert.deepEqual(problems, []);
  assert.deepEqual(report.databases, ["(default)"]);
  assert.equal(report.projectAccounts, 0);
  assert.equal(report.anonymousEnabled, true);
  for (const { method, path } of world.log)
    assert.ok(
      method === "GET" || path.endsWith(":runQuery") || path.endsWith("/accounts:query"),
      `${method} ${path}`,
    );
  assert.ok(world.log.every((e) => e.path.includes(`/projects/${SANDBOX_PROJECT}/`)));
  assert.equal(
    world.rulesets.size + world.releases.size + world.accounts.size + world.documents.size,
    0,
  );
});

test("the preflight reads each way a sandbox can be unfit as a problem", async () => {
  const cases = [
    [
      (w) => w.releases.set("cloud.firestore", "projects/x/rulesets/r"),
      /release\(s\) exist: cloud\.firestore/,
    ],
    [(w) => w.rulesets.set("projects/x/rulesets/r", "src"), /1 ruleset\(s\) exist/],
    [(w) => w.documents.set("a/b", {}), /holds documents/],
    [(w) => w.accounts.set("u", {}), /1 project-level account/],
  ];
  for (const [prepare, pattern] of cases) {
    const { problems } = await runPreflight(prepare);
    assert.equal(problems.length, 1, String(pattern));
    assert.match(problems[0], pattern);
  }
});

test("the preflight treats a refused read as a failed read, never as an empty sandbox", async () => {
  const { fetchImpl } = createWorld();
  const refuse =
    (part, status = 403) =>
    (url, init) =>
      url.includes(part)
        ? Promise.resolve({
            status,
            json: async () => ({ error: { status: "PERMISSION_DENIED" } }),
          })
        : fetchImpl(url, init);
  const releases = await preflight(TARGET, "", { now: NOW, fetchImpl: refuse("/releases") });
  assert.deepEqual(releases.problems, ["preflight read failed: releases (HTTP 403)"]);
  // An error object where a list is expected does not throw and is not an empty list.
  const documents = await preflight(TARGET, "", { now: NOW, fetchImpl: refuse(":runQuery") });
  assert.deepEqual(documents.problems, ["preflight read failed: documents (HTTP 403)"]);
  const accounts = await preflight(TARGET, "", { now: NOW, fetchImpl: refuse("/accounts:query") });
  assert.ok(accounts.problems.some((p) => /accounts \(HTTP 403\)/.test(p)));
  assert.ok(accounts.problems.some((p) => /-1 project-level account/.test(p)));
});

test("the preflight reads the ledger: another lane's recent line blocks", async () => {
  const { fetchImpl } = createWorld();
  const ledger = `${JSON.stringify({ ts: new Date(NOW - 60_000).toISOString(), project: SANDBOX_PROJECT, taskId: "AUTH-X" })}\n`;
  const { problems, report } = await preflight(TARGET, ledger, { now: NOW, fetchImpl });
  assert.deepEqual(report.otherLanesRecently, ["AUTH-X"]);
  assert.equal(problems.length, 1);
});
