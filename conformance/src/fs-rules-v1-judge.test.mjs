import assert from "node:assert/strict";
import { test } from "node:test";

import { scanFixture } from "./auth-account/fixture-scan.mjs";
import { SANDBOX_PROJECT } from "./fs-rules/harness.mjs";
import { HARNESS_CAP, PROGRAMS, programDigest } from "./fs-rules-v1/corpus.mjs";
import {
  brief,
  ceilings,
  classify,
  compareRows,
  confirmedNoAuthRecording,
  estimatedUsd,
  fireemuConfig,
  fixtureText,
  HARNESS_FILES,
  harnessDigest,
  mockToken,
  openRuns,
  otherLanesRecently,
  preflightProblems,
  recentAbort,
  selectPrograms,
  TASK_ID,
} from "./fs-rules-v1/judge.mjs";
import { runSupervised } from "./fs-rules-v1/supervise.mjs";

const NOW = Date.parse("2026-10-14T12:00:00Z");
const ago = (minutes) => new Date(NOW - minutes * 60_000).toISOString();
const line = (entry) => JSON.stringify({ project: SANDBOX_PROJECT, ...entry });

// ---- cost and bounds ------------------------------------------------------------------------

test("two recordings stay far below US$1 even at the harness ceiling", () => {
  const { maxRequests, maxHarnessRequests } = ceilings(PROGRAMS);
  assert.equal(maxRequests, 76);
  assert.equal(maxHarnessRequests, HARNESS_CAP);
  const worstCase = 2 * (maxRequests + maxHarnessRequests);
  assert.equal(worstCase, 3152);
  assert.ok(estimatedUsd(worstCase) < 0.05, String(estimatedUsd(worstCase)));
  assert.ok(estimatedUsd(0) > 0, "the figure includes a fixed margin");
  assert.ok(estimatedUsd(100000) > estimatedUsd(1000), "and grows with the requests");
});

// ---- preflight ------------------------------------------------------------------------------

const cleanReport = () => ({
  failedReads: [],
  projectAccounts: 0,
  anonymousEnabled: true,
  rulesets: 0,
  otherLanesRecently: [],
  openRuns: [],
  releases: [],
  databases: ["(default)"],
  defaultHasDocuments: false,
});

test("a sandbox in the state the lanes leave it passes the preflight", () => {
  assert.deepEqual(preflightProblems(cleanReport()), []);
});

test("every deviation from that state refuses the recording, and only that deviation does", () => {
  const cases = [
    [{ failedReads: ["releases (HTTP 403)"] }, /read failed: releases/],
    [{ databases: ["(default)", "named-db"] }, /databases other than \(default\)/],
    [{ releases: ["cloud.firestore"] }, /release\(s\) exist/],
    [{ rulesets: 1 }, /1 ruleset\(s\) exist/],
    [{ defaultHasDocuments: true }, /holds documents/],
    [{ projectAccounts: 1 }, /1 project-level account/],
    [{ projectAccounts: -1 }, /-1 project-level account/],
    [{ anonymousEnabled: false }, /anonymous sign-in/],
    [{ otherLanesRecently: ["AUTH-X"] }, /other lanes used the sandbox/],
    [{ openRuns: ["AUTH-Y"] }, /runs still open/],
  ];
  for (const [change, pattern] of cases) {
    const problems = preflightProblems({ ...cleanReport(), ...change });
    assert.equal(problems.length, 1, JSON.stringify(change));
    assert.match(problems[0], pattern);
  }
});

// ---- the ledger -----------------------------------------------------------------------------

test("another lane within 30 minutes blocks; this task's own lines and older ones do not", () => {
  const ledger = [
    line({ ts: ago(29), taskId: "AUTH-A" }),
    line({ ts: ago(31), taskId: "AUTH-OLD" }),
    line({ ts: ago(5), taskId: TASK_ID }),
    JSON.stringify({ ts: ago(1), project: "fireemu-oracle-sbx", taskId: "FS-OTHER-PROJECT" }),
    "not json",
    line({ ts: ago(2) }),
  ].join("\n");
  assert.deepEqual(otherLanesRecently(ledger, NOW).toSorted(), ["AUTH-A", "unknown"]);
  assert.deepEqual(otherLanesRecently("", NOW), []);
});

test("a task started in the last 6 hours and not finished is an open run", () => {
  const ledger = [
    line({ ts: ago(60), event: "started", taskId: "AUTH-OPEN" }),
    line({ ts: ago(120), event: "started", taskId: "AUTH-DONE" }),
    line({ ts: ago(100), taskId: "AUTH-DONE", outcome: "recorded" }),
    line({ ts: ago(7 * 60), event: "started", taskId: "AUTH-STALE" }),
    line({ ts: ago(10), event: "started", taskId: TASK_ID }),
    line({ ts: ago(10), event: "started" }),
  ].join("\n");
  assert.deepEqual(openRuns(ledger, NOW), ["AUTH-OPEN"]);
});

test("a run that aborted or needs recovery blocks the next one for an hour", () => {
  const entry = (ts, outcome) => line({ ts, taskId: TASK_ID, outcome });
  assert.equal(recentAbort(entry(ago(59), "aborted-fatal"), NOW).outcome, "aborted-fatal");
  assert.equal(recentAbort(entry(ago(59), "needs-recovery"), NOW).outcome, "needs-recovery");
  assert.equal(recentAbort(entry(ago(61), "aborted"), NOW), undefined);
  assert.equal(recentAbort(entry(ago(5), "recorded"), NOW), undefined);
  assert.equal(
    recentAbort([entry(ago(50), "aborted"), entry(ago(5), "recorded")].join("\n"), NOW),
    undefined,
  );
  assert.equal(
    recentAbort(line({ ts: ago(5), taskId: "AUTH-A", outcome: "aborted" }), NOW),
    undefined,
  );
});

test("the operator's no-AUTH-recording confirmation must be recent and not from the future", () => {
  const env = (at) => ({ FS3_NO_AUTH_RECORDING: at });
  assert.equal(confirmedNoAuthRecording(env(ago(59)), NOW), ago(59));
  assert.throws(() => confirmedNoAuthRecording(env(ago(61)), NOW), /FS3_NO_AUTH_RECORDING/);
  assert.throws(
    () => confirmedNoAuthRecording(env(new Date(NOW + 61_000).toISOString()), NOW),
    /FS3_NO_AUTH_RECORDING/,
  );
  assert.equal(confirmedNoAuthRecording(env(new Date(NOW + 30_000).toISOString()), NOW).length, 24);
  assert.throws(() => confirmedNoAuthRecording({}, NOW), /FS3_NO_AUTH_RECORDING/);
  assert.throws(() => confirmedNoAuthRecording(env("yesterday"), NOW), /FS3_NO_AUTH_RECORDING/);
});

test("FS3_PROGRAMS selects by id prefix and an empty selection is an error", () => {
  assert.equal(selectPrograms(PROGRAMS, {}).length, 4);
  assert.deepEqual(
    selectPrograms(PROGRAMS, { FS3_PROGRAMS: "fs-rules-v1/path-wildcard" }).map((p) => p.id),
    ["fs-rules-v1/path-wildcard/v1", "fs-rules-v1/path-wildcard/v2"],
  );
  assert.throws(
    () => selectPrograms(PROGRAMS, { FS3_PROGRAMS: "fs-rules/" }),
    /no program matches/,
  );
});

// ---- comparison -----------------------------------------------------------------------------

const ok200 = { status: 200, body: [{ document: { name: "n" } }] };
const denied = { status: 403, body: [{ error: { status: "PERMISSION_DENIED" } }] };

test("classify: the statuses and their near misses", () => {
  const row = "p#s";
  assert.equal(classify({ row, stale: true, production: ok200, fireemu: ok200 }), "STALE_FIXTURE");
  assert.equal(classify({ row, production: undefined, fireemu: ok200 }), "MISSING_FIXTURE");
  assert.equal(classify({ row, production: ok200, fireemu: undefined }), "MISSING");
  assert.equal(classify({ row, production: ok200, fireemu: ok200 }), "MATCH");
  assert.equal(classify({ row, production: denied, fireemu: ok200 }), "MISMATCH");
  assert.equal(classify({ row, production: ok200, fireemu: denied }), "MISMATCH");
  // Key order is not behaviour.
  assert.equal(
    classify({ row, production: { status: 200, body: [] }, fireemu: { body: [], status: 200 } }),
    "MATCH",
  );
  // Transient answers say nothing.
  for (const transient of [
    { status: 503 },
    { status: 429 },
    { status: 0, transport: "ETIMEDOUT" },
    { grpc: 14 },
    { status: 200, publication: "unsettled" },
  ])
    assert.equal(classify({ row, production: transient, fireemu: ok200 }), "INDETERMINATE");
  assert.equal(classify({ row, production: ok200, fireemu: { status: 502 } }), "INDETERMINATE");
  // Two production recordings that differ are indeterminate, even if fireemu equals one of them.
  assert.equal(
    classify({ row, production: ok200, alternative: denied, fireemu: ok200 }),
    "INDETERMINATE",
  );
});

test("classify: a row that never ran confirms only the same refusal", () => {
  const unresolved = { status: -1, unresolved: "ruleset path-v1 did not compile" };
  const other = { status: -1, unresolved: "ruleset path-v2 did not compile" };
  assert.equal(
    classify({ row: "r", production: unresolved, fireemu: { ...unresolved } }),
    "DEPENDENCY_REFUSED",
  );
  assert.equal(classify({ row: "r", production: unresolved, fireemu: other }), "MISMATCH");
  assert.equal(classify({ row: "r", production: unresolved, fireemu: ok200 }), "MISMATCH");
  assert.equal(classify({ row: "r", production: ok200, fireemu: unresolved }), "MISMATCH");
  assert.equal(
    classify({ row: "r", production: unresolved, alternative: ok200, fireemu: { ...unresolved } }),
    "INDETERMINATE",
  );
});

const allowAll = () => {
  const results = {};
  for (const program of PROGRAMS) {
    results[program.id] = {
      steps: Object.fromEntries(
        program.steps.map((s) => [s.id, s.publish ? { compiled: true } : ok200]),
      ),
    };
  }
  return results;
};

test("compareRows: a production that refuses v1 group queries makes exactly those rows MISMATCH against a permissive fireemu", () => {
  const harness = harnessDigest();
  const fireemu = allowAll();
  const productionSteps = JSON.parse(JSON.stringify(fireemu));
  const v1 = "fs-rules-v1/recursive-wildcard/v1";
  const refusedRows = ["group-none", "group-count-none", "group-grpc-none", "kindless-root-none"];
  for (const id of refusedRows) productionSteps[v1].steps[id] = denied;
  const fixture = {
    programs: Object.fromEntries(
      PROGRAMS.map((p) => [
        p.id,
        {
          corpusDigest: programDigest(p),
          harnessDigest: harness,
          steps: productionSteps[p.id].steps,
        },
      ]),
    ),
  };
  const rows = compareRows({ fixture, programs: PROGRAMS, local: { results: fireemu }, harness });
  const mismatches = rows.filter((r) => r.status === "MISMATCH").map((r) => r.row);
  assert.deepEqual(
    mismatches,
    refusedRows.map((id) => `${v1}#${id}`),
  );
  assert.equal(rows.filter((r) => r.status === "MATCH").length, rows.length - refusedRows.length);
  assert.equal(rows.length, 4 * 20);
});

test("compareRows: a changed corpus or harness makes the saved rows stale, and no fixture is missing rows", () => {
  const fireemu = allowAll();
  const harness = harnessDigest();
  const steps = (p) => fireemu[p.id].steps;
  const make = (change) => ({
    programs: Object.fromEntries(
      PROGRAMS.map((p) => [
        p.id,
        { corpusDigest: programDigest(p), harnessDigest: harness, steps: steps(p), ...change },
      ]),
    ),
  });
  const statuses = (fixture, h = harness) =>
    new Set(
      compareRows({ fixture, programs: PROGRAMS, local: { results: fireemu }, harness: h }).map(
        (r) => r.status,
      ),
    );
  assert.deepEqual([...statuses(make({}))], ["MATCH"]);
  assert.deepEqual([...statuses(make({ corpusDigest: "0".repeat(64) }))], ["STALE_FIXTURE"]);
  assert.deepEqual([...statuses(make({}), "0".repeat(64))], ["STALE_FIXTURE"]);
  assert.deepEqual([...statuses({ programs: {} })], ["MISSING_FIXTURE"]);
});

test("harnessDigest follows every file it covers and is stable", () => {
  const reader = (changed) => (file) => `${file}:${file === changed ? "x" : "same"}`;
  const base = harnessDigest(reader(undefined));
  assert.equal(base, harnessDigest(reader(undefined)));
  for (const file of HARNESS_FILES) assert.notEqual(harnessDigest(reader(file)), base, file);
  assert.match(harnessDigest(), /^[0-9a-f]{64}$/);
});

// ---- the fixture ----------------------------------------------------------------------------

const recording = (steps, diagnostics = {}) => ({
  results: Object.fromEntries(PROGRAMS.map((p) => [p.id, { steps: structuredClone(steps) }])),
  diagnostics,
});
const META = { startedAt: "2026-10-14T00:00:00.000Z", sha: "a".repeat(40), harness: "h" };

test("fixtureText keeps the first recording, the rows that differed, and the refusal text", () => {
  const first = recording(
    { r1: ok200, r2: ok200 },
    { "path-v1": { status: 400, message: "line 6" } },
  );
  const second = recording({ r1: ok200, r2: denied });
  const fixture = JSON.parse(
    fixtureText({ programs: PROGRAMS, recordings: [first, second], meta: META }),
  );
  const entry = fixture.programs["fs-rules-v1/path-wildcard/v1"];
  assert.deepEqual(entry.steps, { r1: ok200, r2: ok200 });
  assert.deepEqual(entry.second, { r2: denied });
  assert.deepEqual(entry.diagnostics, { status: 400, message: "line 6" });
  assert.equal(fixture.programs["fs-rules-v1/recursive-wildcard/v1"].diagnostics, undefined);
  assert.equal(entry.corpusDigest, programDigest(PROGRAMS[2]));
  assert.equal(fixture.recordedAgainst.project, "demo-fs-rules");
  assert.deepEqual(Object.keys(fixture.programs), Object.keys(fixture.programs).toSorted());
  const same = JSON.parse(
    fixtureText({ programs: PROGRAMS, recordings: [first, first], meta: META }),
  );
  assert.equal(same.programs["fs-rules-v1/recursive-wildcard/v1"].second, undefined);
  scanFixture(JSON.stringify(fixture), ["AIzaKey", SANDBOX_PROJECT, "555500000001"]);
});

test("brief: one token per recorded shape", () => {
  assert.equal(brief(undefined), "-");
  assert.equal(brief({ compiled: false }), "compiled=false");
  assert.equal(brief({ status: -1, unresolved: "x" }), "not-published");
  assert.equal(brief(ok200), "200 docs=1");
  assert.equal(brief(denied), "403 PERMISSION_DENIED");
  assert.equal(
    brief({ status: 200, body: [{ result: { aggregateFields: { n: { integerValue: "3" } } } }] }),
    "200 count=3",
  );
  assert.equal(brief({ grpc: 0, messages: [{}, {}] }), "grpc0 msgs=2");
  assert.equal(brief({ grpc: 7 }), "grpc7");
  assert.equal(brief({ status: 404 }), "404");
  const listen = {
    listen: true,
    frames: [
      { kind: "targetChange", type: "ADD" },
      { kind: "documentChange", names: ["a", "b"] },
      { kind: "targetChange", type: "REMOVE", cause: { code: 7 } },
    ],
    end: { code: 7 },
  };
  assert.equal(brief(listen), "listen[ADD,documentChangex2,REMOVE:cause7] end=7");
});

// ---- local side -----------------------------------------------------------------------------

test("fireemu runs strict with productionExact and the emulator profile without the key", () => {
  assert.equal(fireemuConfig("strict").productionExact, true);
  assert.equal(Object.hasOwn(fireemuConfig("emulator"), "productionExact"), false);
  assert.equal(fireemuConfig("emulator").profile, "emulator");
  assert.deepEqual(fireemuConfig("strict").auth.apiKeys, ["fake-api-key"]);
});

test("the mock token is an unsigned anonymous ID token of the project and expires in an hour", () => {
  const token = mockToken("u1", "demo-x", 1000);
  const [header, payload, signature] = token.split(".");
  assert.equal(signature, "");
  assert.deepEqual(JSON.parse(Buffer.from(header, "base64url")), { alg: "none", typ: "JWT" });
  const claims = JSON.parse(Buffer.from(payload, "base64url"));
  assert.equal(claims.exp - claims.iat, 3600);
  assert.equal(claims.aud, "demo-x");
  assert.equal(claims.iss, "https://securetoken.google.com/demo-x");
  assert.equal(claims.sub, "u1");
  assert.equal(claims.firebase.sign_in_provider, "anonymous");
});

// ---- supervising a real child ---------------------------------------------------------------

/** The children are plain node processes; a preloaded module of the parent is not theirs. */
const CHILD_ENV = { ...process.env, NODE_OPTIONS: "" };
const groupAlive = (pgid) => {
  try {
    process.kill(-pgid, 0);
    return true;
  } catch {
    return false;
  }
};
/** A killed process stays listed until its parent (or init) reaps it: give that a moment. */
const groupGone = async (pgid) => {
  for (let i = 0; i < 100 && groupAlive(pgid); i += 1)
    await new Promise((resolve) => setTimeout(resolve, 30));
  return !groupAlive(pgid);
};

test("a child that outlives its timeout is stopped with its whole process group", async () => {
  // The child starts a grandchild in its group, prints its pid, and sleeps forever.
  const script = `const { spawn } = require("node:child_process");
const g = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore" });
console.log(g.pid);
setInterval(() => {}, 1000);`;
  const { exitCode, timedOut, pid } = await runSupervised({
    command: process.execPath,
    args: ["-e", script],
    timeoutMs: 700,
    graceMs: 500,
    env: CHILD_ENV,
    stdio: ["ignore", "ignore", "inherit"],
  });
  assert.equal(timedOut, true);
  assert.notEqual(exitCode, 0);
  assert.equal(await groupGone(pid), true, "no member of the group survives");
});

test("a child that exits by itself leaves nothing behind either", async () => {
  const script = `const { spawn } = require("node:child_process");
spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore" });
process.exit(0);`;
  const { exitCode, timedOut, pid } = await runSupervised({
    command: process.execPath,
    args: ["-e", script],
    timeoutMs: 10_000,
    graceMs: 500,
    env: CHILD_ENV,
    stdio: ["ignore", "ignore", "inherit"],
  });
  assert.equal(exitCode, 0);
  assert.equal(timedOut, false);
  assert.equal(await groupGone(pid), true, "the orphaned grandchild was killed with the group");
});

test("a failing launch is reported as no exit code, not as a hang", async () => {
  const { exitCode, timedOut } = await runSupervised({
    command: "/nonexistent/fs3-binary",
    args: [],
    timeoutMs: 5000,
    env: CHILD_ENV,
    stdio: ["ignore", "ignore", "ignore"],
  });
  assert.equal(exitCode, null);
  assert.equal(timedOut, false);
});
