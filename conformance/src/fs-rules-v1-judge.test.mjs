import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { scanFixture } from "./auth-account/fixture-scan.mjs";

import { SANDBOX_PROJECT } from "./fs-rules/harness.mjs";
import { HARNESS_CAP, PROGRAMS, programDigest } from "./fs-rules-v1/corpus.mjs";
import {
  brief,
  ceilings,
  classify,
  comparable,
  compareRows,
  confirmedNoAuthRecording,
  estimatedUsd,
  fireemuConfig,
  fixtureText,
  HARNESS_FILES,
  LOCAL_PROJECT_NUMBER,
  OFFICIAL_PROJECT,
  PASSING,
  sha256,
  harnessDigest,
  mockToken,
  openRuns,
  otherLanesRecently,
  preflightProblems,
  recentAbort,
  selectPrograms,
  TASK_ID,
} from "./fs-rules-v1/judge.mjs";
import { GRACE_MS, runSupervised } from "./fs-rules-v1/supervise.mjs";

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
      { kind: "targetChange", type: "ADD", cause: null },
      { kind: "documentChange", doc: "a" },
      { kind: "documentChange", doc: "b" },
      { kind: "boundary" },
      { kind: "targetChange", type: "REMOVE", cause: { code: 7 } },
    ],
    end: { code: 7 },
  };
  assert.equal(brief(listen), "listen[ADD,documentChangex2,boundary,REMOVE:cause7] end=7");
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
/** Every child names the test directory in its arguments, so a mutation harness can find it. */
/** The children below end by themselves after 15 s, so a test that fails leaves no process. */
const MARK = import.meta.dirname;
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
const g = spawn(process.execPath, ["-e", "setTimeout(() => process.exit(0), 15000)", process.argv[1]], { stdio: "ignore" });
console.log(g.pid);
setTimeout(() => process.exit(0), 15000);`;
  const { exitCode, timedOut, pid } = await runSupervised({
    command: process.execPath,
    args: ["-e", script, MARK],
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
  // The shell exits at once and leaves a background sleep in its group that ignores SIGTERM, which
  // only the SIGKILL sweep after the leader's exit can stop.
  const { exitCode, timedOut, pid } = await runSupervised({
    command: "/bin/sh",
    args: ["-c", "(trap '' TERM; exec sleep 15) & exit 0", MARK],
    timeoutMs: 10_000,
    graceMs: 500,
    env: CHILD_ENV,
    stdio: ["ignore", "ignore", "inherit"],
  });
  assert.equal(exitCode, 0);
  assert.equal(timedOut, false);
  assert.equal(await groupGone(pid), true, "the orphaned sleep was killed with the group");
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

// ---- pinned values and exact boundaries -----------------------------------------------------

test("the names and numbers the recorder is bound to", () => {
  assert.equal(TASK_ID, "FS-3-V1-RULES");
  assert.equal(LOCAL_PROJECT_NUMBER, "123456789012");
  assert.equal(OFFICIAL_PROJECT, "demo-fs3-v1");
  assert.deepEqual([...PASSING].toSorted(), [
    "DEPENDENCY_REFUSED",
    "MATCH",
    "MATCH_NONDETERMINISTIC",
  ]);
  assert.equal(GRACE_MS, 8000);
  assert.equal(sha256("a"), "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb");
});

test("harnessDigest is the SHA-256 of the covered sources joined by newlines", () => {
  const reader = (file) => `<${file}>`;
  assert.equal(harnessDigest(reader), sha256(HARNESS_FILES.map(reader).join("\n")));
  const text = HARNESS_FILES.map((f) => readFileSync(join(import.meta.dirname, f), "utf8")).join(
    "\n",
  );
  assert.equal(harnessDigest(), sha256(text));
});

test("the estimate is rounded to four decimals", () => {
  assert.equal(estimatedUsd(76), 0.0102);
  assert.equal(estimatedUsd(1000), 0.012);
  assert.equal(estimatedUsd(1234), 0.0125);
});

test("preflight problems list their items separated by a comma and a space", () => {
  const problems = preflightProblems({
    ...cleanReport(),
    databases: ["(default)", "a", "b"],
    releases: ["x", "y"],
    otherLanesRecently: ["L1", "L2"],
    openRuns: ["R1", "R2"],
  });
  assert.deepEqual(problems, [
    "databases other than (default) exist: a, b",
    "release(s) exist: x, y",
    "other lanes used the sandbox within 30 minutes: L1, L2",
    "runs still open: R1, R2",
  ]);
});

test("the time windows are exact: 30 minutes, 6 hours, 1 hour, and a minute into the future", () => {
  const entry = (ms, extra = {}) =>
    JSON.stringify({ project: SANDBOX_PROJECT, ts: new Date(NOW - ms).toISOString(), ...extra });
  const MIN = 60_000;
  assert.deepEqual(otherLanesRecently(entry(30 * MIN - 1, { taskId: "A" }), NOW), ["A"]);
  assert.deepEqual(otherLanesRecently(entry(30 * MIN, { taskId: "A" }), NOW), []);
  assert.deepEqual(openRuns(entry(6 * 60 * MIN - 1, { taskId: "A", event: "started" }), NOW), [
    "A",
  ]);
  assert.deepEqual(openRuns(entry(6 * 60 * MIN, { taskId: "A", event: "started" }), NOW), []);
  const abort = (ms) => entry(ms, { taskId: TASK_ID, outcome: "aborted" });
  assert.ok(recentAbort(abort(60 * MIN - 1), NOW));
  assert.equal(recentAbort(abort(60 * MIN), NOW), undefined);
  const confirm = (offsetMs) => ({ FS3_NO_AUTH_RECORDING: new Date(NOW + offsetMs).toISOString() });
  confirmedNoAuthRecording(confirm(-60 * MIN), NOW);
  assert.throws(
    () => confirmedNoAuthRecording(confirm(-60 * MIN - 1), NOW),
    /FS3_NO_AUTH_RECORDING/,
  );
  confirmedNoAuthRecording(confirm(MIN), NOW);
  assert.throws(() => confirmedNoAuthRecording(confirm(MIN + 1), NOW), /FS3_NO_AUTH_RECORDING/);
});

test("classify takes the rows allowed to differ from its caller, and nothing is allowed by default", () => {
  const two = { production: ok200, alternative: denied };
  assert.equal(classify({ row: "p#s", ...two, fireemu: denied }), "INDETERMINATE");
  assert.equal(
    classify({ row: "p#s", ...two, fireemu: ok200 }, { "p#s": "why" }),
    "MATCH_NONDETERMINISTIC",
  );
  assert.equal(
    classify({ row: "p#s", ...two, fireemu: denied }, { "p#s": "why" }),
    "MATCH_NONDETERMINISTIC",
  );
  assert.equal(
    classify({ row: "p#s", ...two, fireemu: { status: 404 } }, { "p#s": "why" }),
    "MISMATCH",
  );
  assert.equal(
    classify({ row: "p#other", ...two, fireemu: ok200 }, { "p#s": "why" }),
    "INDETERMINATE",
  );
  assert.equal(
    classify({ row: "p#s", production: ok200, fireemu: ok200 }, { "p#s": "why" }),
    "MATCH",
  );
  // A refused dependency on one side only is a mismatch, whichever side.
  const unresolved = { status: -1, unresolved: "x" };
  assert.equal(classify({ row: "r", production: unresolved, fireemu: ok200 }), "MISMATCH");
});

test("compareRows keeps the second production answer of a row beside the first", () => {
  const harness = harnessDigest();
  const fireemu = allowAll();
  const alternative = denied;
  const fixture = {
    programs: Object.fromEntries(
      PROGRAMS.map((p) => [
        p.id,
        {
          corpusDigest: programDigest(p),
          harnessDigest: harness,
          steps: fireemu[p.id].steps,
          second: { "group-none": alternative },
        },
      ]),
    ),
  };
  const rows = compareRows({ fixture, programs: PROGRAMS, local: { results: fireemu }, harness });
  const row = rows.find((r) => r.row.endsWith("#group-none"));
  assert.deepEqual(row.alternative, alternative);
  assert.equal(row.status, "INDETERMINATE");
  assert.equal(rows.find((r) => r.row.endsWith("#single-none")).alternative, undefined);
  assert.ok(
    !Object.hasOwn(
      rows.find((r) => r.row.endsWith("#single-none")),
      "alternative",
    ),
  );
});

test("fixtureText: indentation, programs missing from a recording, kept programs and diagnostics", () => {
  const first = recording({ r1: ok200 }, { "path-v1": { status: 400 }, "path-v2": undefined });
  first.results = {
    [PROGRAMS[0].id]: first.results[PROGRAMS[0].id],
    [PROGRAMS[2].id]: first.results[PROGRAMS[2].id],
  };
  const second = recording({ r1: ok200 });
  second.results = { [PROGRAMS[0].id]: second.results[PROGRAMS[0].id] };
  const existing = {
    version: 1,
    recordedAgainst: {},
    programs: { "fs-rules-v1/kept/older": { steps: { r: ok200 } } },
  };
  const text = fixtureText({
    programs: PROGRAMS,
    recordings: [first, second],
    meta: META,
    existing,
  });
  assert.ok(text.startsWith('{\n  "version": 1,\n  "recordedAgainst": {'));
  assert.ok(text.endsWith("}\n"));
  const fixture = JSON.parse(text);
  assert.deepEqual(
    Object.keys(fixture.programs),
    [PROGRAMS[0].id, "fs-rules-v1/kept/older"].toSorted(),
  );
  assert.equal(
    fixture.programs[PROGRAMS[0].id].diagnostics,
    undefined,
    "an empty diagnostics object is not kept",
  );
  assert.match(fixture.recordedAgainst.target, /anonymous end-user ID tokens/);
  assert.match(fixture.recordedAgainst.note, /never compared/);
});

test("brief: a listen that ended names its code, an open one does not; a bare error body names its status", () => {
  const open = { listen: true, frames: [], end: "open" };
  assert.equal(brief(open), "listen[]");
  assert.equal(brief({ ...open, end: { code: 7 } }), "listen[] end=7");
  assert.equal(brief({ grpc: 0 }), "grpc0 msgs=0");
  assert.equal(brief({ status: 404, body: { error: { status: "NOT_FOUND" } } }), "404 NOT_FOUND");
  assert.equal(brief({ status: 200, body: [] }), "200 docs=0");
  assert.equal(
    brief({ listen: true, frames: [{ kind: "filter" }], end: "open" }),
    "listen[filter]",
  );
});

test("fireemu's configuration is exactly what the recording needs", () => {
  const common = {
    schemaVersion: 1,
    daemon: { authProjectNumbers: { [SANDBOX_PROJECT]: "123456789012" } },
    auth: { idTokenSigning: "session-rsa", apiKeys: ["fake-api-key"] },
  };
  assert.deepEqual(fireemuConfig("strict"), {
    ...common,
    profile: "strict",
    productionExact: true,
  });
  assert.deepEqual(fireemuConfig("emulator"), { ...common, profile: "emulator" });
});

test("the mock token defaults to now, in seconds", () => {
  const before = Math.floor(Date.now() / 1000);
  const claims = JSON.parse(Buffer.from(mockToken("u").split(".")[1], "base64url"));
  const after = Math.floor(Date.now() / 1000);
  assert.ok(claims.iat >= before && claims.iat <= after);
  assert.equal(claims.auth_time, claims.iat);
  assert.equal(claims.user_id, "u");
  assert.equal(claims.iss, `https://securetoken.google.com/${OFFICIAL_PROJECT}`);
});

// ---- supervision, more closely --------------------------------------------------------------

const probeFile = (name) => join(mkdtempSync(join(tmpdir(), "fs3-probe-")), name);

test("a child that traps SIGTERM is stopped by SIGTERM, one that ignores it by SIGKILL after the grace", async () => {
  // Shell children, so the trap is in place within milliseconds of the start.
  const graceful = await runSupervised({
    command: "/bin/sh",
    args: ["-c", "trap 'exit 7' TERM; sleep 15 & wait", MARK],
    timeoutMs: 1500,
    graceMs: 5000,
    env: CHILD_ENV,
    stdio: ["ignore", "ignore", "inherit"],
  });
  assert.equal(graceful.timedOut, true);
  assert.equal(graceful.exitCode, 7, "the child ran its own SIGTERM handler");

  const started = Date.now();
  const stubborn = await runSupervised({
    command: "/bin/sh",
    args: ["-c", "trap '' TERM; exec sleep 15", MARK],
    timeoutMs: 1500,
    graceMs: 800,
    env: CHILD_ENV,
    stdio: ["ignore", "ignore", "inherit"],
  });
  assert.equal(stubborn.timedOut, true);
  assert.equal(stubborn.exitCode, null, "killed by a signal, so no exit code");
  assert.ok(Date.now() - started >= 2300, "SIGKILL waited for the grace");
});

test("the environment and the default streams are the child's own", async () => {
  const out = probeFile("env");
  const script = `require("node:fs").writeFileSync(${JSON.stringify(out)}, JSON.stringify({ mark: process.env.FS3_SUPERVISE_MARK ?? null, path: Boolean(process.env.PATH) }));`;
  const withEnv = await runSupervised({
    command: process.execPath,
    args: ["-e", script, MARK],
    env: { ...CHILD_ENV, FS3_SUPERVISE_MARK: "given" },
    timeoutMs: 10_000,
  });
  assert.equal(withEnv.exitCode, 0);
  assert.deepEqual(JSON.parse(readFileSync(out, "utf8")), { mark: "given", path: true });
  process.env.FS3_SUPERVISE_MARK = "inherited";
  // The child inherits this process's environment as it is; a preload of this run is not its own.
  const preload = process.env.NODE_OPTIONS;
  delete process.env.NODE_OPTIONS;
  try {
    const inherited = await runSupervised({
      command: process.execPath,
      args: ["-e", script, MARK],
      timeoutMs: 10_000,
    });
    assert.equal(inherited.exitCode, 0);
    assert.equal(JSON.parse(readFileSync(out, "utf8")).mark, "inherited");
  } finally {
    if (preload !== undefined) process.env.NODE_OPTIONS = preload;
    delete process.env.FS3_SUPERVISE_MARK;
    rmSync(join(out, ".."), { recursive: true, force: true });
  }
});

test("a signal to the supervising process stops the child's group, and the handlers are removed afterwards", async () => {
  const script = `
    import { runSupervised } from ${JSON.stringify(join(import.meta.dirname, "fs-rules-v1/supervise.mjs"))};
    const before = [process.listenerCount("SIGINT"), process.listenerCount("SIGTERM")];
    setTimeout(() => process.kill(process.pid, process.argv[1]), 400);
    const startedAt = Date.now();
    const result = await runSupervised({
      command: process.execPath,
      args: ["-e", "setTimeout(() => process.exit(0), 15000)", process.argv[2]],
      timeoutMs: 30000,
      graceMs: 500,
      env: { PATH: process.env.PATH },
      stdio: ["ignore", "ignore", "inherit"],
    });
    const after = [process.listenerCount("SIGINT"), process.listenerCount("SIGTERM")];
    console.log(JSON.stringify({ before, after, timedOut: result.timedOut, exitCode: result.exitCode, pid: result.pid, seconds: (Date.now() - startedAt) / 1000 }));
  `;
  for (const signal of ["SIGINT", "SIGTERM"]) {
    const done = spawnSync(process.execPath, ["--input-type=module", "-e", script, signal, MARK], {
      env: { PATH: process.env.PATH, NODE_OPTIONS: "" },
      encoding: "utf8",
      timeout: 20_000,
    });
    assert.equal(done.status, 0, done.stderr);
    const result = JSON.parse(done.stdout.trim().split("\n").at(-1));
    assert.equal(result.timedOut, false, signal);
    assert.notEqual(result.exitCode, 0, "the child was stopped, it did not run out its time");
    assert.ok(result.seconds < 8, `${signal}: stopped after ${result.seconds} s`);
    assert.deepEqual(result.after, result.before, "the signal handlers are removed");
    assert.equal(await groupGone(result.pid), true);
  }
});

test("a new fixture starts at version 1", () => {
  const first = recording({ r1: ok200 });
  const fixture = JSON.parse(
    fixtureText({ programs: PROGRAMS, recordings: [first, first], meta: META }),
  );
  assert.equal(fixture.version, 1);
  assert.equal(
    JSON.parse(
      fixtureText({
        programs: PROGRAMS,
        recordings: [first, first],
        meta: META,
        existing: { version: 7, programs: {} },
      }),
    ).version,
    7,
  );
});

// ---- the supervisor as a program of its own ------------------------------------------------

/** Runs `body` (module code using `runSupervised`) in a node process of its own. */
function inProcess(body, timeout = 20_000) {
  const script = `
    import { runSupervised } from ${JSON.stringify(join(import.meta.dirname, "fs-rules-v1/supervise.mjs"))};
    ${body}
  `;
  const started = Date.now();
  const done = spawnSync(process.execPath, ["--input-type=module", "-e", script, MARK], {
    env: { PATH: process.env.PATH, NODE_OPTIONS: "" },
    encoding: "utf8",
    timeout,
  });
  return { ...done, seconds: (Date.now() - started) / 1000 };
}

test("the supervisor's grace timer is cleared once the child has gone, so the process can end", () => {
  const done = inProcess(`
    const result = await runSupervised({
      command: "/bin/sh",
      args: ["-c", "trap 'exit 7' TERM; sleep 15 & wait", process.argv[1]],
      timeoutMs: 400,
      graceMs: 20000,
      env: { PATH: process.env.PATH },
      stdio: ["ignore", "ignore", "inherit"],
    });
    console.log(JSON.stringify({ exitCode: result.exitCode, timedOut: result.timedOut }));
  `);
  assert.equal(done.status, 0, done.stderr);
  assert.deepEqual(JSON.parse(done.stdout.trim()), { exitCode: 7, timedOut: true });
  assert.ok(done.seconds < 10, `the process lingered for ${done.seconds} s`);
});

test("the child's output goes where stdio says, and by default to this process's", () => {
  const body = (stdio) => `
    await runSupervised({
      command: "/bin/sh",
      args: ["-c", "echo child-out; echo child-err >&2", process.argv[1]],
      timeoutMs: 10000,
      env: { PATH: process.env.PATH },
      ${stdio}
    });
  `;
  const silent = inProcess(body('stdio: ["ignore", "ignore", "ignore"],'));
  assert.equal(silent.status, 0, silent.stderr);
  assert.equal(silent.stdout, "");
  assert.equal(silent.stderr, "");
  const defaults = inProcess(body(""));
  assert.equal(defaults.status, 0, defaults.stderr);
  assert.match(defaults.stdout, /child-out/);
  assert.match(defaults.stderr, /child-err/);
  const errOnly = inProcess(body('stdio: ["ignore", "ignore", "inherit"],'));
  assert.equal(errOnly.stdout, "");
  assert.match(errOnly.stderr, /child-err/);
});

// ---- Listen rows in the comparison ----------------------------------------------------------

const listenRow = (frames, end = "open", extra = {}) => ({ listen: true, frames, end, ...extra });
const add = { kind: "targetChange", type: "ADD", targetIds: [1], cause: null, resumeToken: false };
const doc = (name) => ({
  kind: "documentChange",
  doc: name,
  n: "1",
  targetIds: [1],
  removedTargetIds: [],
});
const current = {
  kind: "targetChange",
  type: "CURRENT",
  targetIds: [1],
  cause: null,
  resumeToken: true,
};
const boundary = { kind: "boundary", resumeToken: true };
const filter = { kind: "filter", targetId: 1, count: 1 };
const BASE = [add, doc("p/1"), current, boundary];

test("a Listen that ended on a transient gRPC code, or stayed silent, says nothing about behaviour", () => {
  const allowed = listenRow(BASE);
  for (const code of [4, 8, 13, 14]) {
    const ended = listenRow([], { reason: "error", code, details: "x" });
    assert.equal(
      classify({ row: "p#l", production: ended, fireemu: allowed }),
      "INDETERMINATE",
      String(code),
    );
    assert.equal(
      classify({ row: "p#l", production: allowed, fireemu: ended }),
      "INDETERMINATE",
      String(code),
    );
    assert.equal(
      classify({ row: "p#l", production: allowed, alternative: ended, fireemu: allowed }),
      "INDETERMINATE",
    );
  }
  const silent = listenRow([], "open", { silent: true });
  assert.equal(classify({ row: "p#l", production: silent, fireemu: allowed }), "INDETERMINATE");
  assert.equal(classify({ row: "p#l", production: allowed, fireemu: silent }), "INDETERMINATE");
});

test("a Listen refused with PERMISSION_DENIED is a behaviour, not a transient answer", () => {
  const refused = listenRow([
    {
      kind: "targetChange",
      type: "REMOVE",
      targetIds: [1],
      cause: { code: 7, message: "denied" },
      resumeToken: false,
    },
  ]);
  const errored = listenRow([], { reason: "error", code: 7, details: "denied" });
  const allowed = listenRow(BASE);
  for (const refusal of [refused, errored]) {
    assert.equal(classify({ row: "p#l", production: refusal, fireemu: allowed }), "MISMATCH");
    assert.equal(
      classify({ row: "p#l", production: refusal, fireemu: JSON.parse(JSON.stringify(refusal)) }),
      "MATCH",
    );
  }
  // An error that ended the stream normally (code 0) is not transient either.
  assert.equal(
    classify({
      row: "p#l",
      production: listenRow(BASE, { reason: "ended", code: 0, details: "" }),
      fireemu: listenRow(BASE, { reason: "ended", code: 0, details: "" }),
    }),
    "MATCH",
  );
});

test("an existence filter and the heartbeat after it come and go with timing: they are not compared", () => {
  const withFilter = listenRow([...BASE, filter, boundary]);
  const plain = listenRow(BASE);
  assert.equal(classify({ row: "p#l", production: withFilter, fireemu: plain }), "MATCH");
  assert.equal(classify({ row: "p#l", production: plain, fireemu: withFilter }), "MATCH");
  // Two production recordings that differ only that way are the same behaviour.
  assert.equal(
    classify({ row: "p#l", production: withFilter, alternative: plain, fireemu: plain }),
    "MATCH",
  );
  // Anything else in a Listen still counts: a document, a target change, the order, a token.
  for (const other of [
    listenRow([add, doc("p/2"), current, boundary]),
    listenRow([add, current, boundary]),
    listenRow([add, current, doc("p/1"), boundary]),
    listenRow([add, doc("p/1"), { ...current, resumeToken: false }, boundary]),
    listenRow([add, doc("p/1"), current]),
  ])
    assert.equal(classify({ row: "p#l", production: withFilter, fireemu: other }), "MISMATCH");
  // The filter's own content is not compared, and nor is any other row kind affected.
  assert.equal(
    classify({
      row: "p#l",
      production: listenRow([...BASE, { ...filter, count: 9 }, boundary]),
      fireemu: plain,
    }),
    "MATCH",
  );
  assert.equal(
    classify({ row: "r", production: ok200, alternative: denied, fireemu: ok200 }),
    "INDETERMINATE",
  );
});

test("when the filter goes, the heartbeats around it become the last one, with its token flag", () => {
  const head = [add, doc("p/1"), current];
  const production = listenRow([
    ...head,
    { ...boundary, resumeToken: true },
    filter,
    { ...boundary, resumeToken: false },
  ]);
  const lastOnly = listenRow([...head, { ...boundary, resumeToken: false }]);
  const firstOnly = listenRow([...head, { ...boundary, resumeToken: true }]);
  assert.equal(classify({ row: "p#l", production, fireemu: lastOnly }), "MATCH");
  assert.equal(classify({ row: "p#l", production, fireemu: firstOnly }), "MISMATCH");
  assert.deepEqual(comparable(production).frames.at(-1), { ...boundary, resumeToken: false });
  assert.equal(comparable(production).frames.length, 4);
  assert.equal(comparable(ok200), ok200);
});
