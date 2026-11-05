// Finite recorded RTDB families that the closure record names as conditions. Offline: reads
// committed records only, performs no network request and starts no process.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { test } from "node:test";

const read = (path) => readFileSync(new URL(`../../${path}`, import.meta.url));
const json = (path) => JSON.parse(read(path));
const sha = (path) => createHash("sha256").update(read(path)).digest("hex");
const exists = (path) => existsSync(new URL(`../../${path}`, import.meta.url));

const CLOSURE = "spec/compatibility/closure/RTDB.json";
const V035 = {
  sourceCommit: "8220a36ad88c136592551ebb94f358d6abe4d909",
  binarySha256: "d511dfc983d32d6e10ef00066c1c906884518c37b3ecd91c958952dda48c1d21",
};
const V041 = {
  path: "spec/compatibility/closure/evidence/RTDB-v041-public-replay.json",
  sourceCommit: "264df6146bed33b85c23bb88b7c2de559f9f5f9f",
  binarySha256: "0030b466385dd160c0521ff8e985141d1d0adc67a3a8841c97744b0f27ed9315",
};
const SDK_SMALL = "spec/compatibility/closure/evidence/RTDB-sdk-small-comparison.json";
// The closure build: an unpublished release-profile build of the source commit (cargo build --release
// --locked -p fireemu, RUSTC_WRAPPER empty, a fresh worktree-local target directory). The Rust sources
// are unchanged between that commit and the commit that carries these records.
const V043 = {
  sourceCommit: "cae9f99c8f0fc3285839cfe6ee02c10c27505ca9",
  binarySha256: "44c3c889b81a07d570e0eeb34eb42f730a42066d03f981c0dac46255279c8401",
};
const SDK_EVENTS = "spec/compatibility/closure/evidence/RTDB-sdk-events-comparison.json";
const EVENTS_FIXTURE = "tools/sdk-smoke-database/fixtures/production-sdk-events.json";

const closure = () => json(CLOSURE);
const condition = (id) => closure().conditions.find((entry) => entry.conditionId === id);

// Every comparison of a finite condition: the fixture and comparison digests, the bound source
// and binary, and the recorded row count in both profiles.
function checkComparison(entry) {
  assert.ok(exists(entry.fixturePath), entry.fixturePath);
  assert.equal(sha(entry.fixturePath), entry.fixtureSha256, entry.fixturePath);
  assert.equal(sha(entry.comparisonPath), entry.comparisonSha256, entry.comparisonPath);
  const evidence = json(entry.comparisonPath);
  if (entry.sideCampaign) {
    assert.equal(entry.comparisonPath, V041.path);
    assert.equal(evidence.sourceCommit, V041.sourceCommit);
    assert.equal(evidence.binarySha256, V041.binarySha256);
    assert.equal(entry.sourceCommit, V041.sourceCommit);
    assert.equal(entry.binarySha256, V041.binarySha256);
    for (const profile of ["strict", "emulator"]) {
      const side = evidence.sideCampaigns[profile][entry.sideCampaign];
      assert.ok(side, `${profile}/${entry.sideCampaign}`);
      if (entry.cellsPerProfile !== undefined) assert.equal(side.cells, entry.cellsPerProfile);
      else assert.equal(side.rows, entry.rowsPerProfile);
      assert.equal(side.sha256, entry.verdictSha256[profile]);
    }
    return;
  }
  assert.equal(evidence.sourceCommit, V035.sourceCommit);
  assert.equal(evidence.binarySha256, V035.binarySha256);
  assert.equal(entry.sourceCommit, V035.sourceCommit);
  assert.equal(entry.binarySha256, V035.binarySha256);
  assert.equal(evidence.productionRequests, 0);
  for (const profile of ["strict", "emulator"]) {
    assert.deepEqual(evidence[profile].summary, {
      rows: entry.rowsPerProfile,
      counts: { MATCH: entry.rowsPerProfile },
    });
  }
}

function checkCondition(id, expected) {
  const entry = condition(id);
  assert.ok(entry, id);
  assert.equal(entry.status, "VERIFIED");
  assert.equal(entry.source, "spec/compatibility/contract.json#database");
  assert.ok(Array.isArray(entry.cases) && entry.cases.length > 0);
  assert.ok(typeof entry.evidence.scope === "string" && /recorded/.test(entry.evidence.scope));
  assert.equal(entry.evidence.productionRequests, 0);
  const comparisons = entry.evidence.comparisons;
  assert.deepEqual(
    comparisons.map((c) => [c.family, c.fixturePath, c.rowsPerProfile ?? c.cellsPerProfile]),
    expected,
  );
  for (const comparison of comparisons) checkComparison(comparison);
  for (const path of entry.evidence.tests) assert.ok(exists(path.split("#")[0]), path);
}

test("the refreshed RTDB record keeps the parent open", () => {
  const record = closure();
  assert.equal(record.parentStatus, "IMPLEMENTING");
  assert.equal(record.closureReview.decision, "CHANGES_REQUESTED");
  assert.match(record.closureReview.note, /refreshed/);
  assert.match(record.closureReview.note, /remains IMPLEMENTING/);
});

test("R9 amends R2 for the recorded families under the cited owner rows", () => {
  const r9 = closure().scopeDecisions.find((entry) => entry.id === "R9");
  assert.ok(r9);
  assert.equal(r9.amends, "R2");
  assert.equal(r9.decidedBy, "project coordinator (delegated by the owner)");
  for (const row of ["1936", "1948", "1956", "1963", "1988", "2118", "2206"])
    assert.match(r9.decisionRef, new RegExp(`\\b${row}\\b`), row);
  for (const id of [
    "RTDB/rest-verbs-and-options",
    "RTDB/rules-evaluation-finite",
    "RTDB/sdk-small-queries-and-writes",
    "RTDB/ondisconnect-prioritized-split",
  ])
    assert.ok(r9.decision.includes(id), id);
});

test("REST verbs, options, query bounds and server values bind their recorded comparisons", () => {
  const F = "tools/sdk-smoke-database/fixtures/";
  checkCondition("RTDB/rest-verbs-and-options", [
    ["next4", `${F}production-rest-next4.json`, 36],
    ["query-bounds", `${F}production-query-bounds.json`, 20],
    ["server-values", `${F}production-rest-server-values.json`, 10],
  ]);
});

test("finite Rules evaluation binds every recorded Rules family", () => {
  const F = "tools/sdk-smoke-database/fixtures/";
  checkCondition("RTDB/rules-evaluation-finite", [
    ["rules-validation", `${F}production-rules-next.json`, 56],
    ["query-rules", `${F}production-query-rules.json`, 20],
    ["rules-language", `${F}production-rules-language.json`, 16],
    ["rules-methods", `${F}production-rules-methods.json`, 58],
    ["rules-operators", `${F}production-rules-operators.json`, 98],
    ["identity", `${F}production-rules-identity.json`, 7],
  ]);
});

test("the three v0.35 priority shapes stay under the prioritized-split condition only", () => {
  const record = closure();
  const split = condition("RTDB/ondisconnect-prioritized-split");
  assert.ok(split.evidence.v035RecordedPriority);
  const ids = record.conditions.map((entry) => entry.conditionId);
  assert.equal(new Set(ids).size, ids.length);
  assert.ok(!ids.includes("RTDB/priority-shapes"));
});

test("the small SDK observer comparison binds the closure build in both profiles", () => {
  const entry = condition("RTDB/sdk-small-queries-and-writes");
  assert.ok(entry);
  assert.equal(entry.status, "VERIFIED");
  const evidence = entry.evidence;
  assert.equal(evidence.comparisonPath, SDK_SMALL);
  assert.equal(sha(SDK_SMALL), evidence.comparisonSha256);
  assert.equal(sha(evidence.fixturePath), evidence.fixtureSha256);
  const comparison = json(SDK_SMALL);
  assert.equal(comparison.kind, "rtdb-production-comparison-v1");
  assert.equal(comparison.parent, "RTDB");
  assert.deepEqual(comparison.conditions, ["RTDB/sdk-small-queries-and-writes"]);
  assert.equal(comparison.binding.sourceCommit, V043.sourceCommit);
  assert.match(comparison.binding.binarySha256, /^[0-9a-f]{64}$/);
  assert.equal(comparison.binding.productionRequests, 0);
  assert.equal(comparison.fixture.sha256, sha(comparison.fixture.path));
  for (const profile of ["strict", "emulator"]) {
    const run = comparison.profiles[profile];
    assert.equal(run.binarySha256, comparison.binding.binarySha256);
    assert.deepEqual(run.counts, { MATCH: 32, MISMATCH: 0, NEEDS_REVIEW: 0 });
    assert.equal(run.match, true);
  }
  assert.deepEqual(comparison.summary.counts, { MATCH: 32, MISMATCH: 0, NEEDS_REVIEW: 0 });
  const regression = closure().integratedRegression.comparisons.find((c) => c.path === SDK_SMALL);
  assert.ok(regression);
  assert.equal(regression.sha256, evidence.comparisonSha256);
  assert.equal(regression.rows, 32);
});

// Each item of the frozen inventory (docs.local/runs/rtdb-closure-4a/inventory.md, G7-G10, G17)
// and of the decided exclusions stays named as unobserved or out of scope. G6 and G13 were recorded
// on 2026-11-04 (RTDB-EVENTS-20261104-01); what lies beyond their recorded cases stays named.
const STILL_UNOBSERVED = [
  "beyond the recorded cases of RTDB/sdk-events-queries-and-transactions",
  "applyLocally false",
  "Node Admin SDK with a service-account credential",
  "writeSizeLimit",
  "syntax-error",
  "beyond the 72 recorded cases of RTDB/rest-options-and-refusals",
  "the settings path with a non-administrator credential",
  "beyond the 70 cases of RTDB/rules-claims-indexes-and-load-texts",
  "a rejected WebSocket auth falling back to anonymous",
  "/knownGaps/triggerDeliveryBeyondBreadth",
  "/knownGaps/credentialsBeyondInvalidRest",
  "Android, Apple, Unity",
  "latency",
];
// Recorded since 2026-10-28/29; none of these may still be called unverified.
const NOW_RECORDED = [
  "inventory G6",
  "inventory G13",
  "UNVERIFIED Node Admin SDK over WebSocket",
  "transaction on an absent node",
  "the Node Admin SDK over WebSocket",
  "orderByKey, orderByPriority and orderByValue windows",
  "UNVERIFIED REST POST/push ids, DELETE",
  "print=silent, equalTo/endAt/startAfter/endBefore",
  "Security Rules .validate, cascading, data/newData/root, query-based rules",
  "UNVERIFIED REST options (inventory G7): timeout",
  "not observed in production: REST timeout, writeSizeLimit values other than small",
  "UNVERIFIED Security Rules beyond the recorded cases (inventory G8): auth.token custom claims",
  "not observed in production: Rules auth.token custom claims and sign-in providers",
  "UNVERIFIED RTDB-triggered Cloud Functions delivery beyond the recorded one (inventory G9)",
  "UNVERIFIED token edge cases (inventory G10): REST auth= with a tampered signature",
  "not observed in production: ID token expiry, tampered signatures",
];

test("outOfScope lists exactly the still-unobserved shapes and the decided exclusions", () => {
  const text = closure().outOfScope.join("\n");
  for (const item of STILL_UNOBSERVED) assert.ok(text.includes(item), item);
  for (const item of NOW_RECORDED) assert.ok(!text.includes(item), item);
});

test("the contract's database entry no longer calls the recorded families unverified", () => {
  const contract = json("spec/compatibility/contract.json");
  const database = contract.surfaces.find((surface) => surface.id === "database");
  const text = [database.decision, ...database.gaps].join("\n");
  for (const item of NOW_RECORDED) assert.ok(!text.includes(item), item);
  assert.ok(
    !/not observed in production: REST POST\/push ids, DELETE/.test(database.gaps.join("\n")),
  );
  for (const item of ["print=silent", "startAfter", "increment", "serverTimestamp"])
    assert.ok(database.decision.includes(item), item);
  for (const item of [
    "writeSizeLimit",
    "WebSocket auth",
    "Node Admin SDK",
    "service-account",
    "tampered",
    "Android",
  ])
    assert.ok(database.gaps.join("\n").includes(item), item);
  for (const item of ["startAt(value, key)", "firebase-admin 14.3.0", "user OAuth access token"])
    assert.ok(database.decision.includes(item), item);
});

test("the Mac controls stay bound to older binaries and the two jar-only differences are known", () => {
  const record = closure();
  for (const key of ["cv09LongPollingCells", "browserRunsOnOlderBinaries"]) {
    const statement = record.knownGaps[key].statement;
    assert.match(statement, /2218/);
    assert.match(statement, /CV03, CV09 and CV12/);
    assert.match(statement, /not re-run/);
    assert.match(statement, /older binaries/);
  }
  for (const key of ["rootWriteListenOrder", "bodyKey768Bytes"]) {
    const entry = record.knownDifferences[key];
    assert.ok(entry, key);
    assert.match(entry.statement, /official emulator/);
    assert.match(entry.statement, /no production answer/);
    assert.match(entry.decisionRef, /2218/);
  }
});

test("the SDK events and Admin SDK comparison binds the closure build in both profiles", () => {
  const comparison = json(SDK_EVENTS);
  assert.equal(comparison.kind, "rtdb-production-comparison-v1");
  assert.equal(comparison.parent, "RTDB");
  assert.deepEqual(comparison.conditions, [
    "RTDB/sdk-events-queries-and-transactions",
    "RTDB/admin-sdk-websocket",
  ]);
  assert.equal(comparison.production.recording, "RTDB-EVENTS-20261104-01");
  assert.match(comparison.production.credential, /user OAuth access token/);
  assert.match(comparison.production.credential, /not a service account/);
  assert.deepEqual(comparison.production.adminStartup, { "r1-admin": true, "r2-admin": true });
  assert.deepEqual(comparison.production.requests, {
    requests: 188,
    direct: 184,
    reserve: 4,
    adc: 1,
    overflow: 0,
  });
  assert.equal(comparison.binding.sourceCommit, V043.sourceCommit);
  assert.equal(comparison.binding.binarySha256, V043.binarySha256);
  assert.equal(comparison.binding.productionRequests, 0);
  assert.equal(comparison.fixture.path, EVENTS_FIXTURE);
  assert.equal(comparison.fixture.sha256, sha(EVENTS_FIXTURE));
  for (const { path, sha256 } of comparison.tool)
    if (path.startsWith("tools/sdk-smoke-database/")) assert.equal(sha(path), sha256, path);
  const cases = { events: 0, admin: 0 };
  for (const profile of ["strict", "emulator"]) {
    const run = comparison.profiles[profile];
    assert.equal(run.binarySha256, V043.binarySha256);
    assert.deepEqual(run.counts, { MATCH: 160, MISMATCH: 0, NEEDS_REVIEW: 0 });
    assert.equal(run.rows.length, 160);
    assert.ok(run.rows.every((row) => row.verdict === "MATCH"));
    assert.deepEqual(
      run.profiles.map((p) => p.name),
      ["r1-ws", "r1-lp", "r2-ws", "r2-lp", "r1-admin", "r2-admin"],
    );
    cases.events += run.rows.filter((row) => !row.profile.endsWith("-admin")).length;
    cases.admin += run.rows.filter((row) => row.profile.endsWith("-admin")).length;
  }
  assert.deepEqual(cases, { events: 2 * 128, admin: 2 * 32 });
  assert.match(comparison.scope, /service-account Admin SDK credential is not claimed/);
  const regression = closure().integratedRegression.comparisons.find((c) => c.path === SDK_EVENTS);
  assert.ok(regression);
  assert.equal(regression.sha256, sha(SDK_EVENTS));
  assert.equal(regression.rows, 160);
  assert.match(regression.binding, /R29/);
});

test("the events and Admin SDK conditions cite the recording and never claim a service account", () => {
  for (const [id, rows] of [
    ["RTDB/sdk-events-queries-and-transactions", { MATCH: 128 }],
    ["RTDB/admin-sdk-websocket", { MATCH: 32 }],
  ]) {
    const entry = condition(id);
    assert.ok(entry, id);
    assert.equal(entry.status, "VERIFIED");
    const evidence = entry.evidence;
    assert.equal(evidence.comparisonPath, SDK_EVENTS);
    assert.equal(evidence.comparisonSha256, sha(SDK_EVENTS));
    assert.equal(evidence.fixturePath, EVENTS_FIXTURE);
    assert.equal(evidence.fixtureSha256, sha(EVENTS_FIXTURE));
    assert.equal(evidence.release, "closure-build");
    assert.equal(evidence.sourceCommit, V043.sourceCommit);
    assert.equal(evidence.binarySha256, V043.binarySha256);
    assert.equal(evidence.productionRequests, 0);
    assert.deepEqual(evidence.rows, { strict: rows, emulator: rows });
    assert.equal(evidence.productionRecordings[0].recording, "RTDB-EVENTS-20261104-01");
    assert.match(evidence.ownerDecisions, /2227/);
    assert.match(evidence.ownerDecisions, /2228/);
    for (const file of evidence.tests) assert.ok(exists(file), file);
  }
  const admin = condition("RTDB/admin-sdk-websocket");
  assert.match(admin.evidence.scope, /user OAuth access token/);
  assert.match(admin.evidence.scope, /service account/);
  assert.match(admin.cases.join("\n"), /deny/);
  const events = condition("RTDB/sdk-events-queries-and-transactions");
  for (const item of ["startAt(1, 'b')", "prevName", "long polling", "multi-path update", "abort"])
    assert.ok(events.cases.join("\n").includes(item), item);
  const r10 = closure().scopeDecisions.find((entry) => entry.id === "R10");
  assert.ok(r10);
  assert.equal(r10.amends, "R2");
  assert.match(r10.decisionRef, /\b2217\b/);
  assert.match(r10.decisionRef, /\b2218\b/);
  for (const id of ["RTDB/sdk-events-queries-and-transactions", "RTDB/admin-sdk-websocket"])
    assert.ok(r10.decision.includes(id), id);
  assert.match(r10.decision, /service account/);
});

// ---- the recordings of 2026-11-04 and 2026-11-05 (scope decision R11), replayed on the closure build ----
const EV = "spec/compatibility/closure/evidence/";
const RECORDINGS = [
  {
    file: "RTDB-sdk-rest-comparison.json",
    condition: "RTDB/rest-options-and-refusals",
    recording: "RTDB-REST-20261104-01",
    comparison: "sdk-rest",
    strict: { MATCH: 144, MISMATCH: 0, NEEDS_REVIEW: 0 },
    emulator: { MATCH: 138, MISMATCH: 6, NEEDS_REVIEW: 0 },
    official: { cases: 144, match: 142 },
    declared: ["wsl-foo", "wsl-10", "malformed-zz"],
  },
  {
    file: "RTDB-sdk-rules-comparison.json",
    condition: "RTDB/rules-claims-indexes-and-load-texts",
    recording: "RTDB-RULES-20261104-01",
    comparison: "sdk-rules",
    strict: { MATCH: 140, MISMATCH: 0, NEEDS_REVIEW: 0 },
    emulator: { MATCH: 140, MISMATCH: 0, NEEDS_REVIEW: 0 },
  },
  {
    file: "RTDB-sdk-rules-load-comparison.json",
    condition: "RTDB/rules-document-load-diagnostics",
    recording: "RTDB-RULES-LOAD-20261105-01",
    comparison: "sdk-rules-load",
    strict: { MATCH: 14, MISMATCH: 0, NEEDS_REVIEW: 0 },
    emulator: { MATCH: 14, MISMATCH: 0, NEEDS_REVIEW: 0 },
    official: { cases: 14, match: 14 },
    declared: [],
  },
  {
    file: "RTDB-sdk-tokens-comparison.json",
    condition: "RTDB/invalid-credentials-rest",
    recording: "RTDB-TOKENS-20261104-01",
    comparison: "sdk-tokens",
    strict: { MATCH: 54, MISMATCH: 0, NEEDS_REVIEW: 0 },
    emulator: { MATCH: 26, MISMATCH: 28, NEEDS_REVIEW: 0 },
    official: { cases: 54, match: 52 },
    declared: [
      "auth-none-other",
      "auth-none-own",
      "auth-rs256",
      "auth-hs256",
      "auth-huge",
      "bearer-random",
      "bearer-none-own",
      "bearer-rs256",
      "bearer-null",
      "bearer-random-pub",
      "at-empty",
      "at-random",
      "at-rs256",
      "at-random-pub",
    ],
  },
];

test("every recording of 2026-11-04/05 binds its fixture, tools and the closure build, and its condition cites it", () => {
  for (const spec of RECORDINGS) {
    const path = EV + spec.file;
    const evidence = json(path);
    assert.equal(evidence.kind, "rtdb-production-comparison-v1", spec.file);
    assert.equal(evidence.parent, "RTDB");
    assert.equal(evidence.comparison, spec.comparison);
    assert.deepEqual(evidence.conditions, [spec.condition]);
    assert.equal(evidence.production.recording, spec.recording);
    assert.equal(evidence.production.project, "fireemu-oracle-query");
    assert.equal(evidence.production.requests.overflow, 0);
    assert.equal(evidence.production.requests.adc, 1);
    assert.equal(evidence.fixture.sha256, sha(evidence.fixture.path), spec.file);
    for (const { path: toolPath, sha256 } of evidence.tool)
      assert.equal(sha(toolPath), sha256, toolPath);
    assert.equal(evidence.binding.sourceCommit, V043.sourceCommit);
    assert.equal(evidence.binding.binarySha256, V043.binarySha256);
    assert.equal(evidence.binding.productionRequests, 0);
    for (const profile of ["strict", "emulator"]) {
      const run = evidence.profiles[profile];
      assert.equal(run.binarySha256, V043.binarySha256, `${spec.file} ${profile}`);
      assert.deepEqual(run.counts, spec[profile], `${spec.file} ${profile}`);
      assert.equal(run.rows.length, evidence.production.observations);
      assert.equal(run.match, run.counts.MATCH === run.rows.length);
    }
    assert.equal(evidence.profiles.strict.match, true, `${spec.file}: strict matches production`);
    const entry = condition(spec.condition);
    assert.ok(entry, spec.condition);
    assert.equal(entry.status, "VERIFIED");
    assert.equal(entry.evidence.comparisonPath, path);
    assert.equal(entry.evidence.comparisonSha256, sha(path));
    assert.equal(entry.evidence.fixturePath, evidence.fixture.path);
    assert.equal(entry.evidence.fixtureSha256, sha(evidence.fixture.path));
    assert.equal(entry.evidence.binarySha256, V043.binarySha256);
    assert.equal(entry.evidence.sourceCommit, V043.sourceCommit);
    assert.equal(entry.evidence.productionRequests, 0);
    for (const file of entry.evidence.tests) assert.ok(exists(file), file);
    const regression = closure().integratedRegression.comparisons.find((c) => c.path === path);
    assert.ok(regression, path);
    assert.equal(regression.sha256, sha(path));
    assert.equal(regression.rows, evidence.production.observations);
  }
});

test("the emulator profile differs from production only where the official emulator jar is the reference, and each difference is declared", () => {
  for (const spec of RECORDINGS.filter((s) => s.official)) {
    const evidence = json(EV + spec.file);
    const official = evidence.official;
    assert.equal(official.jar.version, "4.11.2");
    assert.equal(official.fixture.sha256, sha(official.fixture.path));
    assert.equal(official.emulatorVsOfficial.counts.MATCH, spec.official.match, spec.file);
    const different = evidence.profiles.emulator.rows.filter((row) => row.verdict !== "MATCH");
    assert.deepEqual([...new Set(different.map((row) => row.case))], spec.declared, spec.file);
    assert.equal(official.emulatorDifferencesFromProduction.length, different.length);
    // The emulator profile answers as the jar wherever it differs from production, save the one
    // oversized token (about 4.8 KB) that the jar cannot take through its request-line limit.
    for (const row of official.emulatorDifferencesFromProduction) {
      if (row.case === "auth-huge") assert.equal(row.emulatorMatchesOfficialEmulator, false);
      else assert.equal(row.emulatorMatchesOfficialEmulator, true, `${spec.file} ${row.case}`);
    }
  }
  const record = closure();
  for (const key of ["restEmulatorFollowsOfficialEmulator", "invalidCredentialsEmulatorProfile"]) {
    assert.match(record.knownDifferences[key].statement, /official emulator/);
    assert.ok(exists(record.knownDifferences[key].evidence), key);
  }
  assert.match(record.knownDifferences.invalidCredentialsEmulatorProfile.statement, /request line/);
});

test("the trigger breadth recording binds the production fixture and the local recordings on the closure build", () => {
  const evidence = json(`${EV}RTDB-breadth-comparison.json`);
  assert.equal(evidence.kind, "rtdb-production-comparison-v1");
  assert.deepEqual(evidence.conditions, ["RTDB/functions-trigger-breadth-and-user-auth"]);
  assert.equal(evidence.production.recording, "RTDB-TRIGGERS-BREADTH-20261105-02");
  assert.deepEqual(evidence.production.functions, [
    "g9WrittenV2Retry",
    "g9WrittenV1Retry",
    "g9WrittenV2",
  ]);
  assert.equal(evidence.production.writes, 12);
  assert.equal(evidence.fixture.sha256, sha(evidence.fixture.path));
  for (const profile of ["strict", "emulator"]) {
    assert.equal(
      evidence.localRecordings[profile].sha256,
      sha(evidence.localRecordings[profile].path),
      profile,
    );
    assert.equal(evidence.profiles[profile].binarySha256, V043.binarySha256, profile);
    assert.deepEqual(evidence.profiles[profile].unattributed, { production: 0, local: 0 });
  }
  for (const { path, sha256 } of evidence.tool) assert.equal(sha(path), sha256, path);
  assert.deepEqual(evidence.profiles.strict.totals, { rows: 69, match: 69, difference: 0 });
  assert.deepEqual(evidence.profiles.emulator.totals, { rows: 69, match: 0, difference: 69 });
  assert.equal(evidence.binding.binarySha256, V043.binarySha256);
  const entry = condition("RTDB/functions-trigger-breadth-and-user-auth");
  assert.ok(entry);
  assert.equal(entry.status, "VERIFIED");
  assert.equal(entry.evidence.comparisonSha256, sha(`${EV}RTDB-breadth-comparison.json`));
  assert.deepEqual(entry.evidence.rows, {
    strict: { MATCH: 69 },
    emulator: { DECLARED_DIFFERENCE: 69 },
  });
  assert.match(entry.cases.join("\n"), /app_user/);
  assert.match(entry.cases.join("\n"), /USER/);
  for (const file of entry.evidence.tests) assert.ok(exists(file), file);
  const regression = closure().integratedRegression.comparisons.find(
    (c) => c.path === `${EV}RTDB-breadth-comparison.json`,
  );
  assert.ok(regression);
  assert.equal(regression.rows, 69);
});

test("the trigger gaps the breadth recording closes are gone, and what it leaves is named", () => {
  const record = closure();
  assert.equal(record.knownGaps.triggerUserAuthContext, undefined);
  assert.equal(record.knownGaps.triggerBreadth, undefined);
  const beyond = record.knownGaps.triggerDeliveryBeyondBreadth.statement;
  for (const item of [
    "wildcard instance",
    "per-kind handlers",
    "latency",
    "retry timing",
    "order of deliveries",
  ])
    assert.ok(beyond.includes(item), item);
  assert.match(record.knownGaps.credentialsBeyondInvalidRest.statement, /WebSocket auth/);
  assert.match(record.knownGaps.credentialsBeyondInvalidRest.statement, /generated/);
});

test("scope decision R11 amends R2 for the recorded cases and keeps the parent open", () => {
  const record = closure();
  const r11 = record.scopeDecisions.find((entry) => entry.id === "R11");
  assert.ok(r11);
  assert.equal(r11.amends, "R2");
  for (const row of ["2217", "2218", "2251", "2231", "2239", "2253", "2262", "2266"])
    assert.match(r11.decisionRef, new RegExp(`\\b${row}\\b`), row);
  for (const id of RECORDINGS.map((s) => s.condition).concat(
    "RTDB/functions-trigger-breadth-and-user-auth",
  ))
    assert.ok(r11.decision.includes(id), id);
  assert.match(r11.decision, /The parent remains IMPLEMENTING/);
  assert.equal(record.parentStatus, "IMPLEMENTING");
  assert.equal(record.closureReview.decision, "CHANGES_REQUESTED");
  assert.match(record.closureReview.note, /review of that refresh is pending/);
});
