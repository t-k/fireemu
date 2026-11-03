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
const V043 = { sourceCommit: "afe1234851c593031c1eea2e2304f3e2a0dc3f01" };

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

test("the small SDK observer comparison binds the v0.43.0 release binary in both profiles", () => {
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

// Each item of the frozen inventory (docs.local/runs/rtdb-closure-4a/inventory.md, G6-G10, G13,
// G17) and of the decided exclusions stays named as unobserved or out of scope.
const STILL_UNOBSERVED = [
  "orderByKey",
  "orderByPriority",
  "orderByValue",
  "equalTo",
  "compound cursors",
  "transaction on an absent node",
  "Node Admin SDK",
  "timeout",
  "writeSizeLimit",
  "print=pretty",
  "if-none-match",
  "X-HTTP-Method-Override",
  "callback=",
  "download=",
  ".settings/rules.json",
  "auth.token",
  "sign_in_provider",
  ".indexOn",
  "numeric string concatenation",
  "syntax-error",
  "U+0085",
  "end user",
  "wildcard",
  "redelivery",
  "tampered",
  "wrong-project",
  "alg:none",
  "expired",
  "Android, Apple, Unity",
  "latency",
];
// Recorded since 2026-10-28/29; none of these may still be called unverified.
const NOW_RECORDED = [
  "UNVERIFIED REST POST/push ids, DELETE",
  "print=silent, equalTo/endAt/startAfter/endBefore",
  "Security Rules .validate, cascading, data/newData/root, query-based rules",
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
  for (const item of ["timeout", "auth.token", "Node Admin SDK", "tampered", "Android"])
    assert.ok(database.gaps.join("\n").includes(item), item);
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
