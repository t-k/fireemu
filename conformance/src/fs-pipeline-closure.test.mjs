// The FS-PIPELINE closure record against its committed comparison: every digest is a real
// digest, every claimed row is a MATCH row of the comparison, the counts of each condition add
// up, and the comparison is the one the release job reruns. Nothing here sends a request.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { PROGRAMS } from "./fs-ent-pipeline/corpus.mjs";
import { planComparisons, RUNS } from "./release-strict-regression.mjs";

const repo = (path) => new URL(`../../${path}`, import.meta.url);
const text = (path) => readFileSync(repo(path), "utf8");
const json = (path) => JSON.parse(text(path));
const sha256 = (path) =>
  createHash("sha256")
    .update(readFileSync(repo(path)))
    .digest("hex");

const CLOSURE = "spec/compatibility/closure/FS-PIPELINE.json";
const closure = json(CLOSURE);
// The comparison of record is the current one; the v0.35 comparison stays as history.
const comparison = json(closure.integratedRegression.comparisons[0].path);
const status = new Map(comparison.rows.map((row) => [row.row, row.status]));
const V035 = "spec/compatibility/closure/evidence/FS-PIPELINE-comparison.json";
const v035 = json(V035);
const v035Status = new Map(v035.rows.map((row) => [row.row, row.status]));
const V041 = "conformance/fs-ent-pipeline-v041-comparison.json";

/** Every [key, value] of a JSON value, with the path of the key. */
function* entries(value, path = "") {
  if (Array.isArray(value)) {
    for (const [index, item] of value.entries()) yield* entries(item, `${path}[${index}]`);
  } else if (value && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      yield [`${path}.${key}`, key, item];
      yield* entries(item, `${path}.${key}`);
    }
  }
}

/** The digest fields of a closure record that are not real digests. */
export function badDigests(record) {
  const bad = [];
  for (const [path, key, value] of entries(record)) {
    if (
      /(Sha256|Digest)$/.test(key) &&
      !(typeof value === "string" && /^[0-9a-f]{64}$/.test(value))
    )
      bad.push(`${path}: ${JSON.stringify(value)}`);
  }
  return bad;
}

/** The strings of a closure record that still hold a placeholder in angle brackets. */
export function placeholders(record) {
  const found = [];
  for (const [path, , value] of entries(record)) {
    if (typeof value === "string" && /<[^<>\s][^<>]*>/.test(value)) found.push(path);
  }
  return found;
}

// These recorded framing cases have differing production response-unit boundaries.
const FRAMING = new Set([
  "fs-ent-pipeline/o8a/framing-small#f500-rest",
  "fs-ent-pipeline/o8a/framing-small#f500-grpc",
  "fs-ent-pipeline/o8a/framing-small#f5000-rest",
  "fs-ent-pipeline/o8a/framing-small#f5000-grpc",
  "fs-ent-pipeline/o8a/framing-small#f5000-select-rest",
  "fs-ent-pipeline/o8a/framing-small#f5000-select-grpc",
  "fs-ent-pipeline/o8a/framing-small#f5000-limit-rest",
  "fs-ent-pipeline/o8a/framing-small#f5000-limit-grpc",
  "fs-ent-pipeline/o8a/framing-large#l12-rest",
  "fs-ent-pipeline/o8a/framing-large#l12-grpc",
  "fs-ent-pipeline/o8a/framing-large#m30-rest",
  "fs-ent-pipeline/o8a/framing-large#m30-grpc",
]);
const O7_CONTRACT = "conformance/fs-ent-pipeline-o7-adjudication.json";
const O6_CONTRACT = "conformance/fs-ent-pipeline-o6-adjudication.json";
const SAMPLE_CONTRACT = "conformance/fs-ent-pipeline-sample-adjudication.json";
const NESTING_OBSERVATION = "conformance/fs-ent-pipeline-nesting-observation.json";
// The rows the sample, O-7 and O-6 contracts name by their original raw MISMATCH.
const SAMPLE_ROWS = new Set(
  json(SAMPLE_CONTRACT)
    .proofs.filter((proof) => proof.rawStatus === "MISMATCH")
    .map((proof) => proof.id),
);
const O7_ROWS = new Set(json(O7_CONTRACT).proofs.map((proof) => proof.id));
const O6_ROWS = new Set(json(O6_CONTRACT).proofs.map((proof) => proof.id));
const CLOCK_ROW = "fs-ent-pipeline/o8c/timestamps-main#timestamp-diff-now";
// The raw MISMATCH rows are owner-decided divergences, listed in the conditions' evidence.
const DIVERGENCES = closure.conditions.flatMap((condition) =>
  (condition.evidence.documentedDivergences ?? []).map((divergence) => ({
    ...divergence,
    conditionId: condition.conditionId,
  })),
);
const DIVERGENT_ROWS = new Set(DIVERGENCES.map((divergence) => divergence.row));
const NESTING_ROWS = new Set([
  "fs-ent-pipeline/o8a/nesting-main#chain-48-grpc",
  "fs-ent-pipeline/o8a/nesting-main#chain-100-grpc",
]);

/** A status other than MATCH is allowed only for the exact rows a recorded decision covers. */
function isUnclaimedStatusAllowed(row, status) {
  if (status === "MATCH_NONDETERMINISTIC") return FRAMING.has(row) || SAMPLE_ROWS.has(row);
  if (status === "MISMATCH") return DIVERGENT_ROWS.has(row);
  if (status === "UNKNOWN") return NESTING_ROWS.has(row);
  return false;
}

test("a status other than MATCH is allowed only for the rows a recorded decision covers", () => {
  assert.equal(FRAMING.size, 12);
  assert.equal(SAMPLE_ROWS.size, 5);
  assert.equal(O7_ROWS.size, 23);
  assert.equal(O6_ROWS.size, 2);
  const framing = "fs-ent-pipeline/o8a/framing-small#f500-rest";
  const sample = "fs-ent-pipeline/o8d/stages-main#sample-documents-2";
  const o7 = "fs-ent-pipeline/o7/aggregate-basic#grouped-all";
  const o6 = "fs-ent-pipeline/o6/sort-ties#g-asc-limit2";
  const other = "fs-ent-pipeline/px1/select#equal-i-d5";
  const nesting = "fs-ent-pipeline/o8a/nesting-main#chain-48-grpc";
  assert.equal(isUnclaimedStatusAllowed(framing, "MATCH_NONDETERMINISTIC"), true);
  assert.equal(isUnclaimedStatusAllowed(sample, "MATCH_NONDETERMINISTIC"), true);
  assert.equal(isUnclaimedStatusAllowed(other, "MATCH_NONDETERMINISTIC"), false);
  assert.equal(
    isUnclaimedStatusAllowed(
      "fs-ent-pipeline/o8a/framing-small#unobserved",
      "MATCH_NONDETERMINISTIC",
    ),
    false,
  );
  assert.equal(isUnclaimedStatusAllowed(framing, "INDETERMINATE"), false);
  assert.equal(isUnclaimedStatusAllowed(framing, "MATCH"), false);
  for (const row of [o7, o6, CLOCK_ROW])
    assert.equal(isUnclaimedStatusAllowed(row, "MISMATCH"), true);
  assert.equal(isUnclaimedStatusAllowed(other, "MISMATCH"), false);
  assert.equal(isUnclaimedStatusAllowed(sample, "MISMATCH"), false);
  assert.equal(isUnclaimedStatusAllowed(nesting, "UNKNOWN"), true);
  assert.equal(isUnclaimedStatusAllowed(other, "UNKNOWN"), false);
  assert.equal(isUnclaimedStatusAllowed(nesting, "MISMATCH"), false);
});

test("a digest field that is not 64 hex characters, or a placeholder, is found", () => {
  assert.deepEqual(badDigests({ a: { fooSha256: "0".repeat(64), barSha256: "<computed>" } }), [
    '.a.barSha256: "<computed>"',
  ]);
  assert.equal(badDigests({ x: [{ binarySha256: "ABC" }] }).length, 1);
  assert.equal(badDigests({ x: { releaseBinarySha256: 5 } }).length, 1);
  assert.equal(badDigests({ x: { releaseBinarySha256: "a".repeat(63) } }).length, 1);
  assert.deepEqual(badDigests({ note: "no digest here", sha: "short" }), []);
  assert.deepEqual(placeholders({ a: ["fine", { b: "<the closure head>" }] }), [".a[1].b"]);
  assert.deepEqual(placeholders({ a: "a < b and c > d", b: "5 <= 6" }), []);
});

test("the FS-PIPELINE record holds no placeholder and its digests are the files'", () => {
  assert.deepEqual(placeholders(closure), []);
  assert.equal(closure.parent, "FS-PIPELINE");
  const ir = closure.integratedRegression;
  assert.equal(ir.releaseBinarySha256, comparison.artifactSha256);
  assert.equal(sha256(ir.buildReceiptPath), ir.buildReceiptSha256);
  assert.equal(json(ir.buildReceiptPath).binarySha256, ir.releaseBinarySha256);
  assert.equal(json(ir.buildReceiptPath).sourceCommit, ir.integrationCommit);
  assert.match(ir.integrationCommit, /^[0-9a-f]{40}$/);
  assert.equal(comparison.kind, "fs-ent-pipeline-comparison-v1");
  assert.equal(comparison.fixtureSha256, sha256("conformance/fs-ent-pipeline-production.json"));
  assert.deepEqual(ir.comparisons.length, 1);
  const [entry] = ir.comparisons;
  assert.equal(entry.sha256, sha256(entry.path));
  assert.equal(entry.rows, comparison.rows.length);
  assert.deepEqual(entry.summary, comparison.summary);
  assert.deepEqual(closure.perCaseAdjudication.summary, comparison.summary);
  assert.equal(closure.perCaseAdjudication.sha256, sha256(closure.perCaseAdjudication.path));
  for (const [, key, value] of entries(closure)) {
    if (key.endsWith("Path") && typeof value === "string" && !value.startsWith("docs.local/"))
      assert.ok(readFileSync(repo(value)), value);
  }
  const frame = closure.knownDifferences.notClaimed_response_framing_large;
  assert.equal(frame.framingSummarySha256, sha256(frame.framingSummaryPath));
});

test("every claimed row is a MATCH row of the comparison, once, and each condition's counts add up", () => {
  const claimed = new Set();
  const unclaimedMatches = closure.knownDifferences.notClaimed_newly_matching.matchingRows;
  assert.equal(new Set(unclaimedMatches).size, unclaimedMatches.length);
  for (const condition of closure.conditions) {
    assert.equal(condition.status, "VERIFIED", condition.conditionId);
    const mine = [];
    for (const row of condition.recipeIds) {
      assert.equal(status.get(row), "MATCH", `${condition.conditionId}: ${row}`);
      assert.ok(!claimed.has(row), `${row} is claimed twice`);
      claimed.add(row);
      mine.push(row);
    }
    const family = [...status.keys()].filter((row) =>
      condition.rowPrefixes.some((prefix) =>
        row.replace("fs-ent-pipeline/", "").startsWith(prefix),
      ),
    );
    const matching = family.filter((row) => status.get(row) === "MATCH");
    assert.deepEqual(
      mine.toSorted(),
      matching.filter((row) => !unclaimedMatches.includes(row)).toSorted(),
      condition.conditionId,
    );
    assert.deepEqual(condition.evidence.rows, {
      MATCH: mine.length,
      NOT_CLAIMED: family.length - mine.length,
    });
    assert.equal(condition.evidence.comparisonSha256, sha256(condition.evidence.comparisonPath));
    assert.equal(condition.evidence.fixtureSha256, sha256(condition.evidence.fixturePath));
    assert.equal(condition.evidence.releaseBinarySha256, comparison.artifactSha256);
  }
  // Every row is claimed, belongs to a not-claimed family, or has no per-row fixture.
  const unclaimed = [...status].filter(([row]) => !claimed.has(row));
  const nonClaimed = unclaimed.filter(
    ([row, s]) => s !== "MISSING_FIXTURE" && !unclaimedMatches.includes(row),
  );
  const mismatching = nonClaimed.filter(([row, s]) => !isUnclaimedStatusAllowed(row, s));
  assert.deepEqual(mismatching, [], "an unclaimed row is covered by no recorded decision");
  assert.equal(
    [...status.values()].filter((s) => s === "MATCH").length,
    claimed.size + [...status].filter(([row, s]) => s === "MATCH" && !claimed.has(row)).length,
  );
  // The explicitly pinned matching rows remain unclaimed until independently reviewed.
  const leftover = [...status].filter(([row, s]) => s === "MATCH" && !claimed.has(row));
  assert.deepEqual(leftover.map(([row]) => row).toSorted(), unclaimedMatches.toSorted());
});

test("the comparison covers the committed corpus and the lane's rows add up", () => {
  const rows = new Set(status.keys());
  const expected = PROGRAMS.filter((p) => p.id.startsWith("fs-ent-pipeline/")).flatMap((p) =>
    p.steps.map((s) => `${p.id}#${s.id}`),
  );
  assert.deepEqual([...rows].toSorted(), expected.toSorted());
  assert.equal(comparison.rows.length, rows.size, "a row exported twice");
  const total = Object.values(comparison.summary).reduce((a, b) => a + b, 0);
  assert.equal(total, rows.size);
  // The two rows the recorder's own client could not serialize count as neither match nor mismatch.
  assert.equal(status.get("fs-ent-pipeline/o8a/nesting-main#chain-48-grpc"), "UNKNOWN");
  assert.equal(status.get("fs-ent-pipeline/o8a/nesting-main#chain-100-grpc"), "UNKNOWN");
});

test("the release job reruns the comparison: one run of this kind, check exits 0 by coverage", () => {
  const runs = RUNS.filter((run) => run.kind === comparison.kind);
  assert.equal(runs.length, 1);
  const [run] = runs;
  assert.deepEqual(run.clear, ["fs-ent-pipeline"]);
  assert.deepEqual(run.commands[0].expectedExitCodes, [0]);
  assert.equal(run.commands[0].env.FIREEMU_SANDBOX_LANE, "fs-ent-pipeline");
  // The parent is promoted only with every condition VERIFIED and an approved closure review.
  assert.equal(
    closure.parentStatus === "COMPAT_VERIFIED",
    closure.conditions.every(({ status: value }) => value === "VERIFIED") &&
      closure.closureReview.decision === "APPROVED",
  );
  const plan = planComparisons([{ closure, path: CLOSURE }], (path) =>
    path === closure.integratedRegression.comparisons[0].path ? comparison : undefined,
  );
  assert.deepEqual(
    plan.errors.filter((e) => e.includes("FS-PIPELINE") || e.includes("fs-ent-pipeline")),
    [],
  );
  assert.deepEqual(
    plan.comparisons.map((c) => c.runIds),
    [[run.id]],
  );
});

test("v0.35 history is preserved and its controlled clock stays bound to its binary", () => {
  const history = closure.historicalIntegratedRegression;
  assert.equal(history.comparisons[0].path, V035);
  assert.equal(sha256(V035), history.comparisons[0].sha256);
  assert.deepEqual(v035.summary, {
    MATCH: 1740,
    MISMATCH: 197,
    INDETERMINATE: 12,
    UNKNOWN: 2,
  });
  assert.equal(v035.artifactSha256, history.releaseBinarySha256);
  assert.equal(v035Status.get(CLOCK_ROW), "MISMATCH");
  const clock = json(history.clockDiffControlPath);
  assert.equal(sha256(history.clockDiffControlPath), history.clockDiffControlSha256);
  assert.equal(clock.recipe, CLOCK_ROW);
  assert.equal(clock.binarySha256, v035.artifactSha256);
  assert.equal(clock.derivedSeconds, "1927857906");
  assert.equal(clock.response[0].results[0].fields.v.integerValue, clock.derivedSeconds);
});

test("the current comparison equals the v0.41 baseline row by row and keeps its raw statuses", () => {
  const baseline = json(V041);
  assert.equal(comparison.fixtureSha256, baseline.fixtureSha256);
  assert.deepEqual(comparison.summary, baseline.summary);
  assert.deepEqual(comparison.summary, {
    MATCH: 1906,
    MISMATCH: 26,
    MATCH_NONDETERMINISTIC: 17,
    UNKNOWN: 2,
  });
  assert.deepEqual(comparison.rows, baseline.rows);
  assert.equal(status.get(CLOCK_ROW), "MISMATCH");
  assert.equal(closure.integratedRegression.productionRequests, 0);
});

test("the current clock controls are bound to the current binary and the pinned clock", () => {
  const ir = closure.integratedRegression;
  for (const [path, digest] of [
    [ir.clockControlPath, ir.clockControlSha256],
    [ir.clockDiffControlPath, ir.clockDiffControlSha256],
  ]) {
    assert.equal(sha256(path), digest);
    const control = json(path);
    assert.equal(control.binarySha256, comparison.artifactSha256);
    assert.equal(control.sourceCommit, ir.integrationCommit);
    assert.equal(control.fixtureSha256, comparison.fixtureSha256);
    assert.equal(control.configuredClock, "2031-02-03T04:05:06.123456789Z");
    assert.equal(control.productionRequests, 0);
    assert.equal(control.status, 200);
  }
  const instant = json(ir.clockControlPath);
  assert.equal(instant.recipe, "fs-ent-pipeline/o8c/timestamps-main#current-timestamp-ok");
  assert.equal(instant.response[0].results[0].fields.v.timestampValue, instant.expectedClock);
  const diff = json(ir.clockDiffControlPath);
  assert.equal(diff.recipe, CLOCK_ROW);
  assert.equal(diff.derivedSeconds, "1927857906");
  assert.equal(diff.response[0].results[0].fields.v.integerValue, diff.derivedSeconds);
  const timestamps = closure.conditions.find(
    (condition) => condition.conditionId === "FS-PIPELINE/recorded-timestamps",
  );
  assert.equal(timestamps.evidence.clockControlSha256, ir.clockControlSha256);
  assert.equal(timestamps.evidence.clockDiffControlSha256, ir.clockDiffControlSha256);
});

test("the record states the platform of its controls and what the release job reruns", () => {
  const note = closure.integratedRegression.platformNote;
  assert.match(note, /Darwin arm64/);
  assert.match(note, /linux-x64 package/);
  assert.match(note, /no native Linux arm64 replay is required/);
  assert.equal(json(closure.integratedRegression.buildReceiptPath).host, "Darwin arm64");
});

test("the 166 rows added after v0.35 are the rows that changed from MISMATCH to MATCH", () => {
  const promotion = closure.recordedLeafReview.currentPromotion;
  const approved = closure.closureReview.decision === "APPROVED";
  assert.equal(
    promotion.decision,
    approved ? "ACCEPTED_AFTER_INDEPENDENT_REVIEW" : "PROPOSED_PENDING_INDEPENDENT_REVIEW",
  );
  assert.equal(sha256(promotion.claimSetPath), promotion.claimSetSha256);
  assert.equal(promotion.comparisonSha256, closure.integratedRegression.comparisons[0].sha256);
  const added = json(promotion.claimSetPath);
  assert.equal(added.decision, promotion.decision);
  assert.equal(added.binarySha256, comparison.artifactSha256);
  assert.equal(added.sourceCommit, closure.integratedRegression.integrationCommit);
  assert.equal(added.previousComparisonSha256, sha256(V035));
  assert.equal(added.strictRecipeIds.length, 166);
  assert.equal(promotion.addedRecipeCount, added.strictRecipeIds.length);
  assert.deepEqual(
    added.strictRecipeIds.toSorted(),
    [...status]
      .filter(([row, value]) => value === "MATCH" && v035Status.get(row) !== "MATCH")
      .map(([row]) => row)
      .toSorted(),
  );
  for (const row of added.strictRecipeIds) assert.equal(v035Status.get(row), "MISMATCH", row);
  const claimed = new Set(closure.conditions.flatMap((condition) => condition.recipeIds));
  for (const row of added.strictRecipeIds) assert.ok(claimed.has(row), row);
  assert.equal(claimed.size, promotion.previousClaimedRecipeCount + added.strictRecipeIds.length);
  for (const [row, value] of v035Status) if (value === "MATCH") assert.ok(claimed.has(row), row);
});

test("every raw MISMATCH row is an owner-decided divergence of the condition that holds it", () => {
  const mismatching = [...status].filter(([, value]) => value === "MISMATCH").map(([row]) => row);
  assert.equal(mismatching.length, 26);
  assert.deepEqual(DIVERGENCES.map(({ row }) => row).toSorted(), mismatching.toSorted());
  assert.equal(DIVERGENT_ROWS.size, DIVERGENCES.length, "a row is a divergence twice");
  const decisions = new Map(closure.scopeDecisions.map((decision) => [decision.id, decision]));
  const ledger = { P4: ["2114", "2117"], P6: ["2211"] };
  for (const divergence of DIVERGENCES) {
    const label = `${divergence.conditionId}: ${divergence.row}`;
    assert.equal(divergence.rawStatus, "MISMATCH", label);
    assert.equal(divergence.decidedBy, "owner", label);
    assert.equal(divergence.decidedOn, "2026-11-03", label);
    assert.ok(divergence.reason.length > 20, label);
    const decision = decisions.get(divergence.scopeDecision);
    assert.equal(decision?.decidedBy, "owner", label);
    for (const id of ledger[divergence.scopeDecision] ?? [])
      assert.ok(decision.decisionRef.includes(id), label);
    assert.equal(divergence.contractSha256, sha256(divergence.contractPath), label);
    const condition = closure.conditions.find((c) => c.conditionId === divergence.conditionId);
    assert.ok(
      condition.rowPrefixes.some((prefix) =>
        divergence.row.replace("fs-ent-pipeline/", "").startsWith(prefix),
      ),
      label,
    );
    assert.ok(!condition.recipeIds.includes(divergence.row), `${label} is not claimed`);
  }
  const rowsOf = (decision, contract) =>
    DIVERGENCES.filter((d) => d.scopeDecision === decision && d.contractPath === contract)
      .map(({ row }) => row)
      .toSorted();
  assert.deepEqual(rowsOf("P6", O7_CONTRACT), [...O7_ROWS].toSorted());
  assert.deepEqual(rowsOf("P4", O6_CONTRACT), [...O6_ROWS].toSorted());
  assert.deepEqual(
    DIVERGENCES.filter((d) => d.row === CLOCK_ROW).map((d) => [d.scopeDecision, d.contractPath]),
    [["P6", closure.integratedRegression.clockDiffControlPath]],
  );
  assert.equal(DIVERGENCES.length, O7_ROWS.size + O6_ROWS.size + 1);
});

test("the closure basis enumerates every unobserved item and names the owner decisions", () => {
  const basis = closure.closureBasis;
  assert.equal(basis.productionRequests, 0);
  assert.ok(basis.ownerDecision.includes("(2212)"));
  assert.ok(basis.divergenceDecision.includes("(2211)"));
  const p5 = closure.scopeDecisions.find((decision) => decision.id === "P5");
  assert.ok(p5.decisionRef.includes("(2212)"));
  assert.ok(p5.decision.includes("replaces ledger 1866 for FS-PIPELINE only"));
  const keys = basis.notClaimedItems.map((item) => item.key);
  assert.equal(new Set(keys).size, keys.length);
  for (const key of keys) assert.ok(closure.knownDifferences[key]?.statement, key);
  // The items the owner named in ledger 2212 are all listed.
  for (const key of [
    "notClaimed_scan_order_edges",
    "notClaimed_is_type_vector",
    "notClaimed_N4_standard_and_non_owner",
    "notClaimed_N6_other_write_methods",
    "notClaimed_duplicate_quoted_path",
    "notClaimed_select_name_forms",
    "notClaimed_regex_unicode",
    "notClaimed_argument_shape_space",
  ])
    assert.ok(keys.includes(key), key);
});

test("the capability and generated inventory describe recorded unnest and base64 behavior", () => {
  const capabilities = text("crates/fireemu/src/capabilities.json");
  const features = text("spec/compatibility/features.json");
  const inventory = text("docs/compatibility/firestore-enterprise-native.md");
  for (const source of [capabilities, features, inventory]) {
    assert.ok(!source.includes("union, unnest and sample remain unsupported"));
    assert.ok(source.includes("recorded unnest"));
  }
  const unimplemented = json("crates/fireemu/src/capabilities.json")["FS-PIPE-RPC-1"].unimplemented;
  assert.ok(!unimplemented[0].includes("union, unnest, sample"));
  for (const name of [
    "array_slice",
    "array_first_n",
    "array_last_n",
    "array_index_of",
    "join",
    "maximum_n",
    "minimum_n",
  ])
    assert.ok(unimplemented[1].includes(name));
  assert.ok(!capabilities.includes("paths accept base64 values with line breaks"));
  assert.ok(capabilities.includes("recorded CR/LF and mixed alphabets"));
});

test("v0.35 promotes exactly the accepted 55 strict rows and preserves all other raw statuses", () => {
  const previous = json("spec/compatibility/closure/evidence/FS-PIPELINE-comparison-v034.json");
  const accepted = json("spec/compatibility/closure/evidence/FS-PIPELINE-v035-55-claims.json");
  assert.equal(accepted.strictRecipeIds.length, 55);
  assert.equal(new Set(accepted.strictRecipeIds).size, 55);
  assert.equal(
    sha256(closure.recordedLeafReview.v035Promotion.claimSetPath),
    closure.recordedLeafReview.v035Promotion.claimSetSha256,
  );
  const before = new Map(previous.rows.map((row) => [row.row, row.status]));
  assert.deepEqual([...v035Status.keys()].toSorted(), [...before.keys()].toSorted());
  const changed = [...v035Status].filter(([row, value]) => before.get(row) !== value);
  assert.equal(changed.length, 55);
  assert.deepEqual(changed.map(([row]) => row).toSorted(), accepted.strictRecipeIds.toSorted());
  for (const [row, value] of changed) {
    assert.equal(before.get(row), "MISMATCH", row);
    assert.equal(value, "MATCH", row);
  }
  assert.equal(accepted.sourceCommit, closure.historicalIntegratedRegression.integrationCommit);
  assert.equal(accepted.binarySha256, v035.artifactSha256);
});

test("finite contract adjudications preserve their declared finite outcomes", () => {
  const contracts = closure.finiteContractEvidence;
  assert.deepEqual(
    contracts.map((item) => item.kind),
    ["sample", "o7-order", "scalar-subquery", "native-positive", "nesting-grpc-observation"],
  );
  for (const entry of contracts) {
    assert.equal(entry.sha256, sha256(entry.path));
    if (entry.kind === "native-positive") {
      const proof = json(entry.path);
      assert.equal(proof.kind, "fs-ent-pipeline-native-positive-observation-v1");
      assert.equal(proof.decision, "ACCEPTED_FINITE_VALUE_AND_SHAPE_CONTRACT");
      assert.equal(proof.contract, "FINITE_VALUE_AND_SHAPE_ONLY");
      assert.equal(proof.parentClosureClaimed, false);
      const cohort = closure.recordedLeafReview.v041Promotion;
      const finalComparison = json(cohort.comparisonPath);
      assert.equal(sha256(cohort.comparisonPath), cohort.comparisonSha256);
      assert.equal(proof.binarySha256, cohort.binarySha256);
      assert.equal(proof.binarySha256, finalComparison.artifactSha256);
      assert.equal(proof.sourceCommit, cohort.sourceCommit);
      assert.equal(proof.fixtureSha256, sha256("conformance/fs-native-positive/production.json"));
      assert.equal(
        proof.requestCorpusSha256,
        sha256("conformance/fs-native-positive/program.json"),
      );
      assert.equal(proof.typedFieldComparisons, 296);
      assert.equal(proof.localReplays.length, 8);
      assert.equal(proof.productionJournals.length, 3);
      for (const row of [...proof.productionJournals, ...proof.localReplays])
        assert.match(row.sha256, /^[a-f0-9]{64}$/);
      assert.equal(proof.proofs.length, 216);
      assert.equal(proof.productionMetadata.length, 54);
      assert.equal(proof.localMetadata.length, 216);
      assert.equal(proof.policy.absoluteTimeEquality, false);
      assert.deepEqual(badDigests(proof), []);
      continue;
    }
    if (entry.kind === "scalar-subquery") {
      const proof = json(entry.path);
      assert.equal(proof.profile, "strict");
      assert.equal(proof.sourceCommit, "1bdc3cdd794de3166b65f72188e04bd0ea30a66a");
      assert.equal(
        proof.binarySha256,
        "c33360d75467ebee4cf2857bcd6b314429f6405d34a3676952ce9231904ead2a",
      );
      assert.deepEqual(
        proof.proofs.map((row) => [row.id, row.rounds, row.code, row.frames]),
        [
          ["scalar-one", 2, 0, 1],
          ["scalar-many", 2, 3, 0],
        ],
      );
      assert.deepEqual(proof.proofs[0].documents, [
        { child: { stringValue: "child-a" }, key: { stringValue: "A" } },
      ]);
      assert.equal(proof.proofs[1].message, "Subpipeline returned multiple results.");
      continue;
    }
    if (entry.kind === "nesting-grpc-observation") {
      const proof = json(entry.path);
      assert.equal(entry.path, NESTING_OBSERVATION);
      assert.equal(proof.kind, "fs-ent-pipeline-nesting-later-observation-v1");
      assert.equal(proof.productionRequests, 0);
      assert.equal(
        closure.knownDifferences.notClaimed_nesting_limits.observationSha256,
        entry.sha256,
      );
      const fixture = json("conformance/fs-ent-pipeline-production.json").programs[
        "fs-ent-pipeline/o8a/nesting-main"
      ].steps;
      const rows = proof.productionObservation.rows;
      assert.deepEqual(new Set(rows.map((row) => row.row)), NESTING_ROWS);
      for (const row of rows) {
        assert.equal(status.get(row.row), "UNKNOWN", row.row);
        assert.match(row.requestSha256, /^[a-f0-9]{64}$/);
        assert.equal(row.rounds, 2);
        assert.equal(row.code, 3);
        assert.equal(row.frames, 0);
        // The recorded row of the same transport that production refused the same way.
        const same = fixture["chain-47-grpc"];
        assert.equal(row.code, same.code);
        assert.equal(row.message, same.message);
        // The unknown row itself keeps the recorder's own client failure.
        const step = fixture[row.row.split("#")[1]];
        assert.equal(typeof step.unknown, "string");
        assert.equal(step.code, 13);
      }
      assert.equal(
        proof.productionObservation.sameAnswerAsRecordedRow,
        "fs-ent-pipeline/o8a/nesting-main#chain-47-grpc",
      );
      assert.deepEqual(proof.localReplay.depths, [47, 48, 100]);
      assert.equal(proof.localReplay.strict.message, rows[0].message);
      const replay = proof.localReplay.test.split("#");
      assert.match(text(replay[0]), new RegExp(`fn ${replay[1]}\\(`));
      assert.deepEqual(badDigests(proof), []);
      continue;
    }
    const proof = json(entry.path);
    assert.equal(proof.decision, "ACCEPTED_FINITE_STRICT_CONTRACT");
    assert.equal(proof.profile, "strict");
    // The contracts were reviewed against the v0.35 comparison; their rows are checked there.
    assert.equal(proof.sourceCommit, closure.historicalIntegratedRegression.integrationCommit);
    assert.equal(proof.binarySha256, v035.artifactSha256);
    assert.deepEqual(proof.rawSummary, v035.summary);
    assert.equal(new Set(proof.proofs.map((row) => row.id)).size, proof.proofs.length);
    for (const row of proof.proofs) assert.equal(v035Status.get(row.id), row.rawStatus, row.id);
    if (entry.kind === "sample") {
      assert.equal(proof.proofs.length, 8);
      assert.equal(proof.proofs.filter((row) => row.rawStatus === "MISMATCH").length, 5);
      assert.equal(proof.proofs.filter((row) => row.rawStatus === "MATCH").length, 3);
      // In the current comparison the five random positives are finite-contract matches.
      for (const row of proof.proofs)
        assert.equal(
          status.get(row.id),
          row.rawStatus === "MISMATCH" ? "MATCH_NONDETERMINISTIC" : "MATCH",
          row.id,
        );
    } else {
      assert.equal(proof.proofs.length, 23);
      assert.equal(
        proof.proofs.filter(
          (row) => row.proofClassification === "FULL_TYPED_RESULT_MULTISET_EQUIVALENT",
        ).length,
        20,
      );
      assert.equal(
        proof.proofs.filter((row) => row.proofClassification === "LEGAL_UNORDERED_SELECTION")
          .length,
        3,
      );
      // The 23 groups-order rows keep their raw MISMATCH; the two argument errors now match.
      for (const row of proof.proofs) assert.equal(status.get(row.id), "MISMATCH", row.id);
      for (const row of proof.unresolved) assert.equal(status.get(row.id ?? row), "MATCH");
      assert.equal(proof.unresolved.length, 2);
      assert.equal(proof.ordinaryProfile, "unproved");
    }
  }
});
