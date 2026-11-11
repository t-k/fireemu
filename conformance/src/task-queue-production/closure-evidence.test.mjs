import "./record/isolation.mjs";
import assert from "node:assert/strict";
import test from "node:test";

import { NOT_COMPARED, conditionEvidence, countsOf } from "./closure-evidence.mjs";

const row = (key, structure = "MATCH", timing = "WITHIN", parts = {}) => ({
  case: key,
  structure,
  timing: { verdict: timing },
  parts,
});
const doc = (...rows) => ({ document: { rows } });
const condition = (over = {}) => ({
  conditionId: "TASK-QUEUE-FUNCTIONS/x",
  evidenceType: "production-parity",
  status: "PLANNED",
  corpusSteps: ["a", "b"],
  productionEvidence: [],
  ...over,
});
const evidence = [{ alias: "pass-1" }];
const ok = () => ({
  runs: doc(row("a"), row("b")),
  strict1: doc(row("a"), row("b")),
  strict2: doc(row("a"), row("b")),
});

test("a condition whose cases all match in the three comparisons is verified with its counts and known differences", () => {
  const withKd = ok();
  withKd.strict1 = doc(
    row("a", "KNOWN_DIFFERENCE", "WITHIN", { admission: { knownDifferences: ["KD-B", "KD-A"] } }),
    row("b"),
  );
  withKd.strict2 = doc(
    row("a", "MATCH_LAYOUT"),
    row("b", "KNOWN_DIFFERENCE", "NOT_COMPARED", {
      deliveries: { knownDifferences: ["KD-A", "KD-C"] },
    }),
  );
  const result = conditionEvidence(condition(), withKd, evidence);
  assert.equal(result.status, "VERIFIED");
  assert.deepEqual(result.knownDifferences, ["KD-A", "KD-B", "KD-C"]);
  assert.deepEqual(result.comparisons.strictVsPass2.counts, {
    MATCH: 0,
    MATCH_LAYOUT: 1,
    KNOWN_DIFFERENCE: 1,
    MISMATCH: 0,
    UNKNOWN: 0,
  });
  assert.equal(result.comparisons.runVsRun.rows, 2);
  assert.deepEqual(result.productionEvidence, evidence);
  assert.equal(result.observedPasses, 2);
});

test("a mismatch, an unknown or an outside timing in any comparison keeps the condition from being verified", () => {
  for (const [which, bad] of [
    ["runs", row("a", "MISMATCH")],
    ["strict1", row("a", "UNKNOWN")],
    ["strict2", row("a", "MATCH", "OUTSIDE")],
    ["strict1", row("a", "MATCH", "OUTSIDE")],
    ["runs", row("a", "UNKNOWN")],
    ["strict2", row("a", "MISMATCH")],
  ]) {
    const docs = ok();
    docs[which] = doc(bad, row("b"));
    assert.equal(
      conditionEvidence(condition(), docs, evidence).status,
      "PLANNED",
      `${which} ${bad.structure} ${bad.timing.verdict}`,
    );
  }
});

test("a case the strict comparison lacks keeps the condition from being verified", () => {
  const docs = ok();
  docs.strict1 = doc(row("a"));
  assert.equal(conditionEvidence(condition(), docs, evidence).status, "PLANNED");
});

test("a row of a case the condition does not name does not count against it", () => {
  const docs = ok();
  docs.runs = doc(row("a"), row("b"), row("other", "MISMATCH"));
  assert.equal(conditionEvidence(condition(), docs, evidence).status, "VERIFIED");
});

test("a condition that is not production parity stays planned with no evidence", () => {
  const result = conditionEvidence(
    condition({ evidenceType: "fireemu-only", status: "VERIFIED", productionEvidence: [1] }),
    ok(),
    evidence,
  );
  assert.deepEqual([result.status, result.productionEvidence], ["PLANNED", []]);
});

test("a named condition is not compared, with its reason, whatever the rows say", () => {
  for (const [id, reason] of Object.entries(NOT_COMPARED)) {
    const result = conditionEvidence(condition({ conditionId: id }), ok(), evidence);
    assert.deepEqual([result.status, result.reason], ["NOT_COMPARED", reason]);
    assert.ok(reason.length > 80);
  }
});

test("a derived field of an earlier run does not survive in the condition", () => {
  const result = conditionEvidence(
    condition({ reason: "old", observedPasses: 9, knownDifferences: ["KD-OLD"] }),
    { ...ok(), strict1: doc(row("a"), row("b", "MISMATCH")) },
    evidence,
  );
  assert.equal(result.status, "PLANNED");
  for (const key of ["reason", "observedPasses", "knownDifferences", "comparisons", "profiles"])
    assert.equal(key in result, false, key);
});

test("the counts are per structure verdict", () => {
  assert.deepEqual(
    countsOf([row("a"), row("b", "MISMATCH"), row("c", "MISMATCH"), row("d", "UNKNOWN")]),
    { MATCH: 1, MATCH_LAYOUT: 0, KNOWN_DIFFERENCE: 0, MISMATCH: 2, UNKNOWN: 1 },
  );
});

test("a timing allowance used by a strict row is a known difference of the condition", () => {
  const docs = ok();
  docs.strict2 = doc(row("a"), {
    ...row("b", "MATCH", "KNOWN_DIFFERENCE"),
    timingKnownDifference: "KD-SKEW",
  });
  assert.deepEqual(conditionEvidence(condition(), docs, evidence).knownDifferences, ["KD-SKEW"]);
  docs.strict2 = doc(row("a"), row("b"));
  assert.deepEqual(conditionEvidence(condition(), docs, evidence).knownDifferences, []);
});
