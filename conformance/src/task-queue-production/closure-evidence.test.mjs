import "./record/isolation.mjs";
import assert from "node:assert/strict";
import test from "node:test";

import {
  NOT_COMPARED,
  REGRESSION,
  conditionEvidence,
  countsOf,
  repositoryRegressionHolds,
  repositoryTestExists,
} from "./closure-evidence.mjs";

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

test("a fireemu-only condition is verified by the tests it names, all of which must exist", () => {
  const local = condition({
    conditionId: "TASK-QUEUE-FUNCTIONS/local-controls",
    evidenceType: "fireemu-only",
  });
  const tests = [
    { control: "a", file: "f.rs", test: "t1" },
    { control: "b", file: "g.rs", test: "t2" },
  ];
  const verified = conditionEvidence(local, ok(), evidence, {
    localTests: tests,
    testExists: () => true,
  });
  assert.equal(verified.status, "VERIFIED");
  assert.deepEqual(verified.localEvidence, tests);
  assert.deepEqual(verified.productionEvidence, []);
  assert.equal("observedPasses" in verified, false, "no production claim");
  const missing = conditionEvidence(local, ok(), evidence, {
    localTests: tests,
    testExists: (file) => file !== "g.rs",
  });
  assert.deepEqual([missing.status, "localEvidence" in missing], ["PLANNED", false]);
  assert.equal(
    conditionEvidence(local, ok(), evidence, { localTests: [], testExists: () => true }).status,
    "PLANNED",
  );
});

test("the release regression needs wiring and the review needs approval and evidence", () => {
  const gate = (name) =>
    condition({ conditionId: `TASK-QUEUE-FUNCTIONS/${name}`, evidenceType: "closure-gate" });
  const wired = conditionEvidence(gate("final-artifact-regression"), ok(), evidence, {
    regressionHolds: () => true,
  });
  assert.equal(wired.status, "VERIFIED");
  assert.equal(wired.regressionEvidence.run, "R38");
  assert.equal(
    conditionEvidence(gate("final-artifact-regression"), ok(), evidence, {
      regressionHolds: () => false,
    }).status,
    "PLANNED",
  );
  assert.equal(
    conditionEvidence(gate("closure-review"), ok(), evidence, { regressionHolds: () => true })
      .status,
    "PLANNED",
  );
  const review = { reviewedCommit: "commit", outcome: "APPROVED" };
  for (const closureReview of [
    { decision: "APPROVED", reviews: [] },
    { decision: "PENDING", reviews: [review] },
  ])
    assert.equal(
      conditionEvidence(gate("closure-review"), ok(), evidence, { closureReview }).status,
      "PLANNED",
    );
  const approved = conditionEvidence(gate("closure-review"), ok(), evidence, {
    closureReview: { decision: "APPROVED", reviews: [review] },
  });
  assert.equal(approved.status, "VERIFIED");
  assert.deepEqual(approved.reviewEvidence, [review]);
  assert.equal(repositoryRegressionHolds(REGRESSION), true, "the repository wires R38");
  for (const broken of [
    { ...REGRESSION, runner: "conformance/src/no-such-file.mjs" },
    { ...REGRESSION, run: "R99" },
    { ...REGRESSION, workflowStep: "a step that does not exist" },
    { ...REGRESSION, releaseDependencies: "npm ci --prefix nowhere" },
    { ...REGRESSION, tests: [...REGRESSION.tests, "conformance/src/missing.test.mjs"] },
  ])
    assert.equal(repositoryRegressionHolds(broken), false, JSON.stringify(broken).slice(0, 80));
  assert.equal(
    repositoryTestExists(
      "crates/fireemu-adapter-functions/tests/task_strict_admission.rs",
      "no_such_test",
    ),
    false,
  );
  assert.equal(repositoryTestExists("no/such/file.rs", "x"), false);
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

test("burst evidence verifies only a matching comparison rebuilt from the projections", async () => {
  const { burstEvidence, FILES } = await import("./closure-evidence.mjs");
  const { compareBurst } = await import("./burst-compare.mjs");
  const { readFileSync } = await import("node:fs");
  const production = JSON.parse(
    readFileSync(new URL("../../task-queue-production-burst-pass-1.json", import.meta.url)),
  );
  const local = { ...production, profile: "strict" };
  const files = {
    [FILES.burstProduction]: JSON.stringify(production),
    [FILES.burstLocal]: JSON.stringify(local),
    [FILES.burstComparison]: JSON.stringify(compareBurst(production, local)),
  };
  const read = (path) => {
    if (!(path in files)) throw new Error("missing");
    return files[path];
  };
  const target = condition({ conditionId: "TASK-QUEUE-FUNCTIONS/max-dispatches-per-second" });
  const derive = () =>
    conditionEvidence(target, ok(), evidence, { burst: () => burstEvidence(read) });
  assert.equal(derive().status, "NOT_COMPARED");
  assert.match(derive().reason, /^One pass: .*second recording is pending/);
  assert.deepEqual(
    derive().productionEvidence.map((item) => item.path),
    [FILES.burstProduction, FILES.burstComparison],
  );
  delete files[FILES.burstComparison];
  assert.equal(derive().status, "NOT_COMPARED");
  const mismatch = { ...local, offsetsMs: local.offsetsMs.slice(0, 119) };
  files[FILES.burstLocal] = JSON.stringify(mismatch);
  files[FILES.burstComparison] = JSON.stringify(compareBurst(production, mismatch));
  assert.equal(derive().status, "NOT_COMPARED");
  files[FILES.burstComparison] = JSON.stringify(compareBurst(production, local));
  assert.equal(derive().status, "NOT_COMPARED");
});
