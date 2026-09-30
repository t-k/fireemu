// The v0.8.0 integrated regression: one release binary built from the integration head reran every
// parent's local comparison against its saved production recordings. Each closure's
// `integratedRegression` must name that binary and receipt, bind each comparison file by digest,
// and state figures that are recomputed here from the committed files, not typed by hand.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { resolvedDivergenceRows } from "./closure-resolved-divergences.mjs";

const repo = (path) => fileURLToPath(new URL(`../../${path}`, import.meta.url));
const read = (path) => readFileSync(repo(path));
const readJson = (path) => JSON.parse(read(path).toString("utf8"));
const sha256 = (path) => createHash("sha256").update(read(path)).digest("hex");

const RECEIPT = "spec/compatibility/closure/evidence/integration-v0.8.0/release-artifact.json";
const PARENTS = [
  "FS-DATA-WRITE",
  "FS-QUERY-INDEX",
  "FS-CONFIG-LIFECYCLE",
  "FS-RULES",
  "AUTH-ACCOUNT",
  "AUTH-CREDENTIAL",
  "AUTH-ACTION",
  "AUTH-MFA",
  "AUTH-CONFIG-SDK",
  "FUNCTIONS-HTTP",
];
const REPROMOTED = ["AUTH-ACCOUNT", "AUTH-CREDENTIAL", "AUTH-ACTION"];
const closure = (parent) => readJson(`spec/compatibility/closure/${parent}.json`);
const rowsOf = (path) => new Map(readJson(path).rows.map(({ row, status }) => [row, status]));

test("the release receipt names one clean build of the integration head", () => {
  const receipt = readJson(RECEIPT);
  assert.equal(receipt.kind, "integration-release-artifact");
  assert.equal(receipt.release, "v0.8.0");
  assert.match(receipt.sourceCommit, /^[0-9a-f]{40}$/);
  assert.match(receipt.binarySha256, /^[0-9a-f]{64}$/);
  assert.deepEqual(receipt.command, [
    "cargo",
    "build",
    "--release",
    "--locked",
    "-p",
    "fireemu",
    "--message-format=json",
  ]);
  assert.equal(receipt.version, "fireemu 0.8.0");
  assert.equal(receipt.gitStatusAtBuild, "");
  assert.equal(receipt.productionRequests, 0);
});

test("every parent binds its integrated comparisons to the release binary", () => {
  const receipt = readJson(RECEIPT);
  for (const parent of PARENTS) {
    const block = closure(parent).integratedRegression;
    assert.ok(block, `${parent}: integratedRegression`);
    assert.equal(block.release, "v0.8.0", parent);
    assert.equal(block.integrationCommit, receipt.sourceCommit, parent);
    assert.equal(block.releaseBinarySha256, receipt.binarySha256, parent);
    assert.equal(block.buildReceiptPath, RECEIPT, parent);
    assert.equal(block.buildReceiptSha256, sha256(RECEIPT), parent);
    assert.equal(block.productionRequests, 0, parent);
    const resolved = resolvedDivergenceRows(closure(parent), read);
    const changed = block.comparisons.flatMap(({ changedRows }) => changedRows);
    assert.equal(
      block.result,
      changed.length === 0 ? "IDENTICAL_TO_LANE" : "IDENTICAL_EXCEPT_RESOLVED_DIVERGENCES",
      parent,
    );
    assert.ok(block.comparisons.length > 0, parent);
    for (const comparison of block.comparisons) {
      const label = `${parent}: ${comparison.path}`;
      assert.ok(
        comparison.path.startsWith("spec/compatibility/closure/evidence/integration-v0.8.0/"),
        label,
      );
      assert.equal(comparison.sha256, sha256(comparison.path), label);
      assert.equal(comparison.laneComparisonSha256, sha256(comparison.laneComparisonPath), label);
      // Only a divergence the closure records as resolved may change, and only to MATCH.
      for (const row of comparison.changedRows) {
        assert.equal(row.lane, "MISMATCH", `${label}: ${row.row}`);
        assert.equal(row.integrated, "MATCH", `${label}: ${row.row}`);
        assert.ok(resolved.has(row.row), `${label}: ${row.row} is a recorded resolved divergence`);
      }
      assert.equal(
        comparison.identicalRows + comparison.changedRows.length,
        comparison.rows,
        label,
      );
      const document = readJson(comparison.path);
      const binary = document.artifactSha256 ?? document.binarySha256;
      assert.equal(binary, receipt.binarySha256, `${label}: produced by the release binary`);
    }
  }
});

test("each row-level comparison is recomputed identical to the lane's committed comparison", () => {
  for (const parent of PARENTS) {
    for (const comparison of closure(parent).integratedRegression.comparisons) {
      const integrated = readJson(comparison.path);
      if (
        !Array.isArray(integrated.rows) ||
        integrated.kind === "fs-data-write-integrated-regression"
      ) {
        continue;
      }
      const label = `${parent}: ${comparison.path}`;
      const lane = rowsOf(comparison.laneComparisonPath);
      const now = rowsOf(comparison.path);
      assert.equal(now.size, comparison.rows, label);
      assert.deepEqual([...now.keys()].toSorted(), [...lane.keys()].toSorted(), label);
      const changed = new Map(comparison.changedRows.map((row) => [row.row, row]));
      for (const [row, status] of lane) {
        const expected = changed.has(row) ? changed.get(row).integrated : status;
        assert.equal(now.get(row), expected, `${label}: ${row}`);
      }
    }
  }
});

test("the FS-DATA-WRITE regression reproduces the release comparison and the historical rows", () => {
  const block = closure("FS-DATA-WRITE").integratedRegression;
  const regression = readJson(block.comparisons[0].path);
  const lane = readJson(
    "spec/compatibility/closure/evidence/FS-DATA-WRITE-current-comparison.json",
  );
  const historical = readJson(
    "spec/compatibility/closure/evidence/FS-DATA-WRITE-historical-regression.json",
  );
  assert.equal(regression.kind, "fs-data-write-integrated-regression");
  assert.equal(regression.current.corpusSha256, lane.corpusSha256);
  assert.equal(regression.current.comparedRestPrograms, lane.comparedRestPrograms);
  assert.equal(regression.current.comparedGrpcStreams, lane.comparedGrpcStreams);
  assert.deepEqual(regression.current.pendingRestIds, []);
  assert.deepEqual(regression.current.pendingStreamIds, []);
  assert.equal(regression.current.mismatches, 0);
  assert.deepEqual(regression.historical.rows, historical.rows.map(({ row }) => row).toSorted());
  assert.equal(regression.historical.newMismatches, 0);
  assert.equal(regression.historical.newIndeterminate, 0);
  assert.equal(
    regression.savedStreamTransaction.result.v2Classification,
    "EXPECTED_NONDETERMINISM",
  );
  assert.equal(regression.savedStreamTransaction.result.indeterminate, 0);
});

test("the re-promoted Auth parents are approved on their evidence and name the release binary", () => {
  const receipt = readJson(RECEIPT);
  for (const parent of REPROMOTED) {
    const current = closure(parent);
    assert.equal(current.parentStatus, "COMPAT_VERIFIED", parent);
    assert.equal(current.closureReview.decision, "APPROVED", parent);
    assert.equal(current.closureReview.decidedOn, "2026-09-28", parent);
    assert.equal(current.closureReview.integratedArtifactSha256, receipt.binarySha256, parent);
    assert.equal(current.closureReview.reviewedCommit, receipt.sourceCommit, parent);
    assert.equal(current.closureReview.previousDecision, "APPROVED", parent);
    assert.match(current.closureReview.previousFinalArtifactSha256, /^[0-9a-f]{64}$/, parent);
    assert.equal(current.closureReview.nextReviewRequired, undefined, parent);
    const review = current.conditions.find(
      ({ conditionId }) => conditionId === `${parent}/closure-review`,
    );
    const regression = current.conditions.find(
      ({ conditionId }) => conditionId === `${parent}/final-artifact-regression`,
    );
    assert.equal(review.status, "VERIFIED", parent);
    assert.equal(
      review.evidence.finalArtifactSha256,
      regression.evidence.finalArtifactSha256,
      parent,
    );
    assert.equal(
      current.closureReview.finalArtifactSha256,
      regression.evidence.finalArtifactSha256,
      parent,
    );
  }
});

test("published integration evidence carries no private or absolute path", () => {
  const paths = [
    RECEIPT,
    ...PARENTS.flatMap((parent) =>
      closure(parent).integratedRegression.comparisons.map(({ path }) => path),
    ),
  ];
  for (const path of new Set(paths)) {
    const text = read(path).toString("utf8");
    assert.doesNotMatch(text, /\/Users\/|docs\.local|\/private\/|\.worktree|scratchpad/, path);
  }
});

test("every inherited regression of a parent is rerun in its integrated regression", () => {
  const evidence = "spec/compatibility/closure/evidence/";
  const files = readdirSync(repo(evidence));
  for (const parent of PARENTS) {
    const covered = new Set(
      closure(parent).integratedRegression.comparisons.map(
        ({ laneComparisonPath }) => laneComparisonPath,
      ),
    );
    for (const name of files.filter(
      (file) => file.startsWith(`${parent}-`) && file.endsWith("-regression.json"),
    )) {
      if (name === `${parent}-historical-regression.json`) continue;
      if (!Array.isArray(readJson(`${evidence}${name}`).rows)) continue;
      assert.ok(covered.has(`${evidence}${name}`), `${parent}: ${name} is rerun`);
    }
  }
});

test("the A12 divergence is resolved wherever it was inherited, and documented nowhere", () => {
  const row = "auth-account/admin/custom-attributes#invalid-json";
  for (const parent of PARENTS) {
    const current = closure(parent);
    for (const condition of current.conditions) {
      for (const divergence of condition.evidence?.documentedDivergences ?? []) {
        assert.notEqual(divergence.row, row, `${condition.conditionId}: still documented`);
      }
    }
  }
  for (const parent of ["AUTH-ACTION", "AUTH-MFA", "AUTH-CONFIG-SDK"]) {
    assert.ok(resolvedDivergenceRows(closure(parent), read).has(row), parent);
  }
});

test("resolved divergences are accepted only when the integrated comparison shows MATCH", () => {
  const artifact = "a".repeat(64);
  const comparison = (status) =>
    Buffer.from(JSON.stringify({ artifactSha256: artifact, rows: [{ row: "p#r", status }] }));
  const closureWith = (bytes, extra = {}) => ({
    integratedRegression: { releaseBinarySha256: artifact },
    conditions: [
      {
        conditionId: "X/c",
        evidence: {
          resolvedDivergences: [
            {
              row: "p#r",
              decidedBy: "owner",
              scopeDecision: "X1",
              resolvedOn: "2026-09-28",
              resolvedArtifactSha256: artifact,
              resolvedEvidence: {
                path: "c.json",
                sha256: createHash("sha256").update(bytes).digest("hex"),
                status: "MATCH",
              },
              ...extra,
            },
          ],
        },
      },
    ],
  });
  const matching = comparison("MATCH");
  assert.deepEqual([...resolvedDivergenceRows(closureWith(matching), () => matching)], ["p#r"]);
  const still = comparison("MISMATCH");
  assert.throws(
    () => resolvedDivergenceRows(closureWith(still), () => still),
    /matches in the integrated comparison/,
  );
  assert.throws(
    () => resolvedDivergenceRows(closureWith(matching), () => comparison("MATCH ")),
    /resolved p#r/,
  );
  assert.throws(
    () =>
      resolvedDivergenceRows(
        closureWith(matching, { resolvedArtifactSha256: "b".repeat(64) }),
        () => matching,
      ),
    /integrated release binary/,
  );
  // A row that is not listed is never resolved.
  assert.equal(resolvedDivergenceRows(closureWith(matching), () => matching).has("p#other"), false);
});

test("the FUNCTIONS-HTTP rows come from recorded runs of the release binary", () => {
  const receipt = readJson(RECEIPT);
  const evidence = readJson(
    "spec/compatibility/closure/evidence/integration-v0.8.0/FUNCTIONS-HTTP-comparison.json",
  );
  assert.deepEqual(
    evidence.runs.map(({ profile }) => profile),
    ["strict", "emulator"],
  );
  for (const run of evidence.runs) {
    assert.equal(run.executedBinary, "target/release/fireemu", run.profile);
    assert.equal(run.binarySha256Before, receipt.binarySha256, run.profile);
    assert.equal(run.binarySha256After, receipt.binarySha256, run.profile);
    assert.equal(run.exitCode, 0, run.profile);
    // The checkout head at run time; the binary itself is identified by its digest.
    assert.match(run.sourceHead, /^[0-9a-f]{40}$/, run.profile);
    assert.match(run.recordingSha256, /^[0-9a-f]{64}$/, run.profile);
  }
  assert.equal(evidence.strictRecordingsIdenticalToLane, true);
  assert.equal(evidence.emulatorRecordingsIdenticalToLaneAfterCheckoutPathNormalization, true);
  assert.equal(evidence.rows.length, evidence.totalCases);
  assert.equal(
    evidence.rows.filter(({ status }) => status === "MATCH").length,
    evidence.strictProductionMatches,
  );
});
