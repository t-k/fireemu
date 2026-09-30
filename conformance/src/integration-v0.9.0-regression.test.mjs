// The v0.9.0 integrated regression of the parents the second integration promoted: each ran its
// final comparisons, and the regressions it inherits, on one release binary built from the
// integration branch. Each closure's `integratedRegression` must name that binary and its receipt,
// bind each comparison file by digest, and state figures recomputed here from the committed files.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const repo = (path) => fileURLToPath(new URL(`../../${path}`, import.meta.url));
const read = (path) => readFileSync(repo(path));
const readJson = (path) => JSON.parse(read(path).toString("utf8"));
const sha256 = (path) => createHash("sha256").update(read(path)).digest("hex");

const EVIDENCE = "spec/compatibility/closure/evidence/";
const RECEIPT = `${EVIDENCE}integration-v0.9.0/release-artifact.json`;
const PARENTS = ["AUTH-TENANT-BLOCKING", "AUTH-FS-CROSS", "AUTH-FEDERATION"];
// AUTH-FS-CROSS's rows need a local tenant setup its recorded harness does not do: its committed
// comparisons stay on the lane artifact, and the release binary reran them only as a supplementary
// regression with that setup added outside the harness (ledger line 473).
const SUPPLEMENTARY = new Set(["AUTH-FS-CROSS"]);
const closure = (parent) => readJson(`spec/compatibility/closure/${parent}.json`);
const artifactOf = (document) => document.artifactSha256 ?? document.fireemu?.artifactSha256;

const summaryOf = (rows) => {
  const counts = {};
  for (const { status } of rows) counts[status] = (counts[status] ?? 0) + 1;
  return counts;
};

test("the release receipt names one clean build of the integration branch", () => {
  const receipt = readJson(RECEIPT);
  assert.equal(receipt.kind, "integration-release-artifact");
  assert.equal(receipt.release, "v0.9.0");
  assert.match(receipt.sourceCommit, /^[0-9a-f]{40}$/);
  assert.match(receipt.binarySha256, /^[0-9a-f]{64}$/);
  assert.deepEqual(receipt.command, ["cargo", "build", "--release", "--locked", "-p", "fireemu"]);
  assert.equal(receipt.gitStatusAtBuild, "");
  assert.equal(receipt.productionRequests, 0);
  // The binary was built before the version commit: it reports the previous version, and the
  // release job rebuilds from the tag and reruns every comparison it can on that build.
  assert.equal(receipt.version, "fireemu 0.8.0");
  assert.match(receipt.buildInputsUnchangedThrough, /^[0-9a-f]{40}$/);
});

test("every promoted parent binds its comparisons to the release binary", () => {
  const receipt = readJson(RECEIPT);
  for (const parent of PARENTS) {
    const block = closure(parent).integratedRegression;
    assert.ok(block, `${parent}: integratedRegression`);
    assert.equal(block.release, "v0.9.0", parent);
    assert.equal(block.integrationCommit, receipt.sourceCommit, parent);
    assert.equal(block.releaseBinarySha256, receipt.binarySha256, parent);
    assert.equal(block.buildReceiptPath, RECEIPT, parent);
    assert.equal(block.buildReceiptSha256, sha256(RECEIPT), parent);
    assert.equal(block.productionRequests, 0, parent);
    const supplementary = SUPPLEMENTARY.has(parent);
    assert.equal(
      block.result,
      supplementary ? "SUPPLEMENTARY_ON_RELEASE_BINARY" : "IDENTICAL_TO_LANE",
      parent,
    );
    if (supplementary) {
      assert.match(block.laneArtifactSha256, /^[0-9a-f]{64}$/, parent);
      assert.notEqual(block.laneArtifactSha256, receipt.binarySha256, parent);
      assert.equal(block.supplementaryRegression.binarySha256, receipt.binarySha256, parent);
      assert.equal(block.supplementaryRegression.productionRequests, 0, parent);
    }
    assert.ok(block.comparisons.length > 0, parent);
    for (const comparison of block.comparisons) {
      const label = `${parent}: ${comparison.path}`;
      assert.ok(comparison.path.startsWith(EVIDENCE), label);
      assert.equal(comparison.sha256, sha256(comparison.path), label);
      // The lane's final comparison ran on the release binary itself: it is the integrated one.
      assert.equal(comparison.laneComparisonPath, comparison.path, label);
      assert.equal(comparison.laneComparisonSha256, comparison.sha256, label);
      assert.deepEqual(comparison.changedRows, [], label);
      const document = readJson(comparison.path);
      assert.equal(
        artifactOf(document),
        supplementary ? block.laneArtifactSha256 : receipt.binarySha256,
        `${label}: produced by the ${supplementary ? "lane" : "release"} binary`,
      );
      if (supplementary) {
        // The supplementary run gave the same figures as the committed comparison.
        assert.deepEqual(
          block.supplementaryRegression.summaries[comparison.path],
          summaryOf(document.rows),
          label,
        );
      }
      assert.equal(comparison.rows, document.rows.length, label);
      assert.equal(comparison.identicalRows, comparison.rows, label);
      assert.deepEqual(comparison.summary, summaryOf(document.rows), label);
    }
  }
});

test("every comparison and regression of a promoted parent is in its integrated regression", () => {
  const files = readdirSync(repo(EVIDENCE));
  for (const parent of PARENTS) {
    const covered = new Set(
      closure(parent).integratedRegression.comparisons.map(({ path }) => path),
    );
    for (const name of files.filter(
      (file) =>
        file.startsWith(`${parent}-`) &&
        (file.endsWith("-regression.json") || file.endsWith("-comparison.json")),
    )) {
      if (!Array.isArray(readJson(`${EVIDENCE}${name}`).rows)) continue;
      assert.ok(covered.has(`${EVIDENCE}${name}`), `${parent}: ${name} is listed`);
    }
  }
});

test("published integration evidence carries no private or absolute path", () => {
  const text = read(RECEIPT).toString("utf8");
  assert.doesNotMatch(text, /\/Users\/|docs\.local|\/private\/|\.worktree|scratchpad/);
});
