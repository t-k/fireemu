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
const comparison = json("spec/compatibility/closure/evidence/FS-PIPELINE-comparison.json");
const status = new Map(comparison.rows.map((row) => [row.row, row.status]));

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
    assert.deepEqual(mine.toSorted(), matching.toSorted(), condition.conditionId);
    assert.deepEqual(condition.evidence.rows, {
      MATCH: matching.length,
      NOT_CLAIMED: family.length - matching.length,
    });
    assert.equal(condition.evidence.comparisonSha256, sha256(condition.evidence.comparisonPath));
    assert.equal(condition.evidence.fixtureSha256, sha256(condition.evidence.fixturePath));
    assert.equal(condition.evidence.releaseBinarySha256, comparison.artifactSha256);
  }
  // Every row is claimed, belongs to a not-claimed family, or has no per-row fixture.
  const unclaimed = [...status].filter(([row]) => !claimed.has(row));
  const notRun = ["o8b/", "o8c/", "o8d/"];
  const nonClaimed = unclaimed.filter(
    ([row, s]) => s !== "MISSING_FIXTURE" && !notRun.some((p) => row.includes(`/${p}`)),
  );
  const mismatching = nonClaimed.filter(([, s]) => s !== "MISMATCH" && s !== "UNKNOWN");
  assert.deepEqual(
    mismatching,
    [],
    "an unclaimed row that is neither MISMATCH, UNKNOWN nor a MATCH in a condition",
  );
  assert.equal(
    [...status.values()].filter((s) => s === "MATCH").length,
    claimed.size + [...status].filter(([row, s]) => s === "MATCH" && !claimed.has(row)).length,
  );
  // No MATCH row is left unclaimed, except the controls of the families recorded but not claimed.
  const leftover = [...status].filter(([row, s]) => s === "MATCH" && !claimed.has(row));
  assert.deepEqual(leftover, []);
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

test("the release job reruns the comparison: one run of this kind, check exits 1", () => {
  const runs = RUNS.filter((run) => run.kind === comparison.kind);
  assert.equal(runs.length, 1);
  const [run] = runs;
  assert.deepEqual(run.clear, ["fs-ent-pipeline"]);
  assert.deepEqual(run.commands[0].expectedExitCodes, [1]);
  assert.equal(run.commands[0].env.FIREEMU_SANDBOX_LANE, "fs-ent-pipeline");
  // As a verified parent the plan accepts it and names this run.
  const verified = { ...closure, parentStatus: "COMPAT_VERIFIED" };
  const plan = planComparisons([{ closure: verified, path: CLOSURE }], (path) =>
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
