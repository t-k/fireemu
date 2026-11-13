import "./record/isolation.mjs";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";
import { compareBurst } from "./burst-compare.mjs";

const production = JSON.parse(
  readFileSync(new URL("../../task-queue-production-burst-pass-1.json", import.meta.url)),
);
const row = (comparison, name) => comparison.rows.find((entry) => entry.name === name).verdict;

test("the production burst matches itself", () => {
  assert.equal(compareBurst(production, production).verdict, "MATCH");
});

test("a single immediate start does not match the burst", () => {
  const result = compareBurst(production, {
    offsetsMs: Array.from({ length: 120 }, (_, i) => i * 1000),
  });
  assert.equal(result.verdict, "MISMATCH");
  assert.equal(row(result, "burst"), "MISMATCH");
});

test("a two second cadence does not match", () => {
  const result = compareBurst(production, {
    offsetsMs: production.offsetsMs.map((n, i) =>
      i < 10 ? n : production.offsetsMs[10] + (i - 10) * 2000,
    ),
  });
  assert.equal(row(result, "cadence"), "MISMATCH");
  assert.equal(result.verdict, "MISMATCH");
});

test("a missing start fails the count", () => {
  const result = compareBurst(production, { offsetsMs: production.offsetsMs.slice(0, 119) });
  assert.equal(row(result, "count"), "MISMATCH");
  assert.equal(result.verdict, "MISMATCH");
});

test("the committed burst comparison rebuilds from the committed projections when present", () => {
  const comparisonPath = new URL(
    "../../task-queue-production-burst-strict-vs-pass-1.json",
    import.meta.url,
  );
  if (!existsSync(comparisonPath)) return;
  const local = JSON.parse(
    readFileSync(new URL("../../task-queue-production-burst-local-strict.json", import.meta.url)),
  );
  assert.deepEqual(JSON.parse(readFileSync(comparisonPath)), compareBurst(production, local));
});
