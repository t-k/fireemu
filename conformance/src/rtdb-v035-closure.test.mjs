// Finite v0.35 recorded replay evidence; this test performs no network requests.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  compareObservation,
  loadFixture,
} from "../../tools/sdk-smoke-database/priority-replay.mjs";

const read = (path) => readFileSync(new URL(`../../${path}`, import.meta.url));
const json = (path) => JSON.parse(read(path));
const sha = (path) => createHash("sha256").update(read(path)).digest("hex");

test("v0.35 RTDB finite replays bind the reviewed source and both profiles", () => {
  const closure = json("spec/compatibility/closure/RTDB.json");
  assert.equal(closure.parentStatus, "IMPLEMENTING");
  const binding = closure.integratedRegression.v035RecordedRevalidation;
  assert.equal(binding.sourceCommit, "18f77be8956cccb768adfe8b43cfd0f9a8dfff09");
  assert.equal(
    binding.binarySha256,
    "39c5825519174115b9cff3da75c0473deea5ed5f8c85e79d5fdf8cba580eda83",
  );
  assert.equal(binding.productionRequests, 0);
  assert.equal(binding.comparisons.length, 6);
  assert.equal(new Set(binding.comparisons.map((entry) => entry.path)).size, 6);
  for (const entry of binding.comparisons) {
    assert.equal(sha(entry.path), entry.sha256);
    const evidence = json(entry.path);
    assert.equal(evidence.sourceCommit, binding.sourceCommit);
    assert.equal(evidence.binarySha256, binding.binarySha256);
    assert.equal(evidence.productionRequests, 0);
    if (entry.rows === 172) {
      assert.equal(evidence.summary.rows, 124);
      assert.equal(evidence.summary.m14Rows, 48);
      assert.deepEqual(evidence.summary.verdicts, { MATCH: 124 });
      assert.deepEqual(evidence.summary.m14Verdicts, { MATCH: 48 });
    } else if (entry.rowsPerProfile === 6) {
      assert.equal(sha(evidence.fixturePath), evidence.fixtureSha256);
      for (const profile of ["strict", "emulator"]) {
        const rows = evidence[profile].rows;
        assert.equal(rows.length, 6);
        assert.deepEqual(
          new Set(rows.map((row) => row.id)),
          new Set(["heal-reregister", "nested-priority", "string-priority"]),
        );
        assert.equal(new Set(rows.map((row) => `${row.id}/${row.round}`)).size, 6);
        assert.ok(rows.every((row) => row.verdict === "MATCH"));
      }
    } else {
      for (const profile of ["strict", "emulator"]) {
        assert.equal(evidence[profile].sourceHead, binding.sourceCommit);
        assert.equal(evidence[profile].binarySha256, binding.binarySha256);
        assert.equal(evidence[profile].summary.rows, entry.rowsPerProfile);
        assert.deepEqual(evidence[profile].summary.counts, { MATCH: entry.rowsPerProfile });
      }
    }
  }
});

test("priority evidence recomputes each recorded result from complete observations", () => {
  const evidence = json("spec/compatibility/closure/evidence/RTDB-priority-v035-comparison.json");
  const fixture = loadFixture(read(evidence.fixturePath).toString("utf8"));
  for (const profile of ["strict", "emulator"]) {
    for (const row of evidence[profile].rows) {
      const expected = fixture.cases.find((item) => item.id === row.id && item.round === row.round);
      assert.ok(expected, `${row.id}/${row.round}`);
      assert.equal(compareObservation(expected, row.actual).verdict, "MATCH");
      const changed = structuredClone(row.actual);
      changed.readback.s = { corrupt: true };
      assert.notEqual(compareObservation(expected, changed).verdict, "MATCH");
    }
  }
});
