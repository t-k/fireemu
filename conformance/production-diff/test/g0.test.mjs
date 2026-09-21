import assert from "node:assert/strict";
import { test } from "node:test";
import { compareG0 } from "../g0.mjs";
import { G0_CASE } from "../registry.mjs";

test("G0 compare refuses a missing retained build binding", () => {
  assert.throws(
    () =>
      compareG0({
        repo: process.cwd(),
        entry: G0_CASE,
        actual: {},
        execution: { artifact: { sha256: "a".repeat(64) } },
        build: null,
      }),
    /g0-artifact-receipt-mismatch/,
  );
});

test("G0 compare refuses a snapshot whose bytes differ from the retained receipt", () => {
  assert.throws(
    () =>
      compareG0({
        repo: process.cwd(),
        entry: G0_CASE,
        actual: {},
        execution: { artifact: { sha256: "b".repeat(64) } },
        build: { artifactSha256: "a".repeat(64) },
      }),
    /g0-artifact-receipt-mismatch/,
  );
});
