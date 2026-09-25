import assert from "node:assert/strict";
import test from "node:test";
import { assessSanity } from "./mutation-sanity-result.mjs";

test("a dry run or empty mutant selection is not mutation evidence", () => {
  assert.equal(assessSanity([]).isErr(), true);
});

for (const status of [
  "Survived",
  "NoCoverage",
  "Timeout",
  "CompileError",
  "RuntimeError",
  "Pending",
  "Ignored",
]) {
  test(`rejects ${status} even when another mutant was killed`, () => {
    assert.equal(assessSanity([{ status: "Killed" }, { status }]).isErr(), true);
  });
}

test("accepts only a nonempty set of killed mutants", () => {
  const result = assessSanity([{ status: "Killed" }, { status: "Killed" }]);
  assert.equal(result.isOk(), true);
  assert.equal(result.value, 2);
});
