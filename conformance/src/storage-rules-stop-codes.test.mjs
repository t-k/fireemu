import assert from "node:assert/strict";
import test from "node:test";
import { STOP_CODES, stopCodeOf, tagged } from "./storage-rules/stop-codes.mjs";

test("a tagged error carries its code and message, and only known codes can be tagged", () => {
  for (const code of Object.values(STOP_CODES)) {
    const error = tagged(code, "why");
    assert.equal(error instanceof Error, true);
    assert.equal(error.message, "why");
    assert.equal(stopCodeOf(error), code);
  }
  assert.throws(() => tagged("nope", "x"), /unknown stop code/);
  assert.throws(() => tagged(undefined, "x"), /unknown stop code/);
  assert.equal(Object.isFrozen(STOP_CODES), true);
  assert.deepEqual(Object.values(STOP_CODES).sort(), [
    "admission-refused",
    "capture-failed",
    "outcome-uncertain",
    "preflight-failed",
  ]);
});

test("an error is mapped by its code and never by its message", () => {
  for (const message of [
    "admission refused: x",
    "preflight failed: p",
    "request outcome uncertain",
    "capture journal uncertain",
    "dispatch gate is poisoned",
  ])
    assert.equal(stopCodeOf(new Error(message)), null, message);
  for (const value of [
    null,
    undefined,
    "admission-refused",
    5,
    {},
    { stopCode: "other" },
    { stopCode: 5 },
    Object.assign(new Error("x"), { stopCode: "unknown" }),
  ])
    assert.equal(stopCodeOf(value), null);
  assert.equal(stopCodeOf({ stopCode: "capture-failed" }), "capture-failed");
});
