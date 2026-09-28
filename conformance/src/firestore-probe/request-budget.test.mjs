import assert from "node:assert/strict";
import { test } from "node:test";

import { createRequestBudget } from "./request-budget.mjs";

test("the production session bounds observation and cleanup requests together", () => {
  const budget = createRequestBudget(2);
  assert.equal(budget.claim(), 1);
  assert.equal(budget.claim(), 2);
  assert.throws(() => budget.claim(), /request cap/);
  assert.equal(budget.count(), 2);
});

test("a malformed request cap cannot silently become unlimited", () => {
  for (const limit of [0, -1, 1.5, NaN, Infinity, 10_001]) {
    assert.throws(() => createRequestBudget(limit), /request cap/);
  }
});
