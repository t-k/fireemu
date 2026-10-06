import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { pendingClosure } from "./functions-events/compare/fixtures/pending-closure.mjs";

const record = JSON.parse(
  readFileSync(
    fileURLToPath(
      new URL("../../spec/compatibility/closure/FUNCTIONS-EVENTS.json", import.meta.url),
    ),
    "utf8",
  ),
);

const promoted = () => {
  const closure = structuredClone(record);
  closure.parentStatus = "COMPAT_VERIFIED";
  closure.integratedRegression = { release: "v0.0.0" };
  closure.closureReview = { decision: "APPROVED", reviewer: "x" };
  for (const condition of closure.conditions) {
    condition.status = "VERIFIED";
    condition.evidence = { rows: { MATCH: 1 } };
  }
  for (const decision of closure.scopeDecisions)
    if (decision.review !== undefined) decision.review = "APPROVED (report x)";
  return closure;
};

test("the pending form of a promoted record is the record as it was before the promotion", () => {
  const pending = pendingClosure(promoted());
  assert.equal(pending.parentStatus, "IMPLEMENTING");
  assert.equal(pending.integratedRegression, undefined);
  assert.deepEqual(pending.closureReview, { decision: "PENDING" });
  for (const condition of pending.conditions) {
    assert.equal(condition.evidence, undefined, condition.conditionId);
    assert.equal(
      condition.status,
      condition.conditionId.endsWith("/closure-review") ? "PENDING_REVIEW" : "PENDING_CORPUS",
      condition.conditionId,
    );
  }
  for (const decision of pending.scopeDecisions)
    if (decision.review !== undefined)
      assert.equal(decision.review, "PENDING (the closure review)", decision.id);
  // What the promotion does not write is kept: the notes, the masks, the cases.
  const withNote = pending.conditions.filter((c) => c.note !== undefined).length;
  assert.equal(withNote, record.conditions.filter((c) => c.note !== undefined).length);
  assert.deepEqual(
    pending.scopeDecisions.map(({ id, masks }) => [id, masks]),
    record.scopeDecisions.map(({ id, masks }) => [id, masks]),
  );
});

test("the pending form is the same whether the record is pending or promoted, and it does not change its input", () => {
  const once = pendingClosure(record);
  assert.deepEqual(pendingClosure(promoted()), once);
  assert.deepEqual(pendingClosure(once), once);
  const input = promoted();
  const copy = structuredClone(input);
  pendingClosure(input);
  assert.deepEqual(input, copy);
});
