// The FUNCTIONS-EVENTS closure record as it stood before its promotion: the tests of the closure inventory and of the generator
// (closure-evidence.mjs) judge a record that is still pending, and the committed record stops being pending when the closure is
// promoted. This undoes exactly what the promotion writes, so the tests give the same answers before and after it:
//   - parentStatus (COMPAT_VERIFIED) goes back to IMPLEMENTING, and the integratedRegression block goes;
//   - every condition goes back to PENDING_CORPUS (the closure-review one to PENDING_REVIEW) and loses its evidence;
//   - the closureReview block goes back to a pending decision, and the review of each accepted difference to its pending text.
// What the promotion does not write (the notes, the masks, the cases, the scope decisions' wording) is kept.

const PENDING_REVIEW_TEXT = "PENDING (the closure review)";

/** A pending copy of a closure record; the input is not changed. */
export function pendingClosure(record) {
  const closure = structuredClone(record);
  closure.parentStatus = "IMPLEMENTING";
  delete closure.integratedRegression;
  closure.closureReview = { decision: "PENDING" };
  for (const condition of closure.conditions) {
    condition.status = condition.conditionId.endsWith("/closure-review")
      ? "PENDING_REVIEW"
      : "PENDING_CORPUS";
    delete condition.evidence;
  }
  for (const decision of closure.scopeDecisions)
    if (decision.review !== undefined) decision.review = PENDING_REVIEW_TEXT;
  return closure;
}
