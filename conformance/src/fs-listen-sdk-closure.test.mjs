import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const read = (path) => JSON.parse(readFileSync(new URL(path, import.meta.url), "utf8"));
const required = new Set([
  "document-event-order",
  "pending-writes",
  "query-change-order",
  "reconnect-resume",
  "unsubscribe",
  "auth-sign-out",
  "default-subscription",
  "cross-principal-rules",
  "token-revocation",
  "raw-resume-token",
  "browser-tab-lifecycle",
  "final-artifact-regression",
  "closure-review",
]);

test("FS-LISTEN-SDK proposal covers its 18-case catalog and leaves unobserved paths open", () => {
  const closure = read("../../spec/compatibility/closure/FS-LISTEN-SDK.json");
  const catalog = read("../../spec/compatibility/fs-listen-sdk-cases.json");
  assert.equal(closure.parent, "FS-LISTEN-SDK");
  assert.equal(closure.parentStatus, "IMPLEMENTING");
  assert.equal(closure.inventoryStatus, "PROPOSED");
  assert.equal(closure.freezeState, "UNFROZEN");
  assert.equal(closure.closureReview.decision, "PENDING");
  assert.deepEqual(new Set(closure.conditions.map(({ conditionId }) => conditionId.split("/")[1])), required);
  assert.equal(closure.conditions.length, required.size);
  const actualCases = closure.conditions.flatMap(({ recipeIds }) => recipeIds).filter((id) => /^FS-LISTEN-SDK-\d/.test(id));
  assert.deepEqual(new Set(actualCases), new Set(catalog.cases.map(({ caseId }) => caseId)));
  assert.equal(actualCases.length, 18, "each catalog case belongs to one proposed condition");
  const tab = closure.conditions.find(({ conditionId }) => conditionId === "FS-LISTEN-SDK/browser-tab-lifecycle");
  assert.deepEqual(tab.observation.transports, ["browser-webchannel-long-polling", "browser-webchannel-streaming"]);
  assert.equal(tab.verification.recordingsRequiredPerTransport, 2);
  for (const condition of closure.conditions) {
    assert.ok(condition.source && condition.observation.method);
    assert.ok(condition.verification.requiredEvidence.length);
    assert.notEqual(condition.status, "VERIFIED");
    assert.equal(condition.localEvidence.productionExecuted, false);
  }
  assert.equal(closure.productionPlan.authorizesProduction, false);
  assert.equal(closure.productionPlan.browserWireBaselineForTwoRecordings, 2776);
  assert.ok(closure.productionPlan.totalWireRequestCapRequired);
  assert.ok(closure.scopeDecisions.every(({ status }) => status === "PROPOSED"));
});
