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
  "initial-unauthenticated-refusal",
  "default-subscription",
  "cross-principal-rules",
  "raw-resume-token",
  "browser-tab-lifecycle",
  "existence-filter-reconnect",
  "backend-cache-transitions",
  "native-target-protocol",
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
  const movedCases = closure.movedCatalogCases.map(({ caseId, movedTo }) => {
    assert.equal(movedTo, "AUTH-FS-CROSS");
    return caseId;
  });
  assert.deepEqual(new Set([...actualCases, ...movedCases]), new Set(catalog.cases.map(({ caseId }) => caseId)));
  assert.equal(actualCases.length, 15, "each retained catalog case belongs to one proposed condition");
  assert.deepEqual(new Set(movedCases), new Set(["FS-LISTEN-SDK-106", "FS-LISTEN-SDK-109", "FS-LISTEN-SDK-109C"]));
  const tab = closure.conditions.find(({ conditionId }) => conditionId === "FS-LISTEN-SDK/browser-tab-lifecycle");
  assert.deepEqual(tab.observation.transports, ["browser-webchannel-long-polling", "browser-webchannel-streaming"]);
  assert.equal(tab.verification.recordingsRequiredPerTransport, 2);
  for (const condition of closure.conditions) {
    assert.ok(condition.source && condition.observation.method);
    assert.ok(condition.verification.requiredEvidence.length);
    assert.equal(condition.verification.recordingsRequired, condition.status === "PENDING_REVIEW" ? 0 : 2);
    assert.notEqual(condition.status, "VERIFIED");
    assert.equal(condition.localEvidence.productionExecuted, false);
  }
  assert.equal(closure.productionPlan.authorizesProduction, false);
  assert.equal(closure.productionPlan.browserWireBaselineForTwoRecordings, 2776);
  assert.ok(closure.productionPlan.totalWireRequestCapRequired);
  assert.equal(closure.productionPlan.project, "fireemu-oracle-query");
  assert.equal(closure.productionPlan.database, "(default)");
  assert.equal(closure.productionPlan.changesRules, false);
  assert.equal(closure.profileComparison.profile, "strict");
  assert.ok(closure.scopeDecisions.every(({ status, decision, decidedBy, decidedOn }) => status === "DECIDED" && decision && decidedBy && decidedOn));
  assert.match(closure.conditions.find(({ conditionId }) => conditionId.endsWith("/query-change-order")).observation.method, /limitToLast/);
  assert.match(closure.conditions.find(({ conditionId }) => conditionId.endsWith("/default-subscription")).observation.method, /includeMetadataChanges/);
  assert.equal(closure.parentStatus === "COMPAT_VERIFIED", closure.conditions.every(({ status }) => status === "VERIFIED") && closure.closureReview.decision === "APPROVED");
});
