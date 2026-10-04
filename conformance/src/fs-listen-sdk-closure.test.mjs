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
const statuses = new Set([
  "PENDING_CORPUS",
  "PENDING_RECORDING",
  "PENDING_REVIEW",
  "PRODUCTION_RECORDED",
  "MISMATCH",
  "VERIFIED",
]);
const requiredScopeDecisions = new Set([
  "L1",
  "L2",
  "L3",
  "L4",
  "L5",
  "L6",
  "L7",
  "L8",
  "OL-1",
  "OL-2",
  "OL-3",
  "Q1-Q4c",
]);

test("FS-LISTEN-SDK proposal covers its 18-case catalog and leaves unobserved paths open", () => {
  const closure = read("../../spec/compatibility/closure/FS-LISTEN-SDK.json");
  const catalog = read("../../spec/compatibility/fs-listen-sdk-cases.json");
  assert.equal(closure.parent, "FS-LISTEN-SDK");
  assert.equal(closure.inventoryStatus, "FROZEN");
  assert.equal(closure.freezeState, "FROZEN");
  assert.match(closure.frozenOn, /^\d{4}-\d{2}-\d{2}$/);
  assert.deepEqual(
    new Set(closure.conditions.map(({ conditionId }) => conditionId.split("/")[1])),
    required,
  );
  assert.equal(closure.conditions.length, required.size);
  const actualCases = closure.conditions
    .flatMap(({ recipeIds }) => recipeIds)
    .filter((id) => /^FS-LISTEN-SDK-\d/.test(id));
  const movedCases = closure.movedCatalogCases.map(({ caseId, movedTo }) => {
    assert.equal(movedTo, "AUTH-FS-CROSS");
    return caseId;
  });
  assert.deepEqual(
    new Set([...actualCases, ...movedCases]),
    new Set(catalog.cases.map(({ caseId }) => caseId)),
  );
  assert.equal(
    actualCases.length,
    15,
    "each retained catalog case belongs to one proposed condition",
  );
  assert.deepEqual(
    new Set(movedCases),
    new Set(["FS-LISTEN-SDK-106", "FS-LISTEN-SDK-109", "FS-LISTEN-SDK-109C"]),
  );
  const tab = closure.conditions.find(
    ({ conditionId }) => conditionId === "FS-LISTEN-SDK/browser-tab-lifecycle",
  );
  assert.deepEqual(tab.observation.transports, [
    "browser-webchannel-long-polling",
    "browser-webchannel-streaming",
  ]);
  assert.equal(tab.verification.recordingsRequiredPerTransport, 2);
  for (const condition of closure.conditions) {
    assert.ok(condition.source && condition.observation.method);
    assert.ok(condition.note?.trim(), `${condition.conditionId}: note`);
    assert.ok(condition.verification.requiredEvidence.length);
    assert.equal(
      condition.verification.recordingsRequired,
      condition.status === "PENDING_REVIEW" ? 0 : 2,
    );
    assert.ok(statuses.has(condition.status), `${condition.conditionId}: ${condition.status}`);
    if (condition.status === "VERIFIED")
      assert.ok(condition.evidence, `${condition.conditionId}: evidence`);
    assert.equal(condition.localEvidence.productionExecuted, false);
  }
  assert.equal(closure.productionPlan.authorizesProduction, false);
  assert.ok(closure.productionPlan.totalWireRequestCapRequired);
  assert.equal(closure.productionPlan.project, "fireemu-oracle-query");
  assert.equal(closure.productionPlan.database, "(default)");
  assert.equal(closure.productionPlan.changesRules, false);
  assert.equal(closure.profileComparison.profile, "strict");
  assert.equal(closure.oracle.project, "fireemu-oracle-query");
  assert.equal(closure.oracle.database, "(default)");
  assert.match(closure.oracle.credentials, /Email\/Password/);
  assert.deepEqual(new Set(closure.scopeDecisions.map(({ id }) => id)), requiredScopeDecisions);
  for (const decision of closure.scopeDecisions) {
    assert.equal(decision.status, "DECIDED");
    assert.ok(decision.decision?.trim());
    assert.match(decision.decidedBy, /^(owner|coordinator)/);
    assert.match(decision.decidedOn, /^\d{4}-\d{2}-\d{2}$/);
    if (decision.id.startsWith("OL-")) assert.match(decision.decidedBy, /^owner/);
  }
  assert.match(
    closure.conditions.find(({ conditionId }) => conditionId.endsWith("/query-change-order"))
      .observation.method,
    /limitToLast/,
  );
  assert.match(
    closure.conditions.find(({ conditionId }) => conditionId.endsWith("/query-change-order"))
      .observation.method,
    /one SDK callback/,
  );
  assert.match(
    closure.conditions.find(({ conditionId }) => conditionId.endsWith("/default-subscription"))
      .observation.method,
    /includeMetadataChanges/,
  );
  assert.equal(
    closure.parentStatus === "COMPAT_VERIFIED",
    closure.conditions.every(({ status }) => status === "VERIFIED") &&
      closure.closureReview.decision === "APPROVED",
  );
});

test("the ledger 824 amendment names the native project and the fixture rows it relies on", () => {
  const closure = read("../../spec/compatibility/closure/FS-LISTEN-SDK.json");
  const fixture = read("../auth-fs-cross-stage2-production.json");
  assert.equal(closure.amendedOn, "2026-10-05");
  assert.equal(closure.productionPlan.nativeProject, "fireemu-oracle-txn");
  assert.equal(closure.oracle.nativeProject, "fireemu-oracle-txn");
  // The SDK, browser and Auth-dependent recordings stay on the query project.
  assert.equal(closure.productionPlan.project, "fireemu-oracle-query");
  const withFixture = closure.conditions.filter(({ fixtureEvidence }) => fixtureEvidence);
  assert.deepEqual(withFixture.map(({ conditionId }) => conditionId.split("/")[1]).toSorted(), [
    "cross-principal-rules",
    "initial-unauthenticated-refusal",
    "raw-resume-token",
  ]);
  for (const { conditionId, fixtureEvidence } of withFixture) {
    assert.equal(fixtureEvidence.fixture, "conformance/auth-fs-cross-stage2-production.json");
    assert.equal(fixtureEvidence.decisionRef, "L8");
    assert.equal(fixtureEvidence.recordings, fixture.recordings.length);
    for (const row of fixtureEvidence.rows)
      assert.ok(Object.hasOwn(fixture.rows, row), `${conditionId}: row ${row} is in the fixture`);
  }
  const decision = (id) => closure.scopeDecisions.find((entry) => entry.id === id);
  assert.match(decision("L7").decidedBy, /^owner via ledger 824/);
  assert.match(decision("L8").decidedBy, /^owner via ledger 824/);
  assert.match(
    closure.conditions.find(({ conditionId }) => conditionId.endsWith("/raw-resume-token")).note,
    /native\/resume-token-expired/,
  );
});
