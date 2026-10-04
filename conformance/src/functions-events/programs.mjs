import assert from "node:assert/strict";

const closureOnlyIds = [
  "FUNCTIONS-EVENTS/final-artifact-regression",
  "FUNCTIONS-EVENTS/closure-review",
];
const handlerNames = {
  "firestore/created": ["fsCreatedV1", "fsCreatedV2"],
  "firestore/updated": ["fsUpdatedV1", "fsUpdatedV2"],
  "firestore/deleted": ["fsDeletedV1", "fsDeletedV2"],
  "firestore/written": ["fsWrittenV1", "fsWrittenV2"],
  "firestore/written-with-auth-context": [null, "fsWrittenWithAuthContextV2"],
  "storage/finalized": ["storageFinalizedV1", "storageFinalizedV2"],
  "storage/deleted": ["storageDeletedV1", "storageDeletedV2"],
  "storage/metadata-updated": ["storageMetadataUpdatedV1", "storageMetadataUpdatedV2"],
  "storage/archived": ["storageArchivedV1", "storageArchivedV2"],
  "auth/created": ["authCreatedV1", null],
  "auth/deleted": ["authDeletedV1", null],
  "pubsub/published": ["pubsubPublishedV1", "pubsubPublishedV2"],
};
const budgetKeys = ["deploy", "sourceMutation", "captureRead", "cleanup"];
const unique = (values) => [...new Set(values)];
const sorted = (values) => values.toSorted();

/** Validate the local program inventory; this grants no production send permission. */
export function validatePrograms(value, corpus, closure) {
  assert.equal(value.schemaVersion, 1);
  assert.equal(value.parent, "FUNCTIONS-EVENTS");
  assert.equal(value.status, "LOCAL_DRAFT");
  assert.equal(value.sendAuthorized, false);
  assert.equal(value.productionEvidence, null);
  assert.equal(value.budgetStatus, "PROVISIONAL_NOT_SEND_READY");
  assert.equal(closure.parent, value.parent);
  assert.equal(closure.inventoryStatus, "FROZEN");
  assert.equal(corpus.parent, value.parent);
  const closureOnly = closure.conditions.filter((condition) =>
    condition.recipeIds.includes("functions-events/"),
  );
  assert.deepEqual(
    closureOnly.map((condition) => condition.conditionId),
    closureOnlyIds,
  );
  for (const condition of closureOnly) {
    assert.deepEqual(condition.recipeIds, ["functions-events/"]);
    assert.equal(condition.generations, undefined);
  }
  const behavioral = closure.conditions.filter(
    (condition) => !condition.recipeIds.includes("functions-events/"),
  );
  assert.equal(behavioral.length, 20);
  for (const condition of behavioral) {
    assert.equal(condition.recipeIds.length, 1);
    assert.ok(Array.isArray(condition.generations) && condition.generations.length > 0);
  }
  assert.ok(Array.isArray(value.programs) && value.programs.length === 20);
  assert.deepEqual(
    sorted(value.programs.map((program) => program.recipeId)),
    sorted(behavioral.map((condition) => condition.recipeIds[0])),
    "exactly one program per behavioral recipe",
  );

  const allCases = new Set();
  let budgetSum = value.productionRequestBudgetDraft.sharedSetup;
  assert.ok(Number.isSafeInteger(budgetSum) && budgetSum >= 0);
  for (const program of value.programs) {
    const rows = corpus.cases.filter((row) => row.recipeId === program.recipeId);
    const condition = behavioral.find(({ recipeIds }) => recipeIds[0] === program.recipeId);
    assert.ok(condition && rows.length > 0, program.recipeId);
    assert.deepEqual(
      program.caseIds,
      rows.map((row) => row.id),
    );
    assert.deepEqual(program.scenarioIds, unique(rows.map((row) => row.scenario)));
    assert.deepEqual(program.sourceOrder, program.scenarioIds);
    assert.deepEqual(program.generations, condition.generations);
    const eventKinds = unique(rows.map((row) => `${row.source}/${row.handlerEvent}`));
    assert.equal(eventKinds.length, 1, program.recipeId);
    const handlerNamesForEvent = handlerNames[eventKinds[0]];
    assert.ok(handlerNamesForEvent, program.recipeId);
    const expectedExports = Object.fromEntries(
      condition.generations.map((generation) => {
        const name = handlerNamesForEvent[generation - 1];
        assert.ok(name, program.recipeId);
        return [`v${generation}`, name];
      }),
    );
    if (program.recipeId === "functions-events/delivery/retry") {
      expectedExports.v2 = "fsRetryV2";
    }
    assert.deepEqual(program.handlerExports, expectedExports);
    for (const row of rows) {
      assert.ok(!allCases.has(row.id), `duplicate aspect: ${row.id}`);
      allCases.add(row.id);
      assert.equal(row.conditionId, condition.conditionId);
      assert.ok(program.generations.includes(row.generation));
      assert.ok(program.scenarioIds.includes(row.scenario));
    }
    assert.deepEqual(sorted(Object.keys(program.productionRequestBudgetDraft)), sorted(budgetKeys));
    for (const key of budgetKeys) {
      const count = program.productionRequestBudgetDraft[key];
      assert.ok(Number.isSafeInteger(count) && count >= 0 && count <= 10_000, key);
      budgetSum += count;
    }
  }
  assert.equal(allCases.size, 109);
  assert.deepEqual(allCases, new Set(corpus.cases.map((row) => row.id)));
  assert.equal(value.productionRequestBudgetDraft.total, budgetSum);
  return { programs: value.programs, aspectCount: allCases.size };
}
