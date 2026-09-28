import assert from "node:assert/strict";
import { test } from "node:test";
import { buildCorpus } from "./storage-object/corpus.mjs";
import { buildStage3DraftPlan } from "./storage-object/stage3-plan.mjs";

const input = {
  projectId: "example-project",
  bucket: "example.appspot.com",
  runIds: ["recordone", "recordtwo"],
};

test("two distinct recordings retain the frozen corpus and a single total request cap", () => {
  const plan = buildStage3DraftPlan(input);
  assert.equal(plan.status, "LOCAL_DRAFT_NO_SEND");
  assert.equal(plan.sendAuthorized, false);
  assert.equal(plan.recordings.length, 2);
  assert.equal(plan.maxRequests, 5600);
  assert.equal(plan.maxUsdReservation, 9);
  assert.equal(plan.recoveryReserveRequests, 600);
  assert.equal(
    plan.recordings.reduce((sum, record) => sum + record.maxRequests, 0),
    5000,
  );
  for (const [index, record] of plan.recordings.entries()) {
    assert.equal(record.runId, input.runIds[index]);
    assert.equal(record.prefix, `storage-object/${record.runId}/`);
    assert.equal(record.declaredRecipeCount, 26);
    assert.deepEqual(record.remainingRecipeIds, []);
    assert.equal(record.baseStaticEntries, 1891);
    assert.equal(record.authStaticEntries, 212);
    assert.equal(record.staticRequestEntries, 2103);
    assert.equal(record.staticCleanupEntries, 439);
    assert.equal(record.staticSubjectEntries, 1664);
    assert.equal(record.maxRequests, 2500);
    assert.equal(record.cleanupReserveRequests, 600);
    assert.equal(record.subjectCapRequests, 1900);
    assert.equal(record.supplementalSubjectMaxRequests, 128);
    assert.equal(record.subjectAllowance, 108);
    assert.equal(record.cleanupAllowance, 161);
    assert.match(record.corpusDigest, /^[a-f0-9]{64}$/);
    assert.match(record.authCorpusDigest, /^[a-f0-9]{64}$/);
    assert.match(record.authPlanDigest, /^[a-f0-9]{64}$/);
  }
  assert.notEqual(plan.recordings[0].corpusDigest, plan.recordings[1].corpusDigest);
});

test("invalid-name refusal budgets a complete run-prefix traversal for each attempted upload", () => {
  const corpus = buildCorpus({
    bucket: input.bucket,
    prefix: `storage-object/${input.runIds[0]}/`,
  });
  const recipe = corpus.recipes.find((item) => item.id === "storage-object/errors/object-name");
  assert.deepEqual(recipe.invalidNameAbsenceProof, {
    dialect: "gcs",
    scopePrefix: `storage-object/${input.runIds[0]}/`,
    delimiter: null,
    maxPagesPerRefusal: 32,
    maxRefusals: 4,
    maxRequests: 128,
    requiresExactKnownOwnedNames: true,
  });
  assert.deepEqual(recipe.observationAspects, [
    "invalid-name-create-refusal",
    "listed-name-or-url-encoded-form",
    "normalized-name-or-no-created-object",
    "malformed-prefix-list-status",
  ]);
});

test("the draft pins the deployed stage 2 Rules and leaves production admission false", () => {
  const plan = buildStage3DraftPlan(input);
  assert.equal(
    plan.rulesSourceSha256,
    "dff1d21237c12a1f3d1e5ef1134ba996d0b79c99530cb88bb016a5241388dc9b",
  );
  assert.equal(plan.rulesMutationAllowed, false);
  assert.equal(plan.budgetStatus, "PROPOSED_NOT_APPROVED");
  assert.equal(
    plan.recordings.every((record) => record.sendAuthorized === false),
    true,
  );
});

test("a reused or malformed run identifier cannot merge recording ownership", () => {
  for (const runIds of [
    ["recordone", "recordone"],
    ["../outside", "recordtwo"],
    ["recordone", ""],
  ]) {
    assert.throws(() => buildStage3DraftPlan({ ...input, runIds }));
  }
  assert.throws(() => buildStage3DraftPlan({ ...input, bucket: "wrong/bucket" }));
});
