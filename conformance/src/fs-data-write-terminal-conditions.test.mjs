import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const rootFile = (path) => new URL(`../../${path}`, import.meta.url);
const read = (path) => JSON.parse(readFileSync(rootFile(path), "utf8"));
const sha = (value) => createHash("sha256").update(value).digest("hex");
const fileSha = (path) => sha(readFileSync(rootFile(path)));
const projectionPath =
  "spec/compatibility/closure/evidence/FS-DATA-WRITE-terminal-local-digests.json";
const sourceFixtures = new Map([
  [
    "FS-DATA-WRITE/near-limit-delete-refusal",
    "conformance/fs-data-write-production-supplements/delta-v3-a14f265fea575003423c7ebd.json",
  ],
  [
    "FS-LIMIT-API-REQUEST-BYTES/non-commit-rest",
    "conformance/fs-data-write-production-supplements/partial-7bfd51026a2ac56617d81504.json",
  ],
  [
    "FS-LIMIT-API-REQUEST-BYTES/webchannel",
    "conformance/fs-data-write-production-supplements/partial-7bfd51026a2ac56617d81504.json",
  ],
]);

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .toSorted()
        .map((key) => [key, canonical(value[key])]),
    );
  }
  return value;
}

function stepDigest(step) {
  const decision =
    step?.code === "OK"
      ? { status: step.status, code: step.code, body: step.body }
      : { status: step?.status, code: step?.code, message: step?.message };
  return sha(JSON.stringify(canonical(decision)));
}

function checkCondition(condition, projection) {
  const fixturePath = sourceFixtures.get(condition.conditionId);
  assert.ok(fixturePath, condition.conditionId);
  const fixture = read(fixturePath);
  assert.equal(
    condition.status,
    condition.conditionId === "FS-DATA-WRITE/near-limit-delete-refusal"
      ? "VERIFIED"
      : "PRODUCTION_RECORDED",
    condition.conditionId,
  );
  assert.equal(condition.evidence.comparisonPath, projectionPath);
  assert.equal(condition.evidence.comparisonSha256, fileSha(projectionPath));
  assert.equal(condition.evidence.sourceHead, projection.sourceHead);
  assert.equal(condition.evidence.finalArtifactSha256, projection.binarySha256);
  assert.equal(condition.evidence.fixturePath, fixturePath);
  assert.equal(condition.evidence.fixtureSha256, fileSha(fixturePath));
  assert.deepEqual(condition.evidence.productionRecordings, fixture.evidence.recordingDigests);
  assert.equal(condition.evidence.productionRecordings.length, 2);
  const expectedIds = Object.keys(fixture.programs).filter((id) =>
    condition.recipeIds.some((recipe) => id === recipe || id.startsWith(`${recipe}/`)),
  );
  assert.ok(
    condition.recipeIds.every((recipe) =>
      expectedIds.some((id) => id === recipe || id.startsWith(`${recipe}/`)),
    ),
  );
  const actual = new Set(Object.keys(projection.conditions[condition.conditionId].programs));
  assert.deepEqual(actual, new Set(expectedIds), condition.conditionId);
  for (const id of expectedIds) {
    const saved = fixture.programs[id];
    const local = projection.conditions[condition.conditionId].programs[id];
    assert.ok(saved && local, id);
    const alternatives = saved.alternatives ?? [saved];
    const choices = alternatives.map((alternative) =>
      Object.fromEntries(
        Object.entries(alternative.steps).map(([step, value]) => [step, stepDigest(value)]),
      ),
    );
    assert.ok(
      choices.some(
        (choice) =>
          Object.keys(choice).length === Object.keys(local.steps).length &&
          Object.entries(choice).every(([step, digest]) => local.steps[step] === digest),
      ),
      `${id}: local rows must match one whole production recording`,
    );
  }
}

test("owner A nondeterministic delete band uses both complete recordings without hybrid rows", () => {
  const closure = read("spec/compatibility/closure/FS-DATA-WRITE.json");
  const condition = closure.conditions.find(
    ({ conditionId }) => conditionId === "FS-DATA-WRITE/near-limit-delete-refusal",
  );
  assert.equal(condition.boundaryStatus, "NONDETERMINISTIC_BAND");
  assert.equal(condition.terminalOwnerDecision, "2026-09-25 FS-DATA-WRITE A");
  assert.deepEqual(condition.deterministicRefusalCounts, {
    rest: 12113,
    commit: 12112,
    "batch-write": 12113,
  });
  assert.deepEqual(condition.nondeterministicRows, [
    "writes/limits/near-limit-delete-refusal/rest/12112",
    "writes/limits/near-limit-delete-refusal/batch-write/12112",
  ]);
  assert.match(condition.boundaryNote, /not a deterministic accepted boundary/);
  const fixture = read(sourceFixtures.get(condition.conditionId));
  assert.deepEqual(
    new Set(fixture.evidence.nondeterministicPrograms),
    new Set(condition.nondeterministicRows),
  );
  for (const id of condition.nondeterministicRows) {
    assert.equal(fixture.programs[id].alternatives.length, 2, id);
    assert.deepEqual(
      new Set(fixture.programs[id].alternatives.map(({ steps }) => stepDigest(steps.delete))).size,
      2,
      id,
    );
  }
  for (const [route, count] of Object.entries(condition.deterministicRefusalCounts)) {
    const id = `writes/limits/near-limit-delete-refusal/${route}/${count}`;
    const saved = fixture.programs[id];
    assert.ok(saved && !saved.alternatives, id);
    assert.equal(saved.steps.delete.status, route === "batch-write" ? 200 : 400, id);
    if (route === "batch-write") {
      assert.equal(saved.steps.delete.body.status[0].code, 3);
      assert.equal(saved.deleteProof.deleteOutcomeProven, false);
    } else {
      assert.equal(saved.steps.delete.message, "Transaction too big. Decrease transaction size.");
      assert.equal(saved.deleteProof.deleteOutcomeProven, true);
    }
    assert.ok(saved.steps["after-delete"].body[0].found, id);
  }
  const projection = read(projectionPath);
  checkCondition(condition, projection);
});

test("owner D4 inferred upper bounds retain unobserved production limits", () => {
  const closure = read("spec/compatibility/closure/FS-DATA-WRITE.json");
  const projection = read(projectionPath);
  for (const id of [
    "FS-LIMIT-API-REQUEST-BYTES/non-commit-rest",
    "FS-LIMIT-API-REQUEST-BYTES/webchannel",
  ]) {
    const condition = closure.conditions.find(({ conditionId }) => conditionId === id);
    assert.equal(condition.status, "PRODUCTION_RECORDED", id);
    assert.equal(condition.boundaryStatus, "INFERRED_UPPER_BOUND", id);
    assert.equal(condition.estimateOwnerDecision, "2026-09-25 FS-DATA-WRITE D4");
    assert.equal(condition.strictLimitEstimateBytes, 11 * 1024 * 1024);
    assert.match(condition.scopeNote, /unobserved estimate/);
    assert.match(condition.scopeNote, /production upper boundary remains unresolved/);
    const fixture = read(sourceFixtures.get(id));
    const selected = Object.keys(fixture.programs).filter((recipe) =>
      condition.recipeIds.some((prefix) => recipe.startsWith(`${prefix}/`)),
    );
    assert.equal(selected.length, id.endsWith("non-commit-rest") ? 10 : 2);
    assert.ok(
      selected.every((recipe) => recipe.endsWith("/10485760") || recipe.endsWith("/10485761")),
    );
    checkCondition(condition, projection);
  }
  const grpc = closure.conditions.find(
    ({ conditionId }) => conditionId === "FS-LIMIT-API-REQUEST-BYTES/grpc",
  );
  assert.equal(grpc.status, "MISMATCH");
  assert.equal(grpc.boundaryStatus, "UNBRACKETED");
});

test("terminal projection binds the same release source and raw local result", () => {
  const projection = read(projectionPath);
  const bundle = read("spec/compatibility/closure/evidence/FS-DATA-WRITE-release-artifact.json");
  const candidate = read(
    "spec/compatibility/closure/evidence/FS-DATA-WRITE-current-comparison.json",
  );
  assert.equal(projection.sourceHead, bundle.sourceCommit);
  assert.equal(projection.binarySha256, bundle.binarySha256);
  assert.equal(projection.sourceResultSha256, candidate.localResultDigests.restSha256);
  assert.deepEqual(new Set(Object.keys(projection.conditions)), new Set(sourceFixtures.keys()));
});

test("a hybrid near-limit DELETE observation is rejected", () => {
  const closure = read("spec/compatibility/closure/FS-DATA-WRITE.json");
  const condition = closure.conditions.find(
    ({ conditionId }) => conditionId === "FS-DATA-WRITE/near-limit-delete-refusal",
  );
  const projection = structuredClone(read(projectionPath));
  const id = "writes/limits/near-limit-delete-refusal/rest/12112";
  const fixture = read(sourceFixtures.get(condition.conditionId));
  const refused = fixture.programs[id].alternatives.find(
    ({ steps }) => steps.delete.status === 400,
  );
  projection.conditions[condition.conditionId].programs[id].steps.delete = stepDigest(
    refused.steps.delete,
  );
  assert.throws(() => checkCondition(condition, projection), /whole production recording/);
});
