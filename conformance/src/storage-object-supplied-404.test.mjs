import assert from "node:assert/strict";
import test from "node:test";
import { buildCorpus } from "./storage-object/corpus.mjs";
import * as absence from "./storage-object/supplied-404.mjs";

const bucket = "example.firebasestorage.app";
const corpus = () => buildCorpus({ bucket, prefix: "owned/absence-run/" });
const rejectedAs = (code) => (error) => error?.code === code;
const notFound = () => ({
  status: 404,
  bodyBase64: Buffer.from('{"error":{"code":404}}').toString("base64"),
});

function fixture(recipe, stepIndex) {
  const step = recipe.steps[stepIndex];
  const responses = new Map(
    [...step.requires.metadata, ...step.requires.media].map((id) => [id, notFound()]),
  );
  return { recipe, stepIndex, responses, bucket };
}

test("all eight zero-absent subjects classify four supplied 404 reads without granting admission", () => {
  assert.equal(typeof absence.evaluateSupplied404Reads, "function");
  let count = 0;
  for (const recipe of corpus().recipes)
    for (const [stepIndex, step] of recipe.steps.entries()) {
      if (step.requires?.state !== "absent") continue;
      count++;
      const input = fixture(recipe, stepIndex);
      const before = JSON.stringify(recipe);
      assert.deepEqual(absence.evaluateSupplied404Reads(input), {
        status: "MATCHED_SUPPLIED_404_READS",
        sendAuthorized: false,
        cleanupAuthorized: false,
      });
      assert.equal(JSON.stringify(recipe), before);
    }
  assert.equal(count, 8);
});

test("missing, 200 and 403 reads never classify as supplied 404", () => {
  const recipe = corpus().recipes.find(
    (row) => row.id === "storage-object/gcs/generation-preconditions",
  );
  const stepIndex = recipe.steps.findIndex((row) => row.requires?.state === "absent");
  const input = fixture(recipe, stepIndex);
  for (const id of [
    ...recipe.steps[stepIndex].requires.metadata,
    ...recipe.steps[stepIndex].requires.media,
  ]) {
    const original = input.responses.get(id);
    input.responses.delete(id);
    assert.throws(() => absence.evaluateSupplied404Reads(input), rejectedAs("MISSING_EVIDENCE"));
    for (const status of [200, 403]) {
      input.responses.set(id, { ...original, status });
      assert.throws(() => absence.evaluateSupplied404Reads(input), rejectedAs("NOT_SUPPLIED_404"));
    }
    input.responses.set(id, original);
  }
});

test("source reads must be prior full metadata and media GETs for the same object", () => {
  const recipe = corpus().recipes.find(
    (row) => row.id === "storage-object/gcs/generation-preconditions",
  );
  const stepIndex = recipe.steps.findIndex((row) => row.requires?.state === "absent");
  const input = fixture(recipe, stepIndex);
  const target = recipe.steps[stepIndex];
  const prior = [...recipe.preflight, ...recipe.steps.slice(0, stepIndex)];
  const metadata = prior.find((row) => row.id === target.requires.metadata[0]);
  const media = prior.find((row) => row.id === target.requires.media[0]);
  const originalName = metadata.objectName;
  metadata.objectName = `${originalName}-other`;
  assert.throws(() => absence.evaluateSupplied404Reads(input), rejectedAs("INVALID_DECLARATION"));
  metadata.objectName = originalName;
  media.headers.Range = "bytes=0-1";
  assert.throws(() => absence.evaluateSupplied404Reads(input), rejectedAs("INVALID_DECLARATION"));
  delete media.headers.Range;
  target.requires.metadata[0] = target.id;
  assert.throws(() => absence.evaluateSupplied404Reads(input), rejectedAs("INVALID_DECLARATION"));
});

test("status 404 with malformed or oversized raw capture is rejected", () => {
  const recipe = corpus().recipes.find(
    (row) => row.id === "storage-object/gcs/generation-preconditions",
  );
  const stepIndex = recipe.steps.findIndex((row) => row.requires?.state === "absent");
  const input = fixture(recipe, stepIndex);
  const id = recipe.steps[stepIndex].requires.metadata[0];
  for (const bodyBase64 of ["!private!", " A==", "A".repeat(1_500_000)]) {
    input.responses.set(id, { status: 404, bodyBase64 });
    assert.throws(
      () => absence.evaluateSupplied404Reads(input),
      (error) => error?.code === "INVALID_EVIDENCE" && !error.message.includes("private"),
    );
  }
});

test("only declared zero-absent GCS subjects can be classified", () => {
  const recipe = corpus().recipes.find(
    (row) => row.id === "storage-object/gcs/generation-preconditions",
  );
  const stepIndex = recipe.steps.findIndex((row) => row.requires?.state === "absent");
  const input = fixture(recipe, stepIndex);
  const target = recipe.steps[stepIndex];
  const original = target.query.ifGenerationMatch;
  target.query.ifGenerationMatch = "1";
  assert.throws(() => absence.evaluateSupplied404Reads(input), rejectedAs("INVALID_DECLARATION"));
  target.query.ifGenerationMatch = original;
  target.requires.bodyBase64 = "";
  assert.throws(() => absence.evaluateSupplied404Reads(input), rejectedAs("INVALID_DECLARATION"));
});

test("declared operation and guard must describe the classified subject", () => {
  const recipe = corpus().recipes.find(
    (row) => row.id === "storage-object/gcs/generation-preconditions",
  );
  const stepIndex = recipe.steps.findIndex((row) => row.requires?.state === "absent");
  const input = fixture(recipe, stepIndex);
  const target = recipe.steps[stepIndex];
  target.preconditionCase.operation = "delete";
  assert.throws(() => absence.evaluateSupplied404Reads(input), rejectedAs("INVALID_DECLARATION"));
  target.preconditionCase.operation = "upload";
  target.preconditionCase.guard = "ifGenerationNotMatch";
  assert.throws(() => absence.evaluateSupplied404Reads(input), rejectedAs("INVALID_DECLARATION"));
  target.preconditionCase.guard = "ifGenerationMatch";
  recipe.id = "storage-object/errors/missing";
  assert.throws(() => absence.evaluateSupplied404Reads(input), rejectedAs("INVALID_DECLARATION"));
});

test("a renamed or duplicate subject cannot extend the frozen eight-subject set", () => {
  const recipe = corpus().recipes.find(
    (row) => row.id === "storage-object/gcs/generation-preconditions",
  );
  const stepIndex = recipe.steps.findIndex((row) => row.requires?.state === "absent");
  const input = fixture(recipe, stepIndex);
  const target = recipe.steps[stepIndex];
  const originalId = target.id;
  target.id = "unfrozen-ninth-subject";
  assert.throws(() => absence.evaluateSupplied404Reads(input), rejectedAs("INVALID_DECLARATION"));
  target.id = originalId;
  recipe.steps.push(structuredClone(target));
  assert.throws(() => absence.evaluateSupplied404Reads(input), rejectedAs("INVALID_DECLARATION"));
});
