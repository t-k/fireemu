import assert from "node:assert/strict";
import { test } from "node:test";
import { buildCorpus } from "./storage-object/corpus.mjs";
import { resolveDeclaredQuery } from "./storage-object/reference-resolution.mjs";

const input = { bucket: "example.firebasestorage.app", prefix: "owned/run-012345/" };
const entry = () =>
  buildCorpus(input).recipes.find((recipe) => recipe.id === "storage-object/auth/admin");
const requests = (recipe) => [...recipe.preflight, ...recipe.steps, ...recipe.cleanup];

test("owner ADC recipe gives both dialects separate bounded object names and private bearer intent", () => {
  const recipe = entry();
  assert.deepEqual(recipe.objects, [
    `${input.prefix}auth/admin-firebase.bin`,
    `${input.prefix}auth/admin-gcs.bin`,
  ]);
  assert.deepEqual(recipe.credentialContract, {
    kind: "owner-adc",
    tokenType: "google-oauth2-access-token",
    wireScheme: "Bearer",
    secretHandling: "private-only",
  });
  assert.equal(recipe.preflight.length, 4);
  assert.equal(recipe.cleanup.length, 6);
  assert.ok(requests(recipe).every((step) => step.credential === "admin"));
  assert.ok(requests(recipe).every((step) => recipe.objects.includes(step.objectName)));
  assert.ok(
    requests(recipe).every(
      (step) => !Object.keys(step.headers).some((key) => key.toLowerCase() === "authorization"),
    ),
  );
});

test("each dialect creates, reads through both APIs, deletes and reads absence", () => {
  const recipe = entry();
  for (const [dialect, name, uploadId, deleteId] of [
    ["firebase", recipe.objects[0], "firebase-upload", "firebase-delete"],
    ["gcs", recipe.objects[1], "gcs-upload", "gcs-delete"],
  ]) {
    const steps = recipe.steps.filter((step) => step.objectName === name);
    assert.equal(steps.length, 10);
    assert.deepEqual(
      steps.map((step) => step.method),
      ["POST", "GET", "GET", "GET", "GET", "DELETE", "GET", "GET", "GET", "GET"],
    );
    assert.equal(steps[0].dialect, dialect);
    assert.equal(steps[0].id, uploadId);
    assert.equal(steps[0].query.name, name);
    assert.equal(steps[0].query.ifGenerationMatch, dialect === "gcs" ? "0" : undefined);
    assert.equal(steps[0].headers["content-type"], "application/octet-stream");
    assert.ok(Buffer.from(steps[0].body.base64, "base64").length > 0);
    assert.equal(steps[5].dialect, dialect);
    assert.equal(steps[5].id, deleteId);
    assert.deepEqual(
      steps.slice(1, 5).map((step) => [step.dialect, step.query.alt ?? null]),
      [
        ["gcs", null],
        ["gcs", "media"],
        ["firebase", null],
        ["firebase", "media"],
      ],
    );
    assert.deepEqual(
      steps.slice(6).map((step) => [step.dialect, step.query.alt ?? null]),
      [
        ["gcs", null],
        ["gcs", "media"],
        ["firebase", null],
        ["firebase", "media"],
      ],
    );
  }
  assert.notEqual(recipe.steps[0].body.base64, recipe.steps[10].body.base64);
});

test("GCS deletion matches the generation read after the owned upload", () => {
  const recipe = entry();
  const stepIndex = recipe.steps.findIndex((step) => step.id === "gcs-delete");
  const deletion = recipe.steps[stepIndex];
  assert.deepEqual(deletion.query, {
    ifGenerationMatch: {
      kind: "metadata-field",
      step: "gcs-after-upload-gcs-metadata",
      field: "generation",
      format: "positive-decimal-string",
    },
  });
  const response = {
    status: 200,
    bodyBase64: Buffer.from(
      JSON.stringify({
        kind: "storage#object",
        bucket: input.bucket,
        name: recipe.objects[1],
        generation: "9007199254740993",
      }),
    ).toString("base64"),
  };
  assert.deepEqual(
    resolveDeclaredQuery({
      recipe,
      stepIndex,
      responses: new Map([["gcs-after-upload-gcs-metadata", response]]),
      bucket: input.bucket,
    }),
    { ifGenerationMatch: "9007199254740993" },
  );
  assert.throws(
    () => resolveDeclaredQuery({ recipe, stepIndex, responses: new Map(), bucket: input.bucket }),
    { code: "MISSING_EVIDENCE" },
  );
  assert.deepEqual(recipe.steps.find((step) => step.id === "firebase-delete").query, {});
});
