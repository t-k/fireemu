import assert from "node:assert/strict";
import test from "node:test";
import { buildCorpus } from "./storage-object/corpus.mjs";

const input = { bucket: "example.firebasestorage.app", prefix: "owned/generation-run/" };
const get = (suffix) => {
  const recipe = buildCorpus(input).recipes.find(
    (row) => row.id === `storage-object/gcs/${suffix}`,
  );
  assert.ok(recipe, `missing ${suffix}`);
  return recipe;
};
const subjects = (recipe) => recipe.steps.filter((step) => step.preconditionCase);
const fieldRef = (step, field) => ({
  kind: "metadata-field",
  step,
  field,
  format: "positive-decimal-string",
});

test("generation cases partition guards, operations and current/stale/zero states with independent names", () => {
  const recipe = get("generation-preconditions");
  const expected = ["upload", "metadata-read", "media-read", "delete"].flatMap((operation) =>
    ["ifGenerationMatch", "ifGenerationNotMatch"].flatMap((guard) =>
      ["current", "stale", "zero-present", "zero-absent"].map(
        (sample) => `${operation}/${guard}/${sample}`,
      ),
    ),
  );
  assert.deepEqual(
    subjects(recipe).map(
      (s) =>
        `${s.preconditionCase.operation}/${s.preconditionCase.guard}/${s.preconditionCase.sample}`,
    ),
    expected,
  );
  assert.equal(recipe.objects.length, 32);
  assert.equal(new Set(subjects(recipe).map((s) => s.objectName)).size, 32);
});

test("metageneration cases cover PATCH, PUT and DELETE with both guards and malformed values", () => {
  const recipe = get("metageneration-preconditions");
  const expected = ["patch", "put", "delete"].flatMap((operation) =>
    ["ifMetagenerationMatch", "ifMetagenerationNotMatch"].flatMap((guard) =>
      [
        "current",
        "stale",
        "malformed-empty",
        "malformed-negative",
        "malformed-fraction",
        "malformed-text",
      ].map((sample) => `${operation}/${guard}/${sample}`),
    ),
  );
  assert.deepEqual(
    subjects(recipe).map(
      (s) =>
        `${s.preconditionCase.operation}/${s.preconditionCase.guard}/${s.preconditionCase.sample}`,
    ),
    expected,
  );
  assert.equal(recipe.objects.length, 36);
  const values = {
    "malformed-empty": "",
    "malformed-negative": "-1",
    "malformed-fraction": "1.5",
    "malformed-text": "not-a-number",
  };
  for (const subject of subjects(recipe)) {
    const { operation, guard, sample } = subject.preconditionCase;
    assert.equal(subject.method, { patch: "PATCH", put: "PUT", delete: "DELETE" }[operation]);
    assert.deepEqual(
      subject.query.ifGenerationMatch,
      fieldRef(subject.requires.metadata.at(-1), "generation"),
    );
    if (sample.startsWith("malformed-")) assert.equal(subject.query[guard], values[sample]);
    if (operation !== "delete") assert.ok(subject.body.json.metadata.preconditionMarker);
  }
});

test("all response references are typed prior same-object reads, never guessed values", () => {
  for (const recipe of buildCorpus(input).recipes) {
    const prior = new Map(recipe.preflight.map((step) => [step.id, step]));
    for (const step of recipe.steps) {
      for (const [key, ref] of Object.entries(step.query))
        if (ref && typeof ref === "object") {
          if (ref.kind === "firebase-download-token") {
            assert.ok(["token", "delete_token"].includes(key));
            assert.deepEqual(Object.keys(ref), [
              "kind",
              "fromStep",
              "priorStep",
              "field",
              "selection",
              "secretHandling",
            ]);
            assert.equal(ref.field, "downloadTokens");
            assert.equal(ref.selection, "exactly-one-new");
            assert.equal(ref.secretHandling, "private-only");
            const priorMetadata = prior.get(ref.priorStep);
            assert.ok(priorMetadata, `missing prior ${ref.priorStep}`);
            assert.equal(priorMetadata.objectName, step.objectName);
            assert.equal(priorMetadata.dialect, "firebase");
            assert.equal(priorMetadata.method, "GET");
            assert.equal(priorMetadata.query.alt, undefined);
            const source = prior.get(ref.fromStep);
            assert.ok(source, `missing prior ${ref.fromStep}`);
            assert.equal(source.objectName, step.objectName);
            assert.equal(source.dialect, "firebase");
            assert.equal(source.method, "POST");
            assert.equal(source.query.create_token, "true");
            continue;
          }
          assert.ok(
            [
              "generation",
              "ifGenerationMatch",
              "ifGenerationNotMatch",
              "ifMetagenerationMatch",
              "ifMetagenerationNotMatch",
              "ifSourceGenerationMatch",
              "ifSourceMetagenerationMatch",
            ].includes(key),
          );
          assert.deepEqual(Object.keys(ref), ["kind", "step", "field", "format"]);
          assert.equal(ref.kind, "metadata-field");
          assert.equal(ref.format, "positive-decimal-string");
          assert.equal(ref.field, key.includes("Metageneration") ? "metageneration" : "generation");
          const source = prior.get(ref.step);
          assert.ok(source, `missing prior ${ref.step}`);
          assert.equal(
            source.objectName,
            key.startsWith("ifSource") ? step.transfer.sourceName : step.objectName,
          );
          assert.equal(source.dialect, "gcs");
          assert.equal(source.method, "GET");
          assert.equal(source.query.alt, undefined);
        }
      prior.set(step.id, step);
    }
  }
});

test("stale guards require observed field changes and the correct current bytes", () => {
  for (const field of ["generation", "metageneration"]) {
    const recipe = get(`${field}-preconditions`);
    for (const subject of subjects(recipe).filter((s) => s.preconditionCase.sample === "stale")) {
      const steps = recipe.steps.filter((s) => s.objectName === subject.objectName);
      const before = steps.slice(0, steps.indexOf(subject));
      const uploads = before.filter((s) => s.method === "POST");
      assert.equal(uploads.length, field === "generation" ? 2 : 1);
      assert.equal(subject.requires.state, "present");
      const relation = subject.requires.relations.find((r) => r.field === field);
      assert.equal(relation.relation, "different");
      assert.deepEqual(
        subject.query[subject.preconditionCase.guard],
        fieldRef(relation.leftStep, field),
      );
      assert.equal(relation.rightStep, subject.requires.metadata.at(-1));
      assert.equal(subject.requires.bodyBase64, uploads.at(-1).body.base64);
      if (field === "metageneration") {
        assert.equal(before.filter((s) => s.method === "PATCH").length, 1);
        assert.ok(
          subject.requires.relations.some(
            (r) => r.field === "generation" && r.relation === "equal",
          ),
        );
        assert.deepEqual(subject.requires.metadataSubset, {
          metadata: { preconditionMarker: "advanced" },
        });
      } else assert.notEqual(uploads[0].body.base64, uploads[1].body.base64);
    }
  }
});

test("zero guards distinguish absent and present controls without implicit creation", () => {
  const recipe = get("generation-preconditions");
  for (const subject of subjects(recipe).filter((s) =>
    s.preconditionCase.sample.startsWith("zero-"),
  )) {
    const absent = subject.preconditionCase.sample === "zero-absent";
    assert.equal(subject.query[subject.preconditionCase.guard], "0");
    const same = recipe.steps.filter((s) => s.objectName === subject.objectName);
    const setup = same.slice(0, same.indexOf(subject));
    assert.equal(
      setup.some((s) => s.method === "POST"),
      !absent,
    );
    assert.equal(subject.requires.state, absent ? "absent" : "present");
    assert.equal(subject.requires.bodyBase64 === null, absent);
    assert.equal(subject.requires.metadata.length, 2);
    assert.equal(subject.requires.media.length, 2);
  }
});

test("every new guarded subject has immediate metadata and media post-state through both APIs", () => {
  for (const suffix of ["generation-preconditions", "metageneration-preconditions"]) {
    const recipe = get(suffix);
    for (const subject of subjects(recipe)) {
      const after = recipe.steps.slice(
        recipe.steps.indexOf(subject) + 1,
        recipe.steps.indexOf(subject) + 5,
      );
      assert.deepEqual(
        after.map((s) => [s.objectName, s.dialect, s.method, s.query.alt ?? null]),
        ["firebase", "gcs"].flatMap((api) => [
          [subject.objectName, api, "GET", null],
          [subject.objectName, api, "GET", "media"],
        ]),
      );
      assert.equal(subject.expectedStatus, undefined);
      assert.equal(subject.credential, "admin");
    }
  }
});

test("selected current-generation download covers metadata, full media and ranged media with readbacks", () => {
  const recipe = get("download");
  const selected = recipe.steps.filter((s) => s.query.generation);
  assert.equal(selected.length, 3);
  assert.deepEqual(
    selected.map((s) => [s.query.alt ?? null, s.headers.range ?? null]),
    [
      [null, null],
      ["media", null],
      ["media", "bytes=0-2"],
    ],
  );
  let previous = "after-ranges";
  for (const step of selected) {
    assert.deepEqual(step.query.generation, fieldRef("after-ranges-metadata", "generation"));
    assert.equal(step.requires.state, "present");
    assert.deepEqual(step.requires.metadata, [`${previous}-metadata`]);
    assert.deepEqual(step.requires.media, [`${previous}-media`]);
    assert.deepEqual(
      step.requires.relations,
      previous === "after-ranges"
        ? []
        : [
            {
              field: "generation",
              leftStep: "after-ranges-metadata",
              rightStep: `${previous}-metadata`,
              relation: "equal",
            },
          ],
    );
    previous = `${step.id}-after`;
    assert.equal(step.requires.bodyBase64, recipe.steps[0].body.base64);
    const after = recipe.steps.slice(
      recipe.steps.indexOf(step) + 1,
      recipe.steps.indexOf(step) + 3,
    );
    assert.deepEqual(
      after.map((s) => [s.method, s.query.alt ?? null, s.query.generation ?? null]),
      [
        ["GET", null, null],
        ["GET", "media", null],
      ],
    );
  }
});

test("state prerequisites and field relations refer only to established reads of the same owned object", () => {
  let checked = 0;
  for (const recipe of buildCorpus(input).recipes) {
    const prior = new Map(recipe.preflight.map((step) => [step.id, step]));
    for (const step of recipe.steps) {
      if (step.requires) {
        checked++;
        for (const [kind, ids] of Object.entries({
          metadata: step.requires.metadata,
          media: step.requires.media,
        })) {
          assert.ok(ids.length > 0);
          for (const id of ids) {
            const source = prior.get(id);
            assert.ok(source);
            assert.equal(source.objectName, step.objectName);
            assert.equal(source.method, "GET");
            assert.equal(source.query.alt ?? null, kind === "media" ? "media" : null);
          }
        }
        for (const relation of step.requires.relations) {
          assert.ok(["equal", "different"].includes(relation.relation));
          assert.ok(["generation", "metageneration"].includes(relation.field));
          for (const id of [relation.leftStep, relation.rightStep]) {
            const source = prior.get(id);
            assert.ok(source);
            assert.equal(source.objectName, step.objectName);
            assert.equal(source.method, "GET");
            assert.equal(source.dialect, "gcs");
            assert.equal(source.query.alt, undefined);
          }
        }
      }
      prior.set(step.id, step);
    }
  }
  assert.equal(checked, 71);
});
