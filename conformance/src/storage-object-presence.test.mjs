import assert from "node:assert/strict";
import test from "node:test";
import { buildCorpus } from "./storage-object/corpus.mjs";
import { evaluatePresentRequires } from "./storage-object/present-requires.mjs";

const bucket = "example.firebasestorage.app";
const makeCorpus = () => buildCorpus({ bucket, prefix: "owned/presence-run/" });
const errorCode = (expected) => (error) => error?.code === expected;
const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64");
const rawObject = (name, fields = {}) => ({
  status: 200,
  bodyBase64: encode({
    kind: "storage#object",
    bucket,
    name,
    generation: "9007199254740993",
    metageneration: "1",
    metadata: {},
    ...fields,
  }),
});
const findSubject = (suffix, predicate) => {
  const recipe = makeCorpus().recipes.find((row) => row.id === `storage-object/gcs/${suffix}`);
  assert.ok(recipe);
  const stepIndex = recipe.steps.findIndex(predicate);
  assert.ok(stepIndex >= 0);
  return { recipe, stepIndex, step: recipe.steps[stepIndex] };
};
const evaluate = ({ recipe, stepIndex, responses }) =>
  evaluatePresentRequires({ recipe, stepIndex, responses, bucket });

function fixture({ recipe, stepIndex, step }) {
  const required = step.requires;
  assert.equal(required.state, "present");
  const prior = [...recipe.preflight, ...recipe.steps.slice(0, stepIndex)];
  const source = (id) => {
    const row = prior.find((candidate) => candidate.id === id);
    assert.ok(row, id);
    return row;
  };
  const metadataIds = new Set(required.metadata);
  for (const relation of required.relations)
    for (const id of [relation.leftStep, relation.rightStep]) metadataIds.add(id);
  const fields = new Map(
    [...metadataIds].map((id) => [
      id,
      {
        generation: "9007199254740993",
        metageneration: "1",
        metadata: {},
      },
    ]),
  );
  for (const relation of required.relations) {
    if (relation.relation === "different")
      fields.get(relation.rightStep)[relation.field] =
        relation.field === "generation" ? "9007199254740994" : "2";
  }
  if (required.metadataSubset)
    for (const id of required.metadata)
      fields.get(id).metadata = { ...required.metadataSubset.metadata };
  const responses = new Map();
  for (const id of metadataIds) responses.set(id, rawObject(source(id).objectName, fields.get(id)));
  for (const id of required.media)
    responses.set(id, { status: 200, bodyBase64: required.bodyBase64 });
  return { recipe, stepIndex, step, responses, source };
}

test("all 63 declared present-state subjects match internally consistent raw records without authorizing a send", () => {
  let checked = 0;
  for (const recipe of makeCorpus().recipes)
    for (const [stepIndex, step] of recipe.steps.entries()) {
      if (step.requires?.state !== "present") continue;
      checked++;
      const input = fixture({ recipe, stepIndex, step });
      const original = JSON.stringify(recipe);
      const result = evaluate(input);
      assert.deepEqual(result, {
        status: "MATCHED_SUPPLIED_RECORDS",
        sendAuthorized: false,
        cleanupAuthorized: false,
      });
      assert.equal(JSON.stringify(recipe), original);
    }
  assert.equal(checked, 63);
});

test("all eight absent-state subjects remain unproven even when responses are supplied", () => {
  let checked = 0;
  for (const recipe of makeCorpus().recipes)
    for (const [stepIndex, step] of recipe.steps.entries()) {
      if (step.requires?.state !== "absent") continue;
      checked++;
      assert.throws(
        () => evaluate({ recipe, stepIndex, responses: new Map() }),
        errorCode("ABSENCE_UNPROVEN"),
      );
    }
  assert.equal(checked, 8);
});

test("missing and unsuccessful metadata or media reads cannot establish presence", () => {
  const input = fixture(
    findSubject("generation-preconditions", (s) => s.preconditionCase?.sample === "current"),
  );
  for (const id of [...input.step.requires.metadata, ...input.step.requires.media]) {
    const original = input.responses.get(id);
    input.responses.delete(id);
    assert.throws(() => evaluate(input), errorCode("MISSING_EVIDENCE"));
    input.responses.set(id, { ...original, status: 404 });
    assert.throws(() => evaluate(input), errorCode("INVALID_EVIDENCE"));
    input.responses.set(id, original);
  }
});

test("metadata identity and exact full-media bytes must agree through both dialects", () => {
  const input = fixture(
    findSubject("generation-preconditions", (s) => s.preconditionCase?.sample === "current"),
  );
  for (const id of input.step.requires.metadata) {
    const old = input.responses.get(id);
    input.responses.set(id, rawObject("owned/presence-run/other.bin"));
    assert.throws(() => evaluate(input), errorCode("EVIDENCE_IDENTITY_MISMATCH"));
    input.responses.set(
      id,
      rawObject(input.step.objectName, { bucket: "other.firebasestorage.app" }),
    );
    assert.throws(() => evaluate(input), errorCode("EVIDENCE_IDENTITY_MISMATCH"));
    input.responses.set(id, rawObject(input.step.objectName, { kind: "storage#objects" }));
    assert.throws(() => evaluate(input), errorCode("EVIDENCE_IDENTITY_MISMATCH"));
    input.responses.set(id, old);
  }
  for (const id of input.step.requires.media) {
    const old = input.responses.get(id);
    input.responses.set(id, { status: 200, bodyBase64: Buffer.from("wrong").toString("base64") });
    assert.throws(() => evaluate(input), errorCode("STATE_MISMATCH"));
    input.responses.set(id, old);
  }
});

test("stale metageneration metadata subset and equal/different relations are checked independently", () => {
  const input = fixture(
    findSubject(
      "metageneration-preconditions",
      (s) =>
        s.preconditionCase?.operation === "patch" &&
        s.preconditionCase.guard === "ifMetagenerationMatch" &&
        s.preconditionCase.sample === "stale",
    ),
  );
  for (const id of input.step.requires.metadata) {
    const old = input.responses.get(id);
    input.responses.set(id, rawObject(input.step.objectName, { metadata: {} }));
    assert.throws(() => evaluate(input), errorCode("STATE_MISMATCH"));
    input.responses.set(id, old);
  }
  const different = input.step.requires.relations.find((row) => row.relation === "different");
  const oldDifferent = input.responses.get(different.rightStep);
  input.responses.set(
    different.rightStep,
    rawObject(input.step.objectName, {
      metadata: { preconditionMarker: "advanced" },
      metageneration: "1",
    }),
  );
  assert.throws(() => evaluate(input), errorCode("RELATION_MISMATCH"));
  input.responses.set(different.rightStep, oldDifferent);
  const equal = input.step.requires.relations.find((row) => row.relation === "equal");
  const oldEqual = input.responses.get(equal.rightStep);
  input.responses.set(
    equal.rightStep,
    rawObject(input.step.objectName, {
      metadata: { preconditionMarker: "advanced" },
      generation: "9007199254740994",
      metageneration: "2",
    }),
  );
  assert.throws(() => evaluate(input), errorCode("RELATION_MISMATCH"));
  input.responses.set(equal.rightStep, oldEqual);
});

test("source declarations must be prior, unique, same-object, unselected full GET routes", () => {
  const input = fixture(
    findSubject("generation-preconditions", (s) => s.preconditionCase?.sample === "current"),
  );
  const id = input.step.requires.metadata[0];
  const source = input.source(id);
  for (const [field, wrong] of [
    ["objectName", "owned/presence-run/other.bin"],
    ["path", "/storage/v1/b/other/o/wrong"],
    ["method", "PATCH"],
    ["credential", "anonymous"],
  ]) {
    const old = source[field];
    source[field] = wrong;
    assert.throws(() => evaluate(input), errorCode("INVALID_DECLARATION"));
    source[field] = old;
  }
  source.query.generation = "1";
  assert.throws(() => evaluate(input), errorCode("INVALID_DECLARATION"));
  delete source.query.generation;
  const targetPath = input.step.path;
  input.step.path = "/storage/v1/b/other.firebasestorage.app/o/wrong";
  assert.throws(() => evaluate(input), errorCode("INVALID_DECLARATION"));
  input.step.path = targetPath;
  const media = input.source(input.step.requires.media[0]);
  media.headers.range = "bytes=0-1";
  assert.throws(() => evaluate(input), errorCode("INVALID_DECLARATION"));
  delete media.headers.range;
  media.headers.Range = "bytes=0-1";
  assert.throws(() => evaluate(input), errorCode("INVALID_DECLARATION"));
  delete media.headers.Range;
  media.query = { unexpected: "media" };
  assert.throws(() => evaluate(input), errorCode("INVALID_DECLARATION"));
  media.query = { alt: "media" };
  input.step.requires.metadata[0] = input.step.id;
  assert.throws(() => evaluate(input), errorCode("INVALID_DECLARATION"));
});

test("a later valid same-object read cannot be substituted for a prior prerequisite", () => {
  const input = fixture(
    findSubject("generation-preconditions", (s) => s.preconditionCase?.sample === "current"),
  );
  const oldId = input.step.requires.metadata[0];
  const prior = input.source(oldId);
  const future = input.recipe.steps.find(
    (row, index) =>
      index > input.stepIndex &&
      row.objectName === input.step.objectName &&
      row.dialect === prior.dialect &&
      row.method === "GET" &&
      Object.keys(row.query).length === 0,
  );
  assert.ok(future);
  input.step.requires.metadata[0] = future.id;
  input.responses.set(future.id, rawObject(input.step.objectName));
  assert.throws(() => evaluate(input), errorCode("INVALID_DECLARATION"));
});

test("noncanonical base64 cannot disguise matching media bytes", () => {
  const input = fixture(
    findSubject("generation-preconditions", (s) => s.preconditionCase?.sample === "current"),
  );
  const id = input.step.requires.media[0];
  const original = input.responses.get(id);
  input.responses.set(id, { ...original, bodyBase64: ` ${original.bodyBase64}` });
  assert.throws(() => evaluate(input), errorCode("INVALID_EVIDENCE"));
});

test("oversized declared expected bytes are rejected before base64 decoding", () => {
  const input = fixture(
    findSubject("generation-preconditions", (s) => s.preconditionCase?.sample === "current"),
  );
  input.step.requires.bodyBase64 = "A".repeat(4 * 400_000);
  const original = Buffer.from;
  let attemptedOversizedDecode = false;
  Buffer.from = function (value, ...args) {
    if (typeof value === "string" && value.length > 1_500_000) {
      attemptedOversizedDecode = true;
      throw new Error("oversized decode attempted");
    }
    return original.call(Buffer, value, ...args);
  };
  try {
    assert.throws(() => evaluate(input), errorCode("INVALID_DECLARATION"));
  } finally {
    Buffer.from = original;
  }
  assert.equal(attemptedOversizedDecode, false);
});

test("malformed, noncanonical and oversized bodies reject without echoing raw bytes", () => {
  const input = fixture(
    findSubject("generation-preconditions", (s) => s.preconditionCase?.sample === "current"),
  );
  const id = input.step.requires.metadata[0];
  for (const bodyBase64 of [
    "!secret!",
    encode({ secret: "hidden" }),
    rawObject(input.step.objectName, { metadata: { filler: "x".repeat(1024 * 1024) } }).bodyBase64,
  ]) {
    input.responses.set(id, { status: 200, bodyBase64 });
    assert.throws(
      () => evaluate(input),
      (error) => error?.code === "INVALID_EVIDENCE" && !error.message.includes("secret"),
    );
  }
});
