import assert from "node:assert/strict";
import test from "node:test";
import { buildCorpus } from "./storage-object/corpus.mjs";
import { resolveDeclaredQuery } from "./storage-object/reference-resolution.mjs";

const bucket = "example.firebasestorage.app";
const corpus = () => buildCorpus({ bucket, prefix: "owned/reference-run/" });
const recipe = (suffix) =>
  corpus().recipes.find((entry) => entry.id === `storage-object/gcs/${suffix}`);
const recorded = (name, fields = {}) => ({
  status: 200,
  bodyBase64: Buffer.from(
    JSON.stringify({
      kind: "storage#object",
      bucket,
      name,
      generation: "9007199254740993",
      metageneration: "7",
      ...fields,
    }),
  ).toString("base64"),
});
const setup = (suffix, predicate) => {
  const declaration = recipe(suffix);
  const stepIndex = declaration.steps.findIndex(predicate);
  assert.ok(stepIndex >= 0);
  return { declaration, stepIndex, step: declaration.steps[stepIndex], responses: new Map() };
};
const resolve = ({ declaration, stepIndex, responses }) =>
  resolveDeclaredQuery({ recipe: declaration, stepIndex, responses, bucket });
const code = (expected) => (error) => error?.code === expected;

test("selected generation is copied from a prior raw GCS metadata response without Number conversion", () => {
  const input = setup("download", (step) => step.id === "selected-generation-metadata");
  input.responses.set("after-ranges-metadata", recorded(input.step.objectName));
  const previous = JSON.stringify(input.declaration);
  const raw = input.responses.get("after-ranges-metadata").bodyBase64;
  const query = resolve(input);
  assert.deepEqual(query, { generation: "9007199254740993" });
  query.generation = "1";
  assert.equal(JSON.stringify(input.declaration), previous);
  assert.equal(input.responses.get("after-ranges-metadata").bodyBase64, raw);
});

test("stale metageneration and current generation resolve from their own prior reads", () => {
  const input = setup(
    "metageneration-preconditions",
    (step) =>
      step.preconditionCase?.operation === "patch" &&
      step.preconditionCase.guard === "ifMetagenerationMatch" &&
      step.preconditionCase.sample === "stale",
  );
  input.responses.set(
    input.step.query.ifMetagenerationMatch.step,
    recorded(input.step.objectName, {
      metageneration: "2",
    }),
  );
  input.responses.set(
    input.step.query.ifGenerationMatch.step,
    recorded(input.step.objectName, {
      metageneration: "3",
    }),
  );
  assert.deepEqual(resolve(input), {
    ifGenerationMatch: "9007199254740993",
    ifMetagenerationMatch: "2",
  });
});

test("a declaration without references yields a separate plain query", () => {
  const input = setup("download", (step) => step.id === "upload");
  const query = resolve(input);
  assert.deepEqual(query, input.step.query);
  assert.notEqual(query, input.step.query);
});

test("missing, unsuccessful and malformed raw evidence cannot supply a generation", () => {
  const input = setup("download", (step) => step.id === "selected-generation-metadata");
  const source = "after-ranges-metadata";
  assert.throws(() => resolve(input), code("MISSING_EVIDENCE"));
  input.responses.set(source, { ...recorded(input.step.objectName), status: 404 });
  assert.throws(() => resolve(input), code("INVALID_EVIDENCE"));
  for (const bodyBase64 of ["{not-base64", Buffer.from("{broken").toString("base64"), ""]) {
    input.responses.set(source, { status: 200, bodyBase64 });
    assert.throws(() => resolve(input), code("INVALID_EVIDENCE"));
  }
  input.responses.set(source, {
    status: 200,
    bodyBase64: Buffer.alloc(1024 * 1024 + 1).toString("base64"),
  });
  assert.throws(() => resolve(input), code("INVALID_EVIDENCE"));
});

test("wrong bucket, object name or GCS resource kind is rejected before query construction", () => {
  const input = setup("download", (step) => step.id === "selected-generation-metadata");
  for (const fields of [
    { bucket: "other.firebasestorage.app" },
    { name: "owned/reference-run/another.bin" },
    { kind: "storage#objects" },
  ]) {
    input.responses.set("after-ranges-metadata", recorded(input.step.objectName, fields));
    assert.throws(() => resolve(input), code("EVIDENCE_IDENTITY_MISMATCH"));
  }
});

test("non-string, zero, noncanonical and malformed version fields fail closed", () => {
  const input = setup("download", (step) => step.id === "selected-generation-metadata");
  for (const generation of [
    Number("9007199254740993"),
    0,
    "0",
    "01",
    "-1",
    "1.5",
    "1e3",
    " 1",
    "1&x=y",
    null,
  ]) {
    input.responses.set("after-ranges-metadata", recorded(input.step.objectName, { generation }));
    assert.throws(() => resolve(input), code("INVALID_FIELD"));
  }
});

test("forward, cross-object and nonmetadata sources are not admissible references", () => {
  const input = setup(
    "generation-preconditions",
    (step) => step.preconditionCase?.sample === "stale",
  );
  const reference = input.step.query[input.step.preconditionCase.guard];
  input.responses.set(reference.step, recorded(input.step.objectName));
  const original = reference.step;
  reference.step = input.step.id;
  assert.throws(() => resolve(input), code("INVALID_REFERENCE"));
  reference.step = input.declaration.steps.find(
    (step) =>
      step.objectName !== input.step.objectName &&
      step.dialect === "gcs" &&
      step.method === "GET" &&
      step.query.alt === undefined,
  ).id;
  assert.throws(() => resolve(input), code("INVALID_REFERENCE"));
  reference.step = input.declaration.steps.find(
    (step) =>
      step.objectName === input.step.objectName &&
      step.dialect === "gcs" &&
      step.method === "GET" &&
      step.query.alt === "media",
  ).id;
  assert.throws(() => resolve(input), code("INVALID_REFERENCE"));
  reference.step = original;
  input.declaration.steps.find((step) => step.id === original).path = "/storage/v1/b/other/o/wrong";
  assert.throws(() => resolve(input), code("INVALID_REFERENCE"));
});

test("a later same-object metadata read cannot supply an earlier request", () => {
  const input = setup("download", (step) => step.id === "selected-generation-metadata");
  const future = input.declaration.steps.find(
    (step, index) =>
      index > input.stepIndex &&
      step.objectName === input.step.objectName &&
      step.dialect === "gcs" &&
      step.method === "GET" &&
      Object.keys(step.query).length === 0,
  );
  assert.ok(future);
  input.step.query.generation.step = future.id;
  input.responses.set(future.id, recorded(input.step.objectName));
  assert.throws(() => resolve(input), code("INVALID_REFERENCE"));
});

test("source object, dialect and method must each agree with the declared GCS metadata read", () => {
  const input = setup("download", (step) => step.id === "selected-generation-metadata");
  const source = input.declaration.steps.find((step) => step.id === "after-ranges-metadata");
  input.responses.set(source.id, recorded(input.step.objectName));
  for (const [field, altered] of [
    ["objectName", "owned/reference-run/another.bin"],
    ["dialect", "firebase"],
    ["method", "PATCH"],
  ]) {
    const original = source[field];
    source[field] = altered;
    assert.throws(() => resolve(input), code("INVALID_REFERENCE"));
    source[field] = original;
  }
});

test("target route and upload name cannot diverge from the object that supplied the generation", () => {
  const selected = setup("download", (step) => step.id === "selected-generation-metadata");
  selected.responses.set("after-ranges-metadata", recorded(selected.step.objectName));
  const selectedPath = selected.step.path;
  selected.step.path = `/storage/v1/b/${bucket}/o/${encodeURIComponent("owned/reference-run/other.bin")}`;
  assert.throws(() => resolve(selected), code("INVALID_REFERENCE"));
  selected.step.path = selectedPath;
  selected.step.dialect = "firebase";
  assert.throws(() => resolve(selected), code("INVALID_REFERENCE"));
  selected.step.dialect = "gcs";
  selected.step.method = "OPTIONS";
  assert.throws(() => resolve(selected), code("INVALID_REFERENCE"));

  const upload = setup(
    "generation-preconditions",
    (step) =>
      step.preconditionCase?.operation === "upload" &&
      step.preconditionCase.guard === "ifGenerationMatch" &&
      step.preconditionCase.sample === "current",
  );
  upload.responses.set(upload.step.query.ifGenerationMatch.step, recorded(upload.step.objectName));
  const originalPath = upload.step.path;
  upload.step.path = `/upload/storage/v1/b/other.firebasestorage.app/o`;
  assert.throws(() => resolve(upload), code("INVALID_REFERENCE"));
  upload.step.path = originalPath;
  upload.step.query.name = "owned/reference-run/other.bin";
  assert.throws(() => resolve(upload), code("INVALID_REFERENCE"));
});

test("a valid but oversized metadata response is rejected before parsing", () => {
  const input = setup("download", (step) => step.id === "selected-generation-metadata");
  input.responses.set(
    "after-ranges-metadata",
    recorded(input.step.objectName, {
      metadata: { filler: "x".repeat(1024 * 1024) },
    }),
  );
  assert.throws(() => resolve(input), code("INVALID_EVIDENCE"));
});

test("unknown query objects and altered reference descriptors cannot be serialized", () => {
  const input = setup("download", (step) => step.id === "selected-generation-metadata");
  input.responses.set("after-ranges-metadata", recorded(input.step.objectName));
  input.step.query.extra = { nested: "unexpected" };
  assert.throws(() => resolve(input), code("INVALID_REFERENCE"));
  delete input.step.query.extra;
  for (const change of [
    { kind: "other" },
    { field: "metageneration" },
    { format: "number" },
    { extra: true },
  ]) {
    const old = input.step.query.generation;
    input.step.query.generation = { ...old, ...change };
    assert.throws(() => resolve(input), code("INVALID_REFERENCE"));
    input.step.query.generation = old;
  }
});
