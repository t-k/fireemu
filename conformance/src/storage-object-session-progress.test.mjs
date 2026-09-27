import assert from "node:assert/strict";
import test from "node:test";
import { buildCorpus } from "./storage-object/corpus.mjs";
import * as progress from "./storage-object/session-progress.mjs";

const bucket = "example.firebasestorage.app";
const errorCode = (expected) => (error) => error?.code === expected;

function fixture() {
  const recipe = buildCorpus({ bucket, prefix: "owned/progress-run/" }).recipes.find(
    (row) => row.id === "storage-object/gcs/resumable-upload",
  );
  const response = { status: 308, headers: { Range: "bytes=0-262143" }, bodyBase64: "" };
  return { recipe, response, bucket };
}

test("exact supplied status Range only classifies; it grants no continuation or cleanup", () => {
  assert.equal(typeof progress.evaluateSuppliedExactStatusRange, "function");
  const result = progress.evaluateSuppliedExactStatusRange(fixture());
  assert.deepEqual(result, {
    status: "MATCHED_SUPPLIED_EXACT_STATUS_RANGE",
    persistedRange: "bytes=0-262143",
    sendAuthorized: false,
    cleanupAuthorized: false,
  });
  assert.ok(Object.isFrozen(result));
  assert.ok(!JSON.stringify(result).includes("upload_id"));
});

test("status must be 308 and the captured body empty", () => {
  for (const status of [200, 201, 503, null]) {
    const input = fixture();
    input.response.status = status;
    assert.throws(
      () => progress.evaluateSuppliedExactStatusRange(input),
      errorCode("INVALID_EVIDENCE"),
    );
  }
  for (const bodyBase64 of ["QQ==", null, "A".repeat(1_500_000)]) {
    const input = fixture();
    input.response.bodyBase64 = bodyBase64;
    assert.throws(
      () => progress.evaluateSuppliedExactStatusRange(input),
      errorCode("INVALID_EVIDENCE"),
    );
  }
});

test("missing, duplicate and nonstring Range headers are rejected", () => {
  for (const headers of [
    {},
    { Range: "bytes=0-262143", range: "bytes=0-262143" },
    { Range: ["bytes=0-262143"] },
    { Range: null },
  ]) {
    const input = fixture();
    input.response.headers = headers;
    assert.throws(
      () => progress.evaluateSuppliedExactStatusRange(input),
      errorCode("INVALID_RANGE"),
    );
  }
  const hiddenDuplicate = fixture();
  Object.defineProperty(hiddenDuplicate.response.headers, "range", {
    value: "bytes=0-0",
    enumerable: false,
  });
  assert.throws(
    () => progress.evaluateSuppliedExactStatusRange(hiddenDuplicate),
    errorCode("INVALID_RANGE"),
  );
  const input = fixture();
  Object.defineProperty(input.response.headers, "range", {
    enumerable: true,
    get() {
      throw new Error("secret");
    },
  });
  assert.throws(
    () => progress.evaluateSuppliedExactStatusRange(input),
    (error) => error?.code === "INVALID_RANGE" && !error.message.includes("secret"),
  );
});

test("partial, oversized and noncanonical progress cannot classify as exact", () => {
  for (const range of [
    "bytes=0-0",
    "bytes=0-262142",
    "bytes=0-262144",
    "bytes=1-262143",
    "bytes=0-262143,0-0",
    "bytes =0-262143",
    "bytes=0-0262143",
    "bytes=0-262143\nX-Bad: 1",
  ]) {
    const input = fixture();
    input.response.headers.Range = range;
    assert.throws(
      () => progress.evaluateSuppliedExactStatusRange(input),
      errorCode("INVALID_RANGE"),
    );
  }
});

test("all recipe fields including status continuation must be canonical", () => {
  for (const change of [
    (recipe) => {
      recipe.steps[0].body.json.name = "foreign/object.bin";
    },
    (recipe) => {
      recipe.steps[2].headers["content-range"] = "bytes */0";
    },
    (recipe) => {
      recipe.steps[3].continuation.range = "bytes=0-0";
    },
    (recipe) => {
      recipe.steps.push({ id: "unexpected", method: "DELETE" });
    },
    (recipe) => {
      recipe.steps[4] = null;
    },
  ]) {
    const input = fixture();
    change(input.recipe);
    assert.throws(
      () => progress.evaluateSuppliedExactStatusRange(input),
      errorCode("INVALID_DECLARATION"),
    );
  }
  const input = fixture();
  input.bucket = "other.firebasestorage.app";
  assert.throws(
    () => progress.evaluateSuppliedExactStatusRange(input),
    errorCode("INVALID_DECLARATION"),
  );
});
