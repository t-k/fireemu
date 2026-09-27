import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { buildCorpus } from "./storage-object/corpus.mjs";
import * as session from "./storage-object/session-location.mjs";

const bucket = "example.firebasestorage.app";
const errorCode = (expected) => (error) => error?.code === expected;

function fixture() {
  const recipe = buildCorpus({ bucket, prefix: "owned/session-run/" }).recipes.find(
    (row) => row.id === "storage-object/gcs/resumable-upload",
  );
  const name = recipe.objects[0];
  const location = `https://storage.googleapis.com/upload/storage/v1/b/${bucket}/o?uploadType=resumable&name=${encodeURIComponent(name)}&upload_id=Abc_123-def`;
  return { recipe, response: { status: 200, headers: { location }, bodyBase64: "" }, bucket };
}

test("valid supplied Location yields only a private digest and no send admission", () => {
  assert.equal(typeof session.evaluateSuppliedSessionLocation, "function");
  const input = fixture();
  const result = session.evaluateSuppliedSessionLocation(input);
  assert.deepEqual(result, {
    status: "MATCHED_SUPPLIED_PRIVATE_SESSION_LOCATION",
    sessionUriSha256: createHash("sha256").update(input.response.headers.location).digest("hex"),
    sendAuthorized: false,
    cleanupAuthorized: false,
  });
  assert.ok(Object.isFrozen(result));
  assert.ok(!JSON.stringify(result).includes("Abc_123-def"));
  assert.ok(!JSON.stringify(result).includes("upload_id"));
});

test("missing, unsuccessful and duplicate Location headers are rejected without echoing secrets", () => {
  const input = fixture();
  const original = input.response.headers.location;
  for (const response of [
    { ...input.response, status: 403 },
    { ...input.response, headers: {} },
    { ...input.response, headers: { location: original, Location: original } },
    { ...input.response, headers: { location: `${original}\nX-Bad: value` } },
  ]) {
    assert.throws(
      () => session.evaluateSuppliedSessionLocation({ ...input, response }),
      (error) => error?.code === "INVALID_EVIDENCE" && !error.message.includes("Abc_123-def"),
    );
  }
});

test("Location must use the exact HTTPS GCS origin, upload path and owned object", () => {
  const input = fixture();
  const original = input.response.headers.location;
  const wrong = [
    original.replace("https://", "http://"),
    original.replace("storage.googleapis.com", "storage.googleapis.com.evil.example"),
    original.replace("storage.googleapis.com", "user@storage.googleapis.com"),
    original.replace("storage.googleapis.com", "storage.googleapis.com:8443"),
    original.replace(`/b/${bucket}/`, "/b/other.firebasestorage.app/"),
    original.replace("/upload/storage/v1/", "/storage/v1/"),
    original.replace(encodeURIComponent(input.recipe.objects[0]), "owned%2Fother.bin"),
    `${original}#fragment`,
  ];
  for (const location of wrong) {
    input.response.headers.location = location;
    assert.throws(
      () => session.evaluateSuppliedSessionLocation(input),
      errorCode("INVALID_LOCATION"),
    );
  }
});

test("Location query requires one bounded opaque upload ID and no additional parameters", () => {
  const input = fixture();
  const original = input.response.headers.location;
  for (const location of [
    original.replace("upload_id=Abc_123-def", "upload_id="),
    `${original}&upload_id=second`,
    `${original}&redirect=https://evil.example`,
    original.replace("uploadType=resumable", "uploadType=media"),
    original.replace("upload_id=Abc_123-def", `upload_id=${"A".repeat(4097)}`),
    original.replace("upload_id=Abc_123-def", "upload_id=bad%2Fslash"),
  ]) {
    input.response.headers.location = location;
    assert.throws(
      () => session.evaluateSuppliedSessionLocation(input),
      errorCode("INVALID_LOCATION"),
    );
  }
});

test("only the frozen guarded initiation can supply a Location reference", () => {
  const input = fixture();
  input.recipe.steps[0].query.ifGenerationMatch = "1";
  assert.throws(
    () => session.evaluateSuppliedSessionLocation(input),
    errorCode("INVALID_DECLARATION"),
  );
  input.recipe.steps[0].query.ifGenerationMatch = "0";
  input.recipe.steps[0].method = "GET";
  assert.throws(
    () => session.evaluateSuppliedSessionLocation(input),
    errorCode("INVALID_DECLARATION"),
  );
});

test("the complete supplied recipe must equal the canonical guarded recipe", () => {
  for (const change of [
    (recipe) => {
      recipe.steps[0].body.json.name = "foreign/object.bin";
    },
    (recipe) => {
      recipe.steps[0].headers["x-upload-content-length"] = "0";
    },
    (recipe) => {
      recipe.steps.push({ id: "unexpected-delete", method: "DELETE" });
    },
    (recipe) => {
      recipe.steps[1].headers["content-range"] = "bytes */0";
    },
    (recipe) => {
      recipe.cleanupAuthorized = true;
    },
  ]) {
    const input = fixture();
    change(input.recipe);
    assert.throws(
      () => session.evaluateSuppliedSessionLocation(input),
      errorCode("INVALID_DECLARATION"),
    );
  }
});

test("malformed declaration steps receive a bounded rejection", () => {
  const input = fixture();
  input.recipe.steps[4] = null;
  assert.throws(
    () => session.evaluateSuppliedSessionLocation(input),
    errorCode("INVALID_DECLARATION"),
  );
});

test("all three subsequent requests must retain the same private reference", () => {
  const input = fixture();
  input.recipe.steps[2].sessionUriReference.expectedOrigin = "https://other.example";
  assert.throws(
    () => session.evaluateSuppliedSessionLocation(input),
    errorCode("INVALID_DECLARATION"),
  );
  input.recipe.steps[2].sessionUriReference.expectedOrigin = "https://storage.googleapis.com";
  input.recipe.steps[3].sessionUriReference.initiateStep = "other";
  assert.throws(
    () => session.evaluateSuppliedSessionLocation(input),
    errorCode("INVALID_DECLARATION"),
  );
});

test("initiation raw body must be the bounded canonical empty capture", () => {
  const input = fixture();
  for (const bodyBase64 of ["!secret!", "QQ==", "A".repeat(1_500_000)]) {
    input.response.bodyBase64 = bodyBase64;
    assert.throws(
      () => session.evaluateSuppliedSessionLocation(input),
      (error) => error?.code === "INVALID_EVIDENCE" && !error.message.includes("secret"),
    );
  }
});
