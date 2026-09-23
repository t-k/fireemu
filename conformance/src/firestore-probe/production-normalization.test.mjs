import assert from "node:assert/strict";
import { test } from "node:test";

import { normalizeRecordedResponse } from "./production-normalization.mjs";

const options = { project: "oracle-sandbox-long", recordProject: "demo-short" };

test("orders nested Firestore object keys without changing array order", () => {
  const recorded = normalizeRecordedResponse(
    { fields: { z: { mapValue: { fields: { y: 2, x: 1 } } }, a: 0 }, rows: [{ b: 2, a: 1 }] },
    options,
  );
  assert.equal(
    JSON.stringify(recorded),
    '{"fields":{"a":0,"z":{"mapValue":{"fields":{"x":1,"y":2}}}},"rows":[{"a":1,"b":2}]}',
  );
});

test("normalizes resource-name index relative to the recorded project", () => {
  const original =
    'Document name "projects/oracle-sandbox-long/databases/(default)/documents/err" lacks "/" at index 61.';
  const normalized = normalizeRecordedResponse(original, { ...options, scope: "error" });
  assert.equal(
    normalized,
    'Document name "projects/demo-short/databases/(default)/documents/err" lacks "/" at index 52.',
  );
  assert.equal(
    normalizeRecordedResponse('Document name "bad/path" lacks "projects" at index 0.', {
      ...options,
      scope: "error",
    }),
    'Document name "bad/path" lacks "projects" at index 0.',
  );
});

test("masks only precondition version micros in an error message", () => {
  assert.equal(
    normalizeRecordedResponse(
      "the stored version (1790151274711454) does not match the required base version (1790151274342881)",
      { ...options, scope: "error" },
    ),
    "the stored version (<version>) does not match the required base version (<version>)",
  );
  assert.equal(
    normalizeRecordedResponse("written 1790151274711454 bytes", { ...options, scope: "error" }),
    "written 1790151274711454 bytes",
  );
});

test("masks metadata etag and uid only in a database-metadata response", () => {
  const value = { uid: "random-uid", etag: "random-etag", type: "FIRESTORE_NATIVE" };
  assert.deepEqual(normalizeRecordedResponse(value, { ...options, scope: "database-metadata" }), {
    etag: "<database-etag>",
    type: "FIRESTORE_NATIVE",
    uid: "<database-uid>",
  });
  assert.deepEqual(normalizeRecordedResponse(value, options), {
    etag: "random-etag",
    type: "FIRESTORE_NATIVE",
    uid: "random-uid",
  });
});
