import assert from "node:assert/strict";
import { test } from "node:test";
import { createRunOwnership } from "./storage-object/ownership.mjs";

const options = { bucket: "example.appspot.com", prefix: "storage-object/recordone/" };
const name = `${options.prefix}simple/object.bin`;
const emptyPages = [{ items: [], nextPageToken: null }];
const absent = { metadataStatus: 404, mediaStatus: 404, prefixPagesComplete: true, nameFound: false };
const owned = {
  bucket: options.bucket,
  name,
  generation: "12345",
  bytesSha256: "a".repeat(64),
  operationId: "simple-upload",
};

test("initial namespace admission rejects an occupied or incomplete run prefix", () => {
  const ownership = createRunOwnership(options);
  assert.throws(
    () => ownership.assertInitialEmpty({ ...options, pages: [{ items: [{ name }], nextPageToken: null }] }),
    /occupied/i,
  );
  assert.throws(
    () => ownership.assertInitialEmpty({ ...options, pages: [{ items: [], nextPageToken: "more" }] }),
    /incomplete/i,
  );
  assert.equal(ownership.assertInitialEmpty({ ...options, pages: emptyPages }), true);
  assert.equal(ownership.noteInitialAbsentFromNamespace(name), true);
  assert.throws(() => ownership.noteInitialAbsentFromNamespace(name), /already recorded/i);
});

test("only the exact run prefix and bucket can enter the ownership journal", () => {
  const ownership = createRunOwnership(options);
  ownership.assertInitialEmpty({ ...options, pages: emptyPages });
  for (const candidate of [
    "storage-object/recordtwo/simple/object.bin",
    "storage-object/recordone2/simple/object.bin",
    "storage-object/recordone/../outside.bin",
  ])
    assert.throws(() => ownership.noteInitialAbsent(candidate, absent), /prefix|name/i);
  assert.throws(
    () => ownership.assertInitialEmpty({ ...options, bucket: "another.appspot.com", pages: emptyPages }),
    /bucket/i,
  );
  assert.throws(() => ownership.cleanupRequest("storage-object/recordtwo/x", owned), /prefix|name/i);
  assert.equal(ownership.noteInitialAbsent(name, absent), true);
});

test("an uncertain write is retained, and cleanup needs matching owned generation and bytes", () => {
  const ownership = createRunOwnership(options);
  ownership.assertInitialEmpty({ ...options, pages: emptyPages });
  ownership.noteInitialAbsent(name, absent);
  ownership.noteMutationAttempt(name, "simple-upload");
  assert.throws(() => ownership.cleanupRequest(name, owned), /uncertain|unverified/i);
  assert.deepEqual(ownership.unresolved(), [name]);
  assert.throws(() => ownership.observeOwnedGeneration(name, { ...owned, bytesSha256: "b".repeat(64) }, owned.bytesSha256), /bytes/i);
  ownership.observeOwnedGeneration(name, owned, owned.bytesSha256);
  assert.throws(() => ownership.cleanupRequest(name, { ...owned, generation: "12346" }), /generation/i);
  assert.deepEqual(ownership.cleanupRequest(name, owned), {
    method: "DELETE",
    bucket: options.bucket,
    name,
    query: { ifGenerationMatch: "12345" },
  });
  ownership.noteDeleted(name, { status: 204, metadataStatus: 404, mediaStatus: 404 });
  assert.equal(ownership.verifyEmpty({ ...options, pages: emptyPages }), true);
  assert.deepEqual(ownership.unresolved(), []);
});

test("an unproved delete or nonempty final prefix cannot mark cleanup complete", () => {
  const ownership = createRunOwnership(options);
  ownership.assertInitialEmpty({ ...options, pages: emptyPages });
  ownership.noteInitialAbsent(name, absent);
  ownership.noteMutationAttempt(name, "simple-upload");
  ownership.observeOwnedGeneration(name, owned, owned.bytesSha256);
  assert.throws(() => ownership.noteDeleted(name, { status: 204, metadataStatus: 404, mediaStatus: 404 }), /cleanup request/i);
  ownership.cleanupRequest(name, owned);
  assert.throws(() => ownership.verifyEmpty({ ...options, pages: emptyPages }), /unresolved/i);
  ownership.noteDeleted(name, { status: 204, metadataStatus: 404, mediaStatus: 404 });
  assert.throws(
    () => ownership.verifyEmpty({ ...options, pages: [{ items: [{ name }], nextPageToken: null }] }),
    /occupied/i,
  );
});
