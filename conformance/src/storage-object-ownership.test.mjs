import assert from "node:assert/strict";
import { test } from "node:test";
import { createRunOwnership } from "./storage-object/ownership.mjs";

const options = { bucket: "example.appspot.com", prefix: "storage-object/recordone/" };
const name = `${options.prefix}simple/object.bin`;
const emptyPages = [{ items: [], nextPageToken: null }];
const absent = {
  metadataStatus: 404,
  mediaStatus: 404,
  prefixPagesComplete: true,
  nameFound: false,
};
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
    () =>
      ownership.assertInitialEmpty({
        ...options,
        pages: [{ items: [{ name }], nextPageToken: null }],
      }),
    /occupied/i,
  );
  assert.throws(
    () =>
      ownership.assertInitialEmpty({ ...options, pages: [{ items: [], nextPageToken: "more" }] }),
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
    () =>
      ownership.assertInitialEmpty({
        ...options,
        bucket: "another.appspot.com",
        pages: emptyPages,
      }),
    /bucket/i,
  );
  assert.throws(
    () => ownership.cleanupRequest("storage-object/recordtwo/x", owned),
    /prefix|name/i,
  );
  assert.equal(ownership.noteInitialAbsent(name, absent), true);
});

test("an uncertain write is retained, and cleanup needs matching owned generation and bytes", () => {
  const ownership = createRunOwnership(options);
  ownership.assertInitialEmpty({ ...options, pages: emptyPages });
  ownership.noteInitialAbsent(name, absent);
  ownership.noteMutationAttempt(name, "simple-upload");
  assert.throws(() => ownership.cleanupRequest(name, owned), /uncertain|unverified/i);
  assert.deepEqual(ownership.unresolved(), [name]);
  assert.throws(
    () =>
      ownership.observeOwnedGeneration(
        name,
        { ...owned, bytesSha256: "b".repeat(64) },
        owned.bytesSha256,
      ),
    /bytes/i,
  );
  ownership.observeOwnedGeneration(name, owned, owned.bytesSha256);
  assert.throws(
    () => ownership.cleanupRequest(name, { ...owned, generation: "12346" }),
    /generation/i,
  );
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
  assert.throws(
    () => ownership.noteDeleted(name, { status: 204, metadataStatus: 404, mediaStatus: 404 }),
    /cleanup request/i,
  );
  ownership.cleanupRequest(name, owned);
  assert.throws(() => ownership.verifyEmpty({ ...options, pages: emptyPages }), /unresolved/i);
  ownership.noteDeleted(name, { status: 204, metadataStatus: 404, mediaStatus: 404 });
  assert.throws(
    () =>
      ownership.verifyEmpty({ ...options, pages: [{ items: [{ name }], nextPageToken: null }] }),
    /occupied/i,
  );
});

test("a refused mutation restores known ownership only after unchanged generation and bytes", () => {
  const ownership = createRunOwnership(options);
  ownership.assertInitialEmpty({ ...options, pages: emptyPages });
  ownership.noteInitialAbsent(name, absent);
  ownership.noteMutationAttempt(name, "initial-upload");
  ownership.observeOwnedGeneration(
    name,
    { ...owned, operationId: "initial-upload" },
    owned.bytesSha256,
  );
  ownership.noteMutationAttempt(name, "refused-patch");
  assert.throws(
    () =>
      ownership.noteRefusedMutation(
        name,
        { operationId: "refused-patch", status: 501 },
        { ...owned, generation: "12346" },
      ),
    /unchanged|generation/i,
  );
  assert.deepEqual(ownership.unresolved(), [name]);
  ownership.noteRefusedMutation(name, { operationId: "refused-patch", status: 501 }, owned);
  assert.deepEqual(ownership.unresolved(), [name]);
  assert.deepEqual(ownership.cleanupRequest(name, owned).query, { ifGenerationMatch: "12345" });
});

test("subject deletion and repeated absent refusal require fresh absence and exact prefix proof", () => {
  const ownership = createRunOwnership(options);
  ownership.assertInitialEmpty({ ...options, pages: emptyPages });
  ownership.noteInitialAbsent(name, absent);
  ownership.noteMutationAttempt(name, "upload");
  ownership.observeOwnedGeneration(name, { ...owned, operationId: "upload" }, owned.bytesSha256);
  ownership.noteMutationAttempt(name, "delete");
  assert.throws(
    () =>
      ownership.noteSubjectDeleted(name, {
        operationId: "delete",
        status: 204,
        metadataStatus: 404,
        mediaStatus: 404,
        prefixPagesComplete: true,
        nameFound: true,
      }),
    /absence|prefix/i,
  );
  ownership.noteSubjectDeleted(name, {
    operationId: "delete",
    status: 204,
    metadataStatus: 404,
    mediaStatus: 404,
    prefixPagesComplete: true,
    nameFound: false,
  });
  assert.deepEqual(ownership.unresolved(), []);
  ownership.noteMutationAttempt(name, "repeat-delete");
  ownership.noteRefusedAbsent(name, {
    operationId: "repeat-delete",
    status: 404,
    metadataStatus: 404,
    mediaStatus: 404,
    prefixPagesComplete: true,
    nameFound: false,
  });
  assert.deepEqual(ownership.unresolved(), []);
});

test("invalid-name refusal needs a complete run list equal to known owned names", () => {
  const ownership = createRunOwnership(options);
  const invalid = `${options.prefix}bad\nname.bin`;
  ownership.assertInitialEmpty({ ...options, pages: emptyPages });
  ownership.noteInitialAbsent(name, absent);
  ownership.noteInitialAbsent(invalid, absent);
  ownership.noteMutationAttempt(name, "upload");
  ownership.observeOwnedGeneration(name, { ...owned, operationId: "upload" }, owned.bytesSha256);
  ownership.noteMutationAttempt(invalid, "invalid-upload");
  const proof = {
    ...options,
    operationId: "invalid-upload",
    status: 400,
    pages: [
      { pageToken: null, items: [{ bucket: options.bucket, name }], nextPageToken: "next" },
      { pageToken: "next", items: [], nextPageToken: null },
    ],
  };
  assert.throws(
    () =>
      ownership.noteRefusedAbsentFromRunList(invalid, {
        ...proof,
        pages: [
          { ...proof.pages[0], nextPageToken: null },
          { ...proof.pages[1], pageToken: "unexpected" },
        ],
      }),
    /page|token|complete/i,
  );
  assert.throws(
    () =>
      ownership.noteRefusedAbsentFromRunList(invalid, {
        ...proof,
        pages: [
          {
            pageToken: null,
            items: [{ bucket: options.bucket, name: `${options.prefix}bad%0Aname.bin` }],
            nextPageToken: null,
          },
        ],
      }),
    /owned|unexpected|names/i,
  );
  assert.throws(
    () =>
      ownership.noteRefusedAbsentFromRunList(invalid, {
        ...proof,
        pages: [{ pageToken: null, items: [], nextPageToken: null }],
      }),
    /owned|missing|names/i,
  );
  assert.deepEqual(ownership.unresolved(), [invalid, name]);
  ownership.noteRefusedAbsentFromRunList(invalid, proof);
  assert.deepEqual(ownership.unresolved(), [name]);
});

test("a 304, production's answer to a not-match guard that names the current value, is a refused write; 399 and 600 are not", () => {
  for (const status of [304, 400, 412, 501, 599]) {
    const ownership = createRunOwnership(options);
    ownership.assertInitialEmpty({ ...options, pages: emptyPages });
    ownership.noteInitialAbsent(name, absent);
    ownership.noteMutationAttempt(name, "initial-upload");
    ownership.observeOwnedGeneration(
      name,
      { ...owned, operationId: "initial-upload" },
      owned.bytesSha256,
    );
    ownership.noteMutationAttempt(name, "refused-write");
    ownership.noteRefusedMutation(name, { operationId: "refused-write", status }, owned);
    // The object is known and owned again, with no write pending: the next write may start.
    ownership.noteMutationAttempt(name, "next-write");
  }
  for (const status of [200, 204, 303, 305, 399, 600, 304.5, "304", null]) {
    const ownership = createRunOwnership(options);
    ownership.assertInitialEmpty({ ...options, pages: emptyPages });
    ownership.noteInitialAbsent(name, absent);
    ownership.noteMutationAttempt(name, "initial-upload");
    ownership.observeOwnedGeneration(
      name,
      { ...owned, operationId: "initial-upload" },
      owned.bytesSha256,
    );
    ownership.noteMutationAttempt(name, "refused-write");
    assert.throws(
      () => ownership.noteRefusedMutation(name, { operationId: "refused-write", status }, owned),
      /not bound to a pending request/,
      String(status),
    );
  }
});

test("a 304 on a write to an absent object is a refused absent write, with the same absence proof", () => {
  for (const [status, accepted] of [
    [304, true],
    [404, true],
    [599, true],
    [399, false],
    [600, false],
    [204, false],
  ]) {
    const ownership = createRunOwnership(options);
    ownership.assertInitialEmpty({ ...options, pages: emptyPages });
    ownership.noteInitialAbsent(name, absent);
    ownership.noteMutationAttempt(name, "refused-upload");
    const proof = {
      operationId: "refused-upload",
      status,
      metadataStatus: 404,
      mediaStatus: 404,
      prefixPagesComplete: true,
      nameFound: false,
    };
    if (accepted) {
      ownership.noteRefusedAbsent(name, proof);
      assert.deepEqual(ownership.unresolved(), [], String(status));
    } else
      assert.throws(
        () => ownership.noteRefusedAbsent(name, proof),
        /refused absent mutation/,
        String(status),
      );
  }
});
