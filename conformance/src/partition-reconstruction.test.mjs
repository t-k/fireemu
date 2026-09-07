import assert from "node:assert/strict";
import { test } from "node:test";
import {
  partitionRanges,
  verifyPartitionDocuments,
} from "./firestore-probe/partition-reconstruction.mjs";

const parent = "projects/demo/databases/(default)/documents";
const structuredQuery = { from: [{ collectionId: "items", allDescendants: true }] };
const cursor = (id) => ({
  values: [{ referenceValue: `${parent}/owners/o/items/${id}` }],
  before: true,
});
const options = { parent, structuredQuery, partitionCount: 4, pageSize: 2 };
const row = (id, fields = {}) => ({ document: { name: `${parent}/owners/o/items/${id}`, fields } });

test("unordered pages reconstruct adjacent inclusive-start exclusive-end ranges", () => {
  const ranges = partitionRanges({
    ...options,
    pages: [
      { partitions: [cursor("d"), cursor("b")], nextPageToken: "next" },
      { partitions: [cursor("c")] },
    ],
  });
  assert.equal(ranges.length, 4);
  assert.equal(ranges[0].startAt, undefined);
  assert.deepEqual(ranges[0].endAt, cursor("b"));
  assert.deepEqual(ranges[1].startAt, ranges[0].endAt);
  assert.deepEqual(ranges[1].endAt, cursor("c"));
  assert.deepEqual(ranges[2].endAt, cursor("d"));
  assert.equal(ranges[3].endAt, undefined);
});

test("zero partition points retain the complete unbounded query", () => {
  assert.deepEqual(partitionRanges({ ...options, pages: [{}] }), [structuredQuery]);
  assert.deepEqual(verifyPartitionDocuments([], [[]]), { documentCount: 0, rangeCount: 1 });
});

test("reference ordering compares path segments before punctuation in longer segments", () => {
  const short = { values: [{ referenceValue: `${parent}/owners/a/items/x` }], before: true };
  const long = { values: [{ referenceValue: `${parent}/owners/a-/items/x` }], before: true };
  const ranges = partitionRanges({ ...options, pages: [{ partitions: [long, short] }] });
  assert.deepEqual(ranges[0].endAt, short);
  assert.deepEqual(ranges[1].endAt, long);
});

test("malformed cursors and incomplete or oversized pagination are rejected", () => {
  for (const pages of [
    [{ partitions: [cursor("a"), cursor("a")] }],
    [{ partitions: [{ values: [{ integerValue: "2" }] }] }],
    [{ partitions: [{ ...cursor("a"), before: "true" }] }],
    [
      {
        partitions: [
          { values: [{ referenceValue: "projects/other/databases/(default)/documents/items/a" }] },
        ],
      },
    ],
    [{ partitions: [{ values: [{ referenceValue: `${parent}/other/a` }] }] }],
    [{ partitions: [cursor("a"), cursor("b"), cursor("c")] }],
    [{ nextPageToken: "unfinished" }],
    [{}, {}],
    [{ nextPageToken: "same" }, { nextPageToken: "same" }, {}],
  ])
    assert.throws(() => partitionRanges({ ...options, pages }));
  assert.throws(() =>
    partitionRanges({
      ...options,
      partitionCount: 1,
      pages: [{ partitions: [cursor("a"), cursor("b")] }],
    }),
  );
});

test("range union detects missing repeated extra and changed documents", () => {
  const expected = [row("a", { v: { integerValue: "1" } }), row("b")];
  assert.deepEqual(verifyPartitionDocuments(expected, [[expected[0]], [expected[1]]]), {
    documentCount: 2,
    rangeCount: 2,
  });
  for (const ranges of [
    [[expected[0]]],
    [[expected[0]], [expected[0], expected[1]]],
    [[...expected, row("c")]],
    [[row("a", { v: { integerValue: "2" } }), expected[1]]],
    [[{ error: { status: "ABORTED" } }]],
  ])
    assert.throws(() => verifyPartitionDocuments(expected, ranges));
});
