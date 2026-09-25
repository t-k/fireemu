import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import test from "node:test";

const moduleUrl = new URL("./partition.mjs", import.meta.url);
const load = async () => {
  assert.ok(existsSync(moduleUrl), "partition invariant implementation is required");
  return import(moduleUrl);
};
const row = (id, value = 1) => ({
  document: {
    name: `projects/demo-partition/databases/(default)/documents/items/${id}`,
    fields: { value: { integerValue: String(value) } },
    createTime: "t1",
    updateTime: "t2",
  },
  readTime: "snapshot",
});

test("ordered reconstruction preserves identity occurrences and complete documents", async () => {
  const { verifyOrdered } = await load();
  assert.equal(verifyOrdered([row("a"), row("b")], [[row("a")], [row("b")]]).documentCount, 2);
  for (const ranges of [
    [[row("a"), row("a"), row("b")]],
    [[row("a")]],
    [[row("b"), row("a")]],
    [[row("a"), row("b", 2)]],
  ]) {
    assert.throws(() => verifyOrdered([row("a"), row("b")], ranges));
  }
  const changed = row("b");
  changed.document.updateTime = "changed";
  assert.throws(() => verifyOrdered([row("a"), row("b")], [[row("a"), changed]]));
  assert.throws(() => verifyOrdered([row("b"), row("a")], [[row("b"), row("a")]]));
  assert.equal(verifyOrdered([{ readTime: "snapshot" }], [[]]).documentCount, 0);
});

test("page merge permits global page disorder and rejects duplicate or incomplete boundaries", async () => {
  const { rangesFor } = await load();
  const cursor = (id) => ({ before: true, values: [{ referenceValue: row(id).document.name }] });
  const options = {
    parent: "projects/demo-partition/databases/(default)/documents",
    structuredQuery: {
      from: [{ collectionId: "items", allDescendants: true }],
      orderBy: [{ field: { fieldPath: "__name__" }, direction: "ASCENDING" }],
    },
    partitionCount: 2,
    pageSize: 1,
  };
  const ranges = rangesFor({
    ...options,
    pages: [{ partitions: [cursor("b")], nextPageToken: "next" }, { partitions: [cursor("a")] }],
  });
  assert.equal(ranges.length, 3);
  assert.deepEqual(ranges[0].endAt, cursor("a"));
  assert.throws(() =>
    rangesFor({
      ...options,
      pages: [{ partitions: [cursor("a")], nextPageToken: "next" }, { partitions: [cursor("a")] }],
    }),
  );
  assert.throws(() => rangesFor({ ...options, pages: [{ nextPageToken: "pending" }] }));
});
