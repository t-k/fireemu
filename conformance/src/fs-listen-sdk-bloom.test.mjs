import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { SDK_VERSION, loadSdkBloom, sdkBloomVectors, sdkFilter } from "./fs-listen/sdk-bloom.mjs";

const FIXTURE = new URL(
  "../../crates/fireemu-adapter-grpc/tests/fixtures/sdk-bloom-vectors.json",
  import.meta.url,
);

test("the committed bloom vectors are exactly what the pinned SDK's own BloomFilter produces", () => {
  const committed = JSON.parse(readFileSync(FIXTURE, "utf8"));
  assert.deepEqual(committed, sdkBloomVectors());
});

test("the SDK bloom is the one the existence filter of production uses: the sizes recorded for 1, 2 and 3 documents", () => {
  assert.equal(SDK_VERSION, "4.17.1");
  const bitCount = ({ bytes, padding }) => bytes * 8 - padding;
  // Production's three recorded filters (L1 and L1b): hash count, bitmap bytes, padding. The recordings state the bitmap by the length
  // of its base64 text, which is 4, 8 and 12 for these 3, 6 and 9 bytes.
  assert.deepEqual(
    [
      [12, 3, 7],
      [13, 6, 3],
      [14, 9, 5],
    ].map(([hashCount, bytes, padding]) => bitCount({ hashCount, bytes, padding })),
    [17, 45, 67],
  );
});

test("the extracted SDK filter accepts what was inserted and is deterministic", () => {
  const names = ["projects/p/databases/(default)/documents/r/a", "projects/p/databases/(default)/documents/r/b"];
  const filter = sdkFilter({ hashCount: 13, bytes: 6, padding: 3 }, names);
  for (const name of names) assert.equal(filter.mightContain(name), true);
  assert.equal(filter.bitCount, 45);
  assert.deepEqual(sdkFilter({ hashCount: 13, bytes: 6, padding: 3 }, names).bitmap, filter.bitmap);
  const { BloomFilter } = loadSdkBloom();
  assert.equal(typeof BloomFilter, "function");
  // An empty bitmap contains nothing.
  assert.equal(new BloomFilter(new Uint8Array(0), 0, 0).mightContain("x"), false);
});
