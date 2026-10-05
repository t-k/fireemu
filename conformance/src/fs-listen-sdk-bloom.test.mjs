import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  SDK_VERSION,
  bloomSource,
  checkSdkVersion,
  findBundle,
  loadSdkBloom,
  sdkBloomVectors,
  sdkFilter,
} from "./fs-listen/sdk-bloom.mjs";

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
  const names = [
    "projects/p/databases/(default)/documents/r/a",
    "projects/p/databases/(default)/documents/r/b",
  ];
  const filter = sdkFilter({ hashCount: 13, bytes: 6, padding: 3 }, names);
  for (const name of names) assert.equal(filter.mightContain(name), true);
  assert.equal(filter.bitCount, 45);
  assert.deepEqual(sdkFilter({ hashCount: 13, bytes: 6, padding: 3 }, names).bitmap, filter.bitmap);
  const { BloomFilter } = loadSdkBloom();
  assert.equal(typeof BloomFilter, "function");
  // An empty bitmap contains nothing.
  assert.equal(new BloomFilter(new Uint8Array(0), 0, 0).mightContain("x"), false);
});

test("the extraction refuses another SDK version, a package without the bundle and a bundle that moved the class", () => {
  checkSdkVersion("4.17.1");
  for (const other of ["4.17.2", "4.16.1", "5.0.0", "", undefined])
    assert.throws(() => checkSdkVersion(other), /is not 4\.17\.1/, String(other));
  const marker = "// Hash a string using md5 hashing algorithm.";
  const bundles = {
    "index.js": `${marker}`,
    "common-a.node.cjs.js": "nothing here",
    "common-b.esm.js": marker,
    "common-c.node.cjs.js": `x\n${marker}\ny`,
  };
  const names = Object.keys(bundles);
  assert.equal(
    findBundle(names, (name) => bundles[name]),
    "common-c.node.cjs.js",
  );
  assert.throws(
    () => findBundle(["common-a.node.cjs.js", "common-b.esm.js"], (name) => bundles[name]),
    /bundle with the bloom filter was not found/,
  );
  assert.throws(() => findBundle([], () => ""), /not found/);
  // The source runs from the first marker to the closing brace of the error class, and not a character further.
  const text = `before\n${marker}\nfunction f() {}\nclass BloomFilterError extends Error {\n  constructor() {}\n}\nafter`;
  assert.equal(
    bloomSource(text),
    `${marker}\nfunction f() {}\nclass BloomFilterError extends Error {\n  constructor() {}\n}\n`,
  );
  assert.throws(() => bloomSource("no markers"), /not where it was/);
  assert.throws(
    () => bloomSource(`class BloomFilterError extends Error {\n}\n${marker}`),
    /not where it was/,
  );
  assert.throws(() => bloomSource(`${marker}\nno class`), /not where it was/);
});

test("loading the SDK bloom from a package root refuses another version and a package without the bundle", () => {
  const fake = (version, files = {}) => {
    const root = mkdtempSync(join(tmpdir(), "sdk-bloom-"));
    writeFileSync(join(root, "package.json"), JSON.stringify({ version }));
    mkdirSync(join(root, "dist"));
    for (const [name, text] of Object.entries(files)) writeFileSync(join(root, "dist", name), text);
    return root;
  };
  assert.throws(() => loadSdkBloom(fake("9.9.9")), /9\.9\.9 is not 4\.17\.1/);
  assert.throws(() => loadSdkBloom(fake("4.17.1")), /bundle with the bloom filter was not found/);
  assert.throws(
    () =>
      loadSdkBloom(
        fake("4.17.1", {
          "common-x.node.cjs.js": "// Hash a string using md5 hashing algorithm.\n",
        }),
      ),
    /not where it was/,
  );
});

test("the source may begin at the very start of the bundle", () => {
  const marker = "// Hash a string using md5 hashing algorithm.";
  const text = `${marker}\nclass BloomFilterError extends Error {\n}\n`;
  assert.equal(bloomSource(text), text);
});
