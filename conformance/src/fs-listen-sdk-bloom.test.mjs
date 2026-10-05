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
  // Production's three recorded filters (L1 and L1b): hash count, bitmap bytes, padding. The
  // recordings state the bitmap only by the length of its base64 text (4, 8 and 12, which allow
  // 1-3, 4-6 and 7-9 bytes); the bytes are derived: the one size per count whose hash count is the
  // rounded optimum bits / documents * ln 2 (see the Rust test of the same relation).
  assert.deepEqual(
    [
      [12, 3, 7],
      [13, 5, 3],
      [14, 8, 5],
    ].map(([hashCount, bytes, padding]) => bitCount({ hashCount, bytes, padding })),
    [17, 37, 59],
  );
});

test("each recorded size is the only one whose hash count is the rounded optimum and whose base64 text has the recorded length", () => {
  const hashes = (bytes, padding, documents) =>
    Math.round(((bytes * 8 - padding) / documents) * Math.LN2);
  const base64Length = (bytes) => Math.ceil(bytes / 3) * 4;
  // [documents, hash count, bytes, padding, base64 length]
  for (const [documents, hashCount, bytes, padding, text] of [
    [1, 12, 3, 7, 4],
    [2, 13, 5, 3, 8],
    [3, 14, 8, 5, 12],
  ]) {
    const fits = [1, 2, 3, 4, 5, 6, 7, 8, 9].filter(
      (candidate) =>
        base64Length(candidate) === text && hashes(candidate, padding, documents) === hashCount,
    );
    assert.deepEqual(fits, [bytes], `${documents} documents`);
  }
  // The near misses a base64 length alone would allow: 6 and 9 bytes give 16 and 15 hashes.
  assert.equal(hashes(6, 3, 2), 16);
  assert.equal(hashes(9, 5, 3), 15);
});

test("the extracted SDK filter accepts what was inserted and is deterministic", () => {
  const names = [
    "projects/p/databases/(default)/documents/r/a",
    "projects/p/databases/(default)/documents/r/b",
  ];
  const filter = sdkFilter({ hashCount: 13, bytes: 5, padding: 3 }, names);
  for (const name of names) assert.equal(filter.mightContain(name), true);
  assert.equal(filter.bitCount, 37);
  assert.deepEqual(sdkFilter({ hashCount: 13, bytes: 5, padding: 3 }, names).bitmap, filter.bitmap);
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
