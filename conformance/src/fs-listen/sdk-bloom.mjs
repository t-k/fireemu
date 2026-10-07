// The Web SDK's own bloom filter (the `unchanged_names` of an existence filter), taken out of the
// pinned SDK bundle so that a bloom filter fireemu sends can be checked with the SDK's code, not
// with a copy of its algorithm. The class is not exported by the package, so its source is cut out
// of the bundle between two markers and evaluated with the bundle's own dependencies.

import { readdirSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";

const require = createRequire(import.meta.url);

/** The version of @firebase/firestore the extraction was written against. */
export const SDK_VERSION = "4.17.1";

const START = "// Hash a string using md5 hashing algorithm.";
const END = "class BloomFilterError extends Error {";

/** Refuses a package that is not the version the extraction was written against. */
export function checkSdkVersion(version) {
  if (version !== SDK_VERSION)
    throw new Error(`@firebase/firestore ${version} is not ${SDK_VERSION}`);
}

/** The bundle of `names` (the file names of the package's dist) that holds the bloom filter. */
export function findBundle(names, read) {
  const file = names.find(
    (name) => /^common-.*\.node\.cjs\.js$/.test(name) && read(name).includes(START),
  );
  if (!file) throw new Error("the SDK bundle with the bloom filter was not found");
  return file;
}

/** The source of the md5 helpers and the two classes, cut out of a bundle between the markers. */
export function bloomSource(text) {
  const from = text.indexOf(START);
  const end = text.indexOf(END);
  if (from < 0 || end < from) throw new Error("the bloom filter is not where it was");
  const to = text.indexOf("\n}\n", end) + 3;
  return text.slice(from, to);
}

/** The SDK's `BloomFilter` and its md5 helper, from the bundle of the installed package. */
export function loadSdkBloom(root = dirname(require.resolve("@firebase/firestore/package.json"))) {
  checkSdkVersion(JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version);
  const dist = join(root, "dist");
  const file = findBundle(readdirSync(dist), (name) => readFileSync(join(dist, name), "utf8"));
  const body = bloomSource(readFileSync(join(dist, file), "utf8"));
  const bloomBlob = require(
    require.resolve("@firebase/webchannel-wrapper/bloom-blob", { paths: [root] }),
  );
  const make = new Function(
    "bloomBlob",
    "newTextEncoder",
    `const MAX_64_BIT_UNSIGNED_INTEGER = new bloomBlob.Integer([0xffffffff, 0xffffffff], 0);\n${body}\nreturn { BloomFilter, BloomFilterError };`,
  );
  return make(bloomBlob, () => new TextEncoder());
}

/** The SDK's filter over `names`, with the bitmap size fireemu is to send: bytes and padding. */
export function sdkFilter({ hashCount, bytes, padding }, names) {
  const { BloomFilter } = loadSdkBloom();
  const filter = new BloomFilter(new Uint8Array(bytes), padding, hashCount);
  for (const name of names) filter.insert(name);
  return filter;
}

const ROOT = "projects/vectors/databases/(default)/documents";

/**
 * The sizes production sent for 1, 2 and 3 documents (12 hashes in 3 bytes with 7 padding bits, 13 in 6
 * with 3, 14 in 9 with 5: the recordings state the bitmap by the length of its base64 text, 4, 8 and 12),
 * and a few others that exercise the arithmetic.
 */
const SIZES = [
  { hashCount: 12, bytes: 3, padding: 7 },
  { hashCount: 13, bytes: 5, padding: 3 },
  { hashCount: 14, bytes: 8, padding: 5 },
  { hashCount: 1, bytes: 1, padding: 0 },
  { hashCount: 7, bytes: 2, padding: 3 },
  { hashCount: 20, bytes: 16, padding: 0 },
  { hashCount: 3, bytes: 5, padding: 7 },
];

const NAME_SETS = [
  ["r/a"],
  ["r/a", "r/b"],
  ["r/a", "r/b", "r/c"],
  ["lsn_native/nmuv70w0y-g0-a", "lsn_native/nmuv70w0y-g0-b", "lsn_native/nmuv70w0y-g0-c"],
  ["users/ü/posts/日本語", "users/ü/posts/x y", "a/b"],
  ["x/1", "x/2", "x/3", "x/4", "x/5", "x/6"],
  [],
];

const PROBES = [
  "r/a",
  "r/b",
  "r/c",
  "r/d",
  "r/zz",
  "lsn_native/nmuv70w0y-g0-d",
  "users/ü/posts/日本語",
  ...Array.from({ length: 9 }, (_, i) => `probe/${i}`),
];

/**
 * Bloom filters built and checked by the SDK's own code, for sizes and name sets: the bitmap and the
 * SDK's `mightContain` of every probe. fireemu's filter must equal the bitmap and give the same
 * membership answers; the vectors are committed and a test regenerates them from the SDK.
 */
export function sdkBloomVectors() {
  const vectors = [];
  for (const size of SIZES) {
    for (const set of NAME_SETS) {
      const names = set.map((path) => `${ROOT}/${path}`);
      const filter = sdkFilter(size, names);
      vectors.push({
        ...size,
        names,
        bitmap: Buffer.from(filter.bitmap).toString("hex"),
        probes: PROBES.map((path) => {
          const name = `${ROOT}/${path}`;
          return [name, filter.mightContain(name)];
        }),
      });
    }
  }
  return { sdk: `@firebase/firestore ${SDK_VERSION}`, vectors };
}
