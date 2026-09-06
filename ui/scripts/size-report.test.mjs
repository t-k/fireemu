import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  buildReport,
  classifyChunks,
  compareReports,
  COMPRESSION,
  readManifest,
} from "./size-report.mjs";

/**
 * A Vite manifest shaped like the app's: one entry, two route chunks loaded lazily, a chunk
 * both routes share, a vendor chunk the entry imports statically, and CSS on the entry.
 */
const manifest = () => ({
  "index.html": {
    file: "assets/index-AAAA.js",
    src: "index.html",
    isEntry: true,
    imports: ["_vendor-BBBB.js"],
    dynamicImports: ["src/routes/Firestore.tsx", "src/routes/Auth.tsx"],
    css: ["assets/index-CCCC.css"],
  },
  "_vendor-BBBB.js": { file: "assets/vendor-BBBB.js" },
  "src/routes/Firestore.tsx": {
    file: "assets/Firestore-DDDD.js",
    src: "src/routes/Firestore.tsx",
    isDynamicEntry: true,
    imports: ["_common-EEEE.js", "_vendor-BBBB.js"],
  },
  "src/routes/Auth.tsx": {
    file: "assets/Auth-FFFF.js",
    src: "src/routes/Auth.tsx",
    isDynamicEntry: true,
    imports: ["_common-EEEE.js"],
  },
  "_common-EEEE.js": { file: "assets/common-EEEE.js" },
});

const bytes = (length, seed) =>
  Buffer.from(Array.from({ length }, (_, index) => (index * 31 + seed) % 251));

/** Writes a dist directory holding the manifest and every file it names. */
function writeDist(root, files) {
  const dist = join(root, "dist");
  mkdirSync(join(dist, ".vite"), { recursive: true });
  mkdirSync(join(dist, "assets"), { recursive: true });
  writeFileSync(join(dist, ".vite", "manifest.json"), JSON.stringify(manifest()));
  writeFileSync(join(dist, "index.html"), "<!doctype html><title>fireemu</title>");
  for (const [name, content] of Object.entries(files)) writeFileSync(join(dist, name), content);
  return dist;
}

const defaultFiles = () => ({
  "assets/index-AAAA.js": bytes(4000, 1),
  "assets/vendor-BBBB.js": bytes(9000, 2),
  "assets/index-CCCC.css": bytes(1500, 3),
  "assets/Firestore-DDDD.js": bytes(3000, 4),
  "assets/Auth-FFFF.js": bytes(2500, 5),
  "assets/common-EEEE.js": bytes(800, 6),
});

const environment = () => ({
  commit: "0123456789abcdef0123456789abcdef01234567",
  node: "v24.14.0",
  vite: "8.2.2",
  platform: "darwin-arm64",
});

let root;
test.beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "fireemu-size-report-"));
});
test.afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

test("chunks are classified as initial, async or shared from the manifest graph", () => {
  const classes = classifyChunks(manifest());
  assert.deepEqual(classes.get("assets/index-AAAA.js"), { category: "initial", owners: [] });
  assert.deepEqual(classes.get("assets/vendor-BBBB.js"), { category: "initial", owners: [] });
  assert.deepEqual(classes.get("assets/index-CCCC.css"), { category: "initial", owners: [] });
  assert.deepEqual(classes.get("assets/Firestore-DDDD.js"), {
    category: "async",
    owners: ["src/routes/Firestore.tsx"],
  });
  assert.deepEqual(classes.get("assets/Auth-FFFF.js"), {
    category: "async",
    owners: ["src/routes/Auth.tsx"],
  });
  assert.deepEqual(classes.get("assets/common-EEEE.js"), {
    category: "shared",
    owners: ["src/routes/Auth.tsx", "src/routes/Firestore.tsx"],
  });
});

test("a report counts every emitted file exactly once and re-aggregates identically", async () => {
  const dist = writeDist(root, defaultFiles());
  const first = await buildReport({ dist, environment: environment() });
  const second = await buildReport({ dist, environment: environment() });
  assert.deepEqual(first, second);

  const total = first.files.reduce((sum, file) => sum + file.bytes, 0);
  assert.equal(first.totals.embedded.bytes, total);
  const byCategory = Object.values(first.totals.categories).reduce(
    (sum, entry) => sum + entry.bytes,
    0,
  );
  assert.equal(byCategory, first.totals.embedded.bytes);
  assert.equal(first.totals.categories.initial.bytes, 4000 + 9000 + 1500);
  assert.equal(first.totals.categories.async.bytes, 3000 + 2500);
  assert.equal(first.totals.categories.shared.bytes, 800);
  assert.equal(first.totals.categories.static.files, 1);
  assert.equal(
    first.files.filter((file) => file.path === "assets/common-EEEE.js").length,
    1,
    "a shared chunk appears once",
  );
  assert.equal(
    first.files.some((file) => file.path.startsWith(".vite/")),
    false,
    "the manifest itself is not an embedded asset",
  );
  for (const file of first.files) {
    assert.ok(file.gzip > 0 && file.gzip <= file.bytes + 32, `${file.path} gzip`);
    assert.ok(file.brotli > 0 && file.brotli <= file.bytes + 32, `${file.path} brotli`);
  }
  assert.deepEqual(first.compression, COMPRESSION);
});

test("a report carries the build conditions and no absolute path or environment variable", async () => {
  const dist = writeDist(root, defaultFiles());
  const report = await buildReport({ dist, environment: environment() });
  const text = JSON.stringify(report);
  assert.equal(text.includes(root), false, "the report must not leak the build directory");
  assert.equal(text.includes(tmpdir()), false);
  assert.equal(report.environment.commit, environment().commit);
  assert.equal(report.environment.vite, "8.2.2");
  assert.equal("env" in report, false);
  assert.equal("HOME" in report.environment, false);
});

test("a missing manifest is an error, not an empty report", async () => {
  mkdirSync(join(root, "dist"), { recursive: true });
  const read = readManifest(join(root, "dist"));
  assert.equal(read.isErr(), true);
  assert.match(read.error, /manifest/);
  await assert.rejects(buildReport({ dist: join(root, "dist"), environment: environment() }));
});

test("a manifest that names a file the build did not emit is an error", async () => {
  const files = defaultFiles();
  delete files["assets/common-EEEE.js"];
  const dist = writeDist(root, files);
  await assert.rejects(
    buildReport({ dist, environment: environment() }),
    /assets\/common-EEEE\.js/,
  );
});

test("an intended asset growth shows up as a per-file and per-category delta", async () => {
  const before = await buildReport({
    dist: writeDist(root, defaultFiles()),
    environment: environment(),
  });
  rmSync(join(root, "dist"), { recursive: true, force: true });
  const grown = defaultFiles();
  grown["assets/Firestore-DDDD.js"] = bytes(3600, 4);
  const after = await buildReport({ dist: writeDist(root, grown), environment: environment() });

  const comparison = compareReports(before, after);
  assert.equal(comparison.isOk(), true, comparison.isErr() ? comparison.error : "");
  const firestore = comparison.value.files.find(
    (entry) => entry.path === "assets/Firestore-DDDD.js",
  );
  assert.equal(firestore.bytes.before, 3000);
  assert.equal(firestore.bytes.after, 3600);
  assert.equal(firestore.bytes.delta, 600);
  assert.equal(comparison.value.categories.async.bytes.delta, 600);
  assert.equal(comparison.value.categories.initial.bytes.delta, 0);
  assert.equal(comparison.value.embedded.bytes.delta, 600);
});

test("reports built under different compression settings or binary targets do not compare", async () => {
  const dist = writeDist(root, defaultFiles());
  const base = await buildReport({ dist, environment: environment() });
  const otherCompression = { ...base, compression: { ...base.compression, gzipLevel: 6 } };
  const refused = compareReports(base, otherCompression);
  assert.equal(refused.isErr(), true);
  assert.match(refused.error, /compression/);

  const binary = {
    path: "target/release/fireemu",
    bytes: 40_000_000,
    target: "aarch64-apple-darwin",
    profile: "release",
    features: [],
  };
  const withBinary = await buildReport({ dist, environment: environment(), binary });
  const otherTarget = await buildReport({
    dist,
    environment: environment(),
    binary: { ...binary, target: "x86_64-unknown-linux-gnu" },
  });
  const crossTarget = compareReports(withBinary, otherTarget);
  assert.equal(crossTarget.isErr(), true);
  assert.match(crossTarget.error, /aarch64-apple-darwin.*x86_64-unknown-linux-gnu/);

  const otherProfile = await buildReport({
    dist,
    environment: environment(),
    binary: { ...binary, profile: "debugging" },
  });
  assert.equal(compareReports(withBinary, otherProfile).isErr(), true);

  const sameTarget = await buildReport({
    dist,
    environment: environment(),
    binary: { ...binary, bytes: 41_000_000 },
  });
  const grown = compareReports(withBinary, sameTarget);
  assert.equal(grown.isOk(), true);
  assert.equal(grown.value.binary.bytes.delta, 1_000_000);

  const uiOnly = compareReports(base, withBinary);
  assert.equal(uiOnly.isOk(), true);
  assert.equal(uiOnly.value.binary, null, "a missing binary on one side is reported as absent");
});
