// Size report for the built Emulator UI and, optionally, the daemon binary that embeds it.
//
//   node scripts/size-report.mjs --out .runs/size-report.json
//   node scripts/size-report.mjs --out .runs/size-report.json --baseline .runs/previous.json
//   node scripts/size-report.mjs --binary ../target/release/fireemu --target aarch64-apple-darwin --profile release
//
// The report reads Vite's build manifest (`dist/.vite/manifest.json`) to tell the initial
// bundle (the entry and everything it imports statically) from route chunks loaded on demand
// (`async`) and chunks several routes share (`shared`); files the manifest does not describe
// (`index.html`, icons) are `static`. Every emitted file is counted exactly once, so the
// category totals add up to the embedded total. Compression uses fixed settings so two reports
// measure the same thing; a comparison refuses reports whose settings, binary target, profile
// or features differ instead of presenting them as a trend.
//
// Paths in the report are relative to `dist`; no environment variable or absolute path is
// recorded.

import { readdirSync, readFileSync, statSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { brotliCompressSync, constants as zlib, gzipSync } from "node:zlib";
import { execFileSync } from "node:child_process";
import { err, ok } from "neverthrow";

export const SCHEMA_VERSION = 1;

/** Fixed compression settings; a report records them so a comparison can refuse a mismatch. */
export const COMPRESSION = Object.freeze({
  gzipLevel: 9,
  brotliQuality: 11,
  brotliMode: "text",
});

const MANIFEST = join(".vite", "manifest.json");
const CATEGORIES = ["initial", "async", "shared", "static"];

/** Reads and parses the Vite manifest, or explains why the report cannot be built. */
export function readManifest(dist) {
  const path = join(dist, MANIFEST);
  let text;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return err(
      `no Vite manifest at ${MANIFEST}: build with \`pnpm -C ui build\` (vite.config.ts sets build.manifest)`,
    );
  }
  try {
    const manifest = JSON.parse(text);
    if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) {
      return err(`${MANIFEST} is not a JSON object`);
    }
    return ok(manifest);
  } catch (error) {
    return err(`${MANIFEST} is not valid JSON: ${error.message}`);
  }
}

/** Static import closure of `start`, as manifest keys, excluding anything in `stop`. */
function staticClosure(manifest, start, stop = new Set()) {
  const seen = new Set();
  const stack = [...start];
  while (stack.length > 0) {
    const key = stack.pop();
    if (seen.has(key) || stop.has(key)) continue;
    seen.add(key);
    for (const next of manifest[key]?.imports ?? []) stack.push(next);
  }
  return seen;
}

const emittedFiles = (manifest, keys) => {
  const files = [];
  for (const key of keys) {
    const chunk = manifest[key];
    if (!chunk) continue;
    if (chunk.file) files.push(chunk.file);
    for (const css of chunk.css ?? []) files.push(css);
    for (const asset of chunk.assets ?? []) files.push(asset);
  }
  return files;
};

/**
 * Classifies every file the manifest emits.
 *
 * @returns Map from emitted path to `{category, owners}`, where `owners` lists the dynamic
 *   entries (manifest keys, sorted) whose static closure reaches a non-initial chunk.
 */
export function classifyChunks(manifest) {
  const entries = Object.keys(manifest).filter((key) => manifest[key].isEntry);
  const initialKeys = staticClosure(manifest, entries);
  const classes = new Map();
  for (const file of emittedFiles(manifest, initialKeys)) {
    classes.set(file, { category: "initial", owners: [] });
  }

  const dynamicRoots = Object.keys(manifest).filter(
    (key) => manifest[key].isDynamicEntry && !initialKeys.has(key),
  );
  const owners = new Map();
  for (const root of dynamicRoots) {
    for (const key of staticClosure(manifest, [root], initialKeys)) {
      for (const file of emittedFiles(manifest, [key])) {
        if (!owners.has(file)) owners.set(file, new Set());
        owners.get(file).add(root);
      }
    }
  }
  for (const [file, roots] of owners) {
    if (classes.has(file)) continue;
    const sorted = [...roots].toSorted();
    classes.set(file, { category: sorted.length > 1 ? "shared" : "async", owners: sorted });
  }
  // A chunk neither an entry nor a dynamic entry reaches: emitted, so still counted.
  for (const key of Object.keys(manifest)) {
    for (const file of emittedFiles(manifest, [key])) {
      if (!classes.has(file)) classes.set(file, { category: "async", owners: [] });
    }
  }
  return classes;
}

function listFiles(dist) {
  const out = [];
  const walk = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        if (relative(dist, path) === ".vite") continue;
        walk(path);
      } else if (entry.isFile()) {
        out.push(relative(dist, path).split(sep).join("/"));
      }
    }
  };
  walk(dist);
  return out.toSorted();
}

function measure(content) {
  const gzip = gzipSync(content, { level: COMPRESSION.gzipLevel }).length;
  const brotli = brotliCompressSync(content, {
    params: {
      [zlib.BROTLI_PARAM_QUALITY]: COMPRESSION.brotliQuality,
      [zlib.BROTLI_PARAM_MODE]: zlib.BROTLI_MODE_TEXT,
      [zlib.BROTLI_PARAM_SIZE_HINT]: content.length,
    },
  }).length;
  return { bytes: content.length, gzip, brotli };
}

const emptyTotal = () => ({ files: 0, bytes: 0, gzip: 0, brotli: 0 });

const add = (total, file) => {
  total.files += 1;
  total.bytes += file.bytes;
  total.gzip += file.gzip;
  total.brotli += file.brotli;
};

/**
 * @param options.dist the Vite output directory
 * @param options.environment `{commit, node, vite, platform}` and nothing else
 * @param options.binary optional `{path, bytes, target, profile, features}` of the daemon
 */
export async function buildReport({ dist, environment, binary = null }) {
  const manifest = readManifest(dist);
  if (manifest.isErr()) throw new Error(manifest.error);
  const classes = classifyChunks(manifest.value);
  const present = new Set(listFiles(dist));
  for (const file of classes.keys()) {
    if (!present.has(file)) {
      throw new Error(`the manifest names ${file}, which the build did not emit`);
    }
  }
  const files = [];
  const categories = Object.fromEntries(CATEGORIES.map((name) => [name, emptyTotal()]));
  const embedded = emptyTotal();
  for (const path of present) {
    const content = readFileSync(join(dist, path));
    const sizes = measure(content);
    const cls = classes.get(path) ?? { category: "static", owners: [] };
    const file = { path, category: cls.category, owners: cls.owners, ...sizes };
    files.push(file);
    add(categories[cls.category], file);
    add(embedded, file);
  }
  return {
    schemaVersion: SCHEMA_VERSION,
    environment: {
      commit: environment.commit,
      node: environment.node,
      vite: environment.vite,
      platform: environment.platform,
    },
    compression: { ...COMPRESSION },
    files,
    totals: { categories, embedded },
    binary: binary
      ? {
          path: binary.path,
          bytes: binary.bytes,
          target: binary.target,
          profile: binary.profile,
          features: [...(binary.features ?? [])].toSorted(),
        }
      : null,
  };
}

const delta = (before, after) => ({ before, after, delta: after - before });

const deltas = (before, after) => ({
  bytes: delta(before?.bytes ?? 0, after?.bytes ?? 0),
  gzip: delta(before?.gzip ?? 0, after?.gzip ?? 0),
  brotli: delta(before?.brotli ?? 0, after?.brotli ?? 0),
});

/**
 * Compares two reports. Refuses (as `err`) when they did not measure the same thing: different
 * schema or compression settings, or binaries of different target, profile or features.
 */
export function compareReports(before, after) {
  if (before.schemaVersion !== after.schemaVersion) {
    return err(`schema versions differ: ${before.schemaVersion} vs ${after.schemaVersion}`);
  }
  const compression = ["gzipLevel", "brotliQuality", "brotliMode"].find(
    (key) => before.compression?.[key] !== after.compression?.[key],
  );
  if (compression) {
    return err(
      `compression settings differ (${compression}: ${before.compression?.[compression]} vs ${after.compression?.[compression]}); the reports are not comparable`,
    );
  }
  let binary = null;
  if (before.binary && after.binary) {
    for (const key of ["target", "profile"]) {
      if (before.binary[key] !== after.binary[key]) {
        return err(
          `binary ${key} differs: ${before.binary[key]} vs ${after.binary[key]}; a size comparison across ${key}s is not meaningful`,
        );
      }
    }
    if (JSON.stringify(before.binary.features) !== JSON.stringify(after.binary.features)) {
      return err(
        `binary features differ: [${before.binary.features}] vs [${after.binary.features}]`,
      );
    }
    binary = {
      target: after.binary.target,
      profile: after.binary.profile,
      features: after.binary.features,
      bytes: delta(before.binary.bytes, after.binary.bytes),
    };
  }
  const byPath = (report) => new Map(report.files.map((file) => [file.path, file]));
  const previous = byPath(before);
  const current = byPath(after);
  const paths = [...new Set([...previous.keys(), ...current.keys()])].toSorted();
  const files = paths.map((path) => {
    const entry = deltas(previous.get(path), current.get(path));
    entry.path = path;
    entry.category = (current.get(path) ?? previous.get(path)).category;
    entry.status = !previous.has(path) ? "added" : !current.has(path) ? "removed" : "kept";
    return entry;
  });
  const categories = Object.fromEntries(
    CATEGORIES.map((name) => [
      name,
      deltas(before.totals.categories[name], after.totals.categories[name]),
    ]),
  );
  return ok({
    commits: { before: before.environment.commit, after: after.environment.commit },
    files,
    categories,
    embedded: deltas(before.totals.embedded, after.totals.embedded),
    binary,
  });
}

function parseArguments(argv) {
  const options = { dist: "dist", out: null, baseline: null, binary: null };
  const binary = { path: null, target: null, profile: null, features: [] };
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const value = argv[index + 1];
    const take = () => {
      if (value === undefined) throw new Error(`${flag} needs a value`);
      index += 1;
      return value;
    };
    switch (flag) {
      case "--dist":
        options.dist = take();
        break;
      case "--out":
        options.out = take();
        break;
      case "--baseline":
        options.baseline = take();
        break;
      case "--binary":
        binary.path = take();
        break;
      case "--target":
        binary.target = take();
        break;
      case "--profile":
        binary.profile = take();
        break;
      case "--features":
        binary.features = take().split(",").filter(Boolean);
        break;
      default:
        throw new Error(`unknown argument ${flag}`);
    }
  }
  if (binary.path) {
    if (!binary.target || !binary.profile) {
      throw new Error("--binary needs --target <triple> and --profile <name>");
    }
    options.binary = binary;
  }
  return options;
}

const uiRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function environmentOf() {
  const git = (...args) => execFileSync("git", args, { cwd: uiRoot, encoding: "utf8" }).trim();
  const dirty = git("status", "--porcelain", "--", ".").length > 0;
  const vite = JSON.parse(readFileSync(join(uiRoot, "node_modules/vite/package.json"), "utf8"));
  return {
    commit: `${git("rev-parse", "HEAD")}${dirty ? "-dirty" : ""}`,
    node: process.version,
    vite: vite.version,
    platform: `${process.platform}-${process.arch}`,
  };
}

async function main(argv) {
  const options = parseArguments(argv);
  const dist = resolve(uiRoot, options.dist);
  let binary = null;
  if (options.binary) {
    const path = resolve(uiRoot, options.binary.path);
    const size = statSync(path).size;
    binary = {
      path: relative(resolve(uiRoot, ".."), path).split(sep).join("/"),
      bytes: size,
      target: options.binary.target,
      profile: options.binary.profile,
      features: options.binary.features,
    };
  }
  const report = await buildReport({ dist, environment: environmentOf(), binary });
  const summary = (name) => {
    const total = report.totals.categories[name];
    return `${name.padEnd(8)} ${String(total.files).padStart(3)} files ${String(total.bytes).padStart(9)} B  gzip ${String(total.gzip).padStart(8)} B  brotli ${String(total.brotli).padStart(8)} B`;
  };
  for (const name of CATEGORIES) console.log(summary(name));
  const { embedded } = report.totals;
  console.log(
    `embedded ${String(embedded.files).padStart(3)} files ${String(embedded.bytes).padStart(9)} B  gzip ${String(embedded.gzip).padStart(8)} B  brotli ${String(embedded.brotli).padStart(8)} B`,
  );
  if (binary)
    console.log(`binary   ${binary.path} ${binary.bytes} B (${binary.target}, ${binary.profile})`);
  if (options.out) {
    const out = resolve(uiRoot, options.out);
    mkdirSync(dirname(out), { recursive: true });
    writeFileSync(out, `${JSON.stringify(report, null, 2)}\n`);
    console.log(`wrote ${relative(uiRoot, out)}`);
  }
  if (options.baseline) {
    const baseline = JSON.parse(readFileSync(resolve(uiRoot, options.baseline), "utf8"));
    const comparison = compareReports(baseline, report);
    if (comparison.isErr()) {
      console.error(`not comparable: ${comparison.error}`);
      return 1;
    }
    const { embedded: total, binary: bin } = comparison.value;
    console.log(
      `vs ${comparison.value.commits.before.slice(0, 12)}: embedded ${total.bytes.delta >= 0 ? "+" : ""}${total.bytes.delta} B, gzip ${total.gzip.delta >= 0 ? "+" : ""}${total.gzip.delta} B, brotli ${total.brotli.delta >= 0 ? "+" : ""}${total.brotli.delta} B`,
    );
    for (const file of comparison.value.files) {
      if (file.bytes.delta !== 0 || file.status !== "kept") {
        console.log(
          `  ${file.status.padEnd(7)} ${file.category.padEnd(7)} ${file.path} ${file.bytes.delta >= 0 ? "+" : ""}${file.bytes.delta} B`,
        );
      }
    }
    if (bin) console.log(`  binary ${bin.bytes.delta >= 0 ? "+" : ""}${bin.bytes.delta} B`);
  }
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    (error) => {
      console.error(error.message);
      process.exitCode = 1;
    },
  );
}
