// The runner modules an approved packet pins (every .mjs below conformance/src/storage-rules, hashed by
// pins.mjs) must not be touched by the formatter or the linter, and nothing else may hide behind the
// same lists: the ignore lists name exactly the pinned files, one by one.
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, posix } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const CONFORMANCE_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");
const RUNNER_DIR = "src/storage-rules";
const GENERIC = new Set(["node_modules", "fixtures", ".runs"]);

const config = (name) => JSON.parse(readFileSync(join(CONFORMANCE_DIR, name), "utf8"));

const pinnedModules = (relative = RUNNER_DIR) =>
  readdirSync(join(CONFORMANCE_DIR, relative), { withFileTypes: true }).flatMap((entry) => {
    const path = posix.join(relative, entry.name);
    if (entry.isDirectory()) return pinnedModules(path);
    return entry.isFile() && entry.name.endsWith(".mjs") ? [path] : [];
  });

test("the pinned set is found and is the one pins.mjs hashes", () => {
  const pinned = pinnedModules();
  assert.ok(pinned.length >= 50, `${pinned.length} pinned modules`);
  const pins = readFileSync(join(CONFORMANCE_DIR, RUNNER_DIR, "pins.mjs"), "utf8");
  assert.ok(
    pins.includes(`RUNNER_DIR = "conformance/${RUNNER_DIR}"`),
    "the runner directory moved",
  );
  assert.ok(pinned.includes(`${RUNNER_DIR}/pins.mjs`));
});

test("every pinned module is on the formatter's ignore list", () => {
  const ignored = new Set(config(".oxfmtrc.json").ignorePatterns);
  const missing = pinnedModules().filter((path) => !ignored.has(path));
  assert.deepEqual(
    missing,
    [],
    "a pinned module the formatter would rewrite changes the runner pin",
  );
});

test("the formatter's ignore list names no runner path that is not a pinned module", () => {
  const pinned = new Set(pinnedModules());
  const stray = config(".oxfmtrc.json").ignorePatterns.filter(
    (pattern) => pattern.startsWith(`${RUNNER_DIR}/`) && !pinned.has(pattern),
  );
  assert.deepEqual(stray, []);
});

test("the linter's ignore list hides only pinned modules and the generic directories", () => {
  const pinned = new Set(pinnedModules());
  const hidden = config(".oxlintrc.json").ignorePatterns.filter(
    (pattern) => !GENERIC.has(pattern) && !pinned.has(pattern),
  );
  assert.deepEqual(hidden, [], "an unpinned file is hidden from the linter");
});

test("no ignore entry is a glob over the runner directory", () => {
  for (const name of [".oxfmtrc.json", ".oxlintrc.json"]) {
    for (const pattern of config(name).ignorePatterns) {
      if (pattern.includes(RUNNER_DIR)) {
        assert.ok(!/[*?[\]{}]/.test(pattern), `${name}: ${pattern} is a glob`);
        assert.ok(pattern.endsWith(".mjs"), `${name}: ${pattern} is not one file`);
      }
    }
  }
});
