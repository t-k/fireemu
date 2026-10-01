import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, readdirSync, symlinkSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { leftovers, runStatus, TOOL_ENTRIES } from "./selftest-tmpdir.mjs";
import { removeTree, tempDir } from "./test-tmpdir.mjs";

const SELFTEST_TMPDIR = fileURLToPath(new URL("./selftest-tmpdir.mjs", import.meta.url));
const TEST_TMPDIR = new URL("./test-tmpdir.mjs", import.meta.url).href;

/** A scratch root for these tests, removed when the file ends. */
const root = tempDir("test-tmpdir-root-");

/** Runs `node --test` on one generated test file with TMPDIR pointed at `dir`. */
function runTestFile(dir, body) {
  const file = join(root, `case-${readdirSync(root).length}.test.mjs`);
  writeFileSync(
    file,
    `import test from "node:test";\nimport { tempDir } from ${JSON.stringify(TEST_TMPDIR)};\n${body}\n`,
  );
  // A child `node --test` started from a test reports to its parent runner unless the parent's
  // context variable is dropped.
  const { NODE_TEST_CONTEXT: _context, ...env } = process.env;
  return spawnSync(process.execPath, ["--test", "--test-reporter=tap", file], {
    env: { ...env, TMPDIR: dir },
    encoding: "utf8",
  });
}

function emptyDir(name) {
  const dir = join(root, name);
  mkdirSync(dir);
  return dir;
}

test("a temp dir made in a passing or failing test, or at module level, is gone when the file ends", () => {
  const dir = emptyDir("lifetimes");
  const result = runTestFile(
    dir,
    `const top = tempDir("top-");
test("passes", () => { tempDir("passing-"); });
test("fails", () => { tempDir("failing-"); throw new Error("boom"); });
test("nested", async (t) => { await t.test("inner", () => { tempDir("inner-"); }); });
test("sees the module-level one until the end", async () => {
  const { existsSync } = await import("node:fs");
  if (!existsSync(top)) throw new Error("removed too early");
});`,
  );
  assert.equal(result.status, 1, "only the deliberately failing test fails");
  assert.match(result.stdout, /# pass 4/);
  assert.match(result.stdout, /# fail 1/);
  assert.deepEqual(readdirSync(dir), []);
});

test("a temp dir lives until its own test ends, so later steps of that test can use it", () => {
  const dir = emptyDir("own-test");
  const result = runTestFile(
    dir,
    `test("uses it after an await", async () => {
  const made = tempDir("kept-");
  await new Promise((resolve) => setTimeout(resolve, 20));
  const { existsSync } = await import("node:fs");
  if (!existsSync(made)) throw new Error("removed before the test ended");
});`,
  );
  assert.equal(result.status, 0, result.stdout);
  assert.deepEqual(readdirSync(dir), []);
});

test("removeTree removes read-only directories and does not follow symbolic links", () => {
  const target = tempDir("test-tmpdir-target-");
  writeFileSync(join(target, "kept"), "x");
  const tree = tempDir("test-tmpdir-tree-");
  mkdirSync(join(tree, "locked", "deeper"), { recursive: true });
  writeFileSync(join(tree, "locked", "deeper", "file"), "x");
  symlinkSync(target, join(tree, "link"));
  chmodSync(join(tree, "locked", "deeper"), 0o500);
  chmodSync(join(tree, "locked"), 0o500);
  removeTree(tree);
  assert.equal(existsSync(tree), false);
  assert.equal(existsSync(join(target, "kept")), true);
  removeTree(join(target, "missing"));
});

test("the selftest wrapper fails a passing run that leaves entries, and names them", () => {
  const dir = emptyDir("wrapper-leak");
  const result = spawnSync(
    process.execPath,
    [
      SELFTEST_TMPDIR,
      process.execPath,
      "-e",
      'require("node:fs").mkdirSync(require("node:path").join(require("node:os").tmpdir(), "leaked-x"))',
    ],
    { env: { ...process.env, TMPDIR: dir }, encoding: "utf8" },
  );
  assert.equal(result.status, 1);
  assert.match(result.stderr, /leaked-x/);
  assert.deepEqual(readdirSync(dir), [], "the private directory is removed");
});

test("the selftest wrapper gives the command a private TMPDIR and keeps its exit status", () => {
  const dir = emptyDir("wrapper-status");
  const seen = spawnSync(
    process.execPath,
    [SELFTEST_TMPDIR, process.execPath, "-e", "process.stdout.write(require('node:os').tmpdir())"],
    { env: { ...process.env, TMPDIR: dir }, encoding: "utf8" },
  );
  assert.equal(seen.status, 0, seen.stderr);
  assert.match(basename(seen.stdout), /^conformance-selftest-/);
  assert.equal(join(seen.stdout, ".."), dir);
  const failed = spawnSync(
    process.execPath,
    [SELFTEST_TMPDIR, process.execPath, "-e", "process.exit(3)"],
    {
      env: { ...process.env, TMPDIR: dir },
      encoding: "utf8",
    },
  );
  assert.equal(failed.status, 3);
  const usage = spawnSync(process.execPath, [SELFTEST_TMPDIR], { encoding: "utf8" });
  assert.equal(usage.status, 2);
  assert.deepEqual(readdirSync(dir), []);
});

test("leftovers ignores only the tool caches, and the run status keeps the command's", () => {
  assert.deepEqual(leftovers([]), []);
  assert.deepEqual(leftovers([...TOOL_ENTRIES]), []);
  assert.deepEqual(leftovers(["b", "node-compile-cache", "a", "node-compile-cache-x"]), [
    "a",
    "b",
    "node-compile-cache-x",
  ]);
  for (const [code, signal, left, expected] of [
    [0, null, [], 0],
    [0, null, ["x"], 1],
    [3, null, [], 3],
    [3, null, ["x"], 3],
    [null, "SIGTERM", [], 143],
    [null, "SIGINT", ["x"], 130],
    [null, "SIGHUP", [], 129],
    [null, "SIGKILL", [], 137],
  ]) {
    assert.equal(runStatus(code, signal, left), expected, `${code} ${signal} ${left}`);
  }
});
