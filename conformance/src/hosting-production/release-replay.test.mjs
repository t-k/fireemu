import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { exitCodeOf, failedPaths, optionValue, usageOk } from "./release-replay.mjs";

const document = (MISMATCH, UNKNOWN) => ({
  summary: { MATCH: 201 - MISMATCH - UNKNOWN, MISMATCH, UNKNOWN },
});

test("the exit code is nonzero when any exported document has a mismatch or an unknown row", () => {
  assert.deepEqual(failedPaths({ documents: { a: document(0, 0), b: document(0, 0) } }), []);
  assert.deepEqual(failedPaths({ documents: { a: document(1, 0), b: document(0, 0) } }), ["a"]);
  assert.deepEqual(failedPaths({ documents: { a: document(0, 0), b: document(0, 2) } }), ["b"]);
  assert.deepEqual(failedPaths({ documents: { a: document(3, 0), b: document(0, 2) } }), [
    "a",
    "b",
  ]);
});

test("the process exits 0 for a clean replay and 1 for any failing document", () => {
  assert.equal(exitCodeOf({ documents: { a: document(0, 0) } }), 0);
  assert.equal(exitCodeOf({ documents: {} }), 0);
  assert.equal(exitCodeOf({ documents: { a: document(0, 0), b: document(1, 0) } }), 1);
  assert.equal(exitCodeOf({ documents: { a: document(0, 1) } }), 1);
});

test("the command line needs the local mode, a binary and a new export file", () => {
  assert.equal(usageOk(["local", "--fireemu", "bin", "--export", "out.json"]), true);
  assert.equal(usageOk(["local", "--export", "out.json", "--fireemu", "bin"]), true);
  assert.equal(usageOk(["export", "--fireemu", "bin", "--export", "out.json"]), false);
  assert.equal(usageOk(["local", "--fireemu", "bin"]), false);
  assert.equal(usageOk(["local", "--export", "out.json"]), false);
  assert.equal(usageOk([]), false);
  // a flag followed by another flag has no value
  assert.equal(usageOk(["local", "--fireemu", "--export", "out.json"]), false);
  assert.equal(usageOk(["local", "--fireemu", "bin", "--export"]), false);
  assert.equal(optionValue(["local", "--export", "x"], "--fireemu"), undefined);
  assert.equal(optionValue(["local", "--export", "x"], "--export"), "x");
});

test("run as a program, a missing argument stops it before it starts anything", () => {
  const script = fileURLToPath(new URL("./release-replay.mjs", import.meta.url));
  const result = spawnSync(process.execPath, [script, "local"], { encoding: "utf8" });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /usage: release-replay\.mjs local --fireemu/);
});
