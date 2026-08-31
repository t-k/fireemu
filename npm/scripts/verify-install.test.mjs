import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";

const source = readFileSync(new URL("verify-install.mjs", import.meta.url), "utf8");

test("packaged verification invokes npm through Node without a command shell", () => {
  assert.doesNotMatch(source, /run\("npm",/);
  assert.doesNotMatch(source, /\bshell\b/);
  assert.doesNotMatch(source, /(?:run|spawnSync)\(bin,/);
  assert.match(source, /run\(\s*process\.execPath,\s*\[npmCli,/);
  assert.match(source, /run\(\s*process\.execPath,\s*\[launcher,/);
});

test("a missing distribution path cannot inject terminal controls into diagnostics", () => {
  const script = fileURLToPath(new URL("verify-install.mjs", import.meta.url));
  const result = spawnSync(process.execPath, [script, "--dist", "missing-\u{1b}[31m"], {
    encoding: "utf8",
  });
  assert.equal(result.status, 2);
  assert.equal(result.stderr.includes("\u{1b}"), false);
  assert.equal(result.stderr.includes("\\u{1b}"), true);
});
