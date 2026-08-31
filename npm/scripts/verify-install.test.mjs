import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(new URL("verify-install.mjs", import.meta.url), "utf8");

test("packaged verification invokes npm through Node without a command shell", () => {
  assert.doesNotMatch(source, /run\("npm",/);
  assert.doesNotMatch(source, /\bshell\b/);
  assert.doesNotMatch(source, /(?:run|spawnSync)\(bin,/);
  assert.match(source, /run\(\s*process\.execPath,\s*\[npmCli,/);
  assert.match(source, /run\(\s*process\.execPath,\s*\[launcher,/);
});
