// materializeLocal copies the fixture into a scratch root. The release job installs the fixture's own node_modules (npm ci) before
// the replay, so the copy must not carry that directory along: the symlink to the installation would then fail with EEXIST.
import assert from "node:assert/strict";
import { lstatSync, mkdirSync, readlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { materializeLocal } from "./local.mjs";
import { tempDir } from "./record/testtmp.mjs";

function fixtureSource({ installed }) {
  const source = join(tempDir("tq-source-"), "functions");
  mkdirSync(source, { recursive: true });
  writeFileSync(join(source, "index.js"), "module.exports = {};\n");
  if (installed) {
    mkdirSync(join(source, "node_modules/firebase-functions"), { recursive: true });
    writeFileSync(join(source, "node_modules/firebase-functions/package.json"), "{}\n");
  }
  return source;
}

test("an installed fixture is linked, not copied, into the scratch root", () => {
  const source = fixtureSource({ installed: true });
  const root = tempDir("tq-root-");
  materializeLocal(root, source);
  const link = join(root, "functions/node_modules");
  assert.ok(lstatSync(link).isSymbolicLink());
  assert.equal(readlinkSync(link), join(source, "node_modules"));
  assert.ok(lstatSync(join(root, "functions/index.js")).isFile());
});

test("a fixture without its own installation links the harness's node_modules", () => {
  const source = fixtureSource({ installed: false });
  const root = tempDir("tq-root-");
  materializeLocal(root, source);
  const link = join(root, "functions/node_modules");
  assert.ok(lstatSync(link).isSymbolicLink());
  assert.match(readlinkSync(link), /conformance[/\\]node_modules$/);
});
