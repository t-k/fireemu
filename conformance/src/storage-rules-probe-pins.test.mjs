import assert from "node:assert/strict";
import { mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { probeCodeDigests, RUNNER_DIRS, SCHEMA_FILES } from "./storage-rules-probe/pins.mjs";
import { CODE_FILES, cleanup, scratchCode } from "./storage-rules-probe-support.mjs";

test("the runner pin covers every module under both directories, the schema pin exactly the probe and target modules", async (t) => {
  assert.deepEqual(RUNNER_DIRS, ["conformance/src/storage-rules", "conformance/src/storage-rules-probe"]);
  assert.deepEqual(SCHEMA_FILES, ["conformance/src/storage-rules-probe/probe.mjs", "conformance/src/storage-rules-probe/targets.mjs"]);
  const root = scratchCode();
  t.after(() => cleanup(root));
  const base = await probeCodeDigests(root);
  assert.match(base.runnerSha256, /^[0-9a-f]{64}$/);
  assert.deepEqual(await probeCodeDigests(root), base);
  for (const file of CODE_FILES) {
    writeFileSync(join(root, file), "changed\n");
    const changed = await probeCodeDigests(root);
    assert.notEqual(changed.runnerSha256, base.runnerSha256, file);
    assert.equal(changed.fixtureSchemaSha256 !== base.fixtureSchemaSha256, SCHEMA_FILES.includes(file), file);
    writeFileSync(join(root, file), `export const name = ${JSON.stringify(file)};\n`);
  }
  // A new module, in a nested directory of either runner directory, moves the runner pin; a file that is not a module, or another directory, does not.
  for (const path of ["conformance/src/storage-rules/new.mjs", "conformance/src/storage-rules-probe/deep/er/new.mjs"]) {
    mkdirSync(join(root, path, ".."), { recursive: true });
    writeFileSync(join(root, path), "x\n");
    assert.notEqual((await probeCodeDigests(root)).runnerSha256, base.runnerSha256, path);
    rmSync(join(root, path));
  }
  for (const path of ["conformance/src/storage-rules/notes.txt", "conformance/src/storage-rules-iam/other.mjs", "conformance/src/other.mjs"]) {
    mkdirSync(join(root, path, ".."), { recursive: true });
    writeFileSync(join(root, path), "x\n");
    assert.deepEqual(await probeCodeDigests(root), base, path);
  }
  assert.equal(Object.isFrozen(base), true);
});

test("a symbolic link, an empty runner directory and a missing schema file refuse the pin", async (t) => {
  const linked = scratchCode();
  t.after(() => cleanup(linked));
  symlinkSync(join(linked, CODE_FILES[0]), join(linked, "conformance/src/storage-rules/link.mjs"));
  await assert.rejects(probeCodeDigests(linked), /pin source refused/);
  const empty = scratchCode();
  t.after(() => cleanup(empty));
  rmSync(join(empty, "conformance/src/storage-rules-probe"), { recursive: true });
  mkdirSync(join(empty, "conformance/src/storage-rules-probe"));
  await assert.rejects(probeCodeDigests(empty), /pin source refused/);
  const missing = scratchCode();
  t.after(() => cleanup(missing));
  rmSync(join(missing, SCHEMA_FILES[0]));
  await assert.rejects(probeCodeDigests(missing));
});

test("a module larger than eight mebibytes refuses the pin", async (t) => {
  const root = scratchCode();
  t.after(() => cleanup(root));
  writeFileSync(join(root, "conformance/src/storage-rules/big.mjs"), Buffer.alloc(8 * 1024 * 1024 + 1, 0x20));
  await assert.rejects(probeCodeDigests(root), /pin source refused/);
  writeFileSync(join(root, "conformance/src/storage-rules/big.mjs"), Buffer.alloc(8 * 1024 * 1024, 0x20));
  assert.match((await probeCodeDigests(root)).runnerSha256, /^[0-9a-f]{64}$/);
});
