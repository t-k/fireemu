import assert from "node:assert/strict";
import { mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { releaseCodeDigests, RUNNER_DIRS, SCHEMA_FILES } from "./storage-rules-release/pins.mjs";
import { CODE_FILES, cleanup, scratchCode } from "./storage-rules-release-support.mjs";

test("the runner pin covers every module under both directories, the schema pin exactly the release and target modules", async (t) => {
  assert.deepEqual(RUNNER_DIRS, ["conformance/src/storage-rules", "conformance/src/storage-rules-release"]);
  assert.deepEqual(SCHEMA_FILES, ["conformance/src/storage-rules-release/release.mjs", "conformance/src/storage-rules-release/targets.mjs"]);
  const root = scratchCode();
  t.after(() => cleanup(root));
  const base = await releaseCodeDigests(root);
  assert.match(base.runnerSha256, /^[0-9a-f]{64}$/);
  assert.deepEqual(await releaseCodeDigests(root), base);
  for (const file of CODE_FILES) {
    writeFileSync(join(root, file), "changed\n");
    const changed = await releaseCodeDigests(root);
    assert.notEqual(changed.runnerSha256, base.runnerSha256, file);
    assert.equal(changed.fixtureSchemaSha256 !== base.fixtureSchemaSha256, SCHEMA_FILES.includes(file), file);
    writeFileSync(join(root, file), `export const name = ${JSON.stringify(file)};\n`);
  }
  // A new module, in a nested directory of either runner directory, moves the runner pin; a file that is not a module, or another directory, does not.
  for (const path of ["conformance/src/storage-rules/new.mjs", "conformance/src/storage-rules-release/deep/er/new.mjs"]) {
    mkdirSync(join(root, path, ".."), { recursive: true });
    writeFileSync(join(root, path), "x\n");
    assert.notEqual((await releaseCodeDigests(root)).runnerSha256, base.runnerSha256, path);
    rmSync(join(root, path));
  }
  for (const path of ["conformance/src/storage-rules/notes.txt", "conformance/src/storage-rules-iam/other.mjs", "conformance/src/other.mjs"]) {
    mkdirSync(join(root, path, ".."), { recursive: true });
    writeFileSync(join(root, path), "x\n");
    assert.deepEqual(await releaseCodeDigests(root), base, path);
  }
  assert.equal(Object.isFrozen(base), true);
});

test("a symbolic link, an empty runner directory and a missing schema file refuse the pin", async (t) => {
  const linked = scratchCode();
  t.after(() => cleanup(linked));
  symlinkSync(join(linked, CODE_FILES[0]), join(linked, "conformance/src/storage-rules/link.mjs"));
  await assert.rejects(releaseCodeDigests(linked), /pin source refused/);
  const empty = scratchCode();
  t.after(() => cleanup(empty));
  rmSync(join(empty, "conformance/src/storage-rules-release"), { recursive: true });
  mkdirSync(join(empty, "conformance/src/storage-rules-release"));
  await assert.rejects(releaseCodeDigests(empty), /pin source refused/);
  const missing = scratchCode();
  t.after(() => cleanup(missing));
  rmSync(join(missing, SCHEMA_FILES[0]));
  await assert.rejects(releaseCodeDigests(missing));
});

test("a module larger than eight mebibytes refuses the pin", async (t) => {
  const root = scratchCode();
  t.after(() => cleanup(root));
  writeFileSync(join(root, "conformance/src/storage-rules/big.mjs"), Buffer.alloc(8 * 1024 * 1024 + 1, 0x20));
  await assert.rejects(releaseCodeDigests(root), /pin source refused/);
  writeFileSync(join(root, "conformance/src/storage-rules/big.mjs"), Buffer.alloc(8 * 1024 * 1024, 0x20));
  assert.match((await releaseCodeDigests(root)).runnerSha256, /^[0-9a-f]{64}$/);
});
