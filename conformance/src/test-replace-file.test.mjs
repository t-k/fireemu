// Self-tests of the replace-file helper: the replacement must be another file, on every filesystem.
import assert from "node:assert/strict";
import { lstatSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { replaceFile, replaceFileSync } from "./test-replace-file.mjs";

const scratch = (t) => {
  const directory = mkdtempSync(join(tmpdir(), "replace-file-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  return directory;
};

for (const [name, replace] of [
  ["sync", async (...args) => replaceFileSync(...args)],
  ["async", replaceFile],
]) {
  test(`${name}: the replacement is another file with the new content, and the old name is kept`, async (t) => {
    const directory = scratch(t);
    const path = join(directory, "lock.json");
    writeFileSync(path, "same text", { mode: 0o600 });
    const before = lstatSync(path);
    await replace(path, "same text", { mode: 0o600 });
    const after = lstatSync(path);
    assert.notEqual(after.ino, before.ino, "a replaced file has an inode of its own");
    assert.equal(readFileSync(path, "utf8"), "same text");
    assert.equal(after.mode & 0o777, 0o600);
    assert.deepEqual(readdirSync(directory), ["lock.json"], "no temporary file is left behind");
  });

  test(`${name}: different content replaces the old content`, async (t) => {
    const directory = scratch(t);
    const path = join(directory, "lock.json");
    writeFileSync(path, "old");
    await replace(path, "new");
    assert.equal(readFileSync(path, "utf8"), "new");
  });

  test(`${name}: replacing a file that does not exist creates it`, async (t) => {
    const directory = scratch(t);
    const path = join(directory, "absent.json");
    await replace(path, "created");
    assert.equal(readFileSync(path, "utf8"), "created");
    assert.deepEqual(readdirSync(directory), ["absent.json"]);
  });
}
