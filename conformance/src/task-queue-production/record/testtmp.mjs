// Test support: temporary directories the tests make are removed when the test file ends.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after } from "node:test";

const made = [];
after(() => {
  for (const directory of made.splice(0)) rmSync(directory, { recursive: true, force: true });
});

export const tempDir = (prefix) => {
  const directory = mkdtempSync(join(tmpdir(), prefix));
  made.push(directory);
  return directory;
};
