import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import test from "node:test";

test("standalone original lineage assertions preserve production TLS argv policy", () => {
  const child = spawnSync(
    process.execPath,
    [fileURLToPath(new URL("./storage-object-runtime-owner-lineage-cases.mjs", import.meta.url))],
    { encoding: "utf8", env: { PATH: process.env.PATH, TMPDIR: tmpdir() }, timeout: 10000 },
  );
  assert.equal(child.error, undefined);
  assert.equal(child.signal, null);
  assert.equal(child.status, 0, child.stdout + child.stderr);
  assert.match(child.stdout, /^(?:#|ℹ) tests 8\r?$/m);
  assert.match(child.stdout, /^(?:#|ℹ) pass 8\r?$/m);
  for (const label of ["fail", "cancelled", "skipped", "todo"]) {
    assert.match(child.stdout, new RegExp(`^(?:#|ℹ) ${label} 0\\r?$`, "m"));
  }
});
