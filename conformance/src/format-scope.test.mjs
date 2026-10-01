import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";

const conformance = join(import.meta.dirname, "..");
const formatter = join(conformance, "node_modules/oxfmt/bin/oxfmt");
const config = readFileSync(join(conformance, ".oxfmtrc.json"), "utf8");
const packageJson = JSON.parse(readFileSync(join(conformance, "package.json"), "utf8"));

// Recorded evidence and raw or frozen harnesses need exact exclusions; directory and JSON globs would also hide future formatting mistakes.
const boundPaths = [
  "auth-action-production.json",
  "auth-config-sdk-production.json",
  "auth-credential-production.json",
  "auth-mfa-production.json",
  "fs-config-lifecycle-production.json",
  "fs-data-write-list-production.json",
  "fs-data-write-production-supplements/bracket-fb886aa8eed899746ecf607b.json",
  "fs-data-write-production-supplements/delta-v3-a14f265fea575003423c7ebd.json",
  "fs-data-write-production-supplements/followup-b0aeefc97b4c48765db4a9a1-indexed.json",
  "fs-data-write-production-supplements/followup-b0aeefc97b4c48765db4a9a1-webchannel.json",
  "fs-data-write-production-supplements/partial-7bfd51026a2ac56617d81504.json",
  "fs-rules-production.json",
  "src/fs-config-lifecycle/harness.mjs",
  "auth-federation-production.json",
  "auth-federation-saml-production.json",
  "auth-fs-cross-stage2-production.json",
  "auth-tenant-blocking-production.json",
  "src/auth-federation/corpus-saml.mjs",
  "src/auth-federation/corpus.mjs",
  "src/auth-federation/saml.mjs",
  "src/auth-fs-cross/stage2-orchestrator.mjs",
];
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

function fixture(run) {
  const root = mkdtempSync(join(tmpdir(), "fireemu-format-scope-"));
  try {
    writeFileSync(join(root, ".oxfmtrc.json"), config);
    for (const path of boundPaths) {
      const target = join(root, path);
      mkdirSync(dirname(target), { recursive: true });
      writeFileSync(target, path.endsWith(".json") ? '{ "bound" :true}' : "export  const bound=1");
    }
    run(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

function check(root) {
  assert.equal(packageJson.scripts["fmt:check"], "oxfmt --check .");
  const result = spawnSync(process.execPath, [formatter, "--check", "."], {
    cwd: root,
    encoding: "utf8",
    timeout: 30_000,
  });
  assert.ifError(result.error);
  assert.equal(result.signal, null);
  return { status: result.status, log: result.stdout + result.stderr };
}

test("format check preserves individually excluded bound evidence bytes", () => {
  fixture((root) => {
    const before = boundPaths.map((path) => sha256(readFileSync(join(root, path))));
    const result = check(root);
    assert.equal(result.status, 0, result.log);
    assert.deepEqual(
      boundPaths.map((path) => sha256(readFileSync(join(root, path)))),
      before,
    );
  });
});

for (const path of [
  "src/new-format-scope-fixture.mjs",
  "src/auth-federation/new-format-scope-fixture.mjs",
  "src/fs-config-lifecycle/new-format-scope-fixture.mjs",
  "new-format-scope-fixture.json",
]) {
  test(`format check refuses a new badly formatted ordinary file: ${path}`, () => {
    fixture((root) => {
      const target = join(root, path);
      mkdirSync(dirname(target), { recursive: true });
      const json = path.endsWith(".json");
      writeFileSync(target, json ? '{"value":1}\n' : "export  const value=1\n");
      const refused = check(root);
      assert.equal(refused.status, 1, refused.log);
      assert.ok(refused.log.includes(path), refused.log);
      writeFileSync(target, json ? '{\n  "value": 1\n}\n' : "export const value = 1;\n");
      const accepted = check(root);
      assert.equal(accepted.status, 0, accepted.log);
    });
  });
}
