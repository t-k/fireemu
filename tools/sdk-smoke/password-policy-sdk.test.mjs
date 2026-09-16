import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { assertLocalArtifactBinding } from "./password-policy-sdk.mjs";

test("password policy smoke refuses an unbound or non-fireemu artifact", async () => {
  const root = await mkdtemp(join(tmpdir(), "password-policy-sdk-"));
  const artifact = join(root, "fake-fireemu");
  const bytes = Buffer.from("fixture, not an executable\n");
  await writeFile(artifact, bytes, { mode: 0o700 });
  const old = {
    artifact: process.env.FIREEMU_ARTIFACT,
    hash: process.env.FIREEMU_ARTIFACT_SHA256,
  };
  try {
    process.env.FIREEMU_ARTIFACT = artifact;
    process.env.FIREEMU_ARTIFACT_SHA256 = createHash("sha256").update(bytes).digest("hex");
    await assert.rejects(assertLocalArtifactBinding(), /fireemu binary/);
    await mkdir(`${root}/fireemu`);
    process.env.FIREEMU_ARTIFACT = `${root}/fireemu`;
    await assert.rejects(assertLocalArtifactBinding(), /regular file/);
  } finally {
    if (old.artifact === undefined) delete process.env.FIREEMU_ARTIFACT;
    else process.env.FIREEMU_ARTIFACT = old.artifact;
    if (old.hash === undefined) delete process.env.FIREEMU_ARTIFACT_SHA256;
    else process.env.FIREEMU_ARTIFACT_SHA256 = old.hash;
    await rm(root, { recursive: true, force: true });
  }
});

test("password policy smoke output contains no password material", async () => {
  const source = await readFile(new URL("./password-policy-sdk.mjs", import.meta.url), "utf8");
  assert.match(source, /passwordLength/);
  assert.doesNotMatch(source, /console\.log\(password/);
  assert.match(source, /production: "unobserved"/);
});
