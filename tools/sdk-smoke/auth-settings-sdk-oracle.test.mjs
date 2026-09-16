import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { createHash } from "node:crypto";
import { bindLocalArtifact, requireLoopbackAuthHost, validateShadowResult } from "./auth-settings-sdk-oracle.mjs";

test("shadow rejects fixture success without real artifact and cleanup evidence", () => {
  assert.throws(
    () => validateShadowResult({ status: "completed", transport: "fixture", productionExecuted: false }),
    /fixture transport/,
  );
  assert.throws(
    () => validateShadowResult({ status: "completed", transport: "real-fireemu-artifact", productionExecuted: false, artifact: { sha256: "a".repeat(64) }, cleanup: { ownedResources: 1 }, comparison: { contract: "auth-settings-v1" } }),
    /owned resources/,
  );
});

test("artifact binding and loopback guard are mandatory", async () => {
  const root = await mkdtemp(join(tmpdir(), "auth-settings-sdk-"));
  const path = join(root, "fireemu");
  const bytes = Buffer.from("artifact fixture");
  await writeFile(path, bytes, { mode: 0o700 });
  await assert.rejects(bindLocalArtifact({ FIREEMU_ARTIFACT: path }), /SHA256/);
  const hash = createHash("sha256").update(bytes).digest("hex");
  assert.deepEqual(await bindLocalArtifact({ FIREEMU_ARTIFACT: path, FIREEMU_ARTIFACT_SHA256: hash }), { path, sha256: hash });
  assert.equal(requireLoopbackAuthHost("127.0.0.1:9099").port, "9099");
  assert.throws(() => requireLoopbackAuthHost("identitytoolkit.googleapis.com:443"), /local-only/);
  await rm(root, { recursive: true, force: true });
});
