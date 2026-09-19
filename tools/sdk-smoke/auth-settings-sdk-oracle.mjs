import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";

const LOOPBACK = new Set(["127.0.0.1", "localhost", "[::1]"]);

export async function bindLocalArtifact(env = process.env) {
  const artifact = env.FIREEMU_ARTIFACT;
  const expected = env.FIREEMU_ARTIFACT_SHA256;
  assert.ok(artifact, "FIREEMU_ARTIFACT is required");
  assert.match(artifact, /(^|\/)fireemu(\.exe)?$/, "artifact must be fireemu");
  assert.match(expected ?? "", /^[0-9a-f]{64}$/, "FIREEMU_ARTIFACT_SHA256 is required");
  assert.ok((await stat(artifact)).isFile(), "artifact must be a regular file");
  const actual = createHash("sha256").update(await readFile(artifact)).digest("hex");
  assert.equal(actual, expected, "artifact digest mismatch");
  return { path: artifact, sha256: actual };
}

export function requireLoopbackAuthHost(value) {
  assert.ok(value, "FIREBASE_AUTH_EMULATOR_HOST is required");
  const url = new URL(`http://${value}`);
  assert.ok(LOOPBACK.has(url.hostname), "Auth settings shadow is local-only");
  return url;
}

export function validateShadowResult(result) {
  assert.equal(result?.productionExecuted, false, "shadow must not be production traffic");
  assert.equal(result?.status, "completed", "fixture success is not a completed shadow");
  assert.equal(result?.transport, "real-fireemu-artifact", "fixture transport is not evidence");
  assert.equal(typeof result?.artifact?.sha256, "string");
  assert.equal(result?.cleanup?.ownedResources, 0, "owned resources must be reclaimed");
  assert.equal(result?.comparison?.contract, "auth-settings-v1");
  return result;
}

export function shadowPlan() {
  return {
    status: "WAITING_ORACLE",
    productionExecuted: false,
    sdk: { firebase: "12.18.0", firebaseAdmin: "14.3.0", node: ">=20" },
    safetyClass: "AUTH_ACCOUNT",
    cases: [
      "account-linking-duplicate-email",
      "client-permission-and-email-privacy",
      "blocking-selection-and-token-forwarding",
      "signup-quota-boundary",
    ],
    comparator: "auth-settings-v1",
    ownerInputs: ["owner identity", "permission reference", "project/tenant", "window", "fresh nonce", "recovery owner"],
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    if (process.env.AUTH_SETTINGS_LIVE === "1") {
      const artifact = await bindLocalArtifact();
      requireLoopbackAuthHost(process.env.FIREBASE_AUTH_EMULATOR_HOST);
      console.log(JSON.stringify({ ...shadowPlan(), artifact }, null, 2));
    } else {
      console.log(JSON.stringify(shadowPlan(), null, 2));
    }
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
