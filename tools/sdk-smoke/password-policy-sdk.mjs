import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { stat } from "node:fs/promises";

const loopbackHosts = new Set(["127.0.0.1", "localhost", "[::1]"]);

const passwordValidationStatusFields = [
  ["containsLowercaseCharacter", "containsLowercaseLetter"],
  ["containsUppercaseCharacter", "containsUppercaseLetter"],
  ["containsNumericCharacter", "containsNumericCharacter"],
  ["containsNonAlphanumericCharacter", "containsNonAlphanumericCharacter"],
  ["meetsMinPasswordLength", "meetsMinPasswordLength"],
  ["meetsMaxPasswordLength", "meetsMaxPasswordLength"],
];

export async function assertLocalArtifactBinding() {
  const artifact = process.env.FIREEMU_ARTIFACT;
  const expectedSha256 = process.env.FIREEMU_ARTIFACT_SHA256;
  assert.ok(artifact, "FIREEMU_ARTIFACT must identify the artifact under test");
  assert.match(artifact, /(^|\/)fireemu(\.exe)?$/, "artifact must be the fireemu binary");
  assert.ok(expectedSha256, "FIREEMU_ARTIFACT_SHA256 must bind the local artifact");
  assert.match(expectedSha256, /^[0-9a-f]{64}$/, "artifact hash must be sha256");
  const info = await stat(artifact);
  assert.ok(info.isFile(), "FIREEMU_ARTIFACT must be a regular file");
  const bytes = await readFile(artifact);
  assert.equal(createHash("sha256").update(bytes).digest("hex"), expectedSha256);
  return { artifact, artifactSha256: expectedSha256 };
}

export function mapPasswordValidationStatus(status) {
  assert.equal(typeof status, "object");
  assert.ok(status && !Array.isArray(status));
  assert.equal(typeof status.isValid, "boolean", "isValid");

  return Object.fromEntries(
    passwordValidationStatusFields.map(([collectorKey, sdkKey]) => {
      const value = status[sdkKey];
      assert.ok(value === undefined || typeof value === "boolean", sdkKey);
      return [collectorKey, value];
    }),
  );
}

function summarizePolicy(policy) {
  assert.equal(typeof policy, "object");
  assert.ok(policy && !Array.isArray(policy));
  assert.equal(typeof policy.enforcementState, "string");
  assert.equal(typeof policy.schemaVersion, "number");
  const options = policy.customStrengthOptions;
  assert.ok(options && typeof options === "object" && !Array.isArray(options));
  for (const key of [
    "minPasswordLength",
    "maxPasswordLength",
    "containsLowercaseCharacter",
    "containsUppercaseCharacter",
    "containsNumericCharacter",
    "containsNonAlphanumericCharacter",
  ]) {
    if (options[key] !== undefined) {
      assert.ok(["number", "boolean"].includes(typeof options[key]), key);
    }
  }
  return {
    schemaVersion: policy.schemaVersion,
    enforcementState: policy.enforcementState,
    forceUpgradeOnSignin: policy.forceUpgradeOnSignin,
    customStrengthOptions: { ...options },
    allowedNonAlphanumericCharacters: policy.allowedNonAlphanumericCharacters,
  };
}

function authHost() {
  const value = process.env.FIREBASE_AUTH_EMULATOR_HOST;
  assert.ok(value, "FIREBASE_AUTH_EMULATOR_HOST is required");
  const url = new URL(`http://${value}`);
  assert.ok(loopbackHosts.has(url.hostname), "password policy smoke is local-only");
  return url;
}

export async function runPasswordPolicySmoke() {
  const [{ initializeApp }, { connectAuthEmulator, getAuth, validatePassword }] =
    await Promise.all([import("firebase/app"), import("firebase/auth")]);
  const binding = await assertLocalArtifactBinding();
  const projectId = process.env.GOOGLE_CLOUD_PROJECT ?? "demo-app";
  const tenantId = process.env.PASSWORD_POLICY_TENANT_ID;
  const auth = getAuth(
    initializeApp(
      { projectId, apiKey: "fake-api-key" },
      `password-policy-${process.pid}-${Date.now()}`,
    ),
  );
  connectAuthEmulator(auth, authHost().origin, { disableWarnings: true });
  auth.tenantId = tenantId ?? null;

  const passwords = [
    ["weak", "minimum policy rejection/control"],
    ["Aa9!valid-policy-password", "all requirements control"],
  ];
  const checks = [];
  for (const [password, label] of passwords) {
    const result = await validatePassword(auth, password);
    const policy = summarizePolicy(result.passwordPolicy);
    const status = mapPasswordValidationStatus(result);
    checks.push({
      label,
      passwordLength: password.length,
      isValid: result.isValid,
      status,
      policy,
    });
  }

  assert.ok(checks[0].status);
  assert.ok(checks[1].status);
  return {
    production: "unobserved",
    transport: "firebase-js-auth-sdk",
    sdkVersion: "firebase 12.18.0",
    projectId,
    tenantId: tenantId ?? null,
    artifact: binding,
    checks,
    cacheControl: "same-auth-instance-then-fresh-instance is required for config-change comparisons",
    limitations: [
      "This runner does not mutate project or tenant configuration.",
      "Production response, policy inheritance, and Unicode backend length semantics remain unobserved.",
      "A successful SDK call is local artifact evidence and is not production compatibility evidence.",
    ],
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    console.log(JSON.stringify(await runPasswordPolicySmoke(), null, 2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
