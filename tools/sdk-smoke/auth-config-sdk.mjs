import assert from "node:assert/strict";

import { initializeApp } from "firebase/app";
import { connectAuthEmulator, getAuth, sendPasswordResetEmail, signOut } from "firebase/auth";
import { initializeApp as initializeAdminApp } from "firebase-admin/app";
import { getAuth as getAdminAuth } from "firebase-admin/auth";

const project = process.env.GOOGLE_CLOUD_PROJECT ?? "demo-app";
const authHost = process.env.FIREBASE_AUTH_EMULATOR_HOST ?? "127.0.0.1:9099";
const authUrl = new URL(`http://${authHost}`);
assert.ok(
  ["127.0.0.1", "localhost", "[::1]"].includes(authUrl.hostname),
  "local emulator required",
);

const app = initializeApp(
  { projectId: project, apiKey: "fake-api-key" },
  `auth-config-${process.pid}`,
);
const auth = getAuth(app);
connectAuthEmulator(auth, authUrl.origin, { disableWarnings: true });
const admin = getAdminAuth(
  initializeAdminApp({ projectId: project }, `auth-config-admin-${process.pid}`),
);
const email = `auth-config-sdk-unknown-${Date.now()}@example.test`;
const result = { sdkVersion: "firebase 12.18.0 / firebase-admin 14.3.0", project };

const privacyEnabled = (config) => config.emailPrivacyConfig?.enableImprovedEmailPrivacy === true;
const readUnknownReset = async () => {
  try {
    await sendPasswordResetEmail(auth, email);
    return { outcome: "silent-success" };
  } catch (error) {
    return { outcome: "error", code: error?.code ?? null };
  }
};

let original;
try {
  original = await admin.getProjectConfig();
  result.initial = { improvedEmailPrivacy: privacyEnabled(original) };

  const enabled = await admin.updateProjectConfig({
    emailPrivacyConfig: { enableImprovedEmailPrivacy: true },
  });
  result.enabled = {
    improvedEmailPrivacy: privacyEnabled(enabled),
    client: await readUnknownReset(),
  };
  assert.equal(result.enabled.improvedEmailPrivacy, true);
  assert.deepEqual(result.enabled.client, { outcome: "silent-success" });

  const disabled = await admin.updateProjectConfig({
    emailPrivacyConfig: { enableImprovedEmailPrivacy: false },
  });
  result.disabled = {
    improvedEmailPrivacy: privacyEnabled(disabled),
    client: await readUnknownReset(),
  };
  assert.equal(result.disabled.improvedEmailPrivacy, false);
  assert.deepEqual(result.disabled.client, { outcome: "error", code: "auth/user-not-found" });
  result.passed = true;
} finally {
  if (original) {
    await admin
      .updateProjectConfig({
        emailPrivacyConfig: { enableImprovedEmailPrivacy: privacyEnabled(original) },
      })
      .catch((error) => {
        result.restoreError = {
          code: error?.code ?? null,
          message: error?.message ?? String(error),
        };
      });
  }
  await signOut(auth).catch(() => {});
}

console.log(
  JSON.stringify(
    { transport: "firebase-auth-and-admin", production: "unobserved", ...result },
    null,
    2,
  ),
);
if (!result.passed || result.restoreError) process.exitCode = 1;
