// The pinned Web SDK debug provider sends its proto field name to a local App Check exchange. Its production URL is redirected at the fetch boundary so this smoke never contacts Google.
// Run through fireemu exec with --config tools/sdk-smoke/fireemu.appcheck.json --only appcheck --http-port 0 --hub-port 0 --logging-port 0.

import assert from "node:assert/strict";

const appId = "1:1234567890:web:local-test-app";
const debugSecret = "deadbeef-0000-4000-8000-000000000001";
const project = process.env.GOOGLE_CLOUD_PROJECT ?? "demo-app";
const host = process.env.FIREEMU_APP_CHECK_EMULATOR_HOST;
assert.ok(host, "fireemu exec must set FIREEMU_APP_CHECK_EMULATOR_HOST");
const local = new URL(`http://${host}`);
assert.ok(["127.0.0.1", "localhost", "[::1]"].includes(local.hostname), "App Check host must be loopback");

globalThis.FIREBASE_APPCHECK_DEBUG_TOKEN = debugSecret;
const originalFetch = globalThis.fetch;
let exchangeCount = 0;
globalThis.fetch = (input, init) => {
  const requestUrl = new URL(typeof input === "string" ? input : input.url);
  assert.equal(requestUrl.origin, "https://content-firebaseappcheck.googleapis.com", "the SDK made an unexpected request");
  assert.equal(requestUrl.pathname, `/v1/projects/${project}/apps/${appId}:exchangeDebugToken`);
  const request = JSON.parse(init.body);
  assert.deepEqual(request, { debug_token: debugSecret });
  exchangeCount += 1;
  requestUrl.protocol = "http:";
  requestUrl.host = local.host;
  return originalFetch(requestUrl, init);
};

const { initializeApp } = await import("firebase/app");
const { CustomProvider, getToken, initializeAppCheck } = await import("firebase/app-check");
const app = initializeApp({ projectId: project, appId, apiKey: "fake-api-key" }, "app-check-debug-spelling-smoke");
const appCheck = initializeAppCheck(app, {
  provider: new CustomProvider({ getToken: async () => { throw new Error("the debug provider was not selected"); } }),
  isTokenAutoRefreshEnabled: false,
});
const { token } = await getToken(appCheck);
assert.equal(exchangeCount, 1);
const [, encodedClaims] = token.split(".");
const claims = JSON.parse(Buffer.from(encodedClaims, "base64url").toString("utf8"));
assert.equal(claims.sub, appId);
console.log("The Web SDK debug provider exchanged its proto field name for a local App Check token.");
