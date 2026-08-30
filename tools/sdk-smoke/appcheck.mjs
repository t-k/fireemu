// App Check smoke: the real Firebase Web SDK obtains a local App Check token through
// `initializeAppCheck` + `CustomProvider` and sends it to Firestore, Storage, Auth and a
// callable function (APPCHECK-SDK-WEB-1, specification section 10.3).
//
// Env: FIRESTORE_EMULATOR_HOST, FIREBASE_AUTH_EMULATOR_HOST, FIREBASE_STORAGE_EMULATOR_HOST,
//      FTD_APP_CHECK_EMULATOR_HOST, FTD_FUNCTIONS_HOST, GOOGLE_CLOUD_PROJECT.
// Run it against `--config tools/sdk-smoke/firebase-testd.appcheck.json`, whose `appCheck`
// section registers the app and the digest of the clearly fake debug secret below.
//
// `initializeAppCheck` needs no browser shims here: `CustomProvider` never touches
// `document`, `window` or `navigator` (only the reCAPTCHA providers do), and the SDK's token
// cache guards its `indexedDB` access with `isIndexedDBAvailable()`. What the SDK will not do
// is talk to the local exchange endpoint itself -- `@firebase/app-check` hard-codes the
// production `content-firebaseappcheck.googleapis.com` base URL -- so the provider below calls
// the daemon and hands the resulting JWT back.

import { initializeApp } from "firebase/app";
import { CustomProvider, getToken, initializeAppCheck } from "firebase/app-check";
import {
  connectAuthEmulator,
  createUserWithEmailAndPassword,
  getAuth,
} from "firebase/auth";
import {
  connectFirestoreEmulator,
  doc,
  getDoc,
  getFirestore,
  setDoc,
} from "firebase/firestore";
import {
  connectStorageEmulator,
  getBytes,
  getStorage,
  ref,
  uploadBytesResumable,
} from "firebase/storage";

const project = process.env.GOOGLE_CLOUD_PROJECT ?? "demo-app";
const fsHost = process.env.FIRESTORE_EMULATOR_HOST ?? "127.0.0.1:8080";
const authHost = process.env.FIREBASE_AUTH_EMULATOR_HOST ?? "127.0.0.1:9099";
const storageHost = process.env.FIREBASE_STORAGE_EMULATOR_HOST ?? "127.0.0.1:9199";
const appCheckHost = process.env.FTD_APP_CHECK_EMULATOR_HOST ?? authHost;
const functionsHost = process.env.FTD_FUNCTIONS_HOST ?? "127.0.0.1:5001";

// A clearly fake local debug secret. Its SHA-256 digest is what
// firebase-testd.appcheck.json registers; never reuse a production App Check debug token.
const APP_ID = "1:1234567890:web:local-test-app";
const DEBUG_SECRET = "deadbeef-0000-4000-8000-000000000001";

const results = [];
async function check(name, fn) {
  try {
    results.push({ name, ok: true, extra: await fn() });
  } catch (e) {
    results.push({ name, ok: false, extra: e.code ?? e.message ?? String(e) });
  }
}

/// Exchanges the registered debug secret for a locally signed App Check token.
async function exchangeDebugToken() {
  const url = `http://${appCheckHost}/v1/projects/${project}/apps/${encodeURIComponent(APP_ID)}:exchangeDebugToken`;
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ debugToken: DEBUG_SECRET, limitedUse: false }),
  });
  const body = await response.json();
  if (!response.ok) {
    throw new Error(`exchange failed: ${response.status} ${JSON.stringify(body)}`);
  }
  // The REST shape is `{"token": "<JWT>", "ttl": "3600s"}`; the SDK wants an absolute expiry.
  const ttlSeconds = Number.parseInt(String(body.ttl).replace(/s$/, ""), 10);
  return { token: body.token, expireTimeMillis: Date.now() + ttlSeconds * 1000 };
}

const app = initializeApp({ projectId: project, apiKey: "fake-api-key", appId: APP_ID });
const appCheck = initializeAppCheck(app, {
  provider: new CustomProvider({ getToken: exchangeDebugToken }),
  isTokenAutoRefreshEnabled: false,
});

const auth = getAuth(app);
connectAuthEmulator(auth, `http://${authHost}`, { disableWarnings: true });
const [fsHostname, fsPort] = fsHost.split(":");
const db = getFirestore(app);
connectFirestoreEmulator(db, fsHostname, Number(fsPort));
const [stHostname, stPort] = storageHost.split(":");
const storage = getStorage(app, `gs://${project}.appspot.com`);
connectStorageEmulator(storage, stHostname, Number(stPort));

await check("initializeAppCheck obtains a local token through CustomProvider", async () => {
  const result = await getToken(appCheck, false);
  if (!result.token) throw new Error("no token");
  const [, payload] = result.token.split(".");
  const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  if (claims.sub !== APP_ID) throw new Error(`sub is ${claims.sub}`);
  if (!claims.aud?.includes(`projects/${project}`)) {
    throw new Error(`aud is ${JSON.stringify(claims.aud)}`);
  }
  return { sub: claims.sub, iss: claims.iss };
});

// Auth: an end-user sign-up while App Check is configured. The Auth service is `unenforced`
// in the smoke config, so this checks that a configured provider does not break sign-up
// rather than that Auth refuses without one -- the refusal matrix is a Rust test.
const email = `appcheck-${Date.now()}@example.com`;
await check("Auth sign-up succeeds with an App Check provider configured", async () => {
  const credential = await createUserWithEmailAndPassword(auth, email, "s3cret-passphrase");
  return { uid: credential.user.uid };
});

await check("Firestore admits a write from an App Check enabled app", async () => {
  await setDoc(doc(db, "appcheck", "web"), { via: "web-sdk", at: Date.now() });
  const read = await getDoc(doc(db, "appcheck", "web"));
  if (!read.exists()) throw new Error("the document was not written");
  return read.data().via;
});

await check("Storage admits a resumable upload from an App Check enabled app", async () => {
  const object = ref(storage, `appcheck/web-${Date.now()}.txt`);
  // uploadBytesResumable is the initiation-plus-continuation path: it is the one that binds
  // the upload session to this app.
  const task = uploadBytesResumable(object, new TextEncoder().encode("hello app check"), {
    contentType: "text/plain",
  });
  await task;
  const bytes = await getBytes(object);
  return { size: bytes.byteLength };
});

// The callable path: the Web SDK's own Functions client attaches the App Check token, and the
// daemon verifies it before the runner ever decodes it.
await check("an enforceAppCheck callable receives the verified app", async () => {
  const { connectFunctionsEmulator, getFunctions, httpsCallable } = await import(
    "firebase/functions"
  );
  const [fnHostname, fnPort] = functionsHost.split(":");
  const functions = getFunctions(app);
  connectFunctionsEmulator(functions, fnHostname, Number(fnPort));
  const guarded = httpsCallable(functions, "guarded");
  const answer = await guarded({});
  if (answer.data.appId !== APP_ID) {
    throw new Error(`request.app.appId is ${JSON.stringify(answer.data.appId)}`);
  }
  return answer.data;
});

await check("an enforceAppCheck callable refuses a request without a token", async () => {
  const response = await fetch(`http://${functionsHost}/${project}/us-central1/guarded`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ data: {} }),
  });
  const body = await response.json();
  if (response.status !== 401 || body.error?.status !== "UNAUTHENTICATED") {
    throw new Error(`expected the callable 401 envelope, got ${response.status} ${JSON.stringify(body)}`);
  }
  return body.error.status;
});

await check("an enforceAppCheck callable refuses a forged token", async () => {
  const response = await fetch(`http://${functionsHost}/${project}/us-central1/guarded`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-firebase-appcheck": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.e30.",
    },
    body: JSON.stringify({ data: {} }),
  });
  if (response.status !== 401) {
    throw new Error(`expected 401, got ${response.status}`);
  }
  return response.status;
});

await check("an unenforced callable still runs without a token", async () => {
  const response = await fetch(`http://${functionsHost}/${project}/us-central1/add`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ data: { a: 2, b: 3 } }),
  });
  const body = await response.json();
  if (response.status !== 200 || body.result?.sum !== 5) {
    throw new Error(`expected the callable result envelope, got ${response.status} ${JSON.stringify(body)}`);
  }
  return body.result;
});

await check("Firestore refuses a write from an app that presents no token", async () => {
  // A bare REST write: no App Check field at all, so the enforced Firestore service denies it.
  const response = await fetch(
    `http://${fsHost}/v1/projects/${project}/databases/(default)/documents/appcheck?documentId=bare`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ fields: { via: { stringValue: "no token" } } }),
    },
  );
  const body = await response.json();
  if (response.status !== 403 || body.error?.status !== "PERMISSION_DENIED") {
    throw new Error(`expected 403 PERMISSION_DENIED, got ${response.status} ${JSON.stringify(body)}`);
  }
  return body.error.status;
});

console.log(JSON.stringify(results, null, 2));
const failed = results.filter((r) => !r.ok);
process.exit(failed.length === 0 ? 0 : 1);
