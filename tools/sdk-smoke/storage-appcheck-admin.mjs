// Admin Storage under Storage App Check enforcement: the real firebase-admin SDK (whatever
// version is installed, including firebase-admin 14.4 and later with @google-cloud/storage 8.1
// and later) uses the plain STORAGE_EMULATOR_HOST that `fireemu exec` exports and reaches Storage
// without an App Check token, resumable uploads included, while the Firebase Storage API and a
// browser-shaped JSON API request are still refused.
//
// Run it with the config that puts Storage in `enforced`:
//   fireemu exec --config tools/sdk-smoke/fireemu.appcheck.json --project demo-app --only storage \
//     --hub-port 0 -- node tools/sdk-smoke/storage-appcheck-admin.mjs
// `appCheck.storageServerRequests` is left at its default, "loopback".
import http from "node:http";

import { initializeApp } from "firebase-admin/app";
import { getStorage } from "firebase-admin/storage";

const project = process.env.GOOGLE_CLOUD_PROJECT ?? "demo-app";
const storageHost = process.env.FIREBASE_STORAGE_EMULATOR_HOST ?? "127.0.0.1:9199";
const bucketName = `${project}.appspot.com`;

const results = [];
async function check(name, fn) {
  try {
    results.push({ name, ok: true, extra: await fn() });
  } catch (e) {
    results.push({ name, ok: false, extra: e.code ?? e.message ?? String(e) });
  }
}

/// A request with explicit headers. `fetch` would do for most, but a request that must carry
/// browser evidence has to control `Origin` exactly, which the Fetch standard forbids a script.
function request(path, headers = {}) {
  const [hostname, port] = storageHost.split(":");
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname, port: Number(port), path, method: "GET", headers }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        let body;
        try {
          body = JSON.parse(text);
        } catch {
          body = text;
        }
        resolve({ status: res.statusCode, body });
      });
    });
    req.on("error", reject);
    req.end();
  });
}

const endpoint = process.env.STORAGE_EMULATOR_HOST;
await check("exec exports a plain STORAGE_EMULATOR_HOST without credentials", async () => {
  if (!endpoint) throw new Error("STORAGE_EMULATOR_HOST is not set");
  const url = new URL(endpoint);
  if (url.username || url.password) throw new Error(`the endpoint embeds credentials: ${url.origin}`);
  return url.origin;
});

const adminApp = initializeApp({ projectId: project, storageBucket: bucketName });
const bucket = getStorage(adminApp).bucket();
const stamp = Date.now();

for (const resumable of [true, false]) {
  const file = bucket.file(`appcheck-admin/${resumable ? "resumable" : "simple"}-${stamp}.txt`);
  await check(`admin save (resumable: ${resumable}) and download under enforcement`, async () => {
    const data = `hello ${resumable ? "resumable" : "simple"}`;
    await file.save(Buffer.from(data), { contentType: "text/plain", resumable });
    const [bytes] = await file.download();
    if (bytes.toString() !== data) throw new Error(`downloaded ${JSON.stringify(bytes.toString())}`);
    const [metadata] = await file.getMetadata();
    return { size: metadata.size };
  });
}

await check("admin lists, checks and deletes objects under enforcement", async () => {
  const [files] = await bucket.getFiles({ prefix: "appcheck-admin/" });
  const names = files.map((file) => file.name);
  if (names.length < 2) throw new Error(`the list is ${JSON.stringify(names)}`);
  const [exists] = await files[0].exists();
  if (!exists) throw new Error("exists() is false for a listed object");
  await Promise.all(files.map((file) => file.delete()));
  const [after] = await bucket.getFiles({ prefix: "appcheck-admin/" });
  if (after.length !== 0) throw new Error(`${after.length} objects remain`);
  return { deleted: names.length };
});

await check("the Firebase Storage API without a token is still refused", async () => {
  const { status, body } = await request(`/v0/b/${bucketName}/o`);
  if (status !== 403 || body.error?.reason !== "APP_CHECK_REQUIRED") {
    throw new Error(`expected 403 APP_CHECK_REQUIRED, got ${status} ${JSON.stringify(body)}`);
  }
  return status;
});

await check("a JSON API request that carries an Origin header is still refused", async () => {
  const { status, body } = await request(`/storage/v1/b/${bucketName}/o`, {
    origin: "http://localhost:5173",
  });
  if (status !== 403 || body.error?.reason !== "APP_CHECK_REQUIRED") {
    throw new Error(`expected 403 APP_CHECK_REQUIRED, got ${status} ${JSON.stringify(body)}`);
  }
  return status;
});

await check("a JSON API request that carries Fetch Metadata is still refused", async () => {
  const { status } = await request(`/storage/v1/b/${bucketName}/o`, {
    "sec-fetch-site": "cross-site",
    "sec-fetch-mode": "cors",
    "sec-fetch-dest": "empty",
  });
  if (status !== 403) throw new Error(`expected 403, got ${status}`);
  return status;
});

console.log(JSON.stringify(results, null, 2));
process.exit(results.every((r) => r.ok) ? 0 : 1);
