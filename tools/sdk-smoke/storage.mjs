// Storage smoke: firebase-admin (@google-cloud/storage JSON API) and the firebase client
// SDK (Firebase Storage protocol with X-Goog-Upload resumable uploads) with Storage Rules.
import { initializeApp as initializeAdminApp } from "firebase-admin/app";
import { getStorage as getAdminStorage } from "firebase-admin/storage";
import { initializeApp } from "firebase/app";
import { getAuth, connectAuthEmulator, createUserWithEmailAndPassword } from "firebase/auth";
import {
  getStorage,
  connectStorageEmulator,
  ref,
  uploadBytes,
  uploadBytesResumable,
  uploadString,
  getDownloadURL,
  getBytes,
  getMetadata,
  updateMetadata,
  listAll,
  deleteObject,
} from "firebase/storage";

const project = process.env.GOOGLE_CLOUD_PROJECT ?? "demo-app";
const storageHost = process.env.FIREBASE_STORAGE_EMULATOR_HOST ?? "127.0.0.1:9199";
const authHost = process.env.FIREBASE_AUTH_EMULATOR_HOST ?? "127.0.0.1:9099";
const bucketName = `${project}.appspot.com`;

const results = [];
async function check(name, fn) {
  try {
    results.push({ name, ok: true, extra: await fn() });
  } catch (e) {
    results.push({ name, ok: false, extra: e.code ?? e.message ?? String(e) });
  }
}
async function expectDenied(fn) {
  try {
    await fn();
  } catch (e) {
    if (e.code === "storage/unauthorized" || e.code === "storage/unauthenticated") return e.code;
    throw e;
  }
  throw new Error("expected storage/unauthorized");
}

const RULES = `
rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /users/{uid}/{file=**} {
      allow read, write: if request.auth != null && request.auth.uid == uid;
    }
    match /public/{file=**} { allow read: if true; }
  }
}`;
const put = await fetch(`http://${authHost}/v1/storage/rules`, {
  method: "PUT",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ source: RULES }),
});
if (!put.ok) throw new Error(`PUT /v1/storage/rules failed: ${put.status}`);

// ---- Admin SDK ----
process.env.STORAGE_EMULATOR_HOST = `http://${storageHost}`;
const adminApp = initializeAdminApp({ projectId: project, storageBucket: bucketName });
const bucket = getAdminStorage(adminApp).bucket();
await check("admin save + download", async () => {
  const file = bucket.file("public/hello.txt");
  await file.save(Buffer.from("hello storage"), { contentType: "text/plain", metadata: { metadata: { k: "v" } }, resumable: false });
  const [buf] = await file.download();
  const [meta] = await file.getMetadata();
  return { text: buf.toString(), size: meta.size, contentType: meta.contentType, custom: meta.metadata };
});
await check("admin resumable save", async () => {
  const file = bucket.file("public/big.bin");
  await file.save(Buffer.alloc(300_000, 7), { contentType: "application/octet-stream", resumable: true });
  const [meta] = await file.getMetadata();
  return meta.size;
});
await check("admin exists / getFiles / copy / delete", async () => {
  const [exists] = await bucket.file("public/hello.txt").exists();
  const [files] = await bucket.getFiles({ prefix: "public/" });
  await bucket.file("public/hello.txt").copy(bucket.file("public/hello-copy.txt"));
  await bucket.file("public/hello-copy.txt").delete();
  const [gone] = await bucket.file("public/hello-copy.txt").exists();
  return { exists, names: files.map((f) => f.name), gone };
});

// ---- Client SDK ----
const app = initializeApp({ projectId: project, apiKey: "fake-api-key", storageBucket: bucketName });
const auth = getAuth(app);
connectAuthEmulator(auth, `http://${authHost}`, { disableWarnings: true });
const storage = getStorage(app);
connectStorageEmulator(storage, storageHost.split(":")[0], Number(storageHost.split(":")[1]));

await check("client anonymous upload is denied", () =>
  expectDenied(() => uploadString(ref(storage, "users/nobody/x.txt"), "x")));
await check("client public read via download URL", async () => {
  const url = await getDownloadURL(ref(storage, "public/hello.txt"));
  const res = await fetch(url);
  return { status: res.status, text: await res.text() };
});
const cred = await createUserWithEmailAndPassword(auth, `st-${Date.now()}@example.com`, "password123");
const uid = cred.user.uid;
await check("client uploadBytes + getBytes + metadata", async () => {
  const r = ref(storage, `users/${uid}/notes/日本語.txt`);
  await uploadBytes(r, new TextEncoder().encode("konnichiwa"), { contentType: "text/plain", customMetadata: { mood: "good" } });
  const bytes = await getBytes(r);
  const meta = await getMetadata(r);
  await updateMetadata(r, { cacheControl: "private", customMetadata: { mood: "great" } });
  const meta2 = await getMetadata(r);
  return { text: new TextDecoder().decode(bytes), name: meta.name, fullPath: meta.fullPath, mood: meta2.customMetadata.mood, cache: meta2.cacheControl };
});
await check("client uploadBytesResumable", async () => {
  const r = ref(storage, `users/${uid}/big.bin`);
  const task = uploadBytesResumable(r, new Uint8Array(600_000), { contentType: "application/octet-stream" });
  const snapshot = await task;
  return { bytes: snapshot.totalBytes, state: snapshot.state };
});
await check("client listAll", async () => {
  const res = await listAll(ref(storage, `users/${uid}`));
  return { prefixes: res.prefixes.map((p) => p.name), items: res.items.map((i) => i.name) };
});
await check("client cannot read another user's folder", () =>
  expectDenied(() => getBytes(ref(storage, "users/other/secret.txt"))));
await check("client deleteObject", async () => {
  await deleteObject(ref(storage, `users/${uid}/big.bin`));
  try {
    await getMetadata(ref(storage, `users/${uid}/big.bin`));
    return "still there";
  } catch (e) {
    return e.code;
  }
});

console.log(JSON.stringify(results, null, 1));
process.exit(results.some((r) => !r.ok) ? 1 : 0);
