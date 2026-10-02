// Storage quota smoke: the Web Storage SDK against a daemon whose storage.maxStoredBytes is
// 1,024 bytes (fireemu.storage-quota.json). An upload past the bound is answered 402, which the
// SDK reports at once as storage/quota-exceeded instead of retrying for its upload retry time
// (10 minutes by default for a 5xx). Prints one JSON result and exits non-zero on a mismatch.
//
//   fireemu exec --config tools/sdk-smoke/fireemu.storage-quota.json --project demo-app \
//     --only storage --storage-port 0 --http-port 0 --firestore-port 0 --hub-port 0 \
//     --ui-port 0 --logging-port 0 -- node tools/sdk-smoke/storage-quota.mjs
import { initializeApp } from "firebase/app";
import {
  getStorage,
  connectStorageEmulator,
  ref,
  uploadBytes,
  uploadBytesResumable,
} from "firebase/storage";

const project = process.env.GCLOUD_PROJECT ?? process.env.GOOGLE_CLOUD_PROJECT ?? "demo-app";
const [host, port] = (process.env.FIREBASE_STORAGE_EMULATOR_HOST ?? "127.0.0.1:9199").split(":");
// A bound far below the default ten minutes, so a regression (a retried 5xx) fails this
// script in seconds instead of hanging it.
const RETRY_BOUND_MS = 20_000;
const PROMPT_MS = 5_000;

const app = initializeApp({ projectId: project, storageBucket: `${project}.appspot.com`, apiKey: "fake-api-key" });
const storage = getStorage(app);
connectStorageEmulator(storage, host, Number(port));
storage.maxUploadRetryTime = RETRY_BOUND_MS;

async function refusal(name, upload) {
  const started = Date.now();
  try {
    await upload();
    return { name, ok: false, detail: "accepted past the bound" };
  } catch (error) {
    const ms = Date.now() - started;
    const ok = error.code === "storage/quota-exceeded" && ms < PROMPT_MS;
    return { name, ok, code: error.code, ms };
  }
}

const results = [];
await uploadBytes(ref(storage, "first.bin"), new Uint8Array(1_000));
results.push({ name: "within the bound", ok: true });
results.push(await refusal("uploadBytes past the bound", () =>
  uploadBytes(ref(storage, "second.bin"), new Uint8Array(100))));
results.push(await refusal("uploadBytesResumable past the bound", () =>
  new Promise((resolve, reject) => {
    uploadBytesResumable(ref(storage, "third.bin"), new Uint8Array(100)).on("state_changed", null, reject, resolve);
  })));
console.log(JSON.stringify(results));
process.exit(results.every((result) => result.ok) ? 0 : 1);
