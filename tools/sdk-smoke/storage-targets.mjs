// Real Firebase Web Storage SDK coverage for bucket-specific rules resolved from deploy targets.
import { initializeApp } from "firebase/app";
import {
  connectStorageEmulator,
  getStorage,
  ref,
  uploadString,
} from "firebase/storage";

const project = process.env.GCLOUD_PROJECT ?? "demo-storage-targets";
const storageHost = process.env.FIREBASE_STORAGE_EMULATOR_HOST ?? "127.0.0.1:9199";
const [host, portText] = storageHost.split(":");
const port = Number(portText);
const app = initializeApp({ projectId: project, apiKey: "fake-api-key" });

function storageFor(bucket) {
  const storage = getStorage(app, `gs://${bucket}`);
  connectStorageEmulator(storage, host, port);
  return storage;
}

async function expectDenied(bucket, name) {
  try {
    await uploadString(ref(storageFor(bucket), name), "denied");
  } catch (error) {
    if (error?.code === "storage/unauthorized") return;
    throw error;
  }
  throw new Error(`${bucket} unexpectedly accepted ${name}`);
}

await uploadString(ref(storageFor("public.example.test"), "allowed.txt"), "allowed");
await expectDenied("private.example.test", "private.txt");
await expectDenied("unknown.example.test", "unknown.txt");

console.log(
  JSON.stringify({
    ok: true,
    checks: ["target allow", "target deny", "unknown bucket deny"],
  }),
);
