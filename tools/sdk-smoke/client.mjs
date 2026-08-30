// Client SDK smoke: the real `firebase` JS SDK (Auth + Firestore over gRPC) against
// fireemu with Security Rules loaded through the control API.
//
// Env: FIRESTORE_EMULATOR_HOST, FIREBASE_AUTH_EMULATOR_HOST, GOOGLE_CLOUD_PROJECT (demo-app)
import { initializeApp } from "firebase/app";
import {
  getAuth,
  connectAuthEmulator,
  createUserWithEmailAndPassword,
  signOut,
} from "firebase/auth";
import {
  getFirestore,
  connectFirestoreEmulator,
  doc,
  setDoc,
  getDoc,
  getDocs,
  collection,
  query,
  where,
  deleteDoc,
} from "firebase/firestore";

const project = process.env.GOOGLE_CLOUD_PROJECT ?? "demo-app";
const fsHost = process.env.FIRESTORE_EMULATOR_HOST ?? "127.0.0.1:8080";
const authHost = process.env.FIREBASE_AUTH_EMULATOR_HOST ?? "127.0.0.1:9099";

const RULES = `
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /profiles/{uid} {
      allow read, write: if request.auth != null && request.auth.uid == uid;
    }
    match /notes/{id} {
      allow read: if request.auth != null && resource.data.owner == request.auth.uid;
      allow create: if request.auth != null && request.resource.data.owner == request.auth.uid;
    }
    match /public/{id} {
      allow read: if true;
    }
  }
}
`;

const results = [];
async function check(name, fn) {
  try {
    const extra = await fn();
    results.push({ name, ok: true, extra });
  } catch (e) {
    results.push({ name, ok: false, extra: e.code ?? e.message });
  }
}
async function expectDenied(fn) {
  try {
    await fn();
  } catch (e) {
    if (e.code === "permission-denied") return "permission-denied";
    throw e;
  }
  throw new Error("expected permission-denied");
}

const control = `http://${authHost}/v1/rules`;
const put = await fetch(control, {
  method: "PUT",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ source: RULES }),
});
if (!put.ok) throw new Error(`PUT /v1/rules failed: ${put.status} ${await put.text()}`);

const app = initializeApp({ projectId: project, apiKey: "fake-api-key" });
const auth = getAuth(app);
connectAuthEmulator(auth, `http://${authHost}`, { disableWarnings: true });
const db = getFirestore(app);
connectFirestoreEmulator(db, fsHost.split(":")[0], Number(fsHost.split(":")[1]));

await check("anonymous read of a protected doc is denied", () =>
  expectDenied(() => getDoc(doc(db, "profiles/nobody"))));
await check("anonymous read of a public collection", async () => {
  const snap = await getDocs(collection(db, "public"));
  return snap.size;
});

const alice = await createUserWithEmailAndPassword(auth, "alice@example.com", "password123");
const aliceUid = alice.user.uid;
await check("signed-in user writes own profile", async () => {
  await setDoc(doc(db, `profiles/${aliceUid}`), { name: "Alice" });
  return (await getDoc(doc(db, `profiles/${aliceUid}`))).data();
});
await check("signed-in user cannot write another profile", () =>
  expectDenied(() => setDoc(doc(db, "profiles/someone-else"), { name: "X" })));
await check("create note with owner claim", async () => {
  await setDoc(doc(db, "notes/n1"), { owner: aliceUid, text: "hi" });
  return "ok";
});
await check("create note for another owner is denied", () =>
  expectDenied(() => setDoc(doc(db, "notes/n2"), { owner: "bob", text: "no" })));
await check("owner-filtered query passes per-document rules", async () => {
  const snap = await getDocs(query(collection(db, "notes"), where("owner", "==", aliceUid)));
  return snap.docs.map((d) => d.id);
});
await check("delete without a delete rule is denied", () =>
  expectDenied(() => deleteDoc(doc(db, "notes/n1"))));
await signOut(auth);
await check("after sign-out the profile is protected again", () =>
  expectDenied(() => getDoc(doc(db, `profiles/${aliceUid}`))));

console.log(JSON.stringify(results, null, 1));
const failed = results.filter((r) => !r.ok);
process.exit(failed.length === 0 ? 0 : 1);
