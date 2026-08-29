// Firestore Lite SDK smoke: `firebase/firestore/lite` speaks the REST API only, so this
// exercises FS-REST-1 end to end (with Security Rules loaded through the control API).
import { initializeApp } from "firebase/app";
import { getAuth, connectAuthEmulator, createUserWithEmailAndPassword } from "firebase/auth";
import {
  getFirestore,
  connectFirestoreEmulator,
  doc,
  setDoc,
  getDoc,
  getDocs,
  updateDoc,
  deleteDoc,
  collection,
  query,
  where,
  orderBy,
  limit,
  runTransaction,
  writeBatch,
  getCount,
  serverTimestamp,
  increment,
} from "firebase/firestore/lite";

const project = process.env.GOOGLE_CLOUD_PROJECT ?? "demo-app";
const fsHost = process.env.FIRESTORE_EMULATOR_HOST ?? "127.0.0.1:8080";
const authHost = process.env.FIREBASE_AUTH_EMULATOR_HOST ?? "127.0.0.1:9099";

const RULES = `
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /lite/{id} { allow read, write: if request.auth != null; }
    match /counters/{id} { allow read, write: if request.auth != null; }
  }
}
`;
const put = await fetch(`http://${authHost}/v1/rules`, {
  method: "PUT",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ source: RULES }),
});
if (!put.ok) throw new Error(`PUT /v1/rules failed: ${put.status}`);

const results = [];
async function check(name, fn) {
  try {
    results.push({ name, ok: true, extra: await fn() });
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

const app = initializeApp({ projectId: project, apiKey: "fake-api-key" });
const auth = getAuth(app);
connectAuthEmulator(auth, `http://${authHost}`, { disableWarnings: true });
const db = getFirestore(app);
connectFirestoreEmulator(db, fsHost.split(":")[0], Number(fsHost.split(":")[1]));

await check("anonymous write is denied over REST", () =>
  expectDenied(() => setDoc(doc(db, "lite/anon"), { v: 1 })));
await createUserWithEmailAndPassword(auth, "lite@example.com", "password123");
await check("set + get", async () => {
  await setDoc(doc(db, "lite/a"), { n: 1, s: "x", nested: { k: [1, "two", null] }, at: serverTimestamp() });
  const snap = await getDoc(doc(db, "lite/a"));
  return { exists: snap.exists(), n: snap.data().n, at: snap.data().at?.constructor?.name };
});
await check("update with increment + merge", async () => {
  await updateDoc(doc(db, "lite/a"), { n: increment(4), "nested.k": [9] });
  return (await getDoc(doc(db, "lite/a"))).data();
});
await check("query with filter/order/limit", async () => {
  await setDoc(doc(db, "lite/b"), { n: 7, s: "y" });
  await setDoc(doc(db, "lite/c"), { n: 3, s: "z" });
  const snap = await getDocs(query(collection(db, "lite"), where("n", ">", 2), orderBy("n", "desc"), limit(2)));
  return snap.docs.map((d) => d.id);
});
await check("count aggregation", async () => (await getCount(collection(db, "lite"))).data().count);
await check("batch write", async () => {
  const b = writeBatch(db);
  b.set(doc(db, "lite/d"), { n: 10 });
  b.delete(doc(db, "lite/c"));
  await b.commit();
  return (await getDoc(doc(db, "lite/c"))).exists();
});
await check("transaction", async () => {
  await setDoc(doc(db, "counters/x"), { value: 1 });
  const result = await runTransaction(db, async (tx) => {
    const snap = await tx.get(doc(db, "counters/x"));
    tx.update(doc(db, "counters/x"), { value: snap.data().value + 1 });
    return snap.data().value;
  });
  return { before: result, after: (await getDoc(doc(db, "counters/x"))).data().value };
});
await check("delete", async () => {
  await deleteDoc(doc(db, "lite/a"));
  return (await getDoc(doc(db, "lite/a"))).exists();
});

console.log(JSON.stringify(results, null, 1));
process.exit(results.some((r) => !r.ok) ? 1 : 0);
