// Transaction ordering probe: the SDKs require every read before the first write; the
// daemon is exercised through the real client and admin SDKs.
import { initializeApp } from "firebase/app";
import { connectFirestoreEmulator, doc, getFirestore, runTransaction } from "firebase/firestore";
import { initializeApp as adminInit } from "firebase-admin/app";
import { getFirestore as adminFirestore } from "firebase-admin/firestore";

const [host, port] = process.env.FIRESTORE_EMULATOR_HOST.split(":");
const app = initializeApp({ projectId: "demo-app" });
const db = getFirestore(app);
connectFirestoreEmulator(db, host, Number(port));
const out = [];
try {
  await runTransaction(db, async (tx) => {
    tx.set(doc(db, "txn/a"), { v: 1 });
    await tx.get(doc(db, "txn/b"));
  });
  out.push({ sdk: "web", ok: false, note: "no error" });
} catch (e) {
  out.push({ sdk: "web", ok: /reads to be executed before all writes/.test(e.message), message: e.message });
}
adminInit({ projectId: "demo-app" });
const adb = adminFirestore();
try {
  await adb.runTransaction(async (tx) => {
    tx.set(adb.doc("txn/a"), { v: 1 });
    await tx.get(adb.doc("txn/b"));
  });
  out.push({ sdk: "admin", ok: false, note: "no error" });
} catch (e) {
  out.push({ sdk: "admin", ok: /reads to be executed before all writes/.test(e.message), message: e.message });
}
// A well-ordered transaction commits and the server enforces the read set at commit.
await adb.runTransaction(async (tx) => {
  const b = await tx.get(adb.doc("txn/b"));
  tx.set(adb.doc("txn/a"), { v: b.exists ? 2 : 1 });
});
out.push({ sdk: "admin-ordered", ok: true });
console.log(JSON.stringify(out, null, 2));
process.exit(out.every((o) => o.ok) ? 0 : 1);
