import { initializeApp } from "firebase-admin/app";
import { getFirestore, FieldValue } from "firebase-admin/firestore";
import { getAuth } from "firebase-admin/auth";

const app = initializeApp({ projectId: "demo-app" });
const db = getFirestore(app);
const results = [];
const check = (name, ok, extra) => results.push({ name, ok: !!ok, extra });

try {
  await db.doc("users/alice").set({ name: "Alice", age: 30, tags: ["a"] });
  await db.doc("users/bob").set({ name: "Bob", age: 25, tags: ["b"] });
  const snap = await db.doc("users/alice").get();
  check("set/get", snap.exists && snap.data().age === 30, snap.data());
  await db.doc("users/alice").update({ age: FieldValue.increment(5), updatedAt: FieldValue.serverTimestamp(), tags: FieldValue.arrayUnion("z") });
  const after = (await db.doc("users/alice").get()).data();
  check("update transforms", after.age === 35 && after.updatedAt && after.tags.length === 2, after);
  const q = await db.collection("users").where("age", ">=", 30).orderBy("age", "desc").get();
  check("query where/orderBy", q.size === 1 && q.docs[0].id === "alice", q.size);
  const all = await db.collection("users").orderBy("name").limit(5).get();
  check("query orderBy name", all.size === 2 && all.docs[0].id === "alice", all.docs.map(d => d.id));
  const cnt = await db.collection("users").count().get();
  check("count aggregation", cnt.data().count === 2, cnt.data());
  await db.runTransaction(async (tx) => {
    const d = await tx.get(db.doc("users/bob"));
    tx.update(db.doc("users/bob"), { age: d.data().age + 1 });
  });
  check("transaction", (await db.doc("users/bob").get()).data().age === 26);
  const batch = db.batch();
  batch.set(db.doc("rooms/r1"), { open: true });
  batch.delete(db.doc("users/bob"));
  await batch.commit();
  check("batch", !(await db.doc("users/bob").get()).exists && (await db.doc("rooms/r1").get()).exists);
  const cols = await db.listCollections();
  check("listCollections", cols.map(c => c.id).sort().join(",") === "rooms,users", cols.map(c => c.id));
  const added = await db.collection("users").add({ name: "Auto" });
  check("add auto id", added.id.length === 20, added.id);
  try {
    await db.collection("users").where("name", "==", "x").where("age", "==", 1).get();
    check("missing composite index rejected", false);
  } catch (e) {
    check("missing composite index rejected", e.code === 9 || /index/i.test(e.message), e.message.slice(0, 80));
  }
  const auth = getAuth(app);
  try {
    const user = await auth.createUser({ email: "admin@example.com", password: "hunter22" });
    check("auth createUser", !!user.uid, user.uid);
    await auth.setCustomUserClaims(user.uid, { role: "admin" });
    const fetched = await auth.getUser(user.uid);
    check("auth custom claims", fetched.customClaims?.role === "admin", fetched.customClaims);
  } catch (e) {
    check("auth admin", false, e.message.slice(0, 160));
  }
} catch (e) {
  results.push({ name: "fatal", ok: false, extra: e.message });
}
console.log(JSON.stringify(results, null, 1));
process.exit(results.every(r => r.ok) ? 0 : 1);
