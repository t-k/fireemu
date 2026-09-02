import { initializeApp } from "firebase-admin/app";
import { FieldValue, Timestamp, getFirestore } from "firebase-admin/firestore";

const app = initializeApp({ projectId: process.env.GOOGLE_CLOUD_PROJECT ?? "demo-app" });
const db = getFirestore(app);
const document = db.collection("recent-jobs").doc("server-timestamp-query");
await document.set({
  owner: "user-one",
  createdAt: FieldValue.serverTimestamp(),
  updatedAt: FieldValue.serverTimestamp(),
});

const result = await db.runTransaction(async (transaction) => {
  const snapshot = await transaction.get(
    db
      .collection("recent-jobs")
      .where("owner", "==", "user-one")
      .where("createdAt", ">=", Timestamp.fromMillis(Date.now() - 30 * 60 * 1000))
      .limit(1),
  );
  return snapshot.docs.map((candidate) => ({
    id: candidate.id,
    createdAtIsTimestamp: candidate.get("createdAt") instanceof Timestamp,
  }));
});
await document.delete();

const passed = result.length === 1 && result[0].createdAtIsTimestamp;
console.log(JSON.stringify({ passed, result }, null, 2));
process.exit(passed ? 0 : 1);
