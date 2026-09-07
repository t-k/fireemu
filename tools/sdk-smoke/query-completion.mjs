import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { initializeApp, deleteApp, applicationDefault } from "firebase-admin/app";
import { getFirestore, FieldPath } from "firebase-admin/firestore";

const production = process.env.PRODUCTION_ORACLE_PROJECT_ID;
if (!process.env.FIRESTORE_EMULATOR_HOST) {
  assert.equal(production, "fireemu-35fe6", "An explicitly selected oracle or emulator is required");
  assert.equal(process.env.PRODUCTION_ORACLE_EXPECTED_PROJECT_NUMBER, "592603257417");
}
const app = initializeApp({ projectId: production || "demo-app", ...(production ? { credential: applicationDefault() } : {}) });
const db = getFirestore(app);
const collection = db.collection(`query-completion-${randomUUID()}`);
const refs = Array.from({ length: 200 }, (_, index) => collection.doc(`doc-${String(index).padStart(3, "0")}`));
const ids = refs.map(ref => ref.id);
try {
  const created = await Promise.allSettled(refs.map((ref, index) => ref.create({ index })));
  for (const result of created) if (result.status === "rejected") throw result.reason;
  const direct = await db.getAll(...refs);
  assert.equal(direct.filter(doc => doc.exists).length, 200);
  for (const size of [0, 1, 31, 32, 33, 63, 64, 65, 200]) {
    const snapshot = await collection.where("index", "<", size).orderBy("index").get();
    assert.deepEqual(snapshot.docs.map(doc => doc.id), ids.slice(0, size));
    assert.deepEqual(snapshot.docs.map(doc => doc.data().index), Array.from({ length: size }, (_, i) => i));
  }
  assert.deepEqual((await collection.get()).docs.map(doc => doc.id), ids);
  for (const limit of [1, 31, 32, 33, 64, 200, 201]) {
    assert.deepEqual((await collection.limit(limit).get()).docs.map(doc => doc.id), ids.slice(0, limit));
  }
  for (const offset of [0, 1, 31, 32, 201]) {
    assert.deepEqual((await collection.offset(offset).get()).docs.map(doc => doc.id), ids.slice(offset));
  }
  assert.deepEqual((await collection.orderBy("index", "desc").get()).docs.map(doc => doc.id), ids.toReversed());
  assert.deepEqual((await collection.orderBy(FieldPath.documentId()).startAfter(refs[30]).endBefore(refs[100]).get()).docs.map(doc => doc.id), ids.slice(31, 100));
  await db.runTransaction(async transaction => {
    assert.deepEqual((await transaction.get(collection)).docs.map(doc => doc.id), ids);
  }, { readOnly: true });
  console.log(JSON.stringify({ ok: true, project: app.options.projectId, documents: 200, boundaryCases: 9 }));
} finally {
  try {
    const deleted = await Promise.allSettled(refs.map(ref => ref.delete()));
    for (const result of deleted) if (result.status === "rejected") throw result.reason;
  } finally {
    try { await db.terminate(); } finally { await deleteApp(app); }
  }
}
