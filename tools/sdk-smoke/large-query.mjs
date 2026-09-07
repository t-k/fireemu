import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { initializeApp, deleteApp, applicationDefault } from "firebase-admin/app";
import { getFirestore } from "firebase-admin/firestore";

const production = process.env.PRODUCTION_ORACLE_PROJECT_ID;
if (!process.env.FIRESTORE_EMULATOR_HOST) {
  assert.equal(
    production,
    "fireemu-35fe6",
    "An explicitly selected oracle or emulator is required",
  );
  assert.equal(process.env.PRODUCTION_ORACLE_EXPECTED_PROJECT_NUMBER, "592603257417");
}
const app = initializeApp({
  projectId: production || "demo-app",
  ...(production ? { credential: applicationDefault() } : {}),
});
const db = getFirestore(app);
const collection = db.collection(`large-query-${randomUUID()}`);
const payload = "x".repeat(192 * 1024);
const refs = Array.from({ length: 65 }, (_, index) =>
  collection.doc(`doc-${String(index).padStart(3, "0")}`),
);
const ids = refs.map((ref) => ref.id);
async function deleteFixtures() {
  const results = await Promise.allSettled(refs.map((ref) => ref.delete()));
  const errors = results
    .filter((result) => result.status === "rejected")
    .map((result) => result.reason);
  if (errors.length) throw new AggregateError(errors, "Fixture cleanup failed");
}
function verify(documents, count) {
  assert.deepEqual(
    documents.map((document) => document.id),
    ids.slice(0, count),
  );
  documents.forEach((document, index) => {
    assert.deepEqual(document.data(), { index, payload });
  });
}
try {
  for (let start = 0; start < refs.length; start += 8) {
    const results = await Promise.allSettled(
      refs
        .slice(start, start + 8)
        .map((ref, offset) => ref.create({ index: start + offset, payload })),
    );
    for (const result of results) if (result.status === "rejected") throw result.reason;
  }
  for (const count of [53, 54, 64, 65]) {
    verify((await collection.limit(count).get()).docs, count);
  }
  verify((await collection.get()).docs, 65);
  await db.runTransaction(
    async (transaction) => {
      verify((await transaction.get(collection)).docs, 65);
      verify((await transaction.get(collection)).docs, 65);
      verify(await transaction.getAll(...refs), 65);
    },
    { readOnly: true },
  );
  console.log(
    JSON.stringify({ ok: true, documents: 65, payloadBytes: payload.length * 65, readOnly: true }),
  );
} finally {
  try {
    await deleteFixtures();
  } finally {
    try {
      await db.terminate();
    } finally {
      await deleteApp(app);
    }
  }
}
