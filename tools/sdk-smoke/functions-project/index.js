// Firebase Functions (v2) exercised by tools/sdk-smoke/functions.mjs against firebase-testd.
const { initializeApp } = require("firebase-admin/app");
const { getFirestore, FieldValue } = require("firebase-admin/firestore");
const { onDocumentCreated, onDocumentWritten, onDocumentDeleted } = require("firebase-functions/v2/firestore");
const { onObjectFinalized } = require("firebase-functions/v2/storage");
const { onSchedule } = require("firebase-functions/v2/scheduler");
const { onRequest, onCall, HttpsError } = require("firebase-functions/v2/https");
const logger = require("firebase-functions/logger");

initializeApp();
const db = getFirestore();

// A created todo is mirrored with its captured id and the event's params.
exports.mirrorTodo = onDocumentCreated("todos/{todoId}", async (event) => {
  const data = event.data.data();
  logger.info("mirrorTodo", { todoId: event.params.todoId, title: data.title });
  await db.doc(`mirror/${event.params.todoId}`).set({
    title: data.title,
    eventType: event.type,
    createTime: event.data.createTime.toDate().toISOString(),
    source: event.source,
    subject: event.subject,
    database: event.database,
    document: event.document,
  });
});

// Every write under audit/** is counted; updates report the before / after values.
exports.auditWrites = onDocumentWritten("audit/{docId}", async (event) => {
  const before = event.data?.before?.exists ? event.data.before.data() : null;
  const after = event.data?.after?.exists ? event.data.after.data() : null;
  await db.doc("stats/audit").set(
    {
      writes: FieldValue.increment(1),
      last: { docId: event.params.docId, before, after, type: event.type },
    },
    { merge: true },
  );
});

exports.onTodoDeleted = onDocumentDeleted("todos/{todoId}", async (event) => {
  await db.doc(`mirror/${event.params.todoId}`).delete();
});

// A failing function declared with retry: fails twice, then succeeds.
exports.flaky = onDocumentCreated({ document: "flaky/{id}", retry: true }, async (event) => {
  const ref = db.doc(`flakyAttempts/${event.params.id}`);
  const snap = await ref.get();
  const attempts = (snap.exists ? snap.data().attempts : 0) + 1;
  await ref.set({ attempts });
  if (attempts < 3) throw new Error(`attempt ${attempts} fails on purpose`);
});

exports.indexUpload = onObjectFinalized(async (event) => {
  const o = event.data;
  await db.doc(`uploads/${o.name.replace(/\//g, "_")}`).set({
    bucket: o.bucket,
    name: o.name,
    size: Number(o.size),
    contentType: o.contentType,
    generation: o.generation,
    md5Hash: o.md5Hash,
  });
});

exports.tick = onSchedule({ schedule: "every 5 minutes", timeZone: "Asia/Tokyo" }, async (event) => {
  await db.doc("stats/ticks").set(
    { count: FieldValue.increment(1), lastScheduleTime: event.scheduleTime, lastJob: event.jobName },
    { merge: true },
  );
});

exports.echo = onRequest((req, res) => {
  res.status(200).json({ method: req.method, path: req.path, query: req.query, body: req.body, header: req.get("x-smoke") });
});

exports.add = onCall((request) => {
  const { a, b } = request.data || {};
  if (typeof a !== "number" || typeof b !== "number") {
    throw new HttpsError("invalid-argument", "a and b must be numbers");
  }
  return { sum: a + b, uid: request.auth?.uid ?? null };
});
