// Firebase Functions (v2) exercised by tools/sdk-smoke/functions.mjs against fireemu.
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

// firebase-functions v1 API (legacy (data, context) handlers).
const functionsV1 = require("firebase-functions/v1");

exports.v1Mirror = functionsV1.firestore.document("v1todos/{todoId}").onCreate(async (snap, context) => {
  await db.doc(`v1mirror/${context.params.todoId}`).set({
    title: snap.data().title,
    eventType: context.eventType,
    resource: context.resource.name,
  });
});

exports.v1Upload = functionsV1.storage.object().onFinalize(async (object, context) => {
  await db.doc(`v1uploads/${object.name.replace(/\//g, "_")}`).set({
    size: Number(object.size),
    eventType: context.eventType,
  });
});

exports.v1Tick = functionsV1.pubsub.schedule("every 10 minutes").onRun(async (context) => {
  await db.doc("stats/v1ticks").set({ count: FieldValue.increment(1), eventType: context.eventType }, { merge: true });
});

exports.add = onCall((request) => {
  const { a, b } = request.data || {};
  if (typeof a !== "number" || typeof b !== "number") {
    throw new HttpsError("invalid-argument", "a and b must be numbers");
  }
  return { sum: a + b, uid: request.auth?.uid ?? null };
});

// A callable that enforces App Check. With appCheck disabled it behaves like any other
// callable and never sees an app; with appCheck enabled the daemon refuses a missing or
// invalid token with the callable 401 envelope before this handler runs, and a valid one
// arrives here as `request.app`.
exports.guarded = onCall({ enforceAppCheck: true }, (request) => ({
  appId: request.app?.appId ?? null,
  // The decoded claims of the local App Check token, minus anything secret-shaped.
  subject: request.app?.token?.sub ?? null,
  uid: request.auth?.uid ?? null,
}));

// Pub/Sub (v2): messages published through the control API land here.
const { onMessagePublished } = require("firebase-functions/v2/pubsub");
exports.onJob = onMessagePublished("jobs", async (event) => {
  const message = event.data.message;
  await db.doc(`jobs/${message.messageId}`).set({
    json: message.json,
    attributes: message.attributes,
    orderingKey: message.orderingKey || null,
    publishTime: message.publishTime,
    subscription: event.data.subscription,
  });
});

// Pub/Sub (v1): the same topic through the legacy API.
exports.v1Job = functionsV1.pubsub.topic("jobs").onPublish(async (message, context) => {
  await db.doc(`v1jobs/${context.eventId}`).set({ json: message.json, eventType: context.eventType });
});

// Auth user events (v1): every created user gets a profile.
exports.onUserCreated = functionsV1.auth.user().onCreate(async (user, context) => {
  await db.doc(`profiles/${user.uid}`).set({
    email: user.email || null,
    eventType: context.eventType,
    creationTime: user.metadata.creationTime,
    providers: user.providerData.map((p) => p.providerId),
  });
});

exports.onUserDeleted = functionsV1.auth.user().onDelete(async (user) => {
  await db.doc(`profiles/${user.uid}`).delete();
});

// withAuthContext: the principal that made the change travels with the event.
const { onDocumentCreatedWithAuthContext } = require("firebase-functions/v2/firestore");
exports.auditedCreate = onDocumentCreatedWithAuthContext("audited/{id}", async (event) => {
  await db.doc(`auditedBy/${event.params.id}`).set({
    authType: event.authType,
    authId: event.authId || null,
    type: event.type,
  });
});

// Eventarc custom events: `getEventarc().channel().publish()` reaches this handler through
// the emulator's publishEvents route. The whole CloudEvent is written down so the smoke can
// check the conversion from the proto form the Admin SDK sends.
const { onCustomEventPublished } = require("firebase-functions/v2/eventarc");
exports.onThingDone = onCustomEventPublished("com.example.thing.done", async (event) => {
  await db.doc(`customEvents/${event.data.id}`).set({
    type: event.type,
    source: event.source,
    subject: event.subject ?? null,
    specversion: event.specversion,
    datacontenttype: event.datacontenttype,
    hasTime: typeof event.time === "string" && event.time.length > 0,
    data: event.data,
  });
});

// The same event type with a filter: only events whose `region` attribute is `emea` arrive.
exports.onThingDoneInEmea = onCustomEventPublished(
  { eventType: "com.example.thing.done", filters: { region: "emea" } },
  async (event) => {
    await db.doc(`customEventsEmea/${event.data.id}`).set({ region: event.region });
  },
);

// Firebase alerts. The official emulator has no alert-injection route of its own: the alert
// providers register an ordinary event trigger with no channel, its Eventarc emulator indexes
// them under `<eventType>-google`, and its UI fires one by POSTing the CloudEvent to
// /google/publishEvents. fireemu serves that route on the dedicated Eventarc port.
const { onNewFatalIssuePublished } = require("firebase-functions/v2/alerts/crashlytics");
exports.onFatalIssue = onNewFatalIssuePublished(async (event) => {
  await db.doc(`alerts/${event.data.payload.issue.id}`).set({
    // `convertAlertAndApp` adds the camelCase aliases and keeps the lowercase originals.
    alertType: event.alertType,
    alerttype: event.alerttype,
    appId: event.appId ?? null,
    title: event.data.payload.issue.title,
    createTime: event.data.createTime,
  });
});


// Cloud Tasks. `getFunctions().taskQueue("countJob").enqueue(payload)` reaches the queue
// through CLOUD_TASKS_EMULATOR_HOST, and the queue dispatches to this handler with the
// X-CloudTasks-* headers a task carries.
const { onTaskDispatched } = require("firebase-functions/v2/tasks");
exports.countJob = onTaskDispatched(
  { retryConfig: { maxAttempts: 3, minBackoffSeconds: 0.1 } },
  async (request) => {
    await db.doc(`tasks/${request.data.id}`).set({
      n: request.data.n,
      queueName: request.queueName,
      retryCount: request.retryCount,
      executionCount: request.executionCount,
      hasScheduledTime: typeof request.scheduledTime === "string",
    });
  },
);

// A task-queue function that fails until its third attempt: the retry schedule is the thing
// under test, not the handler.
let taskAttempts = 0;
exports.flakyJob = onTaskDispatched(
  { retryConfig: { maxAttempts: 5, minBackoffSeconds: 0.05 } },
  async (request) => {
    taskAttempts += 1;
    if (taskAttempts < 3) {
      throw new Error(`attempt ${taskAttempts} fails on purpose`);
    }
    await db.doc("tasks/flaky").set({ attempts: taskAttempts, retryCount: request.retryCount });
  },
);
