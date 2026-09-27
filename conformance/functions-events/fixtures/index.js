const { createHash } = require("node:crypto");
const { getApps, initializeApp } = require("firebase-admin/app");
const { getFirestore } = require("firebase-admin/firestore");
const functions = require("firebase-functions/v1");
const {
  onDocumentCreated,
  onDocumentDeleted,
  onDocumentUpdated,
  onDocumentWritten,
  onDocumentWrittenWithAuthContext,
} = require("firebase-functions/v2/firestore");
const {
  onObjectArchived,
  onObjectDeleted,
  onObjectFinalized,
  onObjectMetadataUpdated,
} = require("firebase-functions/v2/storage");
const { onMessagePublished } = require("firebase-functions/v2/pubsub");
const { firestoreData, report, v1Context, v2Event } = require("./report");

const collection = process.env.FE_EVENTS_PRIMARY_COLLECTION || "fe_events_primary";
const document = `${collection}/{documentId}`;
const bucket = process.env.FE_EVENTS_PRIMARY_BUCKET || "demo-conformance-events-primary";
const topic = process.env.FE_EVENTS_PRIMARY_TOPIC || "fe-events-primary";

const v1 = (handler, source, data, context) =>
  report({ handler, generation: 1, source, event: { context: v1Context(context), data } });
const v2 = (handler, source, event, data) =>
  report({ handler, generation: 2, source, event: v2Event(event, data) });

const v1Document = functions.firestore.document(document);
exports.fsCreatedV1 = v1Document.onCreate((value, context) =>
  v1("fsCreatedV1", "firestore", firestoreData(value), context),
);
exports.fsUpdatedV1 = v1Document.onUpdate((value, context) =>
  v1("fsUpdatedV1", "firestore", firestoreData(value), context),
);
exports.fsDeletedV1 = v1Document.onDelete((value, context) =>
  v1("fsDeletedV1", "firestore", firestoreData(value), context),
);
exports.fsWrittenV1 = v1Document.onWrite((value, context) =>
  v1("fsWrittenV1", "firestore", firestoreData(value), context),
);

exports.fsCreatedV2 = onDocumentCreated(document, (event) =>
  v2("fsCreatedV2", "firestore", event, firestoreData(event.data)),
);
exports.fsUpdatedV2 = onDocumentUpdated(document, (event) =>
  v2("fsUpdatedV2", "firestore", event, firestoreData(event.data)),
);
exports.fsDeletedV2 = onDocumentDeleted(document, (event) =>
  v2("fsDeletedV2", "firestore", event, firestoreData(event.data)),
);
exports.fsWrittenV2 = onDocumentWritten(document, (event) =>
  v2("fsWrittenV2", "firestore", event, firestoreData(event.data)),
);
exports.fsWrittenWithAuthContextV2 = onDocumentWrittenWithAuthContext(document, (event) =>
  v2("fsWrittenWithAuthContextV2", "firestore", event, firestoreData(event.data)),
);

exports.fsRetryV2 = onDocumentWritten({ document, retry: true }, async (event) => {
  const app = getApps()[0] ?? initializeApp();
  const db = getFirestore(app);
  const markerId = createHash("sha256").update(event.id).digest("hex");
  const marker = db.doc(`fe_events_retry_markers/${markerId}`);
  const firstAttempt = await db.runTransaction(async (transaction) => {
    const previous = await transaction.get(marker);
    if (previous.exists) return false;
    transaction.create(marker, { eventId: event.id, source: event.source });
    return true;
  });
  await v2("fsRetryV2", "firestore", event, {
    ...firestoreData(event.data),
    fixtureAttempt: firstAttempt ? "failed" : "succeeded",
  });
  if (firstAttempt) throw new Error("intentional first delivery failure");
});

const v1Object = functions.storage.bucket(bucket).object();
exports.storageFinalizedV1 = v1Object.onFinalize((object, context) =>
  v1("storageFinalizedV1", "storage", object, context),
);
exports.storageDeletedV1 = v1Object.onDelete((object, context) =>
  v1("storageDeletedV1", "storage", object, context),
);
exports.storageMetadataUpdatedV1 = v1Object.onMetadataUpdate((object, context) =>
  v1("storageMetadataUpdatedV1", "storage", object, context),
);
exports.storageArchivedV1 = v1Object.onArchive((object, context) =>
  v1("storageArchivedV1", "storage", object, context),
);
exports.storageFinalizedV2 = onObjectFinalized({ bucket }, (event) =>
  v2("storageFinalizedV2", "storage", event, event.data),
);
exports.storageDeletedV2 = onObjectDeleted({ bucket }, (event) =>
  v2("storageDeletedV2", "storage", event, event.data),
);
exports.storageMetadataUpdatedV2 = onObjectMetadataUpdated({ bucket }, (event) =>
  v2("storageMetadataUpdatedV2", "storage", event, event.data),
);
exports.storageArchivedV2 = onObjectArchived({ bucket }, (event) =>
  v2("storageArchivedV2", "storage", event, event.data),
);

exports.authCreatedV1 = functions.auth.user().onCreate((user, context) =>
  v1("authCreatedV1", "auth", user.toJSON(), context),
);
exports.authDeletedV1 = functions.auth.user().onDelete((user, context) =>
  v1("authDeletedV1", "auth", user.toJSON(), context),
);

exports.pubsubPublishedV1 = functions.pubsub.topic(topic).onPublish((message, context) =>
  v1("pubsubPublishedV1", "pubsub", message.toJSON(), context),
);
exports.pubsubPublishedV2 = onMessagePublished({ topic }, (event) =>
  v2("pubsubPublishedV2", "pubsub", event, event.data),
);
