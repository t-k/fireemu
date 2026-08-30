// Storage-triggered Cloud Functions for the storage probe (conformance/src/storage-probe).
//
// Every v1 and v2 Storage trigger the SDK offers is declared on the probe's bucket, and each
// handler reports the event it received to the probe session, which listens on a fixed
// loopback port. Nothing else is computed here: the row under test is the payload exactly
// as the Functions emulator handed it to the handler.
//
// The port is a constant rather than an environment variable because neither emulator
// promises to forward arbitrary variables into the runtime.
const {
  onObjectArchived,
  onObjectDeleted,
  onObjectFinalized,
  onObjectMetadataUpdated,
} = require("firebase-functions/v2/storage");
const functions = require("firebase-functions/v1");

const BUCKET = "demo-storage-probe.appspot.com";
const SINK = "http://127.0.0.1:32310/events";

async function report(payload) {
  await fetch(SINK, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
}

const v2 = (event) =>
  report({
    api: "v2",
    type: event.type,
    source: event.source,
    subject: event.subject ?? null,
    bucket: event.bucket ?? null,
    specversion: event.specversion ?? null,
    datacontenttype: event.datacontenttype ?? null,
    hasId: typeof event.id === "string" && event.id.length > 0,
    hasTime: typeof event.time === "string" && event.time.length > 0,
    data: event.data,
  });

exports.probeFinalizedV2 = onObjectFinalized({ bucket: BUCKET }, v2);
exports.probeDeletedV2 = onObjectDeleted({ bucket: BUCKET }, v2);
exports.probeMetadataV2 = onObjectMetadataUpdated({ bucket: BUCKET }, v2);
exports.probeArchivedV2 = onObjectArchived({ bucket: BUCKET }, v2);

const v1 = (object, context) =>
  report({
    api: "v1",
    eventType: context.eventType,
    resource: context.resource,
    params: context.params,
    hasEventId: typeof context.eventId === "string" && context.eventId.length > 0,
    hasTimestamp: typeof context.timestamp === "string" && context.timestamp.length > 0,
    data: object,
  });

const v1Object = functions.storage.bucket(BUCKET).object();
exports.probeFinalizedV1 = v1Object.onFinalize(v1);
exports.probeDeletedV1 = v1Object.onDelete(v1);
exports.probeMetadataV1 = v1Object.onMetadataUpdate(v1);
exports.probeArchivedV1 = v1Object.onArchive(v1);
