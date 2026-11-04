// The source operations of the check, as declared requests, in the order they are sent. Each says which functions
// its delivery reaches, so that the judge knows what to look for and the recorder knows how long to wait. Nothing
// here sends anything. The local dry run sends the same operations to fireemu (with the hosts mapped), so a judge
// that reads a local delivery reads a production one the same way.
import {
  CHANNEL,
  COLLECTION,
  EVENT_TYPE,
  FAMILIES,
  OBJECT_PREFIX,
  PROJECT,
  REGION,
  TOPIC,
  jobId,
  runMarker,
} from "./plan.mjs";

const b64 = (text) => Buffer.from(text, "utf8").toString("base64");
const field = (value) =>
  typeof value === "number" ? { integerValue: String(value) } : { stringValue: value };
const fields = (data) => Object.fromEntries(Object.entries(data).map(([k, v]) => [k, field(v)]));

export const documentUrl = (id) =>
  `https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents/${COLLECTION}/${id}`;
export const documentId = (runId) => runMarker(runId) + "-a";
export const objectName = (runId) => `${OBJECT_PREFIX}${runMarker(runId)}-a.json`;
export const storageUploadUrl = (bucket, name) =>
  `https://storage.googleapis.com/upload/storage/v1/b/${encodeURIComponent(bucket)}/o?uploadType=media&name=${encodeURIComponent(name)}`;
export const storageObjectUrl = (bucket, name) =>
  `https://storage.googleapis.com/storage/v1/b/${encodeURIComponent(bucket)}/o/${encodeURIComponent(name)}`;
export const topicUrl = `https://pubsub.googleapis.com/v1/projects/${PROJECT}/topics/${TOPIC}`;
export const channelPublishUrl = `https://eventarcpublishing.googleapis.com/v1/projects/${PROJECT}/locations/${REGION}/channels/${CHANNEL}:publishEvents`;
export const jobRunUrl = (fn) =>
  `https://cloudscheduler.googleapis.com/v1/projects/${PROJECT}/locations/${REGION}/jobs/${jobId(fn)}:run`;
export const taskCreateUrl = (fn) =>
  `https://cloudtasks.googleapis.com/v2/projects/${PROJECT}/locations/${REGION}/queues/${fn}/tasks`;

/** The CloudEvent the Admin SDK's Eventarc client publishes: the proto form, the time as a timestamp attribute. */
export function customEvent({ runId, label, time }) {
  const marker = runMarker(runId);
  return {
    "@type": "type.googleapis.com/io.cloudevents.v1.CloudEvent",
    id: `${marker}-${label}`,
    source: "https://example.com/pycheck",
    specVersion: "1.0",
    type: EVENT_TYPE,
    attributes: {
      datacontenttype: { ceString: "application/json" },
      time: { ceTimestamp: time },
    },
    textData: JSON.stringify({ run: marker, label }),
  };
}

export const EVENT_TIMES = Object.freeze({
  fraction: "2026-01-01T00:00:02.500Z",
  whole: "2026-01-01T00:00:02Z",
});

/** A Cloud Tasks task body the way the Admin SDK writes one: the callable format, the function's own URL and identity. */
export function taskBody({ runId, label, uri, serviceAccountEmail }) {
  return {
    task: {
      httpRequest: {
        url: uri,
        httpMethod: "POST",
        headers: { "Content-Type": "application/json" },
        body: b64(JSON.stringify({ data: { run: runMarker(runId), label } })),
        oidcToken: { serviceAccountEmail, audience: uri },
      },
    },
  };
}

/**
 * The ordered source operations. `needs` names a value only the readbacks can give (`bucket`, `uri:<fn>`); the
 * recorder fills them in, and refuses to send an operation whose value it does not have.
 */
export function operations({ runId, bucket, targets }) {
  const marker = runMarker(runId);
  const id = documentId(runId);
  const name = objectName(runId);
  const list = [
    {
      key: "fs-create",
      family: "firestoreCreated",
      reaches: ["pcfsc", "pcfscraw"],
      request: {
        method: "POST",
        url: `https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents/${COLLECTION}?documentId=${encodeURIComponent(id)}`,
        json: { fields: fields({ run: marker, n: 1 }) },
      },
    },
    {
      key: "fs-update",
      family: "firestoreUpdated",
      reaches: ["pcfsu"],
      request: {
        method: "PATCH",
        url: `${documentUrl(id)}?updateMask.fieldPaths=n&currentDocument.exists=true`,
        json: { fields: fields({ n: 2 }) },
      },
    },
    {
      key: "ps-plain",
      family: "pubsub",
      reaches: ["pcps", "pcpsraw"],
      request: {
        method: "POST",
        url: topicUrl + ":publish",
        json: { messages: [{ data: b64("hello"), attributes: { run: marker, label: "plain" } }] },
      },
    },
    {
      key: "ps-ordered",
      family: "pubsub",
      reaches: ["pcps", "pcpsraw"],
      request: {
        method: "POST",
        url: topicUrl + ":publish",
        json: {
          messages: [
            {
              data: b64("ordered"),
              attributes: { run: marker, label: "ordered" },
              orderingKey: "pycheck-key",
            },
          ],
        },
      },
    },
    {
      key: "st-upload",
      family: "storage",
      reaches: ["pcst", "pcstraw"],
      request: {
        method: "POST",
        url: storageUploadUrl(bucket, name),
        json: { run: marker },
      },
    },
    {
      key: "ea-fraction",
      family: "eventarc",
      reaches: ["pcea", "pcearaw"],
      request: {
        method: "POST",
        url: channelPublishUrl,
        json: { events: [customEvent({ runId, label: "fraction", time: EVENT_TIMES.fraction })] },
      },
    },
    {
      key: "ea-whole",
      family: "eventarc",
      reaches: ["pcea", "pcearaw"],
      request: {
        method: "POST",
        url: channelPublishUrl,
        json: { events: [customEvent({ runId, label: "whole", time: EVENT_TIMES.whole })] },
      },
    },
  ];
  for (const fn of [FAMILIES.scheduler.sdk, FAMILIES.scheduler.raw])
    list.push({
      key: "sched-" + fn,
      family: "scheduler",
      reaches: [fn],
      request: { method: "POST", url: jobRunUrl(fn), json: {} },
    });
  for (const fn of [FAMILIES.tasks.sdk, FAMILIES.tasks.raw]) {
    const target = targets?.[fn];
    list.push({
      key: "task-" + fn,
      family: "tasks",
      reaches: [fn],
      request: {
        method: "POST",
        url: taskCreateUrl(fn),
        json: target ? taskBody({ runId, label: fn, ...target }) : undefined,
      },
      needs: target ? [] : ["task-target:" + fn],
    });
  }
  return list;
}

/** The operations that undo the sources, run in the cleanup. */
export function undoOperations({ runId, bucket }) {
  return [
    { key: "fs-delete", request: { method: "DELETE", url: documentUrl(documentId(runId)) } },
    {
      key: "st-delete",
      request: { method: "DELETE", url: storageObjectUrl(bucket, objectName(runId)) },
    },
  ];
}
