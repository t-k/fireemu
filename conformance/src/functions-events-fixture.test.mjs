import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
process.env.GCLOUD_PROJECT = "demo-conformance";
const fixturePath = fileURLToPath(
  new URL("../functions-events/fixtures/index.js", import.meta.url),
);
const reportPath = fileURLToPath(
  new URL("../functions-events/fixtures/report.js", import.meta.url),
);
const manifest = JSON.parse(
  readFileSync(fileURLToPath(new URL("../functions-events/programs.json", import.meta.url))),
);

test("the fixture exports every declared handler from one codebase", () => {
  const fixture = require(fixturePath);
  const expected = new Set(
    manifest.programs.flatMap((program) => Object.values(program.handlerExports)),
  );
  assert.deepEqual(new Set(Object.keys(fixture)), expected);
  for (const name of expected) {
    assert.equal(typeof fixture[name], "function", name);
    assert.ok(fixture[name].__endpoint?.eventTrigger, name);
  }
});

test("trigger filters select the owned Firestore path, Storage bucket, and Pub/Sub topic", () => {
  const fixture = require(fixturePath);
  for (const [name, handler] of Object.entries(fixture)) {
    const trigger = handler.__endpoint.eventTrigger;
    const filters = JSON.stringify(trigger);
    if (name.startsWith("fs")) assert.match(filters, /fe_events_primary\/\{documentId\}/, name);
    if (name.startsWith("storage")) assert.match(filters, /demo-conformance-events-primary/, name);
    if (name.startsWith("pubsub")) assert.match(filters, /fe-events-primary/, name);
    if (name.startsWith("auth")) assert.match(filters, /auth\.user|firebase\.auth/, name);
  }
  assert.equal(fixture.fsRetryV2.__endpoint.eventTrigger.retry, true);
  assert.equal(
    Object.keys(fixture).some((name) => /^auth.*V2$/.test(name)),
    false,
  );
});

test("the declared generation and event kind match each SDK trigger", () => {
  const fixture = require(fixturePath);
  const expectedTypes = {
    fsCreated: [
      "providers/cloud.firestore/eventTypes/document.create",
      "google.cloud.firestore.document.v1.created",
    ],
    fsUpdated: [
      "providers/cloud.firestore/eventTypes/document.update",
      "google.cloud.firestore.document.v1.updated",
    ],
    fsDeleted: [
      "providers/cloud.firestore/eventTypes/document.delete",
      "google.cloud.firestore.document.v1.deleted",
    ],
    fsWritten: [
      "providers/cloud.firestore/eventTypes/document.write",
      "google.cloud.firestore.document.v1.written",
    ],
    fsWrittenWithAuthContext: [null, "google.cloud.firestore.document.v1.written.withAuthContext"],
    fsRetry: [null, "google.cloud.firestore.document.v1.written"],
    storageFinalized: [
      "google.storage.object.finalize",
      "google.cloud.storage.object.v1.finalized",
    ],
    storageDeleted: ["google.storage.object.delete", "google.cloud.storage.object.v1.deleted"],
    storageMetadataUpdated: [
      "google.storage.object.metadataUpdate",
      "google.cloud.storage.object.v1.metadataUpdated",
    ],
    storageArchived: ["google.storage.object.archive", "google.cloud.storage.object.v1.archived"],
    authCreated: ["providers/firebase.auth/eventTypes/user.create", null],
    authDeleted: ["providers/firebase.auth/eventTypes/user.delete", null],
    pubsubPublished: [
      "google.pubsub.topic.publish",
      "google.cloud.pubsub.topic.v1.messagePublished",
    ],
  };
  for (const [stem, generations] of Object.entries(expectedTypes)) {
    for (const [index, expected] of generations.entries()) {
      if (!expected) continue;
      const name = `${stem}V${index + 1}`;
      assert.equal(fixture[name].__endpoint.platform, `gcfv${index + 1}`, name);
      assert.equal(fixture[name].__endpoint.eventTrigger.eventType, expected, name);
    }
  }
});

test("the fixture retains raw event identity, time, resource, and document fields", () => {
  const { firestoreData, v1Context, v2Event } = require(reportPath);
  const before = {
    exists: true,
    id: "doc-1",
    ref: { path: "fe_events_primary/doc-1" },
    data: () => ({ value: "before", count: 1 }),
    createTime: { seconds: 101, nanoseconds: 2 },
    updateTime: { seconds: 102, nanoseconds: 3 },
  };
  const after = {
    ...before,
    data: () => ({ value: "after", count: 2 }),
    updateTime: { seconds: 103, nanoseconds: 4 },
  };
  const payload = firestoreData({ before, after });
  assert.deepEqual(payload.before.data, { value: "before", count: 1 });
  assert.deepEqual(payload.after.data, { value: "after", count: 2 });
  assert.deepEqual(payload.after.updateTime, { seconds: 103, nanoseconds: 4 });
  assert.equal(payload.after.path, "fe_events_primary/doc-1");
  const context = v1Context({
    eventId: "raw-v1-id",
    timestamp: "2026-09-27T00:00:00.123Z",
    eventType: "providers/cloud.firestore/eventTypes/document.update",
    resource: {
      name: "projects/demo-conformance/databases/(default)/documents/fe_events_primary/doc-1",
    },
    params: { documentId: "doc-1" },
  });
  assert.equal(context.eventId, "raw-v1-id");
  assert.equal(context.timestamp, "2026-09-27T00:00:00.123Z");
  assert.equal(context.resource.name.includes("doc-1"), true);
  const event = v2Event(
    {
      id: "raw-v2-id",
      time: "2026-09-27T00:00:01.456Z",
      type: "google.cloud.firestore.document.v1.updated",
      source: "//firestore.googleapis.com/projects/demo-conformance/databases/(default)",
      subject: "documents/fe_events_primary/doc-1",
      params: { documentId: "doc-1" },
    },
    payload,
  );
  assert.equal(event.id, "raw-v2-id");
  assert.equal(event.time, "2026-09-27T00:00:01.456Z");
  assert.equal(event.data.after.data.value, "after");
});
