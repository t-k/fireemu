import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
process.env.GCLOUD_PROJECT = "demo-conformance";
for (const name of [
  "FIRESTORE_EMULATOR_HOST",
  "FIREBASE_STORAGE_EMULATOR_HOST",
  "FIREBASE_AUTH_EMULATOR_HOST",
  "PUBSUB_EMULATOR_HOST",
])
  process.env[name] = "127.0.0.1:1";
const fixturePath = fileURLToPath(
  new URL("../functions-events/fixtures/index.js", import.meta.url),
);
const reportPath = fileURLToPath(
  new URL("../functions-events/fixtures/report.js", import.meta.url),
);
const fixtureDir = fileURLToPath(new URL("../functions-events/fixtures/", import.meta.url));
const manifest = JSON.parse(
  readFileSync(fileURLToPath(new URL("../functions-events/programs.json", import.meta.url))),
);

function productionDiscovery(overrides = {}) {
  const env = { ...process.env };
  for (const name of Object.keys(env)) {
    if (name.startsWith("FE_EVENTS_") || name.endsWith("_EMULATOR_HOST")) delete env[name];
  }
  Object.assign(env, {
    FE_EVENTS_MODE: "production",
    FE_EVENTS_PROJECT_ID: "demo-events-prod",
    GCLOUD_PROJECT: "demo-events-prod",
    FE_EVENTS_PRIMARY_COLLECTION: "fe_events_primary",
    FE_EVENTS_PRIMARY_BUCKET: "demo-events-prod.firebasestorage.app",
    FE_EVENTS_PRIMARY_TOPIC: "fe-events-primary",
    FE_EVENTS_CAPTURE_MODE: "reject-canary",
    ...overrides,
  });
  return spawnSync(
    process.execPath,
    [
      "-e",
      "const f=require('./index.js'); console.log(JSON.stringify({names:Object.keys(f),v1:f.fsCreatedV1.__endpoint.eventTrigger,v2:f.fsCreatedV2.__endpoint.eventTrigger}));",
    ],
    { cwd: fixtureDir, env, encoding: "utf8", timeout: 10_000 },
  );
}

test("production discovery loads the same event handlers for an explicit project", () => {
  const result = productionDiscovery();
  assert.equal(result.status, 0, result.stderr);
  const discovered = JSON.parse(result.stdout);
  assert.equal(discovered.names.length, 22);
  assert.match(JSON.stringify(discovered.v1), /fe_events_primary/);
  assert.match(JSON.stringify(discovered.v2), /fe_events_primary/);
});

test("production discovery rejects a different target or any emulator host", () => {
  for (const overrides of [
    { GCLOUD_PROJECT: "another-project" },
    { FE_EVENTS_PROJECT_ID: "another-project" },
    { FIRESTORE_EMULATOR_HOST: "127.0.0.1:8080" },
    { FIREBASE_STORAGE_EMULATOR_HOST: "127.0.0.1:9199" },
    { STORAGE_EMULATOR_HOST: "http://127.0.0.1:9199" },
    { GCP_PROJECT: "another-project" },
    { FIREBASE_CONFIG: '{"projectId":"another-project"}' },
  ]) {
    const result = productionDiscovery(overrides);
    assert.notEqual(result.status, 0, JSON.stringify(overrides));
    assert.doesNotMatch(result.stderr, /another-project|fireemu-oracle|Bearer /);
  }
});

test("production discovery requires exact resources and a rejecting canary capture", () => {
  for (const overrides of [
    { FE_EVENTS_PRIMARY_COLLECTION: "" },
    { FE_EVENTS_PRIMARY_BUCKET: "other-project.firebasestorage.app" },
    { FE_EVENTS_PRIMARY_TOPIC: "" },
    { FE_EVENTS_CAPTURE_MODE: "" },
    { FE_EVENTS_CAPTURE_MODE: "other" },
    { FE_EVENTS_CAPTURE_MODE: "stdout", FE_EVENTS_CAPTURE_SOCKET: "/tmp/example.sock" },
    { FE_EVENTS_CAPTURE_MODE: "socket", FE_EVENTS_CAPTURE_SOCKET: "/tmp/example.sock" },
    { FE_EVENTS_CAPTURE_SOCKET: "/tmp/example.sock" },
  ]) {
    const result = productionDiscovery(overrides);
    assert.notEqual(result.status, 0, JSON.stringify(overrides));
  }
});

test("production discovery accepts the stdout capture of the delivery probe", () => {
  const result = productionDiscovery({ FE_EVENTS_CAPTURE_MODE: "stdout" });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).names.length, 22);
});

test("stdout capture prints exactly one FE_EVENTS_FRAME line per event", async () => {
  const { report } = require(reportPath);
  const previous = process.env.FE_EVENTS_CAPTURE_MODE;
  const lines = [];
  const log = console.log;
  process.env.FE_EVENTS_CAPTURE_MODE = "stdout";
  console.log = (line) => lines.push(line);
  try {
    await report({ handler: "fsCreatedV2", generation: 2, event: { id: "e1" } });
  } finally {
    console.log = log;
    if (previous === undefined) delete process.env.FE_EVENTS_CAPTURE_MODE;
    else process.env.FE_EVENTS_CAPTURE_MODE = previous;
  }
  assert.equal(lines.length, 1);
  assert.match(lines[0], /^FE_EVENTS_FRAME \{.*\}$/);
  assert.deepEqual(JSON.parse(lines[0].slice("FE_EVENTS_FRAME ".length)), {
    handler: "fsCreatedV2",
    generation: 2,
    event: { id: "e1" },
  });
});

test("canary capture rejects an unexpected event without serializing its payload", async () => {
  const { report } = require(reportPath);
  const previous = process.env.FE_EVENTS_CAPTURE_MODE;
  const circular = { secret: "synthetic-secret" };
  circular.self = circular;
  process.env.FE_EVENTS_CAPTURE_MODE = "reject-canary";
  try {
    await assert.rejects(() => report(circular), /canary capture rejects events/);
  } finally {
    if (previous === undefined) delete process.env.FE_EVENTS_CAPTURE_MODE;
    else process.env.FE_EVENTS_CAPTURE_MODE = previous;
  }
});

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

test("stdout capture adds the event and context member listing; other modes keep the frame bytes", () => {
  const { v1Context, v2Event } = require(reportPath);
  const context = {
    eventId: "id-1",
    timestamp: "2026-09-30T12:00:00.000Z",
    eventType: "google.storage.object.finalize",
    resource: { service: "storage.googleapis.com", name: "projects/_/buckets/b/objects/o#1" },
    params: {},
    authType: undefined,
    authId: undefined,
    extraFlag: true,
    extraCount: 7,
    extraNote: "x".repeat(300),
    extraObject: { token: "must-not-be-printed", uid: "u" },
    extraList: [1, 2, 3],
  };
  const event = {
    id: "e",
    time: "2026-09-30T12:00:00Z",
    type: "google.cloud.storage.object.v1.finalized",
    source: "//storage.googleapis.com/projects/_/buckets/b",
    subject: "objects/o",
    specversion: "1.0",
    bucket: "b",
    location: "us-central1",
    data: { name: "o" },
  };
  const previous = process.env.FE_EVENTS_CAPTURE_MODE;
  try {
    for (const mode of [undefined, "socket", "reject-canary"]) {
      if (mode === undefined) delete process.env.FE_EVENTS_CAPTURE_MODE;
      else process.env.FE_EVENTS_CAPTURE_MODE = mode;
      assert.equal(Object.hasOwn(v1Context(context), "contextKeys"), false, String(mode));
      assert.equal(Object.hasOwn(v1Context(context), "contextExtras"), false, String(mode));
      assert.equal(Object.hasOwn(v2Event(event, null), "eventKeys"), false, String(mode));
      assert.equal(Object.hasOwn(v2Event(event, null), "extensionAttributes"), false, String(mode));
    }
    process.env.FE_EVENTS_CAPTURE_MODE = "stdout";
    const printedContext = v1Context(context);
    assert.deepEqual(printedContext.contextKeys, [
      "authId", "authType", "eventId", "eventType", "extraCount", "extraFlag", "extraList",
      "extraNote", "extraObject", "params", "resource", "timestamp",
    ]);
    assert.deepEqual(printedContext.contextExtras, {
      extraCount: 7,
      extraFlag: true,
      extraList: { type: "array", length: 3 },
      extraNote: { type: "string", length: 300 },
      extraObject: { type: "object", keys: ["token", "uid"] },
    });
    assert.equal(JSON.stringify(printedContext).includes("must-not-be-printed"), false);
    const printedEvent = v2Event(event, { name: "o" });
    assert.deepEqual(printedEvent.eventKeys, [
      "bucket", "data", "id", "location", "source", "specversion", "subject", "time", "type",
    ]);
    assert.deepEqual(printedEvent.extensionAttributes, { bucket: "b", location: "us-central1" });
    assert.deepEqual(printedEvent.data, { name: "o" });
  } finally {
    if (previous === undefined) delete process.env.FE_EVENTS_CAPTURE_MODE;
    else process.env.FE_EVENTS_CAPTURE_MODE = previous;
  }
});

test("Firestore snapshots do not require the local SDK readTime getter", () => {
  const { firestoreData } = require(reportPath);
  const value = {
    exists: true,
    id: "doc-1",
    ref: { path: "fe_events_primary/doc-1" },
    data: () => ({ value: "after" }),
    createTime: { seconds: 101 },
    updateTime: { seconds: 102 },
    get readTime() {
      throw new Error("readTime is unavailable on a local document");
    },
  };
  const captured = firestoreData(value);
  assert.deepEqual(captured.updateTime, { seconds: 102 });
  assert.equal(Object.hasOwn(captured, "readTime"), false);
});

test("the retry handler ignores other Firestore programs", async () => {
  const fixture = require(fixturePath);
  await fixture.fsRetryV2.run({
    id: "ordinary-event",
    time: "2026-09-27T00:00:00Z",
    data: {
      before: null,
      after: {
        exists: true,
        id: "ordinary-doc",
        ref: { path: "fe_events_primary/ordinary-doc" },
        data: () => ({ value: "ordinary" }),
      },
    },
  });
});

test("retry cannot initialize Admin Firestore without a loopback emulator", async () => {
  const fixture = require(fixturePath);
  const original = process.env.FIRESTORE_EMULATOR_HOST;
  const retry = {
    id: "retry-event",
    time: "2026-09-27T00:00:00Z",
    data: {
      before: null,
      after: {
        exists: true,
        id: "retry-doc",
        ref: { path: "fe_events_primary/retry-doc" },
        data: () => ({ fixtureKind: "retry" }),
      },
    },
  };
  try {
    for (const host of [undefined, "firestore.googleapis.com:443", "localhost.evil.com:8080"]) {
      if (host === undefined) delete process.env.FIRESTORE_EMULATOR_HOST;
      else process.env.FIRESTORE_EMULATOR_HOST = host;
      await assert.rejects(fixture.fsRetryV2.run(retry), /loopback Firestore emulator/);
    }
  } finally {
    if (original === undefined) delete process.env.FIRESTORE_EMULATOR_HOST;
    else process.env.FIRESTORE_EMULATOR_HOST = original;
  }
});

test("fixture service hosts must all be loopback before SDK initialization", () => {
  const { assertLocalEnvironment } = require("../functions-events/fixtures/local-host.js");
  const valid = Object.fromEntries(
    [
      "FIRESTORE_EMULATOR_HOST",
      "FIREBASE_STORAGE_EMULATOR_HOST",
      "FIREBASE_AUTH_EMULATOR_HOST",
      "PUBSUB_EMULATOR_HOST",
    ].map((name) => [name, "127.0.0.1:1234"]),
  );
  assert.doesNotThrow(() => assertLocalEnvironment(valid));
  assert.doesNotThrow(() =>
    assertLocalEnvironment({
      ...valid,
      STORAGE_EMULATOR_HOST: "http://fireemu:synthetic-local-secret@127.0.0.1:1234",
    }),
  );
  for (const name of Object.keys(valid)) {
    for (const bad of [undefined, "firestore.googleapis.com:443", "localhost.evil.com:8080"]) {
      assert.throws(() => assertLocalEnvironment({ ...valid, [name]: bad }), /loopback emulator/);
    }
  }
  assert.throws(
    () =>
      assertLocalEnvironment({
        ...valid,
        STORAGE_EMULATOR_HOST: "https://storage.googleapis.com",
      }),
    /loopback emulator/,
  );
});
