import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { validateNativeFirestoreV2Evidence } from "./functions-events/native_evidence.mjs";

const read = (path) => JSON.parse(readFileSync(new URL(path, import.meta.url)));
const corpus = read("../functions-events/corpus.json");
const closure = read("../../spec/compatibility/closure/FUNCTIONS-EVENTS.json");
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const blob = (value = "synthetic") => {
  const bytes = Buffer.from(typeof value === "string" ? value : JSON.stringify(value));
  return { base64: bytes.toString("base64"), sha256: hash(bytes) };
};
const caseRow = (id) => corpus.cases.find((row) => row.id === id);
const scenario = (id) => corpus.scenarios.find((item) => item.id === id);
const created = "FUNCTIONS-EVENTS/firestore-created#new-document#v2";
const negative = "FUNCTIONS-EVENTS/firestore-noop#same-value-write-no-event#v2";
const retry = "FUNCTIONS-EVENTS/delivery-retry-identity#handler-failure#v2";
const authContexts = corpus.cases.filter(
  (row) =>
    row.source === "firestore" &&
    row.generation === 2 &&
    row.handlerEvent === "written-with-auth-context",
);

function fixture(row) {
  const absent = row.delivery === "none-in-window";
  const repeated = row.delivery === "failed-then-succeeded-same-event";
  const binding = {
    runId: "run-one",
    recordingId: "recording-one",
    handlerId: "handler-one",
    resources: {
      "collection-primary": "projects/project-a/databases/(default)/documents/tasks",
      "collection-control": "projects/project-a/databases/(default)/documents/controls",
      "bucket-primary": "bucket-primary",
      "bucket-control": "bucket-control",
      "auth-project": "auth-project",
      "topic-primary": "topic-primary",
      "topic-control": "topic-control",
    },
    entities: { subject: "subject", before: "before", after: "after" },
  };
  const window = { startMs: 40, endMs: absent ? 40 + row.window.maximumSeconds * 1000 : 100 };
  function operation(id, scenarioId, startedMs, endedMs) {
    const source = scenario(scenarioId);
    return {
      id,
      scenarioId,
      resourceRole: source.resource,
      resource: binding.resources[source.resource],
      entity: binding.entities[id],
      startedMs,
      endedMs,
      result: source.sourceResult,
      receipt: blob(),
      readbacks: Object.fromEntries(source.readback.map((key) => [key, blob()])),
      preconditions: Object.fromEntries(source.preconditions.map((key) => [key, blob()])),
    };
  }
  const operations = [operation("subject", row.scenario, 30, 40)];
  if (absent)
    operations.push(
      operation("before", row.positiveControlScenario, 5, 10),
      operation("after", row.positiveControlScenario, window.endMs + 10, window.endMs + 20),
    );
  function event(operationId, atMs, outcome = "succeeded") {
    const op = operations.find((item) => item.id === operationId);
    const document = `tasks/${op.entity}`;
    const documentName = `projects/project-a/databases/(default)/documents/${document}`;
    const eventId = `event-${operationId}`;
    const eventTime = "2026-09-27T00:00:00Z";
    const kind = row.handlerEvent === "written-with-auth-context" ? "written" : row.handlerEvent;
    const native = {
      specversion: "1.0",
      id: eventId,
      source: documentName,
      subject: `documents/${document}`,
      type: `google.cloud.firestore.document.v1.${kind}`,
      time: eventTime,
      datacontenttype: "application/json",
      project: "project-a",
      database: "(default)",
      document,
      data: {},
    };
    if (row.handlerEvent === "written-with-auth-context") {
      native.type += ".withAuthContext";
      native.authtype = "USER";
    }
    return {
      kind: "event",
      atMs,
      runId: binding.runId,
      recordingId: binding.recordingId,
      operationId,
      handlerId: binding.handlerId,
      generation: row.generation,
      handlerEvent: row.handlerEvent,
      handlerResource: binding.resources[row.handlerResource],
      source: row.source,
      resource: op.resource,
      entity: op.entity,
      eventSource: documentName,
      eventId,
      eventTime,
      outcome,
      raw: blob(native),
    };
  }
  const frames = absent
    ? [event("before", 20), event("after", window.endMs + 30)]
    : repeated
      ? [event("subject", 50, "failed"), event("subject", 60)]
      : [event("subject", 50)];
  const endedMs = absent ? window.endMs + 40 : 100;
  frames.push({ kind: "barrier", atMs: endedMs, raw: blob() });
  frames.forEach((frame, index) => {
    frame.cursor = index + 6;
  });
  return {
    binding,
    record: {
      schema: "functions-event-delivery-evidence-v1",
      corpusSha256: hash(JSON.stringify(corpus)),
      caseId: row.id,
      runId: binding.runId,
      recordingId: binding.recordingId,
      operations,
      window,
      capture: {
        clockId: "clock-one",
        startedMs: 0,
        endedMs,
        baselineCursor: 5,
        endCursor: 5 + frames.length,
        lossStart: 0,
        lossEnd: 0,
        baselineReceipt: blob(),
        endReceipt: blob(),
        frames,
      },
    },
  };
}

const check = (value) =>
  validateNativeFirestoreV2Evidence(corpus, closure, value.binding, value.record);

test("positive Firestore v2 record verifies one native frame without authority", () => {
  const result = check(fixture(caseRow(created)));
  assert.equal(result.status, "native-firestore-v2-evidence-consistent");
  assert.equal(result.nativeFramesVerified, 1);
  assert.equal(result.nativeFrameConsistencyVerified, true);
  assert.equal(result.semanticAdaptersVerified, false);
  assert.equal(result.captureProvenanceVerified, false);
  assert.equal(result.compatibilityEstablished, false);
  assert.equal(result.absenceEstablished, false);
  assert.equal(result.sendAuthorized, false);
});

test("negative controls and retry attempts all require native frames", () => {
  assert.equal(check(fixture(caseRow(negative))).nativeFramesVerified, 2);
  assert.equal(check(fixture(caseRow(retry))).nativeFramesVerified, 2);
});

test("Auth context frame requires the written event suffix and auth type", () => {
  assert.equal(authContexts.length, 3);
  for (const row of authContexts) {
    const value = fixture(row);
    assert.equal(check(value).nativeFramesVerified, 1);
    const frame = value.record.capture.frames[0];
    const native = JSON.parse(Buffer.from(frame.raw.base64, "base64"));
    delete native.authtype;
    frame.raw = blob(native);
    assert.throws(() => check(value));
    native.authtype = "USER";
    native.type = "google.cloud.firestore.document.v1.written";
    frame.raw = blob(native);
    assert.throws(() => check(value));
  }
});

test("raw event and adapter claim mismatch are rejected after base validation", () => {
  for (const mutation of [
    (frame) => {
      frame.eventId = "other";
    },
    (frame) => {
      frame.eventTime = "2026-09-28T00:00:00Z";
    },
    (frame) => {
      const native = JSON.parse(Buffer.from(frame.raw.base64, "base64"));
      native.id = "other";
      frame.raw = blob(native);
    },
  ]) {
    const value = fixture(caseRow(created));
    mutation(value.record.capture.frames[0]);
    assert.throws(() => check(value));
  }
});

test("every negative control frame is checked", () => {
  for (const index of [0, 1]) {
    const value = fixture(caseRow(negative));
    value.record.capture.frames[index].eventId = "other";
    assert.throws(() => check(value));
  }
});

test("invalid base evidence and non-Firestore-v2 rows are rejected", () => {
  const value = fixture(caseRow(created));
  value.record.window.startMs++;
  assert.throws(() => check(value));
  const v1 = corpus.cases.find((row) => row.source === "firestore" && row.generation === 1);
  assert.throws(() => check(fixture(v1)));
  const storage = corpus.cases.find((row) => row.source === "storage" && row.generation === 2);
  assert.throws(() => check(fixture(storage)));
});
