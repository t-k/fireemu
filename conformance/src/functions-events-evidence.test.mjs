import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import * as evidence from "./functions-events/evidence.mjs";

const { validateDeliveryEvidence } = evidence;

const read = (path) => JSON.parse(readFileSync(new URL(path, import.meta.url)));
const corpus = read("../functions-events/corpus.json");
const closure = read("../../spec/compatibility/closure/FUNCTIONS-EVENTS.json");
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const blob = (text = "synthetic raw evidence") => ({
  base64: Buffer.from(text).toString("base64"),
  sha256: digest(text),
});
const scenario = (id, sourceCorpus = corpus) => sourceCorpus.scenarios.find((s) => s.id === id);

function fixture(row, runId = "run-1", recordingId = "recording-1", sourceCorpus = corpus) {
  const negative = row.delivery === "none-in-window";
  const retry = row.delivery === "failed-then-succeeded-same-event";
  const binding = {
    runId,
    recordingId,
    handlerId: "handler-1",
    resources: Object.fromEntries(
      [
        "collection-primary",
        "collection-control",
        "bucket-primary",
        "bucket-control",
        "auth-project",
        "topic-primary",
        "topic-control",
      ].map((role) => [role, `project-1/${role}`]),
    ),
    entities: { subject: "owned/subject", before: "owned/before", after: "owned/after" },
  };
  const window = { startMs: 40, endMs: negative ? 40 + row.window.maximumSeconds * 1000 : 100 };
  function operation(id, scenarioId, startedMs, endedMs) {
    const s = scenario(scenarioId, sourceCorpus);
    return {
      id,
      scenarioId,
      resourceRole: s.resource,
      resource: binding.resources[s.resource],
      entity: binding.entities[id],
      startedMs,
      endedMs,
      result: s.sourceResult,
      receipt: blob(),
      readbacks: Object.fromEntries(s.readback.map((key) => [key, blob()])),
      preconditions: Object.fromEntries(s.preconditions.map((key) => [key, blob()])),
    };
  }
  const operations = [operation("subject", row.scenario, 30, 40)];
  if (negative)
    operations.push(
      operation("before", row.positiveControlScenario, 5, 10),
      operation("after", row.positiveControlScenario, window.endMs + 10, window.endMs + 20),
    );
  function event(op, atMs, outcome = "succeeded", eventId = `event-${op}`) {
    const operation = operations.find((o) => o.id === op);
    return {
      kind: "event",
      atMs,
      runId: binding.runId,
      recordingId: binding.recordingId,
      operationId: op,
      handlerId: binding.handlerId,
      generation: row.generation,
      handlerEvent: row.handlerEvent,
      handlerResource: binding.resources[row.handlerResource],
      source: row.source,
      resource: operation.resource,
      entity: operation.entity,
      eventSource: "//synthetic/source",
      eventId,
      eventTime: "2026-09-26T00:00:00.000Z",
      outcome,
      raw: blob(),
    };
  }
  const frames = negative
    ? [event("before", 20), event("after", window.endMs + 30)]
    : retry
      ? [event("subject", 50, "failed", "event-subject"), event("subject", 60)]
      : [event("subject", 50)];
  const endedMs = negative ? window.endMs + 40 : 100;
  frames.push({ kind: "barrier", atMs: endedMs, raw: blob() });
  frames.forEach((frame, i) => {
    frame.cursor = i + 6;
  });
  const record = {
    schema: "functions-event-delivery-evidence-v1",
    corpusSha256: digest(JSON.stringify(sourceCorpus)),
    caseId: row.id,
    runId: binding.runId,
    recordingId: binding.recordingId,
    operations,
    window,
    capture: {
      clockId: "capture-monotonic-1",
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
  };
  return { binding, record, row };
}
const positive = () => fixture(corpus.cases.find((r) => r.delivery === "at-least-one"));
const negative = () => fixture(corpus.cases.find((r) => r.case === "nonmatching-bucket"));
const retry = () =>
  fixture(corpus.cases.find((r) => r.delivery === "failed-then-succeeded-same-event"));
const check = ({ binding, record }) => validateDeliveryEvidence(corpus, closure, binding, record);

test("all frozen case forms can express evidence consistency without compatibility claims", () => {
  for (const row of corpus.cases) {
    const result = check(fixture(row));
    assert.equal(result.status, "evidence-consistent");
    assert.equal(result.caseId, row.id);
    assert.equal(result.compatibilityEstablished, false);
    assert.equal(result.absenceEstablished, false);
    assert.equal(result.sendAuthorized, false);
    assert.equal(result.semanticAdaptersVerified, false);
    assert.equal(Object.isFrozen(result), true);
  }
});

test("case evidence rejects a changed corpus even when its record digest is recomputed", () => {
  const changedCorpus = structuredClone(corpus);
  changedCorpus.scenarios.find((item) => item.id === "fs-create").mutation =
    "firestore.create-altered";
  const row = changedCorpus.cases.find((item) => item.scenario === "fs-create");
  const { binding, record } = fixture(row, "run-1", "recording-1", changedCorpus);
  assert.throws(
    () => validateDeliveryEvidence(changedCorpus, closure, binding, record),
    /delivery evidence rejected/,
  );
});

test("case evidence rejects a changed closure with the same case inventory", () => {
  const changedClosure = structuredClone(closure);
  changedClosure.scopeDecisions[0].rationale = "altered frozen decision";
  const { binding, record } = positive();
  assert.throws(
    () => validateDeliveryEvidence(corpus, changedClosure, binding, record),
    /delivery evidence rejected/,
  );
});

test("negative routing binds source and handler separately and brackets the full window", () => {
  const f = negative();
  assert.notEqual(f.record.operations[0].resource, f.record.capture.frames[0].handlerResource);
  assert.equal(check(f).subjectEvents, 0);
  for (const mutate of [
    (r) => {
      r.operations = r.operations.filter((o) => o.id !== "before");
    },
    (r) => {
      r.operations.find((o) => o.id === "after").startedMs = r.window.endMs;
    },
    (r) => {
      r.capture.frames[0].atMs = r.operations[0].startedMs;
    },
    (r) => {
      r.window.endMs--;
    },
    (r) => {
      r.capture.frames.shift();
    },
    (r) => {
      r.capture.frames[0].handlerEvent = "wrong-event";
    },
    (r) => {
      r.capture.frames[0].generation = 3;
    },
    (r) => {
      r.capture.frames[0].handlerResource = r.operations[0].resource;
    },
    (r) => {
      r.operations[0].resourceRole = "bucket-primary";
    },
  ]) {
    const value = negative();
    mutate(value.record);
    assert.throws(() => check(value), /delivery evidence rejected/);
  }
});

test("negative evidence derives matches from all frames, including frames after the window", () => {
  for (const atMs of [60, 120045]) {
    const f = negative(),
      source = f.record.operations[0];
    const entry = {
      ...structuredClone(f.record.capture.frames[0]),
      operationId: "subject",
      atMs,
      resource: source.resource,
      entity: source.entity,
      eventId: "late-subject",
    };
    f.record.capture.frames.splice(1, 0, entry);
    f.record.capture.frames.forEach((v, i) => {
      v.cursor = i + 6;
    });
    f.record.capture.endCursor++;
    assert.throws(() => check(f), /delivery evidence rejected/);
  }
});

test("gaps, capture loss, stale binding, raw corruption and missing source evidence reject", () => {
  const mutations = [
    (f) => {
      f.record.capture.frames[0].cursor++;
    },
    (f) => {
      f.record.capture.endCursor++;
    },
    (f) => {
      f.record.capture.lossEnd++;
    },
    (f) => {
      f.record.capture.lossStart = 1;
      f.record.capture.lossEnd = 1;
    },
    (f) => {
      f.record.capture.startedMs = 31;
    },
    (f) => {
      f.record.capture.endedMs = 90;
    },
    (f) => {
      f.record.capture.frames.pop();
      f.record.capture.endCursor--;
    },
    (f) => {
      f.record.runId = "other-run";
    },
    (f) => {
      f.record.corpusSha256 = "0".repeat(64);
    },
    (f) => {
      f.record.caseId = "unknown";
    },
    (f) => {
      f.record.operations.push(structuredClone(f.record.operations[0]));
    },
    (f) => {
      f.record.operations[0].receipt.sha256 = "0".repeat(64);
    },
    (f) => {
      f.record.operations[0].receipt.base64 += "!";
    },
    (f) => {
      f.record.operations[0].readbacks = {};
    },
    (f) => {
      f.record.operations[0].preconditions = {};
    },
    (f) => {
      f.record.operations[0].result = "typed-refusal";
    },
    (f) => {
      f.record.capture.frames[0].raw = blob("");
    },
    (f) => {
      f.record.capture.frames[0].entity = "outside";
    },
    (f) => {
      f.record.capture.frames[0].runId = "other-run";
    },
    (f) => {
      f.record.capture.frames[0].eventTime = "";
    },
    (f) => {
      f.record.capture.frames[0].operationId = "unknown";
    },
    (f) => {
      f.record.capture.frames[0].source = "pubsub";
    },
    (f) => {
      f.record.capture.frames[0].handlerId = "other-handler";
    },
    (f) => {
      f.binding.resources["bucket-control"] = f.binding.resources["bucket-primary"];
    },
    (f) => {
      f.record.sendAuthorized = true;
    },
  ];
  for (const mutate of mutations) {
    const f = positive();
    mutate(f);
    assert.throws(() => check(f), /delivery evidence rejected/);
  }
});

test("positive delivery requires an in-window successful subject event", () => {
  for (const mutate of [
    (f) => {
      f.record.capture.frames[0].outcome = "failed";
    },
    (f) => {
      f.record.capture.frames[0].atMs = 29;
    },
    (f) => {
      f.record.window.endMs = 49;
    },
    (f) => {
      f.record.capture.frames.shift();
      f.record.capture.frames[0].cursor = 6;
      f.record.capture.endCursor = 6;
    },
  ]) {
    const f = positive();
    mutate(f);
    assert.throws(() => check(f), /delivery evidence rejected/);
  }
});

test("retry requires the same identity and event time in failed then successful order", () => {
  assert.equal(check(retry()).subjectEvents, 2);
  for (const mutate of [
    (f) => {
      f.record.capture.frames[0].eventId = "different";
    },
    (f) => {
      f.record.capture.frames[0].eventTime = "2026-09-26T00:00:01.000Z";
    },
    (f) => {
      f.record.capture.frames[0].eventSource = "//other/source";
    },
    (f) => {
      f.record.capture.frames[0].outcome = "succeeded";
    },
    (f) => {
      f.record.capture.frames[1].outcome = "failed";
    },
    (f) => {
      f.record.capture.frames[0].outcome = "succeeded";
      f.record.capture.frames[1].outcome = "failed";
    },
    (f) => {
      delete f.record.operations[0].preconditions["retry-enabled-readback"];
    },
  ]) {
    const f = retry();
    mutate(f);
    assert.throws(() => check(f), /delivery evidence rejected/);
  }
});

test("native time strings and duplicate attempts remain unchanged and are not normalized", () => {
  for (const eventTime of ["2026-09-26T00:00:00.123456789Z", "2026-09-26T09:00:00+09:00"]) {
    const f = retry();
    for (const frame of f.record.capture.frames.filter((v) => v.kind === "event"))
      frame.eventTime = eventTime;
    const duplicate = structuredClone(f.record.capture.frames[1]);
    duplicate.atMs = 70;
    f.record.capture.frames.splice(2, 0, duplicate);
    f.record.capture.frames.forEach((v, i) => {
      v.cursor = i + 6;
    });
    f.record.capture.endCursor++;
    const saved = structuredClone(f);
    assert.equal(check(f).subjectEvents, 3);
    assert.deepEqual(f, saved);
  }
});

test("oversized evidence and excess frames reject before an unbounded scan", () => {
  const oversized = positive();
  oversized.record.operations[0].receipt = blob("x".repeat(1024 * 1024 + 1));
  assert.throws(() => check(oversized), /delivery evidence rejected/);
  const aggregate = negative(),
    large = blob("x".repeat(1024 * 1024));
  function replaceBlobs(value) {
    for (const [key, child] of Object.entries(value)) {
      if (child && typeof child === "object") {
        if (Object.hasOwn(child, "base64")) value[key] = large;
        else replaceBlobs(child);
      }
    }
  }
  replaceBlobs(aggregate.record);
  assert.throws(() => check(aggregate), /delivery evidence rejected/);
  const excess = positive();
  excess.record.capture.frames = Array.from({ length: 10001 }, (_, i) => ({
    kind: "barrier",
    atMs: 100,
    cursor: i + 6,
    raw: blob(),
  }));
  excess.record.capture.endCursor = 10006;
  assert.throws(() => check(excess), /delivery evidence rejected/);
});

function twoRecordings(sourceCorpus = corpus) {
  return [1, 2].map((index) => {
    const runId = `run-${index}`;
    const recordingId = `recording-${index}`;
    return {
      runId,
      recordingId,
      cases: sourceCorpus.cases.map((row) => {
        const { binding, record } = fixture(row, runId, recordingId, sourceCorpus);
        return { binding, record };
      }),
    };
  });
}

function retag(group, key, value) {
  group[key] = value;
  for (const entry of group.cases) {
    entry.binding[key] = value;
    entry.record[key] = value;
    for (const frame of entry.record.capture.frames) if (frame.kind === "event") frame[key] = value;
  }
}

const checkSet = (groups) => evidence.validateRecordingSet(corpus, closure, groups);

test("two declared recordings contain every frozen case once without compatibility claims", () => {
  const groups = twoRecordings();
  const result = checkSet(groups);
  assert.deepEqual(result, {
    status: "declared-evidence-set-consistent",
    recordingCount: 2,
    caseCountPerRecording: 109,
    semanticAdaptersVerified: false,
    compatibilityEstablished: false,
    absenceEstablished: false,
    sendAuthorized: false,
  });
  assert.equal(Object.isFrozen(result), true);
  assert.equal(groups[0].cases.length, 109);
  assert.equal(groups[1].cases.length, 109);
});

test("recording set rejects a corpus and closure jointly missing frozen cases", () => {
  const reducedCorpus = structuredClone(corpus);
  const reducedClosure = structuredClone(closure);
  const omitted = "FUNCTIONS-EVENTS/firestore-noop";
  reducedCorpus.cases = reducedCorpus.cases.filter((row) => row.conditionId !== omitted);
  reducedClosure.conditions = reducedClosure.conditions.filter(
    (condition) => condition.conditionId !== omitted,
  );
  assert.equal(reducedCorpus.cases.length, 107);
  assert.throws(
    () =>
      evidence.validateRecordingSet(reducedCorpus, reducedClosure, twoRecordings(reducedCorpus)),
    /delivery evidence rejected/,
  );
});

test("recording set rejects changed frozen inputs even when the case count stays 109", () => {
  const changedCorpus = structuredClone(corpus);
  changedCorpus.cases[0].handlerEvent = "different-event";
  assert.throws(
    () => evidence.validateRecordingSet(changedCorpus, closure, twoRecordings(changedCorpus)),
    /delivery evidence rejected/,
  );
  const changedClosure = structuredClone(closure);
  changedClosure.conditions[0].source = "changed-source";
  assert.throws(
    () => evidence.validateRecordingSet(corpus, changedClosure, twoRecordings()),
    /delivery evidence rejected/,
  );
});

test("recording set rejects missing, duplicate, unknown and extra case declarations", () => {
  for (const mutate of [
    (groups) => groups[0].cases.pop(),
    (groups) => {
      groups[0].cases[1] = structuredClone(groups[0].cases[0]);
    },
    (groups) => {
      groups[0].cases[0].record.caseId = "unknown";
    },
    (groups) => {
      groups[0].cases.push(structuredClone(groups[0].cases[0]));
    },
  ]) {
    const groups = twoRecordings();
    mutate(groups);
    assert.throws(() => checkSet(groups), /delivery evidence rejected/);
  }
});

test("recording set rejects reused run and recording identities", () => {
  for (const key of ["runId", "recordingId"]) {
    const groups = twoRecordings();
    retag(groups[1], key, groups[0][key]);
    assert.throws(() => checkSet(groups), /delivery evidence rejected/);
  }
});

test("recording set rejects case bindings from another recording and invalid raw evidence", () => {
  for (const mutate of [
    (groups) => {
      groups[1].cases[0] = structuredClone(groups[0].cases[0]);
    },
    (groups) => {
      const entry = groups[1].cases[0];
      entry.binding.runId = groups[0].runId;
      entry.record.runId = groups[0].runId;
      for (const frame of entry.record.capture.frames)
        if (frame.kind === "event") frame.runId = groups[0].runId;
    },
    (groups) => {
      const entry = groups[1].cases[0];
      entry.binding.recordingId = groups[0].recordingId;
      entry.record.recordingId = groups[0].recordingId;
      for (const frame of entry.record.capture.frames)
        if (frame.kind === "event") frame.recordingId = groups[0].recordingId;
    },
    (groups) => {
      groups[1].cases[0].binding.recordingId = groups[0].recordingId;
    },
    (groups) => {
      groups[1].cases[0].record.operations[0].receipt.sha256 = "0".repeat(64);
    },
  ]) {
    const groups = twoRecordings();
    mutate(groups);
    assert.throws(() => checkSet(groups), /delivery evidence rejected/);
  }
});

test("recording set rejects malformed top-level structure before any case scan", () => {
  for (const groups of [null, [], [twoRecordings()[0]], [...twoRecordings(), twoRecordings()[0]]]) {
    assert.throws(() => checkSet(groups), /delivery evidence rejected/);
  }
  const extra = twoRecordings();
  extra[0].sendAuthorized = true;
  assert.throws(() => checkSet(extra), /delivery evidence rejected/);
  const extraEntry = twoRecordings();
  extraEntry[0].cases[0].sendAuthorized = true;
  assert.throws(() => checkSet(extraEntry), /delivery evidence rejected/);
});

test("recording set cannot count one case while validating another through an accessor", () => {
  const groups = twoRecordings();
  const first = groups[0].cases[0].record.caseId;
  const duplicate = structuredClone(groups[0].cases[1]);
  let reads = 0;
  Object.defineProperty(duplicate.record, "caseId", {
    enumerable: true,
    get() {
      reads++;
      return reads <= 3 ? first : groups[0].cases[1].record.caseId;
    },
  });
  groups[0].cases[0] = duplicate;
  assert.throws(() => checkSet(groups), /delivery evidence rejected/);
});

test("recording set rejects accessor-backed group and case identities", () => {
  for (const select of [
    (groups) => [groups[0], "runId"],
    (groups) => [groups[0].cases[0], "binding"],
    (groups) => [groups[0].cases[0].binding, "runId"],
    (groups) => [groups[0].cases[0].record, "recordingId"],
    (groups) => [groups[0].cases[0].record, "caseId"],
  ]) {
    const groups = twoRecordings();
    const [target, key] = select(groups);
    const value = target[key];
    Object.defineProperty(target, key, { enumerable: true, get: () => value });
    assert.throws(() => checkSet(groups), /delivery evidence rejected/);
  }
});
