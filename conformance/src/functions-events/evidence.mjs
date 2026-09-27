import { createHash } from "node:crypto";
import { validateCorpus } from "./corpus.mjs";

const roles = [
  "collection-primary",
  "collection-control",
  "bucket-primary",
  "bucket-control",
  "auth-project",
  "topic-primary",
  "topic-control",
];
const rejected = () => new Error("delivery evidence rejected");
const require = (condition) => {
  if (!condition) throw rejected();
};
const object = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const keys = (value, expected) =>
  object(value) &&
  Object.keys(value).length === expected.length &&
  expected.every((key) => Object.hasOwn(value, key));
const text = (value) =>
  typeof value === "string" &&
  value.length > 0 &&
  value.length <= 2048 &&
  !/[\u0000-\u001f]/.test(value);
const integer = (value) => Number.isSafeInteger(value) && value >= 0;
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const ownData = (value, key) =>
  object(value) && Object.hasOwn(Object.getOwnPropertyDescriptor(value, key) ?? {}, "value");
const frozenCorpusSha256 = "b9074dd1df4adf8c1c270ca06d7c2a417a286258b0de6eba8bdc4d6315acac26";
const frozenClosureSha256 = "c572c54905e3e9e8eb7cff01d05f79111975269534f97e99a9eb17cd927ed171";

/** Check adapter claims and raw-byte integrity only; native semantics and capture provenance remain unverified. */
export function validateDeliveryEvidence(inputCorpus, inputClosure, binding, record) {
  try {
    const corpusJson = JSON.stringify(inputCorpus);
    const closureJson = JSON.stringify(inputClosure);
    require(typeof corpusJson === "string" && Buffer.byteLength(corpusJson) <= 2 * 1024 * 1024);
    require(typeof closureJson === "string" && Buffer.byteLength(closureJson) <= 1024 * 1024);
    require(hash(corpusJson) === frozenCorpusSha256 && hash(closureJson) === frozenClosureSha256);
    const corpus = JSON.parse(corpusJson);
    const closure = JSON.parse(closureJson);
    validateCorpus(corpus, closure);
    require(keys(binding, ["runId", "recordingId", "handlerId", "resources", "entities"]));
    require([binding.runId, binding.recordingId, binding.handlerId].every(text));
    require(keys(binding.resources, roles) && Object.values(binding.resources).every(text));
    require(new Set(Object.values(binding.resources)).size === roles.length);
    require(
      keys(binding.entities, ["subject", "before", "after"]) &&
        Object.values(binding.entities).every(text),
    );
    require(new Set(Object.values(binding.entities)).size === 3);
    require(
      keys(record, [
        "schema",
        "corpusSha256",
        "caseId",
        "runId",
        "recordingId",
        "operations",
        "window",
        "capture",
      ]),
    );
    require(
      record.schema === "functions-event-delivery-evidence-v1" &&
        record.corpusSha256 === hash(JSON.stringify(corpus)),
    );
    require(record.runId === binding.runId && record.recordingId === binding.recordingId);
    const row = corpus.cases.find((candidate) => candidate.id === record.caseId);
    require(Boolean(row));
    const negative = row.delivery === "none-in-window",
      retry = row.delivery === "failed-then-succeeded-same-event";
    const operationIds = negative ? ["subject", "before", "after"] : ["subject"];
    require(Array.isArray(record.operations) && record.operations.length === operationIds.length);
    require(new Set(record.operations.map((op) => op.id)).size === operationIds.length);
    let rawBytes = 0;
    function blob(value) {
      require(
        keys(value, ["base64", "sha256"]) &&
          typeof value.base64 === "string" &&
          value.base64.length <= 1398104,
      );
      require(typeof value.sha256 === "string" && /^[a-f0-9]{64}$/.test(value.sha256));
      const bytes = Buffer.from(value.base64, "base64");
      require(
        bytes.length > 0 &&
          bytes.length <= 1024 * 1024 &&
          bytes.toString("base64") === value.base64,
      );
      rawBytes += bytes.length;
      require(rawBytes <= 16 * 1024 * 1024 && hash(bytes) === value.sha256);
    }
    const operations = new Map();
    for (const op of record.operations) {
      require(
        keys(op, [
          "id",
          "scenarioId",
          "resourceRole",
          "resource",
          "entity",
          "startedMs",
          "endedMs",
          "result",
          "receipt",
          "readbacks",
          "preconditions",
        ]),
      );
      require(operationIds.includes(op.id));
      const scenarioId = op.id === "subject" ? row.scenario : row.positiveControlScenario;
      const scenario = corpus.scenarios.find((candidate) => candidate.id === scenarioId);
      require(op.scenarioId === scenarioId && op.resourceRole === scenario.resource);
      require(
        op.resource === binding.resources[scenario.resource] &&
          op.entity === binding.entities[op.id],
      );
      require(
        op.result === scenario.sourceResult &&
          integer(op.startedMs) &&
          integer(op.endedMs) &&
          op.startedMs <= op.endedMs,
      );
      blob(op.receipt);
      require(
        keys(op.readbacks, scenario.readback) && keys(op.preconditions, scenario.preconditions),
      );
      for (const value of [...Object.values(op.readbacks), ...Object.values(op.preconditions)])
        blob(value);
      operations.set(op.id, op);
    }
    const subject = operations.get("subject"),
      window = record.window,
      capture = record.capture;
    require(keys(window, ["startMs", "endMs"]) && integer(window.startMs) && integer(window.endMs));
    require(window.startMs === subject.endedMs && window.endMs >= window.startMs);
    const duration = window.endMs - window.startMs;
    require(duration <= row.window.maximumSeconds * 1000);
    if (negative) require(duration === row.window.maximumSeconds * 1000);
    require(
      keys(capture, [
        "clockId",
        "startedMs",
        "endedMs",
        "baselineCursor",
        "endCursor",
        "lossStart",
        "lossEnd",
        "baselineReceipt",
        "endReceipt",
        "frames",
      ]),
    );
    require(text(capture.clockId) && integer(capture.startedMs) && integer(capture.endedMs));
    require(capture.startedMs < Math.min(...record.operations.map((op) => op.startedMs)));
    require(
      capture.endedMs >= Math.max(window.endMs, ...record.operations.map((op) => op.endedMs)),
    );
    require(integer(capture.baselineCursor) && integer(capture.endCursor));
    require(capture.lossStart === 0 && capture.lossEnd === 0);
    blob(capture.baselineReceipt);
    blob(capture.endReceipt);
    require(
      Array.isArray(capture.frames) && capture.frames.length > 0 && capture.frames.length <= 10000,
    );
    require(capture.endCursor === capture.baselineCursor + capture.frames.length);
    let previousTime = capture.startedMs;
    const events = [],
      eventOwners = new Map();
    for (const [index, frame] of capture.frames.entries()) {
      require(frame.cursor === capture.baselineCursor + index + 1 && integer(frame.cursor));
      require(integer(frame.atMs) && frame.atMs >= previousTime && frame.atMs <= capture.endedMs);
      previousTime = frame.atMs;
      blob(frame.raw);
      if (frame.kind === "barrier") {
        require(keys(frame, ["cursor", "atMs", "kind", "raw"]));
        continue;
      }
      require(
        keys(frame, [
          "cursor",
          "atMs",
          "kind",
          "runId",
          "recordingId",
          "operationId",
          "handlerId",
          "generation",
          "handlerEvent",
          "handlerResource",
          "source",
          "resource",
          "entity",
          "eventSource",
          "eventId",
          "eventTime",
          "outcome",
          "raw",
        ]),
      );
      require(
        frame.kind === "event" &&
          frame.runId === binding.runId &&
          frame.recordingId === binding.recordingId,
      );
      require(
        frame.handlerId === binding.handlerId &&
          frame.generation === row.generation &&
          frame.handlerEvent === row.handlerEvent,
      );
      require(
        frame.handlerResource === binding.resources[row.handlerResource] &&
          frame.source === row.source,
      );
      const op = operations.get(frame.operationId);
      require(
        Boolean(op) &&
          frame.resource === op.resource &&
          frame.entity === op.entity &&
          frame.atMs >= op.startedMs,
      );
      // These are lossless adapter claims; native timestamp/URI semantics are checked by future source adapters.
      require(text(frame.eventSource) && text(frame.eventId) && text(frame.eventTime));
      require(["failed", "succeeded"].includes(frame.outcome));
      const identity = JSON.stringify([frame.eventSource, frame.eventId]);
      require(!eventOwners.has(identity) || eventOwners.get(identity) === frame.operationId);
      eventOwners.set(identity, frame.operationId);
      events.push(frame);
    }
    const last = capture.frames.at(-1);
    require(last.kind === "barrier" && last.atMs === capture.endedMs);
    const subjectEvents = events.filter((event) => event.operationId === "subject");
    if (negative) {
      // Every captured event is inspected, including late observations after the finite window.
      require(subjectEvents.length === 0);
      require(
        operations.get("before").endedMs < subject.startedMs &&
          operations.get("after").startedMs > window.endMs,
      );
      require(
        events.some(
          (event) =>
            event.operationId === "before" &&
            event.outcome === "succeeded" &&
            event.atMs < subject.startedMs,
        ),
      );
      require(
        events.some(
          (event) =>
            event.operationId === "after" &&
            event.outcome === "succeeded" &&
            event.atMs > window.endMs,
        ),
      );
    } else {
      const inWindow = subjectEvents.filter((event) => event.atMs <= window.endMs);
      require(inWindow.some((event) => event.outcome === "succeeded"));
      if (retry) {
        require(
          subjectEvents.every(
            (event) =>
              event.eventSource === subjectEvents[0].eventSource &&
              event.eventId === subjectEvents[0].eventId &&
              event.eventTime === subjectEvents[0].eventTime,
          ),
        );
        require(
          inWindow.some(
            (event, index) =>
              event.outcome === "failed" &&
              inWindow.slice(index + 1).some((later) => later.outcome === "succeeded"),
          ),
        );
      }
    }
    return Object.freeze({
      status: "evidence-consistent",
      caseId: row.id,
      subjectEvents: subjectEvents.length,
      rawBytes,
      semanticAdaptersVerified: false,
      compatibilityEstablished: false,
      absenceEstablished: false,
      sendAuthorized: false,
    });
  } catch {
    throw rejected();
  }
}

/** Check completeness of two supplied recording declarations; capture provenance remains unverified. */
export function validateRecordingSet(corpus, closure, recordings) {
  try {
    require(object(corpus) && Array.isArray(corpus.cases) && corpus.cases.length === 109);
    require(
      object(closure) && Array.isArray(closure.conditions) && closure.conditions.length === 22,
    );
    const corpusJson = JSON.stringify(corpus);
    const closureJson = JSON.stringify(closure);
    require(typeof corpusJson === "string" && Buffer.byteLength(corpusJson) <= 2 * 1024 * 1024);
    require(typeof closureJson === "string" && Buffer.byteLength(closureJson) <= 1024 * 1024);
    require(hash(corpusJson) === frozenCorpusSha256 && hash(closureJson) === frozenClosureSha256);
    const frozenCorpus = JSON.parse(corpusJson);
    const frozenClosure = JSON.parse(closureJson);
    validateCorpus(frozenCorpus, frozenClosure);
    require(Array.isArray(recordings) && recordings.length === 2);
    for (const group of recordings) {
      require(keys(group, ["runId", "recordingId", "cases"]));
      require(["runId", "recordingId", "cases"].every((key) => ownData(group, key)));
      require(text(group.runId) && text(group.recordingId));
      require(Array.isArray(group.cases) && group.cases.length === frozenCorpus.cases.length);
    }
    require(recordings[0].runId !== recordings[1].runId);
    require(recordings[0].recordingId !== recordings[1].recordingId);
    const expected = new Set(frozenCorpus.cases.map((row) => row.id));
    for (const group of recordings) {
      const seen = new Set();
      for (const entry of group.cases) {
        require(keys(entry, ["binding", "record"]));
        require(ownData(entry, "binding") && ownData(entry, "record"));
        const { binding, record } = entry;
        require(object(binding) && object(record));
        require(ownData(binding, "runId") && ownData(binding, "recordingId"));
        require(ownData(record, "runId") && ownData(record, "recordingId"));
        require(ownData(record, "caseId"));
        require(binding.runId === group.runId && record.runId === group.runId);
        require(
          binding.recordingId === group.recordingId && record.recordingId === group.recordingId,
        );
        const caseId = record.caseId;
        require(expected.has(caseId) && !seen.has(caseId));
        seen.add(caseId);
        const result = validateDeliveryEvidence(frozenCorpus, frozenClosure, binding, record);
        require(
          result.status === "evidence-consistent" &&
            result.caseId === caseId &&
            result.compatibilityEstablished === false,
        );
        require(result.absenceEstablished === false && result.sendAuthorized === false);
      }
      require(seen.size === expected.size);
    }
    return Object.freeze({
      status: "declared-evidence-set-consistent",
      recordingCount: 2,
      caseCountPerRecording: expected.size,
      semanticAdaptersVerified: false,
      compatibilityEstablished: false,
      absenceEstablished: false,
      sendAuthorized: false,
    });
  } catch {
    throw rejected();
  }
}
