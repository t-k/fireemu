import assert from "node:assert/strict";
import { test } from "node:test";
import {
  eventTimeMs,
  fromLocalSession,
  fromProductionRun,
  parseTimeMs,
} from "./functions-events/compare/adapters.mjs";

const DIGEST = "a".repeat(64);

function v2Frame(path, time, extra = {}) {
  return {
    handler: "fsCreatedV2",
    generation: 2,
    source: "firestore",
    event: {
      id: "dc880941-8bb2-410f-9b10-51c47560a33a",
      time,
      type: "google.cloud.firestore.document.v1.created",
      subject: `documents/${path}`,
      data: { path },
      ...extra,
    },
  };
}

function operation(overrides = {}) {
  return {
    scenarioId: "fs-create",
    role: "subject",
    sourceResult: "typed-success",
    startedAt: "2026-10-04T00:00:00.000Z",
    endedAt: "2026-10-04T00:00:01.000Z",
    matchKey: { kind: "firestore", value: "fe_events_primary/eaaa" },
    readback: { exists: true },
    windowSeconds: 120,
    ...overrides,
  };
}

function run(overrides = {}) {
  return {
    schemaVersion: 1,
    kind: "functions-events-production-run",
    project: "fireemu-oracle-events",
    corpusDigest: DIGEST,
    recordedAt: "2026-10-04T00:00:00.000Z",
    passes: [
      {
        pass: 1,
        startedAt: "2026-10-04T00:00:00.000Z",
        endedAt: "2026-10-04T00:10:00.000Z",
        operations: [operation()],
      },
      {
        pass: 2,
        startedAt: "2026-10-04T00:15:00.000Z",
        endedAt: "2026-10-04T00:25:00.000Z",
        operations: [],
      },
    ],
    frames: [
      {
        insertId: "i1",
        logTimestamp: "2026-10-04T00:00:02.500000Z",
        readAt: "2026-10-04T00:00:30Z",
        handler: "fsCreatedV2",
        generation: 2,
        source: "firestore",
        frame: v2Frame("fe_events_primary/eaaa", "2026-10-04T00:00:00.500123Z"),
      },
    ],
    cleanup: {},
    deploy: {},
    ...overrides,
  };
}

test("times keep sub-millisecond precision and offsets; anything else is unparseable", () => {
  assert.equal(parseTimeMs("1970-01-01T00:00:00.000500Z"), 0.5);
  assert.equal(parseTimeMs("1970-01-01T00:00:01Z"), 1000);
  assert.equal(parseTimeMs("1970-01-01T09:00:00+09:00"), 0);
  assert.equal(parseTimeMs("1970-01-01T00:00:00"), null);
  assert.equal(parseTimeMs("1970-13-01T00:00:00Z"), null);
  assert.equal(parseTimeMs(42), null);
  assert.equal(parseTimeMs(undefined), null);
});

test("event time is the v1 context timestamp or the v2 time, chosen by generation", () => {
  assert.equal(
    eventTimeMs({ generation: 1, event: { context: { timestamp: "1970-01-01T00:00:02Z" } } }),
    2000,
  );
  assert.equal(eventTimeMs({ generation: 2, event: { time: "1970-01-01T00:00:03Z" } }), 3000);
  assert.equal(
    eventTimeMs({ generation: 2, event: { context: { timestamp: "1970-01-01T00:00:02Z" } } }),
    null,
  );
  assert.equal(eventTimeMs({ generation: 1, event: { time: "1970-01-01T00:00:03Z" } }), null);
  assert.equal(eventTimeMs({ generation: 3, event: {} }), null);
});

test("a production run record is read into passes, operations and frames", () => {
  const production = fromProductionRun(run());
  assert.equal(production.project, "fireemu-oracle-events");
  assert.equal(production.passes.length, 2);
  const [op] = production.passes[0].operations;
  assert.equal(op.pass, 1);
  assert.equal(op.startMs, parseTimeMs("2026-10-04T00:00:00.000Z"));
  assert.deepEqual(op.issues, []);
  const [frame] = production.frames;
  assert.equal(frame.logMs, parseTimeMs("2026-10-04T00:00:02.500000Z"));
  assert.equal(frame.eventMs, parseTimeMs("2026-10-04T00:00:00.500123Z"));
  assert.deepEqual(frame.issues, []);
  assert.equal(production.duplicateFrames, 0);
});

test("a run record that is not the contract shape is refused, never half-read", () => {
  assert.throws(() => fromProductionRun(null), /production run/);
  assert.throws(() => fromProductionRun(run({ schemaVersion: 2 })), /schemaVersion/);
  assert.throws(() => fromProductionRun(run({ kind: "other" })), /kind/);
  assert.throws(() => fromProductionRun(run({ project: "" })), /project/);
  assert.throws(() => fromProductionRun(run({ corpusDigest: "x" })), /corpusDigest/);
  assert.throws(() => fromProductionRun(run({ passes: [run().passes[0]] })), /two passes/);
  const swapped = run();
  swapped.passes.reverse();
  assert.throws(() => fromProductionRun(swapped), /pass 1 and pass 2/);
  assert.throws(() => fromProductionRun(run({ frames: {} })), /frames/);
  const noOps = run();
  noOps.passes[1].operations = null;
  assert.throws(() => fromProductionRun(noOps), /operations/);
});

test("a malformed operation or frame is kept with its issue so its rows become INCOMPLETE", () => {
  const record = run();
  record.passes[0].operations.push(
    operation({ startedAt: "later", scenarioId: "fs-update" }),
    operation({ endedAt: "2026-10-03T00:00:00Z" }),
    operation({ sourceResult: "ok" }),
    operation({ matchKey: { kind: "firestore", value: "" } }),
    operation({ matchKey: { kind: "auth", values: [] } }),
    operation({ matchKey: { kind: "ftp", value: "x" } }),
    operation({ windowSeconds: 0 }),
    operation({ scenarioId: 7 }),
  );
  record.frames.push(
    { ...record.frames[0], insertId: "i2", handler: "fsCreatedV1" },
    { ...record.frames[0], insertId: "i3", generation: 1 },
    { ...record.frames[0], insertId: "i4", logTimestamp: "soon" },
    { ...record.frames[0], insertId: "i5", frame: v2Frame("fe_events_primary/eaaa", "no time") },
    { ...record.frames[0], insertId: "i6", frame: "not an object" },
    { ...record.frames[0], insertId: "" },
  );
  const production = fromProductionRun(record);
  const issues = production.passes[0].operations.map((op) => op.issues.join("; "));
  assert.deepEqual(issues, [
    "",
    "operation startedAt is not an ISO time",
    "operation endedAt is before startedAt",
    "operation sourceResult is not a typed result",
    "operation matchKey is not a valid role key",
    "operation matchKey is not a valid role key",
    "operation matchKey is not a valid role key",
    "operation windowSeconds is not a positive number",
    "operation scenarioId is not a string",
  ]);
  assert.deepEqual(
    production.frames.map((frame) => frame.issues.join("; ")),
    [
      "",
      "frame handler disagrees with the record handler",
      "frame generation disagrees with the record generation",
      "frame logTimestamp is not an ISO time",
      "frame has no event time for its generation",
      "frame is not a JSON object; frame has no event time for its generation",
      "frame insertId is missing",
    ],
  );
});

test("frames read twice are counted once; a conflicting duplicate insertId is an issue", () => {
  const record = run();
  record.frames.push({ ...record.frames[0], readAt: "2026-10-04T00:01:00Z" });
  const production = fromProductionRun(record);
  assert.equal(production.frames.length, 1);
  assert.equal(production.duplicateFrames, 1);

  const conflict = run();
  conflict.frames.push({
    ...conflict.frames[0],
    frame: v2Frame("fe_events_primary/eaaa", "2026-10-04T00:00:00.600000Z"),
  });
  const read = fromProductionRun(conflict);
  assert.equal(read.frames.length, 2);
  assert.ok(
    read.frames.every((frame) => frame.issues.includes("insertId read with different content")),
  );
});

function localSession(frames, overrides = {}) {
  return {
    schemaVersion: 1,
    parent: "FUNCTIONS-EVENTS",
    status: "LOCAL_OBSERVATION",
    authority: "LOCAL_ONLY",
    productionEvidence: null,
    programs: [
      {
        recipeId: "functions-events/firestore/create",
        status: "LOCAL_OBSERVATION",
        operations: [
          {
            scenarioId: "fs-create",
            role: "subject",
            status: "LOCAL_OBSERVATION",
            sourceResult: "typed-success",
            readback: { exists: true },
            matchKey: { kind: "firestore", value: "fe_events_primary/eloc" },
            framesByGeneration: frames,
          },
        ],
        cases: [],
      },
    ],
    ...overrides,
  };
}

test("a local session is read from the exact rawJson of each frame", () => {
  const raw = JSON.stringify(v2Frame("fe_events_primary/eloc", "2026-10-04T00:00:00.5Z"));
  const local = fromLocalSession(
    localSession({
      v2: [{ sequence: 4, receivedAt: "x", rawJson: raw, frame: { ignored: true } }],
    }),
  );
  const [op] = local.programs.get("functions-events/firestore/create").operations;
  assert.deepEqual(op.issues, []);
  assert.deepEqual(op.frames[2], [{ sequence: 4, frame: JSON.parse(raw) }]);
  assert.deepEqual(op.frames[1], []);
});

test("an unreadable or foreign local frame is an operation issue", () => {
  const wrongPath = JSON.stringify(v2Frame("fe_events_primary/eother", "2026-10-04T00:00:00Z"));
  const v1Labelled = JSON.stringify(v2Frame("fe_events_primary/eloc", "2026-10-04T00:00:00Z"));
  const local = fromLocalSession(
    localSession({
      v1: [{ sequence: 1, rawJson: v1Labelled }],
      v2: [
        { sequence: 2, rawJson: "{not json" },
        { sequence: 3, rawJson: wrongPath },
        { sequence: 4, frame: {} },
      ],
    }),
  );
  const [op] = local.programs.get("functions-events/firestore/create").operations;
  assert.deepEqual(op.issues, [
    "local v1 frame 1 generation disagrees with its list",
    "local v2 frame 2 rawJson is not a JSON object",
    "local v2 frame 3 does not match the operation matchKey",
    "local v2 frame 4 has no rawJson",
  ]);
});

test("a local session that is not LOCAL_ONLY or repeats a program is refused", () => {
  assert.throws(
    () => fromLocalSession(localSession({}, { authority: "PRODUCTION" })),
    /LOCAL_ONLY/,
  );
  assert.throws(() => fromLocalSession(localSession({}, { schemaVersion: 2 })), /schemaVersion/);
  const twice = localSession({});
  twice.programs.push(twice.programs[0]);
  assert.throws(() => fromLocalSession(twice), /twice/);
  assert.throws(() => fromLocalSession(localSession({}, { programs: null })), /programs/);
});
