// Edge rules of the comparator: attribution boundaries, retry attempts, controls, local issues,
// frozen-input consistency and frame accounting. Each test breaks one thing in the agreeing world.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { compareRuns, resourceIdentified } from "./functions-events/compare/compare.mjs";
import {
  LOCAL_PROJECT,
  PRODUCTION_PROJECT,
  T0,
  firestoreFrame,
  frameEntry,
  iso,
  isoMicros,
  localOp,
  op,
} from "./functions-events/compare/fixtures/build.mjs";
import { docId, uuid, world } from "./functions-events/compare/fixtures/world.mjs";

const readJson = (path) => JSON.parse(readFileSync(new URL(path, import.meta.url)));
const corpus = readJson("../functions-events/corpus.json");
const programs = readJson("../functions-events/programs.json");
const S = T0 + 60_000;
const CREATE_V1 = "functions-events/firestore/create#new-document#v1";
const OTHER_V1 = "functions-events/firestore/routing#nonmatching-path#v1";
const OTHER_V2 = "functions-events/firestore/routing#nonmatching-path#v2";
const RETRY_ROW = "functions-events/delivery/retry#event-id-across-attempts#v2";

const compare = (w, extra = {}) =>
  compareRuns({
    corpus,
    programs,
    productionRun: w.run,
    localSessions: { emulator: w.emulator, strict: w.strict },
    localProject: LOCAL_PROJECT,
    ...extra,
  });
const row = (result, id) => result.rows.find((candidate) => candidate.row === id);
const createFrame = (w, generation, n) =>
  w.run.frames.find(
    (entry) =>
      entry.handler === `fsCreatedV${generation}` && JSON.stringify(entry.frame).includes(docId(n)),
  );
const retryFrames = (w, n) =>
  w.run.frames.filter(
    (entry) => entry.handler === "fsRetryV2" && entry.frame.event.subject.endsWith(docId(n)),
  );
const setEventTime = (entry, ms) => {
  if (entry.generation === 1) entry.frame.event.context.timestamp = isoMicros(ms);
  else entry.frame.event.time = isoMicros(ms);
};

test("event times exactly on the source call bounds belong to it; on the tolerance bounds are unattributable", () => {
  for (const at of [S, S + 1000]) {
    const w = world();
    setEventTime(createFrame(w, 1, 101), at);
    assert.equal(row(compare(w), CREATE_V1).status, "MATCH", `${at - S}`);
  }
  for (const at of [S - 1000, S + 2000]) {
    const w = world();
    setEventTime(createFrame(w, 1, 101), at);
    const found = row(compare(w), CREATE_V1);
    assert.equal(found.status, "INCOMPLETE", `${at - S}`);
    assert.match(found.reasons[0], /cannot be attributed/);
  }
  for (const at of [S - 1000.001, S + 2000.001]) {
    const w = world();
    setEventTime(createFrame(w, 1, 101), at);
    assert.deepEqual(row(compare(w), CREATE_V1).reasons, [
      "production pass 1: no fsCreatedV1 frame in the 120 s window",
    ]);
  }
});

test("the window runs from the end of the source call and includes its last instant", () => {
  for (const offset of [60_000, 120_000]) {
    const w = world();
    createFrame(w, 1, 101).logTimestamp = iso(S + 1000 + offset);
    assert.equal(row(compare(w), CREATE_V1).status, "MATCH", `${offset}`);
  }
});

test("an operation or subject frame with an issue makes its rows INCOMPLETE without a crash", () => {
  const badKey = world();
  badKey.run.passes[0].operations[0].matchKey = { kind: "firestore" };
  const keyed = row(compare(badKey), CREATE_V1);
  assert.equal(keyed.status, "INCOMPLETE");
  assert.deepEqual(keyed.reasons, [
    "production pass 1: operation matchKey is not a valid role key",
  ]);

  const badFrame = world();
  createFrame(badFrame, 1, 101).generation = 2;
  const framed = row(compare(badFrame), CREATE_V1);
  assert.equal(framed.status, "INCOMPLETE");
  assert.deepEqual(framed.reasons, [
    "production pass 1: frame generation disagrees with the record generation",
  ]);
});

test("a frame attributed to two operations is INCOMPLETE and never serves as a control", () => {
  const w = world();
  const path = `fe_events_primary/${docId(101)}`;
  w.run.passes[0].operations.push(
    op({ scenarioId: "fs-auth-client", start: S, matchKey: { kind: "firestore", value: path } }),
  );
  const result = compare(w);
  assert.deepEqual(row(result, CREATE_V1).reasons, [
    "production pass 1: a fsCreatedV1 frame matches more than one operation",
  ]);
  assert.equal(result.frameAccounting.multiplyAttributed, 2);
  const negative = row(result, OTHER_V1);
  assert.equal(negative.status, "INCOMPLETE");
  assert.deepEqual(negative.reasons, [
    "production pass 1: no positive fsCreatedV1 frame before the operation",
  ]);
});

test("negative case: a near frame of the subject is INCOMPLETE; controls need a clean frame logged strictly before", () => {
  const near = world();
  near.run.frames.push(
    frameEntry(
      firestoreFrame({
        handler: "fsCreatedV2",
        generation: 2,
        project: PRODUCTION_PROJECT,
        path: `fe_events_control/${docId(102)}`,
        eventId: uuid(5),
        timeMs: S + 11_500,
      }),
      S + 13_000,
    ),
  );
  const nearRow = row(compare(near), OTHER_V2);
  assert.equal(nearRow.status, "INCOMPLETE");
  assert.match(nearRow.reasons[0], /cannot be attributed/);

  const atStart = world();
  createFrame(atStart, 2, 101).logTimestamp = iso(S + 10_000);
  assert.deepEqual(row(compare(atStart), OTHER_V2).reasons, [
    "production pass 1: no positive fsCreatedV2 frame before the operation",
  ]);

  const flawed = world();
  createFrame(flawed, 2, 103).generation = 1;
  assert.deepEqual(row(compare(flawed), OTHER_V2).reasons, [
    "production pass 1: no positive fsCreatedV2 frame after the window",
  ]);
});

test("retry: attempts without a fixture attempt, a missing failed attempt or disagreeing attempts are INCOMPLETE", () => {
  const unmarked = world();
  delete retryFrames(unmarked, 104)[1].frame.event.data.fixtureAttempt;
  assert.deepEqual(row(compare(unmarked), RETRY_ROW).reasons, [
    "production pass 1: fsRetryV2 frame(s) without a fixture attempt",
  ]);

  const noFailure = world();
  noFailure.run.frames = noFailure.run.frames.filter(
    (entry) => entry !== retryFrames(noFailure, 104)[0],
  );
  assert.deepEqual(row(compare(noFailure), RETRY_ROW).reasons, [
    "production pass 1: no failed fsRetryV2 attempt in the 600 s window",
  ]);

  const twice = world();
  const extra = structuredClone(retryFrames(twice, 104)[1]);
  extra.insertId = "retry-again";
  extra.frame.event.id = uuid(77);
  twice.run.frames.push(extra);
  assert.deepEqual(row(compare(twice), RETRY_ROW).reasons, [
    "production pass 1: 2 succeeded fsRetryV2 frames differ from each other",
  ]);
});

test("retry: a local succeeded attempt with another source or time is a DIFF", () => {
  for (const [field, value, path] of [
    ["source", "//firestore.googleapis.com/projects/other/databases/(default)", "sameSource"],
    ["time", "2026-10-04T00:00:00.999999Z", "sameTime"],
  ]) {
    const w = world();
    const retry = w.emulator.programs[2].operations[0];
    const succeeded = JSON.parse(retry.framesByGeneration.v2[1].rawJson);
    succeeded.event[field] = value;
    retry.framesByGeneration.v2[1].rawJson = JSON.stringify(succeeded);
    const found = row(compare(w), RETRY_ROW);
    assert.equal(found.status, "DIFF");
    assert.ok(
      found.reasons.some((reason) => reason.startsWith(`emulator: value $.retry.${path} `)),
      found.reasons.join("; "),
    );
  }
});

test("local controls: the nearest control of the right role, clean and complete, at any index", () => {
  const between = world();
  const routing = between.emulator.programs[1].operations;
  routing.splice(
    3,
    0,
    localOp({
      scenarioId: "fs-update",
      matchKey: { kind: "firestore", value: "fe_events_primary/x" },
    }),
  );
  assert.equal(row(compare(between), OTHER_V1).status, "MATCH");

  const incomplete = world();
  incomplete.emulator.programs[1].operations[3].status = "INCOMPLETE";
  assert.deepEqual(row(compare(incomplete), OTHER_V1).reasons, [
    "emulator: no positive fsCreatedV1 control after the operation",
  ]);

  const broken = world();
  broken.emulator.programs[1].operations[3].framesByGeneration.v2[0].rawJson = "{";
  assert.deepEqual(row(compare(broken), OTHER_V1).reasons, [
    "emulator: no positive fsCreatedV1 control after the operation",
  ]);

  const before = world();
  before.strict.programs[1].operations[1].framesByGeneration.v1 = [];
  assert.deepEqual(row(compare(before), OTHER_V1).reasons, [
    "strict: no positive fsCreatedV1 control before the operation",
  ]);

  const first = world();
  first.emulator.programs[1].operations.shift();
  assert.equal(row(compare(first), OTHER_V1).status, "MATCH", "control at index 0");
});

test("local subject issues: broken frames, INCOMPLETE status, another handler or no frame", () => {
  const broken = world();
  broken.emulator.programs[0].operations[0].framesByGeneration.v1[0].rawJson = "[]";
  assert.deepEqual(row(compare(broken), CREATE_V1).reasons, [
    "emulator: local v1 frame 1 rawJson is not a JSON object",
  ]);

  const marked = world();
  marked.emulator.programs[0].operations[0].status = "INCOMPLETE";
  assert.deepEqual(row(compare(marked), CREATE_V1).reasons, [
    "emulator: the local driver marked the operation INCOMPLETE",
  ]);

  const other = world();
  const entry = other.strict.programs[0].operations[0].framesByGeneration.v1[0];
  const frame = JSON.parse(entry.rawJson);
  frame.handler = "fsWrittenV1";
  entry.rawJson = JSON.stringify(frame);
  assert.deepEqual(row(compare(other), CREATE_V1).reasons, [
    "strict: a local frame belongs to another handler than fsCreatedV1",
  ]);

  const none = world();
  none.strict.programs[0].operations[0].framesByGeneration.v1 = [];
  assert.deepEqual(row(compare(none), CREATE_V1).reasons, ["strict: no local fsCreatedV1 frame"]);
});

test("frozen inputs must agree: a case from another recipe or without a handler is refused", () => {
  const w = world();
  const sessions = { emulator: w.emulator, strict: w.strict };
  const moved = structuredClone(programs);
  moved.programs[0].caseIds.push(moved.programs[1].caseIds[0]);
  assert.throws(
    () =>
      compareRuns({
        corpus,
        programs: moved,
        productionRun: w.run,
        localSessions: sessions,
        localProject: LOCAL_PROJECT,
      }),
    /unknown case/,
  );
  const handlerless = structuredClone(programs);
  delete handlerless.programs[0].handlerExports.v2;
  assert.throws(
    () =>
      compareRuns({
        corpus,
        programs: handlerless,
        productionRun: w.run,
        localSessions: sessions,
        localProject: LOCAL_PROJECT,
      }),
    /no handler, scenario or window/,
  );
});

test("frame accounting counts duplicates, issues, unattributable and unknown handlers", () => {
  const w = world();
  w.run.frames.push(structuredClone(w.run.frames[0]));
  const flawed = structuredClone(w.run.frames[1]);
  flawed.insertId = "flawed";
  flawed.logTimestamp = "later";
  const unknown = structuredClone(w.run.frames[2]);
  unknown.insertId = "unknown";
  unknown.handler = "probeV9";
  unknown.frame.handler = "probeV9";
  w.run.frames.push(flawed, unknown);
  w.run.passes[1].operations[1].startedAt = "not a time";
  const accounting = compare(w).frameAccounting;
  assert.deepEqual(accounting, {
    frames: w.run.frames.length - 1,
    duplicateReads: 1,
    withIssues: 1,
    unknownHandlers: ["probeV9"],
    unowned: 0,
    unidentified: 0,
    lifecycle: 0,
    unattributable: 0,
    multiplyAttributed: 0,
  });

  const timeless = world();
  timeless.run.passes[0].operations[0].startedAt = "not a time";
  assert.equal(compare(timeless).frameAccounting.unattributable, 2);
});

test("a frame names its resource the way resourceMatches reads it, per source", () => {
  const cases = [
    [
      {
        source: "firestore",
        event: {
          context: { resource: { name: "projects/p/databases/(default)/documents/c/d" } },
          data: {},
        },
      },
      true,
    ],
    [{ source: "firestore", event: { subject: "documents/c/d", data: {} } }, true],
    [{ source: "firestore", event: { data: { before: { path: "c/d" } } } }, true],
    [{ source: "firestore", event: { data: { after: { path: "c/d" } } } }, true],
    [{ source: "firestore", event: { data: { id: "d" } } }, false],
    [{ source: "storage", event: { data: { name: "o" } } }, true],
    [{ source: "storage", event: { data: { bucket: "b" } } }, false],
    [{ source: "auth", event: { data: { uid: "u" } } }, true],
    [{ source: "auth", event: { data: { email: "e" } } }, false],
    [{ source: "pubsub", event: { data: { message: { messageId: "1" } } } }, true],
    [{ source: "pubsub", event: { data: { messageId: "1" } } }, true],
    [{ source: "pubsub", event: { context: { eventId: "1" }, data: {} } }, true],
    [{ source: "pubsub", event: { data: { message: {} } } }, false],
    [{ source: "other", event: { data: { name: "o" } } }, false],
    [{ source: "storage" }, false],
  ];
  for (const [frame, expected] of cases)
    assert.equal(resourceIdentified(frame), expected, JSON.stringify(frame));
});

test("the attribution tolerance is a parameter of the comparison", () => {
  const w = world();
  setEventTime(createFrame(w, 1, 101), S - 1500);
  assert.equal(row(compare(w), CREATE_V1).status, "INCOMPLETE");
  assert.equal(row(compare(w, { toleranceMs: 2000 }), CREATE_V1).status, "INCOMPLETE");
  assert.match(row(compare(w, { toleranceMs: 2000 }), CREATE_V1).reasons[0], /within 2000 ms/);
});
