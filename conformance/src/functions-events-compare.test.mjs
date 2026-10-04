import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { compareRuns } from "./functions-events/compare/compare.mjs";
import {
  LOCAL_PROJECT,
  PRODUCTION_PROJECT,
  T0,
  firestoreFrame,
  frameEntry,
  localOp,
  localSession,
  op,
  productionRun,
} from "./functions-events/compare/fixtures/build.mjs";

const readJson = (path) => JSON.parse(readFileSync(new URL(path, import.meta.url)));
const corpus = readJson("../functions-events/corpus.json");
const programs = readJson("../functions-events/programs.json");

const uuid = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
const docId = (n) => `e${String(n).padStart(32, "0")}`;
const PASS_OFFSET = 3_600_000;

/**
 * A production run and two local sessions for the firestore/create, firestore/routing and
 * delivery/retry programs, where production and fireemu agree. Tests break one thing at a time.
 */
function world() {
  const passes = [[], []];
  const frames = [];
  for (const pass of [1, 2]) {
    const s = T0 + 60_000 + (pass - 1) * PASS_OFFSET;
    const n = pass * 100;
    const create = `fe_events_primary/${docId(n + 1)}`;
    const other = `fe_events_control/${docId(n + 2)}`;
    const after = `fe_events_primary/${docId(n + 3)}`;
    const retry = `fe_events_primary/${docId(n + 4)}`;
    const ops = passes[pass - 1];
    ops.push(
      op({
        scenarioId: "fs-create",
        start: s,
        matchKey: { kind: "firestore", value: create },
        readback: { exists: true, path: create },
      }),
      op({
        scenarioId: "fs-other-path",
        start: s + 10_000,
        matchKey: { kind: "firestore", value: other },
        readback: { exists: true, path: other },
      }),
      op({
        scenarioId: "fs-auth-admin",
        start: s + 140_000,
        matchKey: { kind: "firestore", value: after },
        readback: { exists: true, path: after },
      }),
      op({
        scenarioId: "fs-retry",
        start: s + 200_000,
        matchKey: { kind: "firestore", value: retry },
        readback: { exists: true, path: retry },
        windowSeconds: 600,
      }),
    );
    for (const [generation, handler] of [
      [1, "fsCreatedV1"],
      [2, "fsCreatedV2"],
    ]) {
      frames.push(
        frameEntry(
          firestoreFrame({
            handler,
            generation,
            project: PRODUCTION_PROJECT,
            path: create,
            eventId: uuid(n + 10 + generation),
            timeMs: s + 500.123,
          }),
          s + 2000,
        ),
        frameEntry(
          firestoreFrame({
            handler,
            generation,
            project: PRODUCTION_PROJECT,
            path: after,
            eventId: uuid(n + 20 + generation),
            timeMs: s + 140_400.5,
          }),
          s + 142_000,
        ),
      );
    }
    for (const fixtureAttempt of ["failed", "succeeded"]) {
      frames.push(
        frameEntry(
          firestoreFrame({
            handler: "fsRetryV2",
            generation: 2,
            project: PRODUCTION_PROJECT,
            path: retry,
            eventId: uuid(n + 30),
            timeMs: s + 200_300.25,
            data: { fixtureKind: "retry" },
            fixtureAttempt,
          }),
          s + (fixtureAttempt === "failed" ? 202_000 : 215_000),
        ),
      );
    }
  }
  const run = productionRun(passes[0], passes[1], frames);
  const local = (salt) => {
    const create = `fe_events_primary/${docId(salt + 1)}`;
    const before = `fe_events_primary/${docId(salt + 2)}`;
    const other = `fe_events_control/${docId(salt + 3)}`;
    const after = `fe_events_primary/${docId(salt + 4)}`;
    const retry = `fe_events_primary/${docId(salt + 5)}`;
    const both = (path, base, timeMs) => ({
      v1: [
        firestoreFrame({
          handler: "fsCreatedV1",
          generation: 1,
          project: LOCAL_PROJECT,
          path,
          eventId: uuid(base + 1),
          timeMs,
        }),
      ],
      v2: [
        firestoreFrame({
          handler: "fsCreatedV2",
          generation: 2,
          project: LOCAL_PROJECT,
          path,
          eventId: uuid(base + 2),
          timeMs,
        }),
      ],
    });
    const key = (path) => ({ kind: "firestore", value: path });
    const subject = () =>
      localOp({
        scenarioId: "fs-create",
        matchKey: key(create),
        readback: { exists: true, path: create },
        ...both(create, salt + 10, T0 + 7.5),
      });
    return localSession([
      { recipeId: "functions-events/firestore/create", operations: [subject()] },
      {
        recipeId: "functions-events/firestore/routing",
        operations: [
          subject(),
          localOp({
            scenarioId: "fs-create",
            role: "positive-control-before",
            matchKey: key(before),
            readback: { exists: true, path: before },
            ...both(before, salt + 20, T0 + 9.25),
          }),
          localOp({
            scenarioId: "fs-other-path",
            matchKey: key(other),
            readback: { exists: true, path: other },
          }),
          localOp({
            scenarioId: "fs-create",
            role: "positive-control-after",
            matchKey: key(after),
            readback: { exists: true, path: after },
            ...both(after, salt + 30, T0 + 11.5),
          }),
        ],
      },
      {
        recipeId: "functions-events/delivery/retry",
        operations: [
          localOp({
            scenarioId: "fs-retry",
            matchKey: key(retry),
            readback: { exists: true, path: retry },
            v2: ["failed", "succeeded"].map((fixtureAttempt) =>
              firestoreFrame({
                handler: "fsRetryV2",
                generation: 2,
                project: LOCAL_PROJECT,
                path: retry,
                eventId: uuid(salt + 40),
                timeMs: T0 + 13.75,
                data: { fixtureKind: "retry" },
                fixtureAttempt,
              }),
            ),
          }),
        ],
      },
    ]);
  };
  return { run, emulator: local(900), strict: local(950) };
}

function compare(w) {
  return compareRuns({
    corpus,
    programs,
    productionRun: w.run,
    localSessions: { emulator: w.emulator, strict: w.strict },
    localProject: LOCAL_PROJECT,
  });
}

const rowsOf = (result, recipeId) =>
  result.rows.filter(({ row }) => row === recipeId || row.startsWith(`${recipeId}#`));
const rowById = (result, id) => result.rows.find(({ row }) => row === id);
const statuses = (rows) => Object.fromEntries(rows.map(({ row, status }) => [row, status]));

test("rows cover every frozen case id once, named recipe#case#vN for the closure filter", () => {
  const result = compare(world());
  const caseIds = programs.programs.flatMap((program) => program.caseIds);
  assert.equal(result.rows.length, caseIds.length);
  assert.deepEqual(
    result.rows.map(({ caseId }) => caseId),
    caseIds,
  );
  for (const row of result.rows) {
    const program = programs.programs.find((candidate) => candidate.caseIds.includes(row.caseId));
    assert.equal(row.row, `${program.recipeId}#${row.case}#v${row.generation}`);
    assert.ok(["MATCH", "DIFF", "INCOMPLETE"].includes(row.status));
    assert.ok(Array.isArray(row.reasons));
  }
  assert.deepEqual(result.summary, {
    rows: result.rows.length,
    match: result.rows.filter(({ status }) => status === "MATCH").length,
    diff: result.rows.filter(({ status }) => status === "DIFF").length,
    incomplete: result.rows.filter(({ status }) => status === "INCOMPLETE").length,
  });
});

test("agreeing production passes and local profiles MATCH; volatile paths come from the passes", () => {
  const result = compare(world());
  for (const recipe of [
    "functions-events/firestore/create",
    "functions-events/firestore/routing",
    "functions-events/delivery/retry",
  ]) {
    for (const row of rowsOf(result, recipe))
      assert.equal(row.status, "MATCH", `${row.row}: ${row.reasons.join("; ")}`);
  }
  assert.deepEqual(result.volatilePaths["fsCreatedV2/fs-create"], {
    "$.frame.event.data.createTime._seconds": ["value"],
    "$.frame.event.id": ["value"],
    "$.frame.event.time": ["value"],
    "$.frame.event.data.updateTime._seconds": ["value"],
  });
  assert.equal(result.conditions["FUNCTIONS-EVENTS/firestore-created"], "MATCH");
  assert.equal(result.conditions["FUNCTIONS-EVENTS/storage-finalized"], "INCOMPLETE");
});

test("a case with no production observation is INCOMPLETE with a reason, never MATCH", () => {
  const result = compare(world());
  const row = rowById(result, "functions-events/firestore/update#changed-field#v1");
  assert.equal(row.status, "INCOMPLETE");
  assert.ok(row.reasons.includes("production pass 1: 0 subject operations for fs-update"));
  assert.ok(
    row.reasons.includes(
      "emulator: local session has no functions-events/firestore/update program",
    ),
  );
});

test("Gen1 and Gen2 are compared per generation, never against each other", () => {
  const w = world();
  w.run.frames = w.run.frames.filter(
    (entry) => !(entry.handler === "fsCreatedV2" && entry.frame.event.subject.endsWith(docId(101))),
  );
  const result = compare(w);
  const rows = statuses(rowsOf(result, "functions-events/firestore/create"));
  assert.equal(rows["functions-events/firestore/create#new-document#v1"], "MATCH");
  assert.equal(rows["functions-events/firestore/create#new-document#v2"], "INCOMPLETE");
  assert.ok(
    rowById(result, "functions-events/firestore/create#new-document#v2").reasons.includes(
      "production pass 1: no fsCreatedV2 frame in the 120 s window",
    ),
  );
});

test("a deterministic local difference is a DIFF naming the path, profile by profile", () => {
  const w = world();
  for (const program of w.strict.programs) {
    for (const operation of program.operations) {
      for (const entry of operation.framesByGeneration.v1) {
        const frame = JSON.parse(entry.rawJson);
        frame.event.context.eventType = "providers/cloud.firestore/eventTypes/document.create";
        entry.rawJson = JSON.stringify(frame);
      }
    }
  }
  const result = compare(w);
  const v1 = rowById(result, "functions-events/firestore/create#new-document#v1");
  assert.equal(v1.status, "DIFF");
  assert.equal(v1.reasons.length, 1);
  assert.match(
    v1.reasons[0],
    /^strict: value \$\.frame\.event\.context\.eventType \(production string#[0-9a-f]{12}, local string#[0-9a-f]{12}\)$/,
  );
  assert.equal(
    rowById(result, "functions-events/firestore/create#new-document#v2").status,
    "MATCH",
  );
  assert.equal(result.conditions["FUNCTIONS-EVENTS/firestore-created"], "DIFF");
});

test("a local frame with a field production never showed is a DIFF, not silently accepted", () => {
  const w = world();
  const subject = w.emulator.programs[0].operations[0];
  const frame = JSON.parse(subject.framesByGeneration.v2[0].rawJson);
  frame.event.data.extra = { unrecorded: true };
  delete frame.event.datacontenttype;
  subject.framesByGeneration.v2[0].rawJson = JSON.stringify(frame);
  const row = rowById(compare(w), "functions-events/firestore/create#new-document#v2");
  assert.equal(row.status, "DIFF");
  assert.deepEqual(row.reasons, [
    "emulator: extra-field $.frame.event.data.extra",
    "emulator: missing-field $.frame.event.datacontenttype",
  ]);
});

test("production passes that disagree on presence or type make the row INCOMPLETE", () => {
  const w = world();
  const pass2 = w.run.frames.find(
    (entry) =>
      entry.handler === "fsCreatedV1" &&
      entry.frame.event.context.resource.name.endsWith(docId(201)),
  );
  pass2.frame.event.context.authType = "ADMIN";
  pass2.frame.event.data.data.count = "1";
  const row = rowById(compare(w), "functions-events/firestore/create#new-document#v1");
  assert.equal(row.status, "INCOMPLETE");
  assert.deepEqual(row.reasons, [
    "production passes disagree: production-type $.frame.event.context.authType (null, string)",
    "production passes disagree: production-type $.frame.event.data.data.count (number, string)",
  ]);
});

test("a source call that did not return the corpus result is INCOMPLETE; a local result that differs is a DIFF", () => {
  const w = world();
  w.run.passes[1].operations[0].sourceResult = "typed-refusal";
  const row = rowById(compare(w), "functions-events/firestore/create#new-document#v1");
  assert.equal(row.status, "INCOMPLETE");
  assert.ok(
    row.reasons.includes(
      "production pass 2: source call returned typed-refusal, the corpus expects typed-success",
    ),
  );

  const local = world();
  local.emulator.programs[0].operations[0].sourceResult = "typed-absent";
  const diff = rowById(compare(local), "functions-events/firestore/create#new-document#v1");
  assert.equal(diff.status, "DIFF");
  assert.ok(diff.reasons.some((reason) => reason.startsWith("emulator: value $.sourceResult ")));
});

test("a positive frame after the window is a DIFF, not a pass", () => {
  const w = world();
  const entry = w.run.frames.find(
    (frame) =>
      frame.handler === "fsCreatedV1" &&
      frame.frame.event.context.resource.name.endsWith(docId(101)),
  );
  entry.logTimestamp = new Date(T0 + 60_000 + 1000 + 120_001).toISOString();
  const row = rowById(compare(w), "functions-events/firestore/create#new-document#v1");
  assert.equal(row.status, "DIFF");
  assert.ok(
    row.reasons.includes(
      "production pass 1: 1 fsCreatedV1 frame(s) arrived after the 120 s window",
    ),
  );
});

test("negative case: a production delivery anywhere after the call is a DIFF, late or not", () => {
  for (const logOffset of [3000, 900_000]) {
    const w = world();
    const s = T0 + 60_000;
    w.run.frames.push(
      frameEntry(
        firestoreFrame({
          handler: "fsCreatedV2",
          generation: 2,
          project: PRODUCTION_PROJECT,
          path: `fe_events_control/${docId(102)}`,
          eventId: uuid(7),
          timeMs: s + 10_500,
        }),
        s + 10_000 + logOffset,
      ),
    );
    w.run.passes[0].operations[1].matchKey = {
      kind: "firestore",
      value: `fe_events_control/${docId(102)}`,
    };
    const row = rowById(compare(w), "functions-events/firestore/routing#nonmatching-path#v2");
    assert.equal(row.status, "DIFF", `${logOffset}`);
    assert.ok(
      row.reasons.includes(
        "production pass 1: fsCreatedV2 delivered 1 frame(s) on a no-event case",
      ),
    );
    assert.equal(
      rowById(compare(w), "functions-events/firestore/routing#nonmatching-path#v1").status,
      "MATCH",
    );
  }
});

test("negative case: positive controls before the operation and after the window are required", () => {
  const before = world();
  before.run.frames = before.run.frames.filter(
    (entry) => !(entry.handler === "fsCreatedV2" && entry.frame.event.subject.endsWith(docId(101))),
  );
  const missingBefore = rowById(
    compare(before),
    "functions-events/firestore/routing#nonmatching-path#v2",
  );
  assert.equal(missingBefore.status, "INCOMPLETE");
  assert.ok(
    missingBefore.reasons.includes(
      "production pass 1: no positive fsCreatedV2 frame before the operation",
    ),
  );

  const after = world();
  const control = after.run.frames.find(
    (entry) => entry.handler === "fsCreatedV2" && entry.frame.event.subject.endsWith(docId(103)),
  );
  control.logTimestamp = new Date(T0 + 60_000 + 11_000 + 120_000).toISOString();
  const missingAfter = rowById(
    compare(after),
    "functions-events/firestore/routing#nonmatching-path#v2",
  );
  assert.equal(missingAfter.status, "INCOMPLETE");
  assert.ok(
    missingAfter.reasons.includes(
      "production pass 1: no positive fsCreatedV2 frame after the window",
    ),
  );
});

test("negative case: a frame of the handler that correlates with no operation leaves the absence unproven", () => {
  const w = world();
  const s = T0 + 60_000;
  w.run.frames.push(
    frameEntry(
      firestoreFrame({
        handler: "fsCreatedV1",
        generation: 1,
        project: PRODUCTION_PROJECT,
        path: "fe_events_primary/unknown",
        eventId: uuid(8),
        timeMs: s + 50_000,
      }),
      s + 51_000,
    ),
  );
  const row = rowById(compare(w), "functions-events/firestore/routing#nonmatching-path#v1");
  assert.equal(row.status, "INCOMPLETE");
  assert.ok(
    row.reasons.includes(
      "production pass 1: 1 fsCreatedV1 frame(s) correlate with no operation during or after the observation",
    ),
  );
  assert.equal(compare(w).frameAccounting.foreign, 1);
});

test("frames of the subject resource from other mutations are not the subject's; near ones are INCOMPLETE", () => {
  const cleanup = world();
  const s = T0 + 60_000;
  const path = `fe_events_primary/${docId(101)}`;
  cleanup.run.frames.push(
    frameEntry(
      firestoreFrame({
        handler: "fsCreatedV1",
        generation: 1,
        project: PRODUCTION_PROJECT,
        path,
        eventId: uuid(9),
        timeMs: s - 30_000,
      }),
      s - 29_000,
    ),
    frameEntry(
      firestoreFrame({
        handler: "fsCreatedV1",
        generation: 1,
        project: PRODUCTION_PROJECT,
        path,
        eventId: uuid(10),
        timeMs: s + 600_000,
      }),
      s + 601_000,
    ),
  );
  const lifecycle = compare(cleanup);
  assert.equal(
    rowById(lifecycle, "functions-events/firestore/create#new-document#v1").status,
    "MATCH",
  );
  assert.equal(lifecycle.frameAccounting.lifecycle, 2);

  const near = world();
  near.run.frames.push(
    frameEntry(
      firestoreFrame({
        handler: "fsCreatedV1",
        generation: 1,
        project: PRODUCTION_PROJECT,
        path,
        eventId: uuid(11),
        timeMs: s - 400,
      }),
      s + 1500,
    ),
  );
  const row = rowById(compare(near), "functions-events/firestore/create#new-document#v1");
  assert.equal(row.status, "INCOMPLETE");
  assert.ok(
    row.reasons.includes(
      "production pass 1: 1 fsCreatedV1 frame(s) of the subject cannot be attributed (no event time, or within 1000 ms of the source call)",
    ),
  );
});

test("negative case: a local delivery is a DIFF and a missing local control is INCOMPLETE", () => {
  const delivered = world();
  const routing = delivered.emulator.programs[1].operations;
  routing[2].framesByGeneration.v1 = routing[0].framesByGeneration.v1.map((entry) => ({
    ...entry,
    rawJson: entry.rawJson
      .split(docId(901))
      .join(docId(903))
      .split("fe_events_primary")
      .join("fe_events_control"),
  }));
  const diff = rowById(
    compare(delivered),
    "functions-events/firestore/routing#nonmatching-path#v1",
  );
  assert.equal(diff.status, "DIFF");
  assert.ok(diff.reasons.includes("emulator: fsCreatedV1 delivered 1 frame(s) on a no-event case"));

  const control = world();
  control.strict.programs[1].operations[3].framesByGeneration.v2 = [];
  const incomplete = rowById(
    compare(control),
    "functions-events/firestore/routing#nonmatching-path#v2",
  );
  assert.equal(incomplete.status, "INCOMPLETE");
  assert.ok(
    incomplete.reasons.includes("strict: no positive fsCreatedV2 control after the operation"),
  );
});

test("retry compares event identity across the failed and succeeded frames (E9)", () => {
  const changed = world();
  const retry = changed.emulator.programs[2].operations[0];
  const succeeded = JSON.parse(retry.framesByGeneration.v2[1].rawJson);
  succeeded.event.id = uuid(999);
  retry.framesByGeneration.v2[1].rawJson = JSON.stringify(succeeded);
  const rows = rowsOf(compare(changed), "functions-events/delivery/retry");
  assert.equal(rows.length, 4);
  for (const row of rows) {
    assert.equal(row.status, "DIFF");
    assert.ok(
      row.reasons.some((reason) => reason.startsWith("emulator: value $.retry.sameEventId ")),
      row.reasons.join("; "),
    );
  }

  const unfinished = world();
  unfinished.run.frames = unfinished.run.frames.filter(
    (entry) =>
      !(
        entry.handler === "fsRetryV2" &&
        entry.frame.event.data.fixtureAttempt === "succeeded" &&
        entry.frame.event.subject.endsWith(docId(204))
      ),
  );
  for (const row of rowsOf(compare(unfinished), "functions-events/delivery/retry")) {
    assert.equal(row.status, "INCOMPLETE");
    assert.ok(
      row.reasons.includes("production pass 2: no succeeded fsRetryV2 attempt in the 600 s window"),
    );
  }
});

test("more than one subject operation for a scenario in a pass is INCOMPLETE", () => {
  const w = world();
  w.run.passes[0].operations.push({ ...w.run.passes[0].operations[0] });
  const row = rowById(compare(w), "functions-events/firestore/create#new-document#v1");
  assert.equal(row.status, "INCOMPLETE");
  assert.ok(row.reasons.includes("production pass 1: 2 subject operations for fs-create"));
});

test("the condition result is the worst row of its cases", () => {
  const w = world();
  w.strict.programs[0].operations[0].readback = { exists: false, path: "x" };
  const result = compare(w);
  assert.equal(rowById(result, "functions-events/firestore/create#new-document#v1").status, "DIFF");
  assert.equal(result.conditions["FUNCTIONS-EVENTS/firestore-created"], "DIFF");
  assert.equal(result.conditions["FUNCTIONS-EVENTS/firestore-routing-params"], "MATCH");
  assert.equal(result.conditions["FUNCTIONS-EVENTS/delivery-retry-identity"], "MATCH");
  assert.equal(result.conditions["FUNCTIONS-EVENTS/auth-created"], "INCOMPLETE");
});

test("the result never carries a raw id or time from either side", () => {
  const text = JSON.stringify(compare(world()));
  for (const raw of [
    docId(101),
    docId(201),
    docId(901),
    uuid(111),
    uuid(912),
    "2026-10-04T00:01:00.500123Z",
    PRODUCTION_PROJECT,
    LOCAL_PROJECT,
  ]) {
    assert.equal(text.includes(raw), false, raw);
  }
});

test("inconsistent frozen inputs are refused", () => {
  const w = world();
  const bad = structuredClone(programs);
  bad.programs[0].caseIds.push("FUNCTIONS-EVENTS/firestore-created#unknown#v1");
  assert.throws(
    () =>
      compareRuns({
        corpus,
        programs: bad,
        productionRun: w.run,
        localSessions: { emulator: w.emulator, strict: w.strict },
        localProject: LOCAL_PROJECT,
      }),
    /unknown case/,
  );
  assert.throws(
    () =>
      compareRuns({
        corpus,
        programs,
        productionRun: w.run,
        localSessions: { emulator: w.emulator, strict: w.strict },
      }),
    /localProject/,
  );
  assert.throws(
    () =>
      compareRuns({
        corpus,
        programs,
        productionRun: w.run,
        localSessions: { emulator: w.emulator },
        localProject: LOCAL_PROJECT,
      }),
    /strict/,
  );
});
