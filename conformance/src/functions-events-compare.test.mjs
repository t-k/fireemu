import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  GEN2_FIRESTORE_FIELD_MAPS,
  compareRuns,
  orderIgnoredFor,
} from "./functions-events/compare/compare.mjs";
import {
  LOCAL_PROJECT,
  PRODUCTION_PROJECT,
  T0,
  firestoreFrame,
  frameEntry,
  op,
} from "./functions-events/compare/fixtures/build.mjs";

const readJson = (path) => JSON.parse(readFileSync(new URL(path, import.meta.url)));
const corpus = readJson("../functions-events/corpus.json");
const programs = readJson("../functions-events/programs.json");

import { docId, uuid, world } from "./functions-events/compare/fixtures/world.mjs";

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

test("every row carries a status and the reasons of each profile; production-side problems count against both", () => {
  const w = world();
  // a strict-only difference
  for (const program of w.strict.programs)
    for (const operation of program.operations)
      for (const entry of operation.framesByGeneration.v1) {
        const frame = JSON.parse(entry.rawJson);
        frame.event.context.eventType = "providers/cloud.firestore/eventTypes/document.create";
        entry.rawJson = JSON.stringify(frame);
      }
  const result = compare(w);
  const diff = rowById(result, "functions-events/firestore/create#new-document#v1");
  assert.deepEqual(diff.production, { status: "MATCH", reasons: [] });
  assert.deepEqual(Object.keys(diff.profiles), ["emulator", "strict"]);
  assert.deepEqual(diff.profiles.emulator, { status: "MATCH", reasons: [] });
  assert.equal(diff.profiles.strict.status, "DIFF");
  assert.deepEqual(diff.profiles.strict.reasons, diff.reasons);
  const match = rowById(result, "functions-events/firestore/create#new-document#v2");
  assert.deepEqual(match.profiles, {
    emulator: { status: "MATCH", reasons: [] },
    strict: { status: "MATCH", reasons: [] },
  });
  // an emulator-only difference does not touch strict
  const e = world();
  for (const program of e.emulator.programs)
    for (const operation of program.operations)
      for (const entry of operation.framesByGeneration.v1) {
        const frame = JSON.parse(entry.rawJson);
        frame.event.context.eventType = "providers/cloud.firestore/eventTypes/document.create";
        entry.rawJson = JSON.stringify(frame);
      }
  const only = rowById(compare(e), "functions-events/firestore/create#new-document#v1");
  assert.equal(only.status, "DIFF");
  assert.equal(only.profiles.emulator.status, "DIFF");
  assert.deepEqual(only.profiles.strict, { status: "MATCH", reasons: [] });
});

test("a production-side INCOMPLETE is INCOMPLETE in both profiles, with its reason in each", () => {
  const w = world();
  const pass2 = w.run.frames.find(
    (entry) =>
      entry.handler === "fsCreatedV1" &&
      entry.frame.event.context.resource.name.endsWith(docId(201)),
  );
  pass2.frame.event.context.authType = "ADMIN";
  const row = rowById(compare(w), "functions-events/firestore/create#new-document#v1");
  for (const profile of ["emulator", "strict"]) {
    assert.equal(row.profiles[profile].status, "INCOMPLETE", profile);
    assert.deepEqual(row.profiles[profile].reasons, row.reasons, profile);
  }
  // the production side is its own entry: its status and reasons, which both profiles include
  assert.equal(row.production.status, "INCOMPLETE");
  assert.deepEqual(row.production.reasons, row.reasons);
  assert.ok(row.production.reasons.every((r) => r.startsWith("production passes disagree")));
  // a local-driver problem of one profile stays that profile's, next to the production reasons
  const m = world();
  const update = rowById(compare(m), "functions-events/firestore/update#changed-field#v1");
  assert.ok(
    update.profiles.strict.reasons.includes(
      "production pass 1: 0 subject operations for fs-update",
    ),
  );
  assert.ok(
    update.profiles.strict.reasons.includes(
      "strict: local session has no functions-events/firestore/update program",
    ),
  );
  assert.equal(update.production.status, "INCOMPLETE");
  assert.deepEqual(update.production.reasons, [
    "production pass 1: 0 subject operations for fs-update",
    "production pass 2: 0 subject operations for fs-update",
  ]);
  assert.ok(!update.profiles.strict.reasons.some((r) => r.startsWith("emulator:")));
  assert.ok(!update.profiles.emulator.reasons.some((r) => r.startsWith("strict:")));
});

function reorderLocalData(w, generation, mutate = (data) => data) {
  for (const profile of ["emulator", "strict"])
    for (const program of w[profile].programs)
      for (const operation of program.operations)
        for (const entry of operation.framesByGeneration[`v${generation}`]) {
          const frame = JSON.parse(entry.rawJson);
          const { data } = frame.event.data;
          frame.event.data.data = mutate(Object.fromEntries(Object.entries(data).reverse()));
          entry.rawJson = JSON.stringify(frame);
        }
}

test("ledger 840: a Gen2 Firestore field map in another order is a MATCH, a different value is a DIFF, and Gen1 order still DIFFs", () => {
  const w = world();
  reorderLocalData(w, 2);
  const v2 = rowById(compare(w), "functions-events/firestore/create#new-document#v2");
  assert.equal(v2.status, "MATCH", v2.reasons.join("; "));
  assert.deepEqual(v2.profiles.strict, { status: "MATCH", reasons: [] });

  const valued = world();
  reorderLocalData(valued, 2, (data) => ({ ...data, count: data.count + 1 }));
  const changed = rowById(compare(valued), "functions-events/firestore/create#new-document#v2");
  assert.equal(changed.status, "DIFF");
  assert.ok(
    changed.reasons.some((r) => r.startsWith("strict: value $.frame.event.data.data.count ")),
    changed.reasons.join("; "),
  );
  assert.ok(!changed.reasons.some((r) => r.includes(": order ")));

  const gen1 = world();
  reorderLocalData(gen1, 1);
  const v1 = rowById(compare(gen1), "functions-events/firestore/create#new-document#v1");
  assert.equal(v1.status, "DIFF");
  assert.ok(v1.reasons.some((r) => r.startsWith("strict: order $.frame.event.data.data (")));
  // the Gen2 row of the same world is untouched by the Gen1 reordering
  assert.equal(
    rowById(compare(gen1), "functions-events/firestore/create#new-document#v2").status,
    "MATCH",
  );
});

test("ledger 840 reaches only Gen2 Firestore: another member's order in a Gen2 Firestore frame still DIFFs", () => {
  const w = world();
  for (const profile of ["emulator", "strict"])
    for (const program of w[profile].programs)
      for (const operation of program.operations)
        for (const entry of operation.framesByGeneration.v2) {
          const frame = JSON.parse(entry.rawJson);
          frame.event = Object.fromEntries(Object.entries(frame.event).reverse());
          entry.rawJson = JSON.stringify(frame);
        }
  const v2 = rowById(compare(w), "functions-events/firestore/create#new-document#v2");
  assert.equal(v2.status, "DIFF");
  assert.ok(
    v2.reasons.some((r) => r.startsWith("strict: order $.frame.event (")),
    v2.reasons.join("; "),
  );
});

test("order is ignored only for the three Gen2 Firestore field maps and what lies under them", () => {
  const ignored = orderIgnoredFor({ generation: 2 }, { source: "firestore" });
  for (const root of GEN2_FIRESTORE_FIELD_MAPS) {
    assert.equal(ignored(root), true, root);
    assert.equal(ignored(`${root}.nested`), true, root);
    assert.equal(ignored(`${root}.nested.deeper`), true, root);
    assert.equal(ignored(`${root}[0]`), true, root);
    assert.equal(ignored(`${root}x`), false, `${root}x`);
  }
  assert.equal(GEN2_FIRESTORE_FIELD_MAPS.length, 3);
  for (const path of [
    "$.frame.event",
    "$.frame.event.data",
    "$.frame.event.data.before",
    "$.frame.event.data.after",
    "$.frame.event.context.resource",
    "$.frame.event.data.dataX",
    "$.frame.event.data.value.data",
  ])
    assert.equal(ignored(path), false, path);
  for (const [row, scenario] of [
    [{ generation: 1 }, { source: "firestore" }],
    [{ generation: 2 }, { source: "storage" }],
    [{ generation: 2 }, { source: "auth" }],
    [{ generation: 2 }, { source: "pubsub" }],
  ])
    assert.equal(orderIgnoredFor(row, scenario)("$.frame.event.data.data"), false);
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

test("negative case: a frame of the handler whose resource cannot be identified leaves the absence unproven", () => {
  const s = T0 + 60_000;
  const unowned = (path) =>
    firestoreFrame({
      handler: "fsCreatedV1",
      generation: 1,
      project: PRODUCTION_PROJECT,
      path,
      eventId: uuid(8),
      timeMs: s + 50_000,
    });
  const owned = world();
  owned.run.frames.push(frameEntry(unowned("fe_events_primary/unknown"), s + 51_000));
  const ignored = compare(owned);
  assert.equal(
    rowById(ignored, "functions-events/firestore/routing#nonmatching-path#v1").status,
    "MATCH",
    "a frame for a resource no operation owns cannot be the subject's",
  );
  assert.equal(ignored.frameAccounting.unowned, 1);
  assert.equal(ignored.frameAccounting.unidentified, 0);

  for (const blank of [
    (frame) => {
      delete frame.event.data.path;
      delete frame.event.context.resource.name;
    },
    (frame) => {
      frame.source = "unknown";
    },
  ]) {
    const w = world();
    const frame = unowned("fe_events_primary/unknown");
    blank(frame);
    w.run.frames.push(frameEntry(frame, s + 51_000));
    const result = compare(w);
    const row = rowById(result, "functions-events/firestore/routing#nonmatching-path#v1");
    assert.equal(row.status, "INCOMPLETE");
    assert.ok(
      row.reasons.includes(
        "production pass 1: 1 fsCreatedV1 frame(s) with no identifiable resource during or after the observation",
      ),
    );
    assert.equal(result.frameAccounting.unidentified, 1);
    const before = world();
    before.run.frames.push(frameEntry(frame, s + 9_000));
    assert.equal(
      rowById(compare(before), "functions-events/firestore/routing#nonmatching-path#v1").status,
      "MATCH",
      "an unidentified frame logged before the operation cannot be its event",
    );
  }
});

test("frames of the subject resource from other mutations are not the subject's; a frame near two operations is INCOMPLETE", () => {
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
  const nearFrame = frameEntry(
    firestoreFrame({
      handler: "fsCreatedV1",
      generation: 1,
      project: PRODUCTION_PROJECT,
      path,
      eventId: uuid(11),
      timeMs: s - 400,
    }),
    s + 1500,
  );
  near.run.frames.push(nearFrame);
  // alone, the one operation of the resource owns a frame within the tolerance of its window
  const single = rowById(compare(near), "functions-events/firestore/create#new-document#v1");
  assert.ok(
    !single.reasons.some((reason) => reason.includes("cannot be attributed")),
    single.reasons.join("; "),
  );
  // with a second operation on the same resource whose window it is near too, the frame is nobody's: fail closed
  near.run.passes[0].operations.push(
    op({
      scenarioId: "fs-update",
      start: s - 1600,
      end: s - 500,
      matchKey: { kind: "firestore", value: path },
    }),
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
  w.strict.programs[0].operations[0].sourceResult = "typed-refusal";
  const result = compare(w);
  assert.equal(rowById(result, "functions-events/firestore/create#new-document#v1").status, "DIFF");
  assert.equal(result.conditions["FUNCTIONS-EVENTS/firestore-created"], "DIFF");
  assert.equal(result.conditions["FUNCTIONS-EVENTS/firestore-routing-params"], "MATCH");
  assert.equal(result.conditions["FUNCTIONS-EVENTS/delivery-retry-identity"], "MATCH");
  assert.equal(result.conditions["FUNCTIONS-EVENTS/auth-created"], "INCOMPLETE");
});

test("source readbacks are recorded for review but never compared", () => {
  const w = world();
  w.strict.programs[0].operations[0].readback = { exists: false, path: "x" };
  w.run.passes[0].operations[0].readback = [{ id: "fs-create.2", status: 200 }];
  const result = compare(w);
  assert.equal(
    rowById(result, "functions-events/firestore/create#new-document#v1").status,
    "MATCH",
  );
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

test("duplicate deliveries of one subject must agree with each other to pick a representative", () => {
  const pass1V1 = (w) =>
    w.run.frames.find(
      (entry) =>
        entry.handler === "fsCreatedV1" &&
        entry.frame.event.context.resource.name.endsWith(docId(101)),
    );
  const duplicate = (w, edit) => {
    const copy = structuredClone(pass1V1(w));
    copy.insertId = "duplicate-delivery";
    copy.logTimestamp = new Date(T0 + 60_000 + 5000).toISOString();
    edit(copy.frame);
    w.run.frames.push(copy);
  };
  const same = world();
  duplicate(same, (frame) => {
    frame.event.extensionAttributes = { traceparent: "00-other" };
  });
  assert.equal(
    rowById(compare(same), "functions-events/firestore/create#new-document#v1").status,
    "MATCH",
  );

  const differ = world();
  duplicate(differ, (frame) => {
    frame.event.data.data.value = "other";
  });
  const row = rowById(compare(differ), "functions-events/firestore/create#new-document#v1");
  assert.equal(row.status, "INCOMPLETE");
  assert.deepEqual(row.reasons, [
    "production pass 1: 2 fsCreatedV1 frames of the subject differ from each other",
  ]);

  const local = world();
  const subject = local.emulator.programs[0].operations[0];
  const second = JSON.parse(subject.framesByGeneration.v1[0].rawJson);
  subject.framesByGeneration.v1.push({
    sequence: 9,
    receivedAt: "x",
    rawJson: JSON.stringify(second),
  });
  assert.equal(
    rowById(compare(local), "functions-events/firestore/create#new-document#v1").status,
    "MATCH",
  );
  second.event.data.data.count = 2;
  subject.framesByGeneration.v1[1].rawJson = JSON.stringify(second);
  const localRow = rowById(compare(local), "functions-events/firestore/create#new-document#v1");
  assert.equal(localRow.status, "INCOMPLETE");
  assert.deepEqual(localRow.reasons, [
    "emulator: 2 local fsCreatedV1 frames differ from each other",
  ]);
});

test("ledger 840 reaches the derivation of volatile paths too: production passes that differ only in field-map order derive no volatile order there", () => {
  const w = world();
  const pass2 = (generation) =>
    w.run.frames.find(
      (entry) =>
        entry.handler === `fsCreatedV${generation}` &&
        JSON.stringify(entry.frame).includes(docId(201)),
    );
  for (const generation of [1, 2]) {
    const entry = pass2(generation);
    entry.frame.event.data.data = Object.fromEntries(
      Object.entries(entry.frame.event.data.data).reverse(),
    );
  }
  const result = compare(w);
  const v2 = rowById(result, "functions-events/firestore/create#new-document#v2");
  assert.equal(v2.status, "MATCH", v2.reasons.join("; "));
  const volatile2 = result.volatilePaths["fsCreatedV2/fs-create"];
  assert.equal(
    "$.frame.event.data.data" in volatile2,
    false,
    "a Gen2 field map is not volatile in order",
  );
  // Gen1 keeps the order feature: production's own passes differ in order there, so it is volatile (and not a DIFF)
  const volatile1 = result.volatilePaths["fsCreatedV1/fs-create"];
  assert.deepEqual(volatile1["$.frame.event.data.data"], ["order"]);
});
