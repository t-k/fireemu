// Replays the two production recordings of the kinds follow-up through the judge and against the local
// recordings of fireemu's strict and emulator profiles: RTDB-TRIGGERS-KINDS-20261108-01 (k1 to k13, 72
// frames, stopped by the 400 of k13) and RTDB-TRIGGERS-KINDS-20261109-02 (k15 to k26, 43 frames). The
// fixtures are the masked run directories (kinds-mask.mjs); the local ones are real runs of a release build
// of this tree (kinds-local-run.mjs), masked the same way.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { compareRecordings } from "./kinds-compare.mjs";
import { judgeRun } from "./kinds-judge.mjs";
import { MASKED_NONCE } from "./kinds-mask.mjs";
import { KINDS_V2_SCENARIO } from "./kinds-scenario.mjs";
import { buildSteps, observe } from "./kinds-sequence.mjs";

const read = (name) =>
  JSON.parse(readFileSync(new URL(`./recorded/${name}.json`, import.meta.url), "utf8"));
const FIRST = buildSteps(MASKED_NONCE);
const SECOND = KINDS_V2_SCENARIO.buildSteps(MASKED_NONCE);
const REFUSAL =
  '{\n  "error" : "This request would cause a function payload exceeding the maximum size allowed."\n}\n';

const judged = (recording, steps) => {
  const writes = Object.fromEntries(recording.steps.map((step) => [step.id, step.write]));
  const report = observe({ writes, frames: recording.frames, steps });
  return {
    report,
    reasons: judgeRun({
      report,
      frames: recording.frames,
      writes,
      ignored: {},
      userUid: "<uid>",
    }),
  };
};
const stepOf = (row) => Number(row.row[0].slice(1));
const totals = (rows) => ({
  rows: rows.length,
  match: rows.filter((r) => r.verdict === "MATCH").length,
  difference: rows.filter((r) => r.verdict !== "MATCH").length,
});

test("the first recording passes the judge: k1 to k13, every frame attributed, k13 refused with the recorded 400", () => {
  const production = read("production-rtdb-kinds");
  assert.equal(production.frames.length, 72);
  const { report, reasons } = judged(production, FIRST);
  assert.deepEqual(reasons, []);
  assert.deepEqual(report.totals, { frames: 72, attributed: 72, unattributed: 0 });
  const answers = Object.fromEntries(production.answers.map((a) => [a.step, a]));
  assert.deepEqual(
    Object.keys(answers),
    Array.from({ length: 13 }, (_, i) => `k${i + 1}`),
  );
  for (let n = 1; n <= 12; n += 1) assert.equal(answers[`k${n}`].status, 200);
  assert.equal(answers.k11.bytes, 102446);
  assert.equal(answers.k12.bytes, 614446);
  assert.deepEqual(
    [answers.k13.status, answers.k13.outcome, answers.k13.bytes, answers.k13.body],
    [400, "refused", 98, REFUSAL],
  );
  assert.equal(REFUSAL.length, 98);
});

test("the second recording passes the judge: k15 to k26, 43 frames, the ladder refused from the 1.05 MB rung", () => {
  const production = read("production-rtdb-kinds-user-ladder");
  assert.equal(production.frames.length, 43);
  const { report, reasons } = judged(production, SECOND);
  assert.deepEqual(reasons, []);
  assert.deepEqual(report.totals, { frames: 43, attributed: 43, unattributed: 0 });
  const answers = Object.fromEntries(production.answers.map((a) => [a.step, a]));
  assert.deepEqual(
    ["k15", "k16", "k17", "k22", "k23", "k24", "k25", "k26"].map((id) => [
      id,
      answers[id].status,
      answers[id].bytes,
    ]),
    [
      ["k15", 200, 36],
      ["k16", 200, 11],
      ["k17", 200, 4],
      ["k22", 200, 614447],
      ["k23", 200, 949947],
      ["k24", 200, 1023947],
      ["k25", 400, 98],
      ["k26", 400, 98],
    ],
  );
  assert.equal(answers.k25.body, REFUSAL);
  assert.equal(answers.k26.body, REFUSAL);
  // the accepted rungs are delivered to the three item handlers and the group handler, the refused ones to none
  const perStep = (id) => production.frames.filter((f) => f.step === id).length;
  for (const id of ["k22", "k23", "k24"]) assert.equal(perStep(id), 4, id);
  for (const id of ["k25", "k26"]) assert.equal(perStep(id), 0, id);
  // the SDK steps were answered ok and each delivered all it was expected to (judged, no reason above)
  for (const id of ["k18", "k19", "k20", "k21"])
    assert.equal(production.steps.find((s) => s.id === id).write.outcome, "ok", id);
});

test("the strict profile matches the second recording in every row, ladder and user writes included", () => {
  const production = read("production-rtdb-kinds-user-ladder");
  const local = read("local-strict-rtdb-kinds-user-ladder");
  const comparison = compareRecordings({
    production: production.frames,
    local: local.frames,
    steps: SECOND,
  });
  assert.deepEqual(comparison.unattributed, { production: [], local: [] });
  assert.deepEqual(comparison.totals, { rows: 43, match: 43, difference: 0 });
});

test("the strict profile matches the first recording except the 600 KiB write k12, which production did not deliver once", () => {
  const production = read("production-rtdb-kinds");
  const local = read("local-strict-rtdb-kinds");
  const comparison = compareRecordings({
    production: production.frames,
    local: local.frames.filter((f) => Number(f.step.slice(1)) <= 13),
  });
  assert.deepEqual(comparison.totals, { rows: 76, match: 72, difference: 4 });
  const differing = comparison.rows.filter((r) => r.verdict !== "MATCH");
  // the only difference: four handlers did not deliver k12's 600 KiB create in production's first recording
  // while fireemu delivers it, as production did for the same shape in the second recording (k22). A
  // one-off, unexplained observation; fireemu is unchanged.
  assert.deepEqual(
    differing.map((r) => [r.row[0], r.production, r.local]),
    [
      ["k12", 0, 1],
      ["k12", 0, 1],
      ["k12", 0, 1],
      ["k12", 0, 1],
    ],
  );
});

// The members the emulator profile's events differ in, all declared: the event shape of the official emulator
// (/knownDifferences/triggerEventShapeEmulatorProfile: id, time, source, datacontenttype, the principal in
// authtype, the missing traceparent, the 2nd gen `context` key set, the 1st gen context's id and time) and
// the priorities the emulator profile keeps in an event (strict sends none, as production did; the official
// emulator was not measured).
const SHAPE_MEMBERS = new Set([
  "authType",
  "context.eventId",
  "context.timestamp",
  "datacontenttype",
  "eventKeys.datacontenttype",
  "eventKeys.traceparent",
  "extras.context.keys",
  "extras.traceparent",
  "id",
  "source",
  "time",
]);
const memberOf = (path) =>
  path.replace(/^\$\[\d+\]\.frame\.event\./u, "").replace(/\.(\d+)\b/gu, "");
const isPriority = (member) =>
  /^data\.(?:before\.|after\.)?value(?:\.items\.[^.]+)?\.\.priority$|^data\.(?:before\.|after\.)?value(?:\.items\.[^.]+)?$|^data\.value(?:\.\.priority)?$/u.test(
    member,
  );

const declared = (comparison, steps) => {
  const undeclared = [];
  const noProduction = [];
  for (const row of comparison.rows) {
    assert.equal(row.verdict, "DIFFERENCE", `${row.row}`);
    if (row.production === 0) {
      noProduction.push(row.row[0]);
      continue;
    }
    for (const difference of row.differences) {
      const member = memberOf(difference.path);
      const priorityStep = [7, 8, 9, 10].includes(stepOf(row));
      if (!SHAPE_MEMBERS.has(member) && !(priorityStep && isPriority(member)))
        undeclared.push(`${row.row.join("/")} ${member}`);
    }
  }
  assert.ok(steps.length > 0);
  return { undeclared, noProduction: [...new Set(noProduction)] };
};

test("the emulator profile differs from the second recording only in declared members, and delivers the two refused rungs", () => {
  const production = read("production-rtdb-kinds-user-ladder");
  const local = read("local-emulator-rtdb-kinds-user-ladder");
  const comparison = compareRecordings({
    production: production.frames,
    local: local.frames,
    steps: SECOND,
  });
  assert.deepEqual(totals(comparison.rows), { rows: 51, match: 0, difference: 51 });
  const { undeclared, noProduction } = declared(comparison, SECOND);
  assert.deepEqual(undeclared, []);
  // no size limit in the emulator profile: it delivers what production refused (k25, k26)
  assert.deepEqual(noProduction, ["k25", "k26"]);
});

test("the emulator profile differs from the first recording only in declared members, with the priorities, k12 and k13 apart", () => {
  const production = read("production-rtdb-kinds");
  const local = read("local-emulator-rtdb-kinds");
  const comparison = compareRecordings({
    production: production.frames,
    local: local.frames.filter((f) => stepOf({ row: [f.step] }) <= 13),
  });
  assert.deepEqual(totals(comparison.rows), { rows: 80, match: 0, difference: 80 });
  const { undeclared, noProduction } = declared(comparison, FIRST);
  assert.deepEqual(undeclared, []);
  assert.deepEqual(noProduction, ["k12", "k13"]);
});

test("strict events carry no priority member where the emulator profile's do: production's priority rows", () => {
  const production = read("production-rtdb-kinds");
  const strict = read("local-strict-rtdb-kinds");
  const emulator = read("local-emulator-rtdb-kinds");
  const text = (recording) =>
    JSON.stringify(
      recording.frames.filter((f) => ["k7", "k9", "k10"].includes(f.step)).map((f) => f.event),
    );
  assert.equal(text(production).includes('".priority"'), false);
  assert.equal(text(strict).includes('".priority"'), false);
  assert.equal(text(emulator).includes('".priority"'), true);
  // the priority-only write k8 shows its new priority as the delta merged into `after`, in production and strict
  const after = (recording) =>
    recording.frames
      .filter((f) => f.step === "k8" && f.handler === "k9UpdatedV2")
      .map((f) => f.event.data.after.value);
  assert.deepEqual(after(strict), after(production));
  assert.equal(after(production)[0][".priority"], 9);
});
