import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import {
  ANSWER_KINDS,
  answerAgreement,
  answerKind,
  answerTable,
  renderAnswerTable,
} from "./fs-listen/resume-answers.mjs";

const L1 = JSON.parse(
  readFileSync(new URL("../fixtures/fs-listen/l1-production-rows.json", import.meta.url), "utf8"),
).recordings;
const recorded = (id) => L1["native-1"].rows[id];

const add = { kind: "targetChange", type: "ADD", targetIds: [1], cause: null, resumeToken: false };
const current = {
  kind: "targetChange",
  type: "CURRENT",
  targetIds: [1],
  cause: null,
  resumeToken: true,
};
const bnd = { kind: "boundary", resumeToken: true };
const doc = (name) => ({
  kind: "documentChange",
  doc: name,
  fields: {},
  targetIds: [1],
  removedTargetIds: [],
});
const gone = (name) => ({ kind: "documentDelete", doc: name, removedTargetIds: [1] });
const filter = (count, bits = { hashCount: 0, bitmapBytes: 0, padding: 0 }) => ({
  kind: "filter",
  targetId: 1,
  count,
  unchangedNames: bits,
});
const row = (rows, extra = {}) => ({ rows, end: null, timedOut: false, ...extra });
const kind = (rows, extra) => answerKind(row(rows, extra));

test("the recorded production answers of L1 are classified as the design note describes them", () => {
  // Each entry: the answer in run 1 (nmuuicyas) and in run 2 (nmuukwo6n). Production answers a
  // resume with nothing to replay with a filter in one run and none in the other (the L1 filters
  // that only one run sent), which the kinds keep apart as filter-only and empty.
  const expected = {
    "native/resume-token/current": ["replay", "replay"],
    "native/resume-token/older": ["diff+filter", "diff+filter"],
    "native/resume-token/unchanged": ["empty", "filter-only"],
    "native/resume-token/other-query": ["filter-only", "filter-only"],
    "native/resume-token/invalid": ["removed", "removed"],
    "native/existence-filter/with-expected-count": ["replay", "replay"],
    "native/existence-filter/without-expected-count": ["filter-only", "filter-only"],
    "native/existence-filter/no-change": ["empty", "filter-only"],
    "native/resume-token-expired/expired": ["diff+filter", "diff+filter"],
    "native/resume-token/first": ["diff", "diff"],
  };
  for (const [id, want] of Object.entries(expected))
    ["native-1", "native-2"].forEach((run, i) =>
      assert.equal(answerKind(L1[run].rows[id]), want[i], `${run} ${id}`),
    );
  // A fresh target's rows are initial snapshots, not resumes, but still classify: documents and no boundary between.
  assert.ok(ANSWER_KINDS.includes(answerKind(recorded("native/resume-token/fresh-control"))));
});

test("answerKind: the shapes", () => {
  assert.equal(kind([add, bnd, current, bnd]), "empty");
  assert.equal(kind([add, bnd, doc("a"), bnd, current, bnd]), "replay");
  assert.equal(kind([add, bnd, doc("a"), bnd, doc("b"), bnd, current, bnd]), "replay");
  assert.equal(
    kind([add, bnd, doc("a"), doc("b"), bnd, current, bnd]),
    "replay",
    "a run of two, one boundary",
  );
  assert.equal(kind([add, bnd, gone("a"), bnd, doc("b"), bnd, current, bnd]), "replay");
  assert.equal(kind([add, bnd, doc("a"), doc("b"), current, bnd]), "diff");
  assert.equal(kind([add, bnd, doc("a"), doc("b"), filter(2), current, bnd]), "diff+filter");
  assert.equal(kind([add, bnd, doc("a"), filter(1), current, bnd]), "diff+filter");
  assert.equal(kind([add, bnd, filter(0), current, bnd]), "filter-only");
  // Some replayed and some not: neither shape.
  assert.equal(kind([add, bnd, doc("a"), bnd, doc("b"), current, bnd]), "mixed");
  assert.equal(kind([add, bnd, doc("a"), bnd, doc("b"), bnd, doc("c"), current, bnd]), "mixed");
  assert.equal(kind([add, bnd, doc("a"), bnd, doc("b"), filter(2), current, bnd]), "mixed");
  assert.equal(
    kind([add, bnd, doc("a"), bnd, filter(1), current, bnd]),
    "mixed",
    "a filter and a replay",
  );
  // A RESET or a REMOVE is the answer, whatever else came.
  const reset = {
    kind: "targetChange",
    type: "RESET",
    targetIds: [1],
    cause: null,
    resumeToken: false,
  };
  const remove = {
    kind: "targetChange",
    type: "REMOVE",
    targetIds: [1],
    cause: { code: 3 },
    resumeToken: false,
  };
  assert.equal(kind([add, reset, doc("a"), current, bnd]), "reset");
  assert.equal(kind([remove]), "removed");
  assert.equal(kind([add, remove]), "removed");
});

test("answerKind looks at what comes before CURRENT only: later filters and boundaries change nothing", () => {
  const base = [add, bnd, doc("a"), bnd, current];
  for (const tail of [
    [],
    [bnd],
    [bnd, filter(1, { hashCount: 12, bitmapBytes: 4, padding: 7 })],
    [bnd, filter(1), bnd, doc("z")],
  ])
    assert.equal(kind([...base, ...tail]), "replay", JSON.stringify(tail));
  const diff = [add, bnd, doc("a"), doc("b"), current];
  for (const tail of [
    [],
    [bnd],
    [bnd, filter(2, { hashCount: 13, bitmapBytes: 8, padding: 3 })],
    [bnd, doc("z"), bnd],
  ])
    assert.equal(kind([...diff, ...tail]), "diff", JSON.stringify(tail));
  // A real bloom filter before CURRENT counts as a filter as well.
  assert.equal(
    kind([
      add,
      bnd,
      doc("a"),
      filter(1, { hashCount: 12, bitmapBytes: 4, padding: 7 }),
      current,
      bnd,
    ]),
    "diff+filter",
  );
});

test("answerKind: an unfinished row is not an answer", () => {
  assert.equal(kind([add, bnd], { timedOut: true }), "unfinished");
  assert.equal(kind([add, bnd, doc("a"), bnd, current, bnd], { programError: true }), "unfinished");
  assert.equal(kind([add, bnd, current, bnd], { end: { reason: "frame-cap" } }), "unfinished");
  assert.equal(
    kind([add, bnd, current, bnd], { end: { reason: "ended-without-status" } }),
    "unfinished",
  );
  // A wait that ran out because the target was removed with a cause is the answer.
  const remove = {
    kind: "targetChange",
    type: "REMOVE",
    targetIds: [1],
    cause: { code: 3 },
    resumeToken: false,
  };
  assert.equal(kind([remove], { timedOut: true }), "removed");
  // A row with no frames and no wait is empty of frames: no ADD, nothing answered.
  assert.equal(kind([]), "unfinished");
});

// A small seeded generator, so a failing property replays.
function prng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

test("answerKind over random segments agrees with a regular-expression oracle, and ignores the order of documents inside a run", () => {
  const random = prng(7);
  const pick = (n) => Math.floor(random() * n);
  const isDoc = (item) => item.kind === "documentChange" || item.kind === "documentDelete";
  const letter = (item) => (isDoc(item) ? "D" : item.kind === "boundary" ? "B" : "F");
  for (let round = 0; round < 600; round += 1) {
    // Between the first boundary and CURRENT: documents, boundaries and filters in random order.
    const segment = [];
    for (let i = 0, n = pick(8); i < n; i += 1) {
      const r = random();
      if (r < 0.5) segment.push(random() < 0.3 ? gone(`d${i}`) : doc(`d${i}`));
      else if (r < 0.85) segment.push(bnd);
      else segment.push(filter(pick(4)));
    }
    const rows = [add, bnd, ...segment, current, bnd];
    const s = segment.map(letter).join("");
    // Oracle.
    let want;
    if (!s.includes("D")) want = s.includes("F") ? "filter-only" : "empty";
    else {
      const afterFirstDoc = s.slice(s.indexOf("D"));
      const boundariesAfter = (afterFirstDoc.match(/B/g) ?? []).length;
      const allClosed = !/D([^DB]|$)/.test(s);
      if (boundariesAfter === 0) want = s.includes("F") ? "diff+filter" : "diff";
      else if (s.includes("F")) want = "mixed";
      else want = allClosed ? "replay" : "mixed";
    }
    assert.equal(answerKind(row(rows)), want, s);
    // Reversing each maximal run of documents changes nothing.
    const shuffled = [];
    let run = [];
    for (const item of rows) {
      if (isDoc(item)) run.push(item);
      else {
        shuffled.push(...run.toReversed(), item);
        run = [];
      }
    }
    shuffled.push(...run.toReversed());
    assert.equal(answerKind(row(shuffled)), want, `${s} reversed`);
  }
});

const recording = (rows) => ({ kind: "native", rows });
const named = (id, entry) => ({ [id]: entry });

test("answerTable lists the kind of each resume-variant row and nothing else", () => {
  const rows = {
    ...named("native/resume-grid-g0/k1", row([add, bnd, doc("a"), bnd, current, bnd])),
    ...named(
      "native/resume-grid-g0/k2",
      row([add, bnd, doc("a"), doc("b"), filter(2), current, bnd]),
    ),
    ...named("native/resume-token/current", row([add, bnd, current, bnd])),
    ...named("native/resume-age/first", row([add, bnd, doc("a"), current, bnd])),
  };
  assert.deepEqual(answerTable(recording(rows)), {
    "native/resume-grid-g0/k1": "replay",
    "native/resume-grid-g0/k2": "diff+filter",
    "native/resume-age/first": "diff",
  });
});

test("answerAgreement says, row by row, whether two runs gave the same kind of answer; a row only one run has, or an unfinished one, is not agreement", () => {
  const a = recording({
    ...named("native/resume-grid-g0/k1", row([add, bnd, doc("a"), bnd, current, bnd])),
    ...named(
      "native/resume-grid-g0/k2",
      row([add, bnd, doc("a"), doc("b"), filter(2), current, bnd]),
    ),
    ...named("native/resume-grid-g0/k3", row([add, bnd], { timedOut: true })),
    ...named("native/resume-grid-g0/k0", row([add, bnd, current, bnd])),
  });
  const b = recording({
    ...named("native/resume-grid-g0/k1", row([add, bnd, doc("a"), bnd, current, bnd])),
    ...named("native/resume-grid-g0/k2", row([add, bnd, doc("a"), doc("b"), current, bnd])),
    ...named("native/resume-grid-g0/k3", row([add, bnd], { timedOut: true })),
    ...named("native/resume-grid-g0/k1-repeat", row([add, bnd, current, bnd])),
  });
  assert.deepEqual(answerAgreement(a, b), {
    "native/resume-grid-g0/k0": { first: "empty", second: null, agree: false },
    "native/resume-grid-g0/k1": { first: "replay", second: "replay", agree: true },
    "native/resume-grid-g0/k1-repeat": { first: null, second: "empty", agree: false },
    "native/resume-grid-g0/k2": { first: "diff+filter", second: "diff", agree: false },
    "native/resume-grid-g0/k3": { first: "unfinished", second: "unfinished", agree: false },
  });
});

test("renderAnswerTable prints the grids as k by token and the other programs by row, with a mark where two runs disagree", () => {
  const rows = (kinds) =>
    Object.fromEntries(
      Object.entries(kinds).map(([id, k]) => [
        id,
        k === "replay"
          ? row([add, bnd, doc("a"), bnd, current, bnd])
          : row([add, bnd, doc("a"), doc("b"), filter(2), current, bnd]),
      ]),
    );
  const first = recording(
    rows({
      "native/resume-grid-g0/k1": "replay",
      "native/resume-grid-tc/k1": "diff+filter",
      "native/resume-kinds/modify": "replay",
    }),
  );
  const second = recording(
    rows({
      "native/resume-grid-g0/k1": "replay",
      "native/resume-grid-tc/k1": "replay",
      "native/resume-kinds/modify": "replay",
    }),
  );
  const text = renderAnswerTable(first, second);
  assert.match(text, /\| k1 \| replay \| diff\+filter \/ replay \(runs differ\) \|/);
  assert.match(text, /native\/resume-kinds\/modify \| replay/);
  assert.equal(text.includes("undefined"), false);
});

test("a row of a program that errored is unfinished, not an answer", () => {
  const rows = {
    ...named("native/resume-grid-g0/k1", {
      ...row([add, bnd, doc("a"), bnd, current, bnd]),
      program: "native/resume-grid-g0",
    }),
    ...named("native/resume-kinds/modify", {
      ...row([add, bnd, doc("a"), bnd, current, bnd]),
      program: "native/resume-kinds",
    }),
  };
  assert.deepEqual(answerTable({ rows, errors: { "native/resume-grid-g0": "boom" } }), {
    "native/resume-grid-g0/k1": "unfinished",
    "native/resume-kinds/modify": "replay",
  });
  assert.deepEqual(answerTable({ rows, errors: {} }), {
    "native/resume-grid-g0/k1": "replay",
    "native/resume-kinds/modify": "replay",
  });
});

const CLI = fileURLToPath(new URL("./fs-listen/resume-answers.mjs", import.meta.url));

function runCli(files, args) {
  const dir = mkdtempSync(join(tmpdir(), "fs-listen-answers-"));
  const made = Object.fromEntries(
    Object.entries(files).map(([name, value]) => {
      const file = join(dir, name);
      writeFileSync(file, JSON.stringify(value));
      return [name, file];
    }),
  );
  const out = spawnSync(process.execPath, [CLI, ...args(made)], {
    encoding: "utf8",
    env: { ...process.env, NODE_OPTIONS: "" },
  });
  return { code: out.status, stdout: out.stdout, stderr: out.stderr };
}

const clean = (rows) => ({
  version: 1,
  kind: "native",
  cleanup: { complete: true },
  errors: {},
  rows,
});

test("the command prints the table of two runs, of one run twice when given one, and refuses an unclean recording or no argument", () => {
  const a = clean(named("native/resume-grid-g0/k1", row([add, bnd, doc("a"), bnd, current, bnd])));
  const b = clean(
    named("native/resume-grid-g0/k1", row([add, bnd, doc("a"), doc("b"), filter(2), current, bnd])),
  );
  const two = runCli({ a, b }, (f) => [f.a, f.b]);
  assert.equal(two.code, 0, two.stderr);
  assert.match(two.stdout, /\| k1 \| replay \/ diff\+filter \(runs differ\) \| - \| - \|/);
  const one = runCli({ a }, (f) => [f.a]);
  assert.equal(one.code, 0, one.stderr);
  assert.match(one.stdout, /\| k1 \| replay \| - \| - \|/);
  const dirty = runCli({ a, d: { ...a, cleanup: { complete: false } } }, (f) => [f.a, f.d]);
  assert.equal(dirty.code, 2);
  assert.match(dirty.stderr, /cleanup was not complete/);
  const none = runCli({}, () => []);
  assert.equal(none.code, 2);
  assert.match(none.stderr, /usage/);
  const three = runCli({ a }, (f) => [f.a, f.a, f.a]);
  assert.equal(three.code, 2);
});

test("the answer kinds are exactly these nine", () => {
  assert.deepEqual(ANSWER_KINDS, [
    "empty",
    "filter-only",
    "replay",
    "diff",
    "diff+filter",
    "mixed",
    "reset",
    "removed",
    "unfinished",
  ]);
});

test("answerKind: documentRemove is a document; only the boundary right after the ADD is set aside", () => {
  const dropped = { kind: "documentRemove", doc: "a", removedTargetIds: [1] };
  assert.equal(kind([add, bnd, dropped, bnd, current, bnd]), "replay");
  assert.equal(kind([add, bnd, dropped, current, bnd]), "diff");
  // A segment that starts with a document (no boundary after the ADD): nothing is set aside.
  assert.equal(kind([add, doc("a"), bnd, current, bnd]), "replay");
  assert.equal(kind([add, doc("a"), current, bnd]), "diff");
  assert.equal(kind([add, filter(1), current, bnd]), "filter-only");
  assert.equal(kind([add, current, bnd]), "empty");
  // A second boundary at the start is a boundary of the segment, before any document: it changes nothing.
  assert.equal(kind([add, bnd, bnd, doc("a"), bnd, current, bnd]), "replay");
  assert.equal(kind([add, bnd, bnd, doc("a"), current, bnd]), "diff");
  assert.equal(kind([add, bnd, bnd, current, bnd]), "empty");
  // A boundary between a document and the next, with the first boundary being the one set aside.
  assert.equal(kind([add, bnd, doc("a"), bnd, bnd, doc("b"), bnd, current]), "replay");
  // The segment ends at the first CURRENT; a CURRENT before the ADD is no answer.
  assert.equal(kind([current, add, bnd, doc("a"), bnd]), "unfinished");
  assert.equal(kind([add, bnd, doc("a"), bnd, current, doc("z"), current]), "replay");
});

test("renderAnswerTable prints exactly this table", () => {
  const replayRow = row([add, bnd, doc("a"), bnd, current, bnd]);
  const diffRow = row([add, bnd, doc("a"), doc("b"), filter(2), current, bnd]);
  const text = renderAnswerTable(
    recording({
      "native/resume-grid-g0/k0": replayRow,
      "native/resume-grid-tc/k0": diffRow,
      "native/resume-grid-gc/k3": diffRow,
      "native/resume-age/age-30s-k1": replayRow,
      "native/resume-kinds/leave": diffRow,
    }),
    recording({
      "native/resume-grid-g0/k0": replayRow,
      "native/resume-grid-tc/k0": replayRow,
      "native/resume-grid-gc/k3": diffRow,
      "native/resume-age/age-30s-k1": replayRow,
    }),
  );
  assert.equal(
    text,
    [
      "| row | g0 | tc | gc |",
      "|---|---|---|---|",
      "| first | - | - | - |",
      "| k0 | replay | diff+filter / replay (runs differ) | - |",
      "| k1 | - | - | - |",
      "| k1-repeat | - | - | - |",
      "| k1-expected | - | - | - |",
      "| k2 | - | - | - |",
      "| k2-expected | - | - | - |",
      "| k2-wrong | - | - | - |",
      "| k3 | - | - | diff+filter |",
      "",
      "| row | answer |",
      "|---|---|",
      "| native/resume-age/age-30s-k1 | replay |",
      "| native/resume-kinds/leave | diff+filter / - (runs differ) |",
    ].join("\n"),
  );
});

test("a command refusal names every problem of a recording, separated by semicolons; importing the module runs nothing", () => {
  const bad = {
    version: 1,
    kind: "native",
    cleanup: { complete: false },
    errors: { "sdk/x": "boom" },
    rows: {},
  };
  const out = runCli({ bad }, (f) => [f.bad]);
  assert.equal(out.code, 2);
  assert.match(out.stderr, /a recording is not clean: cleanup was not complete; sdk\/x: boom/);
  const imported = spawnSync(
    process.execPath,
    ["--input-type=module", "-e", `await import(${JSON.stringify(CLI)})`],
    { encoding: "utf8", env: { ...process.env, NODE_OPTIONS: "" } },
  );
  assert.equal(imported.status, 0, imported.stderr);
  assert.equal(imported.stderr, "");
  assert.equal(imported.stdout, "");
});
