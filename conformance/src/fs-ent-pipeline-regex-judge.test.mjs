// The judge of the pipeline regex observation: how a recorded answer is read, how it is set
// against the RE2 prediction and against fireemu, and that an unrecorded shape fails closed.
// Answers here are the shapes FS-ENT-ORACLE O-8B recorded (fs-ent-pipeline-production.json).

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  expectedOutcome,
  readAnswer,
  reportRows,
  sameOutcome,
  verdictOf,
} from "./fs-ent-pipeline/regex-judge.mjs";
import { PAIRS, REGEX_FUNCTIONS, REGEX_PREFIX, stepIdOf } from "./fs-ent-pipeline/regex-corpus.mjs";
import { forAll, pick } from "./fs-ent-pipeline/test-support.mjs";

const ok = (value) => ({
  status: 200,
  body: [{ executionTime: "<t1>", results: [{ fields: { v: value } }] }],
});
const syntax = {
  status: 400,
  body: [
    { error: { code: 400, message: "Unsupported regex syntax.", status: "INVALID_ARGUMENT" } },
  ],
};
const captures = {
  status: 400,
  body: [
    {
      error: {
        code: 400,
        message: "At most one capture group is supported.",
        status: "INVALID_ARGUMENT",
      },
    },
  ],
};
const bool = (v) => ({ booleanValue: v });
const text = (v) => ({ stringValue: v });
const none = { nullValue: null };
const list = (...v) => ({ arrayValue: v.length ? { values: v } : {} });

test("recorded O-8B answers are read as their value", () => {
  assert.deepEqual(readAnswer(ok(bool(true))), { kind: "bool", value: true });
  assert.deepEqual(readAnswer(ok(bool(false))), { kind: "bool", value: false });
  assert.deepEqual(readAnswer(ok(text("o"))), { kind: "string", value: "o" });
  assert.deepEqual(readAnswer(ok(text(""))), { kind: "string", value: "" });
  assert.deepEqual(readAnswer(ok(none)), { kind: "null" });
  assert.deepEqual(readAnswer(ok(list())), { kind: "array", items: [] });
  assert.deepEqual(readAnswer(ok(list(text("o"), text("o")))), {
    kind: "array",
    items: [
      { kind: "string", value: "o" },
      { kind: "string", value: "o" },
    ],
  });
  assert.deepEqual(readAnswer(ok(list(text("a"), none))), {
    kind: "array",
    items: [{ kind: "string", value: "a" }, { kind: "null" }],
  });
  assert.deepEqual(readAnswer(syntax), { kind: "refused-syntax" });
  assert.deepEqual(readAnswer(captures), { kind: "refused-captures" });
});

test("the real recorded rows of the same route read as they were recorded", () => {
  const fixture = JSON.parse(
    readFileSync(new URL("../fs-ent-pipeline-production.json", import.meta.url), "utf8"),
  );
  const steps = fixture.programs["fs-ent-pipeline/o8b/strings-main"].steps;
  const expect = {
    "regex-contains-unicode": { kind: "bool", value: true },
    "regex-contains-invalid-pattern": { kind: "refused-syntax" },
    "regex-find-all-all": {
      kind: "array",
      items: [
        { kind: "string", value: "o" },
        { kind: "string", value: "o" },
      ],
    },
    "regex-find-first": { kind: "string", value: "o" },
    "regex-find-none": { kind: "null" },
    "regex-find-all-none": { kind: "array", items: [] },
    "regex-find-empty-match": { kind: "string", value: "" },
    "regex-match-partial": { kind: "bool", value: false },
    "regex-find-group": { kind: "string", value: "W" },
  };
  for (const [id, outcome] of Object.entries(expect)) {
    assert.deepEqual(readAnswer(steps[id]), outcome, id);
  }
});

test("every unrecorded shape is unknown, never a value", () => {
  const unknown = (answer, why) =>
    assert.equal(readAnswer(answer).kind, "unknown", why ?? JSON.stringify(answer));
  unknown(undefined, "no answer");
  unknown({ status: 500, body: [] }, "500");
  unknown({ status: 503, body: [{ error: { code: 503 } }] }, "503");
  unknown({ status: 302, body: [] }, "3xx");
  unknown({ status: 0, body: [] }, "sub-200");
  unknown({ status: 408, body: [] }, "408");
  unknown({ status: 200, unresolved: true }, "recorder marker");
  unknown({ status: 200, body: "text" }, "text body");
  unknown({ status: 200, body: [] }, "no frame");
  unknown({ status: 200, body: [{ executionTime: "t", results: [] }] }, "no result");
  unknown({ status: 200, body: [{ executionTime: "t", results: [{}] }] }, "no fields");
  unknown({ status: 200, body: [{ executionTime: "t", results: [{ fields: {} }] }] }, "no v");
  unknown(ok({ integerValue: "1" }), "integer");
  unknown(ok({ stringValue: "a", extra: 1 }), "two keys in the value");
  unknown({ status: 200, other: 1 }, "a second key in place of the body");
  unknown({ status: 201, body: ok(bool(true)).body }, "a 2xx that is not 200");
  unknown({ status: 299, body: ok(bool(true)).body }, "the top of the 2xx range");
  unknown(ok({ booleanValue: "true" }), "a boolean value that is text");
  unknown(ok({ stringValue: 1 }), "a string value that is a number");
  unknown(ok({ nullValue: 0 }), "a null value that is not null");
  unknown(ok({ arrayValue: { values: [] } }), "an array with an empty values list");
  unknown(ok(list(text("a"), { integerValue: "1" })), "one good item and one bad");
  unknown(ok(list({ integerValue: "1" }, text("a"))), "one bad item and one good");
  unknown(
    {
      status: 400,
      body: [
        { error: { code: 500, message: "Unsupported regex syntax.", status: "INVALID_ARGUMENT" } },
      ],
    },
    "the error code is not the status",
  );
  unknown(
    { status: 501, body: [{ error: { code: 400, message: "x", status: "UNIMPLEMENTED" } }] },
    "a 501 whose error code is 400",
  );
  unknown(
    { status: 501, body: [{ error: { code: 501, message: 7, status: "UNIMPLEMENTED" } }] },
    "a 501 whose message is not text",
  );
  unknown(ok(list({ integerValue: "1" })), "integer item");
  unknown(ok(list(list())), "nested array");
  unknown({ ...ok(bool(true)), extra: 1 }, "extra key of the answer");
  unknown({ status: 200, body: [...ok(bool(true)).body, ...ok(bool(true)).body] }, "two frames");
  unknown(
    {
      status: 200,
      body: [{ executionTime: "t", results: [{ fields: { v: bool(true), w: bool(true) } }] }],
    },
    "two fields",
  );
  unknown(
    {
      status: 200,
      body: [
        {
          executionTime: "t",
          results: [{ fields: { v: bool(true) } }, { fields: { v: bool(true) } }],
        },
      ],
    },
    "two results",
  );
  unknown(
    {
      status: 400,
      body: [{ error: { code: 400, message: "Other.", status: "INVALID_ARGUMENT" } }],
    },
    "other 400 message",
  );
  unknown(
    {
      status: 400,
      body: [{ error: { code: 400, message: "Unsupported regex syntax.", status: "UNKNOWN" } }],
    },
    "other status text",
  );
  unknown(
    {
      status: 400,
      body: [
        {
          error: {
            code: 400,
            message: "Unsupported regex syntax.",
            status: "INVALID_ARGUMENT",
            details: [],
          },
        },
      ],
    },
    "extra error key",
  );
  unknown({ status: 403, body: syntax.body }, "right body, wrong status");
  unknown({ status: 403, body: captures.body }, "capture message, wrong status");
  unknown(
    {
      status: 400,
      body: [
        {
          error: {
            code: 400,
            message: "At most one capture group is supported",
            status: "INVALID_ARGUMENT",
          },
        },
      ],
    },
    "capture message without the final full stop",
  );
  unknown(
    {
      status: 400,
      body: [
        {
          error: {
            code: 400,
            message: "At most one capture group is supported.",
            status: "UNKNOWN",
          },
        },
      ],
    },
    "capture message, other status text",
  );
});

test("fireemu's refusal of an unobserved function is its own kind", () => {
  assert.deepEqual(
    readAnswer({
      status: 501,
      body: [{ error: { code: 501, message: "x", status: "UNIMPLEMENTED" } }],
    }),
    { kind: "unimplemented" },
  );
  assert.equal(
    readAnswer({ status: 501, body: [{ error: { code: 501, message: "x", status: "INTERNAL" } }] })
      .kind,
    "unknown",
  );
  assert.equal(readAnswer({ status: 501, body: [] }).kind, "unknown");
});

const stringPred = (value) => ({ kind: "string", value });
test("the prediction becomes the outcome each function would give", () => {
  const pred = {
    contains: true,
    match: false,
    find: stringPred("a"),
    findAll: [stringPred("a"), { kind: "unmatched" }],
  };
  assert.deepEqual(expectedOutcome("regex_contains", pred), { kind: "bool", value: true });
  assert.deepEqual(expectedOutcome("regex_match", pred), { kind: "bool", value: false });
  assert.deepEqual(expectedOutcome("regex_find", pred), { kind: "string", value: "a" });
  assert.deepEqual(expectedOutcome("regex_find_all", pred), {
    kind: "array",
    items: [{ kind: "string", value: "a" }, { kind: "either" }],
  });
  assert.deepEqual(expectedOutcome("regex_find", { ...pred, find: null }), { kind: "null" });
  assert.deepEqual(expectedOutcome("regex_find", { ...pred, find: { kind: "unmatched" } }), {
    kind: "either",
  });
  assert.deepEqual(expectedOutcome("regex_find_all", { ...pred, findAll: [] }), {
    kind: "array",
    items: [],
  });
  for (const name of REGEX_FUNCTIONS) {
    assert.deepEqual(expectedOutcome(name, { error: true }), { kind: "refused-syntax" });
  }
  assert.throws(() => expectedOutcome("regex_nope", pred), /unknown function/);
  // Go leaves out the text of an empty match: the prediction reads it as the empty string.
  assert.deepEqual(expectedOutcome("regex_find", { ...pred, find: { kind: "string" } }), {
    kind: "string",
    value: "",
  });
  assert.deepEqual(expectedOutcome("regex_find_all", { ...pred, findAll: [{ kind: "string" }] }), {
    kind: "array",
    items: [{ kind: "string", value: "" }],
  });
});

test("an unmatched group is satisfied by null or an empty string only", () => {
  const either = { kind: "either" };
  assert.equal(sameOutcome({ kind: "null" }, either), true);
  assert.equal(sameOutcome({ kind: "string", value: "" }, either), true);
  assert.equal(sameOutcome({ kind: "string", value: "a" }, either), false);
  assert.equal(sameOutcome({ kind: "bool", value: false }, either), false);
  assert.equal(sameOutcome(either, { kind: "null" }), true);
  assert.equal(
    sameOutcome(
      { kind: "array", items: [{ kind: "string", value: "a" }, { kind: "null" }] },
      { kind: "array", items: [{ kind: "string", value: "a" }, either] },
    ),
    true,
  );
  assert.equal(
    sameOutcome(
      { kind: "array", items: [{ kind: "string", value: "a" }] },
      { kind: "array", items: [{ kind: "string", value: "a" }, either] },
    ),
    false,
  );
  assert.equal(sameOutcome(either, either), true);
  assert.equal(
    sameOutcome({ kind: "unknown", reason: "x" }, { kind: "unknown", reason: "x" }),
    false,
  );
});

const outcomes = [
  { kind: "bool", value: true },
  { kind: "bool", value: false },
  { kind: "string", value: "a" },
  { kind: "string", value: "" },
  { kind: "null" },
  { kind: "array", items: [] },
  { kind: "array", items: [{ kind: "string", value: "a" }] },
  { kind: "refused-syntax" },
  { kind: "unimplemented" },
  { kind: "unknown", reason: "r" },
];

test("verdicts over every production x fireemu x prediction outcome", () => {
  for (const production of outcomes) {
    for (const fireemu of outcomes) {
      for (const prediction of outcomes.filter(
        (o) => o.kind !== "unknown" && o.kind !== "unimplemented",
      )) {
        const verdict = verdictOf({ production, fireemu, prediction });
        const prodKnown = production.kind !== "unknown";
        if (!prodKnown) {
          assert.deepEqual(verdict, { vsFireemu: "unknown", vsPrediction: "unknown" });
          continue;
        }
        const vsPrediction = sameOutcome(production, prediction) ? "agrees" : "differs";
        let vsFireemu;
        if (fireemu.kind === "unknown") vsFireemu = "unknown";
        else if (fireemu.kind === "unimplemented") vsFireemu = "unobserved";
        else vsFireemu = sameOutcome(production, fireemu) ? "agrees" : "differs";
        assert.deepEqual(verdict, { vsFireemu, vsPrediction });
      }
    }
  }
});

test("a property: a row is agreed exactly when the outcomes are equal, whatever the order", () => {
  const known = outcomes.filter((o) => o.kind !== "unknown" && o.kind !== "unimplemented");
  forAll(
    300,
    (random) => [pick(random, known), pick(random, known)],
    ([a, b]) => {
      const { vsFireemu } = verdictOf({ production: a, fireemu: b, prediction: a });
      assert.equal(vsFireemu === "agrees", JSON.stringify(a) === JSON.stringify(b));
    },
  );
});

test("the report reads the saved rows and counts every pair of every function", () => {
  const pred = JSON.parse(
    readFileSync(new URL("./fs-ent-pipeline/regex-predictions.json", import.meta.url), "utf8"),
  );
  assert.equal(Object.keys(pred.pairs).length, PAIRS.length);
  const steps = {};
  const strict = {};
  const emulator = {};
  for (const pair of PAIRS) {
    for (const name of REGEX_FUNCTIONS) {
      const want = expectedOutcome(name, pred.pairs[pair.label]);
      const answer =
        want.kind === "bool"
          ? ok(bool(want.value))
          : want.kind === "refused-syntax"
            ? syntax
            : null;
      if (answer) steps[stepIdOf(name, pair.label)] = answer;
      strict[stepIdOf(name, pair.label)] = {
        status: 501,
        body: [{ error: { code: 501, message: "x", status: "UNIMPLEMENTED" } }],
      };
      emulator[stepIdOf(name, pair.label)] = answer ?? ok(none);
    }
  }
  const fixture = { programs: {} };
  const byGroup = (map) => {
    const out = {};
    for (const pair of PAIRS) {
      out[`fs-ent-pipeline-regex/rx/${pair.group}`] ??= { steps: {} };
      for (const name of REGEX_FUNCTIONS) {
        const id = stepIdOf(name, pair.label);
        if (map[id]) out[`fs-ent-pipeline-regex/rx/${pair.group}`].steps[id] = map[id];
      }
    }
    return out;
  };
  for (const [group, value] of Object.entries(byGroup(steps))) fixture.programs[group] = value;
  const report = reportRows({
    fixture,
    strict: { results: byGroup(strict) },
    emulator: { results: byGroup(emulator) },
    predictions: pred,
  });
  assert.equal(report.rows.length, PAIRS.length * 4);
  const total = Object.values(report.counts.vsPrediction).reduce((a, b) => a + b, 0);
  assert.equal(total, PAIRS.length * 4);
  const known = report.rows.filter((r) => r.production.kind !== "unknown");
  assert.equal(report.counts.strict.unobserved, known.length);
  assert.equal(report.counts.strict.unknown, PAIRS.length * 4 - known.length);
  for (const row of report.rows.filter(
    (r) => r.production.kind === "bool" || r.production.kind === "refused-syntax",
  )) {
    assert.equal(row.vsPrediction, "agrees", row.id);
  }
  // A step production did not record is unknown, not missing.
  const missing = report.rows.find((r) => r.production.kind === "unknown");
  assert.ok(missing);
  assert.equal(missing.vsPrediction, "unknown");
});

test("a row whose second recording differs is unknown for production", () => {
  const pred = {
    pairs: Object.fromEntries(
      PAIRS.map((p) => [p.label, { contains: true, match: true, find: null, findAll: [] }]),
    ),
  };
  const pair = PAIRS[0];
  const id = stepIdOf("regex_contains", pair.label);
  const programId = `fs-ent-pipeline-regex/rx/${pair.group}`;
  const fixture = {
    programs: {
      [programId]: { steps: { [id]: ok(bool(true)) }, second: { [id]: ok(bool(false)) } },
    },
  };
  const report = reportRows({
    fixture,
    strict: { results: {} },
    emulator: { results: {} },
    predictions: pred,
  });
  const row = report.rows.find((r) => r.id === `${programId}#${id}`);
  assert.equal(row.production.kind, "unknown");
  assert.match(row.production.reason, /second recording/);
});

test("the report prints one line per row and the counts, and refuses missing files", async () => {
  const { main, show } = await import("./fs-ent-pipeline/regex-report.mjs");
  const read = (path) =>
    path.endsWith("regex-predictions.json") ? realPredictions : { programs: {}, results: {} };
  const realPredictions = JSON.parse(
    readFileSync(new URL("./fs-ent-pipeline/regex-predictions.json", import.meta.url), "utf8"),
  );
  const printed = main(["f", "s", "e"], read);
  const lines = printed.trimEnd().split("\n");
  assert.equal(lines.length, PAIRS.length * 4 + 1);
  assert.match(
    lines[0],
    /^fs-ent-pipeline-regex\/rx\/[a-z]+#regex-contains-[a-z0-9-]+\tproduction=unknown\(/,
  );
  assert.deepEqual(Object.keys(JSON.parse(lines.at(-1))), ["vsPrediction", "strict", "emulator"]);
  assert.throws(() => main(["f", "s"], read), /usage/);
  assert.equal(
    show({ kind: "array", items: [{ kind: "string", value: "a" }, { kind: "null" }] }),
    '[string:"a",null]',
  );
  assert.equal(show({ kind: "bool", value: false }), "bool:false");
  assert.equal(show({ kind: "refused-syntax" }), "refused-syntax");
});

test("strict and emulator are counted apart, and each row keeps both verdicts", () => {
  const pair = PAIRS[0];
  const programId = `${REGEX_PREFIX}rx/${pair.group}`;
  const id = stepIdOf("regex_contains", pair.label);
  const pred = {
    pairs: Object.fromEntries(
      PAIRS.map((p) => [p.label, { contains: true, match: true, find: null, findAll: [] }]),
    ),
  };
  const side = (answer) => ({ results: { [programId]: { steps: { [id]: answer } } } });
  const report = reportRows({
    fixture: { programs: { [programId]: { steps: { [id]: ok(bool(true)) } } } },
    strict: side(ok(bool(false))),
    emulator: side(ok(bool(true))),
    predictions: pred,
  });
  const row = report.rows.find((r) => r.id === `${programId}#${id}`);
  assert.equal(row.vsStrict, "differs");
  assert.equal(row.vsEmulator, "agrees");
  assert.equal(row.vsPrediction, "agrees");
  assert.deepEqual(report.counts.strict, { differs: 1, unknown: PAIRS.length * 4 - 1 });
  assert.deepEqual(report.counts.emulator, { agrees: 1, unknown: PAIRS.length * 4 - 1 });
  assert.deepEqual(report.counts.vsPrediction, { agrees: 1, unknown: PAIRS.length * 4 - 1 });
  assert.equal(stepIdOf("regex_find_all", "x"), "regex-find-all-x");
  assert.equal(stepIdOf("regex_contains", "a-b"), "regex-contains-a-b");
});

test("a printed row names the production, prediction, strict and emulator readings in order", async () => {
  const { formatRows } = await import("./fs-ent-pipeline/regex-report.mjs");
  const row = {
    id: "p#s",
    production: { kind: "bool", value: true },
    prediction: { kind: "null" },
    strict: { kind: "unimplemented" },
    emulator: { kind: "string", value: "x" },
    vsPrediction: "differs",
    vsStrict: "unobserved",
    vsEmulator: "differs",
  };
  assert.equal(
    formatRows({ rows: [row] }),
    'p#s\tproduction=bool:true\tprediction=null\tstrict=unimplemented\temulator=string:"x"\tvsPrediction=differs\tvsStrict=unobserved\tvsEmulator=differs',
  );
});

test("the recorded production rows of the regex observation all read, and the facts they show are pinned", () => {
  const fixture = JSON.parse(
    readFileSync(new URL("../fs-ent-pipeline-regex-production.json", import.meta.url), "utf8"),
  );
  const pred = JSON.parse(
    readFileSync(new URL("./fs-ent-pipeline/regex-predictions.json", import.meta.url), "utf8"),
  );
  const side = { results: {} };
  const report = reportRows({ fixture, strict: side, emulator: side, predictions: pred });
  assert.equal(report.rows.length, PAIRS.length * 4);
  assert.deepEqual([...new Set(report.rows.map((r) => r.production.kind))].toSorted(), [
    "array",
    "bool",
    "null",
    "refused-captures",
    "refused-syntax",
    "string",
  ]);
  const row = (name, label) => report.rows.find((r) => r.id.endsWith(`#${stepIdOf(name, label)}`));
  const same = (name, label, outcome) =>
    assert.deepEqual(row(name, label).production, outcome, `${name} ${label}`);
  // Shorthand classes and boundaries are ASCII only; \\s also takes the vertical tab.
  same("regex_contains", "d-arabic", { kind: "bool", value: false });
  same("regex_contains", "nd-arabic", { kind: "bool", value: true });
  same("regex_contains", "w-eacute", { kind: "bool", value: false });
  same("regex_contains", "nw-eacute", { kind: "bool", value: true });
  same("regex_contains", "b-cafe-edge", { kind: "bool", value: true });
  same("regex_contains", "s-nbsp", { kind: "bool", value: false });
  same("regex_contains", "ns-nbsp", { kind: "bool", value: true });
  same("regex_contains", "s-vt", { kind: "bool", value: true });
  same("regex_contains", "s-nel", { kind: "bool", value: false });
  same("regex_contains", "s-em", { kind: "bool", value: false });
  // Unicode property classes are Unicode.
  same("regex_contains", "pnd-arabic", { kind: "bool", value: true });
  same("regex_contains", "pl-eacute", { kind: "bool", value: true });
  // Not RE2: POSIX classes and (?m) are refused, (?i) does not fold beyond ASCII, (?u) and (?-u)
  // are accepted, (?U) does not make a quantifier lazy.
  for (const label of [
    "posix-digit",
    "posix-word",
    "posix-nbsp",
    "posix-vt",
    "m-anchor",
    "ctl-class",
    "del-class",
  ])
    same("regex_contains", label, { kind: "refused-syntax" });
  same("regex_contains", "i-eacute", { kind: "bool", value: false });
  same("regex_contains", "i-ascii-ctl", { kind: "bool", value: true });
  same("regex_contains", "u-flag", { kind: "bool", value: false });
  same("regex_contains", "nu-flag", { kind: "bool", value: false });
  same("regex_find", "ungreedy", { kind: "string", value: "aaa" });
  // Captures: find and find_all take at most one group; contains and match do not care.
  same("regex_find", "cap-two", { kind: "refused-captures" });
  same("regex_find_all", "cap-alt-first", { kind: "refused-captures" });
  same("regex_contains", "cap-two", { kind: "bool", value: true });
  same("regex_find", "cap-opt-unmatched", { kind: "null" });
  same("regex_find_all", "cap-all-alt", {
    kind: "array",
    items: [
      { kind: "string", value: "a" },
      { kind: "null" },
      { kind: "string", value: "a" },
      { kind: "null" },
    ],
  });
  // No row is unknown, and none differs between the two recordings.
  assert.equal(report.counts.vsPrediction.unknown, undefined);
  assert.equal(
    Object.keys(fixture.programs).every((id) => fixture.programs[id].second === undefined),
    true,
  );
});
