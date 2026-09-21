import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { CASE, selectCase } from "../registry.mjs";
import { comparatorModuleSource, importText, pin } from "../legacy.mjs";
import {
  canonical,
  digestJson,
  blobSha,
  compareRecords,
  selectProduction,
  validateProgram,
  resultEnvelope,
  gateExitCode,
  renderReport,
} from "../core.mjs";
import { programFixture, actualFixture, matrixFixture } from "./fixtures.mjs";
const text = await readFile(new URL("legacy-comparator.excerpt.txt", import.meta.url), "utf8");
const { compareProductionToFireemu: comparator } = await importText(comparatorModuleSource(text));
const run = (actual = actualFixture()) =>
  compareRecords({
    entry: CASE,
    program: programFixture(),
    production: selectProduction(matrixFixture(), CASE),
    actual,
    comparator,
  });
const execution = () => ({
  state: "completed",
  cleanup: { state: "confirmed" },
  process: { state: "stopped" },
});
const envelope = (comparison, state = execution()) =>
  resultEnvelope({ entry: CASE, comparison, execution: state, provenance: { testOnly: true } });

test("the selected whole-program definition matches its reviewed digest", () => {
  assert.equal(digestJson(programFixture()), CASE.programDigest);
  validateProgram(programFixture(), CASE);
  assert.equal(digestJson(programFixture()), CASE.programDigest);
});
test("registry rejects unregistered cases", () =>
  assert.throws(() => selectCase("arbitrary"), /unknown-case/));
test("five observed rows match without official-emulator values", () => {
  const result = run();
  assert.equal(result.verdict, "MATCH");
  assert.deepEqual(result.counts, { match: 5, mismatch: 0, indeterminate: 0 });
  assert.equal(gateExitCode(envelope(result)), 0);
});
test("legacy and new entry preserve each row classification", () => {
  const actual = actualFixture();
  const production = selectProduction(matrixFixture(), CASE);
  const before = comparator({
    production,
    fireemu: actual,
    programDefinitions: [programFixture()],
  });
  assert.deepEqual(
    run(actual).rows.map((x) => x.comparison),
    before.rows.map((x) => x.comparison.toUpperCase()),
  );
});
for (const [name, mutate] of [
  [
    "canonical error",
    (s) => {
      s["non-atomic-batch"].code = "FAILED_PRECONDITION";
    },
  ],
  [
    "HTTP status",
    (s) => {
      s["non-atomic-batch"].status = 409;
    },
  ],
  [
    "partial write after refusal",
    (s) => {
      s["one-was-written"] = { status: 200, code: "OK", body: {} };
    },
  ],
  [
    "deleted existing document",
    (s) => {
      s["existing-was-deleted"] = { status: 404, code: "NOT_FOUND" };
    },
  ],
  [
    "changed stored field",
    (s) => {
      s["existing-was-deleted"].body.fields.a.integerValue = "2";
    },
  ],
  [
    "integer encoding changed",
    (s) => {
      s["existing-was-deleted"].body.fields.a = { doubleValue: 1 };
    },
  ],
  [
    "missing field",
    (s) => {
      delete s["existing-was-deleted"].body.fields.a;
    },
  ],
  [
    "null instead of absent",
    (s) => {
      s["empty-batch"].body.extra = null;
    },
  ],
  [
    "extra write result",
    (s) => {
      s["empty-batch"].body.writeResults = [{}];
    },
  ],
])
  test(`semantic mutant is detected: ${name}`, () => {
    const actual = actualFixture();
    mutate(actual[CASE.programId].steps);
    const comparison = run(actual);
    assert.equal(comparison.verdict, "MISMATCH");
    assert.equal(gateExitCode(envelope(comparison)), 1);
  });
for (const [name, mutate] of [
  [
    "missing row",
    (a) => {
      delete a[CASE.programId].steps["empty-batch"];
    },
  ],
  [
    "extra row",
    (a) => {
      a[CASE.programId].steps.extra = { status: 200, code: "OK", body: {} };
    },
  ],
  [
    "extra program",
    (a) => {
      a.other = { steps: {} };
    },
  ],
  [
    "seed failure",
    (a) => {
      a[CASE.programId].seedError = "failed";
    },
  ],
  [
    "seed failure even if empty",
    (a) => {
      a[CASE.programId].seedError = "";
    },
  ],
  [
    "timeout",
    (a) => {
      a[CASE.programId].steps["empty-batch"] = { status: 0, code: "no-response" };
    },
  ],
  [
    "non-JSON HTTP response",
    (a) => {
      a[CASE.programId].steps["empty-batch"] = { status: 200, code: "non-json" };
    },
  ],
  [
    "informational HTTP only",
    (a) => {
      a[CASE.programId].steps["empty-batch"] = { status: 100, code: "OK", body: {} };
    },
  ],
  [
    "success missing body",
    (a) => {
      delete a[CASE.programId].steps["empty-batch"].body;
    },
  ],
  [
    "reordered steps",
    (a) => {
      a[CASE.programId].steps = Object.fromEntries(
        Object.entries(a[CASE.programId].steps).reverse(),
      );
    },
  ],
])
  test(`incomplete/invalid execution is not a match: ${name}`, () => {
    const actual = actualFixture();
    mutate(actual);
    const result = run(actual);
    assert.equal(result.verdict, "INDETERMINATE");
    assert.equal(gateExitCode(envelope(result)), 2);
  });
test("both-side missing observations cannot become a match", () => {
  assert.throws(() => {
    const m = matrixFixture();
    m.programs[0].steps["empty-batch"].production = { missing: true };
    selectProduction(m, CASE);
  }, /oracle-incomplete/);
});
test("indeterminate is not counted as semantic mismatch in the new summary", () => {
  const a = actualFixture();
  a[CASE.programId].steps["empty-batch"] = { status: 0, code: "no-response" };
  const r = run(a);
  assert.equal(r.legacySummary.mismatches, 1);
  assert.deepEqual(r.counts, { match: 4, mismatch: 0, indeterminate: 1 });
});
test("error prose is explicitly outside this old contract, not silently promised", () => {
  const a = actualFixture();
  a[CASE.programId].steps["non-atomic-batch"].message = "different wording";
  assert.equal(run(a).verdict, "MATCH");
  assert.match(renderReport(envelope(run(a))), /Error message equality/);
});
test("JSON object member ordering does not change meaning", () => {
  assert.equal(canonical({ a: 1, b: null }), canonical({ b: null, a: 1 }));
});
test("arrays and JSON types remain different", () => {
  assert.notEqual(canonical([1, 2]), canonical([2, 1]));
  assert.notEqual(canonical(true), canonical(1));
  assert.notEqual(canonical("1"), canonical(1));
});
for (const value of [undefined, NaN, Infinity])
  test(`reject non-JSON canonical value ${value}`, () =>
    assert.throws(() => canonical(value), /finite-json/));
for (const [name, change] of [
  [
    "source revision",
    (m) => {
      m.evidence.observations.production.source.gitSha = "0".repeat(40);
    },
  ],
  [
    "corpus binding",
    (m) => {
      m.evidence.observations.production.inputs.corpusDigest = "wrong";
    },
  ],
  [
    "local role",
    (m) => {
      m.evidence.observations.production.observation.side = "fireemu";
    },
  ],
  [
    "stored role",
    (m) => {
      m.evidence.observations.production.observation.mode = "stored";
    },
  ],
  [
    "unverified",
    (m) => {
      m.evidence.verified = false;
    },
  ],
  [
    "validation failures",
    (m) => {
      m.evidence.validation = ["x"];
    },
  ],
  [
    "wrong edition",
    (m) => {
      m.evidence.observations.production.observation.database.databaseEdition = "ENTERPRISE";
    },
  ],
  [
    "duplicate program",
    (m) => {
      m.programs.push(structuredClone(m.programs[0]));
    },
  ],
  [
    "saved seed failure",
    (m) => {
      m.programs[0].seedError = "failed";
    },
  ],
  [
    "extra reference row",
    (m) => {
      m.programs[0].steps.extra = {};
    },
  ],
])
  test(`oracle binding rejects ${name}`, () => {
    const m = matrixFixture();
    change(m);
    assert.throws(() => selectProduction(m, CASE));
  });
test("changed request with unchanged id cannot reuse this oracle", () => {
  const p = programFixture();
  p.steps[0].body.writes[0].update.fields.a.integerValue = "999";
  assert.throws(() => validateProgram(p, CASE), /program-input-drift/);
});
test("byte pin rejects an edited source", () => {
  const bytes = Buffer.from("real source\n");
  pin(bytes, blobSha(bytes));
  assert.throws(() => pin(Buffer.from("other source\n"), blobSha(bytes)), /source-pin/);
});
for (const part of ["cleanup", "process"])
  test(`missing ${part} prevents successful acceptance`, () => {
    const e = execution();
    e[part].state = "unconfirmed";
    const r = envelope(run(), e);
    assert.equal(r.comparison.verdict, "INDETERMINATE");
    assert.equal(gateExitCode(r), 2);
  });
test("failed runtime cannot be rescued by matching saved values", () => {
  const e = execution();
  e.state = "failed";
  assert.equal(gateExitCode(envelope(run(), e)), 2);
});
test("extractor refuses a missing marker", () =>
  assert.throws(() => comparatorModuleSource(""), /anchor/));
test("extractor refuses duplicate function boundaries", () =>
  assert.throws(() => comparatorModuleSource(text + "\nfunction decision(step) {"), /anchor/));
test("no original acquisition entrypoint is imported by the comparison bridge", () => {
  const source = comparatorModuleSource(text);
  for (const name of ["recordProduction", "probeOracle", "DIVERGENCES", "collectEvidence", "spawn"])
    assert.ok(!source.includes(name));
});

test("the executed comparator excerpt has the reviewed effective-code hash", async () => {
  const { sha256 } = await import("../core.mjs");
  assert.equal(sha256(comparatorModuleSource(text)), CASE.comparatorSliceSha256);
});
