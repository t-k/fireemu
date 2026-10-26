// The O-9b corpus (`is_type` over every type name): what each step asks, that it only reads and
// stays in the named database, and the plan of its envelope. Nothing here sends a request.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { PROGRAMS } from "./fs-ent-pipeline/corpus.mjs";
import { buildRestRequest, guardRestRequest, validateCorpus } from "./fs-ent-pipeline/harness.mjs";
import { O9_PROGRAMS, TYPE_NAMES } from "./fs-ent-pipeline/o9-corpus.mjs";
import { KIND_FIELDS, O9B_PREFIX, O9B_PROGRAMS } from "./fs-ent-pipeline/o9b-corpus.mjs";
import { o6Plan } from "./fs-ent-pipeline/o6-corpus.mjs";
import { runCorpus } from "./fs-ent-pipeline/session.mjs";
import {
  fakeFirestore,
  production as productionContext,
  stagesOf,
} from "./fs-ent-pipeline/test-support.mjs";
import { ceilings, estimatedUsd, programDigest, selectPrograms } from "./fs-query-index/run.mjs";

const production = JSON.parse(
  readFileSync(new URL("../fs-ent-pipeline-production.json", import.meta.url), "utf8"),
);
const [program] = O9B_PROGRAMS;
const aliases = (s) => stagesOf(s).find((t) => t.name === "select").args[0].mapValue.fields;

test("the O-9b program follows the O-9 programs in PROGRAMS, under its own prefix, and is valid", () => {
  assert.equal(O9B_PROGRAMS.length, 1);
  assert.equal(program.id, `${O9B_PREFIX}types-matrix`);
  assert.deepEqual(PROGRAMS.slice(-1), O9B_PROGRAMS);
  assert.deepEqual(PROGRAMS.slice(-1 - O9_PROGRAMS.length, -1), O9_PROGRAMS);
  // The O-9 selector does not take it, and its own selector does.
  assert.deepEqual(
    selectPrograms(PROGRAMS, "fs-ent-pipeline/o9/").map((p) => p.id),
    O9_PROGRAMS.map((p) => p.id),
  );
  assert.deepEqual(
    selectPrograms(PROGRAMS, O9B_PREFIX).map((p) => p.id),
    [program.id],
  );
  validateCorpus(PROGRAMS, "fs-ent-pipeline");
});

test("each step is one select of a single call shape, one alias per type name, and nothing else", () => {
  assert.deepEqual(
    program.steps.map((s) => s.id),
    [
      "missing",
      "missing-not",
      "missing-is-error",
      ...KIND_FIELDS.map(([f]) => `present-${f.slice(1)}`),
    ],
  );
  assert.equal(program.steps.length, 14);
  for (const s of program.steps) {
    assert.deepEqual(
      stagesOf(s).map((t) => t.name),
      ["collection", "select"],
      s.id,
    );
    const fields = aliases(s);
    // Twenty aliases, in the order production lists the names, within the 64-field select width.
    assert.deepEqual(Object.keys(fields), TYPE_NAMES, s.id);
    for (const name of TYPE_NAMES) {
      const outer = fields[name].functionValue;
      const call =
        s.id === "missing-not" || s.id === "missing-is-error" ? outer.args[0].functionValue : outer;
      assert.equal(call.name, "is_type", `${s.id}.${name}`);
      assert.deepEqual(call.args[1], { stringValue: name }, `${s.id}.${name}`);
      if (s.id === "missing-not") assert.equal(outer.name, "not");
      if (s.id === "missing-is-error") assert.equal(outer.name, "is_error");
    }
  }
  // is_absent is not used: it takes a field reference and refused every O-9 types step.
  assert.ok(!JSON.stringify(program).includes("is_absent"));
});

test("the missing field is one no document has, and each present step reads one stored kind", () => {
  const fields = new Set(program.seed.flatMap(([, f]) => Object.keys(f)));
  assert.ok(!fields.has("zz"));
  assert.deepEqual(
    [...fields],
    KIND_FIELDS.map(([f]) => f),
  );
  assert.equal(
    JSON.stringify(aliases(program.steps[0]).null.functionValue.args[0]),
    '{"fieldReferenceValue":"zz"}',
  );
  for (const [index, [field]] of KIND_FIELDS.entries()) {
    const call = aliases(program.steps[3 + index]).null.functionValue;
    assert.deepEqual(call.args[0], { fieldReferenceValue: field }, field);
  }
  // No vector (a vector seed is a recorded commit step in this lane), nested array or private value.
  assert.ok(!JSON.stringify(program).includes("__vector__"));
  assert.doesNotMatch(JSON.stringify(program), /projects\/|fireemu-oracle|AIza|@/);
});

test("O-9b reads only, stays in the named database, and its plan equals a simulated run", async () => {
  const ctx = productionContext();
  for (const s of program.steps) {
    assert.equal(s.rpc, "executePipeline");
    assert.equal(s.transport, undefined);
    const built = buildRestRequest(s, ctx, new Map());
    guardRestRequest(built, ctx);
    assert.ok(built.url.includes("/databases/entpipe1/documents"), built.url);
  }
  const plan = o6Plan(O9B_PROGRAMS);
  assert.equal(plan.steps, 14);
  assert.equal(plan.grpc + plan.commits, 0);
  assert.equal(estimatedUsd(O9B_PROGRAMS, 2), plan.estimatedUsd);
  const limits = ceilings(O9B_PROGRAMS);
  assert.equal(plan.stepCeiling, limits.maxRequests);
  assert.equal(plan.harnessCeiling, limits.maxHarnessRequests);
  const fake = fakeFirestore();
  let out;
  try {
    out = await runCorpus(O9B_PROGRAMS, ctx, { ...limits, timeoutMs: 5_000 });
  } finally {
    fake.restore();
  }
  assert.deepEqual(out.failures, []);
  assert.equal(fake.store.size, 0);
  assert.equal(plan.harnessExpected, out.harnessRequests);
  assert.equal(plan.expectedRequests, 5 + 2 * (out.requests + out.harnessRequests));
});

test("the lesson of O-9: the O-9 types program is recorded as refused whole", () => {
  const steps = production.programs["fs-ent-pipeline/o9/types-main"].steps;
  assert.equal(Object.keys(steps).length, 20);
  assert.ok(Object.values(steps).every((answer) => answer.status === 400));
});

/** The frozen table (replaced by the fixture's `corpusDigest` once recorded). */
const FROZEN = [
  [
    "fs-ent-pipeline/o9b/types-matrix",
    "45c084c4634c5262911002f675c1c292e6269bd8a56c4473a22b889b20c61898",
  ],
];

test("the O-9b table is the frozen one", () => {
  assert.deepEqual(
    O9B_PROGRAMS.map((p) => [p.id, programDigest(p)]),
    FROZEN,
  );
});
