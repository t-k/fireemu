// The function-family and stage corpora of O-8B and O-8C (strings and math; timestamps,
// map and array helpers, union, unnest and sample): the case expansion, the arity table read from
// production's own refusals, the stage builders, and invariants every family must keep.
// Nothing here sends a request.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  arityOf,
  c,
  caseStepId,
  functionProgram,
  KINDS,
  sample,
  stageWith,
  union,
  unnest,
} from "./fs-ent-pipeline/o8-cases.mjs";
import { fld, fn, read, select } from "./fs-ent-pipeline/builders.mjs";
import { int, str } from "./fs-query-index/values.mjs";
import { between, forAll, pick, stagesOf } from "./fs-ent-pipeline/test-support.mjs";

const production = JSON.parse(
  readFileSync(new URL("../fs-ent-pipeline-production.json", import.meta.url), "utf8"),
);
const recordedMessage = (name) => {
  const row = production.programs["fs-ent-pipeline/o5/function-names"].steps[`fn-${name}`];
  const element = Array.isArray(row.body) ? row.body[0] : row.body;
  return element.error.message;
};

test("a case becomes a select of one function call over the probe collection", () => {
  const program = functionProgram({
    id: "fam",
    collection: "pc",
    seed: [["pc/d1", { s: str("a") }]],
    functions: {
      to_upper: [c("ok", "ok", str("a")), c("two-args", "arity", str("a"), str("b"))],
      char_length: [c("absent", "absent", fld("x"))],
    },
  });
  assert.equal(program.id, "fam");
  assert.deepEqual(program.seed, [["pc/d1", { s: str("a") }]]);
  assert.deepEqual(
    program.steps.map((s) => s.id),
    ["to-upper-ok", "to-upper-two-args", "char-length-absent"],
  );
  assert.deepEqual(
    program.steps[0],
    read("to-upper-ok", "pc", select({ v: fn("to_upper", str("a")) })),
  );
  assert.deepEqual(stagesOf(program.steps[1])[1].args[0].mapValue.fields.v.functionValue.args, [
    str("a"),
    str("b"),
  ]);
  assert.equal(
    caseStepId("timestamp_to_unix_micros", "pre-epoch"),
    "timestamp-to-unix-micros-pre-epoch",
  );
  assert.deepEqual(KINDS, ["ok", "edge", "null", "absent", "type", "arity", "range"]);
});

test("a case rejects a kind or label it does not know, and a repeated step", () => {
  assert.throws(() => c("ok", "fine", str("a")), /kind/);
  assert.throws(() => c("Bad Label", "ok"), /label/);
  assert.throws(
    () =>
      functionProgram({
        id: "fam",
        collection: "pc",
        seed: [],
        functions: { abs: [c("a", "ok", int(1)), c("a", "edge", int(2))] },
      }),
    /duplicate/,
  );
});

test("property: every case yields one step with its arguments, in order, ids unique", () => {
  forAll(
    100,
    (random) =>
      Array.from({ length: between(random, 1, 6) }, (_, f) => ({
        name: `fn_${f}_${pick(random, ["a", "b"])}`,
        cases: Array.from({ length: between(random, 1, 8) }, (_, k) => ({
          label: `c${k}`,
          kind: pick(random, KINDS),
          args: Array.from({ length: between(random, 0, 4) }, () => int(between(random, 0, 9))),
        })),
      })),
    (functions) => {
      const program = functionProgram({
        id: "p",
        collection: "pc",
        seed: [],
        functions: Object.fromEntries(
          functions.map(({ name, cases }) => [
            name,
            cases.map((x) => c(x.label, x.kind, ...x.args)),
          ]),
        ),
      });
      const expected = functions.flatMap(({ name, cases }) =>
        cases.map((x) => [caseStepId(name, x.label), name, x.args]),
      );
      assert.equal(program.steps.length, expected.length);
      assert.equal(new Set(program.steps.map((s) => s.id)).size, expected.length);
      program.steps.forEach((step, i) => {
        const call = stagesOf(step)[1].args[0].mapValue.fields.v.functionValue;
        assert.deepEqual([step.id, call.name, call.args], expected[i]);
      });
    },
  );
});

test("arityOf reads the range, or the union of the overloads, from production's refusal", () => {
  // Recorded in FS-ENT-ORACLE O-5 (function-names), one overload and several.
  assert.deepEqual(arityOf(recordedMessage("starts_with")), { min: 2, max: 2 });
  assert.deepEqual(arityOf(recordedMessage("concat")), { min: 2, max: Infinity });
  assert.deepEqual(arityOf(recordedMessage("substring")), { min: 2, max: 3 });
  assert.deepEqual(arityOf(recordedMessage("trim")), { min: 1, max: 2 });
  assert.deepEqual(arityOf(recordedMessage("timestamp_trunc")), { min: 2, max: 3 });
  assert.deepEqual(arityOf(recordedMessage("current_timestamp")), { min: 0, max: 0 });
  assert.deepEqual(arityOf(recordedMessage("round")), { min: 1, max: 2 });
  assert.equal(arityOf(recordedMessage("array_reverse")), undefined);
  assert.equal(arityOf("something else"), undefined);
});

test("property: arityOf returns the widest range of the overloads it is given", () => {
  forAll(
    100,
    (random) =>
      Array.from({ length: between(random, 1, 4) }, () => {
        const min = between(random, 0, 3);
        return [min, random() < 0.3 ? Infinity : min + between(random, 0, 3)];
      }),
    (ranges) => {
      const show = (n) => (n === Infinity ? "+∞)" : `${n}]`);
      const text =
        ranges.length === 1
          ? `The function 'f(x: any)' takes [${ranges[0][0]}..${show(ranges[0][1])} argument(s), but 0 were provided.`
          : `The function 'f' does not accept 0 argument(s). Valid options are: ${ranges
              .map(([a, b]) => `- f(x: any) with [${a}..${show(b)} argument(s).`)
              .join(" ")}`;
      assert.deepEqual(arityOf(text), {
        min: Math.min(...ranges.map(([a]) => a)),
        max: Math.max(...ranges.map(([, b]) => b)),
      });
    },
  );
});

test("the stage builders send the SDK's wire forms", () => {
  // union: one argument, a pipeline value holding the other pipeline's stages.
  const other = [{ name: "collection", args: [{ referenceValue: "/b" }] }];
  assert.deepEqual(union(...other), {
    name: "union",
    args: [{ pipelineValue: { stages: other } }],
  });
  // unnest: the expression, then the alias as a field reference; the index field is an option.
  assert.deepEqual(unnest(fld("arr"), "elem"), {
    name: "unnest",
    args: [{ fieldReferenceValue: "arr" }, { fieldReferenceValue: "elem" }],
  });
  assert.deepEqual(unnest(fld("arr"), "elem", "idx").options, {
    index_field: { fieldReferenceValue: "idx" },
  });
  assert.equal("options" in unnest(fld("arr"), "elem"), false);
  // sample: the rate as a number, then the mode as a string.
  assert.deepEqual(sample(5, "documents"), {
    name: "sample",
    args: [{ integerValue: "5" }, { stringValue: "documents" }],
  });
  assert.deepEqual(sample(12.5, "percent").args[0], { doubleValue: 12.5 });
  assert.deepEqual(stageWith("x", [int(1)], { o: int(2) }), {
    name: "x",
    args: [int(1)],
    options: { o: int(2) },
  });
});

// --- the families and the stages ---

import { PROGRAMS, seedHoldsVector } from "./fs-ent-pipeline/corpus.mjs";
import {
  buildGrpcRequest,
  buildRestRequest,
  databaseName,
  guardGrpcRequest,
  guardRestRequest,
  validateCorpus,
} from "./fs-ent-pipeline/harness.mjs";
import { O8A_PROGRAMS } from "./fs-ent-pipeline/o8a-corpus.mjs";
import {
  MATH_FUNCTIONS,
  O8B_AREAS,
  O8B_PREFIX,
  O8B_PROGRAMS,
  STRING_FUNCTIONS,
} from "./fs-ent-pipeline/o8b-corpus.mjs";
import {
  COLLECTION_FUNCTIONS,
  O8C_AREAS,
  O8C_PREFIX,
  O8C_PROGRAMS,
  TIMESTAMP_FUNCTIONS,
} from "./fs-ent-pipeline/o8c-corpus.mjs";
import { O8D_EMPTY, O8D_PREFIX, O8D_PROGRAMS } from "./fs-ent-pipeline/o8d-corpus.mjs";
import { o6Plan } from "./fs-ent-pipeline/o6-corpus.mjs";
import { runCorpus } from "./fs-ent-pipeline/session.mjs";
import {
  fakeFirestore,
  production as productionContext,
  steps,
} from "./fs-ent-pipeline/test-support.mjs";
import { ceilings, estimatedUsd, programDigest, selectPrograms } from "./fs-query-index/run.mjs";

const FAMILIES = [
  { program: O8B_AREAS.strings[0], functions: STRING_FUNCTIONS },
  { program: O8B_AREAS.math[0], functions: MATH_FUNCTIONS },
  { program: O8C_AREAS.timestamps[0], functions: TIMESTAMP_FUNCTIONS },
  { program: O8C_AREAS.collections[0], functions: COLLECTION_FUNCTIONS },
];
const ALL = [...O8B_PROGRAMS, ...O8C_PROGRAMS, ...O8D_PROGRAMS];
const recordedSteps = production.programs["fs-ent-pipeline/o5/function-names"].steps;
/** Functions asked fewer questions, because there is less to ask (still every kind that applies). */
const SMALL = new Set([
  "current_timestamp",
  "ltrim",
  "rtrim",
  "floor",
  "ceil",
  "regex_find",
  "regex_find_all",
  "unix_millis_to_timestamp",
  "unix_seconds_to_timestamp",
  "map_remove",
  "map_keys",
  "map_values",
  "map_entries",
  "array_concat",
  "array_length",
  "array_reverse",
  "array_slice",
  "array_first",
  "array_last",
  "array_first_n",
  "array_last_n",
  "maximum_n",
  "minimum_n",
]);

const calls = (value, found = []) => {
  if (value && typeof value === "object") {
    if (value.functionValue) found.push(value.functionValue);
    for (const inner of Object.values(value)) calls(inner, found);
  }
  return found;
};
const fields = (value, found = new Set()) => {
  if (value && typeof value === "object") {
    if (typeof value.fieldReferenceValue === "string") found.add(value.fieldReferenceValue);
    for (const inner of Object.values(value)) fields(inner, found);
  }
  return found;
};

test("O-8B to O-8D programs follow the O-8A programs, under their own prefixes, unique and valid", () => {
  const at = PROGRAMS.findIndex((p) => p.id === ALL[0].id);
  assert.deepEqual(PROGRAMS.slice(at, at + ALL.length), ALL);
  assert.deepEqual(
    PROGRAMS.slice(at - O8A_PROGRAMS.length, at).map((p) => p.id),
    O8A_PROGRAMS.map((p) => p.id),
  );
  assert.equal(new Set(ALL.map((p) => p.id)).size, ALL.length);
  const prefixes = [O8B_PREFIX, O8C_PREFIX, O8D_PREFIX];
  for (const [index, programs] of [O8B_PROGRAMS, O8C_PROGRAMS, O8D_PROGRAMS].entries()) {
    for (const program of programs) assert.ok(program.id.startsWith(prefixes[index]), program.id);
    assert.deepEqual(
      selectPrograms(PROGRAMS, prefixes[index]).map((p) => p.id),
      programs.map((p) => p.id),
    );
  }
  for (const a of prefixes) for (const b of prefixes) assert.ok(a === b || !a.startsWith(b));
  validateCorpus(PROGRAMS, "fs-ent-pipeline");
});

test("every function the families call is a name production reported", () => {
  for (const { program } of FAMILIES.concat([{ program: O8D_PROGRAMS[0] }])) {
    for (const call of calls(program.steps.map((s) => s.body))) {
      assert.ok(recordedSteps[`fn-${call.name}`], `${call.name} is not in the O-5 sweep`);
    }
  }
});

test("every case calls its function with an argument count production accepts, or refuses", () => {
  let checked = 0;
  for (const { functions } of FAMILIES) {
    for (const [name, cases] of Object.entries(functions)) {
      const row = recordedSteps[`fn-${name}`];
      const message = (Array.isArray(row.body) ? row.body[0] : row.body).error.message;
      const range = arityOf(message);
      if (!range) continue; // array_reverse and its kind answer with a type message instead
      for (const { label, kind, args } of cases) {
        const inside = args.length >= range.min && args.length <= range.max;
        assert.equal(
          inside,
          kind !== "arity",
          `${name}-${label}: ${args.length} arguments, ${JSON.stringify(range)}`,
        );
        checked += 1;
      }
    }
  }
  assert.ok(checked > 200, `${checked}`);
});

test("every function is asked its typical, null, absent and wrong-type questions", () => {
  for (const { functions } of FAMILIES) {
    for (const [name, cases] of Object.entries(functions)) {
      const kinds = new Set(cases.map((k) => k.kind));
      assert.ok(kinds.has("ok"), `${name}: no typical case`);
      assert.ok(kinds.has("type") || kinds.has("arity"), `${name}: no wrong-type or arity case`);
      assert.ok(cases.length >= (SMALL.has(name) ? 3 : 8), `${name}: ${cases.length} cases`);
      assert.ok(cases.length <= 25, `${name}: ${cases.length} cases`);
      if (name !== "current_timestamp") {
        assert.ok(kinds.has("null") && kinds.has("absent"), `${name}: null/absent`);
      }
    }
  }
});

test("the probe documents hold the fields the cases read, and `x` is never set", () => {
  for (const { program } of FAMILIES) {
    const [[, probe]] = program.seed;
    assert.equal(probe.x, undefined);
    for (const path of fields(program.steps.map((s) => s.body))) {
      assert.ok(path === "x" || path === "v" || path in probe, `${program.id}: ${path}`);
    }
  }
});

test("the stage program reads what it wrote, or a collection nothing writes", () => {
  const [program] = O8D_PROGRAMS;
  const written = new Set(program.seed.map(([name]) => name.split("/")[0]));
  for (const step of program.steps) {
    const found = JSON.stringify(step.body).matchAll(/"referenceValue":"\/([a-z0-9]+)"/g);
    for (const [, name] of found)
      assert.ok(written.has(name) || O8D_EMPTY.has(name), `${step.id}: ${name}`);
  }
  for (const name of O8D_EMPTY) assert.ok(!written.has(name));
  const stageNames = new Set(program.steps.flatMap((s) => stagesOf(s).map((t) => t.name)));
  assert.deepEqual(
    [...stageNames].toSorted(),
    ["collection", "limit", "select", "sample", "sort", "union", "unnest", "where"].toSorted(),
  );
  // Sample is asked with rates and modes of both kinds, valid and not.
  const ids = program.steps.map((s) => s.id);
  for (const needed of [
    "union-other",
    "unnest-index-field",
    "sample-percent-50",
    "sample-mode-invalid",
  ]) {
    assert.ok(ids.includes(needed), needed);
  }
});

test("the family seeds hold nothing Firestore refuses, and no private values", () => {
  const nested = (value) =>
    value !== null &&
    typeof value === "object" &&
    ((value.arrayValue?.values ?? []).some((item) => item.arrayValue !== undefined) ||
      Object.values(value).some(nested));
  const boundaries = new Set([
    "9223372036854775807",
    "9223372036854775808",
    "253402300800",
    "253402300800000",
  ]);
  for (const program of ALL) {
    for (const [name, fieldsOfDoc] of program.seed) {
      assert.ok(!nested(fieldsOfDoc) && !seedHoldsVector({ seed: [[name, fieldsOfDoc]] }), name);
      assert.equal(name.split("/").length % 2, 0, name);
    }
    for (const step of program.steps) {
      assert.ok(["executePipeline"].includes(step.rpc), step.id);
      assert.match(step.id, /^[a-z0-9-]+$/);
    }
    const text = JSON.stringify(program);
    for (const forbidden of [/projects\//, /fireemu-oracle/, /AIza/, /@/])
      assert.doesNotMatch(text, forbidden);
    for (const [digits] of text.matchAll(/(?<![\d.])\d{9,}\b/g))
      assert.ok(boundaries.has(digits), digits);
  }
});

test("every step stays in the named database", () => {
  const ctx = productionContext();
  for (const program of ALL) {
    for (const step of program.steps) {
      const built = buildRestRequest(step, ctx, new Map());
      guardRestRequest(built, ctx);
      assert.ok(built.url.includes("/databases/entpipe1/documents"), built.url);
    }
  }
  assert.equal(typeof buildGrpcRequest, "function");
  assert.equal(typeof guardGrpcRequest, "function");
  assert.equal(databaseName(ctx).endsWith("/databases/entpipe1"), true);
});

test("each envelope stays within about 700 requests, and the plans add up", () => {
  const expected = [
    [O8B_PROGRAMS, { programs: 2, steps: 287 }],
    [O8C_PROGRAMS, { programs: 2, steps: 283 }],
    [O8D_PROGRAMS, { programs: 1, steps: 46 }],
  ];
  for (const [programs, want] of expected) {
    const plan = o6Plan(programs);
    assert.equal(plan.programs, want.programs);
    assert.equal(plan.steps, want.steps);
    assert.equal(plan.grpc + plan.commits, 0);
    assert.ok(plan.worstRequests <= 700, `${plan.worstRequests}`);
    assert.equal(estimatedUsd(programs, 2), plan.estimatedUsd);
    const limits = ceilings(programs);
    assert.equal(plan.stepCeiling, limits.maxRequests);
    assert.equal(plan.harnessCeiling, limits.maxHarnessRequests);
  }
});

test("the seed/wipe plan of each envelope equals a simulated run and the database ends empty", async () => {
  for (const programs of [O8B_PROGRAMS, O8C_PROGRAMS, O8D_PROGRAMS]) {
    const fake = fakeFirestore();
    let out;
    try {
      out = await runCorpus(programs, productionContext(), {
        ...ceilings(programs),
        timeoutMs: 5_000,
      });
    } finally {
      fake.restore();
    }
    assert.deepEqual(out.failures, []);
    assert.equal(fake.store.size, 0);
    const totals = o6Plan(programs);
    assert.equal(totals.harnessExpected, out.harnessRequests);
    assert.equal(totals.expectedRequests, 5 + 2 * (out.requests + out.harnessRequests));
  }
  assert.equal(steps({ steps: [] }).length, 0);
});

/** The frozen table (replaced by the fixture's `corpusDigest` once recorded). */
const FROZEN = [
  [
    "fs-ent-pipeline/o8b/strings-main",
    "2ab16dd711e2b1f806597c3c1aa971c00540967d5f9ff86af9eef7a8dbd57b66",
  ],
  [
    "fs-ent-pipeline/o8b/math-main",
    "88aa0e92db55d61fb7a341f4e4b5ce298fada5fe45bed2a4e3d8bd7034864d48",
  ],
  [
    "fs-ent-pipeline/o8c/timestamps-main",
    "c6b28866b5d6edb7cc6f802f02709858bd323a20c39c83124197a6d16fd1d14e",
  ],
  [
    "fs-ent-pipeline/o8c/collections-main",
    "fb68cceefe08b2800d722637621f0762caf794844fc8c14cd22bb320c6f87cc5",
  ],
  [
    "fs-ent-pipeline/o8d/stages-main",
    "329185673ac3519de8c51b429510c7d5547e714b2c86529224fd70bbf42fe050",
  ],
];

test("the O-8B to O-8D tables are the frozen ones", () => {
  assert.deepEqual(
    ALL.map((p) => [p.id, programDigest(p)]),
    FROZEN,
  );
});

test("the functions whose refusal names no count are called with the counts production accepted", () => {
  // O-5 called array_reverse(i) and array_slice(i, i) and was answered with a type message,
  // not a count message: so 1 and 2 arguments are counts production accepts. The cases of kind
  // `arity` must not use them, and the other cases must include them.
  const requests = JSON.parse(
    readFileSync(new URL("../fs-ent-pipeline-requests.json", import.meta.url), "utf8"),
  );
  const program = requests.programs.find((p) => p.id === "fs-ent-pipeline/o5/function-names");
  const accepted = {};
  for (const name of ["array_reverse", "array_slice"]) {
    const step = program.steps.find((s) => s.id === `fn-${name}`);
    accepted[name] = calls(step.body).find((call) => call.name === name).args.length;
    const answer = production.programs["fs-ent-pipeline/o5/function-names"].steps[`fn-${name}`];
    const element = Array.isArray(answer.body) ? answer.body[0] : answer.body;
    assert.match(element.error.message, /requires `Array` but got `LONG`/);
  }
  assert.deepEqual(accepted, { array_reverse: 1, array_slice: 2 });
  for (const [name, count] of Object.entries(accepted)) {
    const cases = COLLECTION_FUNCTIONS[name];
    assert.ok(
      cases.some((k) => k.kind !== "arity" && k.args.length === count),
      name,
    );
    assert.ok(!cases.some((k) => k.kind === "arity" && k.args.length === count), name);
  }
});

test("the recorded O-8B programs are in the fixture with their own digests and every step", () => {
  assert.equal(O8B_PROGRAMS.length, 2);
  for (const program of O8B_PROGRAMS) {
    const row = production.programs[program.id];
    assert.ok(row, program.id);
    assert.equal(row.corpusDigest, programDigest(program), program.id);
    assert.deepEqual(Object.keys(row.steps).toSorted(), program.steps.map((s) => s.id).toSorted());
    // Every step answered: nothing was left unsettled (status 0, or a server error).
    for (const [step, answer] of Object.entries(row.steps)) {
      assert.ok(
        answer.status === 200 || answer.status === 400,
        `${program.id}#${step}: ${answer.status}`,
      );
    }
  }
});
