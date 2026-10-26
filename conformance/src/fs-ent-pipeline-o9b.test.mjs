// The O-9b corpus (`is_type` over every type name): what each step asks, that it only reads and
// stays in the named database, and the plan of its envelope. Nothing here sends a request.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { PROGRAMS } from "./fs-ent-pipeline/corpus.mjs";
import { buildRestRequest, guardRestRequest, validateCorpus } from "./fs-ent-pipeline/harness.mjs";
import { O9_PROGRAMS, TYPE_NAMES } from "./fs-ent-pipeline/o9-corpus.mjs";
import {
  FRESH_ID_SETS,
  GROUP_IDS,
  KIND_FIELDS,
  O9B_PREFIX,
  O9B_PROGRAMS,
  predictedOrder,
} from "./fs-ent-pipeline/o9b-corpus.mjs";
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
const [program, orderFresh, cgParent] = O9B_PROGRAMS;
const aliases = (s) => stagesOf(s).find((t) => t.name === "select").args[0].mapValue.fields;

test("the O-9b program follows the O-9 programs in PROGRAMS, under its own prefix, and is valid", () => {
  assert.equal(O9B_PROGRAMS.length, 3);
  assert.deepEqual(
    O9B_PROGRAMS.map((p) => p.id),
    ["types-matrix", "order-fresh", "cg-parent"].map((name) => `${O9B_PREFIX}${name}`),
  );
  assert.deepEqual(PROGRAMS.slice(-3), O9B_PROGRAMS);
  assert.deepEqual(PROGRAMS.slice(-3 - O9_PROGRAMS.length, -3), O9_PROGRAMS);
  // The O-9 selector does not take it, and its own selector does.
  assert.deepEqual(
    selectPrograms(PROGRAMS, "fs-ent-pipeline/o9/").map((p) => p.id),
    O9_PROGRAMS.map((p) => p.id),
  );
  assert.deepEqual(
    selectPrograms(PROGRAMS, O9B_PREFIX).map((p) => p.id),
    O9B_PROGRAMS.map((p) => p.id),
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
  for (const s of O9B_PROGRAMS.flatMap((p) => p.steps)) {
    assert.equal(s.rpc, "executePipeline");
    assert.equal(s.transport, undefined);
    const built = buildRestRequest(s, ctx, new Map());
    guardRestRequest(built, ctx);
    assert.ok(built.url.includes("/databases/entpipe1/documents"), built.url);
  }
  const plan = o6Plan(O9B_PROGRAMS);
  assert.equal(plan.programs, 3);
  assert.equal(plan.steps, 21);
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

// --- every call is a shape production has accepted ---

const recordedSignatures = () => {
  const steps = production.programs["fs-ent-pipeline/o5/function-names"].steps;
  const out = new Map();
  for (const answer of Object.values(steps)) {
    const message =
      (Array.isArray(answer.body) ? answer.body[0] : answer.body)?.error?.message ?? "";
    const found = /The function '([a-z_0-9]+)\((.*?)\): ([^']*)' takes \[(\d+)\.\.(\d+|\+∞)\]/.exec(
      message,
    );
    if (found) {
      const [, name, params, , min, max] = found;
      out.set(name, { params, min: Number(min), max: max === "+∞" ? Infinity : Number(max) });
    }
  }
  return out;
};

/** `name(kind, kind)` for every call in a value, a kind being field, fn or the literal's type. */
const callShapes = (value, found = []) => {
  if (value && typeof value === "object") {
    if (value.functionValue) {
      const { name, args = [] } = value.functionValue;
      const kind = (a) =>
        a.fieldReferenceValue !== undefined ? "field" : a.functionValue ? "fn" : Object.keys(a)[0];
      found.push({ name, args, shape: `${name}(${args.map(kind).join(",")})` });
    }
    for (const inner of Object.values(value)) callShapes(inner, found);
  }
  return found;
};

/** The shapes some recorded request got a 200 answer for (O-9's refused types program is not one). */
const acceptedShapes = () => {
  const requests = JSON.parse(
    readFileSync(new URL("../fs-ent-pipeline-requests.json", import.meta.url), "utf8"),
  );
  const accepted = new Set();
  for (const p of requests.programs) {
    for (const s of p.steps) {
      if (production.programs[p.id]?.steps[s.id]?.status !== 200) continue;
      for (const { shape } of callShapes(s.body)) accepted.add(shape);
    }
  }
  return accepted;
};

/** What is wrong with a step's calls: an unknown name, a wrong count or enum value, or a shape with no 200 answer on record. */
const problemsOf = (step, signatures, accepted) => {
  const problems = [];
  for (const { name, args, shape } of callShapes(step.body)) {
    const signature = signatures.get(name);
    if (!signature) problems.push(`${name}: not a function production reported`);
    else if (args.length < signature.min || args.length > signature.max)
      problems.push(`${shape}: production takes ${signature.min}..${signature.max} arguments`);
    else {
      const list = /\(([a-z_0-9|]+)\)$/.exec(signature.params)?.[1]?.split("|");
      const literal = args.at(-1)?.stringValue;
      if (list && literal !== undefined && !list.includes(literal))
        problems.push(`${shape}: ${literal} is not one of ${list.join("|")}`);
    }
    if (!accepted.has(shape))
      problems.push(`${shape}: no recorded request with this shape was accepted`);
  }
  return problems;
};

test("every call of O-9b is a function production reported, with a count it takes, in a shape it has accepted", () => {
  const signatures = recordedSignatures();
  assert.ok(signatures.size >= 60, `${signatures.size}`);
  assert.match(signatures.get("is_type").params, /null\|array\|boolean/);
  assert.deepEqual([signatures.get("is_absent").min, signatures.get("is_absent").max], [1, 1]);
  const accepted = acceptedShapes();
  const shapes = new Set();
  for (const s of O9B_PROGRAMS.flatMap((p) => p.steps)) {
    assert.deepEqual(problemsOf(s, signatures, accepted), [], s.id);
    for (const { shape } of callShapes(s.body)) shapes.add(shape);
  }
  assert.deepEqual([...shapes].toSorted(), [
    "is_error(fn)",
    "is_type(field,stringValue)",
    "not(fn)",
  ]);
});

test("the check catches the O-9 mistake: is_absent given a function value has no accepted precedent", () => {
  const signatures = recordedSignatures();
  const accepted = acceptedShapes();
  // The signature says `is_absent(value: any?)`, so the arity and type checks pass; only the
  // precedent check refuses it.
  const mistake = {
    body: select_(
      fn_("is_absent", fn_("is_type", { fieldReferenceValue: "zz" }, { stringValue: "null" })),
    ),
  };
  assert.deepEqual(problemsOf(mistake, signatures, accepted), [
    "is_absent(fn): no recorded request with this shape was accepted",
  ]);
  // The other refusals: an unknown name, a wrong count, a value outside the enum.
  const unknown = { body: select_(fn_("is_typo", { fieldReferenceValue: "zz" })) };
  assert.match(problemsOf(unknown, signatures, accepted)[0], /not a function production reported/);
  const count = { body: select_(fn_("is_type", { fieldReferenceValue: "zz" })) };
  assert.match(problemsOf(count, signatures, accepted)[0], /takes 2\.\.2 arguments/);
  const bogus = {
    body: select_(fn_("is_type", { fieldReferenceValue: "zz" }, { stringValue: "bogus" })),
  };
  assert.match(problemsOf(bogus, signatures, accepted)[0], /bogus is not one of null\|array/);
});

const fn_ = (name, ...args) => ({ functionValue: { name, args } });
const select_ = (value) => ({
  structuredPipeline: {
    pipeline: { stages: [{ name: "select", args: [{ mapValue: { fields: { v: value } } }] }] },
  },
});

// --- the scan-order rule, out of sample ---

test("order-fresh: three collections of fresh ids whose CRC-32 order is neither name nor write order", () => {
  assert.deepEqual(Object.keys(FRESH_ID_SETS), ["oc1", "oc2", "oc3"]);
  const used = new Set(
    PROGRAMS.filter((p) => !O9B_PROGRAMS.includes(p)).flatMap((p) =>
      p.seed.map(([name]) => name.split("/").at(-1)),
    ),
  );
  for (const [coll, ids] of Object.entries(FRESH_ID_SETS)) {
    assert.equal(ids.length, 12);
    assert.equal(new Set(ids).size, 12, coll);
    const order = predictedOrder(ids);
    for (const [label, other] of [
      ["name order", ids.toSorted()],
      ["name order descending", ids.toSorted().toReversed()],
      ["write order", ids],
      ["write order backwards", ids.toReversed()],
    ])
      assert.notDeepEqual(order, other, `${coll}: CRC-32 order equals ${label}`);
    // Fresh: ids of the earlier programs are not reused (the shared "z" ids would give no new evidence).
    for (const id of ids) assert.ok(!used.has(id), `${coll}/${id} was used before`);
    assert.deepEqual(
      orderFresh.seed
        .filter(([name]) => name.startsWith(`${coll}/`))
        .map(([name]) => name.split("/")[1]),
      ids,
    );
  }
  assert.deepEqual(
    orderFresh.steps.map((s) => s.id),
    ["oc1-bare", "oc2-bare", "oc3-bare"],
  );
});

test("cg-parent: several documents under one parent, a top level and a second parent, read as a group and one by one", () => {
  assert.deepEqual(
    cgParent.steps.map((s) => s.id),
    ["group-bare", "top-bare", "a-bare", "b-bare"],
  );
  assert.equal(GROUP_IDS.a.length, 6);
  for (const ids of Object.values(GROUP_IDS)) {
    const order = predictedOrder(ids);
    for (const other of [ids.toSorted(), ids.toSorted().toReversed(), ids, ids.toReversed()])
      assert.notDeepEqual(order, other, ids.join());
  }
  const names = cgParent.seed.map(([name]) => name);
  assert.ok(names.every((n) => /^(pp\/[ab]\/pitems|pitems)\/[a-z0-9]+$/.test(n)));
  assert.equal(names.length, 12);
  assert.equal(
    JSON.stringify(stagesOf(cgParent.steps[0])[0]),
    '{"name":"collection_group","args":[{"referenceValue":""},{"stringValue":"pitems"}]}',
  );
  assert.equal(stagesOf(cgParent.steps[2])[0].args[0].referenceValue, "/pp/a/pitems");
});

/** The frozen table (replaced by the fixture's `corpusDigest` once recorded). */
const FROZEN = [
  [
    "fs-ent-pipeline/o9b/types-matrix",
    "45c084c4634c5262911002f675c1c292e6269bd8a56c4473a22b889b20c61898",
  ],
  [
    "fs-ent-pipeline/o9b/order-fresh",
    "b7f6c182b4ecd4e18e29bb74e68dfd1dd41a190cd59fe360bbeeef0481c4cb52",
  ],
  [
    "fs-ent-pipeline/o9b/cg-parent",
    "1853338be9e123a859123058f537df0cac0f43fdcae81dac6ad005f64c6555b4",
  ],
];

test("the O-9b table is the frozen one", () => {
  assert.deepEqual(
    O9B_PROGRAMS.map((p) => [p.id, programDigest(p)]),
    FROZEN,
  );
});

test("the predicted read orders are the ones the packet states", () => {
  // Ascending CRC-32 of the id, computed before the send. A recording that differs refutes the rule.
  const joined = (ids) => predictedOrder(ids).join(" ");
  assert.equal(
    joined(FRESH_ID_SETS.oc1),
    "hotel bravo echo foxtrot india juliet charlie delta kilo golf alpha lima",
  );
  assert.equal(joined(FRESH_ID_SETS.oc2), "2 100 600 77 1 9 30 10 11 4 8 25");
  assert.equal(joined(FRESH_ID_SETS.oc3), "m.n a_b a-b p5 B2 Q7 x-y P5 Zed q7 b2 zed");
  assert.equal(joined(GROUP_IDS.top), "tu2 tu3 tu1");
  assert.equal(joined(GROUP_IDS.a), "cc6 ff3 hh1 gg2 ee4 dd5");
  assert.equal(joined(GROUP_IDS.b), "v1 v3 v2");
  // The group read is predicted by parent path ("" , pp/a, pp/b), then by CRC-32 inside a parent.
  assert.equal(
    [GROUP_IDS.top, GROUP_IDS.a, GROUP_IDS.b].map(joined).join(" | "),
    "tu2 tu3 tu1 | cc6 ff3 hh1 gg2 ee4 dd5 | v1 v3 v2",
  );
});
