// The O-9 corpus (the residual shapes the strict stages are gated on): what each program asks,
// that it only reads, that it stays in the named database, and the plan of its envelope.
// Nothing here sends a request.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { PROGRAMS } from "./fs-ent-pipeline/corpus.mjs";
import { buildRestRequest, guardRestRequest, validateCorpus } from "./fs-ent-pipeline/harness.mjs";
import { O8D_PROGRAMS } from "./fs-ent-pipeline/o8d-corpus.mjs";
import {
  HASHED_50,
  KEYS_50,
  O9_AREAS,
  O9_PREFIX,
  O9_PROGRAMS,
  REPS_COLLECTIONS,
  TYPE_NAMES,
  words,
} from "./fs-ent-pipeline/o9-corpus.mjs";
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
const byId = Object.fromEntries(O9_PROGRAMS.map((p) => [p.id.slice(O9_PREFIX.length), p]));
const step = (program, id) => {
  const found = program.steps.find((s) => s.id === id);
  assert.ok(found, `${program.id} has no step ${id}`);
  return found;
};
const select = (s) => stagesOf(s).find((t) => t.name === "select").args[0].mapValue.fields;
const addFieldsOf = (s) => stagesOf(s).find((t) => t.name === "add_fields").args[0].mapValue.fields;
const kindOf = (value) => Object.keys(value)[0];
const numberOf = (fieldsOfDoc) => Number(fieldsOfDoc.n.integerValue);

test("O-9 programs follow the O-8D programs in PROGRAMS, under their own prefix, unique and valid", () => {
  assert.equal(O9_PROGRAMS.length, 6);
  assert.deepEqual(PROGRAMS.slice(-O9_PROGRAMS.length), O9_PROGRAMS);
  assert.deepEqual(
    PROGRAMS.slice(-O9_PROGRAMS.length - O8D_PROGRAMS.length, -O9_PROGRAMS.length),
    O8D_PROGRAMS,
  );
  assert.equal(new Set(O9_PROGRAMS.map((p) => p.id)).size, O9_PROGRAMS.length);
  for (const program of O9_PROGRAMS) assert.ok(program.id.startsWith(O9_PREFIX), program.id);
  assert.deepEqual(
    selectPrograms(PROGRAMS, O9_PREFIX).map((p) => p.id),
    O9_PROGRAMS.map((p) => p.id),
  );
  assert.deepEqual(Object.keys(O9_AREAS), ["reps", "fields", "types", "ops", "cg", "order"]);
  validateCorpus(PROGRAMS, "fs-ent-pipeline");
});

test("reps: the same ids hold -0 and 0 (and 1 and 1.0) in every order, read bare beside the group and the distinct", () => {
  const names = REPS_COLLECTIONS.map(([name]) => name);
  assert.deepEqual(names, ["zs", "zt", "zr", "zu", "zp", "zq", "os", "ot", "ou"]);
  const program = byId["reps-main"];
  assert.deepEqual(
    program.seed,
    REPS_COLLECTIONS.flatMap(([, docs]) => docs),
  );
  const docs = Object.fromEntries(REPS_COLLECTIONS);
  const valueOf = (coll, id) => docs[coll].find(([name]) => name === `${coll}/${id}`)[1].v;
  // zs and zt swap the values, zr is zs written backwards, ou is os written backwards.
  assert.deepEqual(valueOf("zs", "z1"), { doubleValue: "-0" });
  assert.deepEqual(valueOf("zt", "z1"), { doubleValue: 0 });
  const idsIn = (coll) => docs[coll].map(([name]) => name.split("/")[1]);
  assert.deepEqual(idsIn("zr"), idsIn("zs").toReversed());
  assert.deepEqual(idsIn("ou"), idsIn("os").toReversed());
  for (const id of ["z1", "z2", "z3", "z4", "z5", "z6"]) {
    assert.deepEqual(valueOf("zr", id), valueOf("zs", id), id);
    assert.deepEqual(valueOf("ou", id), valueOf("os", id), id);
    assert.notDeepEqual(valueOf("zt", id), valueOf("zs", id), id);
    assert.notDeepEqual(valueOf("ot", id), valueOf("os", id), id);
  }
  // The odd ids are a different set; the two-document pairs swap.
  assert.notDeepEqual(
    docs.zu.map(([name]) => name.split("/")[1]).toSorted(),
    docs.zs.map(([name]) => name.split("/")[1]).toSorted(),
  );
  assert.deepEqual(valueOf("zp", "a"), valueOf("zq", "b"));
  assert.deepEqual(valueOf("zp", "b"), valueOf("zq", "a"));
  // Only the two spellings of each value occur, in equal numbers per collection.
  for (const [name, list] of REPS_COLLECTIONS) {
    const kinds = list.map(([, f]) => JSON.stringify(f.v));
    const distinctValues = [...new Set(kinds)];
    assert.equal(distinctValues.length, 2, name);
    assert.equal(kinds.filter((k) => k === distinctValues[0]).length, list.length / 2, name);
    // Every document has its own number, to tell the members apart.
    assert.deepEqual(
      list.map(([, f]) => numberOf(f)).toSorted((a, b) => a - b),
      list.map((_, i) => i + 1),
      name,
    );
    for (const kind of ["bare", "agg", "dist"])
      assert.ok(
        program.steps.some((s) => s.id === `${kind}-${name}`),
        `${kind}-${name}`,
      );
  }
  assert.equal(program.steps.length, 3 * names.length);
  const agg = stagesOf(step(program, "agg-zs"))[1];
  assert.equal(agg.name, "aggregate");
  assert.deepEqual(Object.keys(agg.args[0].mapValue.fields), ["c", "lo", "hi"]);
  assert.deepEqual(Object.keys(agg.args[1].mapValue.fields), ["v"]);
  assert.equal(stagesOf(step(program, "dist-zs"))[1].name, "distinct");
  assert.equal(stagesOf(step(program, "bare-zs")).length, 1);
});

test("fields: a missing value is added under a map, a scalar, an absent and a new parent, and aliases overlap in both orders", () => {
  const program = byId["fields-main"];
  const aliasesOf = (id) => Object.keys(addFieldsOf(step(program, id)));
  assert.deepEqual(aliasesOf("nested-missing-into-map"), ["m.r"]);
  assert.deepEqual(aliasesOf("top-missing-over-scalar"), ["m"]);
  // The wire order of the overlapping aliases is the order written.
  assert.deepEqual(aliasesOf("overlap-parent-child"), ["p", "p.q"]);
  assert.deepEqual(aliasesOf("overlap-child-parent"), ["p.q", "p"]);
  assert.deepEqual(aliasesOf("overlap-existing-parent-child"), ["m", "m.k"]);
  assert.deepEqual(aliasesOf("overlap-missing-parent-child"), ["s", "s.b"]);
  // The missing value is a field no document has.
  const seeded = new Set(program.seed.flatMap(([, f]) => Object.keys(f)));
  assert.ok(!seeded.has("zz"));
  for (const id of [
    "nested-missing-into-map",
    "nested-missing-new-parent",
    "top-missing-over-map",
  ]) {
    assert.deepEqual(Object.values(addFieldsOf(step(program, id)))[0], {
      fieldReferenceValue: "zz",
    });
  }
  // One document each: a map parent, a scalar parent, no parent, a map with two keys.
  const doc = (name) => program.seed.find(([n]) => n === name)[1];
  assert.equal(kindOf(doc("fa/a").m), "mapValue");
  assert.equal(kindOf(doc("fa/b").m), "integerValue");
  assert.equal(doc("fa/c").m, undefined);
  assert.equal(Object.keys(doc("fa/d").m.mapValue.fields).length, 2);
  // Each step selects its own document by number before the stage.
  for (const s of program.steps) {
    const names = stagesOf(s).map((t) => t.name);
    assert.deepEqual(names, ["collection", "where", "add_fields"], s.id);
  }
});

test("types: every type name production lists is asked of a missing value, four ways", () => {
  const program = byId["types-main"];
  // The names are those of production's own refusal of an unknown type name (px1/select).
  const refusal =
    production.programs["fs-ent-pipeline/px1/select"].steps["is-type-i-bogus"].body[0].error
      .message;
  const listed = refusal.match(/\[(.*)\]/)[1].split(", ");
  assert.deepEqual(TYPE_NAMES, listed);
  assert.equal(TYPE_NAMES.length, 20);
  assert.deepEqual(
    program.steps.map((s) => s.id),
    TYPE_NAMES.map((name) => `missing-${name.replaceAll("_", "-")}`),
  );
  for (const [index, name] of TYPE_NAMES.entries()) {
    const fields = select(program.steps[index]);
    assert.deepEqual(Object.keys(fields), ["a", "b", "c", "d"], name);
    const call = fields.a.functionValue;
    assert.equal(call.name, "is_type");
    assert.deepEqual(call.args, [{ fieldReferenceValue: "zz" }, { stringValue: name }]);
    assert.deepEqual(fields.b.functionValue.name, "not");
    assert.deepEqual(fields.b.functionValue.args[0].functionValue, call);
    assert.equal(fields.c.functionValue.name, "is_error");
    assert.equal(fields.d.functionValue.name, "is_absent");
  }
  assert.ok(!Object.keys(program.seed[0][1]).includes("zz"));
});

test("ops: the tables hold every combination once, within the select width", () => {
  assert.deepEqual(words("tf", 2), ["tt", "tf", "ft", "ff"]);
  assert.equal(words("tfn", 3).length, 27);
  assert.equal(new Set(words("tfn", 3)).size, 27);
  const program = byId["ops-main"];
  const expectedCounts = {
    "or3-tfn": 27,
    "and3-tfn": 27,
    "or3-tfm": 27,
    "and3-tfm": 27,
    "or4-tf": 16,
    "and4-tf": 16,
    "xor3-tf": 8,
    "nor3-tf": 8,
    "xor4-tf": 16,
    "nor4-tf": 16,
    "xor5-tf": 32,
  };
  for (const [id, count] of Object.entries(expectedCounts)) {
    const fields = select(step(program, id));
    // The select stage is limited to 64 fields (O-2).
    assert.equal(Object.keys(fields).length, count, id);
    const name = id.replace(/\d.*$/, "");
    for (const [alias, value] of Object.entries(fields)) {
      assert.equal(value.functionValue.name, name, `${id}.${alias}`);
      // The alias spells the operands: t true, f false, n null, m the missing field.
      const operands = value.functionValue.args.map((a) =>
        a.booleanValue === true
          ? "t"
          : a.booleanValue === false
            ? "f"
            : a.nullValue === null
              ? "n"
              : a.fieldReferenceValue === "zz"
                ? "m"
                : "?",
      );
      assert.equal(operands.join(""), alias, `${id}.${alias}`);
    }
  }
  // The non-boolean after a decisive operand, one call per step.
  for (const id of [
    "and-false-int",
    "and-int-false",
    "or-true-int",
    "or-int-true",
    "nor-true-int",
    "nor-false-int",
    "xor-true-int",
  ]) {
    const fields = select(step(program, id));
    assert.deepEqual(Object.keys(fields), ["v"], id);
    assert.ok(
      fields.v.functionValue.args.some((a) => a.integerValue === "1"),
      id,
    );
  }
  const lists = ["equal-any-not-array", "not-equal-any-not-array", "not-equal-any-string"];
  for (const id of lists) {
    const [, list] = select(step(program, id)).v.functionValue.args;
    assert.equal(list.arrayValue, undefined, id);
  }
  assert.equal(program.steps.length, 38);
});

test("cg: the ancestor is a collection path, an unrelated or missing document, a full name or another kind of value", () => {
  const program = byId["cg-main"];
  const ancestor = (id) => {
    const [stageOfInput] = stagesOf(step(program, id));
    assert.equal(stageOfInput.name, "collection_group", id);
    assert.deepEqual(stageOfInput.args[1], { stringValue: "items" }, id);
    assert.equal(stageOfInput.args.length, 2, id);
    return stageOfInput.args[0];
  };
  assert.deepEqual(ancestor("anc-root-empty"), { referenceValue: "" });
  assert.deepEqual(ancestor("anc-collection-path"), { referenceValue: "/cg" });
  assert.deepEqual(ancestor("anc-unrelated-doc"), { referenceValue: "/zz/q" });
  assert.deepEqual(ancestor("anc-missing-doc-under"), { referenceValue: "/cg/zzz" });
  assert.deepEqual(ancestor("anc-full-name"), { referenceValue: "{docs}/cg/a" });
  assert.deepEqual(ancestor("anc-string"), { stringValue: "cg/a" });
  assert.deepEqual(ancestor("anc-null"), { nullValue: null });
  assert.equal(ancestor("anc-int").integerValue, "1");
  // The guard refuses a body that names another project, so no step names another database.
  // The seed is O-7's: the recorded step `nested-parent` read these documents with `/cg/a`.
  const seeded = new Set(program.seed.map(([name]) => name));
  assert.ok(seeded.has("cg/a/items/x") && seeded.has("items/z"));
  assert.equal(program.steps.length, 14);
});

test("order: fifty ids, written ascending and descending, in another collection, and unrelated ids", () => {
  assert.equal(KEYS_50.length, 50);
  assert.equal(new Set(KEYS_50).size, 50);
  assert.deepEqual(KEYS_50.toSorted(), KEYS_50);
  assert.equal(new Set(HASHED_50).size, 50);
  for (const id of HASHED_50) assert.match(id, /^[a-z0-9]{8}$/);
  assert.equal(
    HASHED_50.some((id) => KEYS_50.includes(id)),
    false,
  );
  const program = byId["order-main"];
  const idsOf = (coll) =>
    program.seed
      .filter(([name]) => name.startsWith(`${coll}/`))
      .map(([name]) => name.split("/")[1]);
  assert.deepEqual(idsOf("so1"), KEYS_50);
  assert.deepEqual(idsOf("so2"), KEYS_50.toReversed());
  assert.deepEqual(idsOf("so3"), HASHED_50);
  assert.deepEqual(idsOf("so4"), KEYS_50);
  assert.equal(program.seed.length, 200);
  // The same corpus, the same ids, every time.
  const reads = program.steps.filter((s) => /-bare(-again)?$/.test(s.id));
  assert.deepEqual(
    reads.map((s) => s.id),
    ["so1", "so2", "so3", "so4"].flatMap((c) => [`${c}-bare`, `${c}-bare-again`]),
  );
});

test("O-9 reads only, writes nothing but its own seeds, and holds nothing private", () => {
  const nested = (value) =>
    value !== null &&
    typeof value === "object" &&
    ((value.arrayValue?.values ?? []).some((item) => item.arrayValue !== undefined) ||
      Object.values(value).some(nested));
  for (const program of O9_PROGRAMS) {
    for (const [name, fieldsOfDoc] of program.seed) {
      assert.ok(!nested(fieldsOfDoc), name);
      assert.equal(name.split("/").length % 2, 0, name);
    }
    for (const s of program.steps) {
      assert.equal(s.rpc, "executePipeline", s.id);
      assert.equal(s.transport, undefined, s.id);
      assert.match(s.id, /^[a-z0-9-]+$/);
    }
    const text = JSON.stringify(program);
    for (const forbidden of [/projects\//, /fireemu-oracle/, /AIza/, /@/])
      assert.doesNotMatch(text, forbidden, program.id);
    for (const [digits] of text.matchAll(/(?<![\d.])\d{9,}\b/g)) assert.fail(`${digits}`);
  }
  // A collection a step reads is a collection the program seeds.
  for (const program of O9_PROGRAMS) {
    const written = new Set(program.seed.map(([name]) => name.split("/")[0]));
    for (const s of program.steps) {
      for (const [, name] of JSON.stringify(s.body).matchAll(/"referenceValue":"\/([a-z0-9]+)"/g)) {
        if (stagesOf(s)[0].name === "collection") assert.ok(written.has(name), `${s.id}: ${name}`);
      }
    }
  }
});

test("every O-9 step stays in the named database", () => {
  const ctx = productionContext();
  for (const program of O9_PROGRAMS) {
    for (const s of program.steps) {
      const built = buildRestRequest(s, ctx, new Map());
      guardRestRequest(built, ctx);
      assert.ok(built.url.includes("/databases/entpipe1/documents"), built.url);
    }
  }
});

test("the O-9 envelope stays within about 700 requests, and its plan equals a simulated run", async () => {
  const plan = o6Plan(O9_PROGRAMS);
  assert.equal(plan.programs, 6);
  assert.equal(plan.steps, 126);
  assert.equal(plan.grpc + plan.commits, 0);
  assert.ok(plan.worstRequests <= 700, `${plan.worstRequests}`);
  assert.equal(estimatedUsd(O9_PROGRAMS, 2), plan.estimatedUsd);
  const limits = ceilings(O9_PROGRAMS);
  assert.equal(plan.stepCeiling, limits.maxRequests);
  assert.equal(plan.harnessCeiling, limits.maxHarnessRequests);
  const fake = fakeFirestore();
  let out;
  try {
    out = await runCorpus(O9_PROGRAMS, productionContext(), { ...limits, timeoutMs: 5_000 });
  } finally {
    fake.restore();
  }
  assert.deepEqual(out.failures, []);
  assert.equal(fake.store.size, 0);
  assert.equal(plan.harnessExpected, out.harnessRequests);
  assert.equal(plan.expectedRequests, 5 + 2 * (out.requests + out.harnessRequests));
});

/** The frozen table (replaced by the fixture's `corpusDigest` once recorded). */
const FROZEN = [
  [
    "fs-ent-pipeline/o9/reps-main",
    "efc48c1ead967ae38828af49398f315800bb6bf992bb1a65b40c05f67e9f6d8d",
  ],
  [
    "fs-ent-pipeline/o9/fields-main",
    "aa188969687fa508192c6e75328b91d6a08bc4162b9840bb435dfaa0a1f07bdf",
  ],
  [
    "fs-ent-pipeline/o9/types-main",
    "82dafbd36aad113c039d6f2bd3ec96c72a9ef07f03e8cada7cfbb2406f7ae99b",
  ],
  [
    "fs-ent-pipeline/o9/ops-main",
    "b38171eb5cb1e2ff7ae71620139e309e3806106720b20bb141543cb49f5bc047",
  ],
  [
    "fs-ent-pipeline/o9/cg-main",
    "e1569729b69ef52a6ce1055c14d0e7d5b1e016fdb463ccc05a876133d5be5da1",
  ],
  [
    "fs-ent-pipeline/o9/order-main",
    "0ba260ee8af84ede496879882f191093b1b580c0a64aa266770f4f91e55a23a1",
  ],
];

test("the O-9 table is the frozen one", () => {
  assert.deepEqual(
    O9_PROGRAMS.map((p) => [p.id, programDigest(p)]),
    FROZEN,
  );
});
