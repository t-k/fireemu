// The O-7 pipeline corpus (packet v2: aggregate, distinct, add_fields, remove_fields, and the
// collection_group and documents inputs): case generation, the request plan and the safety
// properties of the table. Nothing here sends a request; the only fetch is an in-memory stand-in
// for the sandbox database.

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  addFields,
  aggregate,
  collection,
  collectionGroup,
  distinct,
  documents,
  fld,
  mapOf,
  readFrom,
  readFromGrpc,
  removeFields,
} from "./fs-ent-pipeline/builders.mjs";
import { PROGRAMS, seedHoldsVector } from "./fs-ent-pipeline/corpus.mjs";
import {
  buildGrpcRequest,
  buildRestRequest,
  databaseName,
  guardGrpcRequest,
  guardRestRequest,
  validateCorpus,
} from "./fs-ent-pipeline/harness.mjs";
import {
  O6_PREFIX,
  O6_PROGRAMS,
  defineArea,
  o6Plan,
  seedWipePlan,
} from "./fs-ent-pipeline/o6-corpus.mjs";
import {
  ACCUMULATORS,
  AROUND_COMBOS,
  EMPTY_COLLECTIONS,
  O7_AREAS,
  O7_PREFIX,
  O7_PROGRAMS,
  accumulatorMap,
  numberScenarios,
} from "./fs-ent-pipeline/o7-corpus.mjs";
import { runCorpus } from "./fs-ent-pipeline/session.mjs";
import {
  between,
  fakeFirestore,
  forAll,
  parentOf,
  pick,
  production,
  relative,
  stagesOf,
  steps,
  writtenCollections,
} from "./fs-ent-pipeline/test-support.mjs";
import { ceilings, estimatedUsd, programDigest, selectPrograms } from "./fs-query-index/run.mjs";

const LANE = "fs-ent-pipeline";
const areaSteps = (area) => O7_AREAS[area].flatMap((program) => steps(program));
const INPUTS = new Set(["collection", "collection_group", "documents"]);

test("O-7 programs follow the O-6 programs in PROGRAMS, under their own prefix, unique and valid", () => {
  assert.ok(O7_PROGRAMS.length > 0);
  // The O-7 programs follow the O-6 programs, in order (the O-8A programs follow them: o8a test).
  const at = PROGRAMS.findIndex((p) => p.id === O7_PROGRAMS[0].id);
  assert.deepEqual(PROGRAMS.slice(at, at + O7_PROGRAMS.length), O7_PROGRAMS);
  assert.deepEqual(PROGRAMS.slice(at - O6_PROGRAMS.length, at), O6_PROGRAMS);
  assert.equal(new Set(O7_PROGRAMS.map((p) => p.id)).size, O7_PROGRAMS.length);
  for (const program of O7_PROGRAMS) assert.ok(program.id.startsWith(O7_PREFIX), program.id);
  assert.notEqual(O7_PREFIX, O6_PREFIX);
  assert.ok(!O7_PREFIX.startsWith(O6_PREFIX) && !O6_PREFIX.startsWith(O7_PREFIX));
  validateCorpus(PROGRAMS, LANE);
  assert.deepEqual(
    selectPrograms(PROGRAMS, O7_PREFIX).map((p) => p.id),
    O7_PROGRAMS.map((p) => p.id),
  );
  assert.deepEqual(selectPrograms(PROGRAMS, O6_PREFIX), O6_PROGRAMS);
  assert.deepEqual(
    Object.values(O7_AREAS)
      .flat()
      .map((p) => p.id),
    O7_PROGRAMS.map((p) => p.id),
  );
});

test("O-7 area sizes stay in the assigned ranges", () => {
  const sizes = Object.fromEntries(Object.keys(O7_AREAS).map((a) => [a, areaSteps(a).length]));
  assert.deepEqual(Object.keys(sizes), ["aggregate", "distinct", "fields", "inputs"]);
  assert.ok(sizes.aggregate >= 100 && sizes.aggregate <= 150, `aggregate ${sizes.aggregate}`);
  assert.ok(sizes.distinct >= 25 && sizes.distinct <= 35, `distinct ${sizes.distinct}`);
  assert.ok(sizes.fields >= 25 && sizes.fields <= 35, `fields ${sizes.fields}`);
  assert.ok(sizes.inputs >= 20 && sizes.inputs <= 30, `inputs ${sizes.inputs}`);
});

/** Every collection id that appears in a document path a program writes, at any depth. */
function pathSegments(program) {
  const names = [
    ...(program.seed ?? []).map(([name]) => name),
    ...steps(program, "commit").flatMap((s) =>
      s.body.writes.filter((w) => w.update).map((w) => relative(w.update.name)),
    ),
  ];
  return new Set(names.flatMap((name) => name.split("/").filter((_, i) => i % 2 === 0)));
}

test("O-7 steps read only what their program wrote, or a collection nothing writes", () => {
  const stages = new Set([
    "collection",
    "collection_group",
    "documents",
    "where",
    "select",
    "sort",
    "limit",
    "offset",
    "aggregate",
    "distinct",
    "add_fields",
    "remove_fields",
  ]);
  const everyWritten = new Set(
    [...O6_PROGRAMS, ...O7_PROGRAMS].flatMap((p) => [...writtenCollections(p), ...pathSegments(p)]),
  );
  for (const name of EMPTY_COLLECTIONS) assert.ok(!everyWritten.has(name), `${name} is written`);
  for (const program of O7_PROGRAMS) {
    const written = writtenCollections(program);
    const segments = pathSegments(program);
    for (const step of steps(program)) {
      const list = stagesOf(step);
      const where = `${program.id}#${step.id}`;
      assert.ok(INPUTS.has(list[0].name), where);
      for (const { name } of list.slice(1)) {
        assert.ok(stages.has(name), `${where}: ${name}`);
        // A second input stage is the one malformed shape a step may carry, and says so.
        if (!step.id.startsWith("invalid-")) assert.ok(!INPUTS.has(name), `${where}: ${name}`);
      }
      const [input] = list;
      if (input.name === "collection") {
        const from = input.args[0].referenceValue.slice(1);
        assert.match(from, /^[a-z0-9]+$/, where);
        assert.ok(written.has(from) || EMPTY_COLLECTIONS.has(from), `${where} reads ${from}`);
      } else if (input.name === "collection_group") {
        const id = input.args.at(-1)?.stringValue;
        if (step.id.startsWith("invalid-")) {
          // Not a collection id Firestore accepts, so it can name no data.
          assert.ok(
            id === undefined || id === "" || id.includes("/") || /^__.*__$/.test(id) || id === "..",
            where,
          );
        } else {
          assert.ok(segments.has(id) || EMPTY_COLLECTIONS.has(id), `${where} reads group ${id}`);
        }
      } else {
        for (const arg of input.args) {
          if (arg.referenceValue === undefined || step.id.startsWith("invalid-")) continue;
          const path = arg.referenceValue.replace(/^\//, "");
          const owner = parentOf(path);
          assert.ok(
            written.has(owner) || EMPTY_COLLECTIONS.has(owner) || owner === "",
            `${where} reads ${path}`,
          );
        }
      }
    }
    for (const step of program.steps) {
      assert.ok(["executePipeline", "commit"].includes(step.rpc), `${program.id}#${step.id}`);
    }
  }
});

test("O-7 commits touch only the program's own collections and delete only what it wrote", () => {
  for (const program of O7_PROGRAMS) {
    const written = writtenCollections(program);
    const existing = new Set((program.seed ?? []).map(([name]) => name));
    for (const step of steps(program, "commit")) {
      assert.deepEqual(Object.keys(step.body), ["writes"]);
      for (const write of step.body.writes) {
        if (write.update) {
          const name = relative(write.update.name);
          assert.ok(written.has(parentOf(name)));
          existing.add(name);
        } else {
          const name = relative(write.delete);
          assert.ok(existing.has(name), `${program.id}#${step.id} deletes ${name}`);
          existing.delete(name);
        }
      }
    }
  }
});

test("O-7 seeds hold nothing Firestore refuses to store", () => {
  const nestedArray = (value) =>
    value !== null &&
    typeof value === "object" &&
    ((value.arrayValue?.values ?? []).some((item) => item.arrayValue !== undefined) ||
      Object.values(value).some(nestedArray));
  for (const program of O7_PROGRAMS) {
    for (const [name, fields] of program.seed) {
      assert.ok(!nestedArray(fields), `${program.id} seed ${name}`);
      assert.ok(!seedHoldsVector({ seed: [[name, fields]] }), `${program.id} seed ${name}`);
      // A document path alternates collection and document ids, so its length is even.
      assert.equal(name.split("/").length % 2, 0, `${program.id} seed ${name}`);
    }
    for (const write of steps(program, "commit").flatMap((s) => s.body.writes)) {
      assert.ok(!nestedArray(write.update?.fields ?? {}), program.id);
    }
  }
});

test("every O-7 step stays in the named database on both transports", () => {
  const ctx = production();
  for (const program of O7_PROGRAMS) {
    for (const step of program.steps) {
      if ((step.transport ?? "rest") === "grpc") {
        const built = buildGrpcRequest(step, ctx, new Map());
        guardGrpcRequest(built, ctx);
        assert.equal(built.request.database, databaseName(ctx), step.id);
      } else {
        const built = buildRestRequest(step, ctx, new Map());
        guardRestRequest(built, ctx);
        assert.ok(built.url.includes("/databases/entpipe1/documents"), built.url);
      }
    }
  }
});

test("O-7 corpus carries no private or run-window values", () => {
  const text = JSON.stringify(O7_PROGRAMS);
  for (const forbidden of [/projects\//, /fireemu-oracle/, /AIza/, /@/, /\b2026-/]) {
    assert.doesNotMatch(text, forbidden);
  }
  // Long numbers are number-boundary values of the aggregate scenarios, nothing else (a project
  // number is twelve digits).
  const boundaries = new Set([
    "9007199254740992",
    "9007199254740993",
    "9223372036854775807",
    "9223372036854775806",
    "4611686018427387904",
    "4611686018427387905",
  ]);
  for (const [digits] of text.matchAll(/\b\d{9,}\b/g)) assert.ok(boundaries.has(digits), digits);
  for (const match of text.matchAll(/\{[a-z]+\}/g)) assert.equal(match[0], "{docs}");
});

test("O-7 programs are deterministic, JSON stable and named for their transport", async () => {
  const again = (await import(`./fs-ent-pipeline/o7-corpus.mjs?again=${Date.now()}`)).O7_PROGRAMS;
  assert.deepEqual(again, O7_PROGRAMS);
  assert.deepEqual(JSON.parse(JSON.stringify(O7_PROGRAMS)), O7_PROGRAMS);
  for (const program of O7_PROGRAMS) {
    const ids = program.steps.map((s) => s.id);
    assert.equal(new Set(ids).size, ids.length, program.id);
    for (const s of program.steps) {
      assert.match(s.id, /^[a-z0-9-]+$/);
      assert.equal(s.id.endsWith("-grpc"), s.transport === "grpc", s.id);
    }
  }
});

test("the O-7 packet counts are pinned", () => {
  const plan = o6Plan(O7_PROGRAMS);
  assert.deepEqual(
    {
      programs: plan.programs,
      steps: plan.steps,
      rest: plan.rest,
      grpc: plan.grpc,
      commits: plan.commits,
      seedDocs: plan.seedDocs,
    },
    { programs: 11, steps: 223, rest: 221, grpc: 2, commits: 0, seedDocs: 140 },
  );
});

test("each aggregate-around step decodes back to its PICT row", () => {
  assert.equal(AROUND_COMBOS.length, 16);
  assert.equal(new Set(AROUND_COMBOS.map((row) => row.join("/"))).size, 16);
  const levels = [
    ["none", "where", "limit"],
    ["none", "one", "two"],
    ["none", "where", "sort", "limit", "select"],
  ];
  // The required rows, and every pair of values of two factors.
  for (const seed of [
    ["none", "none", "none"],
    ["none", "one", "sort"],
    ["where", "two", "select"],
    ["limit", "one", "limit"],
  ]) {
    assert.ok(
      AROUND_COMBOS.some((row) => row.join() === seed.join()),
      seed.join(),
    );
  }
  for (let a = 0; a < 3; a += 1) {
    for (let b = a + 1; b < 3; b += 1) {
      for (const x of levels[a]) {
        for (const y of levels[b]) {
          assert.ok(
            AROUND_COMBOS.some((row) => row[a] === x && row[b] === y),
            `${x} with ${y}`,
          );
        }
      }
    }
  }
  const basic = O7_AREAS.aggregate.find((p) => p.id === `${O7_PREFIX}aggregate-basic`);
  for (const [pre, groups, post] of AROUND_COMBOS) {
    const found = basic.steps.find((s) => s.id === `around-${pre}-${groups}-${post}`);
    assert.ok(found, `${pre}-${groups}-${post}`);
    const list = stagesOf(found);
    assert.equal(list[0].args[0].referenceValue, "/ab");
    const at = list.findIndex((s) => s.name === "aggregate");
    const before = list.slice(1, at);
    const after = list.slice(at + 1);
    if (pre === "none") assert.deepEqual(before, []);
    if (pre === "where") {
      assert.deepEqual(
        before.map((s) => s.name),
        ["where"],
      );
      assert.deepEqual(before[0].args[0].functionValue.args, [
        { fieldReferenceValue: "n" },
        { integerValue: "2" },
      ]);
    }
    if (pre === "limit") {
      assert.deepEqual(
        before.map((s) => s.name),
        ["limit"],
      );
      assert.equal(before[0].args[0].integerValue, "3");
    }
    const [accumulators, keys] = list[at].args.map((arg) => arg.mapValue.fields);
    assert.deepEqual(Object.keys(accumulators), ["c", "s"]);
    assert.deepEqual(accumulators.c, { functionValue: { name: "count", args: [] } });
    assert.deepEqual(accumulators.s.functionValue.args, [{ fieldReferenceValue: "n" }]);
    assert.deepEqual(
      Object.entries(keys),
      {
        none: [],
        one: [["g", { fieldReferenceValue: "g" }]],
        two: [
          ["g", { fieldReferenceValue: "g" }],
          ["d", { fieldReferenceValue: "d" }],
        ],
      }[groups],
    );
    if (post === "none") assert.deepEqual(after, []);
    if (post === "where") {
      assert.deepEqual(
        after.map((s) => s.name),
        ["where"],
      );
      assert.deepEqual(after[0].args[0].functionValue.args, [
        { fieldReferenceValue: "c" },
        { integerValue: "1" },
      ]);
    }
    if (post === "sort") {
      assert.deepEqual(
        after.map((s) => s.name),
        ["sort"],
      );
      assert.deepEqual(after[0].args[0].mapValue.fields.direction, { stringValue: "descending" });
      assert.deepEqual(after[0].args[0].mapValue.fields.expression, { fieldReferenceValue: "c" });
    }
    if (post === "limit") {
      assert.deepEqual(
        after.map((s) => s.name),
        ["limit"],
      );
      assert.equal(after[0].args[0].integerValue, "2");
    }
    if (post === "select") {
      assert.deepEqual(
        after.map((s) => s.name),
        ["select"],
      );
      assert.deepEqual(after[0].args[0].mapValue.fields, { c: { fieldReferenceValue: "c" } });
    }
  }
});

// --- builders and generators ---

test("the v2 stage builders send the SDK's wire forms", () => {
  const accumulators = { n: { functionValue: { name: "count", args: [] } } };
  const groups = { g: fld("g") };
  // aggregate: the accumulators map, then the groups map (stage.js Aggregate._toProto).
  const agg = aggregate(accumulators, groups);
  assert.equal(agg.name, "aggregate");
  assert.deepEqual(agg.args, [
    { mapValue: { fields: accumulators } },
    { mapValue: { fields: groups } },
  ]);
  assert.deepEqual(aggregate(accumulators).args[1], { mapValue: { fields: {} } });
  // distinct and add_fields: one map.
  assert.deepEqual(distinct(groups), {
    name: "distinct",
    args: [{ mapValue: { fields: groups } }],
  });
  assert.deepEqual(addFields(groups), {
    name: "add_fields",
    args: [{ mapValue: { fields: groups } }],
  });
  // remove_fields: one field reference per argument, in order.
  assert.deepEqual(removeFields("a", "b.c"), {
    name: "remove_fields",
    args: [{ fieldReferenceValue: "a" }, { fieldReferenceValue: "b.c" }],
  });
  assert.deepEqual(removeFields().args, []);
  // collection_group: an empty parent reference, then the collection id as a string.
  assert.deepEqual(collectionGroup("items"), {
    name: "collection_group",
    args: [{ referenceValue: "" }, { stringValue: "items" }],
  });
  // documents: one reference per document path, from the root.
  assert.deepEqual(documents("c/d", "c/e/f/g"), {
    name: "documents",
    args: [{ referenceValue: "/c/d" }, { referenceValue: "/c/e/f/g" }],
  });
  assert.deepEqual(mapOf({}), { mapValue: { fields: {} } });
  // A step starts from the input stage it is given, over REST or gRPC.
  const rest = readFrom("s", collectionGroup("items"), distinct(groups));
  assert.deepEqual(rest, {
    id: "s",
    rpc: "executePipeline",
    body: {
      structuredPipeline: {
        pipeline: { stages: [collectionGroup("items"), distinct(groups)] },
      },
    },
  });
  assert.deepEqual(readFromGrpc("s", collection("c")), {
    id: "s",
    rpc: "executePipeline",
    body: { structuredPipeline: { pipeline: { stages: [collection("c")] } } },
    transport: "grpc",
  });
});

test("the accumulator table sends each aggregate function by its wire name", () => {
  assert.deepEqual(
    ACCUMULATORS.map(([alias, name]) => `${alias}:${name}`),
    ["n:count", "c:count", "s:sum", "a:average", "mn:minimum", "mx:maximum", "d:count_distinct"],
  );
  const map = accumulatorMap("v");
  assert.deepEqual(Object.keys(map), ["n", "c", "s", "a", "mn", "mx", "d"]);
  // countAll has no argument; every other accumulator takes the field.
  assert.deepEqual(map.n, { functionValue: { name: "count", args: [] } });
  for (const [alias, name] of ACCUMULATORS.slice(1)) {
    assert.deepEqual(map[alias], {
      functionValue: { name, args: [{ fieldReferenceValue: "v" }] },
    });
  }
  assert.deepEqual(accumulatorMap("x.y").s.functionValue.args, [{ fieldReferenceValue: "x.y" }]);
});

test("property: a number scenario is a collection of documents with one all-in-one aggregate", () => {
  forAll(
    100,
    (random) =>
      Array.from({ length: between(random, 1, 6) }, (_, i) => ({
        collection: `q${i}${pick(random, ["a", "b"])}`,
        values: Array.from({ length: between(random, 1, 5) }, () =>
          pick(random, [
            { integerValue: "1" },
            { stringValue: "x" },
            { nullValue: null },
            undefined,
          ]),
        ),
        split: random() < 0.5,
      })),
    (scenarios) => {
      const group = numberScenarios("numbers", scenarios);
      assert.equal(group.id, "numbers");
      assert.equal(
        group.seed.length,
        scenarios.reduce((n, s) => n + s.values.length, 0),
      );
      assert.equal(
        group.steps.length,
        scenarios.reduce((n, s) => n + 1 + (s.split ? 2 : 0), 0),
      );
      for (const scenario of scenarios) {
        const docs = group.seed.filter(([name]) => name.startsWith(`${scenario.collection}/`));
        assert.equal(docs.length, scenario.values.length);
        scenario.values.forEach((value, i) => {
          assert.equal(docs[i][0], `${scenario.collection}/d${String(i + 1).padStart(2, "0")}`);
          assert.deepEqual(docs[i][1], value === undefined ? {} : { v: value });
        });
        const mine = group.steps.filter((s) => s.id.startsWith(`${scenario.collection}-`));
        assert.deepEqual(
          mine.map((s) => s.id),
          [
            `${scenario.collection}-all`,
            ...(scenario.split
              ? [`${scenario.collection}-sum`, `${scenario.collection}-average`]
              : []),
          ],
        );
        const [all, ...single] = mine.map((s) => stagesOf(s));
        assert.equal(all[0].args[0].referenceValue, `/${scenario.collection}`);
        assert.deepEqual(all[1].args[0], { mapValue: { fields: accumulatorMap("v") } });
        assert.deepEqual(all[1].args[1], { mapValue: { fields: {} } });
        for (const [i, list] of single.entries()) {
          const alias = ["s", "a"][i];
          assert.deepEqual(list[1].args[0].mapValue.fields, {
            [alias]: accumulatorMap("v")[alias],
          });
        }
      }
    },
  );
});

// --- the plan ---

test("property: the O-7 plan is additive and matches the runner's ceilings", () => {
  forAll(
    60,
    (random) => {
      const left = [];
      const right = [];
      for (const program of O7_PROGRAMS) (random() < 0.5 ? left : right).push(program);
      return { left, right };
    },
    ({ left, right }) => {
      const whole = o6Plan([...left, ...right]);
      const a = o6Plan(left);
      const b = o6Plan(right);
      for (const key of ["programs", "steps", "rest", "grpc", "commits", "seedDocs"]) {
        assert.equal(whole[key], a[key] + b[key], key);
      }
      const limits = ceilings([...left, ...right]);
      assert.equal(whole.stepCeiling, limits.maxRequests);
      assert.equal(whole.harnessCeiling, limits.maxHarnessRequests);
    },
  );
  const plan = o6Plan(O7_PROGRAMS);
  assert.ok(plan.estimatedUsd < 10);
  assert.equal(estimatedUsd(O7_PROGRAMS, 2), plan.estimatedUsd);
  assert.ok(plan.expectedRequests <= plan.worstRequests);
});

test("the O-7 seed/wipe plan equals a simulated run and the database ends empty", async () => {
  const restOnly = O7_PROGRAMS.map((program) => ({
    ...program,
    steps: program.steps.filter((s) => (s.transport ?? "rest") === "rest"),
  }));
  const fake = fakeFirestore();
  let out;
  try {
    out = await runCorpus(restOnly, production(), { ...ceilings(restOnly), timeoutMs: 5_000 });
  } finally {
    fake.restore();
  }
  assert.deepEqual(out.failures, []);
  assert.equal(fake.store.size, 0);
  const totals = o6Plan(restOnly);
  assert.equal(totals.harnessExpected, out.harnessRequests);
  assert.equal(
    out.requests,
    restOnly.reduce((n, p) => n + p.steps.length, 0),
  );
  assert.equal(totals.expectedRequests, 5 + 2 * (out.requests + out.harnessRequests));
  assert.equal(fake.calls.length, out.requests + out.harnessRequests);
  for (const program of restOnly) {
    const plan = seedWipePlan(program);
    assert.ok(plan.harnessRequests <= 8 + 2 * Math.ceil(plan.seedDocs / 500));
  }
});

test("a later area joins the O-7 table without changing a program in it", () => {
  const before = O7_PROGRAMS.map(programDigest);
  const [extra] = defineArea("x", [{ id: "g", steps: [] }], O7_PREFIX);
  assert.equal(extra.id, `${O7_PREFIX}x-g`);
  assert.deepEqual(O7_PROGRAMS.map(programDigest), before);
});

/** The frozen table (replaced by the fixture's `corpusDigest` once recorded). */
const FROZEN = [
  [
    "fs-ent-pipeline/o7/aggregate-empty",
    "f42a8a79881917afd9ddf933b08da1dbba18daa8ba47e0634647b3547091bb00",
  ],
  [
    "fs-ent-pipeline/o7/aggregate-basic",
    "61bce044d30443775810303bdaaae237d5f5d846ee3ef0ca358f16316b41b6c6",
  ],
  [
    "fs-ent-pipeline/o7/aggregate-numbers",
    "f0da25d919d2238b448676ab55bb27a703c8c279153ecbc06a6becb24cad0c8c",
  ],
  [
    "fs-ent-pipeline/o7/aggregate-kinds",
    "ca653a8b3196b0e777effd50a7a17e9d7616c60789e7ea14c8b3abb18e7d549c",
  ],
  [
    "fs-ent-pipeline/o7/aggregate-group-keys",
    "77004cb6526311c3706cd6f33439e9d921013a80099f7e279c50f299d6bfa480",
  ],
  [
    "fs-ent-pipeline/o7/aggregate-aliases",
    "2a3a5bc14c5e02ff9c34e8ff928dba18c2c5c13b96b7f959229ba516b6c02bb9",
  ],
  [
    "fs-ent-pipeline/o7/aggregate-args",
    "3bdabbfc55ce34a4a430abd9b26c1f4e7196ad3cf7d6372b222e32a5e54d6b50",
  ],
  [
    "fs-ent-pipeline/o7/distinct-main",
    "6d51d4bf841651ee67e078551ef0ecc4c15a019b67960276dc1c0311c6439bf1",
  ],
  [
    "fs-ent-pipeline/o7/fields-main",
    "d99d06bb136db9c57dcd8ceab714d78e5258239e4ea97ca122d6eb330f78ad62",
  ],
  [
    "fs-ent-pipeline/o7/inputs-collection-group",
    "54ba84606b6d5cd339acfab070512b0b76cfa7c59fcd5b17b8537dac02556eac",
  ],
  [
    "fs-ent-pipeline/o7/inputs-documents",
    "8d1642c557c79189d99eff0e9eaf21f3fc9fafdcac4a7cd544902c39f02d6470",
  ],
];

test("the O-7 table is the frozen one", () => {
  assert.deepEqual(
    O7_PROGRAMS.map((p) => [p.id, programDigest(p)]),
    FROZEN,
  );
});
