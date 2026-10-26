// The O-6 pipeline corpus (sort, relaxed stage order, logical and recorded functions in where,
// result order without a sort): case generation, the request plan and the seed/wipe plan. Nothing
// here sends a request; the only fetch is an in-memory stand-in for the sandbox database.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import { PROGRAMS, seedHoldsVector } from "./fs-ent-pipeline/corpus.mjs";
import {
  O6_AREAS,
  O6_PREFIX,
  O6_PROGRAMS,
  SORT_COMBOS,
  defineArea,
  o6Plan,
  ordering,
  seedWipePlan,
  truthTableDocs,
  withinKindsProgram,
} from "./fs-ent-pipeline/o6-corpus.mjs";
import {
  SANDBOX_PROJECT,
  buildGrpcRequest,
  buildRestRequest,
  createContext,
  databaseName,
  guardGrpcRequest,
  guardRestRequest,
  validateCorpus,
} from "./fs-ent-pipeline/harness.mjs";
import { runCorpus } from "./fs-ent-pipeline/session.mjs";
import { ceilings, estimatedUsd, programDigest, selectPrograms } from "./fs-query-index/run.mjs";

const LANE = "fs-ent-pipeline";
const steps = (program, rpc = "executePipeline") => program.steps.filter((s) => s.rpc === rpc);
const areaSteps = (area) => O6_AREAS[area].flatMap((program) => steps(program));

/** A small seeded generator, so a failing property reproduces from its seed. */
function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const pick = (random, items) => items[Math.floor(random() * items.length)];
const between = (random, low, high) => low + Math.floor(random() * (high - low + 1));

/** Runs `check` on `runs` generated inputs; the seed is in the failure message. */
function forAll(runs, generate, check) {
  for (let seed = 1; seed <= runs; seed += 1) {
    const input = generate(mulberry32(seed));
    try {
      check(input);
    } catch (error) {
      error.message = `seed ${seed}: ${error.message}`;
      throw error;
    }
  }
}

const production = () =>
  createContext({
    run: "1",
    startedMs: Date.parse("2026-10-26T00:00:00Z"),
    database: "entpipe1",
    target: { kind: "production", token: "t", quotaProject: SANDBOX_PROJECT },
  });

const parentOf = (path) => path.split("/").slice(0, -1).join("/");
const relative = (name) => name.replace(/^\{docs\}\//, "");

/** Every collection a program writes: seeds and commit updates. */
function writtenCollections(program) {
  const names = [
    ...(program.seed ?? []).map(([name]) => name),
    ...steps(program, "commit").flatMap((s) =>
      s.body.writes.filter((w) => w.update).map((w) => relative(w.update.name)),
    ),
  ];
  return new Set(names.map(parentOf));
}

test("O-6 programs are the tail of PROGRAMS, under their own prefix, unique and valid", () => {
  assert.ok(O6_PROGRAMS.length > 0);
  assert.deepEqual(PROGRAMS.slice(-O6_PROGRAMS.length), O6_PROGRAMS);
  assert.equal(new Set(O6_PROGRAMS.map((p) => p.id)).size, O6_PROGRAMS.length);
  for (const program of O6_PROGRAMS) assert.ok(program.id.startsWith(O6_PREFIX), program.id);
  validateCorpus(O6_PROGRAMS, LANE);
  validateCorpus(PROGRAMS, LANE);
  assert.deepEqual(
    selectPrograms(PROGRAMS, O6_PREFIX).map((p) => p.id),
    O6_PROGRAMS.map((p) => p.id),
  );
  assert.deepEqual(
    Object.values(O6_AREAS)
      .flat()
      .map((p) => p.id),
    O6_PROGRAMS.map((p) => p.id),
  );
});

test("O-6 area sizes stay in the assigned ranges", () => {
  const sizes = Object.fromEntries(Object.keys(O6_AREAS).map((a) => [a, areaSteps(a).length]));
  assert.deepEqual(Object.keys(sizes), ["sort", "stage-order", "where-functions", "order"]);
  assert.ok(sizes.sort >= 60 && sizes.sort <= 90, `sort ${sizes.sort}`);
  assert.ok(sizes["stage-order"] >= 10 && sizes["stage-order"] <= 20, `${sizes["stage-order"]}`);
  assert.ok(
    sizes["where-functions"] >= 30 && sizes["where-functions"] <= 45,
    `${sizes["where-functions"]}`,
  );
  assert.ok(sizes.order >= 10 && sizes.order <= 20, `order ${sizes.order}`);
});

test("O-6 steps read only what their program wrote and use only the reviewed stages", () => {
  const stages = new Set(["collection", "where", "select", "sort", "limit", "offset"]);
  for (const program of O6_PROGRAMS) {
    const written = writtenCollections(program);
    for (const step of steps(program)) {
      const list = step.body.structuredPipeline.pipeline.stages;
      assert.equal(list[0].name, "collection", `${program.id}#${step.id}`);
      assert.match(list[0].args[0].referenceValue, /^\/[a-z0-9]+$/);
      assert.ok(
        written.has(list[0].args[0].referenceValue.slice(1)),
        `${program.id}#${step.id} reads ${list[0].args[0].referenceValue}`,
      );
      for (const { name } of list.slice(1)) {
        assert.ok(stages.has(name), `${program.id}#${step.id}: ${name}`);
        assert.notEqual(name, "collection");
      }
    }
    for (const step of program.steps) {
      assert.ok(["executePipeline", "commit"].includes(step.rpc), `${program.id}#${step.id}`);
    }
  }
});

test("O-6 commits touch only the program's own collections and delete only what it wrote", () => {
  for (const program of O6_PROGRAMS) {
    const written = writtenCollections(program);
    const existing = new Set((program.seed ?? []).map(([name]) => name));
    for (const step of steps(program, "commit")) {
      assert.deepEqual(Object.keys(step.body), ["writes"]);
      for (const write of step.body.writes) {
        assert.deepEqual(Object.keys(write).length, 1);
        if (write.update) {
          const name = relative(write.update.name);
          assert.match(name, /^[a-z0-9]+\/[A-Za-z0-9_-]+$/);
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

test("O-6 seeds hold nothing Firestore refuses to store", () => {
  // A refused seed is a fatal harness error that ends the recording (session.mjs), so every
  // seed and every commit write must be storable: no array directly inside an array, and a
  // vector only in a commit step.
  const nestedArray = (value) =>
    value !== null &&
    typeof value === "object" &&
    ((value.arrayValue?.values ?? []).some((item) => item.arrayValue !== undefined) ||
      Object.values(value).some(nestedArray));
  for (const program of O6_PROGRAMS) {
    for (const [name, fields] of program.seed) {
      assert.ok(!nestedArray(fields), `${program.id} seed ${name}`);
      assert.ok(!seedHoldsVector({ seed: [[name, fields]] }), `${program.id} seed ${name}`);
    }
    for (const write of steps(program, "commit").flatMap((s) => s.body.writes)) {
      assert.ok(!nestedArray(write.update?.fields ?? {}), program.id);
    }
  }
});

test("every O-6 step stays in the named database on both transports", () => {
  const ctx = production();
  for (const program of O6_PROGRAMS) {
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

test("the O-6 selector records only its programs, within the packet's request bound", () => {
  const selected = selectPrograms(PROGRAMS, O6_PREFIX);
  assert.equal(selected.length, O6_PROGRAMS.length);
  assert.deepEqual(ceilings(selected), { maxRequests: 167, maxHarnessRequests: 178 });
  assert.equal(o6Plan(selected).worstRequests, 1 + 2 + 2 * (167 + 178) + 2);
  assert.equal(estimatedUsd(selected, 2), o6Plan(selected).estimatedUsd);
  assert.ok(o6Plan(selected).estimatedUsd < 0.1);
  // The recorded programs keep their digests, and an O-6 program in the fixture is the same
  // program as the corpus's.
  const recorded = JSON.parse(
    readFileSync(new URL("../fs-ent-pipeline-production.json", import.meta.url), "utf8"),
  ).programs;
  for (const program of PROGRAMS) {
    const row = recorded[program.id];
    if (row) assert.equal(row.corpusDigest, programDigest(program), program.id);
  }
});

test("O-6 corpus carries no private or run-window values", () => {
  const text = JSON.stringify(O6_PROGRAMS);
  for (const forbidden of [/projects\//, /fireemu-oracle/, /AIza/, /@/, /\b2026-/]) {
    assert.doesNotMatch(text, forbidden);
  }
  // Long numbers are the number-boundary values of the sort kinds, nothing else (a project
  // number is twelve digits).
  const boundaries = new Set(["9007199254740992", "9007199254740993", "9223372036854775807"]);
  for (const [digits] of text.matchAll(/\b\d{9,}\b/g)) assert.ok(boundaries.has(digits), digits);
  // The only stand-in for a name is the placeholder the harness resolves.
  for (const match of text.matchAll(/\{[a-z]+\}/g)) assert.equal(match[0], "{docs}");
});

test("O-6 programs are deterministic and JSON stable", async () => {
  const again = (await import(`./fs-ent-pipeline/o6-corpus.mjs?again=${Date.now()}`)).O6_PROGRAMS;
  assert.deepEqual(again, O6_PROGRAMS);
  assert.deepEqual(JSON.parse(JSON.stringify(O6_PROGRAMS)), O6_PROGRAMS);
  assert.deepEqual(again.map(programDigest), O6_PROGRAMS.map(programDigest));
  for (const program of O6_PROGRAMS) {
    const ids = program.steps.map((s) => s.id);
    assert.equal(new Set(ids).size, ids.length, program.id);
    for (const id of ids) assert.match(id, /^[a-z0-9-]+$/);
  }
});

test("the O-6 packet counts are pinned", () => {
  const plan = o6Plan(O6_PROGRAMS);
  assert.deepEqual(
    {
      programs: plan.programs,
      steps: plan.steps,
      rest: plan.rest,
      grpc: plan.grpc,
      commits: plan.commits,
      seedDocs: plan.seedDocs,
    },
    {
      programs: 16,
      steps: 167,
      rest: 163,
      grpc: 4,
      commits: 13,
      seedDocs: 189,
    },
  );
});

// --- generators ---

test("property: the within-kinds generator makes an ascending and a descending step per collection", () => {
  forAll(
    100,
    (random) =>
      Array.from({ length: between(random, 1, 8) }, (_, i) => ({
        collection: `k${i}${pick(random, ["a", "b", "c"])}`,
        docs: Array.from({ length: between(random, 1, 6) }, (_, j) => [
          `d${j}`,
          { v: { integerValue: String(between(random, -5, 5)) } },
        ]),
      })),
    (specs) => {
      const group = withinKindsProgram("within", specs);
      assert.equal(group.steps.length, 2 * specs.length);
      assert.equal(
        group.seed.length,
        specs.reduce((n, spec) => n + spec.docs.length, 0),
      );
      for (const [i, spec] of specs.entries()) {
        const [up, down] = group.steps.slice(2 * i, 2 * i + 2);
        const order = (s) => s.body.structuredPipeline.pipeline.stages;
        assert.equal(order(up)[0].args[0].referenceValue, `/${spec.collection}`);
        assert.equal(order(down)[0].args[0].referenceValue, `/${spec.collection}`);
        assert.equal(order(up)[1].args[0].mapValue.fields.direction.stringValue, "ascending");
        assert.equal(order(down)[1].args[0].mapValue.fields.direction.stringValue, "descending");
        assert.deepEqual(
          order(up)[1].args[0].mapValue.fields.expression,
          order(down)[1].args[0].mapValue.fields.expression,
        );
      }
    },
  );
});

test("property: the truth table holds every pair of the domain once", () => {
  forAll(
    100,
    (random) => {
      const size = between(random, 1, 6);
      const kinds = [
        { id: "t", value: { booleanValue: true } },
        { id: "f", value: { booleanValue: false } },
        { id: "n", value: { nullValue: null } },
        { id: "m", value: undefined },
        { id: "i", value: { integerValue: "1" } },
        { id: "s", value: { stringValue: "x" } },
      ];
      return kinds.slice(0, size);
    },
    (domain) => {
      const docs = truthTableDocs("tt", domain);
      assert.equal(docs.length, domain.length ** 2);
      assert.equal(new Set(docs.map(([name]) => name)).size, docs.length);
      for (const [name, fields] of docs) {
        assert.match(name, /^tt\/[a-z]{2}$/);
        const [a, b] = name
          .slice(3)
          .split("")
          .map((id) => domain.find((d) => d.id === id));
        assert.deepEqual(fields.a, a.value, name);
        assert.deepEqual(fields.b, b.value, name);
        // A missing value is an absent field, never an explicit undefined.
        assert.equal("a" in fields, a.value !== undefined);
        assert.equal("b" in fields, b.value !== undefined);
      }
    },
  );
});

test("property: an ordering is a map of exactly a direction and an expression", () => {
  forAll(
    100,
    (random) => ({
      direction: pick(random, ["ascending", "descending"]),
      path: pick(random, ["v", "a.b", "__name__", "n"]),
    }),
    ({ direction, path }) => {
      const value = ordering({ fieldReferenceValue: path }, direction);
      assert.deepEqual(Object.keys(value), ["mapValue"]);
      assert.deepEqual(Object.keys(value.mapValue.fields).toSorted(), ["direction", "expression"]);
      assert.deepEqual(value.mapValue.fields.direction, { stringValue: direction });
      assert.deepEqual(value.mapValue.fields.expression, { fieldReferenceValue: path });
    },
  );
});

test("sort combinations: the 16 pairwise rows are all in the combos program", () => {
  assert.equal(SORT_COMBOS.length, 16);
  assert.equal(new Set(SORT_COMBOS.map((row) => row.join("/"))).size, 16);
  const seeds = [
    ["none", "asc", "tied", "offset-limit"],
    ["where", "desc", "unique", "limit"],
    ["select-alias", "asc", "unique", "none"],
    ["select-drop", "desc", "name", "select"],
  ];
  for (const seed of seeds) assert.ok(SORT_COMBOS.some((row) => row.join() === seed.join()));
  const combos = O6_AREAS.sort.find((p) => p.id === `${O6_PREFIX}sort-combos`);
  assert.ok(combos);
  assert.deepEqual(
    steps(combos).map((s) => s.id),
    SORT_COMBOS.map((row) => row.join("-")),
  );
  // Every pair of values of two different factors occurs in some row.
  const levels = [
    ["none", "where", "select-alias", "select-drop"],
    ["asc", "desc"],
    ["tied", "unique", "name"],
    ["none", "limit", "offset-limit", "select"],
  ];
  for (let a = 0; a < 4; a += 1) {
    for (let b = a + 1; b < 4; b += 1) {
      for (const x of levels[a]) {
        for (const y of levels[b]) {
          assert.ok(
            SORT_COMBOS.some((row) => row[a] === x && row[b] === y),
            `${x} with ${y}`,
          );
        }
      }
    }
  }
});

test("a later area joins without changing any program already in the table", () => {
  const before = O6_PROGRAMS.map(programDigest);
  const extra = defineArea("aggregate", [
    {
      id: "count",
      seed: [["ag/d", { n: { integerValue: "1" } }]],
      steps: [{ id: "all", rpc: "executePipeline", body: {} }],
    },
  ]);
  assert.deepEqual(
    extra.map((p) => p.id),
    [`${O6_PREFIX}aggregate-count`],
  );
  assert.deepEqual(O6_PROGRAMS.map(programDigest), before);
  // The new program is in no other program's id space.
  assert.ok(!O6_PROGRAMS.some((p) => p.id === extra[0].id));
  assert.throws(() => defineArea("Bad Area", []), /area/);
  assert.throws(
    () =>
      defineArea("x", [
        { id: "g", seed: [], steps: [] },
        { id: "g", seed: [], steps: [] },
      ]),
    /duplicate/,
  );
});

// --- the plan ---

test("property: the plan is additive and matches the runner's ceilings", () => {
  forAll(
    60,
    (random) => {
      const left = [];
      const right = [];
      for (const program of O6_PROGRAMS) (random() < 0.5 ? left : right).push(program);
      return { left, right };
    },
    ({ left, right }) => {
      const whole = o6Plan([...left, ...right]);
      const a = o6Plan(left);
      const b = o6Plan(right);
      for (const key of ["programs", "steps", "rest", "grpc", "commits", "seedDocs"]) {
        assert.equal(whole[key], a[key] + b[key], key);
      }
      assert.equal(whole.steps, whole.rest + whole.grpc);
      const limits = ceilings([...left, ...right]);
      assert.equal(whole.stepCeiling, limits.maxRequests);
      assert.equal(whole.harnessCeiling, limits.maxHarnessRequests);
    },
  );
  const plan = o6Plan(O6_PROGRAMS);
  assert.ok(plan.estimatedUsd < 10);
  // S0 one describe, the preflight two reads, two recordings, A1 two read-backs.
  assert.equal(plan.worstRequests, 1 + 2 + 2 * (plan.stepCeiling + plan.harnessCeiling) + 2);
  assert.ok(plan.expectedRequests <= plan.worstRequests);
});

/** An in-memory Firestore: commit, the kindless wipe query and an empty pipeline answer. */
function fakeFirestore(initial = []) {
  const store = new Map(initial.map((name) => [name, {}]));
  const calls = [];
  const original = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    const path = String(url);
    calls.push(path);
    const base = `https://firestore.googleapis.com/v1/projects/${SANDBOX_PROJECT}/databases/entpipe1/documents`;
    assert.ok(path.startsWith(`${base}:`), path);
    const body = init.body ? JSON.parse(init.body) : {};
    if (path.endsWith(":commit")) {
      for (const write of body.writes) {
        if (write.update) store.set(write.update.name, write.update.fields);
        else store.delete(write.delete);
      }
      return new Response(JSON.stringify({ writeResults: body.writes.map(() => ({})) }));
    }
    if (path.endsWith(":runQuery")) {
      const names = [...store.keys()].toSorted().slice(0, body.structuredQuery.limit);
      return new Response(
        JSON.stringify(names.length ? names.map((name) => ({ document: { name } })) : [{}]),
      );
    }
    return new Response(JSON.stringify([{ executionTime: "2026-10-26T00:00:00Z" }]));
  };
  return {
    store,
    calls,
    restore: () => {
      globalThis.fetch = original;
    },
  };
}

test("seed/wipe plan: the planned requests equal a simulated run and the database ends empty", async () => {
  const restOnly = O6_PROGRAMS.map((program) => ({
    ...program,
    steps: program.steps.filter((s) => (s.transport ?? "rest") === "rest"),
  }));
  const fake = fakeFirestore();
  let out;
  try {
    out = await runCorpus(restOnly, production(), {
      ...ceilings(restOnly),
      timeoutMs: 5_000,
    });
  } finally {
    fake.restore();
  }
  assert.deepEqual(out.failures, []);
  assert.equal(fake.store.size, 0);
  const plan = restOnly.map(seedWipePlan);
  assert.equal(
    out.requests,
    restOnly.reduce((n, p) => n + p.steps.length, 0),
  );
  // Every program: a wipe, its seed batches, a wipe; plus the run's final wipe.
  assert.equal(out.harnessRequests, plan.reduce((n, p) => n + p.harnessRequests, 0) + 1);
  assert.equal(fake.calls.length, out.requests + out.harnessRequests);
  for (const program of plan) {
    assert.deepEqual(program.operations.at(0), "wipe");
    assert.deepEqual(program.operations.at(-1), "wipe");
    assert.ok(program.harnessRequests <= 8 + 2 * Math.ceil(program.seedDocs / 500));
  }
});

test("seed/wipe plan: counts for an empty program, a seed of 501 documents and writes inside the program", () => {
  const empty = seedWipePlan({ id: "fs-ent-pipeline/o6/x", seed: [], steps: [] });
  assert.deepEqual(empty.operations, ["wipe", "wipe"]);
  assert.equal(empty.harnessRequests, 2);
  const many = seedWipePlan({
    id: "fs-ent-pipeline/o6/x",
    seed: Array.from({ length: 501 }, (_, i) => [`m/d${i}`, {}]),
    steps: [],
  });
  // wipe read, two seed batches, then two delete rounds (a read and a delete each) and the
  // closing read.
  assert.equal(many.harnessRequests, 1 + 2 + 2 * 2 + 1);
  const written = seedWipePlan({
    id: "fs-ent-pipeline/o6/x",
    seed: [],
    steps: [
      {
        id: "w",
        rpc: "commit",
        body: { writes: [{ update: { name: "{docs}/o/a", fields: {} } }] },
      },
      { id: "d", rpc: "commit", body: { writes: [{ delete: "{docs}/o/a" }] } },
    ],
  });
  // The program deletes what it wrote, so the closing wipe finds nothing.
  assert.equal(written.harnessRequests, 2);
});

test("the dry run has both profiles' configs and the runner reads the override", async () => {
  const strict = JSON.parse(
    await readFile(new URL("../fs-ent-pipeline.fireemu.json", import.meta.url)),
  );
  const emulator = JSON.parse(
    await readFile(new URL("../fs-ent-pipeline.emulator.fireemu.json", import.meta.url)),
  );
  assert.equal(strict.profile, "strict");
  assert.equal(emulator.profile, "emulator");
  assert.deepEqual(emulator.firestore, strict.firestore);
  const runner = await readFile(new URL("./fs-query-index/run.mjs", import.meta.url), "utf8");
  assert.match(runner, /FS_QUERY_INDEX_LOCAL_CONFIG/);
});
