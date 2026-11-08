// FS-RULES shapes, second family: Rules whose query authorization the Rules fixes decide without a
// production row when the offending key is stored (default, key list, nested membership), the
// exact key set and cardinality, a function called with `resource`, and a named document with an
// offset. The facts the fake production uses are the test's choice, not claims about production.

import assert from "node:assert/strict";
import { test } from "node:test";

import { createContext, SANDBOX_PROJECT } from "./fs-rules/harness.mjs";
import {
  corpusDigest,
  countRequests,
  DIFFS_PROGRAMS,
  PRINCIPALS,
  REQUEST_CAP,
  rulesetSource,
  SHAPES_PROGRAMS,
  SHAPES_TWO_PROGRAMS,
  SHAPES_TWO_RULESET_IDS,
  validateCorpus,
} from "./fs-rules-v1/corpus.mjs";
import {
  ceilings,
  corpusFor,
  fixtureText,
  selectPrograms,
  TASK_ID_SHAPES,
  TASK_ID_SHAPES_TWO,
  taskIdFor,
} from "./fs-rules-v1/judge.mjs";
import { FIXES, OFFICIAL, shapesTwoReport } from "./fs-rules-v1/shapes-two.mjs";
import { shapesReportLine } from "./fs-rules-v1/shapes.mjs";
import { runCorpus } from "./fs-rules-v1/session.mjs";
import { createClock, createWorld } from "./fs-rules-v1/test-world.mjs";

const PRODUCTION = {
  kind: "production",
  adminToken: "ya29.owner-test-token",
  apiKey: "AIzaShapesTwoTestKeyNotReal",
  quotaProject: SANDBOX_PROJECT,
  projectNumber: "555500000003",
};

async function record({ scenario, programs = SHAPES_TWO_PROGRAMS } = {}) {
  const { world, fetchImpl, grpc } = createWorld(scenario);
  const clock = createClock();
  const ctx = createContext({ run: "1790000000200", startedMs: clock.now(), target: PRODUCTION });
  const out = await runCorpus(
    { programs, principals: PRINCIPALS },
    ctx,
    { fetchImpl, grpc, sleep: clock.sleep, now: clock.now },
    ceilings(programs),
  );
  return { out, world };
}

const rowsOf = (program) => program.steps.filter((step) => !step.publish);
const program = (suffix) =>
  SHAPES_TWO_PROGRAMS.find((p) => p.id === `fs-rules-v1/shapes-two/${suffix}`);
const step = (suffix, id) => program(suffix).steps.find((s) => s.id === id);
const query = (id) => step("queries", id).body.structuredQuery;
const collectionOf = (path) => path.split("/").at(-2);

const intFilter = (fieldPath, n) => ({
  fieldFilter: { field: { fieldPath }, op: "EQUAL", value: { integerValue: n } },
});
const boolFilter = (fieldPath, value) => ({
  fieldFilter: { field: { fieldPath }, op: "EQUAL", value: { booleanValue: value } },
});
const nameFilter = (doc) => ({
  fieldFilter: {
    field: { fieldPath: "__name__" },
    op: "EQUAL",
    value: { referenceValue: `{docs}/fsr9-p-own/${doc}` },
  },
});
const A1 = intFilter("a", "1");

// ---- the corpus -----------------------------------------------------------------------------

test("the corpus is two programs of 24 rows, valid and under the cap", () => {
  assert.deepEqual(
    SHAPES_TWO_PROGRAMS.map((p) => p.id),
    ["fs-rules-v1/shapes-two/queries", "fs-rules-v1/shapes-two/fn"],
  );
  assert.deepEqual(SHAPES_TWO_RULESET_IDS, ["shapes-two-queries", "shapes-two-fn"]);
  assert.equal(validateCorpus(SHAPES_TWO_PROGRAMS), 24);
  assert.equal(countRequests(SHAPES_TWO_PROGRAMS), 24);
  assert.ok(24 <= REQUEST_CAP);
  assert.deepEqual(
    SHAPES_TWO_PROGRAMS.map((p) => rowsOf(p).length),
    [21, 3],
  );
  for (const p of SHAPES_TWO_PROGRAMS)
    assert.deepEqual(p.steps[0], { id: "publishes", publish: true });
});

test("the query rules are exactly these, each in its own collection", () => {
  const source = rulesetSource("shapes-two-queries");
  const rules = [
    ["fsr9-p-ctl-true", "true"],
    ["fsr9-p-ctl-false", "false"],
    ["fsr9-p-get", "resource.data.get('blocked', false) == false"],
    ["fsr9-p-get-absent", "resource.data.get('blocked', false) == false"],
    ["fsr9-p-keys", "!resource.data.keys().hasAny(['blocked'])"],
    ["fsr9-p-keys-absent", "!resource.data.keys().hasAny(['blocked'])"],
    ["fsr9-p-meta", "!('blocked' in resource.data.meta)"],
    ["fsr9-p-meta-absent", "!('blocked' in resource.data.meta)"],
    ["fsr9-p-only-plain", "resource.data.keys().hasOnly(['a'])"],
    ["fsr9-p-only-extra", "resource.data.keys().hasOnly(['a'])"],
    ["fsr9-p-only-b", "resource.data.keys().hasOnly(['b'])"],
    ["fsr9-p-size-plain", "resource.data.size() == 1"],
    ["fsr9-p-size-extra", "resource.data.size() == 1"],
    ["fsr9-p-size-zero", "resource.data.size() == 0"],
    ["fsr9-p-own", "resource.data.owner == request.auth.uid"],
  ];
  for (const [match, condition] of rules)
    assert.ok(
      source.includes(`match /${match}/{id} {\n      allow list: if ${condition};\n    }`),
      match,
    );
  assert.equal(source.split("allow list").length - 1, rules.length);
  assert.ok(!source.includes("allow get"), "list rules only");
});

test("the function ruleset declares f and g inside the match and calls them with resource", () => {
  const source = rulesetSource("shapes-two-fn");
  assert.ok(
    source.includes(
      "    function f(r) {\n      return r != null;\n    }\n    function g(r) {\n      return r == null;\n    }\n",
    ),
  );
  for (const [match, condition] of [
    ["fsr9-p-fn-resource", "f(resource)"],
    ["fsr9-p-fn-null", "g(resource)"],
    ["fsr9-p-fn-arg", "f(request.auth)"],
  ])
    assert.ok(
      source.includes(`match /${match}/{id} {\n      allow list: if ${condition};\n    }`),
      match,
    );
  assert.equal(source.split("allow list").length - 1, 3);
  assert.ok(source.indexOf("function f") < source.indexOf("match /fsr9-p-fn-resource"));
});

test("a stored-key row, its absent-key check and its pinned refused control query the same unrelated field", () => {
  const from = (collection) => [{ collectionId: collection }];
  assert.deepEqual(query("get-stored"), { from: from("fsr9-p-get"), where: A1 });
  assert.deepEqual(query("get-absent"), { from: from("fsr9-p-get-absent"), where: A1 });
  assert.deepEqual(query("get-allow"), {
    from: from("fsr9-p-get"),
    where: boolFilter("blocked", false),
  });
  assert.deepEqual(query("get-deny"), {
    from: from("fsr9-p-get"),
    where: boolFilter("blocked", true),
  });
  assert.deepEqual(query("keys-stored"), { from: from("fsr9-p-keys"), where: A1 });
  assert.deepEqual(query("keys-absent"), { from: from("fsr9-p-keys-absent"), where: A1 });
  assert.deepEqual(query("keys-deny"), {
    from: from("fsr9-p-keys"),
    where: boolFilter("blocked", true),
  });
  assert.deepEqual(query("meta-stored"), {
    from: from("fsr9-p-meta"),
    where: intFilter("meta.a", "1"),
  });
  assert.deepEqual(query("meta-absent"), {
    from: from("fsr9-p-meta-absent"),
    where: intFilter("meta.a", "1"),
  });
  assert.deepEqual(query("meta-deny"), {
    from: from("fsr9-p-meta"),
    where: boolFilter("meta.blocked", true),
  });
});

test("the controls, the key-set rows and the cardinality rows query a == 1", () => {
  for (const [id, collection] of [
    ["ctl-allow", "fsr9-p-ctl-true"],
    ["ctl-deny", "fsr9-p-ctl-false"],
    ["only-plain", "fsr9-p-only-plain"],
    ["only-extra", "fsr9-p-only-extra"],
    ["only-b-deny", "fsr9-p-only-b"],
    ["size-plain", "fsr9-p-size-plain"],
    ["size-extra", "fsr9-p-size-extra"],
    ["size-zero-deny", "fsr9-p-size-zero"],
  ])
    assert.deepEqual(query(id), { from: [{ collectionId: collection }], where: A1 }, id);
});

test("the named-document rows skip exactly one document", () => {
  const from = [{ collectionId: "fsr9-p-own" }];
  assert.deepEqual(query("name-offset"), { from, where: nameFilter("mine"), offset: 1 });
  assert.deepEqual(query("foreign-offset"), { from, where: nameFilter("foreign"), offset: 1 });
  assert.deepEqual(query("owner-offset"), {
    from,
    where: {
      fieldFilter: {
        field: { fieldPath: "owner" },
        op: "EQUAL",
        value: { stringValue: "UID(anon)" },
      },
    },
    offset: 1,
  });
});

test("the function rows query a == 1 on the collection of their rule", () => {
  for (const [id, collection] of [
    ["fn-resource", "fsr9-p-fn-resource"],
    ["fn-null-deny", "fsr9-p-fn-null"],
    ["fn-arg-allow", "fsr9-p-fn-arg"],
  ]) {
    const row = step("fn", id);
    assert.equal(row.rpc, "runQuery");
    assert.deepEqual(row.body.structuredQuery, { from: [{ collectionId: collection }], where: A1 });
  }
});

test("the seed stores the key in the stored-key collections and omits it in the absent-key ones", () => {
  const a1 = { a: { integerValue: "1" } };
  const blocked = { blocked: { booleanValue: true } };
  const extra = { extra: { booleanValue: true } };
  const n1 = { n: { integerValue: "1" } };
  assert.deepEqual(program("queries").seed, [
    { doc: "fsr9-p-ctl-true/d1", fields: a1 },
    { doc: "fsr9-p-ctl-false/d1", fields: a1 },
    { doc: "fsr9-p-get/d1", fields: { ...a1, ...blocked } },
    { doc: "fsr9-p-get-absent/d1", fields: a1 },
    { doc: "fsr9-p-keys/d1", fields: { ...a1, ...blocked } },
    { doc: "fsr9-p-keys-absent/d1", fields: a1 },
    { doc: "fsr9-p-meta/d1", fields: { meta: { mapValue: { fields: { ...a1, ...blocked } } } } },
    { doc: "fsr9-p-meta-absent/d1", fields: { meta: { mapValue: { fields: a1 } } } },
    { doc: "fsr9-p-only-plain/d1", fields: a1 },
    { doc: "fsr9-p-only-extra/d1", fields: { ...a1, ...extra } },
    { doc: "fsr9-p-only-b/d1", fields: a1 },
    { doc: "fsr9-p-size-plain/d1", fields: a1 },
    { doc: "fsr9-p-size-extra/d1", fields: { ...a1, ...extra } },
    { doc: "fsr9-p-size-zero/d1", fields: a1 },
    { doc: "fsr9-p-own/mine", fields: { owner: { stringValue: "UID(anon)" }, ...n1 } },
    { doc: "fsr9-p-own/mine2", fields: { owner: { stringValue: "UID(anon)" }, ...n1 } },
    { doc: "fsr9-p-own/foreign", fields: { owner: { stringValue: "other-owner" }, ...n1 } },
  ]);
  assert.deepEqual(program("fn").seed, [
    { doc: "fsr9-p-fn-resource/d1", fields: a1 },
    { doc: "fsr9-p-fn-null/d1", fields: a1 },
    { doc: "fsr9-p-fn-arg/d1", fields: a1 },
  ]);
});

test("every ruleset is version 2 with balanced braces, and every row and seed names a collection that has a rule", () => {
  for (const p of SHAPES_TWO_PROGRAMS) {
    const source = rulesetSource(p.ruleset);
    assert.ok(source.startsWith("rules_version = '2';\n"), p.ruleset);
    assert.equal(source.split("{").length, source.split("}").length, `${p.ruleset}: braces`);
    const collections = [
      ...rowsOf(p).map((s) => s.body.structuredQuery.from[0].collectionId),
      ...p.seed.map((d) => collectionOf(d.doc)),
    ];
    for (const collection of collections)
      assert.ok(source.includes(`match /${collection}/{id} {`), `${p.id}: ${collection}`);
  }
});

test("every row is a REST list query made as the one anonymous principal", () => {
  for (const p of SHAPES_TWO_PROGRAMS)
    for (const s of rowsOf(p)) {
      assert.equal(s.transport, undefined, `${s.id}: REST only`);
      assert.equal(s.rpc, "runQuery");
      assert.equal(s.as, "anon", s.id);
    }
});

test("the corpus names no sandbox, number, address or absolute path", () => {
  const text =
    JSON.stringify(SHAPES_TWO_PROGRAMS) + SHAPES_TWO_RULESET_IDS.map(rulesetSource).join("\n");
  assert.ok(!text.includes(SANDBOX_PROJECT));
  assert.ok(!/@[\w-]+\./.test(text));
  assert.ok(!/\/Users\/|\/home\//.test(text));
  assert.ok(!/\d{9,}/.test(text));
});

test("program digests differ per program and from the other families, and the first family is untouched", () => {
  const digests = SHAPES_TWO_PROGRAMS.map((p) => corpusDigest([p]));
  assert.equal(new Set(digests).size, SHAPES_TWO_PROGRAMS.length);
  assert.notEqual(corpusDigest(SHAPES_TWO_PROGRAMS), corpusDigest(SHAPES_PROGRAMS));
  assert.notEqual(corpusDigest(SHAPES_TWO_PROGRAMS), corpusDigest(DIFFS_PROGRAMS));
  assert.equal(
    corpusDigest(SHAPES_PROGRAMS),
    "1d441b962c393d9097a70c3d1e581f4a5a2cf98590fd08d5c21e68165d63558b",
  );
});

// ---- selection ------------------------------------------------------------------------------

test("FS3_CORPUS=shapes2 picks the family and names its own ledger task; one run never mixes", () => {
  assert.equal(corpusFor({ FS3_CORPUS: "shapes2" }), SHAPES_TWO_PROGRAMS);
  assert.equal(selectPrograms(undefined, { FS3_CORPUS: "shapes2" }).length, 2);
  assert.equal(
    selectPrograms(undefined, { FS3_CORPUS: "shapes2", FS3_PROGRAMS: "fs-rules-v1/shapes-two/fn" })
      .length,
    1,
  );
  assert.equal(TASK_ID_SHAPES_TWO, "FS-RULES-SHAPES-TWO");
  assert.notEqual(TASK_ID_SHAPES_TWO, TASK_ID_SHAPES);
  assert.equal(taskIdFor(SHAPES_TWO_PROGRAMS), TASK_ID_SHAPES_TWO);
  assert.equal(taskIdFor(SHAPES_PROGRAMS), TASK_ID_SHAPES);
  assert.throws(() => taskIdFor([...SHAPES_PROGRAMS, ...SHAPES_TWO_PROGRAMS]), /mixes/);
  assert.throws(() => corpusFor({ FS3_CORPUS: "shapes3" }), /FS3_CORPUS/);
  assert.throws(
    () =>
      selectPrograms(undefined, { FS3_CORPUS: "shapes", FS3_PROGRAMS: "fs-rules-v1/shapes-two" }),
    /no program matches/,
  );
});

// ---- the recorder over the fake production --------------------------------------------------

test("a recording leaves the sandbox as it found it, with the request counts the packet states", async () => {
  const { out, world } = await record();
  assert.equal(out.closureReady, true);
  assert.deepEqual(out.cleanupErrors, []);
  assert.deepEqual(out.failures, []);
  assert.deepEqual(out.unknowns, []);
  assert.equal(out.requests, 24);
  assert.equal(out.harnessRequests, 335);
  assert.equal(out.publications.length, 2);
  assert.equal(world.releases.size, 0);
  assert.equal(world.rulesets.size, 0);
  assert.equal(world.documents.size, 0);
  assert.equal(world.accounts.size, 0);
  for (const p of SHAPES_TWO_PROGRAMS) {
    assert.deepEqual(out.results[p.id].steps.publishes, { compiled: true }, p.id);
    for (const s of rowsOf(p)) {
      const recorded = out.results[p.id].steps[s.id];
      assert.deepEqual(Object.keys(recorded).toSorted(), ["body", "status"], `${p.id}#${s.id}`);
      assert.equal(recorded.status, 200, `${p.id}#${s.id}`);
    }
  }
});

test("the seed and the query bodies carry the principal's uid, and the recording masks it everywhere", async () => {
  const { out, world } = await record();
  const [uid] = [...world.signedUp];
  assert.equal(world.seeded.get("fsr9-p-own/mine").owner.stringValue, uid);
  assert.equal(world.seeded.get("fsr9-p-own/mine2").owner.stringValue, uid);
  assert.equal(world.seeded.get("fsr9-p-own/foreign").owner.stringValue, "other-owner");
  const sent = world.log.filter(
    (c) =>
      c.url.includes(":runQuery") &&
      c.headers.authorization?.startsWith("Bearer ") &&
      !c.headers.authorization.startsWith("Bearer ya29."),
  );
  assert.equal(sent.length, 24);
  const offsetQuery = sent.filter((c) => c.body.structuredQuery.offset === 1);
  assert.equal(offsetQuery.length, 3, "the three offset rows send offset 1");
  assert.ok(JSON.stringify(offsetQuery).includes(`"stringValue":"${uid}"`));
  assert.ok(
    JSON.stringify(offsetQuery).includes("/documents/fsr9-p-own/mine"),
    "the name is expanded",
  );
  assert.ok(!JSON.stringify(sent).includes("UID("), "no placeholder is sent");
  assert.ok(!JSON.stringify(sent).includes("{docs}"), "every document name is expanded");
  const recorded = JSON.stringify(out.results);
  assert.ok(!recorded.includes(uid), "the uid never reaches a recording");
  assert.ok(recorded.includes("<uid:anon>"));
});

test("a refused list reaches its row, and a ruleset production refuses takes its own rows with it", async () => {
  const { out } = await record({
    scenario: { diffs: ({ collection }) => collection !== "fsr9-p-ctl-false" },
  });
  assert.equal(out.results["fs-rules-v1/shapes-two/queries"].steps["ctl-deny"].status, 403);
  assert.equal(out.results["fs-rules-v1/shapes-two/queries"].steps["ctl-allow"].status, 200);
  const refused = await record({
    scenario: { refuseSource: (source) => source.includes("function f(r)") },
  });
  const fn = refused.out.results["fs-rules-v1/shapes-two/fn"].steps;
  assert.deepEqual(fn.publishes, { compiled: false });
  assert.deepEqual(fn["fn-resource"], {
    status: -1,
    unresolved: "ruleset shapes-two-fn did not compile",
  });
  assert.equal(
    refused.out.results["fs-rules-v1/shapes-two/queries"].steps.publishes.compiled,
    true,
  );
  assert.equal(refused.out.closureReady, true);
});

test("an unknown answer to the release delete keeps the run from closing", async () => {
  const { world, fetchImpl, grpc } = createWorld();
  const clock = createClock();
  world.onCall = (method, url) =>
    method === "DELETE" && url.includes("/releases/") ? { status: 503 } : undefined;
  const ctx = createContext({ run: "1790000000201", startedMs: clock.now(), target: PRODUCTION });
  const programs = SHAPES_TWO_PROGRAMS.slice(1);
  await assert.rejects(
    runCorpus(
      { programs, principals: PRINCIPALS },
      ctx,
      { fetchImpl, grpc, sleep: clock.sleep, now: clock.now },
      ceilings(programs),
    ),
    (error) => {
      assert.equal(error.partial.closureReady, false);
      assert.deepEqual(error.partial.unknowns, [{ call: "delete release", answer: "HTTP 503" }]);
      return true;
    },
  );
});

test("the fixture keeps the other corpora and adds the two programs", async () => {
  const { out } = await record();
  const fixture = JSON.parse(
    fixtureText({
      programs: SHAPES_TWO_PROGRAMS,
      recordings: [out, out],
      meta: { harness: "h", startedAt: "t", sha: "s" },
      existing: {
        version: 1,
        recordedAgainst: {},
        programs: { "fs-rules-v1/shapes/queries": { keep: true } },
      },
    }),
  );
  assert.deepEqual(fixture.programs["fs-rules-v1/shapes/queries"], { keep: true });
  assert.equal(Object.keys(fixture.programs).length, 3);
  const rows = shapesTwoReport(fixture);
  assert.equal(rows.length, 26);
  assert.ok(rows.every((r) => ["allowed", "compiled"].includes(r.answer)));
});

// ---- the report ------------------------------------------------------------------------------

test("the official and fireemu answers cover every row, and are answers", () => {
  const rows = SHAPES_TWO_PROGRAMS.flatMap((p) =>
    p.steps.map((s) => `${p.id.split("/").at(-1)}#${s.id}`),
  );
  assert.equal(rows.length, 26);
  assert.deepEqual(Object.keys(OFFICIAL).toSorted(), rows.toSorted());
  assert.deepEqual(Object.keys(FIXES).toSorted(), rows.toSorted());
  for (const table of [OFFICIAL, FIXES])
    for (const answer of Object.values(table))
      assert.ok(["allowed", "denied", "compiled"].includes(answer), answer);
});

test("the measured tables: the official emulator allows every list the controls allow and the fixed fireemu refuses six of them", () => {
  const allowedByOfficial = Object.entries(OFFICIAL)
    .filter(([, answer]) => answer === "allowed")
    .map(([row]) => row);
  assert.equal(allowedByOfficial.length, 16);
  assert.deepEqual(
    Object.keys(OFFICIAL).filter((row) => OFFICIAL[row] !== FIXES[row]),
    [
      "queries#only-plain",
      "queries#only-extra",
      "queries#size-plain",
      "queries#size-extra",
      "queries#name-offset",
      "fn#fn-resource",
    ],
  );
  // The pinned refused controls are refused by both, the shared controls behave as named.
  for (const row of [
    "queries#ctl-deny",
    "queries#get-deny",
    "queries#keys-deny",
    "queries#meta-deny",
    "queries#only-b-deny",
    "queries#size-zero-deny",
    "queries#foreign-offset",
    "fn#fn-null-deny",
  ])
    assert.deepEqual([OFFICIAL[row], FIXES[row]], ["denied", "denied"], row);
  for (const row of [
    "queries#ctl-allow",
    "queries#get-allow",
    "queries#owner-offset",
    "fn#fn-arg-allow",
  ])
    assert.deepEqual([OFFICIAL[row], FIXES[row]], ["allowed", "allowed"], row);
});

test("the report compares each answer with the official emulator and with fireemu", () => {
  const allowed = { status: 200, body: [{ readTime: "t" }] };
  const denied = {
    status: 403,
    body: [
      {
        error: {
          code: 403,
          message: "Missing or insufficient permissions.",
          status: "PERMISSION_DENIED",
        },
      },
    ],
  };
  const fixture = {
    programs: {
      "fs-rules-v1/shapes-two/queries": {
        steps: {
          publishes: { compiled: true },
          "ctl-allow": allowed,
          "ctl-deny": denied,
          "get-stored": denied,
        },
      },
    },
  };
  const rows = Object.fromEntries(
    shapesTwoReport(fixture, {
      official: { "queries#ctl-allow": "allowed", "queries#ctl-deny": "allowed" },
      fixes: { "queries#ctl-allow": "denied", "queries#ctl-deny": "denied" },
    }).map((r) => [r.row, r]),
  );
  assert.equal(rows["queries#publishes"].verdict, "no-claim");
  assert.equal(rows["queries#ctl-allow"].answer, "allowed");
  assert.equal(rows["queries#ctl-allow"].verdict, "agrees");
  assert.equal(rows["queries#ctl-allow"].fixesVerdict, "differs");
  assert.equal(rows["queries#ctl-deny"].answer, "denied");
  assert.equal(rows["queries#ctl-deny"].verdict, "differs");
  assert.equal(rows["queries#ctl-deny"].fixesVerdict, "agrees");
  assert.equal(rows["queries#get-stored"].verdict, "no-claim");
  assert.equal(rows["queries#get-absent"].answer, "missing");
  assert.equal(rows["queries#get-absent"].verdict, "unknown");
  assert.match(
    shapesReportLine(rows["queries#ctl-deny"]),
    /^differs {8}agrees {9}queries#ctl-deny +denied \(official: allowed, fixes: denied\)$/,
  );
});

test("only bare recorded answers count: an unsettled publication, a transport failure or an extra key is unknown", () => {
  const allowed = { status: 200, body: [{ readTime: "t" }] };
  const fixture = {
    programs: {
      "fs-rules-v1/shapes-two/fn": {
        steps: {
          publishes: { compiled: true },
          "fn-resource": { ...allowed, publication: "unsettled" },
          "fn-null-deny": { transport: "reset" },
          "fn-arg-allow": { ...allowed, extra: 1 },
        },
      },
    },
  };
  const rows = Object.fromEntries(shapesTwoReport(fixture).map((r) => [r.row, r]));
  assert.equal(rows["fn#fn-resource"].answer, "unknown");
  assert.equal(rows["fn#fn-null-deny"].answer, "unknown");
  assert.equal(rows["fn#fn-arg-allow"].answer, "unknown");
  assert.equal(rows["fn#publishes"].answer, "compiled");
  const differing = {
    programs: {
      "fs-rules-v1/shapes-two/fn": {
        steps: { publishes: { compiled: true }, "fn-resource": allowed },
        second: { "fn-resource": { status: 403, body: [] } },
      },
    },
  };
  const rowsDiffering = Object.fromEntries(shapesTwoReport(differing).map((r) => [r.row, r]));
  assert.equal(rowsDiffering["fn#fn-resource"].answer, "unknown");
  assert.equal(rowsDiffering["fn#fn-resource"].detail, "the two recordings differ");
});

// ---- properties (seeded, deterministic: a failing round is reproduced by its seed) -----------

function generator(seed) {
  let state = seed >>> 0;
  const next = () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const int = (n) => Math.floor(next() * n);
  return { int, pick: (items) => items[int(items.length)] };
}

const ALLOWED = { status: 200, body: [{ readTime: "t" }] };
const DENIED = {
  status: 403,
  body: [
    {
      error: {
        code: 403,
        message: "Missing or insufficient permissions.",
        status: "PERMISSION_DENIED",
      },
    },
  ],
};
const ROWS = SHAPES_TWO_PROGRAMS.flatMap((p) =>
  p.steps
    .filter((s) => !s.publish)
    .map((s) => ({ program: p.id, row: `${p.id.split("/").at(-1)}#${s.id}`, id: s.id })),
);

function fixtureOf(answers) {
  const programs = {};
  for (const { program: id, id: stepId } of ROWS) {
    programs[id] ??= { steps: { publishes: { compiled: true } } };
    programs[id].steps[stepId] = answers[`${id.split("/").at(-1)}#${stepId}`];
  }
  return { programs };
}

test("property: a verdict agrees exactly when the answer equals the claim, for any answers and claims", () => {
  for (let round = 0; round < 300; round += 1) {
    const g = generator(round + 1);
    const answers = {};
    const official = {};
    const fixes = {};
    for (const { row } of ROWS) {
      answers[row] = g.pick([ALLOWED, DENIED]);
      if (g.int(4) > 0) official[row] = g.pick(["allowed", "denied"]);
      if (g.int(4) > 0) fixes[row] = g.pick(["allowed", "denied"]);
    }
    const report = shapesTwoReport(fixtureOf(answers), { official, fixes });
    for (const r of report.filter((x) => x.row.includes("#") && !x.row.endsWith("#publishes"))) {
      const answer = answers[r.row] === ALLOWED ? "allowed" : "denied";
      assert.equal(r.answer, answer, `seed ${round + 1} ${r.row}`);
      const verdict = (claim) =>
        claim === undefined ? "no-claim" : claim === answer ? "agrees" : "differs";
      assert.equal(r.verdict, verdict(official[r.row]), `seed ${round + 1} ${r.row}`);
      assert.equal(r.fixesVerdict, verdict(fixes[r.row]), `seed ${round + 1} ${r.row}`);
    }
  }
});

test("property: an answer with any extra key, status or unreadable body is never an allow or a deny", () => {
  const extras = ["publication", "transport", "headers", "attempts", "x"];
  const statuses = [0, 100, 199, 204, 301, 302, 400, 401, 404, 409, 429, 500, 503];
  for (let round = 0; round < 300; round += 1) {
    const g = generator(round + 1000);
    const { row } = g.pick(ROWS);
    const base = g.pick([ALLOWED, DENIED]);
    const broken = g.pick([
      { ...base, [g.pick(extras)]: g.pick([1, "unsettled", true, null]) },
      { status: g.pick(statuses), body: base.body },
      { status: base.status },
      { status: base.status, body: "not json" },
      { status: base.status, body: [] },
      {},
    ]);
    const answers = Object.fromEntries(ROWS.map((r) => [r.row, ALLOWED]));
    answers[row] = broken;
    const reported = shapesTwoReport(fixtureOf(answers)).find((r) => r.row === row);
    assert.notEqual(reported.answer, "allowed", `seed ${round + 1000} ${JSON.stringify(broken)}`);
    assert.notEqual(reported.answer, "denied", `seed ${round + 1000} ${JSON.stringify(broken)}`);
  }
});
