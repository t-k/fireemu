// FS-RULES shapes: the corpus of Rules shapes that the fixes after the differences recording
// decided without a production row, the way it is selected and recorded, and the classification
// of what production answers. The facts the fake production uses are the test's choice, not
// claims about production. The answers the classifier accepts are the recorded shapes of the
// differences judge (diffs.mjs RECORDED_SHAPES, each citing its fixture row).

import assert from "node:assert/strict";
import { test } from "node:test";

import { createContext, SANDBOX_PROJECT } from "./fs-rules/harness.mjs";
import {
  BAD_PATH_PROGRAMS,
  corpusDigest,
  countRequests,
  DIFFS_PROGRAMS,
  PRINCIPALS,
  PROGRAMS,
  REQUEST_CAP,
  rulesetSource,
  SHAPES_PROGRAMS,
  SHAPES_RULESET_IDS,
  validateCorpus,
} from "./fs-rules-v1/corpus.mjs";
import {
  classifyShapesAnswer,
  FIXES,
  judgeShapesPublication,
  OFFICIAL,
  shapesReport,
} from "./fs-rules-v1/shapes.mjs";
import {
  ceilings,
  corpusFor,
  fixtureText,
  selectPrograms,
  TASK_ID_DIFFS,
  TASK_ID_SHAPES,
  taskIdFor,
} from "./fs-rules-v1/judge.mjs";
import { runCorpus } from "./fs-rules-v1/session.mjs";
import { createClock, createWorld } from "./fs-rules-v1/test-world.mjs";

const PRODUCTION = {
  kind: "production",
  adminToken: "ya29.owner-test-token",
  apiKey: "AIzaShapesTestKeyNotReal",
  quotaProject: SANDBOX_PROJECT,
  projectNumber: "555500000002",
};

async function record({ scenario, programs = SHAPES_PROGRAMS } = {}) {
  const { world, fetchImpl, grpc } = createWorld(scenario);
  const clock = createClock();
  const ctx = createContext({ run: "1790000000100", startedMs: clock.now(), target: PRODUCTION });
  const out = await runCorpus(
    { programs, principals: PRINCIPALS },
    ctx,
    { fetchImpl, grpc, sleep: clock.sleep, now: clock.now },
    ceilings(programs),
  );
  return { out, world };
}

const rowsOf = (program) => program.steps.filter((step) => !step.publish);
const program = (suffix) => SHAPES_PROGRAMS.find((p) => p.id === `fs-rules-v1/shapes/${suffix}`);
const step = (suffix, id) => program(suffix).steps.find((s) => s.id === id);
const rowNames = () =>
  SHAPES_PROGRAMS.flatMap((p) => p.steps.map((s) => `${p.id.split("/").at(-1)}#${s.id}`));
/** The collection a row or seed path addresses: the second-last segment. */
const collectionOf = (path) => path.split("/").at(-2);

// ---- the corpus -----------------------------------------------------------------------------

test("the corpus is five programs of 72 rows, valid and under the cap", () => {
  assert.deepEqual(
    SHAPES_PROGRAMS.map((p) => p.id),
    [
      "fs-rules-v1/shapes/queries",
      "fs-rules-v1/shapes/strings",
      "fs-rules-v1/shapes/regex",
      "fs-rules-v1/shapes/fn-shadow",
      "fs-rules-v1/shapes/fn-after",
    ],
  );
  assert.deepEqual(SHAPES_RULESET_IDS, [
    "shapes-queries",
    "shapes-strings",
    "shapes-regex",
    "shapes-fn-shadow",
    "shapes-fn-after",
  ]);
  assert.equal(validateCorpus(SHAPES_PROGRAMS), 72);
  assert.equal(countRequests(SHAPES_PROGRAMS), 72);
  assert.ok(72 <= REQUEST_CAP);
  assert.deepEqual(
    SHAPES_PROGRAMS.map((p) => rowsOf(p).length),
    [28, 21, 18, 3, 2],
  );
  for (const p of SHAPES_PROGRAMS) assert.deepEqual(p.steps[0], { id: "publishes", publish: true });
});

test("the string rows test ranges, lower() and upper() on a pair and on a lone-surrogate escape", () => {
  const source = rulesetSource("shapes-strings");
  for (const [id, expr] of [
    ["rng-ctl-true", '"abc"[0:2] == "ab"'],
    ["rng-ctl-false", '"abc"[0:2] == "abc"'],
    ["rng-02", '"é\u{1F525}x"[0:2] == "é\u{1F525}"'],
    ["rng-03", '"é\u{1F525}x"[0:3] == "é\u{1F525}"'],
    ["rng-13", '"é\u{1F525}x"[1:3] == "\u{1F525}"'],
    ["rng-34", '"é\u{1F525}x"[3:4] == "x"'],
    ["rng-12-size", '"é\u{1F525}x"[1:2].size() == 1'],
    ["rng-hi", '"a\\ud83dz"[1:2] == "\\ud83d"'],
    ["low-ctl-true", '"ABC".lower() == "abc"'],
    ["low-ctl-false", '"ABC".lower() == "ABC"'],
    ["low-fire", '"A\u{1F525}X".lower() == "a\u{1F525}x"'],
    ["low-fire-size", '"A\u{1F525}X".lower().size() == 4'],
    ["low-hi", '"A\\ud83d".lower() == "a\\ud83d"'],
    ["low-hi-size", '"A\\ud83d".lower().size() == 2'],
    ["up-ctl-true", '"abc".upper() == "ABC"'],
    ["up-ctl-false", '"abc".upper() == "abc"'],
    ["up-fire", '"a\u{1F525}x".upper() == "A\u{1F525}X"'],
    ["up-hi", '"a\\ud83d".upper() == "A\\ud83d"'],
    ["hi-size", '"\\ud83d".size() == 1'],
    ["hi-self", '"\\ud83d" == "\\ud83d"'],
    ["hi-fffd", '"\\ud83d" == "\\ufffd"'],
  ])
    assert.ok(source.includes(`match /fsr9-t-${id}/{id} {\n      allow get: if ${expr};`), id);
  assert.deepEqual(
    rowsOf(program("strings")).map((s) => s.id),
    [
      "rng-ctl-true",
      "rng-ctl-false",
      "rng-02",
      "rng-03",
      "rng-13",
      "rng-34",
      "rng-12-size",
      "rng-hi",
      "low-ctl-true",
      "low-ctl-false",
      "low-fire",
      "low-fire-size",
      "low-hi",
      "low-hi-size",
      "up-ctl-true",
      "up-ctl-false",
      "up-fire",
      "up-hi",
      "hi-size",
      "hi-self",
      "hi-fffd",
    ],
  );
});

test("the regex rows test split(), replace() and matches() on a pair and on a lone-surrogate escape", () => {
  const source = rulesetSource("shapes-regex");
  const rows = [
    ["split-ctl-true", '"a,b".split(",").size() == 2'],
    ["split-ctl-false", '"a,b".split(",").size() == 3'],
    ["split-fire", '"a\u{1F525}b".split("\u{1F525}").size() == 2'],
    ["split-fire-by-hi", '"a\u{1F525}b".split("\\ud83d").size() == 2'],
    ["split-fire-by-hi-1", '"a\u{1F525}b".split("\\ud83d").size() == 1'],
    ["split-hi", '"a\\ud83dz".split("\\ud83d").size() == 2'],
    ["rep-ctl-true", '"abc".replace("b", "x") == "axc"'],
    ["rep-ctl-false", '"abc".replace("b", "x") == "abc"'],
    ["rep-fire", '"a\u{1F525}b".replace("\u{1F525}", "x") == "axb"'],
    ["rep-dot-fire", '"\u{1F525}".replace(".", "x") == "x"'],
    ["rep-dot-fire-xx", '"\u{1F525}".replace(".", "x") == "xx"'],
    ["rep-hi", '"a\\ud83dz".replace("\\ud83d", "x") == "axz"'],
    ["m-ctl-true", '"abc".matches("a.c")'],
    ["m-ctl-false", '"abc".matches("a.")'],
    ["m-dot-fire", '"\u{1F525}".matches(".")'],
    ["m-dotdot-fire", '"\u{1F525}".matches("..")'],
    ["m-hi-dot", '"\\ud83d".matches(".")'],
    ["m-hi-lit", '"a\\ud83d".matches("a\\ud83d")'],
  ];
  for (const [id, expr] of rows)
    assert.ok(source.includes(`match /fsr9-t-${id}/{id} {\n      allow get: if ${expr};`), id);
  assert.deepEqual(
    rowsOf(program("regex")).map((s) => s.id),
    rows.map(([id]) => id),
  );
});

test("no escape in a rule source is followed by a hex digit", () => {
  for (const id of SHAPES_RULESET_IDS)
    assert.ok(!/\\u[0-9a-f]{4}[0-9a-fA-F]/.test(rulesetSource(id)), id);
});

test("the two function rulesets are exactly these sources", () => {
  assert.equal(
    rulesetSource("shapes-fn-shadow"),
    "rules_version = '2';\nfunction pick() {\n  return false;\n}\nfunction topOnly() {\n  return true;\n}\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    match /fsr-marker/{label} {\n      allow write: if label == 'shapes-fn-shadow-41dbbce49ec4';\n    }\n\n    function pick() {\n      return true;\n    }\n    function innerOnly() {\n      return false;\n    }\n    match /fsr9-fs-pick/{id} {\n      allow get: if pick();\n    }\n    match /fsr9-fs-top-only/{id} {\n      allow get: if topOnly();\n    }\n    match /fsr9-fs-inner-only/{id} {\n      allow get: if innerOnly();\n    }\n  }\n}\n",
  );
  assert.equal(
    rulesetSource("shapes-fn-after"),
    "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    match /fsr-marker/{label} {\n      allow write: if label == 'shapes-fn-after-1d9f31543ab9';\n    }\n\n    match /fsr9-fa-true/{id} {\n      allow get: if afterTrue();\n    }\n    match /fsr9-fa-false/{id} {\n      allow get: if afterFalse();\n    }\n  }\n}\nfunction afterTrue() {\n  return true;\n}\nfunction afterFalse() {\n  return false;\n}\n",
  );
});

test("a ruleset without a postamble keeps its source byte for byte", () => {
  // The differences family's sources (corpus digest 9c9c2837…) are unchanged by the postamble.
  assert.equal(
    corpusDigest(DIFFS_PROGRAMS),
    "9c9c2837ca252fcffa5cafa23d97ec324682941803b5629c25be02b1a82b2528",
  );
  assert.ok(rulesetSource("diffs-fn-top").endsWith("  }\n}\n"));
});

test("the query rules are exactly these", () => {
  const source = rulesetSource("shapes-queries");
  for (const [match, condition] of [
    ["fsr9-q-owner", "resource.data.owner == request.auth.uid"],
    ["fsr9-q-nested-neg", '!("blocked" in resource.data.meta)'],
    ["fsr9-q-nested-pos", '"a" in resource.data.meta'],
    ["fsr9-q-keys-neg", '!resource.data.keys().hasAny(["blocked"])'],
    ["fsr9-q-keys-pos", 'resource.data.keys().hasAll(["a"])'],
    ["fsr9-q-size", "resource.data.size() > 0"],
    ["fsr9-q-get-neg", 'resource.data.get("blocked", false) == false'],
    ["fsr9-q-get-pos", 'resource.data.get("a", 0) == 1'],
    ["{path=**}/fsr9-q-cg", '!("blocked" in resource.data)'],
    ["{path=**}/fsr9-q-cg-has", '"blocked" in resource.data'],
  ])
    assert.ok(
      source.includes(`match /${match}/{id} {\n      allow list: if ${condition};\n    }`),
      match,
    );
  assert.equal(source.split("allow list").length - 1, 10);
});

const owner = {
  fieldFilter: { field: { fieldPath: "owner" }, op: "EQUAL", value: { stringValue: "UID(anon)" } },
};
const name = (doc) => ({
  fieldFilter: {
    field: { fieldPath: "__name__" },
    op: "EQUAL",
    value: { referenceValue: `{docs}/fsr9-q-owner/${doc}` },
  },
});
const and = (...filters) => ({ compositeFilter: { op: "AND", filters } });
const or = (...filters) => ({ compositeFilter: { op: "OR", filters } });
const intFilter = (fieldPath, op, n) => ({
  fieldFilter: { field: { fieldPath }, op, value: { integerValue: n } },
});

test("the named-document rows send the names, branches, limit and cursor the shapes name", () => {
  const query = (id) => step("queries", id).body.structuredQuery;
  const from = [{ collectionId: "fsr9-q-owner" }];
  assert.deepEqual(query("owner-alone"), { from, where: owner });
  assert.deepEqual(query("name-foreign-alone"), { from, where: name("foreign") });
  assert.deepEqual(query("name-own-alone"), { from, where: name("mine") });
  assert.deepEqual(query("two-names-own"), { from, where: and(name("mine"), name("mine2")) });
  assert.deepEqual(query("two-names-mixed"), { from, where: and(name("mine"), name("foreign")) });
  assert.deepEqual(query("or-named-unnamed"), { from, where: or(name("mine"), owner) });
  assert.deepEqual(query("or-foreign-unnamed"), { from, where: or(name("foreign"), owner) });
  assert.deepEqual(query("own-plus-unproven"), {
    from,
    where: and(name("mine"), intFilter("n", "EQUAL", "1")),
  });
  const nameIs = (op) => ({
    fieldFilter: {
      field: { fieldPath: "__name__" },
      op,
      value: { referenceValue: "{docs}/fsr9-q-owner/mine" },
    },
  });
  assert.deepEqual(query("name-own-range"), {
    from,
    where: and(nameIs("GREATER_THAN_OR_EQUAL"), nameIs("LESS_THAN_OR_EQUAL")),
  });
  assert.deepEqual(query("name-own-limit"), { from, where: name("mine"), limit: 1 });
  assert.deepEqual(query("name-own-cursor"), {
    from,
    where: name("mine"),
    orderBy: [{ field: { fieldPath: "__name__" }, direction: "ASCENDING" }],
    startAt: { values: [{ referenceValue: "{docs}/fsr9-q-owner/mine" }], before: true },
  });
});

test("the query-resource rows query each collection without and with a filter, and the group rows", () => {
  const rows = rowsOf(program("queries")).slice(11);
  assert.deepEqual(
    rows.map((s) => [s.id, s.body.structuredQuery]),
    [
      ["nested-neg-nofilter", { from: [{ collectionId: "fsr9-q-nested-neg" }] }],
      [
        "nested-neg-filtered",
        {
          from: [{ collectionId: "fsr9-q-nested-neg" }],
          where: intFilter("meta.a", "EQUAL", "1"),
        },
      ],
      ["nested-pos-nofilter", { from: [{ collectionId: "fsr9-q-nested-pos" }] }],
      [
        "nested-pos-filtered",
        {
          from: [{ collectionId: "fsr9-q-nested-pos" }],
          where: intFilter("meta.a", "EQUAL", "1"),
        },
      ],
      ["keys-neg-nofilter", { from: [{ collectionId: "fsr9-q-keys-neg" }] }],
      [
        "keys-neg-filtered",
        { from: [{ collectionId: "fsr9-q-keys-neg" }], where: intFilter("a", "EQUAL", "1") },
      ],
      ["keys-pos-nofilter", { from: [{ collectionId: "fsr9-q-keys-pos" }] }],
      [
        "keys-pos-filtered",
        { from: [{ collectionId: "fsr9-q-keys-pos" }], where: intFilter("a", "EQUAL", "1") },
      ],
      ["size-nofilter", { from: [{ collectionId: "fsr9-q-size" }] }],
      [
        "size-filtered",
        { from: [{ collectionId: "fsr9-q-size" }], where: intFilter("a", "EQUAL", "1") },
      ],
      ["get-neg-nofilter", { from: [{ collectionId: "fsr9-q-get-neg" }] }],
      [
        "get-neg-filtered",
        { from: [{ collectionId: "fsr9-q-get-neg" }], where: intFilter("a", "EQUAL", "1") },
      ],
      ["get-pos-nofilter", { from: [{ collectionId: "fsr9-q-get-pos" }] }],
      [
        "get-pos-filtered",
        { from: [{ collectionId: "fsr9-q-get-pos" }], where: intFilter("a", "EQUAL", "1") },
      ],
      ["cg-blocked-group", { from: [{ collectionId: "fsr9-q-cg", allDescendants: true }] }],
      ["cg-has-group", { from: [{ collectionId: "fsr9-q-cg-has", allDescendants: true }] }],
      ["cg-blocked-single", { from: [{ collectionId: "fsr9-q-cg" }] }],
    ],
  );
});

test("the query seed is exactly these documents, and the other programs seed nothing", () => {
  const n1 = { n: { integerValue: "1" } };
  const a1 = { a: { integerValue: "1" } };
  const meta = { meta: { mapValue: { fields: a1 } } };
  assert.deepEqual(program("queries").seed, [
    { doc: "fsr9-q-owner/mine", fields: { owner: { stringValue: "UID(anon)" }, ...n1 } },
    { doc: "fsr9-q-owner/mine2", fields: { owner: { stringValue: "UID(anon)" }, ...n1 } },
    { doc: "fsr9-q-owner/foreign", fields: { owner: { stringValue: "other-owner" }, ...n1 } },
    { doc: "fsr9-q-nested-neg/d1", fields: meta },
    { doc: "fsr9-q-nested-pos/d1", fields: meta },
    { doc: "fsr9-q-keys-neg/d1", fields: a1 },
    { doc: "fsr9-q-keys-pos/d1", fields: a1 },
    { doc: "fsr9-q-size/d1", fields: a1 },
    { doc: "fsr9-q-get-neg/d1", fields: a1 },
    { doc: "fsr9-q-get-pos/d1", fields: a1 },
    { doc: "fsr9-q-cg/c1", fields: n1 },
    { doc: "fsr9-q-x/y/fsr9-q-cg/c2", fields: n1 },
    { doc: "fsr9-q-cg-has/c1", fields: n1 },
  ]);
  for (const other of SHAPES_PROGRAMS.slice(1)) assert.deepEqual(other.seed, [], other.id);
});

test("every ruleset is version 2 with balanced braces, and every row and seed names a collection that has a rule", () => {
  for (const p of SHAPES_PROGRAMS) {
    const source = rulesetSource(p.ruleset);
    assert.ok(source.startsWith("rules_version = '2';\n"), p.ruleset);
    assert.equal(source.split("{").length, source.split("}").length, `${p.ruleset}: braces`);
    const collections = [
      ...rowsOf(p).map((s) => s.body?.structuredQuery.from[0].collectionId ?? collectionOf(s.doc)),
      ...p.seed.map((d) => collectionOf(d.doc)),
    ];
    for (const collection of collections)
      assert.ok(
        source.includes(`match /${collection}/{id} {`) ||
          source.includes(`match /{path=**}/${collection}/{id} {`),
        `${p.id}: ${collection}`,
      );
  }
});

test("every row is a REST read; queries are made as the one anonymous principal, gets with none", () => {
  for (const p of SHAPES_PROGRAMS)
    for (const s of rowsOf(p)) {
      assert.equal(s.transport, undefined, `${s.id}: REST only`);
      assert.ok(["get", "runQuery"].includes(s.rpc));
      assert.equal(s.as, s.rpc === "runQuery" ? "anon" : "none", s.id);
    }
});

test("the corpus names no sandbox, number, address or absolute path", () => {
  const text = JSON.stringify(SHAPES_PROGRAMS) + SHAPES_RULESET_IDS.map(rulesetSource).join("\n");
  assert.ok(!text.includes(SANDBOX_PROJECT));
  assert.ok(!/@[\w-]+\./.test(text));
  assert.ok(!/\/Users\/|\/home\//.test(text));
  assert.ok(!/\d{9,}/.test(text));
});

test("program digests differ per program and from the other families", () => {
  const digests = SHAPES_PROGRAMS.map((p) => corpusDigest([p]));
  assert.equal(new Set(digests).size, SHAPES_PROGRAMS.length);
  assert.notEqual(corpusDigest(SHAPES_PROGRAMS), corpusDigest(DIFFS_PROGRAMS));
  assert.equal(validateCorpus(PROGRAMS), 76);
});

// ---- selection ------------------------------------------------------------------------------

test("FS3_CORPUS=shapes picks the family and names its own ledger task; one run never mixes", () => {
  assert.equal(corpusFor({ FS3_CORPUS: "shapes" }), SHAPES_PROGRAMS);
  assert.equal(selectPrograms(undefined, { FS3_CORPUS: "shapes" }).length, 5);
  assert.equal(TASK_ID_SHAPES, "FS-RULES-SHAPES");
  assert.equal(taskIdFor(SHAPES_PROGRAMS), TASK_ID_SHAPES);
  assert.equal(taskIdFor(DIFFS_PROGRAMS), TASK_ID_DIFFS);
  assert.throws(() => taskIdFor([...SHAPES_PROGRAMS, ...DIFFS_PROGRAMS]), /mixes/);
  assert.throws(() => taskIdFor([SHAPES_PROGRAMS[0], BAD_PATH_PROGRAMS[0]]), /mixes/);
  assert.throws(() => corpusFor({ FS3_CORPUS: "shape" }), /FS3_CORPUS/);
});

// ---- the recorder over the fake production --------------------------------------------------

test("a recording leaves the sandbox as it found it, with the request counts the packet states", async () => {
  const { out, world } = await record();
  assert.equal(out.closureReady, true);
  assert.deepEqual(out.cleanupErrors, []);
  assert.deepEqual(out.failures, []);
  assert.deepEqual(out.unknowns, []);
  assert.equal(out.requests, 72);
  assert.equal(out.harnessRequests, 847);
  assert.equal(out.publications.length, 5);
  assert.equal(world.releases.size, 0);
  assert.equal(world.rulesets.size, 0);
  assert.equal(world.documents.size, 0);
  assert.equal(world.accounts.size, 0);
  for (const p of SHAPES_PROGRAMS) {
    assert.deepEqual(out.results[p.id].steps.publishes, { compiled: true }, p.id);
    for (const s of rowsOf(p)) {
      const recorded = out.results[p.id].steps[s.id];
      assert.deepEqual(Object.keys(recorded).toSorted(), ["body", "status"], `${p.id}#${s.id}`);
      assert.equal(recorded.status, s.rpc === "get" ? 404 : 200, `${p.id}#${s.id}`);
    }
  }
});

test("the group rule of the fake answers a group query, and its refusal reaches the row", async () => {
  const { out } = await record({
    programs: SHAPES_PROGRAMS.slice(0, 1),
    scenario: { diffs: ({ collection }) => collection !== "fsr9-q-cg-has" },
  });
  const steps = out.results["fs-rules-v1/shapes/queries"].steps;
  assert.equal(steps["cg-blocked-group"].status, 200);
  assert.equal(steps["cg-blocked-group"].body.length, 2, "both group documents");
  assert.equal(steps["cg-has-group"].status, 403);
  assert.equal(steps["cg-blocked-single"].body.length, 1);
});

test("the seed and the query bodies carry the principal's uid, and the recording masks it everywhere", async () => {
  const { out, world } = await record({ programs: SHAPES_PROGRAMS.slice(0, 1) });
  const [uid] = [...world.signedUp];
  assert.equal(world.seeded.get("fsr9-q-owner/mine").owner.stringValue, uid);
  assert.equal(world.seeded.get("fsr9-q-owner/mine2").owner.stringValue, uid);
  assert.equal(world.seeded.get("fsr9-q-x/y/fsr9-q-cg/c2").n.integerValue, "1");
  const sent = world.log.filter(
    (c) =>
      c.url.includes(":runQuery") &&
      c.headers.authorization?.startsWith("Bearer ") &&
      !c.headers.authorization.startsWith("Bearer ya29."),
  );
  assert.equal(sent.length, 28);
  assert.ok(JSON.stringify(sent[0].body).includes(`"stringValue":"${uid}"`));
  assert.ok(!JSON.stringify(sent).includes("UID("), "no placeholder is sent");
  assert.ok(!JSON.stringify(sent).includes("{docs}"), "every document name is expanded");
  const recorded = JSON.stringify(out.results);
  assert.ok(!recorded.includes(uid), "the uid never reaches a recording");
  assert.ok(recorded.includes("<uid:anon>"));
});

test("a ruleset production refuses takes its own rows with it and nothing else", async () => {
  const { out } = await record({
    scenario: { refuseSource: (source) => source.includes("}\nfunction afterTrue") },
  });
  const after = out.results["fs-rules-v1/shapes/fn-after"].steps;
  assert.deepEqual(after.publishes, { compiled: false });
  assert.deepEqual(after["fn-after-true"], {
    status: -1,
    unresolved: "ruleset shapes-fn-after did not compile",
  });
  assert.equal(out.results["fs-rules-v1/shapes/fn-shadow"].steps.publishes.compiled, true);
  assert.equal(out.closureReady, true);
  const report = Object.fromEntries(
    shapesReport({
      programs: Object.fromEntries(Object.entries(out.results).map(([id, r]) => [id, r])),
    }).map((r) => [r.row, r]),
  );
  assert.equal(report["fn-after#publishes"].answer, "refused");
  assert.equal(report["fn-after#fn-after-true"].answer, "not-evaluated");
  assert.equal(report["fn-shadow#fn-shadow-pick"].answer, "allowed");
});

test("an unknown answer to the release delete keeps the run from closing", async () => {
  const { world, fetchImpl, grpc } = createWorld();
  const clock = createClock();
  world.onCall = (method, url) =>
    method === "DELETE" && url.includes("/releases/") ? { status: 503 } : undefined;
  const ctx = createContext({ run: "1790000000101", startedMs: clock.now(), target: PRODUCTION });
  const programs = SHAPES_PROGRAMS.slice(3, 4);
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

test("the fixture keeps the other corpora and adds the shapes programs", async () => {
  const { out } = await record();
  const existing = {
    version: 1,
    recordedAgainst: {},
    programs: { "fs-rules-v1/diffs/queries": { keep: true } },
  };
  const fixture = JSON.parse(
    fixtureText({
      programs: SHAPES_PROGRAMS,
      recordings: [out, out],
      meta: { harness: "h", startedAt: "t", sha: "s" },
      existing,
    }),
  );
  assert.deepEqual(fixture.programs["fs-rules-v1/diffs/queries"], { keep: true });
  assert.equal(Object.keys(fixture.programs).length, 6);
  // The fixture the recorder writes is what the report reads.
  const rows = shapesReport(fixture);
  assert.equal(rows.length, 77);
  assert.ok(rows.every((r) => ["allowed", "compiled"].includes(r.answer)));
});

// ---- the classifier: bare recorded shapes only -----------------------------------------------

const DENIED_BODY = {
  error: {
    code: 403,
    message: "Missing or insufficient permissions.",
    status: "PERMISSION_DENIED",
  },
};
const NOT_FOUND = {
  error: {
    code: 404,
    message:
      'Document "projects/demo-fs-rules/databases/(default)/documents/fsr9-t-x/x" not found.',
    status: "NOT_FOUND",
  },
};
const allow = { status: 404, body: NOT_FOUND };
const deny = { status: 403, body: DENIED_BODY };

test("bare recorded answers classify as the differences judge does", () => {
  assert.deepEqual(classifyShapesAnswer("get", allow), { kind: "allowed" });
  assert.deepEqual(classifyShapesAnswer("get", deny), { kind: "denied" });
  assert.deepEqual(classifyShapesAnswer("runQuery", { status: 200, body: [{ readTime: "t" }] }), {
    kind: "allowed",
    documents: 0,
  });
  assert.deepEqual(
    classifyShapesAnswer("runQuery", { status: 403, body: [{ error: DENIED_BODY.error }] }),
    { kind: "denied" },
  );
  assert.deepEqual(
    classifyShapesAnswer("get", { status: -1, unresolved: "ruleset x did not compile" }),
    { kind: "not-evaluated", detail: "ruleset x did not compile" },
  );
});

test("an answer with publication unsettled, a transport or any other key is unknown", () => {
  for (const recorded of [
    { ...allow, publication: "unsettled" },
    { ...deny, publication: "unsettled" },
    { status: 200, body: [{ readTime: "t" }], publication: "unsettled" },
    { ...deny, transport: "ETIMEDOUT" },
    { ...allow, extra: 1 },
    { status: 404 },
    { body: NOT_FOUND.body },
    { status: -1, unresolved: "x", publication: "unsettled" },
    { status: -1, unresolved: "x", body: {} },
    null,
    [],
  ]) {
    const { kind, detail } = classifyShapesAnswer("get", recorded);
    assert.equal(kind, "unknown", JSON.stringify(recorded));
    assert.ok(detail.length > 0);
  }
  assert.deepEqual(classifyShapesAnswer("get", undefined), {
    kind: "unknown",
    detail: "no recording",
  });
  assert.deepEqual(classifyShapesAnswer("get", { ...deny, publication: "unsettled" }), {
    kind: "unknown",
    detail: "the answer is not bare (body, publication, status)",
  });
});

test("a publication counts only as a bare compiled flag", () => {
  assert.deepEqual(judgeShapesPublication({ compiled: true }), { answer: "compiled" });
  assert.deepEqual(judgeShapesPublication({ compiled: false }), { answer: "refused" });
  for (const recorded of [
    { compiled: true, publication: "unsettled" },
    { compiled: "true" },
    { compiled: 1 },
    { status: 500, transport: "compile-status" },
    {},
    undefined,
    null,
  ])
    assert.equal(judgeShapesPublication(recorded).answer, "unknown", JSON.stringify(recorded));
  assert.deepEqual(judgeShapesPublication({ compiled: true, publication: "unsettled" }), {
    answer: "unknown",
    detail: "no bare publication answer",
  });
});

// ---- the report -----------------------------------------------------------------------------

const programRecord = (steps, extra = {}) => ({ steps, ...extra });

test("the official and fixed-fireemu answers cover every row, and are answers", () => {
  assert.deepEqual(Object.keys(OFFICIAL).toSorted(), rowNames().toSorted());
  assert.deepEqual(Object.keys(FIXES).toSorted(), rowNames().toSorted());
  for (const table of [OFFICIAL, FIXES])
    for (const [row, answer] of Object.entries(table))
      assert.ok(
        row.endsWith("#publishes")
          ? ["compiled", "refused"].includes(answer)
          : ["allowed", "denied", "not-evaluated"].includes(answer),
        `${row}: ${answer}`,
      );
});

test("the report compares each answer with the official emulator and with fixed fireemu", () => {
  const fixture = {
    programs: {
      "fs-rules-v1/shapes/fn-shadow": programRecord({
        publishes: { compiled: true },
        "fn-shadow-pick": OFFICIAL["fn-shadow#fn-shadow-pick"] === "allowed" ? deny : allow,
        "fn-shadow-top-only": allow,
        "fn-shadow-inner-only": { ...deny, publication: "unsettled" },
      }),
      "fs-rules-v1/shapes/fn-after": programRecord(
        {
          publishes: { compiled: false },
          "fn-after-true": { status: -1, unresolved: "ruleset shapes-fn-after did not compile" },
          "fn-after-false": { status: -1, unresolved: "ruleset shapes-fn-after did not compile" },
        },
        { diagnostics: { stage: "ruleset", status: 400, message: "Unexpected 'function'." } },
      ),
    },
  };
  const rows = Object.fromEntries(shapesReport(fixture).map((r) => [r.row, r]));
  assert.equal(rows["fn-shadow#publishes"].answer, "compiled");
  assert.equal(rows["fn-shadow#fn-shadow-pick"].official, OFFICIAL["fn-shadow#fn-shadow-pick"]);
  assert.equal(rows["fn-shadow#fn-shadow-pick"].verdict, "differs");
  assert.equal(rows["fn-shadow#fn-shadow-top-only"].verdict, "agrees");
  assert.equal(rows["fn-shadow#fn-shadow-inner-only"].answer, "unknown");
  assert.equal(rows["fn-shadow#fn-shadow-inner-only"].verdict, "unknown");
  assert.equal(rows["fn-shadow#fn-shadow-inner-only"].fixesVerdict, "unknown");
  assert.equal(rows["fn-after#publishes"].answer, "refused");
  assert.equal(rows["fn-after#publishes"].detail, "ruleset 400: Unexpected 'function'.");
  assert.equal(rows["fn-after#fn-after-true"].answer, "not-evaluated");
  assert.equal(rows["fn-after#fn-after-true"].verdict, "not-evaluated");
  assert.equal(rows["queries#owner-alone"].answer, "missing");
  assert.equal(rows["queries#owner-alone"].verdict, "unknown");
  assert.equal(
    rows["fn-shadow#fn-shadow-top-only"].fixesVerdict,
    FIXES["fn-shadow#fn-shadow-top-only"] === "allowed" ? "agrees" : "differs",
  );
});

test("a publication that ran unsettled leaves its program unknown, even when both recordings agree", () => {
  const unsettled = (recorded) => ({ ...recorded, publication: "unsettled" });
  const steps = {
    publishes: unsettled({ compiled: true }),
    "fn-shadow-pick": unsettled(allow),
    "fn-shadow-top-only": unsettled(allow),
    "fn-shadow-inner-only": unsettled(deny),
  };
  const rows = shapesReport({
    programs: { "fs-rules-v1/shapes/fn-shadow": programRecord(steps) },
  }).filter((r) => r.row.startsWith("fn-shadow#"));
  assert.equal(rows.length, 4);
  for (const r of rows) {
    assert.equal(r.answer, "unknown", r.row);
    assert.equal(r.verdict, "unknown", r.row);
    assert.equal(r.fixesVerdict, "unknown", r.row);
  }
});

test("a row whose second recording differs is unknown, never an answer", () => {
  const fixture = {
    programs: {
      "fs-rules-v1/shapes/fn-after": programRecord(
        { publishes: { compiled: true }, "fn-after-true": allow, "fn-after-false": deny },
        { second: { "fn-after-true": deny } },
      ),
    },
  };
  const rows = Object.fromEntries(shapesReport(fixture).map((r) => [r.row, r]));
  assert.equal(rows["fn-after#fn-after-true"].answer, "unknown");
  assert.equal(rows["fn-after#fn-after-true"].detail, "the two recordings differ");
  assert.equal(rows["fn-after#fn-after-false"].answer, "denied");
});

test("a query answer carries its document count; a missing claim is no-claim", () => {
  const document = { name: "n", fields: {} };
  const fixture = {
    programs: {
      "fs-rules-v1/shapes/queries": programRecord({
        publishes: { compiled: true },
        "owner-alone": { status: 200, body: [{ document, readTime: "t" }] },
        "name-own-alone": { status: 500, body: {} },
      }),
    },
  };
  const rows = Object.fromEntries(
    shapesReport(fixture, { official: {}, fixes: {} }).map((r) => [r.row, r]),
  );
  assert.deepEqual(rows["queries#owner-alone"], {
    row: "queries#owner-alone",
    answer: "allowed",
    documents: 1,
    verdict: "no-claim",
    fixesVerdict: "no-claim",
  });
  assert.deepEqual(rows["queries#name-own-alone"], {
    row: "queries#name-own-alone",
    answer: "unknown",
    detail: "status 500, not a recorded shape",
    verdict: "unknown",
    fixesVerdict: "unknown",
  });
  assert.equal(rows["queries#publishes"].verdict, "no-claim");
});
