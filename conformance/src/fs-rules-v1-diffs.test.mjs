// FS-RULES differences: the corpus of five Rules differences from the official emulator, the way it
// is selected and recorded, and the classification of what production answers. The facts the fake
// production uses are the test's choice, not claims about production. The recorded answers the
// classifier is pinned to are copied from the checked-in production fixtures (cited per test).

import assert from "node:assert/strict";
import { test } from "node:test";

import { createContext, SANDBOX_PROJECT } from "./fs-rules/harness.mjs";
import {
  BAD_PATH_PROGRAMS,
  corpusDigest,
  countRequests,
  DIFFS_PROGRAMS,
  DIFFS_RULESET_IDS,
  PRINCIPALS,
  PROGRAMS,
  REQUEST_CAP,
  rulesetSource,
  validateCorpus,
} from "./fs-rules-v1/corpus.mjs";
import { classifyAnswer, CLAIMS, diffsReport, RECORDED_SHAPES } from "./fs-rules-v1/diffs.mjs";
import {
  ceilings,
  corpusFor,
  fixtureText,
  selectPrograms,
  TASK_ID,
  TASK_ID_BAD_PATH,
  TASK_ID_DIFFS,
  taskIdFor,
} from "./fs-rules-v1/judge.mjs";
import { runCorpus } from "./fs-rules-v1/session.mjs";
import { createClock, createWorld } from "./fs-rules-v1/test-world.mjs";

const PRODUCTION = {
  kind: "production",
  adminToken: "ya29.owner-test-token",
  apiKey: "AIzaDiffsTestKeyNotReal",
  quotaProject: SANDBOX_PROJECT,
  projectNumber: "555500000001",
};

async function record({ scenario, programs = DIFFS_PROGRAMS } = {}) {
  const { world, fetchImpl, grpc } = createWorld(scenario);
  const clock = createClock();
  const ctx = createContext({ run: "1790000000000", startedMs: clock.now(), target: PRODUCTION });
  const out = await runCorpus(
    { programs, principals: PRINCIPALS },
    ctx,
    { fetchImpl, grpc, sleep: clock.sleep, now: clock.now },
    ceilings(programs),
  );
  return { out, world };
}

const rowsOf = (program) => program.steps.filter((step) => !step.publish);
const program = (suffix) => DIFFS_PROGRAMS.find((p) => p.id === `fs-rules-v1/diffs/${suffix}`);
const step = (suffix, id) => program(suffix).steps.find((s) => s.id === id);

// ---- the corpus -----------------------------------------------------------------------------

test("the corpus is five programs of 28 rows, valid and under the cap", () => {
  assert.deepEqual(
    DIFFS_PROGRAMS.map((p) => p.id),
    [
      "fs-rules-v1/diffs/queries",
      "fs-rules-v1/diffs/string-index",
      "fs-rules-v1/diffs/string-escape",
      "fs-rules-v1/diffs/fn-top",
      "fs-rules-v1/diffs/fn-inner",
    ],
  );
  assert.deepEqual(DIFFS_RULESET_IDS, [
    "diffs-queries",
    "diffs-string-index",
    "diffs-string-escape",
    "diffs-fn-top",
    "diffs-fn-inner",
  ]);
  assert.equal(validateCorpus(DIFFS_PROGRAMS), 28);
  assert.equal(countRequests(DIFFS_PROGRAMS), 28);
  assert.ok(28 <= REQUEST_CAP);
  for (const p of DIFFS_PROGRAMS) assert.deepEqual(p.steps[0], { id: "publishes", publish: true });
});

test("the five cases are the rules the differences name, verbatim", () => {
  const queries = rulesetSource("diffs-queries");
  for (const rule of [
    "match /fsr9-owner/{id} {\n      allow list: if resource.data.owner == request.auth.uid;",
    'match /fsr9-m-guarded/{id} {\n      allow list: if resource != null && resource.data.members[request.auth.uid].role in ["ADMIN","MEMBER"];',
    'match /fsr9-m-unguarded/{id} {\n      allow list: if resource.data.members[request.auth.uid].role in ["ADMIN","MEMBER"];',
    "match /fsr9-m-bare/{id} {\n      allow list: if resource != null;",
    'match /fsr9-blocked/{id} {\n      allow list: if !("blocked" in resource.data);',
    'match /fsr9-has-owner/{id} {\n      allow list: if "owner" in resource.data;',
  ])
    assert.ok(queries.includes(rule), rule);
  const index = rulesetSource("diffs-string-index");
  for (const [id, expr] of [
    ["ascii-ctl", '"abc"[1] == "b"'],
    ["idx0", '"é\u{1F525}x"[0] == "é"'],
    ["idx1-fire", '"é\u{1F525}x"[1] == "\u{1F525}"'],
    ["idx2-x", '"é\u{1F525}x"[2] == "x"'],
    ["idx3-x", '"é\u{1F525}x"[3] == "x"'],
    ["idx4-eq-x", '"é\u{1F525}x"[4] == "x"'],
    ["idx4-not-eq", '!("é\u{1F525}x"[4] == "x")'],
    ["size-4", '"é\u{1F525}x".size() == 4'],
    ["size-3", '"é\u{1F525}x".size() == 3'],
  ])
    assert.ok(index.includes(`match /fsr9-s-${id}/{id} {\n      allow get: if ${expr};`), id);
  const escape = rulesetSource("diffs-string-escape");
  assert.ok(escape.includes('allow get: if "é\u{1F525}x"[1] == "\\ud83d";'));
  assert.ok(escape.includes('allow get: if "\\u00e9" == "é";'));
});

test("a top-level function is declared after rules_version and before service, the control inside the match", () => {
  const top = rulesetSource("diffs-fn-top").split("\n");
  assert.equal(top[0], "rules_version = '2';");
  const fn = top.findIndex((l) => l.startsWith("function topTrue"));
  const service = top.findIndex((l) => l.startsWith("service cloud.firestore"));
  assert.ok(fn > 0 && fn < service, "the function precedes service");
  assert.ok(rulesetSource("diffs-fn-top").includes("allow get: if topTrue();"));
  assert.ok(rulesetSource("diffs-fn-top").includes("allow get: if topFalse();"));
  const inner = rulesetSource("diffs-fn-inner").split("\n");
  const innerFn = inner.findIndex((l) => l.includes("function innerTrue"));
  const innerService = inner.findIndex((l) => l.startsWith("service cloud.firestore"));
  assert.ok(innerFn > innerService, "the control function is inside service");
});

test("the query rows send the filters the cases name", () => {
  const where = (id) => step("queries", id).body.structuredQuery.where;
  const owner = {
    fieldFilter: {
      field: { fieldPath: "owner" },
      op: "EQUAL",
      value: { stringValue: "UID(anon)" },
    },
  };
  const name = (doc) => ({
    fieldFilter: {
      field: { fieldPath: "__name__" },
      op: "EQUAL",
      value: { referenceValue: `{docs}/fsr9-owner/${doc}` },
    },
  });
  assert.deepEqual(where("owner-alone"), owner);
  assert.deepEqual(where("owner-and-name-missing"), {
    compositeFilter: { op: "AND", filters: [owner, name("missing")] },
  });
  assert.deepEqual(where("owner-and-name-foreign"), {
    compositeFilter: { op: "AND", filters: [owner, name("foreign")] },
  });
  assert.deepEqual(where("owner-and-name-own"), {
    compositeFilter: { op: "AND", filters: [owner, name("mine")] },
  });
  assert.deepEqual(where("name-missing-alone"), name("missing"));
  assert.deepEqual(where("name-foreign-alone"), name("foreign"));
  const members = (id, values) => {
    const filter = where(id);
    assert.equal(filter.fieldFilter.field.fieldPath, "members.`UID(anon)`.role");
    assert.equal(filter.fieldFilter.op, "IN");
    assert.deepEqual(
      filter.fieldFilter.value.arrayValue.values.map((v) => v.stringValue),
      values,
    );
  };
  members("members-guarded-in", ["ADMIN", "MEMBER"]);
  members("members-unguarded-in", ["ADMIN", "MEMBER"]);
  members("members-guarded-in-viewer", ["VIEWER"]);
  for (const id of ["members-bare-nofilter", "blocked-nofilter", "has-owner-nofilter"])
    assert.equal(where(id), undefined, id);
  assert.equal(where("has-owner-filtered").fieldFilter.field.fieldPath, "owner");
});

test("every row is a REST read; queries are made as the one anonymous principal, gets with none", () => {
  for (const p of DIFFS_PROGRAMS)
    for (const s of rowsOf(p)) {
      assert.equal(s.transport, undefined, `${s.id}: REST only`);
      assert.ok(["get", "runQuery"].includes(s.rpc));
      assert.equal(s.as, s.rpc === "runQuery" ? "anon" : "none", s.id);
    }
});

test("program digests follow the program's own ruleset, and the other corpora keep theirs", () => {
  const digests = DIFFS_PROGRAMS.map((p) => corpusDigest([p]));
  assert.equal(new Set(digests).size, DIFFS_PROGRAMS.length);
  assert.notEqual(corpusDigest(DIFFS_PROGRAMS), corpusDigest(BAD_PATH_PROGRAMS));
  assert.equal(validateCorpus(PROGRAMS), 76);
});

test("the corpus names no sandbox, number, address or absolute path", () => {
  const text = JSON.stringify(DIFFS_PROGRAMS) + DIFFS_RULESET_IDS.map(rulesetSource).join("\n");
  assert.ok(!text.includes(SANDBOX_PROJECT));
  assert.ok(!/@[\w-]+\./.test(text));
  assert.ok(!/\/Users\/|\/home\//.test(text));
});

// ---- selection ------------------------------------------------------------------------------

test("FS3_CORPUS=diffs picks the family and names its own ledger task; one run never mixes", () => {
  assert.equal(corpusFor({ FS3_CORPUS: "diffs" }), DIFFS_PROGRAMS);
  assert.equal(selectPrograms(undefined, { FS3_CORPUS: "diffs" }).length, 5);
  assert.equal(taskIdFor(DIFFS_PROGRAMS), TASK_ID_DIFFS);
  assert.equal(taskIdFor(PROGRAMS), TASK_ID);
  assert.equal(taskIdFor(BAD_PATH_PROGRAMS), TASK_ID_BAD_PATH);
  assert.notEqual(TASK_ID_DIFFS, TASK_ID);
  assert.notEqual(TASK_ID_DIFFS, TASK_ID_BAD_PATH);
  assert.throws(() => taskIdFor([...DIFFS_PROGRAMS, ...BAD_PATH_PROGRAMS]), /mixes/);
  assert.throws(() => taskIdFor([DIFFS_PROGRAMS[0], PROGRAMS[0]]), /mixes/);
  assert.throws(() => corpusFor({ FS3_CORPUS: "diff" }), /FS3_CORPUS/);
});

// ---- the recorder over the fake production --------------------------------------------------

test("a recording leaves the sandbox as it found it, with the request counts the packet states", async () => {
  const { out, world } = await record();
  assert.equal(out.closureReady, true);
  assert.deepEqual(out.cleanupErrors, []);
  assert.deepEqual(out.failures, []);
  assert.equal(out.requests, 28);
  assert.equal(out.publications.length, 5);
  assert.equal(world.releases.size, 0);
  assert.equal(world.rulesets.size, 0);
  assert.equal(world.documents.size, 0);
  assert.equal(world.accounts.size, 0);
});

test("the seed and the query bodies carry the principal's uid, and the recording masks it everywhere", async () => {
  const { out, world } = await record();
  const uids = [...world.signedUp];
  assert.equal(uids.length, 1);
  const [uid] = uids;
  const seeded = world.seeded;
  assert.equal(seeded.get("fsr9-owner/mine").owner.stringValue, uid);
  assert.equal(seeded.get("fsr9-owner/foreign").owner.stringValue, "other-owner");
  assert.deepEqual(Object.keys(seeded.get("fsr9-m-guarded/g1").members.mapValue.fields), [uid]);
  const sent = world.log.filter(
    (c) =>
      c.url.includes(":runQuery") &&
      c.headers.authorization?.startsWith("Bearer ") &&
      !c.headers.authorization.startsWith("Bearer ya29."),
  );
  assert.equal(sent.length, 13);
  assert.ok(JSON.stringify(sent[1].body).includes(`"stringValue":"${uid}"`));
  assert.ok(JSON.stringify(sent[1].body).includes("projects/"), "the document name is expanded");
  assert.ok(!JSON.stringify(sent).includes("UID("), "no placeholder is sent");
  const recorded = JSON.stringify(out.results);
  assert.ok(!recorded.includes(uid), "the uid never reaches a recording, keys included");
  assert.ok(recorded.includes("<uid:anon>"));
});

test("a ruleset production refuses takes its own rows with it and nothing else", async () => {
  const { out } = await record({
    scenario: { refuseSource: (source) => source.includes("function topTrue") },
  });
  const top = out.results["fs-rules-v1/diffs/fn-top"].steps;
  assert.deepEqual(top.publishes, { compiled: false });
  assert.equal(top["fn-top-true"].unresolved, "ruleset diffs-fn-top did not compile");
  assert.equal(out.results["fs-rules-v1/diffs/fn-inner"].steps.publishes.compiled, true);
  assert.equal(out.results["fs-rules-v1/diffs/fn-inner"].steps["fn-inner-true"].status, 404);
  assert.equal(out.closureReady, true);
});

test("an unknown answer to the release delete keeps the run from closing", async () => {
  const { world, fetchImpl, grpc } = createWorld();
  const clock = createClock();
  world.onCall = (method, url) =>
    method === "DELETE" && url.includes("/releases/") ? { status: 503 } : undefined;
  const ctx = createContext({ run: "1790000000001", startedMs: clock.now(), target: PRODUCTION });
  await assert.rejects(
    runCorpus(
      { programs: DIFFS_PROGRAMS.slice(0, 1), principals: PRINCIPALS },
      ctx,
      { fetchImpl, grpc, sleep: clock.sleep, now: clock.now },
      ceilings(DIFFS_PROGRAMS.slice(0, 1)),
    ),
    (error) => {
      assert.equal(error.partial.closureReady, false);
      assert.deepEqual(error.partial.unknowns, [{ call: "delete release", answer: "HTTP 503" }]);
      return true;
    },
  );
});

test("the fixture keeps the other corpora and adds the diffs programs", async () => {
  const { out } = await record();
  const existing = {
    version: 1,
    recordedAgainst: {},
    programs: { "fs-rules-v1/bad-path/core": { keep: true } },
  };
  const text = fixtureText({
    programs: DIFFS_PROGRAMS,
    recordings: [out, out],
    meta: { harness: "h", startedAt: "t", sha: "s" },
    existing,
  });
  const fixture = JSON.parse(text);
  assert.deepEqual(fixture.programs["fs-rules-v1/bad-path/core"], { keep: true });
  assert.equal(Object.keys(fixture.programs).length, 6);
});

// ---- the classifier: recorded production shapes only -----------------------------------------

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
    message: 'Document "projects/demo-fs-rules/databases/(default)/documents/fsr8-x/x" not found.',
    status: "NOT_FOUND",
  },
};

test("each accepted shape is a recorded one, and cites its fixture row", () => {
  assert.equal(RECORDED_SHAPES.length, 5);
  for (const shape of RECORDED_SHAPES) {
    assert.match(shape.source, /^(fs-rules-v1-observation|fs-rules-production)\.json /);
    assert.match(shape.row, /^fs-rules(-v1)?\//);
  }
});

test("get: a recorded 404 allows, a recorded 403 denies", () => {
  // fs-rules-v1/bad-path/core#ctl-missing-not-exists and #ctl-real-not-exists
  assert.deepEqual(classifyAnswer("get", { status: 404, body: NOT_FOUND }), { kind: "allowed" });
  assert.deepEqual(classifyAnswer("get", { status: 403, body: DENIED_BODY }), { kind: "denied" });
});

test("runQuery: recorded empty and non-empty results allow, the recorded array refusal denies", () => {
  // fs-rules/budgets/access-calls#list-10, fs-rules-v1/path-wildcard/v2#group-none, #kindless-parent-none
  assert.deepEqual(
    classifyAnswer("runQuery", { status: 200, body: [{ readTime: "<run-time>" }] }),
    {
      kind: "allowed",
      documents: 0,
    },
  );
  const document = { name: "n", fields: {}, createTime: "<run-time>", updateTime: "<run-time>" };
  assert.deepEqual(
    classifyAnswer("runQuery", {
      status: 200,
      body: [
        { document, readTime: "<run-time>" },
        { document, readTime: "<run-time>" },
      ],
    }),
    { kind: "allowed", documents: 2 },
  );
  assert.deepEqual(
    classifyAnswer("runQuery", { status: 403, body: [{ error: DENIED_BODY.error }] }),
    {
      kind: "denied",
    },
  );
});

test("every other answer is unknown, with near misses of each recorded shape", () => {
  const unknown = (rpc, recorded) => classifyAnswer(rpc, recorded).kind === "unknown";
  // get
  assert.ok(unknown("get", { status: 200, body: { name: "x", fields: {} } }));
  assert.ok(unknown("get", { status: 404, body: DENIED_BODY }));
  assert.ok(unknown("get", { status: 403, body: NOT_FOUND }));
  assert.ok(
    unknown("get", { status: 403, body: { error: { ...DENIED_BODY.error, message: "other" } } }),
  );
  assert.ok(unknown("get", { status: 403, body: { error: { ...DENIED_BODY.error, code: 404 } } }));
  assert.ok(unknown("get", { status: 403, body: { error: DENIED_BODY.error, extra: 1 } }));
  assert.ok(
    unknown("get", { status: 403, body: { error: { ...DENIED_BODY.error, details: [] } } }),
  );
  assert.ok(
    unknown("get", { status: 404, body: { error: { ...NOT_FOUND.error, message: "gone" } } }),
  );
  assert.ok(
    unknown("get", { status: 400, body: { error: { code: 400, status: "INVALID_ARGUMENT" } } }),
  );
  assert.ok(unknown("get", { status: 500, body: { error: { code: 500, status: "INTERNAL" } } }));
  assert.ok(unknown("get", { status: 403, nonJson: true }));
  assert.ok(unknown("get", { status: 0, transport: "ETIMEDOUT" }));
  // runQuery
  assert.ok(unknown("runQuery", { status: 200, body: [] }));
  assert.ok(unknown("runQuery", { status: 200, body: [{}] }));
  assert.ok(unknown("runQuery", { status: 200, body: { readTime: "x" } }));
  assert.ok(unknown("runQuery", { status: 200, body: [{ readTime: "x", unexpected: 1 }] }));
  assert.ok(unknown("runQuery", { status: 200, body: [{ document: { name: "n" } }] }));
  assert.ok(
    unknown("runQuery", { status: 200, body: [{ readTime: "x" }, { error: DENIED_BODY.error }] }),
  );
  assert.ok(
    unknown("runQuery", {
      status: 403,
      body: [{ error: { ...DENIED_BODY.error, status: "UNAUTHENTICATED" } }],
    }),
  );
  assert.ok(
    unknown("runQuery", {
      status: 403,
      body: [{ error: DENIED_BODY.error }, { error: DENIED_BODY.error }],
    }),
  );
  assert.ok(unknown("runQuery", { status: 403, body: DENIED_BODY }));
  assert.ok(unknown("runQuery", { status: 200, body: [{ error: DENIED_BODY.error }] }));
  assert.ok(
    unknown("runQuery", {
      status: 400,
      body: [
        {
          error: {
            code: 400,
            message: "The query requires a COLLECTION_GROUP_ASC index",
            status: "FAILED_PRECONDITION",
          },
        },
      ],
    }),
  );
  assert.ok(
    unknown("runQuery", { status: 503, body: [{ error: { code: 503, status: "UNAVAILABLE" } }] }),
  );
  assert.ok(unknown("runQuery", { status: 0, transport: "ECONNRESET" }));
  // an rpc this classifier was not recorded for
  assert.ok(unknown("listen", { status: 200, body: [{ readTime: "x" }] }));
  assert.ok(unknown("get", undefined));
});

test("a ruleset that did not compile or a row that never ran is not an answer", () => {
  assert.equal(
    classifyAnswer("get", { status: -1, unresolved: "ruleset x did not compile" }).kind,
    "not-evaluated",
  );
  assert.equal(classifyAnswer("runQuery", { compiled: false }).kind, "unknown");
});

// ---- the report -----------------------------------------------------------------------------

const programRecord = (steps, second) => ({ steps, ...(second ? { second } : {}) });
const allow = { status: 404, body: NOT_FOUND };
const deny = { status: 403, body: DENIED_BODY };

test("the report compares each answer with the official claim, and says no-claim, unknown or not-evaluated otherwise", () => {
  assert.equal(CLAIMS["fn-top#fn-top-true"], "allowed");
  const fixture = {
    programs: {
      "fs-rules-v1/diffs/fn-top": programRecord({
        publishes: { compiled: true },
        "fn-top-true": allow,
        "fn-top-false": allow,
      }),
      "fs-rules-v1/diffs/fn-inner": programRecord({
        publishes: { compiled: true },
        "fn-inner-true": { status: 500, body: { error: { code: 500, status: "INTERNAL" } } },
        "fn-inner-false": deny,
      }),
      "fs-rules-v1/diffs/string-escape": programRecord({
        publishes: { compiled: false },
        "esc-high": { status: -1, unresolved: "ruleset diffs-string-escape did not compile" },
      }),
    },
  };
  const rows = Object.fromEntries(diffsReport(fixture).map((r) => [r.row, r]));
  assert.equal(rows["fn-top#publishes"].answer, "compiled");
  assert.equal(rows["fn-top#publishes"].verdict, "agrees");
  assert.equal(rows["fn-top#fn-top-true"].verdict, "agrees");
  assert.equal(rows["fn-top#fn-top-false"].verdict, "differs");
  assert.equal(rows["fn-inner#fn-inner-true"].answer, "unknown");
  assert.equal(rows["fn-inner#fn-inner-true"].verdict, "unknown");
  assert.equal(rows["fn-inner#fn-inner-false"].verdict, "agrees");
  assert.equal(rows["string-escape#publishes"].answer, "refused");
  assert.equal(rows["string-escape#esc-high"].answer, "not-evaluated");
  assert.equal(rows["string-escape#esc-high"].verdict, "not-evaluated");
  assert.equal(rows["queries#owner-alone"].answer, "missing");
  assert.equal(rows["queries#owner-alone"].verdict, "unknown");
});

test("a row whose second recording differs is unknown, never an answer", () => {
  const fixture = {
    programs: {
      "fs-rules-v1/diffs/fn-top": programRecord(
        { publishes: { compiled: true }, "fn-top-true": allow, "fn-top-false": deny },
        { "fn-top-true": deny },
      ),
    },
  };
  const rows = Object.fromEntries(diffsReport(fixture).map((r) => [r.row, r]));
  assert.equal(rows["fn-top#fn-top-true"].answer, "unknown");
  assert.match(rows["fn-top#fn-top-true"].detail, /recordings differ/);
  assert.equal(rows["fn-top#fn-top-false"].verdict, "agrees");
});

test("every claimed row exists in the corpus, and every claim is allowed or denied", () => {
  const rows = new Set(
    DIFFS_PROGRAMS.flatMap((p) => p.steps.map((s) => `${p.id.split("/").at(-1)}#${s.id}`)),
  );
  for (const [row, claim] of Object.entries(CLAIMS)) {
    assert.ok(rows.has(row), row);
    assert.ok(["allowed", "denied", "compiled"].includes(claim), row);
  }
});

test("the official answers cover every row of the corpus, and a row without one is no-claim", () => {
  const rows = DIFFS_PROGRAMS.flatMap((p) =>
    p.steps.map((s) => `${p.id.split("/").at(-1)}#${s.id}`),
  );
  assert.deepEqual(Object.keys(CLAIMS).toSorted(), rows.toSorted());
  const fixture = {
    programs: {
      "fs-rules-v1/diffs/fn-top": programRecord({
        publishes: { compiled: true },
        "fn-top-true": allow,
      }),
    },
  };
  const rowsByName = Object.fromEntries(diffsReport(fixture, {}).map((r) => [r.row, r]));
  assert.equal(rowsByName["fn-top#fn-top-true"].verdict, "no-claim");
  assert.equal(rowsByName["fn-top#publishes"].verdict, "no-claim");
  assert.equal(rowsByName["fn-top#fn-top-false"].verdict, "unknown");
});

// ---- pins found by the mutation pass ---------------------------------------------------------

test("the two function rulesets are exactly these sources", () => {
  assert.equal(
    rulesetSource("diffs-fn-top"),
    "rules_version = '2';\nfunction topTrue() {\n  return true;\n}\nfunction topFalse() {\n  return false;\n}\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    match /fsr-marker/{label} {\n      allow write: if label == 'diffs-fn-top-469a71701793';\n    }\n\n    match /fsr9-fn-top-true/{id} {\n      allow get: if topTrue();\n    }\n    match /fsr9-fn-top-false/{id} {\n      allow get: if topFalse();\n    }\n  }\n}\n",
  );
  assert.equal(
    rulesetSource("diffs-fn-inner"),
    "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    match /fsr-marker/{label} {\n      allow write: if label == 'diffs-fn-inner-74491fe85c56';\n    }\n\n    function innerTrue() {\n      return true;\n    }\n    function innerFalse() {\n      return false;\n    }\n    match /fsr9-fn-inner-true/{id} {\n      allow get: if innerTrue();\n    }\n    match /fsr9-fn-inner-false/{id} {\n      allow get: if innerFalse();\n    }\n  }\n}\n",
  );
});

test("every ruleset is version 2 with balanced braces, and every row and seed names a collection that has a rule", () => {
  for (const p of DIFFS_PROGRAMS) {
    const source = rulesetSource(p.ruleset);
    assert.ok(source.startsWith("rules_version = '2';\n"), p.ruleset);
    assert.equal(source.split("{").length, source.split("}").length, `${p.ruleset}: braces`);
    const collections = [
      ...rowsOf(p).map((s) => s.body?.structuredQuery.from[0].collectionId ?? s.doc.split("/")[0]),
      ...p.seed.map((d) => d.doc.split("/")[0]),
    ];
    for (const collection of collections)
      assert.ok(source.includes(`match /${collection}/{id} {`), `${p.id}: ${collection}`);
  }
});

test("the seed and the queries' collections are exactly these", () => {
  const queries = program("queries");
  assert.deepEqual(
    rowsOf(queries).map((s) => [s.id, s.body.structuredQuery.from[0].collectionId]),
    [
      ["owner-alone", "fsr9-owner"],
      ["owner-and-name-missing", "fsr9-owner"],
      ["owner-and-name-foreign", "fsr9-owner"],
      ["owner-and-name-own", "fsr9-owner"],
      ["name-missing-alone", "fsr9-owner"],
      ["name-foreign-alone", "fsr9-owner"],
      ["members-guarded-in", "fsr9-m-guarded"],
      ["members-guarded-in-viewer", "fsr9-m-guarded"],
      ["members-unguarded-in", "fsr9-m-unguarded"],
      ["members-bare-nofilter", "fsr9-m-bare"],
      ["blocked-nofilter", "fsr9-blocked"],
      ["has-owner-nofilter", "fsr9-has-owner"],
      ["has-owner-filtered", "fsr9-has-owner"],
    ],
  );
  const role = (r) => ({
    members: {
      mapValue: { fields: { "UID(anon)": { mapValue: { fields: { role: { stringValue: r } } } } } },
    },
  });
  assert.deepEqual(queries.seed, [
    { doc: "fsr9-owner/mine", fields: { owner: { stringValue: "UID(anon)" } } },
    { doc: "fsr9-owner/foreign", fields: { owner: { stringValue: "other-owner" } } },
    { doc: "fsr9-m-guarded/g1", fields: role("ADMIN") },
    { doc: "fsr9-m-unguarded/u1", fields: role("ADMIN") },
    { doc: "fsr9-m-bare/b1", fields: role("ADMIN") },
    { doc: "fsr9-blocked/p1", fields: { n: { integerValue: "1" } } },
    { doc: "fsr9-has-owner/h1", fields: { owner: { stringValue: "o1" } } },
  ]);
  assert.deepEqual(step("queries", "has-owner-filtered").body.structuredQuery.where, {
    fieldFilter: { field: { fieldPath: "owner" }, op: "EQUAL", value: { stringValue: "o1" } },
  });
  for (const other of DIFFS_PROGRAMS.filter((p) => p !== queries)) assert.deepEqual(other.seed, []);
});

test("the ledger task is named FS-RULES-DIFFS", () => {
  assert.equal(TASK_ID_DIFFS, "FS-RULES-DIFFS");
});

test("the recorded shapes are two get shapes and three runQuery shapes, each described", () => {
  assert.deepEqual(
    RECORDED_SHAPES.map((s) => `${s.rpc} ${s.kind}`),
    ["get allowed", "get denied", "runQuery allowed", "runQuery allowed", "runQuery denied"],
  );
  for (const shape of RECORDED_SHAPES)
    assert.ok(shape.note.length > 10 && shape.source.includes("#"));
});

test("a one-document query result is an allow, and an absent recording is unknown with a reason", () => {
  const document = { name: "n", fields: {} };
  assert.deepEqual(
    classifyAnswer("runQuery", { status: 200, body: [{ document, readTime: "t" }] }),
    { kind: "allowed", documents: 1 },
  );
  assert.deepEqual(classifyAnswer("get", undefined), { kind: "unknown", detail: "no recording" });
  assert.deepEqual(classifyAnswer("get", { status: 500, body: {} }), {
    kind: "unknown",
    detail: "status 500, not a recorded shape",
  });
});

test("report rows carry the document count, the reason and the claim, and only when there is one", () => {
  const document = { name: "n", fields: {} };
  const fixture = {
    programs: {
      "fs-rules-v1/diffs/queries": programRecord({
        publishes: { compiled: true },
        "owner-alone": { status: 200, body: [{ document, readTime: "t" }] },
        "owner-and-name-missing": { status: 403, body: [{ error: DENIED_BODY.error }] },
        "name-foreign-alone": { status: 500, body: {} },
      }),
      "fs-rules-v1/diffs/string-index": programRecord({ publishes: { status: 500 } }),
      "fs-rules-v1/diffs/string-escape": programRecord({ publishes: { compiled: false } }),
    },
  };
  const rows = Object.fromEntries(diffsReport(fixture).map((r) => [r.row, r]));
  assert.deepEqual(rows["queries#owner-alone"], {
    row: "queries#owner-alone",
    claim: "allowed",
    answer: "allowed",
    documents: 1,
    verdict: "agrees",
  });
  assert.deepEqual(rows["queries#owner-and-name-missing"], {
    row: "queries#owner-and-name-missing",
    claim: "denied",
    answer: "denied",
    verdict: "agrees",
  });
  assert.deepEqual(rows["queries#name-foreign-alone"], {
    row: "queries#name-foreign-alone",
    claim: "denied",
    answer: "unknown",
    detail: "status 500, not a recorded shape",
    verdict: "unknown",
  });
  assert.deepEqual(rows["queries#members-bare-nofilter"], {
    row: "queries#members-bare-nofilter",
    claim: "allowed",
    answer: "missing",
    detail: "not recorded",
    verdict: "unknown",
  });
  assert.equal(rows["string-index#publishes"].answer, "unknown");
  assert.equal(rows["string-index#publishes"].detail, "no publication answer");
  assert.equal(rows["string-escape#publishes"].answer, "refused");
  assert.equal(rows["string-escape#publishes"].verdict, "differs");
});
