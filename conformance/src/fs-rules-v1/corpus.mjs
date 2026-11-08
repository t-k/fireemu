// Two corpora share this recorder. FS-3 (PROGRAMS): Security Rules without `rules_version = '2'`
// (v1) and collection-group queries. FS-8 (BAD_PATH_PROGRAMS): Rules `get()`/`exists()` on a path
// that is not a document of this database, at the end of the file. The text below is FS-3's.
//
// Under v1, `match /{document=**}` is the only recursive wildcard that can match a collection-group
// query, and Firebase documents that group queries need version 2. Nothing in the FS-RULES corpus
// records a v1 ruleset against a collection-group, aggregation, Listen or kindless query, so this
// corpus records exactly that: four rulesets (two rule shapes, each as v1 and as the v2 control)
// and the same query rows under each.
//
// Everything here is data and pure functions. The corpus addresses `(default)` of the disposable
// Identity Platform sandbox only, with one anonymous principal and no credential at all.

import { createHash } from "node:crypto";

/** Query rows of one recording (requests made as the signed-in or signed-out caller). */
export const REQUEST_CAP = 120;
/** Harness calls (sign-in, publication, markers, seed, wipe, cleanup) of one recording. */
export const HARNESS_CAP = 1500;

const digest = (text) => createHash("sha256").update(text).digest("hex").slice(0, 12);

/** The only principal: one anonymous account (created and deleted by the run), plus `none`. */
export const PRINCIPALS = { anon: { provider: "anonymous" } };

const RECURSIVE = ["    match /{document=**} {", "      allow read: if true;", "    }"];
const PATH_FORM = ["    match /{path=**}/posts/{d} {", "      allow read: if true;", "    }"];

/** Ruleset id to its version and rule body. `v1` has no `rules_version` line at all. */
export const RULESETS = {
  "recursive-v1": { version: 1, body: RECURSIVE },
  "recursive-v2": { version: 2, body: RECURSIVE },
  "path-v1": { version: 1, body: PATH_FORM },
  "path-v2": { version: 2, body: PATH_FORM },
};
export const RULESET_IDS = Object.keys(RULESETS);

function compose(rulesetId, label) {
  const ruleset =
    RULESETS[rulesetId] ??
    BAD_PATH_RULESETS[rulesetId] ??
    DIFFS_RULESETS[rulesetId] ??
    SHAPES_RULESETS[rulesetId];
  if (!ruleset) throw new Error(`unknown ruleset ${rulesetId}`);
  return [
    ...(ruleset.version === 2 ? ["rules_version = '2';"] : []),
    // Declarations outside `service` (FS-RULES differences, case 4).
    ...(ruleset.preamble ?? []),
    "service cloud.firestore {",
    "  match /databases/{database}/documents {",
    // The marker is a write rule: the recursive read rule would allow any marker read.
    "    match /fsr-marker/{label} {",
    `      allow write: if label == '${label}';`,
    "    }",
    "",
    ...ruleset.body,
    "  }",
    "}",
    // Declarations after `service` (FS-RULES shapes).
    ...(ruleset.postamble ?? []),
    "",
  ].join("\n");
}

/** The marker label of a ruleset: its id and the digest of its unlabelled source. */
export const markerOf = (rulesetId) => `${rulesetId}-${digest(compose(rulesetId, "LABEL"))}`;

/** The source of a ruleset as published. */
export const rulesetSource = (rulesetId) => compose(rulesetId, markerOf(rulesetId));

export const RULESET_TEXT = RULESET_IDS.map((id) => rulesetSource(id)).join("\n");

// ---- steps ----------------------------------------------------------------------------------

const GROUP = { collectionId: "posts", allDescendants: true };

const query = (id, as, from, extra = {}) => ({
  id,
  as,
  rpc: "runQuery",
  body: { structuredQuery: { from: [from] } },
  ...extra,
});

const count = (id, as, from, extra = {}) => ({
  id,
  as,
  rpc: "runAggregationQuery",
  body: {
    structuredAggregationQuery: {
      structuredQuery: { from: [from] },
      aggregations: [{ alias: "n", count: {} }],
    },
  },
  ...extra,
});

const listen = (id, as, from) => ({
  id,
  as,
  rpc: "listen",
  transport: "grpc",
  query: { from: [from] },
});

const get = (id, as, doc) => ({ id, as, rpc: "get", doc });

const SEED = [
  { doc: "posts/p0", fields: { n: { integerValue: "1" } } },
  { doc: "fsr-g1/x/posts/p1", fields: { n: { integerValue: "1" } } },
  { doc: "fsr-g1/x/other/o1", fields: { n: { integerValue: "1" } } },
  { doc: "fsr-g2/y/posts/p2", fields: { n: { integerValue: "1" } } },
];

/** The rows every ruleset is put through, after its own publication row. */
const queries = () => [
  // The finding: a collection-group query, its COUNT aggregation and its Listen.
  query("group-none", "none", GROUP),
  query("group-anon", "anon", GROUP),
  count("group-count-none", "none", GROUP),
  count("group-count-anon", "anon", GROUP),
  query("group-grpc-none", "none", GROUP, { transport: "grpc" }),
  count("group-count-grpc-none", "none", GROUP, { transport: "grpc" }),
  listen("group-listen-none", "none", GROUP),
  listen("group-listen-anon", "anon", GROUP),
  // Controls: the same collection queried without allDescendants, and plain gets.
  query("single-none", "none", { collectionId: "posts" }),
  query("single-anon", "anon", { collectionId: "posts" }),
  count("single-count-none", "none", { collectionId: "posts" }),
  query("nested-none", "none", { collectionId: "posts" }, { parent: "fsr-g1/x" }),
  listen("single-listen-none", "none", { collectionId: "posts" }),
  get("get-top-none", "none", "posts/p0"),
  get("get-nested-none", "none", "fsr-g1/x/posts/p1"),
  // Kindless all-descendants queries (no collection id), under a parent document and at the root.
  query("kindless-parent-none", "none", { allDescendants: true }, { parent: "fsr-g1/x" }),
  query("kindless-parent-anon", "anon", { allDescendants: true }, { parent: "fsr-g1/x" }),
  query("kindless-root-none", "none", { allDescendants: true }),
  count("kindless-count-parent-none", "none", { allDescendants: true }, { parent: "fsr-g1/x" }),
];

const buildProgram = (id, ruleset) => ({
  id: `fs-rules-v1/${id}`,
  ruleset,
  seed: SEED,
  steps: [{ id: "publishes", publish: true }, ...queries()],
});

export const PROGRAMS = [
  buildProgram("recursive-wildcard/v1", "recursive-v1"),
  buildProgram("recursive-wildcard/v2", "recursive-v2"),
  buildProgram("path-wildcard/v1", "path-v1"),
  buildProgram("path-wildcard/v2", "path-v2"),
];

/** A program's digest covers its JSON and every ruleset the corpus could publish. */
export const programDigest = (program) =>
  createHash("sha256")
    .update(
      `${JSON.stringify(program)}\n${Object.hasOwn(RULESETS, program.ruleset) ? RULESET_TEXT : rulesetSource(program.ruleset)}`,
    )
    .digest("hex");

export const corpusDigest = (programs = PROGRAMS) =>
  createHash("sha256").update(JSON.stringify(programs)).digest("hex");

// ---- the static guard -----------------------------------------------------------------------

export const RPC_NAMES = new Set(["get", "runQuery", "runAggregationQuery", "listen"]);

/** The query rows of a corpus; a publication row is made of harness calls, not row requests. */
export const countRequests = (programs) =>
  programs.reduce((total, p) => total + p.steps.filter((s) => !s.publish).length, 0);

/**
 * Refuses a corpus that could address anything but a relative document path of `(default)`, use
 * an unknown principal, RPC or ruleset, hold a recorded email outside example.com, or exceed the
 * request cap. Returns the number of query rows.
 */
export function validateCorpus(programs, principals = PRINCIPALS) {
  const ids = new Set();
  const known = new Set(["none", ...Object.keys(principals)]);
  programs.forEach((p) => {
    if (!/^fs-rules-v1\/[a-z-]+\/[a-z0-9-]+$/.test(p.id)) throw new Error(`bad program id ${p.id}`);
    if (ids.has(p.id)) throw new Error(`duplicate program ${p.id}`);
    ids.add(p.id);
    if (
      !RULESET_IDS.includes(p.ruleset) &&
      !BAD_PATH_RULESET_IDS.includes(p.ruleset) &&
      !DIFFS_RULESET_IDS.includes(p.ruleset) &&
      !SHAPES_RULESET_IDS.includes(p.ruleset)
    )
      throw new Error(`${p.id}: unknown ruleset ${p.ruleset}`);
    const stepIds = new Set();
    p.steps.forEach((step, index) => {
      if (!/^[a-z0-9-]+$/.test(step.id)) throw new Error(`${p.id}: bad step id ${step.id}`);
      if (stepIds.has(step.id)) throw new Error(`${p.id}: duplicate step ${step.id}`);
      stepIds.add(step.id);
      if (step.publish) {
        if (index !== 0) throw new Error(`${p.id}#${step.id}: the publication is the first step`);
        return;
      }
      if (!RPC_NAMES.has(step.rpc)) throw new Error(`${p.id}#${step.id}: unknown rpc ${step.rpc}`);
      if (step.database !== undefined)
        throw new Error(`${p.id}#${step.id}: a step names a database; only (default) is used`);
      if (!known.has(step.as)) throw new Error(`${p.id}#${step.id}: unknown principal ${step.as}`);
      if (step.rpc === "listen" && step.transport !== "grpc")
        throw new Error(`${p.id}#${step.id}: Listen is gRPC only`);
      for (const path of [step.doc, step.parent].filter(Boolean)) {
        if (/^[a-z]+:|^\/|\.\./i.test(path))
          throw new Error(`${p.id}#${step.id}: path must be relative`);
      }
    });
    for (const doc of (p.seed ?? []).map((s) => s.doc)) {
      if (/^[a-z]+:|^\/|\.\./i.test(doc)) throw new Error(`${p.id}: seed path must be relative`);
    }
    // An email address anywhere in a program would be recorded; none is needed.
    if (/@[\w-]+\./.test(JSON.stringify(p))) throw new Error(`${p.id}: contains an address`);
  });
  const requests = countRequests(programs);
  if (requests > REQUEST_CAP)
    throw new Error(`corpus exceeds the request cap (${requests} > ${REQUEST_CAP})`);
  return requests;
}

// ---- FS-8: Rules get()/exists() on a path that is not a document of this database -----------
//
// A Rules `get()`/`exists()` argument is a path under `/databases/$(database)/documents`. A
// collection (odd-segment) path, another database and a path without `/documents` are not
// documents of this database. Each case is one `allow get` rule on its own collection, so one
// plain REST get answers it: the request is allowed (the requested document is simply not there,
// 404) or refused (403). Controls (a real document, a missing one, a negated real one, a good
// path built from the request) separate "the rule raised" from "the rule was false".
//
// The cases whose syntax is uncertain (another database, the `(default)` literal, no
// `/documents`) each get their own ruleset: production refuses to compile a ruleset or not as a
// whole, and a refusal is recorded as such without taking the other cases with it.

const DOCS = "/databases/$(database)/documents";
const OTHER = "/databases/other/documents/fsr8-ctl/real";
const NO_DOCS = "/databases/$(database)/fsr8-ctl/real";

/** Case id, the ruleset that publishes it, the rule condition, and the id of the requested document. */
export const BAD_PATH_CASES = [
  // Controls.
  { id: "ctl-exists-real", ruleset: "core", expr: `exists(${DOCS}/fsr8-ctl/real)` },
  { id: "ctl-missing-not-exists", ruleset: "core", expr: `!exists(${DOCS}/fsr8-ctl/absent)` },
  { id: "ctl-real-not-exists", ruleset: "core", expr: `!exists(${DOCS}/fsr8-ctl/real)` },
  { id: "ctl-missing-get-null", ruleset: "core", expr: `get(${DOCS}/fsr8-ctl/absent) == null` },
  { id: "dyn-doc-exists", ruleset: "core", expr: `exists(${DOCS}/fsr8-ctl/$(id))`, docId: "real" },
  // A collection path, plain, negated, through get(), nested, and built from the request.
  { id: "coll-exists", ruleset: "core", expr: `exists(${DOCS}/fsr8-ctl)` },
  { id: "coll-not-exists", ruleset: "core", expr: `!exists(${DOCS}/fsr8-ctl)` },
  { id: "coll-get-null", ruleset: "core", expr: `get(${DOCS}/fsr8-ctl) == null` },
  { id: "nested-coll-not-exists", ruleset: "core", expr: `!exists(${DOCS}/fsr8-ctl/real/sub)` },
  { id: "dyn-coll-not-exists", ruleset: "core", expr: `!exists(${DOCS}/$(id))` },
  // Another database.
  { id: "other-exists", ruleset: "other-database", expr: `exists(${OTHER})` },
  { id: "other-not-exists", ruleset: "other-database", expr: `!exists(${OTHER})` },
  { id: "other-get-null", ruleset: "other-database", expr: `get(${OTHER}) == null` },
  // The literal `(default)` is this database: a positive control and a negated missing one.
  {
    id: "default-literal-exists",
    ruleset: "default-literal",
    expr: "exists(/databases/(default)/documents/fsr8-ctl/real)",
  },
  {
    id: "default-literal-missing-not-exists",
    ruleset: "default-literal",
    expr: "!exists(/databases/(default)/documents/fsr8-ctl/absent)",
  },
  // A path with no `/documents` segment.
  { id: "nodocs-exists", ruleset: "no-documents", expr: `exists(${NO_DOCS})` },
  { id: "nodocs-not-exists", ruleset: "no-documents", expr: `!exists(${NO_DOCS})` },
  { id: "nodocs-get-null", ruleset: "no-documents", expr: `get(${NO_DOCS}) == null` },
];

const badPathRulesetId = (name) => `bad-path-${name}`;

/** Ruleset id to its version and rule body (always version 2: the control the rows run under). */
export const BAD_PATH_RULESETS = {};
for (const { id, ruleset, expr } of BAD_PATH_CASES) {
  const entry = (BAD_PATH_RULESETS[badPathRulesetId(ruleset)] ??= { version: 2, body: [] });
  entry.body.push(`    match /fsr8-${id}/{id} {`, `      allow get: if ${expr};`, "    }");
}
export const BAD_PATH_RULESET_IDS = Object.keys(BAD_PATH_RULESETS);

const BAD_PATH_SEED = [{ doc: "fsr8-ctl/real", fields: { n: { integerValue: "1" } } }];

export const BAD_PATH_PROGRAMS = BAD_PATH_RULESET_IDS.map((ruleset) => ({
  id: `fs-rules-v1/bad-path/${ruleset.slice("bad-path-".length)}`,
  ruleset,
  seed: BAD_PATH_SEED,
  steps: [
    { id: "publishes", publish: true },
    ...BAD_PATH_CASES.filter((c) => badPathRulesetId(c.ruleset) === ruleset).map((c) => ({
      id: c.id,
      as: "none",
      rpc: "get",
      doc: `fsr8-${c.id}/${c.docId ?? "x"}`,
    })),
  ],
}));

// ---- FS-RULES: five differences from the official emulator -------------------------------------
//
// Five Rules behaviours on which fireemu and the official Firestore emulator are claimed to differ
// (the rules-diffs lane report). Each case is the smallest set of rows with an allowed and a
// refused control, so one answer separates "the rule raised" from "the rule was false". Rows are
// REST reads: a get of a missing document (allowed: 404, refused: 403) or a runQuery (allowed: 200,
// refused: 403). The rulesets whose syntax is uncertain (a top-level function, a lone-surrogate
// escape, string indexing) are alone in their program, because production accepts or refuses a
// ruleset as a whole and a refusal is recorded as such. One anonymous principal makes the queries;
// `UID(anon)` is its uid in a seed or a request, resolved by the run.

const FIRE = "é\u{1F525}x"; // e-acute, fire (a surrogate pair in UTF-16), x

const rule = (kind, collection, condition) => [
  `    match /${collection}/{id} {`,
  `      allow ${kind}: if ${condition};`,
  "    }",
];

/** String-indexing cases: id, expression (a `get` of `fsr9-s-<id>/x`). */
const STRING_INDEX_CASES = [
  ["ascii-ctl", '"abc"[1] == "b"'],
  ["idx0", `"${FIRE}"[0] == "é"`],
  ["idx1-fire", `"${FIRE}"[1] == "\u{1F525}"`],
  ["idx2-x", `"${FIRE}"[2] == "x"`],
  ["idx3-x", `"${FIRE}"[3] == "x"`],
  ["idx4-eq-x", `"${FIRE}"[4] == "x"`],
  ["idx4-not-eq", `!("${FIRE}"[4] == "x")`],
  ["size-4", `"${FIRE}".size() == 4`],
  ["size-3", `"${FIRE}".size() == 3`],
];
/** Escapes written in the rule source itself (a lone high surrogate), alone in case production refuses. */
const STRING_ESCAPE_CASES = [
  ["esc-high", `"${FIRE}"[1] == "\\ud83d"`],
  ["esc-ctl", `"\\u00e9" == "é"`],
];

const ROLES = '["ADMIN","MEMBER"]';
const functionRules = (prefix, names) =>
  names.flatMap((name, i) =>
    rule("get", `fsr9-${prefix}-${i === 0 ? "true" : "false"}`, `${name}()`),
  );
const functionDeclarations = (indent, functions) =>
  functions.flatMap(([name, value]) => [
    `${indent}function ${name}() {`,
    `${indent}  return ${value};`,
    `${indent}}`,
  ]);

export const DIFFS_RULESETS = {
  "diffs-queries": {
    version: 2,
    body: [
      ...rule("list", "fsr9-owner", "resource.data.owner == request.auth.uid"),
      ...rule(
        "list",
        "fsr9-m-guarded",
        `resource != null && resource.data.members[request.auth.uid].role in ${ROLES}`,
      ),
      ...rule(
        "list",
        "fsr9-m-unguarded",
        `resource.data.members[request.auth.uid].role in ${ROLES}`,
      ),
      ...rule("list", "fsr9-m-bare", "resource != null"),
      ...rule("list", "fsr9-blocked", '!("blocked" in resource.data)'),
      ...rule("list", "fsr9-has-owner", '"owner" in resource.data'),
    ],
  },
  "diffs-string-index": {
    version: 2,
    body: STRING_INDEX_CASES.flatMap(([id, expr]) => rule("get", `fsr9-s-${id}`, expr)),
  },
  "diffs-string-escape": {
    version: 2,
    body: STRING_ESCAPE_CASES.flatMap(([id, expr]) => rule("get", `fsr9-s-${id}`, expr)),
  },
  // The functions are declared after rules_version and before service.
  "diffs-fn-top": {
    version: 2,
    preamble: functionDeclarations("", [
      ["topTrue", "true"],
      ["topFalse", "false"],
    ]),
    body: functionRules("fn-top", ["topTrue", "topFalse"]),
  },
  // Control: the same functions inside the match.
  "diffs-fn-inner": {
    version: 2,
    body: [
      ...functionDeclarations("    ", [
        ["innerTrue", "true"],
        ["innerFalse", "false"],
      ]),
      ...functionRules("fn-inner", ["innerTrue", "innerFalse"]),
    ],
  },
};
export const DIFFS_RULESET_IDS = Object.keys(DIFFS_RULESETS);

const field = (fieldPath, op, value) => ({ fieldFilter: { field: { fieldPath }, op, value } });
const both = (...filters) => ({ compositeFilter: { op: "AND", filters } });
const OWNER_IS_ME = field("owner", "EQUAL", { stringValue: "UID(anon)" });
const NAME = (doc) => field("__name__", "EQUAL", { referenceValue: `{docs}/fsr9-owner/${doc}` });
const roleIn = (...roles) =>
  field("members.`UID(anon)`.role", "IN", {
    arrayValue: { values: roles.map((stringValue) => ({ stringValue })) },
  });

const listRow = (id, collection, where) => ({
  id,
  as: "anon",
  rpc: "runQuery",
  body: { structuredQuery: { from: [{ collectionId: collection }], ...(where ? { where } : {}) } },
});
const getRow = (collection, id) => ({ id, as: "none", rpc: "get", doc: `${collection}/x` });

const member = (role) => ({
  members: {
    mapValue: {
      fields: { "UID(anon)": { mapValue: { fields: { role: { stringValue: role } } } } },
    },
  },
});

const diffsProgram = (name, steps, seed = []) => ({
  id: `fs-rules-v1/diffs/${name}`,
  ruleset: `diffs-${name}`,
  seed,
  steps: [{ id: "publishes", publish: true }, ...steps],
});

export const DIFFS_PROGRAMS = [
  diffsProgram(
    "queries",
    [
      // Case 1: a query constrained by owner and by documentId().
      listRow("owner-alone", "fsr9-owner", OWNER_IS_ME),
      listRow("owner-and-name-missing", "fsr9-owner", both(OWNER_IS_ME, NAME("missing"))),
      listRow("owner-and-name-foreign", "fsr9-owner", both(OWNER_IS_ME, NAME("foreign"))),
      listRow("owner-and-name-own", "fsr9-owner", both(OWNER_IS_ME, NAME("mine"))),
      listRow("name-missing-alone", "fsr9-owner", NAME("missing")),
      listRow("name-foreign-alone", "fsr9-owner", NAME("foreign")),
      // Case 2: a map-keyed role test, with and without the `resource != null` guard.
      listRow("members-guarded-in", "fsr9-m-guarded", roleIn("ADMIN", "MEMBER")),
      listRow("members-guarded-in-viewer", "fsr9-m-guarded", roleIn("VIEWER")),
      listRow("members-unguarded-in", "fsr9-m-unguarded", roleIn("ADMIN", "MEMBER")),
      listRow("members-bare-nofilter", "fsr9-m-bare"),
      // Case 5: a negated `in` over resource.data, and the plain `in` as controls.
      listRow("blocked-nofilter", "fsr9-blocked"),
      listRow("has-owner-nofilter", "fsr9-has-owner"),
      listRow(
        "has-owner-filtered",
        "fsr9-has-owner",
        field("owner", "EQUAL", { stringValue: "o1" }),
      ),
    ],
    [
      { doc: "fsr9-owner/mine", fields: { owner: { stringValue: "UID(anon)" } } },
      { doc: "fsr9-owner/foreign", fields: { owner: { stringValue: "other-owner" } } },
      { doc: "fsr9-m-guarded/g1", fields: member("ADMIN") },
      { doc: "fsr9-m-unguarded/u1", fields: member("ADMIN") },
      { doc: "fsr9-m-bare/b1", fields: member("ADMIN") },
      { doc: "fsr9-blocked/p1", fields: { n: { integerValue: "1" } } },
      { doc: "fsr9-has-owner/h1", fields: { owner: { stringValue: "o1" } } },
    ],
  ),
  // Case 3: string indexing by UTF-16 code unit or by scalar.
  diffsProgram(
    "string-index",
    STRING_INDEX_CASES.map(([id]) => getRow(`fsr9-s-${id}`, id)),
  ),
  diffsProgram(
    "string-escape",
    STRING_ESCAPE_CASES.map(([id]) => getRow(`fsr9-s-${id}`, id)),
  ),
  // Case 4: functions declared at top level, outside `service`; then the control inside it.
  diffsProgram("fn-top", [
    getRow("fsr9-fn-top-true", "fn-top-true"),
    getRow("fsr9-fn-top-false", "fn-top-false"),
  ]),
  diffsProgram("fn-inner", [
    getRow("fsr9-fn-inner-true", "fn-inner-true"),
    getRow("fsr9-fn-inner-false", "fn-inner-false"),
  ]),
];

// ---- FS-RULES: shapes decided without a production row ------------------------------------------
//
// The fixes that followed the differences recording (string indexing by UTF-16 unit, top-level
// functions, query authorization with named documents and unconstrained `in`) decided some shapes
// that no row recorded. This family records exactly those, each case beside an allowed and a
// refused control in the same ruleset: string ranges and string functions over a supplementary
// character and over a lone high-surrogate escape; a top-level function shadowed inside the
// service and a function declared after it; query authorization with names, OR branches, limits
// and cursors; membership, keys(), size() and get() on the query resource; a collection-group
// query with a negated `in`. Rows are REST reads as in the differences family. The string and the
// function rulesets each stand alone, because production accepts or refuses a ruleset as a whole.

/**
 * A lone high surrogate written as an escape in the rule source, and the replacement character. A
 * character after the escape is never a hex digit, so the escape cannot be read as longer.
 */
const HI = "\\ud83d";
const FFFD = "\\ufffd";
const PAIR = "\u{1F525}";
const UPPER = `A${PAIR}X`;
const LOWER = `a${PAIR}x`;

/** String ranges, lower() and upper(): id, expression (a `get` of `fsr9-t-<id>/x`). */
const SHAPES_STRING_CASES = [
  ["rng-ctl-true", '"abc"[0:2] == "ab"'],
  ["rng-ctl-false", '"abc"[0:2] == "abc"'],
  ["rng-02", `"${FIRE}"[0:2] == "é${PAIR}"`],
  ["rng-03", `"${FIRE}"[0:3] == "é${PAIR}"`],
  ["rng-13", `"${FIRE}"[1:3] == "${PAIR}"`],
  ["rng-34", `"${FIRE}"[3:4] == "x"`],
  ["rng-12-size", `"${FIRE}"[1:2].size() == 1`],
  ["rng-hi", `"a${HI}z"[1:2] == "${HI}"`],
  ["low-ctl-true", '"ABC".lower() == "abc"'],
  ["low-ctl-false", '"ABC".lower() == "ABC"'],
  ["low-fire", `"${UPPER}".lower() == "${LOWER}"`],
  ["low-fire-size", `"${UPPER}".lower().size() == 4`],
  ["low-hi", `"A${HI}".lower() == "a${HI}"`],
  ["low-hi-size", `"A${HI}".lower().size() == 2`],
  ["up-ctl-true", '"abc".upper() == "ABC"'],
  ["up-ctl-false", '"abc".upper() == "abc"'],
  ["up-fire", `"${LOWER}".upper() == "${UPPER}"`],
  ["up-hi", `"a${HI}".upper() == "A${HI}"`],
  ["hi-size", `"${HI}".size() == 1`],
  ["hi-self", `"${HI}" == "${HI}"`],
  ["hi-fffd", `"${HI}" == "${FFFD}"`],
];

/** split(), replace() and matches(), whose arguments are regular expressions. */
const SHAPES_REGEX_CASES = [
  ["split-ctl-true", '"a,b".split(",").size() == 2'],
  ["split-ctl-false", '"a,b".split(",").size() == 3'],
  ["split-fire", `"a${PAIR}b".split("${PAIR}").size() == 2`],
  ["split-fire-by-hi", `"a${PAIR}b".split("${HI}").size() == 2`],
  ["split-fire-by-hi-1", `"a${PAIR}b".split("${HI}").size() == 1`],
  ["split-hi", `"a${HI}z".split("${HI}").size() == 2`],
  ["rep-ctl-true", '"abc".replace("b", "x") == "axc"'],
  ["rep-ctl-false", '"abc".replace("b", "x") == "abc"'],
  ["rep-fire", `"a${PAIR}b".replace("${PAIR}", "x") == "axb"`],
  ["rep-dot-fire", `"${PAIR}".replace(".", "x") == "x"`],
  ["rep-dot-fire-xx", `"${PAIR}".replace(".", "x") == "xx"`],
  ["rep-hi", `"a${HI}z".replace("${HI}", "x") == "axz"`],
  ["m-ctl-true", '"abc".matches("a.c")'],
  ["m-ctl-false", '"abc".matches("a.")'],
  ["m-dot-fire", `"${PAIR}".matches(".")`],
  ["m-dotdot-fire", `"${PAIR}".matches("..")`],
  ["m-hi-dot", `"${HI}".matches(".")`],
  ["m-hi-lit", `"a${HI}".matches("a${HI}")`],
];

/** Query rules: collection, condition (`{path=**}/` before the collection for a group rule). */
const SHAPES_QUERY_RULES = [
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
];

export const SHAPES_RULESETS = {
  "shapes-queries": {
    version: 2,
    body: SHAPES_QUERY_RULES.flatMap(([collection, condition]) =>
      rule("list", collection, condition),
    ),
  },
  "shapes-strings": {
    version: 2,
    body: SHAPES_STRING_CASES.flatMap(([id, expr]) => rule("get", `fsr9-t-${id}`, expr)),
  },
  "shapes-regex": {
    version: 2,
    body: SHAPES_REGEX_CASES.flatMap(([id, expr]) => rule("get", `fsr9-t-${id}`, expr)),
  },
  // pick() is declared at top level and again, with the other answer, inside the match.
  "shapes-fn-shadow": {
    version: 2,
    preamble: functionDeclarations("", [
      ["pick", "false"],
      ["topOnly", "true"],
    ]),
    body: [
      ...functionDeclarations("    ", [
        ["pick", "true"],
        ["innerOnly", "false"],
      ]),
      ...rule("get", "fsr9-fs-pick", "pick()"),
      ...rule("get", "fsr9-fs-top-only", "topOnly()"),
      ...rule("get", "fsr9-fs-inner-only", "innerOnly()"),
    ],
  },
  // The functions are declared after the closing brace of service.
  "shapes-fn-after": {
    version: 2,
    body: functionRules("fa", ["afterTrue", "afterFalse"]),
    postamble: functionDeclarations("", [
      ["afterTrue", "true"],
      ["afterFalse", "false"],
    ]),
  },
};
export const SHAPES_RULESET_IDS = Object.keys(SHAPES_RULESETS);

const either = (...filters) => ({ compositeFilter: { op: "OR", filters } });
const ME = field("owner", "EQUAL", { stringValue: "UID(anon)" });
const named = (doc) => field("__name__", "EQUAL", { referenceValue: `{docs}/fsr9-q-owner/${doc}` });
const A_IS_1 = field("a", "EQUAL", { integerValue: "1" });
const META_A_IS_1 = field("meta.a", "EQUAL", { integerValue: "1" });

const queryRow = (id, from, where, extra = {}) => ({
  id,
  as: "anon",
  rpc: "runQuery",
  body: { structuredQuery: { from: [from], ...(where ? { where } : {}), ...extra } },
});
const ownerRow = (id, where, extra) => queryRow(id, { collectionId: "fsr9-q-owner" }, where, extra);
/** A query of `collection` without a filter and with `filter`. */
const pairRows = (id, collection, filter) => [
  queryRow(`${id}-nofilter`, { collectionId: collection }),
  queryRow(`${id}-filtered`, { collectionId: collection }, filter),
];

const shapesProgram = (name, steps, seed = []) => ({
  id: `fs-rules-v1/shapes/${name}`,
  ruleset: `shapes-${name}`,
  seed,
  steps: [{ id: "publishes", publish: true }, ...steps],
});

const N1 = { n: { integerValue: "1" } };
const A1 = { a: { integerValue: "1" } };
const META_A1 = { meta: { mapValue: { fields: A1 } } };

export const SHAPES_PROGRAMS = [
  shapesProgram(
    "queries",
    [
      // Controls: the owner filter the rule proves, and a name the rule refuses.
      ownerRow("owner-alone", ME),
      ownerRow("name-foreign-alone", named("foreign")),
      // Named documents without the owner filter.
      ownerRow("name-own-alone", named("mine")),
      ownerRow("two-names-own", both(named("mine"), named("mine2"))),
      ownerRow("two-names-mixed", both(named("mine"), named("foreign"))),
      ownerRow("or-named-unnamed", either(named("mine"), ME)),
      ownerRow("or-foreign-unnamed", either(named("foreign"), ME)),
      ownerRow("own-plus-unproven", both(named("mine"), field("n", "EQUAL", N1.n))),
      // A name in an inequality (an equality on the name beside an inequality on another field
      // is INVALID_ARGUMENT in both emulators: "Equality on key is not allowed if there are other
      // inequality fields and key does not appear in inequalities").
      ownerRow(
        "name-own-range",
        both(
          field("__name__", "GREATER_THAN_OR_EQUAL", {
            referenceValue: "{docs}/fsr9-q-owner/mine",
          }),
          field("__name__", "LESS_THAN_OR_EQUAL", { referenceValue: "{docs}/fsr9-q-owner/mine" }),
        ),
      ),
      ownerRow("name-own-limit", named("mine"), { limit: 1 }),
      ownerRow("name-own-cursor", named("mine"), {
        orderBy: [{ field: { fieldPath: "__name__" }, direction: "ASCENDING" }],
        startAt: { values: [{ referenceValue: "{docs}/fsr9-q-owner/mine" }], before: true },
      }),
      // Membership, keys(), size() and get() on the query resource, without and with a filter.
      ...pairRows("nested-neg", "fsr9-q-nested-neg", META_A_IS_1),
      ...pairRows("nested-pos", "fsr9-q-nested-pos", META_A_IS_1),
      ...pairRows("keys-neg", "fsr9-q-keys-neg", A_IS_1),
      ...pairRows("keys-pos", "fsr9-q-keys-pos", A_IS_1),
      ...pairRows("size", "fsr9-q-size", A_IS_1),
      ...pairRows("get-neg", "fsr9-q-get-neg", A_IS_1),
      ...pairRows("get-pos", "fsr9-q-get-pos", A_IS_1),
      // A collection-group query under a negated `in`, its refused control and a plain query.
      queryRow("cg-blocked-group", { collectionId: "fsr9-q-cg", allDescendants: true }),
      queryRow("cg-has-group", { collectionId: "fsr9-q-cg-has", allDescendants: true }),
      queryRow("cg-blocked-single", { collectionId: "fsr9-q-cg" }),
    ],
    [
      { doc: "fsr9-q-owner/mine", fields: { owner: { stringValue: "UID(anon)" }, ...N1 } },
      { doc: "fsr9-q-owner/mine2", fields: { owner: { stringValue: "UID(anon)" }, ...N1 } },
      { doc: "fsr9-q-owner/foreign", fields: { owner: { stringValue: "other-owner" }, ...N1 } },
      { doc: "fsr9-q-nested-neg/d1", fields: META_A1 },
      { doc: "fsr9-q-nested-pos/d1", fields: META_A1 },
      { doc: "fsr9-q-keys-neg/d1", fields: A1 },
      { doc: "fsr9-q-keys-pos/d1", fields: A1 },
      { doc: "fsr9-q-size/d1", fields: A1 },
      { doc: "fsr9-q-get-neg/d1", fields: A1 },
      { doc: "fsr9-q-get-pos/d1", fields: A1 },
      { doc: "fsr9-q-cg/c1", fields: N1 },
      { doc: "fsr9-q-x/y/fsr9-q-cg/c2", fields: N1 },
      { doc: "fsr9-q-cg-has/c1", fields: N1 },
    ],
  ),
  shapesProgram(
    "strings",
    SHAPES_STRING_CASES.map(([id]) => getRow(`fsr9-t-${id}`, id)),
  ),
  shapesProgram(
    "regex",
    SHAPES_REGEX_CASES.map(([id]) => getRow(`fsr9-t-${id}`, id)),
  ),
  shapesProgram("fn-shadow", [
    getRow("fsr9-fs-pick", "fn-shadow-pick"),
    getRow("fsr9-fs-top-only", "fn-shadow-top-only"),
    getRow("fsr9-fs-inner-only", "fn-shadow-inner-only"),
  ]),
  shapesProgram("fn-after", [
    getRow("fsr9-fa-true", "fn-after-true"),
    getRow("fsr9-fa-false", "fn-after-false"),
  ]),
];
