// FS-3: Security Rules without `rules_version = '2'` (v1) and collection-group queries.
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
  const ruleset = RULESETS[rulesetId];
  if (!ruleset) throw new Error(`unknown ruleset ${rulesetId}`);
  return [
    ...(ruleset.version === 2 ? ["rules_version = '2';"] : []),
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
    .update(`${JSON.stringify(program)}\n${RULESET_TEXT}`)
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
    if (!RULESET_IDS.includes(p.ruleset)) throw new Error(`${p.id}: unknown ruleset ${p.ruleset}`);
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
