// Explain programs: plan-only and analyzed Explain for queries and aggregations over automatic,
// composite, merged and collection-group indexes, and for refused queries.

import { NUMBERS_SEED, VECTOR_SEED } from "../datasets.mjs";
import {
  aggregate,
  and,
  asc,
  avg,
  count,
  cursor,
  desc,
  f,
  field,
  from,
  int,
  or,
  query,
  str,
  sum,
  vec,
} from "../values.mjs";
import { INDEX_SEED } from "./indexes.mjs";

const PLAN = { explainOptions: {} };
const ANALYZE = { explainOptions: { analyze: true } };

/** The same query as plan-only and analyzed Explain steps. */
const both = (id, structured) => [
  query(`${id}-plan`, structured, { body: PLAN }),
  query(`${id}-analyze`, structured, { body: ANALYZE }),
];
const bothAggregate = (id, structured, aggregations) => [
  aggregate(`${id}-plan`, structured, aggregations, { body: PLAN }),
  aggregate(`${id}-analyze`, structured, aggregations, { body: ANALYZE }),
];

const numbers = (structured = {}) => ({
  from: from("qn"),
  select: { fields: [field("n")] },
  ...structured,
});
const indexed = (structured = {}) => ({
  from: from("qx"),
  select: { fields: [field("c")] },
  ...structured,
});

export const EXPLAIN_PROGRAMS = [
  {
    id: "fs-query-index/explain/queries",
    seed: NUMBERS_SEED.concat(INDEX_SEED),
    steps: [
      ...both("full-scan", numbers()),
      ...both("equality", numbers({ where: f("g", "EQUAL", str("odd")) })),
      ...both(
        "range-descending",
        numbers({
          where: f("n", "GREATER_THAN", int(3)),
          orderBy: [desc("n")],
        }),
      ),
      ...both(
        "composite",
        numbers({
          where: and(f("g", "EQUAL", str("odd")), f("n", "GREATER_THAN", int(3))),
        }),
      ),
      ...both(
        "merge",
        indexed({
          where: and(f("a", "EQUAL", int(1)), f("b", "EQUAL", int(1))),
        }),
      ),
      ...both(
        "merge-with-order",
        indexed({
          where: and(f("a", "EQUAL", int(1)), f("b", "EQUAL", int(1))),
          orderBy: [asc("c")],
        }),
      ),
      ...both(
        "or",
        numbers({
          where: or(f("g", "EQUAL", str("odd")), f("h", "EQUAL", int(0))),
        }),
      ),
      ...both(
        "in",
        numbers({
          where: f("n", "IN", {
            arrayValue: { values: [int(1), int(4), int(7)] },
          }),
        }),
      ),
      ...both("not-equal", numbers({ where: f("n", "NOT_EQUAL", int(4)) })),
      ...both("array-contains", numbers({ where: f("tags", "ARRAY_CONTAINS", int(1)) })),
      ...both("empty-result", numbers({ where: f("g", "EQUAL", str("none")) })),
      ...both("limit", numbers({ orderBy: [asc("n")], limit: 3 })),
      ...both("limit-zero", numbers({ limit: 0 })),
      ...both("offset", numbers({ orderBy: [asc("n")], offset: 4, limit: 2 })),
      ...both("cursor", numbers({ orderBy: [asc("n")], startAt: cursor([int(6)], true) })),
      ...both(
        "name-descending",
        indexed({
          where: f("a", "EQUAL", int(1)),
          orderBy: [desc("__name__")],
        }),
      ),
      ...both("collection-group", {
        from: from("qn", true),
        select: { fields: [field("n")] },
      }),
      ...both("collection-group-composite", {
        from: from("qcg", true),
        where: f("a", "EQUAL", int(0)),
        orderBy: [asc("b")],
      }),
      ...both("missing-index", indexed({ where: f("a", "EQUAL", int(1)), orderBy: [desc("b")] })),
      ...both("invalid-query", numbers({ limit: -1 })),
      query("analyze-false", numbers({ where: f("g", "EQUAL", str("odd")) }), {
        body: { explainOptions: { analyze: false } },
      }),
      query("analyze-string", numbers(), {
        body: { explainOptions: { analyze: "true" } },
      }),
      query("options-unknown-field", numbers(), {
        body: { explainOptions: { verbose: true } },
      }),
      query(
        "full-documents-analyze",
        { from: from("qn"), where: f("n", "EQUAL", int(2)) },
        { body: ANALYZE },
      ),
    ],
  },
  {
    id: "fs-query-index/explain/aggregations",
    seed: NUMBERS_SEED.concat(INDEX_SEED),
    steps: [
      ...bothAggregate("count", { from: from("qn") }, [count("c")]),
      ...bothAggregate("count-filtered", { from: from("qn"), where: f("g", "EQUAL", str("odd")) }, [
        count("c"),
      ]),
      ...bothAggregate("count-up-to", { from: from("qn") }, [count("c", 3)]),
      ...bothAggregate("sum-avg", { from: from("qn") }, [sum("n", "s"), avg("d", "a")]),
      ...bothAggregate("sum-composite", { from: from("qx"), where: f("a", "EQUAL", int(1)) }, [
        sum("b", "s"),
      ]),
      ...bothAggregate("count-empty", { from: from("qn"), where: f("g", "EQUAL", str("none")) }, [
        count("c"),
      ]),
      ...bothAggregate("sum-missing-index", { from: from("qx"), where: f("a", "EQUAL", int(1)) }, [
        sum("d", "s"),
      ]),
    ],
  },
  {
    // Which member of an index merge production lists first: the one with fewer matching
    // entries, or the one on the later field. `a == 1` has 3 entries; `b == 1` gets 6.
    id: "fs-query-index/explain/merge-order",
    seed: INDEX_SEED.concat(
      Array.from({ length: 4 }, (_, i) => [`qx/m${i}`, { a: int(0), b: int(1), c: int(10 + i) }]),
    ),
    steps: [
      ...both(
        "larger-later-field",
        indexed({
          where: and(f("a", "EQUAL", int(1)), f("b", "EQUAL", int(1))),
          orderBy: [asc("c")],
        }),
      ),
      ...both(
        "larger-earlier-field",
        indexed({
          where: and(f("a", "EQUAL", int(0)), f("b", "EQUAL", int(2))),
          orderBy: [asc("c")],
        }),
      ),
      // The same merge with the filters in the other order, and merges of automatic indexes
      // (no composite starts with c, d or s), to tell request order from field order.
      ...both(
        "filters-reversed",
        indexed({
          where: and(f("b", "EQUAL", int(1)), f("a", "EQUAL", int(1))),
          orderBy: [asc("c")],
        }),
      ),
      ...both(
        "automatic-members",
        indexed({
          where: and(f("c", "EQUAL", int(1)), f("d", "EQUAL", int(4))),
        }),
      ),
      ...both(
        "automatic-members-reversed",
        indexed({
          where: and(f("d", "EQUAL", int(4)), f("c", "EQUAL", int(1))),
        }),
      ),
      ...both(
        "three-automatic-members",
        indexed({
          where: and(f("d", "EQUAL", int(4)), f("s", "EQUAL", str("s1")), f("c", "EQUAL", int(1))),
        }),
      ),
    ],
  },
  {
    id: "fs-query-index/explain/vector",
    seed: VECTOR_SEED,
    steps: [
      ...both("nearest", {
        from: from("qvec"),
        select: { fields: [field("n")] },
        findNearest: {
          vectorField: field("emb"),
          queryVector: vec(1, 0, 0),
          distanceMeasure: "EUCLIDEAN",
          limit: 3,
        },
      }),
      ...both("nearest-prefiltered", {
        from: from("qvec"),
        where: f("color", "EQUAL", str("red")),
        select: { fields: [field("n")] },
        findNearest: {
          vectorField: field("emb"),
          queryVector: vec(1, 0, 0),
          distanceMeasure: "COSINE",
          limit: 2,
        },
      }),
    ],
  },
];
