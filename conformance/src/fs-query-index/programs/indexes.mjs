// Index programs: which queries the configured indexes serve (automatic single-field indexes,
// composites, merges, `__name__` directions, collection-group scope, exemptions) and the exact
// refusal production returns when none does. The indexes are in fs-query-index.indexes.json.

import { GROUP_SEED } from "../datasets.mjs";
import {
  aggregate,
  and,
  arr,
  asc,
  count,
  desc,
  f,
  field,
  from,
  int,
  or,
  query,
  str,
  sum,
} from "../values.mjs";

export const INDEX_SEED = Array.from({ length: 6 }, (_, i) => [
  `qx/x${i}`,
  {
    a: int(i % 2),
    b: int(i % 3),
    c: int(i),
    d: int(5 - i),
    tags: arr(int(i % 2), int(2)),
    nx: int(i),
    s: str(`s${i}`),
  },
]).concat([
  ["qcg/y0", { a: int(0), b: int(1) }],
  ["qcg/y1", { a: int(1), b: int(0) }],
  ["qroot/r1/qcg/y2", { a: int(0), b: int(2) }],
  ["pk/p0", { a: int(1) }],
  ["items/i1", { n: int(1) }],
  ["qroot/r1/items/i2", { n: int(2) }],
]);

const names = { select: { fields: [field("c")] } };
const onIndexed = (id, structured, collection = "qx") =>
  query(id, { from: from(collection), ...names, ...structured });

export const INDEX_PROGRAMS = [
  {
    id: "fs-query-index/index-selection/automatic-and-merge",
    seed: INDEX_SEED,
    steps: [
      onIndexed("single-equality", { where: f("a", "EQUAL", int(1)) }),
      onIndexed("single-range-and-order", {
        where: f("c", "GREATER_THAN", int(2)),
        orderBy: [desc("c")],
      }),
      onIndexed("single-order-descending", { orderBy: [desc("c")] }),
      onIndexed("array-contains-alone", { where: f("tags", "ARRAY_CONTAINS", int(1)) }),
      onIndexed("two-equalities-merge", {
        where: and(f("a", "EQUAL", int(1)), f("b", "EQUAL", int(1))),
      }),
      onIndexed("three-equalities-merge", {
        where: and(f("a", "EQUAL", int(1)), f("b", "EQUAL", int(1)), f("s", "EQUAL", str("s1"))),
      }),
      onIndexed("equality-and-array-contains-merge", {
        where: and(f("a", "EQUAL", int(1)), f("tags", "ARRAY_CONTAINS", int(1))),
      }),
      onIndexed("equalities-with-order-merged", {
        where: and(f("a", "EQUAL", int(1)), f("b", "EQUAL", int(1))),
        orderBy: [asc("c")],
      }),
      onIndexed("equality-and-name-descending", {
        where: f("a", "EQUAL", int(1)),
        orderBy: [desc("__name__")],
      }),
      onIndexed("equality-and-name-ascending", {
        where: f("a", "EQUAL", int(1)),
        orderBy: [asc("__name__")],
      }),
      onIndexed("name-descending-alone", { orderBy: [desc("__name__")] }),
      onIndexed("name-descending-with-own-index", { orderBy: [desc("__name__")] }, "ord"),
      onIndexed("name-range-descending", {
        where: f("__name__", "GREATER_THAN", { referenceValue: "{docs}/qx/x1" }),
        orderBy: [desc("__name__")],
      }),
      onIndexed("in-merge", {
        where: and(f("a", "IN", arr(int(0), int(1))), f("b", "EQUAL", int(1))),
      }),
      onIndexed("or-of-single-fields", {
        where: or(f("a", "EQUAL", int(1)), f("c", "GREATER_THAN", int(4))),
      }),
    ],
  },
  {
    id: "fs-query-index/index-selection/composites",
    seed: INDEX_SEED,
    steps: [
      onIndexed("equality-then-order", { where: f("a", "EQUAL", int(1)), orderBy: [asc("b")] }),
      onIndexed("equality-then-order-descending-missing", {
        where: f("a", "EQUAL", int(1)),
        orderBy: [desc("b")],
      }),
      onIndexed("two-ranges", {
        where: and(f("a", "GREATER_THAN", int(0)), f("b", "GREATER_THAN", int(0))),
      }),
      onIndexed("two-ranges-order-reversed-missing", {
        where: and(f("a", "GREATER_THAN", int(0)), f("b", "GREATER_THAN", int(0))),
        orderBy: [asc("b")],
      }),
      onIndexed("two-orders", { orderBy: [asc("a"), asc("b")] }),
      onIndexed("two-orders-missing", { orderBy: [asc("b"), asc("a")] }),
      onIndexed("array-contains-and-order", {
        where: f("tags", "ARRAY_CONTAINS", int(1)),
        orderBy: [asc("b")],
      }),
      onIndexed("array-contains-and-order-missing", {
        where: f("tags", "ARRAY_CONTAINS", int(1)),
        orderBy: [asc("c")],
      }),
      onIndexed("equalities-with-order-one-missing", {
        where: and(f("a", "EQUAL", int(1)), f("d", "EQUAL", int(1))),
        orderBy: [asc("c")],
      }),
      onIndexed("equality-range-missing", {
        where: and(f("s", "EQUAL", str("s1")), f("c", "GREATER_THAN", int(0))),
      }),
      onIndexed("equality-and-name-range", {
        where: and(
          f("a", "EQUAL", int(1)),
          f("__name__", "GREATER_THAN", { referenceValue: "{docs}/qx/x1" }),
        ),
      }),
      onIndexed("range-and-name-order-descending", {
        where: f("c", "GREATER_THAN", int(1)),
        orderBy: [asc("c"), desc("__name__")],
      }),
      onIndexed("or-needing-composite", {
        where: or(
          and(f("a", "EQUAL", int(1)), f("c", "GREATER_THAN", int(1))),
          f("b", "EQUAL", int(2)),
        ),
      }),
      aggregate("sum-with-composite", { from: from("qx"), where: f("a", "EQUAL", int(1)) }, [
        sum("b", "s"),
      ]),
      aggregate("sum-missing-composite", { from: from("qx"), where: f("a", "EQUAL", int(1)) }, [
        sum("d", "s"),
      ]),
      aggregate(
        "count-missing-composite",
        { from: from("qx"), where: f("s", "EQUAL", str("s1")), orderBy: [asc("d")] },
        [count("n")],
      ),
    ],
  },
  {
    id: "fs-query-index/index-selection/scopes-and-exemptions",
    seed: INDEX_SEED.concat(GROUP_SEED),
    steps: [
      onIndexed("exempted-field-equality", { where: f("nx", "EQUAL", int(1)) }),
      onIndexed("exempted-field-order", { orderBy: [asc("nx")] }),
      onIndexed("wildcard-exempt-collection", { where: f("a", "EQUAL", int(1)) }, "pk"),
      query("group-field-without-group-index", {
        from: from("qg", true),
        where: f("n", "EQUAL", int(1)),
        select: { fields: [field("n")] },
      }),
      query("group-order-without-group-index", {
        from: from("qg", true),
        orderBy: [asc("n")],
        select: { fields: [field("n")] },
      }),
      query("group-order-descending-without-group-index", {
        from: from("qg", true),
        orderBy: [desc("n")],
        select: { fields: [field("n")] },
      }),
      query("group-array-contains-without-group-index", {
        from: from("qg", true),
        where: f("tags", "ARRAY_CONTAINS", int(1)),
        select: { fields: [field("n")] },
      }),
      query("group-scope-composite-for-group", {
        from: from("qcg", true),
        where: f("a", "EQUAL", int(0)),
        orderBy: [asc("b")],
      }),
      query("group-scope-composite-for-collection", {
        from: from("qcg"),
        where: f("a", "EQUAL", int(0)),
        orderBy: [asc("b")],
      }),
      query("collection-scope-composite-for-group", {
        from: from("qx", true),
        where: f("a", "EQUAL", int(1)),
        orderBy: [asc("b")],
      }),
      query("group-only-override-group-equality", {
        from: from("items", true),
        where: f("n", "EQUAL", int(1)),
      }),
      query("group-only-override-collection-equality", {
        from: from("items"),
        where: f("n", "EQUAL", int(1)),
      }),
      query("group-only-override-group-order", { from: from("items", true), orderBy: [asc("n")] }),
    ],
  },
];
