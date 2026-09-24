// Aggregation programs over `qa` and `qn`: count, sum and avg semantics, their options, aliases
// and refusals.

import { AGG_SEED, NUMBERS_SEED } from "../datasets.mjs";
import {
  aggregate,
  asc,
  avg,
  count,
  cursor,
  desc,
  f,
  field,
  from,
  int,
  str,
  sum,
} from "../values.mjs";

const onAgg = (id, aggregations, structured = {}) =>
  aggregate(id, { from: from("qa"), ...structured }, aggregations);
const onNumbers = (id, aggregations, structured = {}) =>
  aggregate(id, { from: from("qn"), ...structured }, aggregations);

export const AGGREGATION_PROGRAMS = [
  {
    id: "fs-query-index/aggregation/semantics",
    seed: AGG_SEED,
    steps: [
      onAgg("count-all", [count("c")]),
      onAgg("count-with-filter", [count("c")], { where: f("k", "EQUAL", str("x")) }),
      onAgg("count-empty-result", [count("c")], { where: f("k", "EQUAL", str("none")) }),
      onAgg("count-missing-collection", [count("c")], { from: from("qnone") }),
      onAgg("sum-integers", [sum("n", "s")]),
      onAgg("sum-doubles-with-nan", [sum("d", "s")]),
      onAgg("sum-mixed-types", [sum("mixed", "s")]),
      onAgg("sum-overflow", [sum("big", "s")]),
      onAgg("sum-infinities", [sum("neg", "s"), sum("d", "t")]),
      onAgg("sum-missing-field", [sum("absent", "s")]),
      onAgg("sum-empty-result", [sum("n", "s")], { where: f("k", "EQUAL", str("none")) }),
      onAgg("avg-integers", [avg("n", "a")]),
      onAgg("avg-doubles-with-nan", [avg("d", "a")]),
      onAgg("avg-mixed-types", [avg("mixed", "a")]),
      onAgg("avg-overflow-input", [avg("big", "a")]),
      onAgg("avg-empty-result", [avg("n", "a")], { where: f("k", "EQUAL", str("none")) }),
      onAgg("avg-missing-field", [avg("absent", "a")]),
      onAgg("count-sum-avg", [count("c"), sum("n", "s"), avg("n", "a")]),
      onAgg("count-beside-sum-over-missing", [count("c"), sum("d", "s")]),
      onAgg("count-beside-avg-over-missing", [count("c"), avg("d", "a")]),
      onAgg("sum-and-avg-different-fields", [sum("n", "s"), avg("d", "a")]),
      onAgg("sum-nested-field", [sum("m.x", "s")]),
      onAgg("same-aggregation-twice", [sum("n", "s1"), sum("n", "s2")]),
    ],
  },
  {
    id: "fs-query-index/aggregation/options",
    seed: NUMBERS_SEED,
    steps: [
      onNumbers("count-up-to", [count("c", 3)]),
      onNumbers("count-up-to-above-size", [count("c", 100)]),
      onNumbers("count-up-to-one", [count("c", 1)]),
      onNumbers("count-up-to-zero", [count("c", 0)]),
      onNumbers("count-up-to-negative", [count("c", -1)]),
      onNumbers("count-up-to-int64-max", [count("c", "9223372036854775807")]),
      onNumbers("count-with-limit", [count("c")], { limit: 4 }),
      onNumbers("count-with-offset", [count("c")], { offset: 7 }),
      onNumbers("count-with-offset-and-limit", [count("c")], { offset: 2, limit: 3 }),
      onNumbers("count-up-to-with-limit", [count("c", 2)], { limit: 4 }),
      onNumbers("count-with-cursor", [count("c")], {
        orderBy: [asc("n")],
        startAt: cursor([int(6)], true),
      }),
      onNumbers("count-with-order-on-missing", [count("c")], { orderBy: [asc("opt")] }),
      onNumbers("sum-with-order-on-missing", [sum("n", "s")], { orderBy: [asc("opt")] }),
      onNumbers("sum-with-limit", [sum("n", "s")], { limit: 3 }),
      onNumbers("sum-with-limit-and-order", [sum("n", "s")], { orderBy: [desc("n")], limit: 3 }),
      onNumbers("avg-with-offset", [avg("n", "a")], { offset: 5 }),
      onNumbers("sum-with-range-on-other-field", [sum("n", "s")], {
        where: f("d", "GREATER_THAN", { doubleValue: 1 }),
      }),
      onNumbers("count-with-select", [count("c")], { select: { fields: [field("n")] } }),
      onNumbers("cursor-too-many-values", [count("c")], {
        orderBy: [asc("n")],
        startAt: cursor([int(1), int(2)], true),
      }),
    ],
  },
  {
    id: "fs-query-index/aggregation/aliases-and-refusals",
    seed: NUMBERS_SEED,
    steps: [
      onNumbers("default-aliases", [count(), sum("n"), avg("n")]),
      onNumbers("default-aliases-around-named", [count("c"), sum("n"), avg("n", "a"), count()]),
      onNumbers("named-collides-with-default", [count(), sum("n", "field_1")]),
      onNumbers("named-field-2-with-one-default", [count(), sum("n", "field_2")]),
      onNumbers("duplicate-alias", [count("x"), sum("n", "x")]),
      onNumbers("alias-with-space", [count("a b")]),
      onNumbers("alias-with-dot", [count("a.b")]),
      onNumbers("alias-reserved", [count("__x__")]),
      onNumbers("alias-backquoted", [count("`a`")]),
      onNumbers("alias-empty", [{ alias: "", count: {} }]),
      onNumbers("alias-1500-bytes", [count("a".repeat(1500))]),
      onNumbers("alias-1501-bytes", [count("a".repeat(1501))]),
      onNumbers("five-aggregations", [
        count("a"),
        count("b"),
        sum("n", "c"),
        avg("n", "d"),
        sum("d", "e"),
      ]),
      onNumbers("six-aggregations", [
        count("a"),
        count("b"),
        sum("n", "c"),
        avg("n", "d"),
        sum("d", "e"),
        avg("d", "f"),
      ]),
      onNumbers("no-aggregations", []),
      onNumbers("aggregation-without-operator", [{ alias: "x" }]),
      onNumbers("sum-on-name", [sum("__name__", "s")]),
      onNumbers("avg-on-name", [avg("__name__", "a")]),
      onNumbers("sum-without-field", [{ alias: "s", sum: {} }]),
      onNumbers("sum-invalid-path", [sum("a..b", "s")]),
      onNumbers("sum-reserved-path", [sum("__x__", "s")]),
      onNumbers("alias-equal-to-field-name", [count("n")]),
    ],
  },
];
