// Collection-group and collection-scope programs over `qg`, which appears at several depths next
// to collections with similar ids.

import { GROUP_SEED } from "../datasets.mjs";
import {
  aggregate,
  asc,
  count,
  cursor,
  desc,
  f,
  field,
  from,
  int,
  query,
  ref,
  str,
} from "../values.mjs";

const names = { select: { fields: [field("n")] } };
const group = (id, structured = {}, parent) =>
  query(id, { from: from("qg", true), ...names, ...structured }, parent ? { parent } : {});
const collection = (id, structured = {}, parent) =>
  query(id, { from: from("qg"), ...names, ...structured }, parent ? { parent } : {});

export const GROUP_PROGRAMS = [
  {
    id: "fs-query-index/collection-group/scopes",
    seed: GROUP_SEED,
    steps: [
      group("root-all-descendants"),
      group("parent-all-descendants", {}, "qroot/r1"),
      group("missing-parent-all-descendants", {}, "qroot/r3"),
      group("absent-parent-all-descendants", {}, "qroot/none"),
      group("deep-parent-all-descendants", {}, "qroot/r1/sub/s1"),
      collection("root-collection"),
      collection("parent-collection", {}, "qroot/r1"),
      collection("missing-parent-collection", {}, "qroot/r3"),
      collection("nested-same-id-collection", {}, "qroot/r1/qg/c1"),
      query("group-absent-id", { from: from("qnone", true), ...names }),
      query("kindless-root", { from: [{ allDescendants: true }], ...names }),
      query(
        "kindless-parent",
        { from: [{ allDescendants: true }], ...names },
        { parent: "qroot/r1" },
      ),
      query("kindless-without-descendants", { from: [{}], ...names }),
      query("kindless-with-filter", {
        from: [{ allDescendants: true }],
        where: f("n", "EQUAL", int(1)),
        ...names,
      }),
      query("kindless-name-order", {
        from: [{ allDescendants: true }],
        orderBy: [asc("__name__")],
        ...names,
      }),
      query("kindless-name-descending", {
        from: [{ allDescendants: true }],
        orderBy: [desc("__name__")],
        ...names,
      }),
    ],
  },
  {
    id: "fs-query-index/collection-group/queries",
    seed: GROUP_SEED,
    steps: [
      group("filter-with-group-index", { where: f("p", "EQUAL", str("r1")) }),
      group("order-with-group-index", { orderBy: [desc("p")] }),
      group("name-order", { orderBy: [asc("__name__")] }),
      group("name-descending", { orderBy: [desc("__name__")] }),
      group("name-range-prefix", {
        where: {
          compositeFilter: {
            op: "AND",
            filters: [
              f("__name__", "GREATER_THAN_OR_EQUAL", ref("qroot/r1")),
              f("__name__", "LESS_THAN", ref("qroot/r2")),
            ],
          },
        },
      }),
      group("name-equality", { where: f("__name__", "EQUAL", ref("qroot/r1/qg/c1")) }),
      group("name-in", {
        where: f("__name__", "IN", {
          arrayValue: { values: [ref("qg/top1"), ref("qroot/r2/qg/c3")] },
        }),
      }),
      group("name-equality-other-group", { where: f("__name__", "EQUAL", ref("qgx/x1")) }),
      group("full-reference-cursor", {
        orderBy: [asc("__name__")],
        startAt: cursor([ref("qroot/r1/qg/c2")], false),
      }),
      group("short-reference-cursor", {
        orderBy: [asc("__name__")],
        startAt: cursor([ref("qg/top2")], false),
      }),
      group("limit-and-offset", { orderBy: [asc("__name__")], offset: 2, limit: 3 }),
      group(
        "parent-name-range",
        { where: f("__name__", "GREATER_THAN", ref("qroot/r1/qg/c1")) },
        "qroot/r1",
      ),
      collection(
        "parent-collection-name-range",
        { where: f("__name__", "GREATER_THAN", ref("qroot/r1/qg/c1")) },
        "qroot/r1",
      ),
      collection(
        "parent-collection-foreign-name",
        { where: f("__name__", "EQUAL", ref("qg/top1")) },
        "qroot/r1",
      ),
      aggregate("count-group", { from: from("qg", true) }, [count("c")]),
      aggregate("count-group-under-parent", { from: from("qg", true) }, [count("c")], {
        parent: "qroot/r1",
      }),
    ],
  },
];
