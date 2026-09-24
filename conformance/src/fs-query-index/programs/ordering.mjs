// Ordering programs: orderBy, cursors, offset and limit, and projection.

import { NUMBERS_SEED, VALUES_SEED } from "../datasets.mjs";
import {
  and,
  arr,
  asc,
  cursor,
  desc,
  f,
  field,
  from,
  int,
  nul,
  query,
  ref,
  str,
  u,
} from "../values.mjs";

const names = { select: { fields: [field("n")] } };
const onNumbers = (id, structured) => query(id, { from: from("qn"), ...names, ...structured });
const onValues = (id, structured) => query(id, { from: from("qv"), ...names, ...structured });
const direction = (path, value) => ({ field: field(path), direction: value });

export const ORDERING_PROGRAMS = [
  {
    id: "fs-query-index/order-by/basic",
    seed: NUMBERS_SEED,
    steps: [
      onNumbers("default-order", {}),
      onNumbers("ascending", { orderBy: [asc("n")] }),
      onNumbers("descending", { orderBy: [desc("n")] }),
      onNumbers("direction-unspecified", { orderBy: [direction("n", "DIRECTION_UNSPECIFIED")] }),
      onNumbers("direction-omitted", { orderBy: [{ field: field("n") }] }),
      onNumbers("direction-unknown", { orderBy: [direction("n", "SIDEWAYS")] }),
      onNumbers("missing-field-excludes", { orderBy: [asc("opt")] }),
      onNumbers("nested-field", { orderBy: [asc("nested.b.c")] }),
      onNumbers("string-field", { orderBy: [asc("s")] }),
      onNumbers("double-field-descending", { orderBy: [desc("d")] }),
      onNumbers("array-field", { orderBy: [asc("tags")] }),
      onNumbers("map-field", { orderBy: [asc("nested")] }),
      onNumbers("two-fields", { orderBy: [asc("g"), desc("n")] }),
      onNumbers("two-fields-both-ascending", { orderBy: [asc("g"), asc("n")] }),
      onNumbers("name-ascending", { orderBy: [asc("__name__")] }),
      onNumbers("field-then-name-descending", { orderBy: [asc("n"), desc("__name__")] }),
      onNumbers("field-then-name-ascending", { orderBy: [desc("n"), asc("__name__")] }),
      onNumbers("field-after-name", { orderBy: [asc("__name__"), asc("n")] }),
      onNumbers("duplicate-field", { orderBy: [asc("n"), asc("n")] }),
      onNumbers("duplicate-field-opposite", { orderBy: [asc("n"), desc("n")] }),
      onNumbers("empty-field-path", { orderBy: [asc("")] }),
      onNumbers("order-without-field", { orderBy: [{ direction: "ASCENDING" }] }),
    ],
  },
  {
    id: "fs-query-index/order-by/with-filters",
    seed: NUMBERS_SEED,
    steps: [
      onNumbers("range-implies-order", { where: f("n", "GREATER_THAN", int(3)) }),
      onNumbers("range-then-other-order", {
        where: f("n", "GREATER_THAN", int(3)),
        orderBy: [asc("h")],
      }),
      onNumbers("range-with-explicit-order-first", {
        where: f("n", "GREATER_THAN", int(3)),
        orderBy: [asc("n"), asc("h")],
      }),
      onNumbers("range-with-explicit-order-second", {
        where: f("n", "GREATER_THAN", int(3)),
        orderBy: [asc("h"), asc("n")],
      }),
      onNumbers("range-descending", {
        where: f("n", "GREATER_THAN", int(3)),
        orderBy: [desc("n")],
      }),
      onNumbers("two-ranges-implied-order", {
        where: and(f("n", "GREATER_THAN", int(1)), f("h", "LESS_THAN", int(2))),
      }),
      onNumbers("two-ranges-explicit-order", {
        where: and(f("n", "GREATER_THAN", int(1)), f("h", "LESS_THAN", int(2))),
        orderBy: [desc("h")],
      }),
      onNumbers("equality-then-order-same-field", {
        where: f("n", "EQUAL", int(3)),
        orderBy: [asc("n")],
      }),
      onNumbers("equality-then-order-other", {
        where: f("g", "EQUAL", str("odd")),
        orderBy: [desc("n")],
      }),
      onNumbers("in-then-order-same-field", {
        where: f("n", "IN", arr(int(3), int(1))),
        orderBy: [desc("n")],
      }),
      onNumbers("not-equal-implies-order", { where: f("n", "NOT_EQUAL", int(3)) }),
      onNumbers("not-in-implies-order", { where: f("n", "NOT_IN", arr(int(3), int(4))) }),
      onNumbers("is-not-null-implies-order", { where: u("opt", "IS_NOT_NULL") }),
      onNumbers("name-range-implies-order", { where: f("__name__", "GREATER_THAN", ref("qn/d4")) }),
      onNumbers("name-range-descending", {
        where: f("__name__", "GREATER_THAN", ref("qn/d4")),
        orderBy: [desc("__name__")],
      }),
    ],
  },
  {
    id: "fs-query-index/order-by/value-types",
    seed: VALUES_SEED,
    steps: [
      onValues("all-types-ascending", { orderBy: [asc("v")] }),
      onValues("all-types-descending", { orderBy: [desc("v")] }),
      onValues("nested-quoted-field", { orderBy: [asc("`a.b`"), asc("n")] }),
    ],
  },
  {
    id: "fs-query-index/cursors/values",
    seed: NUMBERS_SEED,
    steps: [
      onNumbers("start-at", { orderBy: [asc("n")], startAt: cursor([int(3)], true) }),
      onNumbers("start-after", { orderBy: [asc("n")], startAt: cursor([int(3)], false) }),
      onNumbers("start-before-omitted", { orderBy: [asc("n")], startAt: cursor([int(3)]) }),
      onNumbers("end-at", { orderBy: [asc("n")], endAt: cursor([int(3)], false) }),
      onNumbers("end-before", { orderBy: [asc("n")], endAt: cursor([int(3)], true) }),
      onNumbers("end-before-omitted", { orderBy: [asc("n")], endAt: cursor([int(3)]) }),
      onNumbers("start-and-end", {
        orderBy: [asc("n")],
        startAt: cursor([int(2)], true),
        endAt: cursor([int(5)], false),
      }),
      onNumbers("start-past-end", {
        orderBy: [asc("n")],
        startAt: cursor([int(6)], true),
        endAt: cursor([int(2)], false),
      }),
      onNumbers("descending-start-at", { orderBy: [desc("n")], startAt: cursor([int(6)], true) }),
      onNumbers("descending-end-before", { orderBy: [desc("n")], endAt: cursor([int(2)], true) }),
      onNumbers("double-cursor-on-int-order", {
        orderBy: [asc("n")],
        startAt: cursor([{ doubleValue: 2.5 }], true),
      }),
      onNumbers("string-cursor-on-int-order", {
        orderBy: [asc("n")],
        startAt: cursor([str("a")], true),
      }),
      onNumbers("null-cursor", { orderBy: [asc("n")], startAt: cursor([nul()], true) }),
      onNumbers("prefix-cursor", {
        orderBy: [asc("g"), asc("n")],
        startAt: cursor([str("odd")], true),
      }),
      onNumbers("full-cursor-two-fields", {
        orderBy: [asc("g"), asc("n")],
        startAt: cursor([str("even"), int(4)], false),
      }),
      onNumbers("cursor-with-name-tiebreak", {
        orderBy: [asc("h")],
        startAt: cursor([int(1), ref("qn/d4")], false),
      }),
      onNumbers("cursor-empty-values", { orderBy: [asc("n")], startAt: cursor([], true) }),
      onNumbers("cursor-too-many-values", {
        orderBy: [asc("n")],
        startAt: cursor([int(1), ref("qn/d1"), int(3)], true),
      }),
      onNumbers("cursor-too-many-without-order", { startAt: cursor([ref("qn/d1"), int(3)], true) }),
      onNumbers("cursor-with-range-filter", {
        where: f("n", "GREATER_THAN", int(1)),
        startAt: cursor([int(4)], true),
      }),
      onNumbers("end-cursor-with-limit", {
        orderBy: [asc("n")],
        endAt: cursor([int(7)], false),
        limit: 3,
      }),
      onNumbers("cursor-with-offset", {
        orderBy: [asc("n")],
        startAt: cursor([int(2)], true),
        offset: 1,
        limit: 2,
      }),
      onNumbers("cursor-value-without-values-key", {
        orderBy: [asc("n")],
        startAt: { before: true },
      }),
    ],
  },
  {
    id: "fs-query-index/cursors/names",
    seed: NUMBERS_SEED,
    steps: [
      onNumbers("name-order-reference", {
        orderBy: [asc("__name__")],
        startAt: cursor([ref("qn/d3")], true),
      }),
      onNumbers("implicit-name-order-reference", { startAt: cursor([ref("qn/d3")], false) }),
      onNumbers("name-descending-reference", {
        orderBy: [desc("__name__")],
        startAt: cursor([ref("qn/d3")], false),
      }),
      onNumbers("name-reference-absent-document", {
        orderBy: [asc("__name__")],
        startAt: cursor([ref("qn/d35")], true),
      }),
      onNumbers("name-string-value", {
        orderBy: [asc("__name__")],
        startAt: cursor([str("d3")], true),
      }),
      onNumbers("name-string-full-path", {
        orderBy: [asc("__name__")],
        startAt: cursor([str("qn/d3")], true),
      }),
      onNumbers("name-integer-value", {
        orderBy: [asc("__name__")],
        startAt: cursor([int(3)], true),
      }),
      onNumbers("name-foreign-collection", {
        orderBy: [asc("__name__")],
        startAt: cursor([ref("qv/one")], true),
      }),
      onNumbers("name-subcollection-document", {
        orderBy: [asc("__name__")],
        startAt: cursor([ref("qn/d3/sub/x")], true),
      }),
      onNumbers("name-collection-reference", {
        orderBy: [asc("__name__")],
        startAt: cursor([ref("qn")], true),
      }),
      onNumbers("name-other-database", {
        orderBy: [asc("__name__")],
        startAt: cursor(
          [{ referenceValue: "projects/{project}/databases/other-db/documents/qn/d3" }],
          true,
        ),
      }),
      onNumbers("field-then-name-string", {
        orderBy: [asc("h")],
        startAt: cursor([int(1), str("d4")], false),
      }),
    ],
  },
  {
    id: "fs-query-index/offset-limit/all",
    seed: NUMBERS_SEED,
    steps: [
      onNumbers("limit-3", { limit: 3 }),
      onNumbers("limit-0", { limit: 0 }),
      onNumbers("limit-negative", { limit: -1 }),
      onNumbers("limit-string", { limit: "3" }),
      onNumbers("limit-wrapper-object", { limit: { value: 3 } }),
      onNumbers("limit-int32-max", { limit: 2147483647 }),
      onNumbers("limit-int32-overflow", { limit: 2147483648 }),
      onNumbers("limit-fraction", { limit: 1.5 }),
      onNumbers("offset-2", { offset: 2 }),
      onNumbers("offset-0", { offset: 0 }),
      onNumbers("offset-negative", { offset: -1 }),
      onNumbers("offset-past-end", { offset: 20 }),
      onNumbers("offset-equals-size", { offset: 10 }),
      onNumbers("offset-and-limit", { offset: 3, limit: 2 }),
      onNumbers("offset-and-limit-0", { offset: 3, limit: 0 }),
      onNumbers("offset-int32-max", { offset: 2147483647 }),
      onNumbers("offset-with-filter", { where: f("g", "EQUAL", str("odd")), offset: 1 }),
      onNumbers("offset-with-descending-order", { orderBy: [desc("n")], offset: 7 }),
      onNumbers("limit-to-last-wire-form", { orderBy: [desc("n")], limit: 3 }),
      onNumbers("offset-string", { offset: "2" }),
    ],
  },
  {
    id: "fs-query-index/projection/all",
    seed: NUMBERS_SEED,
    steps: [
      query("one-field", { from: from("qn"), select: { fields: [field("g")] }, limit: 2 }),
      query("two-fields", {
        from: from("qn"),
        select: { fields: [field("g"), field("n")] },
        limit: 2,
      }),
      query("nested-leaf", {
        from: from("qn"),
        select: { fields: [field("nested.b.c")] },
        limit: 2,
      }),
      query("nested-map", { from: from("qn"), select: { fields: [field("nested")] }, limit: 2 }),
      query("parent-and-child", {
        from: from("qn"),
        select: { fields: [field("nested"), field("nested.a")] },
        limit: 2,
      }),
      query("missing-field", { from: from("qn"), select: { fields: [field("absent")] }, limit: 2 }),
      query("partly-missing-field", {
        from: from("qn"),
        select: { fields: [field("opt")] },
        limit: 5,
      }),
      query("empty-list", { from: from("qn"), select: { fields: [] }, limit: 2 }),
      query("empty-select", { from: from("qn"), select: {}, limit: 2 }),
      query("name-only", { from: from("qn"), select: { fields: [field("__name__")] }, limit: 2 }),
      query("name-and-field", {
        from: from("qn"),
        select: { fields: [field("__name__"), field("n")] },
        limit: 2,
      }),
      query("duplicate-field", {
        from: from("qn"),
        select: { fields: [field("n"), field("n")] },
        limit: 2,
      }),
      query("invalid-path", { from: from("qn"), select: { fields: [field("a..b")] }, limit: 2 }),
      query("reserved-path", { from: from("qn"), select: { fields: [field("__x__")] }, limit: 2 }),
      query("order-by-unselected", {
        from: from("qn"),
        select: { fields: [field("g")] },
        orderBy: [desc("n")],
        limit: 3,
      }),
      query("filter-on-unselected", {
        from: from("qn"),
        select: { fields: [field("g")] },
        where: f("n", "LESS_THAN", int(3)),
      }),
      query("quoted-segment", {
        from: from("qn"),
        select: { fields: [field("`nested`.a")] },
        limit: 2,
      }),
    ],
  },
];
