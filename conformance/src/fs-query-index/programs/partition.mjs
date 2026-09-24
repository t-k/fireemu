// PartitionQuery programs: a small group production does not split, a 2,000-document group it
// does, page tokens, range reconstruction from the returned cursors, and every refusal.

import { aggregate, asc, count, desc, f, field, from, int, vec } from "../values.mjs";

const SMALL_SEED = Array.from({ length: 5 }, (_, i) => [`qroot/r${i % 2}/qp/s${i}`, { n: int(i) }]);

/** 2,000 small documents spread over three parents, named like the exploration that split. */
export const LARGE_PARTITION_SEED = Array.from({ length: 2000 }, (_, i) => [
  `qroot/r${i % 3}/qp/d${String(i).padStart(5, "0")}`,
  { n: int(i) },
]);

const groupByName = (extra = {}) => ({
  from: from("qp", true),
  orderBy: [asc("__name__")],
  ...extra,
});

const partition = (id, partitions, { structured = groupByName(), parent, ...extra } = {}) => ({
  id,
  rpc: "partitionQuery",
  ...(parent ? { parent } : {}),
  body: {
    structuredQuery: structured,
    ...(partitions === undefined ? {} : { partitionCount: String(partitions) }),
    ...extra,
  },
});

const cursorFrom = (step, index, before = true) => ({
  values: { $from: step, path: `partitions.${index}.values` },
  before,
});

/** The size of one partition range, for reconstruction (the ranges must add up to 2,000). */
const range = (id, { start, end }) =>
  aggregate(
    id,
    groupByName({ ...(start ? { startAt: start } : {}), ...(end ? { endAt: end } : {}) }),
    [count("c")],
  );

export const PARTITION_PROGRAMS = [
  {
    id: "fs-query-index/partition-query/small-group",
    seed: SMALL_SEED,
    steps: [
      partition("count-1", 1),
      partition("count-2", 2),
      partition("count-64", 64),
      partition("count-2-page-size-1", 2, { pageSize: 1 }),
      partition("without-order", 2, { structured: { from: from("qp", true) } }),
      partition("document-parent", 2, { parent: "qroot/r1" }),
      partition("absent-group", 2, {
        structured: { from: from("qnone", true), orderBy: [asc("__name__")] },
      }),
    ],
  },
  {
    id: "fs-query-index/partition-query/refusals",
    seed: SMALL_SEED,
    steps: [
      partition("count-0", 0),
      partition("count-negative", -1),
      partition("count-missing", undefined),
      partition("page-size-negative", 2, { pageSize: -1 }),
      partition("page-token-garbage", 2, { pageToken: "not-a-token" }),
      partition("not-collection-group", 2, {
        structured: { from: from("qp"), orderBy: [asc("__name__")] },
      }),
      partition("with-filter", 2, {
        structured: groupByName({ where: f("n", "GREATER_THAN", int(0)) }),
      }),
      partition("with-limit", 2, { structured: groupByName({ limit: 10 }) }),
      partition("with-offset", 2, { structured: groupByName({ offset: 1 }) }),
      partition("with-select", 2, {
        structured: groupByName({ select: { fields: [field("n")] } }),
      }),
      partition("order-by-field", 2, {
        structured: { from: from("qp", true), orderBy: [asc("n")] },
      }),
      partition("order-by-name-descending", 2, {
        structured: { from: from("qp", true), orderBy: [desc("__name__")] },
      }),
      partition("with-start-cursor", 2, {
        structured: groupByName({
          startAt: { values: [{ referenceValue: "{docs}/qroot/r0/qp/s0" }], before: true },
        }),
      }),
      partition("with-find-nearest", 2, {
        structured: {
          from: from("qp", true),
          findNearest: {
            vectorField: field("e"),
            queryVector: vec(1, 0),
            distanceMeasure: "EUCLIDEAN",
            limit: 2,
          },
        },
      }),
      partition("kindless", 2, {
        structured: { from: [{ allDescendants: true }], orderBy: [asc("__name__")] },
      }),
      { id: "structured-query-missing", rpc: "partitionQuery", body: { partitionCount: "2" } },
    ],
  },
  {
    id: "fs-query-index/partition-query/large-group",
    seed: LARGE_PARTITION_SEED,
    steps: [
      partition("count-1", 1),
      partition("count-2", 2),
      partition("count-3", 3),
      partition("count-8", 8),
      partition("count-64", 64),
      partition("count-8-repeat", 8),
      partition("count-4-page-1", 4, { pageSize: 1 }),
      partition("count-4-page-2", 4, {
        pageSize: 1,
        pageToken: { $from: "count-4-page-1", path: "nextPageToken" },
      }),
      partition("count-4-page-size-3", 4, { pageSize: 3 }),
      partition("count-4-page-size-3-next", 4, {
        pageSize: 3,
        pageToken: { $from: "count-4-page-size-3", path: "nextPageToken" },
      }),
      partition("token-with-other-count", 8, {
        pageSize: 1,
        pageToken: { $from: "count-4-page-1", path: "nextPageToken" },
      }),
      partition("without-order", 3, { structured: { from: from("qp", true) } }),
      partition("document-parent", 4, { parent: "qroot/r1" }),
      range("range-0", { end: cursorFrom("count-3", 0) }),
      range("range-1", { start: cursorFrom("count-3", 0), end: cursorFrom("count-3", 1) }),
      range("range-2", { start: cursorFrom("count-3", 1), end: cursorFrom("count-3", 2) }),
      range("range-3", { start: cursorFrom("count-3", 2) }),
    ],
  },
];
