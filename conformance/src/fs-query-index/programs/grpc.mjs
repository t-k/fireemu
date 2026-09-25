// gRPC programs: representative cases of every query surface sent through google.firestore.v1
// instead of REST, compared with production's gRPC answers.

import { GROUP_SEED, NUMBERS_SEED, VECTOR_SEED } from "../datasets.mjs";
import {
  aggregate,
  and,
  arr,
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
  viaGrpc,
} from "../values.mjs";
import { INDEX_SEED } from "./indexes.mjs";
import { LARGE_PARTITION_SEED } from "./partition.mjs";

const g = (step) => viaGrpc(step, step.id);
const numbers = (structured = {}) => ({
  from: from("qn"),
  select: { fields: [field("n")] },
  ...structured,
});
const partition = (id, partitions, extra = {}) =>
  g({
    id,
    rpc: "partitionQuery",
    body: {
      structuredQuery: { from: from("qp", true), orderBy: [asc("__name__")] },
      partitionCount: String(partitions),
      ...extra,
    },
  });

export const GRPC_PROGRAMS = [
  {
    id: "fs-query-index/grpc/queries",
    seed: NUMBERS_SEED.concat(INDEX_SEED, GROUP_SEED, VECTOR_SEED),
    steps: [
      g(query("full-documents", { from: from("qn"), where: f("n", "EQUAL", int(2)) })),
      g(
        query(
          "or-filter",
          numbers({ where: or(f("g", "EQUAL", str("odd")), f("h", "EQUAL", int(0))) }),
        ),
      ),
      g(
        query(
          "descending-cursor",
          numbers({ orderBy: [desc("n")], startAt: cursor([int(6)], false) }),
        ),
      ),
      g(query("offset-and-limit", numbers({ offset: 3, limit: 2 }))),
      g(query("offset-past-end", numbers({ offset: 20 }))),
      g(query("empty-result", numbers({ where: f("g", "EQUAL", str("none")) }))),
      g(query("projection-empty", { from: from("qn"), select: { fields: [] }, limit: 2 })),
      g(query("collection-group", { from: from("qg", true), select: { fields: [field("n")] } })),
      g(query("negative-limit", numbers({ limit: -1 }))),
      g(
        query(
          "in-31",
          numbers({ where: f("n", "IN", arr(...Array.from({ length: 31 }, (_, i) => int(i)))) }),
        ),
      ),
      g(query("in-empty", numbers({ where: f("n", "IN", arr()) }))),
      g(
        query(
          "cursor-too-many-values",
          numbers({ orderBy: [asc("n")], startAt: cursor([int(1), int(2), int(3)], true) }),
        ),
      ),
      g(
        query("missing-index", {
          from: from("qx"),
          where: f("a", "EQUAL", int(1)),
          orderBy: [desc("b")],
        }),
      ),
      g(query("group-missing-index", { from: from("qg", true), where: f("n", "EQUAL", int(1)) })),
      g(
        query("merge", {
          from: from("qx"),
          where: and(f("a", "EQUAL", int(1)), f("b", "EQUAL", int(1))),
          select: { fields: [field("c")] },
        }),
      ),
      g(
        query("explain-plan", numbers({ where: f("g", "EQUAL", str("odd")) }), {
          body: { explainOptions: {} },
        }),
      ),
      g(
        query("explain-analyze", numbers({ where: f("g", "EQUAL", str("odd")) }), {
          body: { explainOptions: { analyze: true } },
        }),
      ),
      g(
        query(
          "explain-missing-index",
          { from: from("qx"), where: f("a", "EQUAL", int(1)), orderBy: [desc("b")] },
          { body: { explainOptions: {} } },
        ),
      ),
      g(
        query("nearest", {
          from: from("qvec"),
          select: { fields: [field("n")] },
          findNearest: {
            vectorField: field("emb"),
            queryVector: vec(1, 0, 0),
            distanceMeasure: "EUCLIDEAN",
            limit: 3,
            distanceResultField: "distance",
            distanceThreshold: 1.5,
          },
        }),
      ),
      g(
        query("nearest-limit-1001", {
          from: from("qvec"),
          findNearest: {
            vectorField: field("emb"),
            queryVector: vec(1, 0, 0),
            distanceMeasure: "EUCLIDEAN",
            limit: 1001,
          },
        }),
      ),
      g(
        aggregate("count-sum-avg", { from: from("qn") }, [
          count("c"),
          sum("n", "s"),
          avg("d", "a"),
        ]),
      ),
      g(aggregate("default-aliases", { from: from("qn") }, [count(), sum("n"), avg("n", "a")])),
      g(aggregate("duplicate-alias", { from: from("qn") }, [count("x"), sum("n", "x")])),
      g(aggregate("count-up-to", { from: from("qn") }, [count("c", 3)])),
      g(
        aggregate("explain-analyze-count", { from: from("qn") }, [count("c")], {
          body: { explainOptions: { analyze: true } },
        }),
      ),
      g(
        aggregate("sum-missing-index", { from: from("qx"), where: f("a", "EQUAL", int(1)) }, [
          sum("d", "s"),
        ]),
      ),
    ],
  },
  {
    id: "fs-query-index/grpc/read-time",
    seed: [],
    steps: [
      {
        id: "write-1",
        rpc: "commit",
        body: { writes: [{ update: { name: "{docs}/qt/t1", fields: { n: int(1) } } }] },
      },
      {
        id: "write-2",
        rpc: "commit",
        body: { writes: [{ update: { name: "{docs}/qt/t1", fields: { n: int(2) } } }] },
      },
      g(
        query(
          "at-write-1",
          { from: from("qt") },
          { body: { readTime: { $from: "write-1", path: "commitTime" } } },
        ),
      ),
      g(query("future", { from: from("qt") }, { body: { readTime: "2099-01-01T00:00:00Z" } })),
    ],
  },
  {
    id: "fs-query-index/grpc/partitions",
    seed: LARGE_PARTITION_SEED,
    steps: [
      partition("count-2", 2),
      partition("count-4-page-1", 4, { pageSize: 1 }),
      partition("count-4-page-2", 4, {
        pageSize: 1,
        pageToken: { $from: "count-4-page-1", path: "nextPageToken" },
      }),
      partition("count-0", 0),
    ],
  },
];
