// Request programs: queries at a read time, the REST request shape, and the Standard-edition
// refusal of pipeline execution.

import { NUMBERS_SEED } from "../datasets.mjs";
import { aggregate, asc, count, f, field, from, int, query, sum } from "../values.mjs";

const commit = (id, writes) => ({ id, rpc: "commit", body: { writes } });
const put = (path, n) => ({ update: { name: `{docs}/${path}`, fields: { n: int(n) } } });
const atWrite = (step) => ({ $from: step, path: "commitTime" });
const shifted = (step, shift) => ({ $time: { $from: step, path: "commitTime", ...shift } });
const timeline = { from: from("qt"), select: { fields: [field("n")] } };

const raw = (id, rawBody, extra = {}) => ({ id, rpc: "runQuery", rawBody, ...extra });

export const REQUEST_PROGRAMS = [
  {
    id: "fs-query-index/read-time/snapshots",
    seed: [],
    steps: [
      commit("write-1", [put("qt/t1", 1)]),
      commit("write-2", [put("qt/t1", 2), put("qt/t2", 20)]),
      query("current", timeline),
      query("at-write-1", timeline, { body: { readTime: atWrite("write-1") } }),
      query("at-write-2", timeline, { body: { readTime: atWrite("write-2") } }),
      aggregate("count-at-write-1", { from: from("qt") }, [count("c"), sum("n", "s")], {
        body: { readTime: atWrite("write-1") },
      }),
      aggregate("count-current", { from: from("qt") }, [count("c"), sum("n", "s")]),
      {
        id: "partition-at-write-1",
        rpc: "partitionQuery",
        body: {
          structuredQuery: { from: from("qt", true), orderBy: [asc("__name__")] },
          partitionCount: "2",
          readTime: atWrite("write-1"),
        },
      },
      query("one-microsecond-before-write-1", timeline, {
        body: { readTime: shifted("write-1", { addNanos: -1000 }) },
      }),
      query("nanosecond-after-write-1", timeline, {
        body: { readTime: shifted("write-1", { addNanos: 1 }) },
      }),
      query("59-minutes-before-write-1", timeline, {
        body: { readTime: shifted("write-1", { addSeconds: -3540 }) },
      }),
      query("61-minutes-before-write-1", timeline, {
        body: { readTime: shifted("write-1", { addSeconds: -3660 }) },
      }),
      query("future", timeline, { body: { readTime: "2099-01-01T00:00:00Z" } }),
      query("distant-past", timeline, { body: { readTime: "2020-01-01T00:00:00Z" } }),
      query("not-a-time", timeline, { body: { readTime: "yesterday" } }),
      aggregate("aggregation-future", { from: from("qt") }, [count("c")], {
        body: { readTime: "2099-01-01T00:00:00Z" },
      }),
    ],
  },
  {
    id: "fs-query-index/request-shape/rest",
    seed: NUMBERS_SEED,
    steps: [
      raw("body-empty-object", "{}"),
      raw("body-not-json", "not json"),
      raw("body-empty", ""),
      raw("body-array", "[]"),
      raw("body-truncated", '{"structuredQuery":'),
      raw("body-trailing-comma", '{"structuredQuery":{"from":[{"collectionId":"qn"}]},}'),
      raw("body-string", '"text"'),
      raw(
        "unknown-top-level-field",
        '{"structuredQuery":{"from":[{"collectionId":"qn"}],"limit":1},"extra":1}',
      ),
      raw(
        "unknown-structured-field",
        '{"structuredQuery":{"from":[{"collectionId":"qn"}],"limit":1,"extra":1}}',
      ),
      raw(
        "operator-lowercase",
        '{"structuredQuery":{"from":[{"collectionId":"qn"}],"where":{"fieldFilter":{"field":{"fieldPath":"n"},"op":"equal","value":{"integerValue":"1"}}}}}',
      ),
      raw(
        "operator-as-number",
        '{"structuredQuery":{"from":[{"collectionId":"qn"}],"where":{"fieldFilter":{"field":{"fieldPath":"n"},"op":5,"value":{"integerValue":"1"}}}}}',
      ),
      raw(
        "integer-value-as-number",
        '{"structuredQuery":{"from":[{"collectionId":"qn"}],"where":{"fieldFilter":{"field":{"fieldPath":"n"},"op":"EQUAL","value":{"integerValue":1}}}}}',
      ),
      query("structured-query-empty", {}),
      query("from-empty-array", { from: [] }),
      query("from-empty-collection-id", { from: [{ collectionId: "" }] }),
      query("from-slash-collection-id", { from: [{ collectionId: "a/b" }] }),
      query("from-reserved-collection-id", { from: [{ collectionId: "__x__" }] }),
      query("from-dot-collection-id", { from: [{ collectionId: "." }] }),
      query("from-collection-id-1500-bytes", { from: [{ collectionId: "q".repeat(1500) }] }),
      query("from-collection-id-1501-bytes", { from: [{ collectionId: "q".repeat(1501) }] }),
      query("from-two-selectors", { from: [{ collectionId: "qn" }, { collectionId: "qv" }] }),
      query("absent-parent-document", { from: from("qn") }, { parent: "qroot/none" }),
      {
        id: "parent-is-collection",
        rpc: "runQuery",
        path: "v1/{docs}/qn:runQuery",
        body: { structuredQuery: { from: from("qn") } },
      },
      {
        id: "parent-odd-depth",
        rpc: "runQuery",
        path: "v1/{docs}/qroot/r1/qg:runQuery",
        body: { structuredQuery: { from: from("qn") } },
      },
      { id: "aggregation-without-query", rpc: "runAggregationQuery", body: {} },
      {
        id: "aggregation-without-structured-query",
        rpc: "runAggregationQuery",
        body: { structuredAggregationQuery: { aggregations: [count("c")] } },
      },
      {
        id: "aggregation-unknown-field",
        rpc: "runAggregationQuery",
        rawBody:
          '{"structuredAggregationQuery":{"structuredQuery":{"from":[{"collectionId":"qn"}]},"aggregations":[{"alias":"c","count":{}}],"extra":1}}',
      },
      query("where-with-order-only-filter", {
        from: from("qn"),
        where: f("n", "EQUAL", int(1)),
        orderBy: [asc("n")],
      }),
    ],
  },
  {
    id: "fs-query-index/pipeline/standard-refusal",
    seed: NUMBERS_SEED,
    steps: [
      {
        id: "collection-stage",
        rpc: "executePipeline",
        body: {
          structuredPipeline: {
            pipeline: { stages: [{ name: "collection", args: [{ referenceValue: "/qn" }] }] },
          },
        },
      },
      { id: "empty-body", rpc: "executePipeline", body: {} },
      {
        id: "unknown-stage",
        rpc: "executePipeline",
        body: { structuredPipeline: { pipeline: { stages: [{ name: "no_such_stage" }] } } },
      },
      {
        id: "collection-stage-grpc",
        rpc: "executePipeline",
        transport: "grpc",
        body: {
          structuredPipeline: {
            pipeline: { stages: [{ name: "collection", args: [{ referenceValue: "/qn" }] }] },
          },
        },
      },
    ],
  },
];
