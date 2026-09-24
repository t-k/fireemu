// Vector search programs over `qvec`: findNearest on the Standard edition with a flat
// 3-dimensional vector index and a color-prefiltered composite vector index.

import { VECTOR_SEED } from "../datasets.mjs";
import {
  aggregate,
  arr,
  asc,
  count,
  cursor,
  sum,
  dbl,
  f,
  field,
  from,
  int,
  query,
  str,
  vec,
} from "../values.mjs";

const nearest = (measure, extra = {}) => ({
  vectorField: field("emb"),
  queryVector: vec(1, 0, 0),
  distanceMeasure: measure,
  limit: 3,
  ...extra,
});
const search = (id, findNearest, structured = {}) =>
  query(id, { from: from("qvec"), select: { fields: [field("n")] }, findNearest, ...structured });

export const VECTOR_PROGRAMS = [
  {
    id: "fs-query-index/vector/measures",
    seed: VECTOR_SEED,
    steps: [
      search("euclidean", nearest("EUCLIDEAN")),
      search("cosine", nearest("COSINE")),
      search("dot-product", nearest("DOT_PRODUCT")),
      search("euclidean-full-documents", nearest("EUCLIDEAN", { limit: 2 }), { select: undefined }),
      search("euclidean-distance-field", nearest("EUCLIDEAN", { distanceResultField: "distance" })),
      search("cosine-distance-field", nearest("COSINE", { distanceResultField: "distance" })),
      search(
        "dot-product-distance-field",
        nearest("DOT_PRODUCT", { distanceResultField: "distance" }),
      ),
      search(
        "distance-field-existing-name",
        nearest("EUCLIDEAN", { distanceResultField: "dist", limit: 11 }),
        { select: undefined },
      ),
      search("distance-field-nested", nearest("EUCLIDEAN", { distanceResultField: "a.b" })),
      search("euclidean-threshold", nearest("EUCLIDEAN", { distanceThreshold: 1.5, limit: 10 })),
      search("cosine-threshold", nearest("COSINE", { distanceThreshold: 0.5, limit: 10 })),
      search(
        "dot-product-threshold",
        nearest("DOT_PRODUCT", { distanceThreshold: 0.5, limit: 10 }),
      ),
      search(
        "query-vector-other-direction",
        nearest("EUCLIDEAN", { queryVector: vec(0, 0, -1), limit: 11 }),
      ),
      search("limit-covers-all", nearest("COSINE", { limit: 11, distanceResultField: "distance" })),
      // Without a projection the distance result field is visible.
      search(
        "euclidean-distance-values",
        nearest("EUCLIDEAN", { distanceResultField: "distance", limit: 11 }),
        { select: undefined },
      ),
      search(
        "dot-product-distance-values",
        nearest("DOT_PRODUCT", { distanceResultField: "distance", limit: 11 }),
        { select: undefined },
      ),
      search(
        "distance-field-dotted-name",
        nearest("EUCLIDEAN", { distanceResultField: "a.b", limit: 2 }),
        { select: undefined },
      ),
      search(
        "distance-field-replaces-existing",
        nearest("EUCLIDEAN", { distanceResultField: "color", limit: 2 }),
        { select: undefined },
      ),
    ],
  },
  {
    id: "fs-query-index/vector/validation",
    seed: VECTOR_SEED,
    steps: [
      search("limit-1000", nearest("EUCLIDEAN", { limit: 1000 })),
      search("limit-1001", nearest("EUCLIDEAN", { limit: 1001 })),
      search("limit-zero", nearest("EUCLIDEAN", { limit: 0 })),
      search("limit-negative", nearest("EUCLIDEAN", { limit: -1 })),
      search("limit-missing", nearest("EUCLIDEAN", { limit: undefined })),
      search("measure-unspecified", nearest("DISTANCE_MEASURE_UNSPECIFIED")),
      search("measure-missing", nearest(undefined)),
      search("vector-field-missing", nearest("EUCLIDEAN", { vectorField: undefined })),
      search("query-vector-missing", nearest("EUCLIDEAN", { queryVector: undefined })),
      search(
        "query-vector-array",
        nearest("EUCLIDEAN", { queryVector: arr(dbl(1), dbl(0), dbl(0)) }),
      ),
      search("query-vector-empty", nearest("EUCLIDEAN", { queryVector: vec() })),
      search("query-vector-two-dimensions", nearest("EUCLIDEAN", { queryVector: vec(1, 0) })),
      search(
        "query-vector-four-dimensions",
        nearest("EUCLIDEAN", { queryVector: vec(1, 0, 0, 0) }),
      ),
      search("vector-field-without-index", nearest("EUCLIDEAN", { vectorField: field("emb2") })),
      search("vector-field-name", nearest("EUCLIDEAN", { vectorField: field("__name__") })),
      search("distance-field-invalid", nearest("EUCLIDEAN", { distanceResultField: "a..b" })),
      search("distance-field-reserved", nearest("EUCLIDEAN", { distanceResultField: "__name__" })),
      search("threshold-nan", nearest("EUCLIDEAN", { distanceThreshold: "NaN" })),
    ],
  },
  {
    id: "fs-query-index/vector/with-query-clauses",
    seed: VECTOR_SEED,
    steps: [
      search("prefilter-equality", nearest("EUCLIDEAN"), {
        where: f("color", "EQUAL", str("red")),
      }),
      search("prefilter-equality-without-index", nearest("EUCLIDEAN"), {
        where: f("n", "EQUAL", int(1)),
      }),
      search("prefilter-range", nearest("EUCLIDEAN"), {
        where: f("color", "GREATER_THAN", str("blue")),
      }),
      search("prefilter-in", nearest("EUCLIDEAN"), {
        where: f("color", "IN", arr(str("red"), str("blue"))),
      }),
      search("with-query-limit", nearest("EUCLIDEAN"), { limit: 2 }),
      search("with-offset", nearest("EUCLIDEAN"), { offset: 1 }),
      search("with-order-by", nearest("EUCLIDEAN"), { orderBy: [asc("n")] }),
      search("with-cursor", nearest("EUCLIDEAN"), {
        orderBy: [asc("__name__")],
        startAt: cursor([{ referenceValue: "{docs}/qvec/v2" }], true),
      }),
      search("select-vector-field", nearest("EUCLIDEAN", { limit: 1 }), {
        select: { fields: [field("emb")] },
      }),
      query("collection-group", {
        from: from("qvec", true),
        select: { fields: [field("n")] },
        findNearest: nearest("EUCLIDEAN"),
      }),
      aggregate("count-over-nearest", { from: from("qvec"), findNearest: nearest("EUCLIDEAN") }, [
        count("c"),
      ]),
      aggregate("sum-over-nearest", { from: from("qvec"), findNearest: nearest("EUCLIDEAN") }, [
        sum("n", "s"),
      ]),
      aggregate(
        "count-over-nearest-with-limit",
        { from: from("qvec"), findNearest: nearest("EUCLIDEAN"), limit: 2 },
        [count("c")],
      ),
    ],
  },
];
