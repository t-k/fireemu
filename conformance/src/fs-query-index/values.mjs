// REST JSON builders for Firestore values, filters and queries used by the FS-QUERY-INDEX corpus.

export const nul = () => ({ nullValue: null });
export const bool = (v) => ({ booleanValue: v });
export const int = (v) => ({ integerValue: String(v) });
/** A double; pass "-0" (proto3 JSON) for negative zero, which JSON numbers cannot carry. */
export const dbl = (v) => ({ doubleValue: v });
export const nan = () => ({ doubleValue: "NaN" });
export const inf = (sign = 1) => ({ doubleValue: sign > 0 ? "Infinity" : "-Infinity" });
export const str = (v) => ({ stringValue: v });
export const bytes = (base64) => ({ bytesValue: base64 });
export const ts = (v) => ({ timestampValue: v });
export const ref = (path) => ({ referenceValue: `{docs}/${path}` });
export const geo = (latitude, longitude) => ({ geoPointValue: { latitude, longitude } });
export const arr = (...values) => ({ arrayValue: values.length ? { values } : {} });
export const map = (fields) => ({ mapValue: Object.keys(fields).length ? { fields } : {} });
export const vec = (...components) => ({
  mapValue: {
    fields: {
      __type__: str("__vector__"),
      value: arr(...components.map((c) => dbl(c))),
    },
  },
});

export const field = (fieldPath) => ({ fieldPath });
export const f = (path, op, value) => ({ fieldFilter: { field: field(path), op, value } });
export const u = (path, op) => ({ unaryFilter: { field: field(path), op } });
export const and = (...filters) => ({ compositeFilter: { op: "AND", filters } });
export const or = (...filters) => ({ compositeFilter: { op: "OR", filters } });
export const asc = (path) => ({ field: field(path), direction: "ASCENDING" });
export const desc = (path) => ({ field: field(path), direction: "DESCENDING" });
export const from = (collectionId, allDescendants = false) =>
  allDescendants ? [{ collectionId, allDescendants: true }] : [{ collectionId }];
export const cursor = (values, before) => ({ values, ...(before === undefined ? {} : { before }) });

/** A REST runQuery step. */
export const query = (id, structuredQuery, extra = {}) => ({
  id,
  rpc: "runQuery",
  body: { structuredQuery, ...extra.body },
  ...(extra.parent ? { parent: extra.parent } : {}),
  ...(extra.transport ? { transport: extra.transport } : {}),
});

/** A REST runAggregationQuery step. */
export const aggregate = (id, structuredQuery, aggregations, extra = {}) => ({
  id,
  rpc: "runAggregationQuery",
  body: { structuredAggregationQuery: { structuredQuery, aggregations }, ...extra.body },
  ...(extra.parent ? { parent: extra.parent } : {}),
  ...(extra.transport ? { transport: extra.transport } : {}),
});

export const count = (alias, upTo) => ({
  ...(alias ? { alias } : {}),
  count: upTo === undefined ? {} : { upTo: String(upTo) },
});
export const sum = (path, alias) => ({ ...(alias ? { alias } : {}), sum: { field: field(path) } });
export const avg = (path, alias) => ({ ...(alias ? { alias } : {}), avg: { field: field(path) } });

/** The same step over gRPC (the request message is built from the REST body). */
export const viaGrpc = (step, id = `${step.id}-grpc`) => ({ ...step, id, transport: "grpc" });
