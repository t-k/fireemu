// Request builders shared by the FS-ENT-ORACLE pipeline corpora (corpus.mjs and o6-corpus.mjs):
// proto3 JSON `Value`s for expressions and stages, and the steps that carry them. A leaf module,
// so both corpora can import it without a cycle.

import { int, str } from "../fs-query-index/values.mjs";

/** A function call. */
export const fn = (name, ...args) => ({ functionValue: { name, args } });
/** A field reference. */
export const fld = (path) => ({ fieldReferenceValue: path });
/** A constant array (arrayValue literal, as the SDK's ListOfExprs sends it). */
export const list = (...values) => ({ arrayValue: { values } });

export const pipeline = (...stages) => ({ structuredPipeline: { pipeline: { stages } } });
export const stage = (name, ...args) => ({ name, args });
export const collection = (path) => stage("collection", { referenceValue: `/${path}` });
export const select = (aliases) => stage("select", { mapValue: { fields: aliases } });

/** A REST executePipeline step. */
export const step = (id, body, extra = {}) => ({ id, rpc: "executePipeline", body, ...extra });
/** The same step over gRPC. */
export const grpcStep = (id, body) => step(id, body, { transport: "grpc" });

/**
 * A seed written by a recorded commit step rather than by the harness: the request and
 * production's answer become rows of the fixture, and a refusal is that step's row instead of a
 * fatal harness error that ends the recording. New programs seed vectors this way.
 */
export function seedCommit(id, path, fields) {
  if (path.startsWith("/")) throw new Error(`${id}: a seed path is relative to {docs}`);
  const segments = path.split("/");
  if (segments.length % 2 !== 0 || segments.includes("")) {
    throw new Error(`${id}: ${path} is not a document path`);
  }
  return { id, rpc: "commit", body: { writes: [{ update: { name: `{docs}/${path}`, fields } }] } };
}

/** A sort key: the SDK sends an ordering as a map of a direction and an expression. */
export const ordering = (expression, direction) => ({
  mapValue: { fields: { direction: str(direction), expression } },
});
export const asc = (expression) => ordering(expression, "ascending");
export const desc = (expression) => ordering(expression, "descending");
export const sort = (...orderings) => stage("sort", ...orderings);
export const where = (condition) => stage("where", condition);
export const limit = (n) => stage("limit", int(n));
export const offset = (n) => stage("offset", int(n));
export const gt = (a, b) => fn("greater_than", a, b);
export const lt = (a, b) => fn("less_than", a, b);
export const eq = (a, b) => fn("equal", a, b);

/** A REST step reading one collection through the given stages. */
export const read = (id, from, ...stages) => step(id, pipeline(collection(from), ...stages));
export const readGrpc = (id, from, ...stages) =>
  grpcStep(id, pipeline(collection(from), ...stages));

/** A commit step writing several documents (one request). */
export function seedBatch(id, entries) {
  return {
    id,
    rpc: "commit",
    body: {
      writes: entries.map(([path, fields]) => ({ update: { name: `{docs}/${path}`, fields } })),
    },
  };
}
export const del = (id, path) => ({
  id,
  rpc: "commit",
  body: { writes: [{ delete: `{docs}/${path}` }] },
});

/** `[["<prefix>01", {v}], ...]` for a list of values of the field `v`. */
export const numbered = (prefix, values) =>
  values.map((v, i) => [`${prefix}${String(i + 1).padStart(2, "0")}`, { v }]);
