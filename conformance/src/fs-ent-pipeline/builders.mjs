// Request builders shared by the FS-ENT-ORACLE pipeline corpora (corpus.mjs and o6-corpus.mjs):
// proto3 JSON `Value`s for expressions and stages, and the steps that carry them. A leaf module,
// so both corpora can import it without a cycle.

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
