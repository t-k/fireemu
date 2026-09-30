import { buildCorpus } from "./corpus.mjs";
import { buildFullRequestManifest } from "./full-manifest.mjs";

// The one place a run's request manifest is built: the run's bucket, run ID, source commit, project numbers and API key IDs go in,
// and the resource names (the object prefix and the two fixture user IDs) are derived from the bucket and the run ID.
export const TEMPLATE_RUN_ID = "manifest-pin-template";
const FIELDS = ["bucket", "runId", "sourceCommit", "queryProjectNumber", "idpProjectNumber", "queryApiKeyId", "idpApiKeyId"];

export function buildRunManifest(closure, params) {
  if (params === null || typeof params !== "object" || Reflect.ownKeys(params).length !== FIELDS.length || !FIELDS.every((field) => Object.hasOwn(params, field))) throw new Error("invalid run manifest input");
  const { bucket, runId, ...options } = params;
  const binding = { bucket, prefix: `STORAGE-RULES/${runId}/`, uidA: `storage-rules-${runId}-user-a`, uidB: `storage-rules-${runId}-user-b` };
  return buildFullRequestManifest(buildCorpus(binding), closure, { runId, ...options });
}

/** The parameters a manifest was built from, read back from its binding. */
export function manifestParams(manifest) {
  const binding = manifest?.binding;
  if (binding === null || typeof binding !== "object") throw new Error("invalid run manifest input");
  return Object.fromEntries(FIELDS.map((field) => [field, binding[field]]));
}

/** The manifest parameters of one run, taken from the validated private inputs. */
export function paramsFromInputs(inputs, runId, sourceCommit) {
  return {
    bucket: inputs.bucket.name, runId, sourceCommit, queryProjectNumber: inputs.projects.query.projectNumber, idpProjectNumber: inputs.projects.idp.projectNumber,
    queryApiKeyId: inputs.projects.query.apiKeyId, idpApiKeyId: inputs.projects.idp.apiKeyId,
  };
}
