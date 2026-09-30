import { createHash } from "node:crypto";
import { ENTRY_RULESETS } from "../storage-rules/entry-rulesets.mjs";
import { isTimestamp } from "../storage-rules/acceptance-core.mjs";
import { dependentRequest, DEPENDENT_IDS, PROJECT_ID, staticRequests } from "./plan.mjs";

// The targets of the probe's requests. Every request is built here from an exact source: the static requests of plan.mjs, or a dependent request built from an
// ownership proof (a ruleset name that is not one of the kept two, an object generation, a document update time). A caller hands in only an ID (and the proofs it
// read). A dependent request is granted to the transport, by the exact `METHOD URL body` key, only when it is built here. `verify` accepts only what was issued.
const digest = (value) => createHash("sha256").update(value).digest("hex");
const JSON_HEADERS = Object.freeze({ "content-type": "application/json; charset=utf-8" });
const RULESET_NAME = new RegExp(`^projects/${PROJECT_ID}/rulesets/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`);
const KEPT_NAMES = new Set(ENTRY_RULESETS.map((entry) => entry.name));
export const grantKey = (method, url, body) => `${method} ${url} ${body === null ? "" : digest(body)}`;

export function createShapeTargets({ bucket, digestSalt, grant }) {
  if (typeof grant !== "function") throw new Error("invalid targets options");
  const issued = new WeakSet();
  const statics = new Map(staticRequests(bucket).map((entry) => [entry.id, entry]));
  const digestOf = ({ rowId, method, url, headers, body }) => digest([digestSalt, JSON.stringify({ rowId, method, url, headers, body: body === null ? null : digest(body), credential: "admin", project: PROJECT_ID })].join("\0"));

  function issue(rowId, method, url, body, contentType) {
    const headers = body === null ? {} : contentType === undefined ? JSON_HEADERS : { "content-type": contentType };
    const prepared = { rowId, credential: "admin", project: PROJECT_ID, redacted: `${method} ${url}`, targetSha256: digestOf({ rowId, method, url, headers, body }) };
    Object.defineProperty(prepared, "spec", { value: Object.freeze({ url, method, headers: Object.freeze({ ...headers }), body }), enumerable: false });
    Object.freeze(prepared);
    issued.add(prepared);
    return prepared;
  }

  return Object.freeze({
    verify(prepared) {
      try {
        if (!prepared || typeof prepared !== "object" || !issued.has(prepared) || !prepared.spec) return false;
        const { url, method, headers, body } = prepared.spec;
        return digestOf({ rowId: prepared.rowId, method, url, headers, body }) === prepared.targetSha256;
      } catch { return false; }
    },
    prepareIdentity: (rowId) => issue(rowId, "GET", "https://www.googleapis.com/oauth2/v2/userinfo", null),
    /** One static request, by its ID. */
    prepare(rowId) {
      const entry = statics.get(rowId) ?? (() => { throw new Error("not a planned request"); })();
      return issue(rowId, entry.method, entry.url, entry.body, entry.contentType);
    },
    /** One request that follows from an ownership proof; refused when the proof is not of the expected form. */
    prepareDependent(rowId, proofs) {
      if (!DEPENDENT_IDS.includes(rowId) || proofs === null || typeof proofs !== "object") throw new Error("not a planned request");
      if (rowId.startsWith("shape/ruleset/") && !(typeof proofs.ruleset === "string" && RULESET_NAME.test(proofs.ruleset) && !KEPT_NAMES.has(proofs.ruleset))) throw new Error("invalid ownership proof");
      if (rowId === "shape/object/delete" && !(typeof proofs.generation === "string" && /^[1-9]\d{0,19}$/.test(proofs.generation))) throw new Error("invalid ownership proof");
      if (rowId === "shape/document/delete" && !isTimestamp(proofs.updateTime)) throw new Error("invalid ownership proof");
      const entry = dependentRequest(rowId, proofs, bucket);
      grant(grantKey(entry.method, entry.url, entry.body));
      return issue(rowId, entry.method, entry.url, entry.body);
    },
    request: (rowId) => statics.get(rowId) ?? (() => { throw new Error("not a planned request"); })(),
  });
}
