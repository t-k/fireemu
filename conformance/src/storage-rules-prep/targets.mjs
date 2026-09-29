import { createHash } from "node:crypto";
import { createTargetBuilder } from "../storage-rules/target.mjs";
import { keyListRequest, KEY_LIST_IDS, PREP_IDS, standardRows } from "./plan.mjs";

// The targets of the thirteen requests. Eleven are prepared by the stage 3 target builder from the stage 3 manifest's own rows
// (so the same route, header and project rules apply); the two key lists are prepared here, from an exact URL. The two
// key-string reads use a second builder made after the lists, once the real key IDs are known. One `verify` covers all three.
const digest = (value) => createHash("sha256").update(value).digest("hex");
const noReferences = () => { throw new Error("no runtime references in stage 2a"); };
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export function createPrepTargets({ closure, params, digestSalt }) {
  const first = standardRows(closure, params);
  const builderFirst = createTargetBuilder({ manifest: first.manifest, digestSalt });
  let learned = null;
  let builderLearned = null;
  let learnedRows = null;
  const listed = new WeakSet();
  const listDigest = ({ rowId, url, project }) => digest([digestSalt, JSON.stringify({ rowId, method: "GET", url, project })].join("\0"));

  function prepareList(project) {
    const request = keyListRequest(project, project === "query" ? params.queryProjectNumber : params.idpProjectNumber);
    const prepared = { rowId: request.id, credential: request.credential, project: request.project, redacted: `GET ${new URL(request.url).origin}${new URL(request.url).pathname}`, targetSha256: listDigest({ rowId: request.id, url: request.url, project: request.project }) };
    Object.defineProperty(prepared, "spec", { value: Object.freeze({ url: request.url, method: "GET", headers: Object.freeze({}), body: null }), enumerable: false });
    Object.freeze(prepared);
    listed.add(prepared);
    return prepared;
  }

  function verify(prepared) {
    try {
      if (listed.has(prepared)) return listDigest({ rowId: prepared.rowId, url: prepared.spec.url, project: prepared.project }) === prepared.targetSha256 && prepared.spec.method === "GET" && prepared.spec.body === null;
      return builderFirst.verify(prepared) || (builderLearned !== null && builderLearned.verify(prepared));
    } catch { return false; }
  }

  return Object.freeze({
    verify,
    /** A request that needs no learnt value: everything but the two lists and the two key strings. */
    prepareStandard(id) {
      if (!PREP_IDS.includes(id) || Object.values(KEY_LIST_IDS).includes(id) || /\/key-string$/.test(id) || id === "preflight/auth/owner-token") throw new Error("not a standard request");
      return builderFirst.prepare(first.rows.get(id), noReferences);
    },
    prepareList,
    /** Learn the two key IDs (once), then prepare a key-string read. */
    prepareKeyString(project, keyIds) {
      if (learned === null) {
        if (!UUID.test(keyIds?.query ?? "") || !UUID.test(keyIds?.idp ?? "") || keyIds.query === keyIds.idp) throw new Error("invalid key IDs");
        learned = { ...keyIds };
        const rows = standardRows(closure, params, learned);
        builderLearned = createTargetBuilder({ manifest: rows.manifest, digestSalt });
        learnedRows = rows.rows;
      }
      if (keyIds.query !== learned.query || keyIds.idp !== learned.idp) throw new Error("key IDs changed");
      return builderLearned.prepare(learnedRows.get(`preflight/${project}/key-string`), noReferences);
    },
    row: (id) => first.rows.get(id),
    manifestRow: (id) => first.manifest.rows.find((row) => row.id === id),
  });
}
