import { createHash } from "node:crypto";
import { PROJECT_ID } from "./state.mjs";
import { restoreRequests } from "./plan.mjs";

// The targets of the cleanup requests. Every request is built here from an exact source (plan.mjs, for one validated expected state): the owner's identity
// read and the planned requests. A caller hands in only an ID. `verify` accepts only what this builder issued and only while its digest still holds.
const digest = (value) => createHash("sha256").update(value).digest("hex");
const HEADERS = Object.freeze({ "content-type": "application/json; charset=utf-8" });

export function createRestoreTargets({ state, digestSalt }) {
  const issued = new WeakSet();
  const requests = new Map(restoreRequests(state).map((entry) => [entry.id, entry]));
  const digestOf = ({ rowId, method, url, headers, body }) => digest([digestSalt, JSON.stringify({ rowId, method, url, headers, body: body === null ? null : digest(body), credential: "admin", project: PROJECT_ID })].join("\0"));

  function issue(rowId, method, url, body) {
    const headers = body === null ? {} : HEADERS;
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
    /** One planned request, by its ID. */
    prepare(rowId) {
      const entry = requests.get(rowId) ?? (() => { throw new Error("not a planned request"); })();
      return issue(rowId, entry.method, entry.url, entry.body);
    },
    request: (rowId) => requests.get(rowId) ?? (() => { throw new Error("not a planned request"); })(),
  });
}
