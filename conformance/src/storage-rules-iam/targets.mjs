import { createHash } from "node:crypto";
import { assess, parsePolicy, setBody, storageAgentMember, withGrant, withoutGrant } from "./policy.mjs";
import { PROJECT_ID, readUrl, READ_BODY, setUrl } from "./plan.mjs";

// The targets of the IAM requests. Every request is built here from an exact source: the read is fixed, the identity read is fixed, and
// the body of a set is never handed in, it is computed from the policy a read returned (the grant added, or removed again), so a caller
// cannot make the run write anything else. `verify` accepts only what this builder issued and only while its digest still holds.
const digest = (value) => createHash("sha256").update(value).digest("hex");
const HEADERS = Object.freeze({ "content-type": "application/json; charset=utf-8" });

export function createIamTargets({ projectNumber, digestSalt }) {
  const member = storageAgentMember(projectNumber);
  const issued = new WeakSet();
  const digestOf = ({ rowId, method, url, headers, body }) => digest([digestSalt, JSON.stringify({ rowId, method, url, headers, body: body === null ? null : digest(body), credential: "admin", project: PROJECT_ID })].join("\0"));

  function issue(rowId, method, url, body, redacted) {
    const headers = body === null ? {} : HEADERS;
    const prepared = { rowId, credential: "admin", project: PROJECT_ID, redacted, targetSha256: digestOf({ rowId, method, url, headers, body }) };
    Object.defineProperty(prepared, "spec", { value: Object.freeze({ url, method, headers: Object.freeze({ ...headers }), body }), enumerable: false });
    Object.freeze(prepared);
    issued.add(prepared);
    return prepared;
  }
  const json = (value) => Buffer.from(JSON.stringify(value));

  return Object.freeze({
    verify(prepared) {
      try {
        if (!prepared || typeof prepared !== "object" || !issued.has(prepared) || !prepared.spec) return false;
        const { url, method, headers, body } = prepared.spec;
        return digestOf({ rowId: prepared.rowId, method, url, headers, body }) === prepared.targetSha256;
      } catch { return false; }
    },
    prepareIdentity: (rowId) => issue(rowId, "GET", "https://www.googleapis.com/oauth2/v2/userinfo", null, "GET https://www.googleapis.com/oauth2/v2/userinfo"),
    prepareRead: (rowId) => issue(rowId, "POST", readUrl(projectNumber), json(READ_BODY), `POST ${readUrl(projectNumber)}`),
    /** The request that adds the grant to the policy that was read; refused unless the grant is absent from that policy. */
    prepareGrant(rowId, before) {
      const policy = parsePolicy({ etag: before.etag, version: before.version, bindings: before.bindings });
      if (assess(policy, member).state !== "absent") throw new Error("the grant is not absent");
      return issue(rowId, "POST", setUrl(projectNumber), json(setBody(withGrant(policy, member))), `POST ${setUrl(projectNumber)}`);
    },
    /** The request that removes the grant again from the policy that was read; refused unless the grant is present once. */
    prepareRevoke(rowId, current) {
      const policy = parsePolicy({ etag: current.etag, version: current.version, bindings: current.bindings });
      if (assess(policy, member).state !== "present") throw new Error("the grant is not present");
      return issue(rowId, "POST", setUrl(projectNumber), json(setBody(withoutGrant(policy, member))), `POST ${setUrl(projectNumber)}`);
    },
    member,
  });
}
