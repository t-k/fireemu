import { createHash } from "node:crypto";
import { bucketReleaseName, BUCKETLESS_RELEASE_NAME, isBucket, PROJECT_ID, parseSaved, RELEASES_URL, rulesUrl } from "./release.mjs";

// The targets of the release requests. Every request is built here from an exact source: the reads name a fixed resource, and the body of
// the publication is computed from the saved record (never handed in), so a caller cannot make the run write anything else. `verify`
// accepts only what this builder issued and only while its digest still holds.
const digest = (value) => createHash("sha256").update(value).digest("hex");
const HEADERS = Object.freeze({ "content-type": "application/json; charset=utf-8" });

export function createReleaseTargets({ bucket, digestSalt }) {
  if (!isBucket(bucket)) throw new Error("invalid bucket");
  const releaseName = bucketReleaseName(bucket);
  const issued = new WeakSet();
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
    prepareRulesetRead: (rowId, rulesetName) => issue(rowId, "GET", rulesUrl(rulesetName), null),
    prepareBucketRead: (rowId) => issue(rowId, "GET", rulesUrl(releaseName), null),
    prepareBucketlessRead: (rowId) => issue(rowId, "GET", rulesUrl(BUCKETLESS_RELEASE_NAME), null),
    /** The deletion of the bucket release the saved record describes. */
    prepareDelete(rowId, saved) {
      if (parseSaved(saved).name !== releaseName) throw new Error("the saved release is not this bucket's");
      return issue(rowId, "DELETE", rulesUrl(releaseName), null);
    },
    /** The publication of the release the saved record describes, with its ruleset. */
    preparePublish(rowId, saved) {
      const record = parseSaved(saved);
      if (record.name !== releaseName) throw new Error("the saved release is not this bucket's");
      return issue(rowId, "POST", RELEASES_URL, Buffer.from(JSON.stringify({ name: record.name, rulesetName: record.rulesetName })));
    },
    releaseName,
  });
}
