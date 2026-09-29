import { createHash } from "node:crypto";
import { isBucket, PROJECT_ID, probeRequests } from "./probe.mjs";

// Stage 2d: at most eight requests against the query project. Two are preflight (the owner's token and identity); six are the probe reads. There is no
// recovery: nothing is written.
export const IDS = Object.freeze({
  token: "preflight/auth/owner-token", identity: "preflight/owner/identity",
  list: "probe/rulesets-list", metadata: "probe/object-metadata-absent", media: "probe/object-media-absent",
  testValid: "probe/rules-test-valid", testInvalid: "probe/rules-test-invalid", document: "probe/document-absent",
});
export const PREFLIGHT_IDS = Object.freeze([IDS.token, IDS.identity]);
export const PROBE_IDS = Object.freeze([IDS.list, IDS.metadata, IDS.media, IDS.testValid, IDS.testInvalid, IDS.document]);
export const ALL_IDS = Object.freeze([...PREFLIGHT_IDS, ...PROBE_IDS]);
export const MAX_REQUESTS = ALL_IDS.length;
const sha = (value) => createHash("sha256").update(value).digest("hex");
const KEYS = Object.freeze({ list: IDS.list, metadata: IDS.metadata, media: IDS.media, testValid: IDS.testValid, testInvalid: IDS.testInvalid, document: IDS.document });

/** The probe reads with their IDs: method, URL and body of each, as the targets send them. */
export function probeList(bucket) {
  return probeRequests(bucket).map((entry) => Object.freeze({ id: KEYS[entry.key], method: entry.method, url: entry.url, body: entry.body }));
}

/** The operation corpus the approval pins as its manifest: every request with its method, URL and the digest of its body, the bucket and the owner's address digest. */
export function probeCorpus({ bucket, ownerEmailSha256 }) {
  if (!isBucket(bucket) || typeof ownerEmailSha256 !== "string" || !/^[0-9a-f]{64}$/.test(ownerEmailSha256)) throw new Error("invalid corpus input");
  const list = [
    { id: IDS.token, method: "POST", url: "https://oauth2.googleapis.com/token", bodySha256: null },
    { id: IDS.identity, method: "GET", url: "https://www.googleapis.com/oauth2/v2/userinfo", bodySha256: null },
    ...probeList(bucket).map((entry) => ({ id: entry.id, method: entry.method, url: entry.url, bodySha256: entry.body === null ? null : sha(entry.body) })),
  ];
  const document = { project: PROJECT_ID, bucket, ownerEmailSha256, list };
  return Object.freeze({ list, sha256: sha(JSON.stringify(document)) });
}
