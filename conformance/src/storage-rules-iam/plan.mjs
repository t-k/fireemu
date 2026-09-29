import { createHash } from "node:crypto";
import { GRANT_ROLE, storageAgentMember } from "./policy.mjs";

// Stage 2b: at most eight requests against the query project's IAM policy. Five are the normal path (the owner's token, the owner's
// identity, the policy before, the grant, the policy after); three are the recovery of a grant whose result is unknown or wrong (the
// policy now, the removal of the grant this run added, the policy after the removal).
export const PROJECT_ID = "fireemu-oracle-query";
export const IDS = Object.freeze({
  token: "preflight/auth/owner-token", identity: "preflight/owner/identity", before: "preflight/query/iam-before",
  grant: "iam/query/grant", after: "iam/query/after",
  current: "recovery/iam/query/current", revoke: "recovery/iam/query/revoke", absent: "recovery/iam/query/absent",
});
export const PREFLIGHT_IDS = Object.freeze([IDS.token, IDS.identity, IDS.before]);
export const ALL_IDS = Object.freeze([...PREFLIGHT_IDS, IDS.grant, IDS.after, IDS.current, IDS.revoke, IDS.absent]);
export const IAM_HOST = "https://cloudresourcemanager.googleapis.com";
export const READ_BODY = Object.freeze({ options: Object.freeze({ requestedPolicyVersion: 3 }) });
const sha = (value) => createHash("sha256").update(value).digest("hex");

export const readUrl = (projectNumber) => `${IAM_HOST}/v3/projects/${projectNumber}:getIamPolicy`;
export const setUrl = (projectNumber) => `${IAM_HOST}/v3/projects/${projectNumber}:setIamPolicy`;

/**
 * The operation corpus the approval pins as its manifest: the requests with their URLs and bodies (the body of a set is a template,
 * since it is built from the policy that was read), the role and the member granted, and the owner's address digest the identity read is
 * judged against.
 */
export function iamCorpus({ projectNumber, ownerEmailSha256 }) {
  if (typeof ownerEmailSha256 !== "string" || !/^[0-9a-f]{64}$/.test(ownerEmailSha256)) throw new Error("invalid owner digest");
  const member = storageAgentMember(projectNumber);
  const read = { method: "POST", url: readUrl(projectNumber), body: READ_BODY };
  const set = { method: "POST", url: setUrl(projectNumber), body: { policy: "<the policy that was read, with the member added or removed>", updateMask: "bindings,etag" } };
  const list = [
    { id: IDS.token, method: "POST", url: "https://oauth2.googleapis.com/token" },
    { id: IDS.identity, method: "GET", url: "https://www.googleapis.com/oauth2/v2/userinfo" },
    { id: IDS.before, ...read }, { id: IDS.grant, ...set }, { id: IDS.after, ...read },
    { id: IDS.current, ...read }, { id: IDS.revoke, ...set }, { id: IDS.absent, ...read },
  ];
  const document = { project: PROJECT_ID, role: GRANT_ROLE, member, ownerEmailSha256, list };
  return Object.freeze({ list, member, sha256: sha(JSON.stringify(document)) });
}
