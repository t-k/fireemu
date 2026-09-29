import { createHash, timingSafeEqual } from "node:crypto";
import { types } from "node:util";

// Judges the preflight reads against the private packet of expected values: the owner's identity, both projects and their
// keys, the bucket, the database and the policy baselines. It returns true only when every fact the probe carries matches;
// the entry list of Rulesets must be exactly the two rulesets production holds, and the two entry release reads must merely be well formed.
// Bearer values (the owner's address, the key strings) are compared as digests or in constant time and are never returned.
const digest = (value) => createHash("sha256").update(value).digest("hex");
const same = (left, right) => typeof left === "string" && typeof right === "string" && left.length === right.length && timingSafeEqual(Buffer.from(left), Buffer.from(right));
const equalLists = (left, right) => Array.isArray(left) && left.length === right.length && left.every((entry, index) => entry === right[index]);

// The rulesets production holds on the query project when the recording starts, by name and service: the storage ruleset that stage 2c-pre
// deliberately kept (the bucket release that pointed at it is removed for the recording and published again after it) and the project's
// Firestore ruleset. The entry list must be exactly these two, so an unknown ruleset (or a missing one) stops the run before anything is
// written. The run deletes only rulesets it created itself; these two are never touched (see the run ledger).
export const ENTRY_RULESETS = Object.freeze([
  Object.freeze({ name: "projects/fireemu-oracle-query/rulesets/22b746af-a48a-458d-ab5c-7853473bc8c8", services: Object.freeze(["firebase.storage"]) }),
  Object.freeze({ name: "projects/fireemu-oracle-query/rulesets/d0abf7c6-b0b6-4163-8488-7c8a48ac5dd1", services: Object.freeze(["cloud.firestore"]) }),
]);
const isEntryList = (listed) => Array.isArray(listed) && listed.length === ENTRY_RULESETS.length && listed.every((entry, index) => entry?.name === ENTRY_RULESETS[index].name && equalLists(entry.services, ENTRY_RULESETS[index].services));

export function createPreflightJudge(options) {
  const fail = () => { throw new Error("invalid preflight judge options"); };
  if (options === null || typeof options !== "object" || types.isProxy(options) || Reflect.ownKeys(options).length !== 1 || !Object.hasOwn(options, "inputs")) fail();
  const { inputs } = options;
  if (inputs === null || typeof inputs !== "object" || !Object.isFrozen(inputs) || typeof inputs.secrets?.apiKeys?.query !== "string" || typeof inputs.secrets?.apiKeys?.idp !== "string" || typeof inputs.projects?.query?.projectNumber !== "string") fail();
  const { projects, owner, bucket, database } = inputs;
  const secrets = inputs.secrets.apiKeys;

  const projectRow = (name) => (outcome, row) => outcome.kind === "preflight-project" && outcome.verdict === "accepted" && row.request.path === `/v3/projects/${projects[name].projectNumber}` &&
    outcome.facts.projectId === projects[name].projectId && outcome.facts.state === "ACTIVE" && outcome.facts.deleted === false;
  const keyRow = (name) => (outcome, row) => {
    const facts = outcome.facts;
    return outcome.kind === "preflight-key-metadata" && outcome.verdict === "accepted" &&
      row.request.path === `/v2/projects/${projects[name].projectNumber}/locations/global/keys/${projects[name].apiKeyId}` &&
      facts.uid === projects[name].keyUid && facts.deleted === false && equalLists(facts.apiTargets, projects[name].apiTargets) && same(facts.restrictionsSha256, projects[name].restrictionsSha256) && facts.methodRestricted === false;
  };
  const keyStringRow = (name) => (outcome, row) => outcome.kind === "preflight-key-string" && outcome.verdict === "accepted" &&
    row.request.path === `/v2/projects/${projects[name].projectNumber}/locations/global/keys/${projects[name].apiKeyId}/keyString` && same(outcome.secretFacts?.keyString, secrets[name]);
  const permissionsRow = (kind) => (outcome) => outcome.kind === kind && outcome.verdict === "accepted" && Array.isArray(outcome.facts.missing) && outcome.facts.missing.length === 0 && outcome.facts.granted === outcome.facts.requested;

  const JUDGES = {
    "preflight/owner/identity": (outcome) => outcome.kind === "preflight-identity" && outcome.verdict === "accepted" && outcome.facts.verifiedEmail === true &&
      typeof outcome.secretFacts?.email === "string" && typeof outcome.secretFacts?.subject === "string" && same(digest(outcome.secretFacts.email), owner.emailSha256) && same(digest(outcome.secretFacts.subject), owner.subjectSha256),
    "preflight/query/project": projectRow("query"),
    "preflight/idp/project": projectRow("idp"),
    "preflight/query/key-metadata": keyRow("query"),
    "preflight/idp/key-metadata": keyRow("idp"),
    "preflight/query/key-string": keyStringRow("query"),
    "preflight/idp/key-string": keyStringRow("idp"),
    "preflight/query/permissions": permissionsRow("preflight-permissions"),
    "preflight/idp/permissions": permissionsRow("preflight-permissions"),
    "preflight/bucket/permissions": permissionsRow("preflight-bucket-permissions"),
    "preflight/bucket/metadata": (outcome, row) => outcome.kind === "preflight-bucket-metadata" && outcome.verdict === "accepted" && row.request.path === `/storage/v1/b/${bucket.name}` &&
      outcome.facts.projectNumber === projects.query.projectNumber && outcome.facts.location === bucket.location && (bucket.uniformBucketLevelAccess === null || outcome.facts.uniformBucketLevelAccess === bucket.uniformBucketLevelAccess),
    "preflight/bucket/iam": (outcome) => outcome.kind === "preflight-bucket-iam" && outcome.verdict === "accepted" && same(outcome.facts.policySha256, bucket.iamPolicySha256),
    "preflight/query/database": (outcome) => outcome.kind === "preflight-database" && outcome.verdict === "accepted" && outcome.facts.locationId === database.locationId && outcome.facts.type === database.type,
    "preflight/query/iam": (outcome) => outcome.kind === "preflight-project-iam" && outcome.verdict === "accepted" && same(outcome.facts.policySha256, inputs.queryProjectIamPolicySha256),
    "preflight/rulesets-list/entry/1": (outcome) => outcome.kind === "rules-list-page" && outcome.verdict === "accepted" && outcome.facts.hasNextPage === false && isEntryList(outcome.facts.rulesets),
    "preflight/release/entry/bucket": (outcome) => outcome.kind === "rules-release-read" && outcome.verdict !== "unexpected",
    "preflight/release/entry/bucketless": (outcome) => outcome.kind === "rules-release-read" && outcome.verdict !== "unexpected",
  };

  return (row, outcome) => {
    try {
      const judge = JUDGES[row?.id];
      return typeof judge === "function" && outcome !== null && typeof outcome === "object" && judge(outcome, row) === true;
    } catch { return false; }
  };
}
