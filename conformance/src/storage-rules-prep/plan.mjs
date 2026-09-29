import { createHash, timingSafeEqual } from "node:crypto";
import { buildRunManifest, TEMPLATE_RUN_ID } from "../storage-rules/run-manifest.mjs";
import { parsePrivateInputs } from "../storage-rules/private-inputs.mjs";
import { tagged, STOP_CODES } from "../storage-rules/stop-codes.mjs";

// Stage 2a: thirteen read-only requests that yield the values of the stage 3 private inputs file. Twelve of them are the
// stage 3 manifest's own preflight rows (the same method, URL, body and credential); the two API key lists are the only new
// requests. Nothing here sends anything: this module declares the requests, judges what came back and assembles the file.
export const QUERY_PROJECT = "fireemu-oracle-query";
export const IDP_PROJECT = "fireemu-oracle-idp";
export const KEY_LIST_IDS = Object.freeze({ query: "preflight/query/key-list", idp: "preflight/idp/key-list" });
export const OWNER_TOKEN_ID = "preflight/auth/owner-token";
// The order the requests are sent in; each ID is used once.
export const PREP_IDS = Object.freeze([
  OWNER_TOKEN_ID, "preflight/owner/identity", KEY_LIST_IDS.query, KEY_LIST_IDS.idp, "preflight/query/key-string", "preflight/idp/key-string",
  "preflight/bucket/metadata", "preflight/bucket/iam", "preflight/query/database", "preflight/query/iam",
  "preflight/query/permissions", "preflight/idp/permissions", "preflight/bucket/permissions",
]);
const PLACEHOLDER_KEYS = Object.freeze({ query: "00000000-0000-4000-8000-000000000001", idp: "00000000-0000-4000-8000-000000000002" });
// An API Keys v2 key ID: a UUID, or a custom ID (a lower-case letter first, then lower-case letters, digits and hyphens, at most 63 characters).
export const KEY_ID = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[a-z][a-z0-9-]{0,62})$/;
const REQUIRED_SERVICES = ["identitytoolkit.googleapis.com", "securetoken.googleapis.com"];
const sha = (value) => createHash("sha256").update(value).digest("hex");
const same = (left, right) => typeof left === "string" && typeof right === "string" && left.length === right.length && timingSafeEqual(Buffer.from(left), Buffer.from(right));
const stop = (message) => { throw tagged(STOP_CODES.preflightFailed, message); };

/** The manifest rows of the stage 3 preflight, keyed by ID, with the given (possibly placeholder) API key IDs. */
export function standardRows(closure, params, keyIds = PLACEHOLDER_KEYS) {
  const manifest = buildRunManifest(closure, { bucket: params.bucket, runId: TEMPLATE_RUN_ID, sourceCommit: params.sourceCommit, queryProjectNumber: params.queryProjectNumber, idpProjectNumber: params.idpProjectNumber, queryApiKeyId: keyIds.query, idpApiKeyId: keyIds.idp });
  return { manifest, rows: new Map(manifest.rows.filter((row) => PREP_IDS.includes(row.id)).map((row) => [row.id, row])) };
}

/** The API key list request of one project: an exact URL, no query, no body. */
export function keyListRequest(project, number) {
  if (!["query", "idp"].includes(project) || typeof number !== "string" || !/^[1-9]\d{0,19}$/.test(number)) throw new Error("invalid key list request");
  return Object.freeze({ id: KEY_LIST_IDS[project], project: project === "query" ? QUERY_PROJECT : IDP_PROJECT, method: "GET", url: `https://apikeys.googleapis.com/v2/projects/${number}/locations/global/keys`, credential: "admin" });
}

/**
 * The operation corpus the approval pins as its manifest: the thirteen requests (method, URL and body), with the two key IDs of
 * the key-string reads as placeholders because the real ones are learnt from the lists, and the key each project is expected to use
 * (`params.expectedKeyIds`, a key ID or null for "the one live key").
 */
export function prepCorpus(closure, params) {
  const { rows } = standardRows(closure, params);
  const list = PREP_IDS.map((id) => {
    if (id === OWNER_TOKEN_ID) return { id, method: "POST", url: "https://oauth2.googleapis.com/token" };
    if (id === KEY_LIST_IDS.query) { const r = keyListRequest("query", params.queryProjectNumber); return { id, method: r.method, url: r.url }; }
    if (id === KEY_LIST_IDS.idp) { const r = keyListRequest("idp", params.idpProjectNumber); return { id, method: r.method, url: r.url }; }
    const request = rows.get(id).request;
    return { id, method: request.method, url: `${request.origin}${request.path}`, query: request.query ?? null, body: request.body ?? null, credential: request.credential, project: request.project ?? QUERY_PROJECT };
  });
  const expectedKeyIds = { query: params.expectedKeyIds?.query ?? null, idp: params.expectedKeyIds?.idp ?? null };
  if (Object.values(expectedKeyIds).some((id) => id !== null && (typeof id !== "string" || !KEY_ID.test(id)))) throw new Error("invalid expected key ID");
  return Object.freeze({ list, expectedKeyIds, sha256: sha(JSON.stringify({ expectedKeyIds, list })) });
}

/**
 * The key of a project's list the run will use, or a stop. A next page is a stop (the list is only read once). With an expected key ID
 * the key must be live and named exactly; the other live keys are tolerated and counted. Without one, the project must have exactly one
 * live key.
 */
export function selectKey(body, number, expectedKeyId = null) {
  const keys = body?.keys;
  if (body === null || typeof body !== "object" || Array.isArray(body) || body.nextPageToken !== undefined || (keys !== undefined && !Array.isArray(keys))) stop("key list is paged or malformed");
  const live = (keys ?? []).filter((item) => item !== null && typeof item === "object" && item.deleteTime === undefined);
  const nameOf = (item) => (typeof item.name === "string" ? item.name : "");
  const prefix = `projects/${number}/locations/global/keys/`;
  let item;
  if (expectedKeyId === null) {
    if (live.length !== 1) stop(`expected exactly one live key, found ${live.length}`);
    [item] = live;
  } else {
    if (typeof expectedKeyId !== "string" || !KEY_ID.test(expectedKeyId)) stop("the expected key ID is not a key ID");
    const named = live.filter((entry) => nameOf(entry) === `${prefix}${expectedKeyId}`);
    if (named.length !== 1) stop(`the expected key is not one live key of the project, found ${named.length}`);
    [item] = named;
  }
  const keyId = nameOf(item).startsWith(prefix) ? nameOf(item).slice(prefix.length) : "";
  if (!KEY_ID.test(keyId)) stop("key name is not the expected resource");
  return Object.freeze({ keyId, item, otherLiveKeys: live.length - 1 });
}

/** Judge the facts of one key (as the stage 3 preflight does): live, not method restricted, the two sign-in services allowed; its restriction digest is recorded. */
export function keyFacts(facts) {
  if (facts.deleted !== false || facts.methodRestricted !== false || !Array.isArray(facts.apiTargets) || typeof facts.uid !== "string" || facts.uid === "" || !/^[0-9a-f]{64}$/.test(facts.restrictionsSha256 ?? "")) stop("key restrictions are not the expected shape");
  const targets = facts.apiTargets;
  if (targets.length > 64 || targets.some((target, index) => index > 0 && !(targets[index - 1] < target))) stop("key targets are not a strictly ascending list");
  if (!REQUIRED_SERVICES.every((service) => targets.includes(service))) stop("the key does not allow the two sign-in services");
  return { keyUid: facts.uid, apiTargets: [...targets], restrictionsSha256: facts.restrictionsSha256 };
}

/**
 * The private inputs file for stage 3, from what the reads showed. `local` carries the ADC path, the two project numbers and
 * the two API key strings the operator already holds; a key string that is not the one production reports is a stop.
 */
export const keyStringMatches = (reported, local) => typeof reported === "string" && typeof local === "string" && same(sha(reported), sha(local));

export function assembleInputs({ adcPath, local, identity, query, idp, bucket, database, queryIamSha256 }) {
  if (!keyStringMatches(query.keyString, local.keys.query) || !keyStringMatches(idp.keyString, local.keys.idp)) stop("a local key string is not the key production reports");
  const inputs = {
    schemaVersion: 1, adcPath,
    owner: { emailSha256: sha(identity.email), subjectSha256: sha(identity.subject) },
    projects: {
      query: { projectId: QUERY_PROJECT, projectNumber: local.numbers.query, apiKeyId: query.keyId, apiKey: local.keys.query, keyUid: query.facts.keyUid, apiTargets: query.facts.apiTargets, restrictionsSha256: query.facts.restrictionsSha256 },
      idp: { projectId: IDP_PROJECT, projectNumber: local.numbers.idp, apiKeyId: idp.keyId, apiKey: local.keys.idp, keyUid: idp.facts.keyUid, apiTargets: idp.facts.apiTargets, restrictionsSha256: idp.facts.restrictionsSha256 },
    },
    bucket: { name: bucket.name, location: bucket.facts.location, uniformBucketLevelAccess: bucket.facts.uniformBucketLevelAccess, iamPolicySha256: bucket.iamSha256 },
    database: { locationId: database.locationId, type: database.type },
    queryProjectIamPolicySha256: queryIamSha256,
  };
  parsePrivateInputs(structuredClone(inputs));
  return inputs;
}
