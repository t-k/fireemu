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
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
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
  if (!["query", "idp"].includes(project) || !/^[1-9]\d{0,19}$/.test(number)) throw new Error("invalid key list request");
  return Object.freeze({ id: KEY_LIST_IDS[project], project: project === "query" ? QUERY_PROJECT : IDP_PROJECT, method: "GET", url: `https://apikeys.googleapis.com/v2/projects/${number}/locations/global/keys`, credential: "admin" });
}

/**
 * The operation corpus the approval pins as its manifest: the thirteen requests (method, URL and body), with the two key IDs of
 * the key-string reads as placeholders because the real ones are learnt from the lists.
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
  return Object.freeze({ list, sha256: sha(JSON.stringify(list)) });
}

/** The single live key of a project's list, or a stop: a next page or anything but exactly one live key is ambiguous. */
export function selectKey(body, number) {
  const keys = body?.keys;
  if (body === null || typeof body !== "object" || Array.isArray(body) || body.nextPageToken !== undefined || (keys !== undefined && !Array.isArray(keys))) stop("key list is paged or malformed");
  const live = (keys ?? []).filter((item) => item !== null && typeof item === "object" && item.deleteTime === undefined);
  if (live.length !== 1) stop(`expected exactly one live key, found ${live.length}`);
  const [item] = live;
  const match = new RegExp(`^projects/${number}/locations/global/keys/([0-9a-f-]{36})$`).exec(item.name ?? "");
  if (match === null || !UUID.test(match[1])) stop("key name is not the expected resource");
  return Object.freeze({ keyId: match[1], item });
}

/** Judge the facts of one key (as the stage 3 preflight does) against the wide open assumptions the run makes of it. */
export function keyFacts(facts) {
  if (facts.deleted !== false || facts.otherRestrictions.length !== 0 || facts.methodRestricted !== false || !Array.isArray(facts.apiTargets) || typeof facts.uid !== "string" || facts.uid === "") stop("key restrictions are not the expected shape");
  const targets = facts.apiTargets;
  if (targets.length > 8 || targets.some((target, index) => index > 0 && !(targets[index - 1] < target))) stop("key targets are not a strictly ascending list");
  return { keyUid: facts.uid, apiTargets: [...targets] };
}

/**
 * The private inputs file for stage 3, from what the reads showed. `local` carries the ADC path, the two project numbers and
 * the two API key strings the operator already holds; a key string that is not the one production reports is a stop.
 */
export function assembleInputs({ adcPath, local, identity, query, idp, bucket, database, queryIamSha256 }) {
  if (!same(sha(query.keyString), sha(local.keys.query)) || !same(sha(idp.keyString), sha(local.keys.idp))) stop("a local key string is not the key production reports");
  const inputs = {
    schemaVersion: 1, adcPath,
    owner: { emailSha256: sha(identity.email), subjectSha256: sha(identity.subject) },
    projects: {
      query: { projectId: QUERY_PROJECT, projectNumber: local.numbers.query, apiKeyId: query.keyId, apiKey: local.keys.query, keyUid: query.facts.keyUid, apiTargets: query.facts.apiTargets },
      idp: { projectId: IDP_PROJECT, projectNumber: local.numbers.idp, apiKeyId: idp.keyId, apiKey: local.keys.idp, keyUid: idp.facts.keyUid, apiTargets: idp.facts.apiTargets },
    },
    bucket: { name: bucket.name, location: bucket.facts.location, uniformBucketLevelAccess: bucket.facts.uniformBucketLevelAccess, iamPolicySha256: bucket.iamSha256 },
    database: { locationId: database.locationId, type: database.type },
    queryProjectIamPolicySha256: queryIamSha256,
  };
  parsePrivateInputs(structuredClone(inputs));
  return inputs;
}
