import { createHash } from "node:crypto";
import { PROJECT_ID, stateSha256 } from "./state.mjs";

// Stage 2e: the requests, in order, for one expected state. Preflight reads every fact the cleanup relies on (both releases are absent, the Rulesets are the two
// kept ones and the run's own, each object is there with the journaled generation, the accounts are there); the writes delete exactly those objects, accounts
// and rulesets, once each; the verification reads prove each is gone and that nothing else moved.
export const RULES_HOST = "https://firebaserules.googleapis.com";
export const GCS_HOST = "https://storage.googleapis.com";
export const AUTH_HOST = "https://identitytoolkit.googleapis.com";
const sha = (value) => createHash("sha256").update(value).digest("hex");
const json = (value) => Buffer.from(JSON.stringify(value));
const objectUrl = (state, name) => `${GCS_HOST}/storage/v1/b/${state.bucket}/o/${encodeURIComponent(name)}`;
const bucketRelease = (state) => `${RULES_HOST}/v1/projects/${PROJECT_ID}/releases/firebase.storage/${state.bucket}`;
const bucketlessRelease = `${RULES_HOST}/v1/projects/${PROJECT_ID}/releases/firebase.storage`;
const rulesetList = `${RULES_HOST}/v1/projects/${PROJECT_ID}/rulesets?pageSize=100`;
const accountUrl = (verb) => `${AUTH_HOST}/v1/projects/${PROJECT_ID}/accounts:${verb}`;

export const TOKEN_ID = "preflight/auth/owner-token";
export const IDENTITY_ID = "preflight/owner/identity";

/** Every request after the owner's token and identity, as { id, phase, kind, method, url, body, ... }; the kind names what the run expects of its answer. */
export function restoreRequests(state) {
  const list = [];
  const add = (entry) => list.push(Object.freeze({ body: null, ...entry }));
  add({ id: "preflight/release/bucket", phase: "preflight", kind: "release-absent", method: "GET", url: bucketRelease(state) });
  add({ id: "preflight/release/bucketless", phase: "preflight", kind: "release-absent", method: "GET", url: bucketlessRelease });
  add({ id: "preflight/rulesets/list", phase: "preflight", kind: "rulesets-with-run", method: "GET", url: rulesetList });
  state.objects.forEach((object, index) => add({ id: `preflight/object/${index}`, phase: "preflight", kind: "object-present", method: "GET", url: objectUrl(state, object.name), index }));
  add({ id: "preflight/accounts/lookup", phase: "preflight", kind: "accounts-present", method: "POST", url: accountUrl("lookup"), body: json({ localId: [...state.accounts] }) });
  state.objects.forEach((object, index) => add({ id: `cleanup/object/${index}/delete`, phase: "normal", kind: "object-delete", method: "DELETE", url: `${objectUrl(state, object.name)}?ifGenerationMatch=${object.generation}`, index }));
  state.accounts.forEach((uid, index) => add({ id: `cleanup/account/${index}/delete`, phase: "normal", kind: "json-ok", method: "POST", url: accountUrl("delete"), body: json({ localId: uid }), index }));
  state.rulesets.forEach((name, index) => add({ id: `cleanup/ruleset/${index}/delete`, phase: "normal", kind: "json-ok", method: "DELETE", url: `${RULES_HOST}/v1/${name}`, index }));
  state.objects.forEach((object, index) => add({ id: `verify/object/${index}/absent`, phase: "normal", kind: "object-absent", method: "GET", url: objectUrl(state, object.name), index }));
  add({ id: "verify/accounts/lookup", phase: "normal", kind: "accounts-absent", method: "POST", url: accountUrl("lookup"), body: json({ localId: [...state.accounts] }) });
  add({ id: "verify/rulesets/list", phase: "normal", kind: "rulesets-kept", method: "GET", url: rulesetList });
  add({ id: "verify/release/bucket", phase: "normal", kind: "release-absent", method: "GET", url: bucketRelease(state) });
  add({ id: "verify/release/bucketless", phase: "normal", kind: "release-absent", method: "GET", url: bucketlessRelease });
  add({ id: "verify/objects/list", phase: "normal", kind: "objects-empty", method: "GET", url: `${GCS_HOST}/storage/v1/b/${state.bucket}/o?prefix=${encodeURIComponent(state.runPrefix)}&maxResults=1` });
  return Object.freeze(list);
}

export const preflightIdsOf = (state) => Object.freeze([TOKEN_ID, IDENTITY_ID, ...restoreRequests(state).filter((entry) => entry.phase === "preflight").map((entry) => entry.id)]);
export const allIdsOf = (state) => Object.freeze([TOKEN_ID, IDENTITY_ID, ...restoreRequests(state).map((entry) => entry.id)]);

/** The operation corpus the approval pins as its manifest: every request with its method, URL and body digest, the state's digest and the owner's address digest. */
export function restoreCorpus({ state, ownerEmailSha256 }) {
  if (typeof ownerEmailSha256 !== "string" || !/^[0-9a-f]{64}$/.test(ownerEmailSha256)) throw new Error("invalid corpus input");
  const list = [
    { id: TOKEN_ID, method: "POST", url: "https://oauth2.googleapis.com/token", bodySha256: null },
    { id: IDENTITY_ID, method: "GET", url: "https://www.googleapis.com/oauth2/v2/userinfo", bodySha256: null },
    ...restoreRequests(state).map((entry) => ({ id: entry.id, method: entry.method, url: entry.url, bodySha256: entry.body === null ? null : sha(entry.body) })),
  ];
  const document = { project: PROJECT_ID, stateSha256: stateSha256(state), ownerEmailSha256, list };
  return Object.freeze({ list, sha256: sha(JSON.stringify(document)) });
}
