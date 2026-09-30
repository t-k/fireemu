import { googleError, isObject, jsonBody, readResponse } from "../storage-rules/acceptance-core.mjs";
import { ENTRY_RULESETS } from "../storage-rules/entry-rulesets.mjs";

// What the cleanup expects of each answer, by the kind the plan gives the request. Every judge is a pure function of the raw response and the expected
// state; none of them reads a secret, and each answers true only for exactly what the cleanup needs to go on (or to call the state clean).
const decode = (raw) => { try { return readResponse(raw); } catch { return null; } };
const notFoundJson = (response) => response.status === 404 && (() => {
  const body = jsonBody(response);
  return isObject(body) && isObject(body.error) && body.error.code === 404 && Array.isArray(body.error.errors) && isObject(body.error.errors[0]) && body.error.errors[0].reason === "notFound";
})();
const byName = (left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0);

/** What a rulesets list page holds, by name, creation time and services (sorted by name), or null when it is not one complete page of that shape. */
function listed(response) {
  const body = response.status === 200 ? jsonBody(response) : undefined;
  if (!isObject(body) || Reflect.ownKeys(body).some((key) => key !== "rulesets") || !Array.isArray(body.rulesets)) return null;
  const entries = [];
  for (const entry of body.rulesets) {
    if (!isObject(entry) || typeof entry.name !== "string" || typeof entry.createTime !== "string" || !isObject(entry.metadata) || !Array.isArray(entry.metadata.services) || !entry.metadata.services.every((service) => typeof service === "string")) return null;
    entries.push({ name: entry.name, createTime: entry.createTime, services: [...entry.metadata.services].sort() });
  }
  return entries.sort(byName);
}
// The two rulesets that stay, as production listed them at the start of the recordings (stage 2d probe, 2026-09-29T23:27Z; `rulesetList` in the production fixtures).
const KEPT_CREATE_TIMES = Object.freeze({
  "projects/fireemu-oracle-query/rulesets/22b746af-a48a-458d-ab5c-7853473bc8c8": "2026-09-25T11:08:54.358767Z",
  "projects/fireemu-oracle-query/rulesets/d0abf7c6-b0b6-4163-8488-7c8a48ac5dd1": "2026-09-23T23:02:05.839536Z",
});
const keptEntries = () => ENTRY_RULESETS.map((entry) => ({ name: entry.name, createTime: KEPT_CREATE_TIMES[entry.name], services: [...entry.services] }));
const equalEntries = (left, right) => left.length === right.length && left.every((entry, index) => entry.name === right[index].name && (right[index].createTime === undefined || entry.createTime === right[index].createTime) && entry.services.length === right[index].services.length && entry.services.every((service, at) => service === right[index].services[at]));

const JUDGES = {
  // A release is absent when Google says the entity was not found.
  "release-absent": (response) => response.status === 404 && googleError(response, 404, "NOT_FOUND"),
  // The list is the two kept rulesets and the run's own (each serving the storage rules), on one page.
  "rulesets-with-run": (response, { state }) => {
    const seen = listed(response);
    const expected = [...keptEntries(), ...state.rulesets.map((name) => ({ name, services: ["firebase.storage"] }))].sort(byName);
    return seen !== null && equalEntries(seen, expected);
  },
  // Only the two kept rulesets.
  "rulesets-kept": (response) => { const seen = listed(response); return seen !== null && equalEntries(seen, keptEntries()); },
  "object-present": (response, { state, request }) => {
    const expected = state.objects[request.index];
    const body = response.status === 200 ? jsonBody(response) : undefined;
    return isObject(body) && body.kind === "storage#object" && body.bucket === state.bucket && body.name === expected.name && body.generation === expected.generation;
  },
  "object-absent": (response) => notFoundJson(response),
  // A deletion is a 204 without a body.
  "object-delete": (response) => response.status === 204 && response.bytes.length === 0,
  // A ruleset deletion: 200 with a JSON object. The answer was not recorded before (only the release deletion, 200 `{}`), so the read that follows decides whether it worked.
  "ruleset-delete": (response) => response.status === 200 && isObject(jsonBody(response)),
  "accounts-present": (response, { state }) => {
    const body = response.status === 200 ? jsonBody(response) : undefined;
    if (!isObject(body) || body.kind !== "identitytoolkit#GetAccountInfoResponse" || !Array.isArray(body.users) || !body.users.every((user) => isObject(user) && typeof user.localId === "string")) return false;
    const seen = body.users.map((user) => user.localId).sort();
    return seen.length === state.accounts.length && seen.every((uid, index) => uid === state.accounts[index]);
  },
  // No account of the run: the answer production recorded for a lookup of deleted accounts (conformance/auth-account-production.json, program auth-account/admin/batch-delete,
  // step lookup-after-force): 200 with the kind alone, and no `users` key.
  "accounts-absent": (response) => {
    const body = response.status === 200 ? jsonBody(response) : undefined;
    return isObject(body) && Reflect.ownKeys(body).length === 1 && body.kind === "identitytoolkit#GetAccountInfoResponse";
  },
  // An account deletion, as recorded (auth-account/admin/delete, step delete): 200 with the kind alone.
  "account-delete": (response) => {
    const body = response.status === 200 ? jsonBody(response) : undefined;
    return isObject(body) && Reflect.ownKeys(body).length === 1 && body.kind === "identitytoolkit#DeleteAccountResponse";
  },
  "objects-empty": (response) => {
    const body = response.status === 200 ? jsonBody(response) : undefined;
    const none = (value) => value === undefined || (Array.isArray(value) && value.length === 0);
    return isObject(body) && body.kind === "storage#objects" && none(body.items) && none(body.prefixes) && body.nextPageToken === undefined;
  },
};

export const JUDGE_KINDS = Object.freeze(Object.keys(JUDGES));

/** Whether the raw answer to a request of this kind is the one the cleanup needs. */
export function judgeAnswer(kind, raw, context) {
  const judge = Object.hasOwn(JUDGES, kind) ? JUDGES[kind] : null;
  if (judge === null) return false;
  const response = decode(raw);
  if (response === null) return false;
  try { return judge(response, context) === true; } catch { return false; }
}
