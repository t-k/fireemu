import { googleError, isObject, jsonBody, readResponse } from "../storage-rules/acceptance-core.mjs";
import { RULES_CLASSIFIERS } from "../storage-rules/acceptance-rules.mjs";
import { ENTRY_RULESETS, isEntryList } from "../storage-rules/entry-rulesets.mjs";

// What the cleanup expects of each answer, by the kind the plan gives the request. Every judge is a pure function of the raw response and the expected
// state; none of them reads a secret, and each answers true only for exactly what the cleanup needs to go on (or to call the state clean).
const decode = (raw) => { try { return readResponse(raw); } catch { return null; } };
const notFoundJson = (response) => response.status === 404 && (() => {
  const body = jsonBody(response);
  return isObject(body) && isObject(body.error) && body.error.code === 404 && Array.isArray(body.error.errors) && isObject(body.error.errors[0]) && body.error.errors[0].reason === "notFound";
})();
const byName = (left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0);

/** The rulesets a list answer holds, as the stage 3 classifier reports them (sorted by name, each with its services), or null. */
function listed(response) {
  const outcome = RULES_CLASSIFIERS["rules-list-page"](null, response);
  return outcome.verdict === "accepted" && outcome.facts.hasNextPage === false ? outcome.facts.rulesets : null;
}
const equalEntries = (left, right) => left.length === right.length && left.every((entry, index) => entry.name === right[index].name && entry.services.length === right[index].services.length && entry.services.every((service, at) => service === right[index].services[at]));

const JUDGES = {
  // A release is absent when Google says the entity was not found.
  "release-absent": (response) => response.status === 404 && googleError(response, 404, "NOT_FOUND"),
  // The list is the two kept rulesets and the run's own (each serving the storage rules), on one page.
  "rulesets-with-run": (response, { state }) => {
    const seen = listed(response);
    const expected = [...ENTRY_RULESETS.map((entry) => ({ name: entry.name, services: [...entry.services] })), ...state.rulesets.map((name) => ({ name, services: ["firebase.storage"] }))].sort(byName);
    return seen !== null && equalEntries(seen, expected);
  },
  // Only the two kept rulesets.
  "rulesets-kept": (response) => { const seen = listed(response); return seen !== null && isEntryList(seen); },
  "object-present": (response, { state, request }) => {
    const expected = state.objects[request.index];
    const body = response.status === 200 ? jsonBody(response) : undefined;
    return isObject(body) && body.kind === "storage#object" && body.bucket === state.bucket && body.name === expected.name && body.generation === expected.generation;
  },
  "object-absent": (response) => notFoundJson(response),
  // A deletion is a 204 without a body.
  "object-delete": (response) => response.status === 204 && response.bytes.length === 0,
  // A deletion the API answers with a JSON object; the read that follows decides whether it worked.
  "json-ok": (response) => response.status === 200 && isObject(jsonBody(response)),
  "accounts-present": (response, { state }) => {
    const body = response.status === 200 ? jsonBody(response) : undefined;
    if (!isObject(body) || !Array.isArray(body.users) || !body.users.every((user) => isObject(user) && typeof user.localId === "string")) return false;
    const seen = body.users.map((user) => user.localId).sort();
    return seen.length === state.accounts.length && seen.every((uid, index) => uid === state.accounts[index]);
  },
  "accounts-absent": (response) => {
    const body = response.status === 200 ? jsonBody(response) : undefined;
    return isObject(body) && (body.users === undefined || (Array.isArray(body.users) && body.users.length === 0));
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
