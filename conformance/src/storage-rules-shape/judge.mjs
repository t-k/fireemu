import { googleError, isObject, isTimestamp, jsonBody, readResponse } from "../storage-rules/acceptance-core.mjs";
import { ENTRY_RULESETS } from "../storage-rules/entry-rulesets.mjs";
import { DOCUMENT_NAME, OBJECT_NAME, PROJECT_ID } from "./plan.mjs";

// What the probe expects of an answer. Three kinds guard the environment before anything is created and prove the deletion at the end (the two kept rulesets and nothing
// else, no object under the probe's prefix, no probe document). Three kinds read the ownership proof out of a create answer (the ruleset's name, the object's generation,
// the document's update time); the shape steps in between are recorded and never judged (`record`). Every judge is a pure function of the raw answer.
const decode = (raw) => { try { return readResponse(raw); } catch { return null; } };
const byName = (left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
const RULESET_NAME = new RegExp(`^projects/${PROJECT_ID}/rulesets/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`);
const KEPT_NAMES = new Set(ENTRY_RULESETS.map((entry) => entry.name));
// The two rulesets that stay, as production listed them at the start of the recordings (stage 2d probe, 2026-09-29T23:27Z; `rulesetList` in the production fixtures).
const KEPT_CREATE_TIMES = Object.freeze({
  "projects/fireemu-oracle-query/rulesets/22b746af-a48a-458d-ab5c-7853473bc8c8": "2026-09-25T11:08:54.358767Z",
  "projects/fireemu-oracle-query/rulesets/d0abf7c6-b0b6-4163-8488-7c8a48ac5dd1": "2026-09-23T23:02:05.839536Z",
});

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
const keptEntries = () => ENTRY_RULESETS.map((entry) => ({ name: entry.name, createTime: KEPT_CREATE_TIMES[entry.name], services: [...entry.services] }));
const equalEntries = (left, right) => left.length === right.length && left.every((entry, index) => entry.name === right[index].name && entry.createTime === right[index].createTime && entry.services.length === right[index].services.length && entry.services.every((service, at) => service === right[index].services[at]));

const JUDGES = {
  "kept-rulesets": (response) => { const seen = listed(response); return seen !== null && equalEntries(seen, keptEntries()); },
  "objects-empty": (response) => {
    const body = response.status === 200 ? jsonBody(response) : undefined;
    const none = (value) => value === undefined || (Array.isArray(value) && value.length === 0);
    return isObject(body) && body.kind === "storage#objects" && none(body.items) && none(body.prefixes) && body.nextPageToken === undefined;
  },
  // A Firestore document that is not there: 404 with the Google error `NOT_FOUND` (stage 2d probe, `documentAbsent`).
  "document-absent": (response) => googleError(response, 404, "NOT_FOUND"),
  // A shape step: whatever the answer is, it is recorded.
  record: () => true,
};

/** The values an ownership proof can hand over, by kind; each returns the value or null. */
const PROOFS = {
  "own-ruleset": (response) => {
    const body = response.status === 200 ? jsonBody(response) : undefined;
    return isObject(body) && typeof body.name === "string" && RULESET_NAME.test(body.name) && !KEPT_NAMES.has(body.name) && typeof body.createTime === "string" ? body.name : null;
  },
  "own-object": (response, { bucket }) => {
    const body = response.status === 200 ? jsonBody(response) : undefined;
    return isObject(body) && body.kind === "storage#object" && body.bucket === bucket && body.name === OBJECT_NAME && typeof body.generation === "string" && /^[1-9]\d{0,19}$/.test(body.generation) ? body.generation : null;
  },
  "own-document": (response) => {
    const body = response.status === 200 ? jsonBody(response) : undefined;
    return isObject(body) && body.name === DOCUMENT_NAME && typeof body.updateTime === "string" && isTimestamp(body.updateTime) ? body.updateTime : null;
  },
};

export const JUDGE_KINDS = Object.freeze([...Object.keys(JUDGES), ...Object.keys(PROOFS)]);

/** Whether the raw answer of a request of this kind is the one the probe needs to go on (or to call the state clean). A proof kind is judged by whether it proves ownership. */
export function judgeAnswer(kind, raw, context) {
  if (Object.hasOwn(PROOFS, kind)) return proofOf(kind, raw, context) !== null;
  const judge = Object.hasOwn(JUDGES, kind) ? JUDGES[kind] : null;
  if (judge === null) return false;
  const response = decode(raw);
  if (response === null) return false;
  try { return judge(response, context) === true; } catch { return false; }
}

/** The ownership proof a create answer hands over, or null. */
export function proofOf(kind, raw, context) {
  const proof = Object.hasOwn(PROOFS, kind) ? PROOFS[kind] : null;
  if (proof === null) return null;
  const response = decode(raw);
  if (response === null) return null;
  try { return proof(response, context) ?? null; } catch { return null; }
}
