import { createHash } from "node:crypto";
import { ENTRY_RULESETS } from "../storage-rules/entry-rulesets.mjs";

// Stage 2e: the cleanup of what a stage 3 recording left behind. The state to clean is read from the journal of that recording and written, by hand and
// once, into a private file (`expected-state.json`, mode 600): the objects the run created and did not delete (with the generation the journal shows), the Auth
// accounts it created (by uid), and the Rulesets it created (by name). The run this stage performs deletes exactly these and nothing else, and it reads
// everything back first: an object with another generation, an account or ruleset that is not there, or a ruleset that is one of the two production keeps,
// stops it before anything is deleted.
export const PROJECT_ID = "fireemu-oracle-query";
const BUCKET = /^[a-z0-9][a-z0-9._-]{2,221}$/;
const RUN_ID = /^[a-z0-9][a-z0-9-]{0,47}$/;
const RULESET = /^projects\/fireemu-oracle-query\/rulesets\/[A-Za-z0-9_-]{1,128}$/;
const GENERATION = /^[1-9]\d{0,19}$/;
const KEPT = new Set(ENTRY_RULESETS.map((entry) => entry.name));
const plain = (value) => value !== null && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype;
const closed = (value, keys) => plain(value) && Reflect.ownKeys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
const refuse = (message) => { throw new Error(message); };
export const isBucket = (value) => typeof value === "string" && BUCKET.test(value);

const sorted = (list, key) => list.every((entry, index) => index === 0 || key(list[index - 1]) < key(entry));

/** The expected state, validated: a closed record, sorted without duplicates, every name inside the run's own namespace, and none of the kept rulesets. */
export function parseState(value) {
  if (!closed(value, ["schemaVersion", "runId", "runPrefix", "bucket", "objects", "accounts", "rulesets"]) || value.schemaVersion !== 1) refuse("invalid expected state");
  if (typeof value.runId !== "string" || !RUN_ID.test(value.runId) || value.runPrefix !== `STORAGE-RULES/${value.runId}/` || !isBucket(value.bucket)) refuse("invalid expected state");
  const { objects, accounts, rulesets } = value;
  if (!Array.isArray(objects) || objects.length > 50 || !Array.isArray(accounts) || accounts.length > 10 || !Array.isArray(rulesets) || rulesets.length > 10) refuse("invalid expected state");
  for (const object of objects) {
    if (!closed(object, ["name", "generation"]) || typeof object.name !== "string" || !object.name.startsWith(value.runPrefix) || object.name.length > 512 || !/^[\x21-\x7e]+$/.test(object.name) || object.name.includes("..") || object.name.endsWith("/") || typeof object.generation !== "string" || !GENERATION.test(object.generation)) refuse("invalid expected state");
  }
  const accountPattern = new RegExp(`^storage-rules-${value.runId}-[a-z0-9-]{1,40}$`);
  if (accounts.some((uid) => typeof uid !== "string" || !accountPattern.test(uid))) refuse("invalid expected state");
  if (rulesets.some((name) => typeof name !== "string" || !RULESET.test(name) || KEPT.has(name))) refuse("invalid expected state");
  if (!sorted(objects, (object) => object.name) || !sorted(accounts, (uid) => uid) || !sorted(rulesets, (name) => name)) refuse("invalid expected state");
  return Object.freeze({
    schemaVersion: 1, runId: value.runId, runPrefix: value.runPrefix, bucket: value.bucket,
    objects: Object.freeze(objects.map((object) => Object.freeze({ name: object.name, generation: object.generation }))),
    accounts: Object.freeze([...accounts]), rulesets: Object.freeze([...rulesets]),
  });
}

/** The digest an approval pins for the state: a canonical JSON of the validated record. */
export const stateSha256 = (state) => createHash("sha256").update(JSON.stringify({ schemaVersion: state.schemaVersion, runId: state.runId, runPrefix: state.runPrefix, bucket: state.bucket, objects: state.objects.map((object) => ({ name: object.name, generation: object.generation })), accounts: [...state.accounts], rulesets: [...state.rulesets] })).digest("hex");
