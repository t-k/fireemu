import { createHash } from "node:crypto";
import { googleError, isObject, isTimestamp, jsonBody, readResponse } from "../storage-rules/acceptance-core.mjs";

// Stage 2c: the one Firebase Rules release the Storage Rules observation has to move out of the way. The query project's bucket release
// (`firebase.storage/<bucket>`) points at a ruleset another lane depends on; the observation needs the bucket to have no release, so the
// release is read, saved, deleted before the recordings and published again, with the same ruleset, after them. This module is the pure
// part: names, what a release or ruleset response is, and the saved record that carries the release from the first run to the second.
// It sends nothing.
export const PROJECT_ID = "fireemu-oracle-query";
export const RULES_HOST = "https://firebaserules.googleapis.com";
const RULESET_NAME = /^projects\/fireemu-oracle-query\/rulesets\/[A-Za-z0-9_-]{1,128}$/;
const BUCKET = /^[a-z0-9][a-z0-9._-]{2,221}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const sha = (value) => createHash("sha256").update(value).digest("hex");
const refuse = (message) => { throw new Error(message); };
const onlyKeys = (value, allowed) => Object.keys(value).every((key) => allowed.includes(key));

export const isBucket = (value) => typeof value === "string" && BUCKET.test(value);
export const isRulesetName = (value) => typeof value === "string" && RULESET_NAME.test(value);
export const bucketReleaseName = (bucket) => (isBucket(bucket) ? `projects/${PROJECT_ID}/releases/firebase.storage/${bucket}` : refuse("invalid bucket"));
export const BUCKETLESS_RELEASE_NAME = `projects/${PROJECT_ID}/releases/firebase.storage`;
export const RELEASES_URL = `${RULES_HOST}/v1/projects/${PROJECT_ID}/releases`;
export const rulesUrl = (resourceName) => `${RULES_HOST}/v1/${resourceName}`;

const canonical = (value) => (Array.isArray(value) ? value.map(canonical) : isObject(value) ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])])) : value);
export const canonicalDigest = (value) => sha(JSON.stringify(canonical(value)));
const response = (raw) => { try { return readResponse(raw); } catch { return null; } };

/** A release read (or the answer to its creation): present with its ruleset, absent (404), or not what the schema allows. */
export function classifyRelease(raw, expectedName) {
  const read = response(raw);
  if (read === null) return Object.freeze({ state: "unexpected" });
  if (read.status === 200) {
    const body = jsonBody(read);
    if (isObject(body) && onlyKeys(body, ["name", "rulesetName", "createTime", "updateTime"]) && body.name === expectedName && isRulesetName(body.rulesetName) && isTimestamp(body.createTime) && isTimestamp(body.updateTime)) {
      return Object.freeze({ state: "present", release: Object.freeze({ name: body.name, rulesetName: body.rulesetName, createTime: body.createTime, updateTime: body.updateTime, bodySha256: canonicalDigest(body) }) });
    }
    return Object.freeze({ state: "unexpected" });
  }
  return Object.freeze({ state: googleError(read, 404, "NOT_FOUND") ? "absent" : "unexpected" });
}

/** A ruleset read: present (its name, creation time and a digest of its source, never the source), absent, or unexpected. */
export function classifyRuleset(raw, expectedName) {
  const read = response(raw);
  if (read === null) return Object.freeze({ state: "unexpected" });
  if (read.status === 200) {
    const body = jsonBody(read);
    if (isObject(body) && onlyKeys(body, ["name", "createTime", "source", "metadata"]) && body.name === expectedName && isRulesetName(body.name) && isTimestamp(body.createTime) && isObject(body.source)) {
      return Object.freeze({ state: "present", ruleset: Object.freeze({ name: body.name, createTime: body.createTime, sourceSha256: canonicalDigest(body.source) }) });
    }
    return Object.freeze({ state: "unexpected" });
  }
  return Object.freeze({ state: googleError(read, 404, "NOT_FOUND") ? "absent" : "unexpected" });
}

/** A release deletion is accepted only as the empty object. */
export function isEmptyOk(raw) {
  const read = response(raw);
  if (read === null || read.status !== 200) return false;
  const body = jsonBody(read);
  return isObject(body) && Object.keys(body).length === 0;
}

const SAVED_KEYS = ["schemaVersion", "bucket", "name", "rulesetName", "createTime", "updateTime", "releaseBodySha256", "rulesetSourceSha256"];

/** The record that carries the release from the run that deletes it to the run that publishes it again. */
export function makeSaved({ bucket, release, ruleset }) {
  return parseSaved({ schemaVersion: 1, bucket, name: release.name, rulesetName: release.rulesetName, createTime: release.createTime, updateTime: release.updateTime, releaseBodySha256: release.bodySha256, rulesetSourceSha256: ruleset.sourceSha256 });
}

export function parseSaved(value) {
  if (!isObject(value) || Object.getPrototypeOf(value) !== Object.prototype || Reflect.ownKeys(value).length !== SAVED_KEYS.length || !SAVED_KEYS.every((key) => Object.hasOwn(value, key))) refuse("invalid saved release");
  if (value.schemaVersion !== 1 || !isBucket(value.bucket) || value.name !== bucketReleaseName(value.bucket) || !isRulesetName(value.rulesetName) || !isTimestamp(value.createTime) || !isTimestamp(value.updateTime) || !HEX64.test(value.releaseBodySha256) || !HEX64.test(value.rulesetSourceSha256)) refuse("invalid saved release");
  return Object.freeze(Object.fromEntries(SAVED_KEYS.map((key) => [key, value[key]])));
}

const BASELINE_KEYS = ["release", "ruleset"];
const BASELINE_RELEASE_KEYS = ["createTime", "updateTime", "bodySha256"];
const BASELINE_RULESET_KEYS = ["createTime", "sourceSha256"];
const exactKeys = (value, keys) => isObject(value) && Object.getPrototypeOf(value) === Object.prototype && Reflect.ownKeys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));

/**
 * The baseline a reclaim run confirms before it writes anything: the release and the ruleset exactly as a recorded read left them (the
 * times the service gave, and the digests this module computes). The operator pins it through the corpus digest of the approval.
 */
export function parseBaseline(value) {
  if (!exactKeys(value, BASELINE_KEYS) || !exactKeys(value.release, BASELINE_RELEASE_KEYS) || !exactKeys(value.ruleset, BASELINE_RULESET_KEYS)) refuse("invalid baseline");
  const { release, ruleset } = value;
  if (!isTimestamp(release.createTime) || !isTimestamp(release.updateTime) || !HEX64.test(release.bodySha256) || !isTimestamp(ruleset.createTime) || !HEX64.test(ruleset.sourceSha256)) refuse("invalid baseline");
  return Object.freeze({
    release: Object.freeze({ createTime: release.createTime, updateTime: release.updateTime, bodySha256: release.bodySha256 }),
    ruleset: Object.freeze({ createTime: ruleset.createTime, sourceSha256: ruleset.sourceSha256 }),
  });
}

/** Whether a release read is the baseline's release (and points at the expected ruleset): the times and the digest of the whole body. */
export const matchesBaselineRelease = (release, baseline, rulesetName) => release.rulesetName === rulesetName && release.createTime === baseline.release.createTime && release.updateTime === baseline.release.updateTime && release.bodySha256 === baseline.release.bodySha256;
/** Whether a ruleset read is the baseline's ruleset: its creation time and the digest of its source. */
export const matchesBaselineRuleset = (ruleset, baseline) => ruleset.createTime === baseline.ruleset.createTime && ruleset.sourceSha256 === baseline.ruleset.sourceSha256;

/** The digest the second run's approval pins for the saved record. */
export const savedSha256 = (saved) => canonicalDigest(parseSaved(saved));
