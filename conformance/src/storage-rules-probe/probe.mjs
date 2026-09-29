import { buildCorpus } from "../storage-rules/corpus.mjs";

// Stage 2d: a read-only shape probe of the query project. Stage 3's first recording stopped on a response shape no earlier stage had seen (the
// entry list of Rulesets carries `metadata` that its closed schema did not allow). This probe sends, once each, the read requests stage 3 sends
// before its first write and in its cleanup, with exactly the shapes stage 3 builds, and records each answer in the private journal, so stage 3's
// classifiers can be checked against real bodies before another recording is spent. It writes nothing, judges nothing and stores nothing.
export const PROJECT_ID = "fireemu-oracle-query";
export const RULES_HOST = "https://firebaserules.googleapis.com";
export const GCS_HOST = "https://storage.googleapis.com";
export const FIRESTORE_HOST = "https://firestore.googleapis.com";
const BUCKET = /^[a-z0-9][a-z0-9._-]{2,221}$/;
// Names no run ever creates: the probe reads them expecting absence. They sit in the lane's namespaces but under a name no run ID can take.
export const PROBE_OBJECT = "STORAGE-RULES/probe-2d/absent-object.bin";
export const PROBE_DOCUMENT = "STORAGE-RULES/probe-2d-absent-document";

export const isBucket = (value) => typeof value === "string" && BUCKET.test(value);
const refuse = (message) => { throw new Error(message); };

/** The two Rules sources stage 3 sends to `:test`: the first valid source of its compile program and its invalid source. */
export function compileSources(bucket) {
  if (!isBucket(bucket)) refuse("invalid bucket");
  const corpus = buildCorpus({ bucket, prefix: "STORAGE-RULES/probe-2d/", uidA: "storage-rules-probe-2d-user-a", uidB: "storage-rules-probe-2d-user-b" });
  const program = corpus.managementPrograms.find((entry) => entry.id === "storage-service-compile") ?? refuse("no compile program");
  return Object.freeze({ valid: program.validSources[0].content, invalid: program.invalidSource.content });
}

const testBody = (content) => Buffer.from(JSON.stringify({ source: { files: [{ name: "storage.rules", content }] } }));

/** The probe's read requests, in order, each as stage 3 builds it. */
export function probeRequests(bucket) {
  const sources = compileSources(bucket);
  const object = `${GCS_HOST}/storage/v1/b/${bucket}/o/${encodeURIComponent(PROBE_OBJECT)}`;
  return Object.freeze([
    { key: "list", method: "GET", url: `${RULES_HOST}/v1/projects/${PROJECT_ID}/rulesets?pageSize=100`, body: null },
    { key: "metadata", method: "GET", url: object, body: null },
    { key: "media", method: "GET", url: `${object}?alt=media`, body: null },
    { key: "testValid", method: "POST", url: `${RULES_HOST}/v1/projects/${PROJECT_ID}:test`, body: testBody(sources.valid) },
    { key: "testInvalid", method: "POST", url: `${RULES_HOST}/v1/projects/${PROJECT_ID}:test`, body: testBody(sources.invalid) },
    { key: "document", method: "GET", url: `${FIRESTORE_HOST}/v1/projects/${PROJECT_ID}/databases/(default)/documents/${PROBE_DOCUMENT}`, body: null },
  ].map((entry) => Object.freeze(entry)));
}
