import { createHash } from "node:crypto";

// Stage 2f: a small shape probe on the query project, run while the bucket's release is absent. It records the answers of the Rules API for a ruleset it creates and
// deletes (and for a name that never existed), of Cloud Storage JSON for one object and for the prefix list, and of Firestore for one document, so that the judges of
// the next recording are fitted to recorded bodies. Everything it creates is owned (a fixed name, or a name the create answer proves) and is deleted in the same run;
// three reads at the end prove that. The answers of the shape steps are recorded and never judged: only a create answer that cannot prove ownership, and a final read
// that cannot prove the deletion, stop the run.
export const PROJECT_ID = "fireemu-oracle-query";
export const RULES_HOST = "https://firebaserules.googleapis.com";
export const GCS_HOST = "https://storage.googleapis.com";
export const FIRESTORE_HOST = "https://firestore.googleapis.com";
export const OBJECT_NAME = "STORAGE-RULES/probe-2f/object.bin";
export const OBJECT_PREFIX = "STORAGE-RULES/probe-2f/";
export const DOCUMENT_ID = "probe-2f-doc";
export const NEVER_RULESET = `projects/${PROJECT_ID}/rulesets/00000000-0000-4000-8000-0000000002f0`;
export const RULESET_SOURCE = "rules_version = '2';\nservice firebase.storage {\n  match /b/{bucket}/o {\n    match /STORAGE-RULES/probe-2f/{name} {\n      allow get: if false;\n    }\n  }\n}\n";
export const OBJECT_BODY = "probe-2f";
const DOCUMENTS = `projects/${PROJECT_ID}/databases/(default)/documents`;
export const DOCUMENT_NAME = `${DOCUMENTS}/STORAGE-RULES/${DOCUMENT_ID}`;
const sha = (value) => createHash("sha256").update(value).digest("hex");
const json = (value) => Buffer.from(JSON.stringify(value));
const BUCKET = /^[a-z0-9][a-z0-9._-]{2,221}$/;

export const TOKEN_ID = "preflight/auth/owner-token";
export const IDENTITY_ID = "preflight/owner/identity";
/** The steps whose answers hand over what the run then owns (the ruleset's name, the object's generation, the document's update time). */
export const CREATE_IDS = Object.freeze({ ruleset: "shape/ruleset/create", object: "shape/object/create", document: "shape/document/create" });
export const WRITE_IDS = Object.freeze(["shape/ruleset/create", "shape/ruleset/delete", "shape/object/create", "shape/object/delete", "shape/document/create", "shape/document/delete"]);

const rulesetList = `${RULES_HOST}/v1/projects/${PROJECT_ID}/rulesets?pageSize=100`;
const objectList = (bucket) => `${GCS_HOST}/storage/v1/b/${bucket}/o?prefix=${encodeURIComponent(OBJECT_PREFIX)}&maxResults=1`;
const objectUrl = (bucket) => `${GCS_HOST}/storage/v1/b/${bucket}/o/${encodeURIComponent(OBJECT_NAME)}`;
const documentUrl = `${FIRESTORE_HOST}/v1/${DOCUMENT_NAME}`;

/** The requests whose form does not depend on an answer, in order, as { id, phase, kind, method, url, body }. */
export function staticRequests(bucket) {
  if (typeof bucket !== "string" || !BUCKET.test(bucket)) throw new Error("invalid bucket");
  const list = [];
  const add = (entry) => list.push(Object.freeze({ body: null, ...entry }));
  add({ id: "preflight/rulesets/list", phase: "preflight", kind: "kept-rulesets", method: "GET", url: rulesetList });
  add({ id: "preflight/objects/list", phase: "preflight", kind: "objects-empty", method: "GET", url: objectList(bucket) });
  add({ id: "preflight/document/absent", phase: "preflight", kind: "document-absent", method: "GET", url: documentUrl });
  add({ id: "shape/ruleset/never", phase: "normal", kind: "record", method: "GET", url: `${RULES_HOST}/v1/${NEVER_RULESET}` });
  add({ id: CREATE_IDS.ruleset, phase: "normal", kind: "own-ruleset", method: "POST", url: `${RULES_HOST}/v1/projects/${PROJECT_ID}/rulesets`, body: json({ source: { files: [{ name: "storage.rules", content: RULESET_SOURCE }] } }) });
  add({ id: CREATE_IDS.object, phase: "normal", kind: "own-object", method: "POST", url: `${GCS_HOST}/upload/storage/v1/b/${bucket}/o?uploadType=media&name=${encodeURIComponent(OBJECT_NAME)}&ifGenerationMatch=0`, body: Buffer.from(OBJECT_BODY), contentType: "text/plain" });
  add({ id: "shape/object/list", phase: "normal", kind: "record", method: "GET", url: objectList(bucket) });
  add({ id: CREATE_IDS.document, phase: "normal", kind: "own-document", method: "POST", url: `${FIRESTORE_HOST}/v1/${DOCUMENTS}/STORAGE-RULES?documentId=${DOCUMENT_ID}`, body: json({ fields: { probe: { stringValue: "2f" } } }) });
  add({ id: "shape/document/read", phase: "normal", kind: "record", method: "GET", url: documentUrl });
  add({ id: "verify/rulesets/list", phase: "normal", kind: "kept-rulesets", method: "GET", url: rulesetList });
  add({ id: "verify/objects/list", phase: "normal", kind: "objects-empty", method: "GET", url: objectList(bucket) });
  add({ id: "verify/document/absent", phase: "normal", kind: "document-absent", method: "GET", url: documentUrl });
  return Object.freeze(list);
}

/**
 * The requests that follow from an ownership proof, in the order the run sends them: the ruleset's read, deletion and read after deletion, the object's deletion,
 * the document's deletion. `proofs` holds the values `judge.mjs` proved: `{ ruleset: <name> }`, `{ generation }`, `{ updateTime }`.
 */
export function dependentRequest(id, proofs, bucket) {
  const make = (entry) => Object.freeze({ body: null, phase: "normal", kind: "record", ...entry });
  switch (id) {
    case "shape/ruleset/read": return make({ id, method: "GET", url: `${RULES_HOST}/v1/${proofs.ruleset}` });
    case "shape/ruleset/delete": return make({ id, method: "DELETE", url: `${RULES_HOST}/v1/${proofs.ruleset}` });
    case "shape/ruleset/read-deleted": return make({ id, method: "GET", url: `${RULES_HOST}/v1/${proofs.ruleset}` });
    case "shape/object/delete": return make({ id, method: "DELETE", url: `${objectUrl(bucket)}?ifGenerationMatch=${proofs.generation}` });
    case "shape/document/delete": return make({ id, method: "DELETE", url: `${documentUrl}?currentDocument.updateTime=${encodeURIComponent(proofs.updateTime)}` });
    default: throw new Error("not a dependent request");
  }
}
export const DEPENDENT_IDS = Object.freeze(["shape/ruleset/read", "shape/ruleset/delete", "shape/ruleset/read-deleted", "shape/object/delete", "shape/document/delete"]);

// The order the run sends everything in.
export const ORDER = Object.freeze([
  "preflight/rulesets/list", "preflight/objects/list", "preflight/document/absent",
  "shape/ruleset/never", "shape/ruleset/create", "shape/ruleset/read", "shape/ruleset/delete", "shape/ruleset/read-deleted",
  "shape/object/create", "shape/object/list", "shape/object/delete",
  "shape/document/create", "shape/document/read", "shape/document/delete",
  "verify/rulesets/list", "verify/objects/list", "verify/document/absent",
]);
export const allIds = Object.freeze([TOKEN_ID, IDENTITY_ID, ...ORDER]);
export const preflightIds = Object.freeze([TOKEN_ID, IDENTITY_ID, "preflight/rulesets/list", "preflight/objects/list", "preflight/document/absent"]);

/** The operation corpus the approval pins as its manifest: every request as a template (the dependent ones with their placeholders), with its method, URL and body digest. */
export function shapeCorpus({ bucket, ownerEmailSha256 }) {
  if (typeof ownerEmailSha256 !== "string" || !/^[0-9a-f]{64}$/.test(ownerEmailSha256)) throw new Error("invalid corpus input");
  const placeholders = { ruleset: "<ruleset name>", generation: "<object generation>", updateTime: "<document update time>" };
  const byId = new Map(staticRequests(bucket).map((entry) => [entry.id, entry]));
  const list = [
    { id: TOKEN_ID, method: "POST", url: "https://oauth2.googleapis.com/token", bodySha256: null },
    { id: IDENTITY_ID, method: "GET", url: "https://www.googleapis.com/oauth2/v2/userinfo", bodySha256: null },
    ...ORDER.map((id) => {
      const entry = byId.get(id) ?? dependentRequest(id, placeholders, bucket);
      return { id, method: entry.method, url: entry.url, bodySha256: entry.body === null ? null : sha(entry.body) };
    }),
  ];
  const document = { project: PROJECT_ID, bucket, ownerEmailSha256, list };
  return Object.freeze({ list, sha256: sha(JSON.stringify(document)) });
}
