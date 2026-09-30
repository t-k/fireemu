import assert from "node:assert/strict";
import test from "node:test";
import { ENTRY_RULESETS } from "./storage-rules/entry-rulesets.mjs";
import { judgeAnswer, JUDGE_KINDS, proofOf } from "./storage-rules-shape/judge.mjs";
import { CREATE_IDS, DEPENDENT_IDS, DOCUMENT_NAME, NEVER_RULESET, OBJECT_NAME, ORDER, WRITE_IDS, allIds, dependentRequest, preflightIds, shapeCorpus, staticRequests } from "./storage-rules-shape/plan.mjs";
import { createShapeTargets, grantKey } from "./storage-rules-shape/targets.mjs";
import { PRODUCTION, rawOf } from "./storage-rules-production-fixtures.mjs";
import { BUCKET, DOCUMENT, OBJECT, RULESET, ownerDigest } from "./storage-rules-shape-support.mjs";

const json = (body, status = 200, type = "application/json; charset=UTF-8") => ({ status, rawHeaders: ["Content-Type", type], bytes: Buffer.from(JSON.stringify(body)) });
const statics = staticRequests(BUCKET);
const byId = (id) => statics.find((entry) => entry.id === id) ?? assert.fail(id);
const proofs = { ruleset: RULESET, generation: "1790727977683752", updateTime: "2026-09-30T02:30:01.654321Z" };
const KEPT_TIMES = ["2026-09-25T11:08:54.358767Z", "2026-09-23T23:02:05.839536Z"];

test("the plan is 19 requests in a fixed order: 5 preflight, 11 steps and 3 proving reads", () => {
  assert.equal(allIds.length, 19);
  assert.equal(new Set(allIds).size, 19);
  assert.deepEqual(preflightIds, ["preflight/auth/owner-token", "preflight/owner/identity", "preflight/rulesets/list", "preflight/objects/list", "preflight/document/absent"]);
  assert.deepEqual(allIds.slice(0, 2), ["preflight/auth/owner-token", "preflight/owner/identity"]);
  assert.deepEqual(allIds.slice(2), ORDER);
  assert.deepEqual(ORDER.filter((id) => id.startsWith("verify/")), ["verify/rulesets/list", "verify/objects/list", "verify/document/absent"]);
  assert.deepEqual(ORDER.slice(0, 3), ["preflight/rulesets/list", "preflight/objects/list", "preflight/document/absent"]);
  // Every request is either static or dependent, exactly once.
  assert.deepEqual([...statics.map((entry) => entry.id), ...DEPENDENT_IDS].sort(), [...ORDER].sort());
  assert.deepEqual(statics.map((entry) => entry.phase), statics.map((entry) => (entry.id.startsWith("preflight/") ? "preflight" : "normal")));
  // The ruleset is read once before it exists (a name that never did), then created, read, deleted and read again.
  assert.deepEqual(ORDER.filter((id) => id.startsWith("shape/ruleset/")), ["shape/ruleset/never", "shape/ruleset/create", "shape/ruleset/read", "shape/ruleset/delete", "shape/ruleset/read-deleted"]);
  assert.equal(new Set(WRITE_IDS).size, 6);
  assert.deepEqual([...WRITE_IDS].sort(), ["shape/document/create", "shape/document/delete", "shape/object/create", "shape/object/delete", "shape/ruleset/create", "shape/ruleset/delete"]);
  assert.equal(Object.isFrozen(statics) && statics.every((entry) => Object.isFrozen(entry)), true);
  assert.throws(() => staticRequests("Bad Bucket"), /invalid bucket/);
  assert.throws(() => staticRequests(5), /invalid bucket/);
});

test("each request is exactly the read or the write it names: URL, method, body and content type", () => {
  const obj = `https://storage.googleapis.com/storage/v1/b/${BUCKET}/o/${encodeURIComponent(OBJECT_NAME)}`;
  const list = `https://storage.googleapis.com/storage/v1/b/${BUCKET}/o?prefix=${encodeURIComponent("STORAGE-RULES/probe-2f/")}&maxResults=1`;
  const doc = `https://firestore.googleapis.com/v1/${DOCUMENT_NAME}`;
  const shape = (id) => [byId(id).method, byId(id).url, byId(id).body === null ? null : byId(id).body.toString("utf8")];
  assert.equal(OBJECT_NAME, OBJECT);
  assert.equal(DOCUMENT_NAME, DOCUMENT);
  assert.deepEqual(shape("preflight/rulesets/list"), ["GET", "https://firebaserules.googleapis.com/v1/projects/fireemu-oracle-query/rulesets?pageSize=100", null]);
  assert.deepEqual(shape("preflight/objects/list"), ["GET", list, null]);
  assert.deepEqual(shape("preflight/document/absent"), ["GET", doc, null]);
  assert.deepEqual(shape("shape/ruleset/never"), ["GET", `https://firebaserules.googleapis.com/v1/${NEVER_RULESET}`, null]);
  assert.equal(NEVER_RULESET, "projects/fireemu-oracle-query/rulesets/00000000-0000-4000-8000-0000000002f0");
  const create = shape(CREATE_IDS.ruleset);
  assert.deepEqual(create.slice(0, 2), ["POST", "https://firebaserules.googleapis.com/v1/projects/fireemu-oracle-query/rulesets"]);
  assert.deepEqual(JSON.parse(create[2]), { source: { files: [{ name: "storage.rules", content: "rules_version = '2';\nservice firebase.storage {\n  match /b/{bucket}/o {\n    match /STORAGE-RULES/probe-2f/{name} {\n      allow get: if false;\n    }\n  }\n}\n" }] } });
  assert.deepEqual(shape(CREATE_IDS.object), ["POST", `https://storage.googleapis.com/upload/storage/v1/b/${BUCKET}/o?uploadType=media&name=STORAGE-RULES%2Fprobe-2f%2Fobject.bin&ifGenerationMatch=0`, "probe-2f"]);
  assert.equal(byId(CREATE_IDS.object).contentType, "text/plain");
  assert.deepEqual(shape("shape/object/list"), ["GET", list, null]);
  assert.deepEqual([byId(CREATE_IDS.document).method, byId(CREATE_IDS.document).url, JSON.parse(byId(CREATE_IDS.document).body)], ["POST", "https://firestore.googleapis.com/v1/projects/fireemu-oracle-query/databases/(default)/documents/STORAGE-RULES?documentId=probe-2f-doc", { fields: { probe: { stringValue: "2f" } } }]);
  assert.deepEqual(shape("shape/document/read"), ["GET", doc, null]);
  for (const id of ["verify/rulesets/list", "verify/objects/list", "verify/document/absent"]) assert.deepEqual(shape(id), shape(id.replace("verify/", "preflight/")));
  const dep = (id) => dependentRequest(id, proofs, BUCKET);
  assert.deepEqual([dep("shape/ruleset/read").method, dep("shape/ruleset/read").url], ["GET", `https://firebaserules.googleapis.com/v1/${RULESET}`]);
  assert.deepEqual([dep("shape/ruleset/delete").method, dep("shape/ruleset/delete").url], ["DELETE", `https://firebaserules.googleapis.com/v1/${RULESET}`]);
  assert.deepEqual([dep("shape/ruleset/read-deleted").method, dep("shape/ruleset/read-deleted").url], ["GET", `https://firebaserules.googleapis.com/v1/${RULESET}`]);
  assert.deepEqual([dep("shape/object/delete").method, dep("shape/object/delete").url], ["DELETE", `${obj}?ifGenerationMatch=1790727977683752`]);
  assert.deepEqual([dep("shape/document/delete").method, dep("shape/document/delete").url], ["DELETE", `${doc}?currentDocument.updateTime=2026-09-30T02%3A30%3A01.654321Z`]);
  for (const id of DEPENDENT_IDS) assert.equal(dep(id).body, null, id);
  assert.throws(() => dependentRequest("shape/object/create", proofs, BUCKET), /not a dependent request/);
  assert.throws(() => dependentRequest("preflight/rulesets/list", proofs, BUCKET), /not a dependent request/);
  assert.equal(statics.filter((entry) => entry.method === "DELETE").length, 0);
});

test("the corpus digest moves with the bucket and the owner, and lists every request", () => {
  const corpus = shapeCorpus({ bucket: BUCKET, ownerEmailSha256: ownerDigest });
  assert.deepEqual(corpus.list.map((entry) => entry.id), allIds);
  assert.equal(corpus.list[0].method, "POST");
  assert.equal(corpus.list[1].url, "https://www.googleapis.com/oauth2/v2/userinfo");
  assert.equal(corpus.list.find((entry) => entry.id === "shape/object/delete").url.includes("<object generation>"), true);
  assert.equal(corpus.list.find((entry) => entry.id === "shape/ruleset/delete").url.includes("<ruleset name>"), true);
  assert.equal(corpus.list.find((entry) => entry.id === "shape/document/delete").url.includes("%3Cdocument%20update%20time%3E"), true);
  const digests = new Set([corpus.sha256, shapeCorpus({ bucket: "other-bucket.appspot.com", ownerEmailSha256: ownerDigest }).sha256, shapeCorpus({ bucket: BUCKET, ownerEmailSha256: "f".repeat(64) }).sha256]);
  assert.equal(digests.size, 3);
  assert.equal(shapeCorpus({ bucket: BUCKET, ownerEmailSha256: ownerDigest }).sha256, corpus.sha256);
  for (const bad of ["abc", 5, undefined]) assert.throws(() => shapeCorpus({ bucket: BUCKET, ownerEmailSha256: bad }), /invalid corpus input/);
});

test("targets are built from exact sources; a dependent request needs an ownership proof and is granted to the transport only then", () => {
  const granted = new Set();
  const targets = createShapeTargets({ bucket: BUCKET, digestSalt: "s".repeat(64), grant: (key) => granted.add(key) });
  for (const entry of statics) {
    const prepared = targets.prepare(entry.id);
    assert.deepEqual([prepared.rowId, prepared.credential, prepared.project, prepared.spec.method, prepared.spec.url, prepared.spec.body === null ? null : prepared.spec.body.toString("utf8")], [entry.id, "admin", "fireemu-oracle-query", entry.method, entry.url, entry.body === null ? null : entry.body.toString("utf8")]);
    assert.deepEqual({ ...prepared.spec.headers }, entry.body === null ? {} : { "content-type": entry.contentType ?? "application/json; charset=utf-8" }, entry.id);
    assert.equal(targets.verify(prepared), true);
    assert.deepEqual(targets.request(entry.id), entry);
  }
  assert.equal(granted.size, 0);
  for (const id of DEPENDENT_IDS) {
    const prepared = targets.prepareDependent(id, proofs);
    const expected = dependentRequest(id, proofs, BUCKET);
    assert.deepEqual([prepared.rowId, prepared.spec.method, prepared.spec.url, prepared.spec.body], [id, expected.method, expected.url, null]);
    assert.equal(granted.has(grantKey(expected.method, expected.url, null)), true, id);
    assert.equal(targets.verify(prepared), true);
  }
  assert.equal(granted.size, 4, "read and read-after-deletion share a key");
  assert.equal(targets.prepareIdentity("x").spec.url, "https://www.googleapis.com/oauth2/v2/userinfo");
  for (const id of ["preflight/auth/owner-token", "preflight/owner/identity", "shape/ruleset/read", "", undefined]) { assert.throws(() => targets.prepare(id), /not a planned request/); assert.throws(() => targets.request(id), /not a planned request/); }
  for (const id of ["preflight/rulesets/list", "shape/ruleset/create", "", undefined]) assert.throws(() => targets.prepareDependent(id, proofs), /not a planned request/);
  assert.throws(() => targets.prepareDependent("shape/ruleset/read", null), /not a planned request/);
  // A proof of the wrong form is refused and grants nothing.
  const before = granted.size;
  const other = createShapeTargets({ bucket: BUCKET, digestSalt: "s".repeat(64), grant: (key) => granted.add(key) });
  const spoiled = [
    ["shape/ruleset/delete", { ruleset: ENTRY_RULESETS[0].name }], ["shape/ruleset/delete", { ruleset: ENTRY_RULESETS[1].name }], ["shape/ruleset/delete", { ruleset: "projects/other/rulesets/3f2a9c1e-7b64-4d0a-9e51-0c8a6f2b7d14" }],
    ["shape/ruleset/delete", { ruleset: `${RULESET}/../x` }], ["shape/ruleset/delete", { ruleset: `${RULESET}?x=1` }], ["shape/ruleset/delete", { ruleset: 5 }], ["shape/ruleset/delete", {}], ["shape/ruleset/read-deleted", { ruleset: "projects/fireemu-oracle-query/rulesets/abc" }],
    ["shape/object/delete", { generation: "0" }], ["shape/object/delete", { generation: "1&x=1" }], ["shape/object/delete", { generation: 5 }], ["shape/object/delete", {}], ["shape/object/delete", { generation: "1".repeat(21) }],
    ["shape/document/delete", { updateTime: "not a time" }], ["shape/document/delete", { updateTime: "2026-09-30T02:30:01Z&x=1" }], ["shape/document/delete", {}], ["shape/document/delete", { updateTime: 5 }],
  ];
  for (const [id, bad] of spoiled) assert.throws(() => other.prepareDependent(id, bad), /invalid ownership proof/, `${id} ${JSON.stringify(bad)}`);
  assert.equal(granted.size, before);
  assert.throws(() => createShapeTargets({ bucket: BUCKET, digestSalt: "s" }), /invalid targets options/);
  const read = targets.prepare("preflight/rulesets/list");
  const forged = { rowId: read.rowId, credential: read.credential, project: read.project, redacted: read.redacted, targetSha256: read.targetSha256 };
  Object.defineProperty(forged, "spec", { value: read.spec, enumerable: false });
  for (const value of [null, undefined, {}, { ...read }, JSON.parse(JSON.stringify(read)), forged]) assert.equal(targets.verify(value), false);
  assert.equal(createShapeTargets({ bucket: BUCKET, digestSalt: "t".repeat(64), grant() {} }).verify(read), false);
  assert.equal(JSON.stringify(read).includes("\"spec\""), false);
  assert.equal(Object.isFrozen(read) && Object.isFrozen(read.spec) && Object.isFrozen(read.spec.headers), true);
  assert.notEqual(createShapeTargets({ bucket: BUCKET, digestSalt: "t".repeat(64), grant() {} }).prepare("preflight/rulesets/list").targetSha256, read.targetSha256);
  assert.notEqual(targets.prepare("preflight/objects/list").targetSha256, read.targetSha256);
});

test("the guards accept exactly the clean environment, by the recorded bodies where they exist", () => {
  const kept = (times = KEPT_TIMES, extra = []) => json({ rulesets: [...ENTRY_RULESETS.map((entry, index) => ({ name: entry.name, createTime: times[index], metadata: { services: [...entry.services] } })), ...extra] });
  assert.equal(judgeAnswer("kept-rulesets", rawOf(PRODUCTION.rulesetList), {}), true);
  assert.equal(judgeAnswer("kept-rulesets", kept(), {}), true);
  const withRun = [{ name: RULESET, createTime: "2026-09-30T02:30:00Z", metadata: { services: ["firebase.storage"] } }];
  const mutated = (change) => json({ rulesets: JSON.parse(kept().bytes).rulesets.map(change) });
  for (const bad of [kept(KEPT_TIMES, withRun), json({ rulesets: [] }), json({ rulesets: JSON.parse(kept().bytes).rulesets.slice(0, 1) }), kept(["2026-09-25T11:08:54.358767Z", "2026-09-23T23:02:05.839537Z"]), kept(["2026-09-25T11:08:54.358768Z", "2026-09-23T23:02:05.839536Z"]), json({ ...JSON.parse(kept().bytes), nextPageToken: "t" }), json({ ...JSON.parse(kept().bytes), extra: 1 }), mutated((entry) => ({ ...entry, createTime: 5 })), mutated((entry) => ({ name: entry.name, createTime: entry.createTime })), mutated((entry) => ({ ...entry, metadata: { services: [5] } })), mutated((entry) => ({ ...entry, metadata: { services: ["cloud.firestore", "firebase.storage"] } })), json({ rulesets: "x" }), json({}, 500)]) assert.equal(judgeAnswer("kept-rulesets", bad, {}), false);
  assert.equal(judgeAnswer("objects-empty", json({ kind: "storage#objects" }), {}), true);
  assert.equal(judgeAnswer("objects-empty", json({ kind: "storage#objects", items: [], prefixes: [] }), {}), true);
  for (const bad of [json({ kind: "storage#objects", items: [{ name: "x" }] }), json({ kind: "storage#objects", prefixes: ["x/"] }), json({ kind: "storage#objects", nextPageToken: "t" }), json({}), json({ kind: "storage#bucket" }), json({ kind: "storage#objects" }, 403)]) assert.equal(judgeAnswer("objects-empty", bad, {}), false);
  assert.equal(judgeAnswer("document-absent", rawOf(PRODUCTION.documentAbsent), {}), true);
  for (const bad of [json({ name: DOCUMENT }), json({ error: { code: 404, message: "x", status: "OTHER" } }, 404), json({ error: { code: 404, status: "NOT_FOUND" } }, 404), json({ error: { code: 403, message: "x", status: "NOT_FOUND" } }, 403), json({}, 404), { status: 404, rawHeaders: [], bytes: Buffer.alloc(0) }]) assert.equal(judgeAnswer("document-absent", bad, {}), false);
});

test("an ownership proof is read only from a create answer that names exactly what was created", () => {
  const ctx = { bucket: BUCKET };
  const ruleset = (delta = {}) => json({ name: RULESET, createTime: "2026-09-30T02:30:00.123456Z", ...delta });
  assert.equal(proofOf("own-ruleset", ruleset(), ctx), RULESET);
  for (const bad of [ruleset({ name: ENTRY_RULESETS[0].name }), ruleset({ name: ENTRY_RULESETS[1].name }), ruleset({ name: `${RULESET}x` }), ruleset({ name: "projects/other/rulesets/3f2a9c1e-7b64-4d0a-9e51-0c8a6f2b7d14" }), ruleset({ name: 5 }), ruleset({ createTime: 5 }), json({}), json({ name: RULESET }), json({}, 500), json({ name: RULESET, createTime: "t" }, 403), json([]), { status: 200, rawHeaders: [], bytes: Buffer.alloc(0) }]) assert.equal(proofOf("own-ruleset", bad, ctx), null);
  const object = (delta = {}) => json({ kind: "storage#object", bucket: BUCKET, name: OBJECT_NAME, generation: "1790727977683752", metageneration: "1", ...delta });
  assert.equal(proofOf("own-object", object(), ctx), "1790727977683752");
  for (const bad of [object({ generation: "0" }), object({ generation: 5 }), object({ generation: "-1" }), object({ generation: "1&x" }), object({ name: `${OBJECT_NAME}2` }), object({ bucket: "other" }), object({ kind: "storage#bucket" }), json({}), json({}, 403)]) assert.equal(proofOf("own-object", bad, ctx), null);
  assert.equal(proofOf("own-object", object(), { bucket: "other" }), null);
  const document = (delta = {}) => json({ name: DOCUMENT_NAME, fields: {}, createTime: "2026-09-30T02:30:01.654321Z", updateTime: "2026-09-30T02:30:01.654321Z", ...delta });
  assert.equal(proofOf("own-document", document(), ctx), "2026-09-30T02:30:01.654321Z");
  for (const bad of [document({ name: `${DOCUMENT_NAME}2` }), document({ updateTime: "not a time" }), document({ updateTime: 5 }), json({ name: DOCUMENT_NAME }), json({}, 409)]) assert.equal(proofOf("own-document", bad, ctx), null);
  for (const kind of ["", "record", "kept-rulesets", "constructor", "__proto__", undefined, 5]) assert.equal(proofOf(kind, ruleset(), ctx), null);
  for (const raw of [null, undefined, {}, { status: 200 }, { status: 200, rawHeaders: [], bytes: "text" }]) assert.equal(proofOf("own-ruleset", raw, ctx), null);
  for (const context of [undefined, {}, null]) assert.equal(proofOf("own-object", object(), context), null);
});

test("a shape step is never judged, unknown kinds and answers the transport could not have handed over are refused", () => {
  for (const raw of [json({}), json({ error: { code: 500 } }, 500), { status: 302, rawHeaders: ["Location", "x"], bytes: Buffer.alloc(0) }, { status: 200, rawHeaders: [], bytes: Buffer.from("<html>") }]) assert.equal(judgeAnswer("record", raw, {}), true);
  assert.equal(judgeAnswer("own-ruleset", json({}), { bucket: BUCKET }), false);
  for (const kind of ["", "unknown", "constructor", "__proto__", undefined, null, 5]) assert.equal(judgeAnswer(kind, json({}), {}), false);
  for (const raw of [null, undefined, {}, { status: 200 }, { status: 200, rawHeaders: [], bytes: "text" }]) for (const kind of ["record", "kept-rulesets", "objects-empty", "document-absent"]) assert.equal(judgeAnswer(kind, raw, {}), false, kind);
  assert.deepEqual([...JUDGE_KINDS].sort(), ["document-absent", "kept-rulesets", "objects-empty", "own-document", "own-object", "own-ruleset", "record"]);
});
