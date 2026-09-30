import assert from "node:assert/strict";
import test from "node:test";
import { ALLOWED_LIMIT, createShapeHttpsTransport } from "./storage-rules-shape/transport.mjs";
import { dependentRequest, DEPENDENT_IDS, staticRequests } from "./storage-rules-shape/plan.mjs";
import { grantKey } from "./storage-rules-shape/targets.mjs";
import { BUCKET, RULESET, fakeRequestImpl } from "./storage-rules-shape-support.mjs";

// The stage 2f transport allows exactly the planned `METHOD URL body` triples, the ones the target builder granted from an ownership proof, and the token refresh and identity read.
const planned = staticRequests(BUCKET);
const granted = new Set();
const transport = createShapeHttpsTransport({ requestImpl: () => { throw new Error("must not send"); }, planned, isGranted: (key) => granted.has(key) });
const spec = (method, url, body = null, headers = {}) => ({ url, method, headers, body });
const json = (value) => Buffer.from(JSON.stringify(value));
const asSpec = (entry) => spec(entry.method, entry.url, entry.body, entry.body === null ? {} : { "content-type": entry.contentType ?? "application/json; charset=utf-8" });
const proofs = { ruleset: RULESET, generation: "1790727977683752", updateTime: "2026-09-30T02:30:01.654321Z" };
const dependents = DEPENDENT_IDS.map((id) => dependentRequest(id, proofs, BUCKET));
const GCS = "https://storage.googleapis.com";
const RULES = "https://firebaserules.googleapis.com";

test("every planned request, the token refresh and the identity read are allowed", () => {
  for (const entry of planned) assert.doesNotThrow(() => transport.validate(asSpec(entry)), `${entry.method} ${entry.url}`);
  assert.doesNotThrow(() => transport.validate(spec("POST", "https://oauth2.googleapis.com/token", Buffer.from("grant_type=refresh_token"), { "content-type": "application/x-www-form-urlencoded" })));
  assert.doesNotThrow(() => transport.validate(spec("GET", "https://www.googleapis.com/oauth2/v2/userinfo")));
});

test("a request that follows from an ownership proof is refused until it is granted, and then only that exact one", () => {
  for (const entry of dependents) assert.throws(() => transport.validate(asSpec(entry)), /invalid HTTP transport input/, entry.id);
  for (const entry of dependents) granted.add(grantKey(entry.method, entry.url, entry.body));
  for (const entry of dependents) assert.doesNotThrow(() => transport.validate(asSpec(entry)), entry.id);
  // Another name, generation or method is not the granted one.
  const object = dependents.find((entry) => entry.id === "shape/object/delete");
  for (const bad of [spec("DELETE", object.url.replace("1790727977683752", "1790727977683753")), spec("GET", object.url), spec("PATCH", object.url, json({})), spec("DELETE", `${object.url}&x=1`), spec("DELETE", `${RULES}/v1/projects/fireemu-oracle-query/rulesets/3f2a9c1e-7b64-4d0a-9e51-0c8a6f2b7d15`), spec("DELETE", `${RULES}/v1/projects/fireemu-oracle-query/rulesets/22b746af-a48a-458d-ab5c-7853473bc8c8`), spec("DELETE", object.url, json({}))]) assert.throws(() => transport.validate(bad), (error) => error.notSent === true && /invalid HTTP transport input/.test(error.message), `${bad.method} ${bad.url}`);
  granted.clear();
});

test("anything that is not planned is refused before it is counted", () => {
  const obj = `${GCS}/storage/v1/b/${BUCKET}/o/STORAGE-RULES%2Fprobe-2f%2Fobject.bin`;
  const refused = [
    spec("DELETE", obj), spec("DELETE", `${obj}?ifGenerationMatch=1`), spec("PATCH", obj, json({})), spec("PUT", obj, json({})), spec("POST", obj, json({})), spec("GET", `${obj}?alt=media`), spec("GET", obj), spec("GET", `${obj}?`), spec("GET", `${obj}#x`),
    spec("GET", `${GCS}/storage/v1/b/${BUCKET}/o/STORAGE-RULES%2Fother%2Fx`), spec("GET", `${GCS}/storage/v1/b/other/o?prefix=STORAGE-RULES%2Fprobe-2f%2F&maxResults=1`), spec("GET", `${GCS}/storage/v1/b/${BUCKET}/o`), spec("GET", `${GCS}/storage/v1/b/${BUCKET}/o?prefix=STORAGE-RULES%2F&maxResults=1`), spec("GET", `${GCS}/storage/v1/b/${BUCKET}`),
    spec("POST", `${GCS}/upload/storage/v1/b/${BUCKET}/o?uploadType=media&name=STORAGE-RULES%2Fprobe-2f%2Fother.bin&ifGenerationMatch=0`, Buffer.from("probe-2f")), spec("POST", `${GCS}/upload/storage/v1/b/${BUCKET}/o?uploadType=media&name=STORAGE-RULES%2Fprobe-2f%2Fobject.bin&ifGenerationMatch=0`, Buffer.from("other")), spec("POST", `${GCS}/upload/storage/v1/b/${BUCKET}/o?uploadType=resumable&name=STORAGE-RULES%2Fprobe-2f%2Fobject.bin`, Buffer.from("probe-2f")),
    spec("POST", `${RULES}/v1/projects/fireemu-oracle-query/rulesets`, json({ source: { files: [{ name: "storage.rules", content: "other" }] } })), spec("POST", `${RULES}/v1/projects/other/rulesets`, json({})), spec("GET", `${RULES}/v1/projects/fireemu-oracle-query/rulesets`), spec("GET", `${RULES}/v1/projects/fireemu-oracle-query/rulesets?pageSize=10`),
    spec("DELETE", `${RULES}/v1/projects/fireemu-oracle-query/rulesets/22b746af-a48a-458d-ab5c-7853473bc8c8`), spec("DELETE", `${RULES}/v1/projects/fireemu-oracle-query/rulesets/d0abf7c6-b0b6-4163-8488-7c8a48ac5dd1`), spec("GET", `${RULES}/v1/${RULESET}`), spec("DELETE", `${RULES}/v1/${RULESET}`),
    spec("DELETE", `${RULES}/v1/projects/fireemu-oracle-query/releases/firebase.storage/${BUCKET}`), spec("POST", `${RULES}/v1/projects/fireemu-oracle-query/releases`, json({})), spec("PATCH", `${RULES}/v1/projects/fireemu-oracle-query/releases/firebase.storage/${BUCKET}`, json({})),
    spec("POST", "https://firestore.googleapis.com/v1/projects/fireemu-oracle-query/databases/(default)/documents/STORAGE-RULES?documentId=other", json({ fields: { probe: { stringValue: "2f" } } })), spec("POST", "https://firestore.googleapis.com/v1/projects/fireemu-oracle-query/databases/(default)/documents/STORAGE-RULES?documentId=probe-2f-doc", json({ fields: {} })),
    spec("DELETE", "https://firestore.googleapis.com/v1/projects/fireemu-oracle-query/databases/(default)/documents/STORAGE-RULES/probe-2f-doc"), spec("DELETE", "https://firestore.googleapis.com/v1/projects/fireemu-oracle-query/databases/(default)/documents/STORAGE-RULES/other"), spec("GET", "https://firestore.googleapis.com/v1/projects/fireemu-oracle-query/databases/(default)/documents/STORAGE-RULES/other"),
    spec("POST", "https://identitytoolkit.googleapis.com/v1/projects/fireemu-oracle-query/accounts:delete", json({ localId: "x" })), spec("POST", "https://identitytoolkit.googleapis.com/v1/projects/fireemu-oracle-query/accounts:signUp", json({})),
    spec("GET", "https://oauth2.googleapis.com/token"), spec("POST", "https://oauth2.googleapis.com/token?x=1", Buffer.from("x")), spec("GET", "https://www.googleapis.com/oauth2/v2/userinfo?alt=json"), spec("POST", "https://www.googleapis.com/oauth2/v2/userinfo", json({})),
    spec("GET", "https://cloudresourcemanager.googleapis.com/v3/projects/123"), spec("POST", "https://cloudresourcemanager.googleapis.com/v3/projects/123:setIamPolicy", json({})),
    spec("GET", "http://storage.googleapis.com/x"), spec("GET", `https://user@storage.googleapis.com/storage/v1/b/${BUCKET}/o?prefix=STORAGE-RULES%2Fprobe-2f%2F&maxResults=1`), spec("GET", `${GCS}:443/storage/v1/b/${BUCKET}/o?prefix=STORAGE-RULES%2Fprobe-2f%2F&maxResults=1`),
    spec("GET", planned[1].url, json({})),
  ];
  for (const one of refused) assert.throws(() => transport.validate(one), (error) => error.notSent === true && /invalid HTTP transport input/.test(error.message), `${one.method} ${one.url}`);
});

test("the input record is closed, the headers are plain, bounded and lower-case, and the allowed set has a size limit", () => {
  const good = asSpec(planned[1]);
  for (const bad of [null, undefined, {}, { ...good, extra: 1 }, { ...good, headers: null }, { ...good, headers: { Authorization: "x" } }, { ...good, headers: { host: "evil" } }, { ...good, headers: { "content-length": "1" } }, { ...good, headers: { a: "x\ny" } }, { ...good, method: "TRACE" }, { ...good, url: 5 }, { ...good, body: "text" }]) assert.throws(() => transport.validate(bad), /invalid HTTP transport input/);
  const isGranted = () => false;
  for (const bad of [{}, { requestImpl: 5, planned, isGranted }, { requestImpl() {}, planned: "x", isGranted }, { requestImpl() {}, planned: [{ method: "GET" }], isGranted }, { requestImpl() {}, planned: [null], isGranted }, { requestImpl() {}, planned, isGranted, extra: 1 }, { requestImpl() {}, planned }, { requestImpl() {}, planned, isGranted: 5 }, { planned, isGranted }]) assert.throws(() => createShapeHttpsTransport(bad), /invalid HTTP transport input/);
  assert.equal(ALLOWED_LIMIT, 200);
  const many = Array.from({ length: ALLOWED_LIMIT + 1 }, (_, index) => ({ method: "GET", url: `https://storage.googleapis.com/x/${index}` }));
  assert.throws(() => createShapeHttpsTransport({ requestImpl() {}, planned: many, isGranted }), /invalid HTTP transport input/);
  assert.doesNotThrow(() => createShapeHttpsTransport({ requestImpl() {}, planned: many.slice(0, ALLOWED_LIMIT), isGranted }));
});

test("a planned request is sent as issued: method, exact URL, identity encoding and the body's length", async () => {
  const seen = [];
  const send = createShapeHttpsTransport({ requestImpl: fakeRequestImpl(() => ({ status: 200, rawHeaders: [], bytes: Buffer.from("{}") }), seen), planned, isGranted: () => false });
  const create = planned.find((entry) => entry.id === "shape/ruleset/create");
  const answer = await send.send(asSpec(create));
  assert.equal(answer.status, 200);
  const list = planned.find((entry) => entry.id === "shape/object/list");
  await send.send(asSpec(list));
  assert.deepEqual(seen.map((entry) => [entry.method, entry.url]), [["POST", create.url], ["GET", list.url]]);
  assert.equal(seen[0].headers["accept-encoding"], "identity");
  assert.equal(seen[0].headers["content-length"], String(create.body.length));
  assert.equal(seen[1].headers["content-length"], undefined);
  await assert.rejects(send.send(spec("DELETE", `${list.url}0`)), (error) => error.notSent === true);
  assert.equal(seen.length, 2);
});
