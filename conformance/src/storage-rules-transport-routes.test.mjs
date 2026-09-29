import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { buildCorpus } from "./storage-rules/corpus.mjs";
import { buildFullRequestManifest } from "./storage-rules/full-manifest.mjs";
import { createSingleAttemptHttpsTransport } from "./storage-rules/http-transport.mjs";
import { createTargetBuilder } from "./storage-rules/target.mjs";

// The real transport must be able to carry every request the controller counts, and must refuse anything near them.
const closure = JSON.parse(readFileSync(new URL("../../spec/compatibility/closure/STORAGE-RULES.json", import.meta.url)));
const options = { runId: "local-run", sourceCommit: "a".repeat(40), queryProjectNumber: "111111111111", idpProjectNumber: "222222222222", queryApiKeyId: "00000000-0000-4000-8000-000000000001", idpApiKeyId: "00000000-0000-4000-8000-000000000002" };
const binding = { bucket: "synthetic-rules-bucket", prefix: "STORAGE-RULES/local-run/", uidA: "storage-rules-local-run-user-a", uidB: "storage-rules-local-run-user-b" };
const manifest = buildFullRequestManifest(buildCorpus(binding), closure, options);
const VALUES = { "download-token": "0a1b2c3d-1111-2222-3333-444455556666", generation: "1700000000000001", metageneration: "1", "update-time": "2026-09-29T10:00:00Z", "ruleset-name": "projects/fireemu-oracle-query/rulesets/abc-123", "ruleset-path": "/v1/projects/fireemu-oracle-query/rulesets/abc-123", "page-token": "next-token_1" };
const typeOf = (reference) => reference.type ?? { "firestore-update-time": "update-time", "gcs-object-generation": "generation", "firebase-resumable-session-url": "session-url", "firebase-download-token": "download-token" }[reference.kind];
const sessionUrl = (objectName) => `https://firebasestorage.googleapis.com/v0/b/${binding.bucket}/o?name=${encodeURIComponent(objectName)}&upload_id=CANARYUPLOADID0123456789&upload_protocol=resumable`;
const resolver = (reference) => (typeOf(reference) === "session-url" ? sessionUrl(reference.expectedObjectName) : VALUES[typeOf(reference)]);
const delegated = (row) => ["auth", "credential-cache"].includes(row.family);

const transport = () => createSingleAttemptHttpsTransport({ requestImpl: () => assert.fail("nothing is sent by a check") });
const spec = (url, method = "GET", body = null) => ({ url, method, headers: {}, body });

test("every counted row's prepared request passes the real transport's input checks", () => {
  const targets = createTargetBuilder({ manifest, digestSalt: "3".repeat(64) });
  const t = transport();
  assert.equal(typeof t.validate, "function");
  let checked = 0;
  for (const row of manifest.rows.filter((r) => !delegated(r))) {
    const prepared = targets.prepare(row, resolver);
    assert.doesNotThrow(() => t.validate({ url: prepared.spec.url, method: prepared.spec.method, headers: { ...prepared.spec.headers, authorization: "Bearer x" }, body: prepared.spec.body }), row.id);
    checked++;
  }
  assert.equal(checked, manifest.rows.filter((r) => !delegated(r)).length);
});

test("the three origins the preflight uses are reachable only through their exact routes", () => {
  const t = transport();
  const q = options.queryProjectNumber;
  const key = options.queryApiKeyId;
  const good = [
    spec("https://www.googleapis.com/oauth2/v2/userinfo"),
    spec(`https://cloudresourcemanager.googleapis.com/v3/projects/${q}`),
    spec(`https://cloudresourcemanager.googleapis.com/v3/projects/${q}:testIamPermissions`, "POST", Buffer.from("{}")),
    spec(`https://cloudresourcemanager.googleapis.com/v3/projects/${q}:getIamPolicy`, "POST", Buffer.from("{}")),
    spec(`https://apikeys.googleapis.com/v2/projects/${q}/locations/global/keys/${key}`),
    spec(`https://apikeys.googleapis.com/v2/projects/${q}/locations/global/keys/${key}/keyString`),
  ];
  for (const s of good) assert.doesNotThrow(() => t.validate(s), s.url);
  const bad = [
    spec("https://www.googleapis.com/oauth2/v2/userinfo?alt=json"), spec("https://www.googleapis.com/oauth2/v2/userinfo/", "GET"), spec("https://www.googleapis.com/oauth2/v2/userinfo", "POST", Buffer.from("{}")),
    spec("https://www.googleapis.com/oauth2/v1/userinfo"), spec("https://www.googleapis.com/storage/v1/b"), spec("https://www.googleapis.com/"), spec("https://www.googleapis.com/oauth2/v2/tokeninfo"),
    spec(`https://cloudresourcemanager.googleapis.com/v3/projects/${q}`, "DELETE"), spec(`https://cloudresourcemanager.googleapis.com/v3/projects/${q}`, "POST", Buffer.from("{}")),
    spec(`https://cloudresourcemanager.googleapis.com/v3/projects/${q}:setIamPolicy`, "POST", Buffer.from("{}")), spec(`https://cloudresourcemanager.googleapis.com/v3/projects/${q}:testIamPermissions`),
    spec(`https://cloudresourcemanager.googleapis.com/v3/projects/${q}:getIamPolicy?x=1`, "POST", Buffer.from("{}")), spec("https://cloudresourcemanager.googleapis.com/v3/projects"), spec(`https://cloudresourcemanager.googleapis.com/v1/projects/${q}`),
    spec("https://cloudresourcemanager.googleapis.com/v3/projects/abc"), spec("https://cloudresourcemanager.googleapis.com/v3/projects/0123"), spec(`https://cloudresourcemanager.googleapis.com/v3/projects/${q}/x`),
    spec("https://cloudresourcemanager.googleapis.com/v3/folders/1"), spec("https://cloudresourcemanager.googleapis.com/v3/organizations/1"),
    spec(`https://apikeys.googleapis.com/v2/projects/${q}/locations/global/keys/${key}`, "DELETE"), spec(`https://apikeys.googleapis.com/v2/projects/${q}/locations/global/keys/${key}`, "PATCH", Buffer.from("{}")),
    spec(`https://apikeys.googleapis.com/v2/projects/${q}/locations/global/keys`), spec(`https://apikeys.googleapis.com/v2/projects/${q}/locations/global/keys/${key}/keyString`, "POST", Buffer.from("{}")),
    spec(`https://apikeys.googleapis.com/v2/projects/${q}/locations/global/keys/${key}/other`), spec(`https://apikeys.googleapis.com/v2/projects/${q}/locations/global/keys/NOT-A-UUID`),
    spec(`https://apikeys.googleapis.com/v2/projects/${q}/locations/eu/keys/${key}`), spec(`https://apikeys.googleapis.com/v2/projects/${q}/locations/global/keys/${key}?x=1`), spec(`https://apikeys.googleapis.com/v2/keys:lookupKey`),
    spec(`https://apikeys.googleapis.com/v2/projects/${q}/locations/global/keys/${key.replaceAll("0", "A")}`),
    spec("https://iam.googleapis.com/v1/projects/x/serviceAccounts"), spec("https://example.com/"), spec("http://apikeys.googleapis.com/v2/projects/1/locations/global/keys/00000000-0000-4000-8000-000000000001"),
  ];
  for (const s of bad) assert.throws(() => t.validate(s), /invalid HTTP transport input/, `${s.method} ${s.url}`);
});

test("an API key is reachable by a UUID or by a custom key ID of the documented shape, with or without keyString, and by nothing else", () => {
  const t = transport();
  const q = options.queryProjectNumber;
  const url = (id, tail = "") => `https://apikeys.googleapis.com/v2/projects/${q}/locations/global/keys/${id}${tail}`;
  for (const id of ["fireemu-query-auth-20260925", "a", "a1", `a${"b".repeat(62)}`, "abc-def", "00000000-0000-4000-8000-000000000001", "ffffffff-ffff-ffff-ffff-ffffffffffff"]) {
    for (const tail of ["", "/keyString"]) assert.doesNotThrow(() => t.validate(spec(url(id, tail))), `${id}${tail}`);
  }
  for (const id of [`a${"b".repeat(63)}`, "1abc", "Abc", "aBc", "a_b", "a.b", "a b", "a%2Fb", "-abc", "abc/def", "", "0000000A-0000-4000-8000-00000000000A", "00000000-0000-4000-8000-00000000000", "00000000-0000-4000-8000-0000000000012", "abc$"]) {
    for (const tail of ["", "/keyString"]) assert.throws(() => t.validate(spec(url(id, tail))), /invalid HTTP transport input/, `${id}${tail}`);
  }
  // The route stays a plain GET without a query and without a body.
  assert.throws(() => t.validate(spec(url("fireemu-query-auth-20260925"), "POST", Buffer.from("{}"))), /invalid HTTP transport input/);
  assert.throws(() => t.validate(spec(`${url("fireemu-query-auth-20260925")}?a=b`)), /invalid HTTP transport input/);
  assert.throws(() => t.validate(spec(url("fireemu-query-auth-20260925", "/keyString/x"))), /invalid HTTP transport input/);
});

test("the origins that were already allowed stay allowed and validation sends nothing", async () => {
  const t = transport();
  for (const url of ["https://firebasestorage.googleapis.com/v0/b/b/o", "https://storage.googleapis.com/storage/v1/b/b/o", "https://firestore.googleapis.com/v1/projects/p/databases/(default)", "https://firebaserules.googleapis.com/v1/projects/p/rulesets", "https://identitytoolkit.googleapis.com/v1/accounts:signUp", "https://oauth2.googleapis.com/token"]) {
    assert.doesNotThrow(() => t.validate(spec(url)), url);
  }
  assert.doesNotThrow(() => t.validate(spec("https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com")));
  assert.throws(() => t.validate(spec("https://www.googleapis.com/robot/v1/metadata/x509/other@system.gserviceaccount.com")), /invalid HTTP transport input/);
});

test("send carries the new preflight routes through the same single attempt", async () => {
  const calls = [];
  const requestImpl = (url, opts, callback) => {
    const listeners = {};
    const request = { destroyed: false, destroy() {}, on() {}, once() {}, end() { calls.push(String(url)); const response = { statusCode: 200, rawHeaders: ["Content-Type", "application/json"], complete: true, on(name, fn) { listeners[name] = fn; }, once(name, fn) { listeners[name] = fn; }, destroy() {} }; queueMicrotask(() => { callback(response); listeners.data?.(Buffer.from("{}")); listeners.end?.(); }); } };
    return request;
  };
  const t = createSingleAttemptHttpsTransport({ requestImpl });
  const answer = await t.send(spec("https://www.googleapis.com/oauth2/v2/userinfo"));
  assert.equal(answer.status, 200);
  assert.deepEqual(calls, ["https://www.googleapis.com/oauth2/v2/userinfo"]);
  await assert.rejects(t.send(spec("https://www.googleapis.com/oauth2/v2/userinfo?x=1")), /invalid HTTP transport input/);
  assert.equal(calls.length, 1);
});

test("an exact route is bound to its own origin, not only to its path", () => {
  const t = transport();
  const q = options.queryProjectNumber;
  const key = options.queryApiKeyId;
  for (const s of [
    spec("https://example.com/oauth2/v2/userinfo"),
    spec(`https://apikeys.googleapis.com/v3/projects/${q}`), spec(`https://www.googleapis.com/v3/projects/${q}`), spec(`https://iam.googleapis.com/v3/projects/${q}:getIamPolicy`, "POST", Buffer.from("{}")),
    spec(`https://cloudresourcemanager.googleapis.com/v2/projects/${q}/locations/global/keys/${key}`), spec(`https://www.googleapis.com/v2/projects/${q}/locations/global/keys/${key}/keyString`),
    spec("https://cloudresourcemanager.googleapis.com/oauth2/v2/userinfo"),
  ]) assert.throws(() => t.validate(s), /invalid HTTP transport input/, `${s.method} ${s.url}`);
});

test("a refusal of the transport's input is marked as not sent, and only that refusal", async () => {
  const t = transport();
  for (const s of [spec("https://example.com/"), spec("https://www.googleapis.com/oauth2/v2/userinfo?x=1")]) {
    assert.throws(() => t.validate(s), (error) => error.notSent === true && error.message === "invalid HTTP transport input");
    await assert.rejects(t.send(s), (error) => error.notSent === true && error.message === "invalid HTTP transport input");
  }
  // A failure once the request was made is not a "not sent".
  const failing = createSingleAttemptHttpsTransport({ requestImpl: () => { const listeners = {}; return { destroy() {}, on(name, fn) { listeners[name] = fn; }, once(name, fn) { listeners[name] = fn; }, end() { queueMicrotask(() => listeners.error?.(new Error("connection reset"))); } }; } });
  await assert.rejects(failing.send(spec("https://www.googleapis.com/oauth2/v2/userinfo")), (error) => error.notSent !== true);
});
