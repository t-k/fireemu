import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { restrictionsSha256 } from "./storage-rules/acceptance-preflight.mjs";
import { buildCorpus } from "./storage-rules/corpus.mjs";
import { buildFullRequestManifest } from "./storage-rules/full-manifest.mjs";

const closure = JSON.parse(readFileSync(new URL("../../spec/compatibility/closure/STORAGE-RULES.json", import.meta.url)));
const options = { runId: "local-run", sourceCommit: "a".repeat(40), queryProjectNumber: "1".repeat(12), idpProjectNumber: "2".repeat(12), queryApiKeyId: "00000000-0000-4000-8000-000000000001", idpApiKeyId: "00000000-0000-4000-8000-000000000002" };
const binding = { bucket: "synthetic-rules-bucket", prefix: "STORAGE-RULES/local-run/", uidA: "storage-rules-local-run-user-a", uidB: "storage-rules-local-run-user-b" };
const manifest = buildFullRequestManifest(buildCorpus(binding), closure, options);
const row = (id) => manifest.rows.find((r) => r.id === id) ?? assert.fail(id);
const load = () => import("./storage-rules/acceptance.mjs");
const response = (status, body = "", headers = {}) => ({ status, rawHeaders: Object.entries(headers).flat(), bytes: Buffer.from(typeof body === "string" ? body : JSON.stringify(body)) });
const json = (status, body) => response(status, body, { "Content-Type": "application/json; charset=UTF-8" });
const sha = (value) => createHash("sha256").update(value).digest("hex");
const time = "2026-09-29T10:00:00.000000Z";
const errorBody = (code, status) => ({ error: { code, message: "x", status } });

test("the ten preflight kinds are implemented and every kind but Auth and the cache now has a schema", async () => {
  const { ACCEPTANCE_KINDS, unimplementedKinds, acceptanceKindOf } = await load();
  const preflight = Object.keys(ACCEPTANCE_KINDS).filter((k) => k.startsWith("preflight-"));
  assert.equal(preflight.length, 10);
  for (const kind of preflight) { assert.equal(ACCEPTANCE_KINDS[kind].implemented, true, kind); assert.ok(manifest.rows.some((r) => acceptanceKindOf(r) === kind), kind); }
  assert.deepEqual(unimplementedKinds(), ["credential-cache", "auth"]);
});

test("the owner identity keeps the email and subject in a secret and only a flag in the facts", async () => {
  const { classifyResponse } = await load();
  const identity = row("preflight/owner/identity");
  const ok = classifyResponse(identity, json(200, { id: "1234567890", email: "owner@example.com", verified_email: true, picture: "https://x/p.png" }));
  assert.equal(ok.verdict, "accepted");
  assert.deepEqual({ ...ok.facts }, { status: 200, verifiedEmail: true });
  assert.equal(JSON.stringify(ok).includes("owner@example.com"), false);
  assert.deepEqual({ ...ok.secretFacts }, { email: "owner@example.com", subject: "1234567890" });
  assert.equal(classifyResponse(identity, json(200, { id: "1", email: "o@example.com", verified_email: false })).facts.verifiedEmail, false);
  for (const bad of [json(200, { email: "o@example.com", verified_email: true }), json(200, { id: 1, email: "o@example.com", verified_email: true }), json(200, { id: "1", email: "", verified_email: true }), json(200, { id: "1", email: "o@example.com", verified_email: "yes" }), json(401, errorBody(401, "UNAUTHENTICATED")), response(200, "")]) {
    assert.equal(classifyResponse(identity, bad).verdict, "unexpected");
  }
});

test("a project read checks the project number in the path", async () => {
  const { classifyResponse } = await load();
  const project = row("preflight/query/project");
  const number = project.request.path.split("/").at(-1);
  const body = (extra = {}) => ({ name: `projects/${number}`, projectId: "fireemu-oracle-query", state: "ACTIVE", displayName: "n", createTime: time, etag: "e", ...extra });
  const ok = classifyResponse(project, json(200, body()));
  assert.equal(ok.verdict, "accepted");
  assert.deepEqual({ ...ok.facts }, { status: 200, projectId: "fireemu-oracle-query", state: "ACTIVE", deleted: false });
  assert.equal(classifyResponse(project, json(200, body({ state: "DELETE_REQUESTED", deleteTime: time }))).facts.deleted, true);
  for (const bad of [json(200, body({ name: "projects/999" })), json(200, body({ projectId: "" })), json(200, body({ state: 7 })), json(403, errorBody(403, "PERMISSION_DENIED")), response(200, "[]")]) assert.equal(classifyResponse(project, bad).verdict, "unexpected");
});

test("a key read reports its uid, deletion and API targets, and its string stays secret", async () => {
  const { classifyResponse } = await load();
  const meta = row("preflight/query/key-metadata");
  const name = meta.request.path.slice(4);
  const key = (extra = {}) => ({ name, uid: "08c3ec4e-d284-4034-a35a-c061cafeeff7", displayName: "k", createTime: time, updateTime: time, restrictions: { apiTargets: [{ service: "securetoken.googleapis.com" }, { service: "identitytoolkit.googleapis.com" }] }, etag: "e", ...extra });
  const ok = classifyResponse(meta, json(200, key()));
  assert.equal(ok.verdict, "accepted");
  assert.deepEqual({ ...ok.facts }, { status: 200, uid: "08c3ec4e-d284-4034-a35a-c061cafeeff7", deleted: false, apiTargets: ["identitytoolkit.googleapis.com", "securetoken.googleapis.com"], otherRestrictions: [], methodRestricted: false, restrictionsSha256: restrictionsSha256({ apiTargets: [{ service: "identitytoolkit.googleapis.com" }, { service: "securetoken.googleapis.com" }] }) });
  assert.equal(classifyResponse(meta, json(200, key({ restrictions: { apiTargets: [{ service: "a.googleapis.com", methods: ["x"] }], browserKeyRestrictions: {} } }))).facts.methodRestricted, true);
  assert.deepEqual(classifyResponse(meta, json(200, key({ restrictions: { browserKeyRestrictions: {}, apiTargets: [] } }))).facts.otherRestrictions, ["browserKeyRestrictions"]);
  assert.equal(classifyResponse(meta, json(200, key({ deleteTime: time }))).facts.deleted, true);
  // The digest covers the whole restriction object: any restriction moves it, and neither key order nor target order does.
  const digest = (restrictions) => classifyResponse(meta, json(200, key({ restrictions }))).facts.restrictionsSha256;
  const browser = { browserKeyRestrictions: { allowedReferrers: [] }, apiTargets: [{ service: "b.googleapis.com" }, { service: "a.googleapis.com" }] };
  assert.equal(digest(browser), digest({ apiTargets: [{ service: "a.googleapis.com" }, { service: "b.googleapis.com" }], browserKeyRestrictions: { allowedReferrers: [] } }));
  for (const other of [{ apiTargets: browser.apiTargets }, { ...browser, browserKeyRestrictions: { allowedReferrers: ["*"] } }, { ...browser, apiTargets: browser.apiTargets.slice(1) }, { ...browser, apiTargets: [...browser.apiTargets, { service: "c.googleapis.com" }] }, { ...browser, androidKeyRestrictions: {} }, { ...browser, apiTargets: [{ service: "a.googleapis.com", methods: ["x"] }, { service: "b.googleapis.com" }] }]) assert.notEqual(digest(other), digest(browser));
  // Key order inside nested objects and inside API target entries does not matter either, but list order inside other lists does.
  const nested = { browserKeyRestrictions: { allowedReferrers: ["https://a.example/", "https://b.example/"], extra: { x: 1, y: 2 } }, apiTargets: [{ service: "a.googleapis.com", methods: ["m1", "m2"] }] };
  assert.equal(digest(nested), digest({ apiTargets: [{ methods: ["m1", "m2"], service: "a.googleapis.com" }], browserKeyRestrictions: { extra: { y: 2, x: 1 }, allowedReferrers: ["https://a.example/", "https://b.example/"] } }));
  assert.notEqual(digest(nested), digest({ ...nested, browserKeyRestrictions: { ...nested.browserKeyRestrictions, allowedReferrers: ["https://b.example/", "https://a.example/"] } }));
  assert.notEqual(digest(nested), digest({ ...nested, browserKeyRestrictions: { ...nested.browserKeyRestrictions, extra: { x: 1, y: 3 } } }));
  assert.notEqual(digest(nested), digest({ ...nested, apiTargets: [{ service: "a.googleapis.com", methods: ["m2", "m1"] }] }));
  assert.match(digest(browser), /^[0-9a-f]{64}$/);
  assert.equal(classifyResponse(meta, json(200, { ...key(), restrictions: undefined })).facts.restrictionsSha256, restrictionsSha256({}));
  assert.equal(restrictionsSha256(undefined), restrictionsSha256({}));
  for (const bad of [json(200, key({ name: `${name}x` })), json(200, key({ uid: "" })), json(200, key({ restrictions: { apiTargets: [{}] } })), json(404, errorBody(404, "NOT_FOUND"))]) assert.equal(classifyResponse(meta, bad).verdict, "unexpected");
  const string = row("preflight/query/key-string");
  const secret = "AIzaCANARYKEYSTRING0123456789abcdefghij";
  const shown = classifyResponse(string, json(200, { keyString: secret }));
  assert.equal(shown.verdict, "accepted");
  assert.deepEqual({ ...shown.facts }, { status: 200, keyStringLength: secret.length });
  assert.equal(JSON.stringify(shown).includes(secret), false);
  assert.equal(shown.secretFacts.keyString, secret);
  for (const bad of [json(200, {}), json(200, { keyString: "" }), json(200, { keyString: 7 }), json(403, errorBody(403, "PERMISSION_DENIED"))]) assert.equal(classifyResponse(string, bad).verdict, "unexpected");
});

test("permission checks report requested, granted and missing names", async () => {
  const { classifyResponse } = await load();
  const project = row("preflight/query/permissions");
  const requested = project.request.body.json.permissions;
  const all = classifyResponse(project, json(200, { permissions: requested }));
  assert.deepEqual({ ...all.facts }, { status: 200, requested: requested.length, granted: requested.length, missing: [] });
  const some = classifyResponse(project, json(200, { permissions: requested.slice(1) }));
  assert.deepEqual({ ...some.facts }, { status: 200, requested: requested.length, granted: requested.length - 1, missing: [requested[0]] });
  assert.deepEqual({ ...classifyResponse(project, json(200, {})).facts }, { status: 200, requested: requested.length, granted: 0, missing: requested });
  assert.equal(classifyResponse(project, json(200, { permissions: [...requested, "unrequested.permission"] })).verdict, "unexpected");
  assert.equal(classifyResponse(project, json(200, { permissions: "x" })).verdict, "unexpected");
  assert.equal(classifyResponse(project, json(403, errorBody(403, "PERMISSION_DENIED"))).verdict, "unexpected");
  const bucket = row("preflight/bucket/permissions");
  const asked = bucket.request.query.permissions;
  const answer = classifyResponse(bucket, json(200, { kind: "storage#testIamPermissionsResponse", permissions: asked.slice(0, 2) }));
  assert.equal(answer.verdict, "accepted");
  assert.equal(answer.facts.granted, 2);
  assert.equal(classifyResponse(bucket, json(200, { permissions: asked })).verdict, "unexpected");
});

test("bucket metadata and policies report digests and counts, never members", async () => {
  const { classifyResponse } = await load();
  const meta = row("preflight/bucket/metadata");
  const bucket = (extra = {}) => ({ kind: "storage#bucket", id: binding.bucket, name: binding.bucket, projectNumber: options.queryProjectNumber, location: "US-CENTRAL1", storageClass: "STANDARD", iamConfiguration: { uniformBucketLevelAccess: { enabled: false }, publicAccessPrevention: "inherited" }, ...extra });
  const ok = classifyResponse(meta, json(200, bucket()));
  assert.deepEqual({ ...ok.facts }, { status: 200, projectNumber: options.queryProjectNumber, location: "US-CENTRAL1", uniformBucketLevelAccess: false, publicAccessPrevention: "inherited" });
  for (const bad of [json(200, bucket({ name: "other" })), json(200, bucket({ kind: "storage#object" })), json(200, bucket({ projectNumber: "x" })), json(404, errorBody(404, "NOT_FOUND"))]) assert.equal(classifyResponse(meta, bad).verdict, "unexpected");
  const bindings = [{ role: "roles/storage.admin", members: ["user:owner@example.com", "serviceAccount:s@example.iam"] }, { role: "roles/viewer", members: ["projectViewer:p"] }];
  for (const [id, kind] of [["preflight/bucket/iam", "storage#policy"], ["preflight/query/iam", undefined]]) {
    const r = row(id);
    const ok2 = classifyResponse(r, json(200, { ...(kind ? { kind } : {}), version: 3, etag: "CAE=", bindings }));
    assert.equal(ok2.verdict, "accepted");
    assert.deepEqual({ ...ok2.facts }, { status: 200, bindings: 2, members: 3, version: 3, policySha256: sha(JSON.stringify([...bindings].map((b) => ({ role: b.role, members: [...b.members].sort() })).sort((a, b) => (a.role < b.role ? -1 : 1)))) });
    assert.equal(JSON.stringify(ok2).includes("owner@example.com"), false);
    const reordered = classifyResponse(r, json(200, { ...(kind ? { kind } : {}), version: 3, etag: "CAE=", bindings: [...bindings].reverse().map((b) => ({ ...b, members: [...b.members].reverse() })) }));
    assert.equal(reordered.facts.policySha256, ok2.facts.policySha256);
    assert.equal(classifyResponse(r, json(200, { ...(kind ? { kind } : {}), etag: "e" })).facts.bindings, 0);
    for (const bad of [json(200, { bindings: {} }), json(200, { bindings: [{ role: 7, members: [] }] }), json(200, { bindings: [{ role: "r", members: "x" }] }), json(403, errorBody(403, "PERMISSION_DENIED"))]) assert.equal(classifyResponse(r, bad).verdict, "unexpected");
  }
});

test("the default database read checks its own name", async () => {
  const { classifyResponse } = await load();
  const db = row("preflight/query/database");
  const name = db.request.path.slice(4);
  const ok = classifyResponse(db, json(200, { name, uid: "u", createTime: time, updateTime: time, locationId: "us-central1", type: "FIRESTORE_NATIVE", concurrencyMode: "PESSIMISTIC" }));
  assert.equal(ok.verdict, "accepted");
  assert.deepEqual({ ...ok.facts }, { status: 200, locationId: "us-central1", type: "FIRESTORE_NATIVE" });
  for (const bad of [json(200, { name: `${name}x`, locationId: "l", type: "t" }), json(200, { name, type: "t" }), json(200, { name, locationId: "l" }), json(404, errorBody(404, "NOT_FOUND"))]) assert.equal(classifyResponse(db, bad).verdict, "unexpected");
});
