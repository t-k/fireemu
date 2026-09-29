import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { buildCorpus } from "./storage-rules/corpus.mjs";
import { buildFullRequestManifest } from "./storage-rules/full-manifest.mjs";

const closure = JSON.parse(readFileSync(new URL("../../spec/compatibility/closure/STORAGE-RULES.json", import.meta.url)));
const options = { runId: "local-run", sourceCommit: "a".repeat(40), queryProjectNumber: "1".repeat(12), idpProjectNumber: "2".repeat(12), queryApiKeyId: "00000000-0000-4000-8000-000000000001", idpApiKeyId: "00000000-0000-4000-8000-000000000002" };
const binding = { bucket: "synthetic-rules-bucket", prefix: "STORAGE-RULES/local-run/", uidA: "storage-rules-local-run-user-a", uidB: "storage-rules-local-run-user-b" };
const manifest = buildFullRequestManifest(buildCorpus(binding), closure, options);
const salt = "7".repeat(64);
const VALUES = { "download-token": "0a1b2c3d-1111-2222-3333-444455556666", generation: "1700000000000001", metageneration: "1", "update-time": "2026-09-29T10:00:00Z", "ruleset-name": "projects/fireemu-oracle-query/rulesets/abc-123", "ruleset-path": "/v1/projects/fireemu-oracle-query/rulesets/abc-123", "page-token": "next-token_1" };
const typeOf = (reference) => reference.type ?? { "firestore-update-time": "update-time", "gcs-object-generation": "generation", "firebase-resumable-session-url": "session-url", "firebase-download-token": "download-token" }[reference.kind];
const sessionUrl = (objectName, over = {}) => `https://firebasestorage.googleapis.com${over.path ?? `/v0/b/${binding.bucket}/o`}?name=${encodeURIComponent(over.name ?? objectName)}&upload_id=${over.uploadId ?? "CANARYUPLOADID0123456789"}&upload_protocol=${over.protocol ?? "resumable"}${over.extra ?? ""}`;
const valueFor = (reference) => (typeOf(reference) === "session-url" ? sessionUrl(reference.expectedObjectName) : VALUES[typeOf(reference)]);
const resolver = (log = []) => (reference, rowId) => { log.push([typeOf(reference), rowId]); return valueFor(reference) ?? assert.fail(`unexpected ${typeOf(reference)}`); };
const UNPREPARED = (row) => ["auth", "credential-cache"].includes(row.family);
const load = async () => {
  const module = await import("./storage-rules/target.mjs").catch((error) => { if (error.code === "ERR_MODULE_NOT_FOUND") return {}; throw error; });
  assert.equal(typeof module.createTargetBuilder, "function");
  return module;
};
const builder = async (overrides = {}) => (await load()).createTargetBuilder({ manifest, digestSalt: salt, ...overrides });
const row = (id) => manifest.rows.find((r) => r.id === id) ?? assert.fail(`missing ${id}`);
const withRequest = (id, delta) => { const r = row(id); return { ...r, request: { ...r.request, ...delta } }; };
const prepare = async (r, resolve = resolver()) => (await builder()).prepare(r, resolve);
const sha = (value) => createHash("sha256").update(value).digest("hex");

test("every row that is not delegated prepares into a canonical, exact target", async () => {
  const b = await builder();
  const rows = manifest.rows.filter((r) => !UNPREPARED(r));
  assert.equal(rows.length, 6172 - 37 - 19);
  const seen = new Set();
  for (const r of rows) {
    const prepared = b.prepare(r, resolver());
    assert.equal(Object.isFrozen(prepared), true);
    assert.equal(prepared.rowId, r.id);
    assert.equal(prepared.spec.method, r.request.method);
    assert.equal(new URL(prepared.spec.url).href, prepared.spec.url, r.id);
    assert.ok(prepared.spec.url.startsWith(`${r.request.origin}/`), r.id);
    assert.match(prepared.targetSha256, /^[0-9a-f]{64}$/);
    assert.equal(prepared.credential, r.request.credential);
    assert.ok(!Object.keys(prepared.spec.headers).some((h) => /^(?:authorization|cookie|x-goog-user-project|host)$/i.test(h)), r.id);
    seen.add(prepared.targetSha256);
  }
  assert.ok(seen.size > 6000);
});

test("rows carried by other modules are refused here", async () => {
  const b = await builder();
  for (const r of manifest.rows.filter(UNPREPARED)) assert.throws(() => b.prepare(r, resolver()), /invalid target row/, r.id);
});

test("the spec never appears in a serialized target and no resolved value reaches the redacted form", async () => {
  const r = row("rulesets-list/final/2");
  const prepared = await prepare(r);
  assert.equal(JSON.stringify(prepared).includes("next-token_1"), false);
  assert.equal(prepared.spec.url.includes("pageToken=next-token_1"), true);
  assert.equal(Object.getOwnPropertyDescriptor(prepared, "spec").enumerable, false);
  assert.equal(prepared.redacted.includes("next-token_1"), false);
  assert.ok(prepared.redacted.includes("<ref:page-token>"));
  const del = await prepare(row("management/control-0/delete"));
  assert.equal(del.redacted.includes(VALUES.generation), false);
  assert.ok(del.redacted.includes("ifGenerationMatch=<ref:generation>"));
  assert.ok(del.redacted.startsWith("DELETE https://storage.googleapis.com/storage/v1/b/synthetic-rules-bucket/o/"));
});

test("the digest binds method, URL, headers, body and credential under a salt, and is deterministic", async () => {
  const r = row("management/control-0/seed");
  const one = await prepare(r);
  const two = await prepare(r);
  assert.equal(one.targetSha256, two.targetSha256);
  const other = (await builder({ digestSalt: "8".repeat(64) })).prepare(r, resolver());
  assert.notEqual(other.targetSha256, one.targetSha256);
  for (const changed of [withRequest(r.id, { credential: "user-a" }), withRequest(r.id, { headers: { "content-type": "text/html" } }), withRequest(r.id, { body: { base64: "eHh4eA==" } })]) {
    assert.notEqual(((await builder()).prepare(changed, resolver())).targetSha256, one.targetSha256);
  }
  assert.equal(one.spec.body.toString(), "next");
  assert.equal(one.spec.headers["content-type"], "text/plain");
});

test("every reference is resolved for its own row and a failing resolver stops the preparation", async () => {
  const log = [];
  const prepared = await prepare(row("release/v1/publish"), resolver(log));
  assert.deepEqual(log, [["ruleset-name", "release/v1/publish"]]);
  assert.equal(JSON.parse(prepared.spec.body.toString()).rulesetName, VALUES["ruleset-name"]);
  for (const id of ["management/control-0/delete", "ruleset/v1/read-source", "rulesets-list/final/2"]) {
    const b = await builder();
    assert.throws(() => b.prepare(row(id), () => { throw new Error("not bound"); }), /invalid target row/);
  }
  const b = await builder();
  assert.throws(() => b.prepare(row("management/control-0/delete"), () => undefined), /invalid target row/);
});

test("a resolved value outside its kind's grammar is refused, so no query or path injection can pass", async () => {
  const b = await builder();
  const cases = [["management/control-0/delete", "generation", ["0", "1&x=1", "1#", "1\r\nX: y", "../1", "1%26", " 1"]], ["rulesets-list/final/2", "page-token", ["a&b=1", "a b", "a\r\nb", "a#"]], ["release/v1/publish", "ruleset-name", ["projects/other/rulesets/x", "projects/fireemu-oracle-query/rulesets/../x", "x"]], ["ruleset/v1/read-source", "ruleset-path", ["/v1/projects/other/rulesets/x", "/v1/projects/fireemu-oracle-query/rulesets/x/../y", "/v1/projects/fireemu-oracle-query/rulesets/x?y=1", "x"]]];
  for (const [id, type, values] of cases) for (const value of values) assert.throws(() => b.prepare(row(id), (reference) => (typeOf(reference) === type ? value : valueFor(reference))), /invalid target row/, `${type} ${value}`);
});

const OWNED = `/storage/v1/b/${binding.bucket}/o/${encodeURIComponent(`${binding.prefix}x/object.bin`)}`;
test("storage targets stay in the owned bucket and prefix", async () => {
  const b = await builder();
  const del = row("management/control-0/delete");
  const name = del.request.objectName;
  const mutated = (delta) => ({ ...del, request: { ...del.request, ...delta } });
  assert.doesNotThrow(() => b.prepare(del, resolver()));
  for (const delta of [
    { objectName: "STORAGE-RULES/other-run/x.bin", path: `/storage/v1/b/${binding.bucket}/o/${encodeURIComponent("STORAGE-RULES/other-run/x.bin")}` },
    { objectName: "outside/x.bin", path: `/storage/v1/b/${binding.bucket}/o/${encodeURIComponent("outside/x.bin")}` },
    { path: `/storage/v1/b/other-bucket/o/${encodeURIComponent(name)}` },
    { path: `/storage/v1/b/${binding.bucket}/o/${encodeURIComponent(`${binding.prefix}../escape`)}`, objectName: `${binding.prefix}../escape` },
    { path: `/storage/v1/b/${binding.bucket}/o/${encodeURIComponent(`${binding.prefix}a/./b`)}`, objectName: `${binding.prefix}a/./b` },
    { path: `/storage/v1/b/${binding.bucket}/o/${name}` },
    { path: `/storage/v1/b/${binding.bucket}/o/${encodeURIComponent(name)}/extra` },
    { path: `${OWNED}` },
    { path: `/storage/v1/b/${binding.bucket}/o/${encodeURIComponent(name).replaceAll("%2F", "%252F")}` },
    { path: `/storage/v1/b/${binding.bucket}/o/${encodeURIComponent(name)}%00` },
    { path: null },
    { origin: "https://firebasestorage.googleapis.com" },
    { origin: "http://storage.googleapis.com" },
    { origin: "https://storage.googleapis.com.evil.example" },
  ]) assert.throws(() => b.prepare(mutated(delta), resolver()), /invalid target row/, JSON.stringify(delta).slice(0, 80));
});

test("an upload and a list are bound to the owned name and prefix", async () => {
  const b = await builder();
  const seed = row("management/control-0/seed");
  for (const delta of [{ query: { ...seed.request.query, name: "outside/x.bin" } }, { query: { ...seed.request.query, uploadType: "resumable" } }, { query: { ...seed.request.query, extra: "1" } }, { query: { uploadType: "media", ifGenerationMatch: "0" } }, { path: `/upload/storage/v1/b/other/o` }]) {
    assert.throws(() => b.prepare({ ...seed, request: { ...seed.request, ...delta } }, resolver()), /invalid target row/);
  }
  const list = row("management/prefix-empty");
  assert.doesNotThrow(() => b.prepare(list, resolver()));
  assert.doesNotThrow(() => b.prepare({ ...list, request: { ...list.request, query: { prefix: `${binding.prefix}case/`, maxResults: "1000" } } }, resolver()));
  for (const query of [{ prefix: "STORAGE-RULES/", maxResults: "1" }, { prefix: "", maxResults: "1" }, { prefix: binding.prefix.slice(0, -1), maxResults: "1" }, { prefix: binding.prefix, maxResults: "1001" }, { prefix: binding.prefix, maxResults: "0" }, { prefix: binding.prefix, maxResults: "01" }, { maxResults: "1" }, { prefix: binding.prefix }, { prefix: binding.prefix, maxResults: "1", pageToken: "x" }]) {
    assert.throws(() => b.prepare({ ...list, request: { ...list.request, query } }, resolver()), /invalid target row/);
  }
});

test("Firestore writes are limited to the declared documents", async () => {
  const b = await builder();
  const rows = manifest.rows.filter((r) => r.service === "firestore" && r.request.method !== "GET");
  assert.ok(rows.length >= 20);
  for (const r of rows) assert.doesNotThrow(() => b.prepare(r, resolver()), r.id);
  const del = row("recovery/document-0/delete");
  const other = "/v1/projects/fireemu-oracle-query/databases/(default)/documents/other-collection/doc";
  for (const delta of [{ path: other }, { path: del.request.path.replace("fireemu-oracle-query", "other") }, { path: `${del.request.path}/x` }, { path: del.request.path.replace("/documents/", "/documents/../") }, { origin: "https://storage.googleapis.com" }]) {
    assert.throws(() => b.prepare({ ...del, request: { ...del.request, ...delta } }, resolver()), /invalid target row/);
  }
  const create = manifest.rows.find((r) => r.service === "firestore" && r.request.method === "POST");
  assert.throws(() => b.prepare({ ...create, request: { ...create.request, query: { documentId: "not-declared" } } }, resolver()), /invalid target row/);
});

test("Rules API and preflight requests match exact templates only", async () => {
  const b = await builder();
  const release = row("release/v1/publish");
  const ok = row("release/restore/delete");
  for (const delta of [{ path: "/v1/projects/other/releases/firebase.storage/x" }, { path: `/v1/projects/fireemu-oracle-query/releases/firebase.storage/other-bucket` }, { path: "/v1/projects/fireemu-oracle-query/releases/../x" }]) {
    assert.throws(() => b.prepare({ ...ok, request: { ...ok.request, ...delta } }, resolver()), /invalid target row/);
  }
  const bucketless = row("preflight/release/entry/bucketless");
  assert.doesNotThrow(() => b.prepare(bucketless, resolver()));
  for (const method of ["DELETE", "PATCH", "POST"]) assert.throws(() => b.prepare({ ...bucketless, request: { ...bucketless.request, method } }, resolver()), /invalid target row/);
  assert.throws(() => b.prepare({ ...release, request: { ...release.request, method: "DELETE" } }, resolver()), /invalid target row/);
  const pre = row("preflight/query/permissions");
  assert.doesNotThrow(() => b.prepare(pre, resolver()));
  for (const path of ["/v3/projects/111111111111:setIamPolicy", "/v3/projects/111111111111", "/v3/projects/111111111111:testIamPermissions/x"]) {
    assert.throws(() => b.prepare({ ...pre, request: { ...pre.request, path } }, resolver()), /invalid target row/);
  }
  const key = row("preflight/query/key-string");
  assert.throws(() => b.prepare({ ...key, request: { ...key.request, method: "POST" } }, resolver()), /invalid target row/);
});

test("headers and bodies are closed", async () => {
  const b = await builder();
  const seed = row("management/control-0/seed");
  for (const headers of [{ authorization: "Bearer x" }, { Authorization: "Bearer x" }, { "content-type": "text/plain\r\nX: y" }, { host: "evil" }, { "x-goog-user-project": "p" }, { cookie: "a=b" }, { "content-length": "1" }, { "transfer-encoding": "chunked" }, { "content-type": 7 }, { "bad name": "x" }]) {
    assert.throws(() => b.prepare({ ...seed, request: { ...seed.request, headers } }, resolver()), /invalid target row/, JSON.stringify(headers));
  }
  for (const body of [{ base64: "%%%" }, { base64: 7 }, { text: "x" }, { base64: "eA==", json: {} }, { json: () => 1 }, "string", 7, { base64: Buffer.alloc(262145).toString("base64") }]) {
    assert.throws(() => b.prepare({ ...seed, request: { ...seed.request, body } }, resolver()), /invalid target row/);
  }
  const patch = manifest.rows.find((r) => r.request.method === "PATCH" && r.request.body?.json);
  const prepared = b.prepare(patch, resolver());
  assert.equal(prepared.spec.headers["content-type"], patch.request.headers["content-type"]);
  const bare = b.prepare({ ...patch, request: { ...patch.request, headers: {} } }, resolver());
  assert.equal(bare.spec.headers["content-type"], "application/json; charset=utf-8");
  assert.deepEqual(JSON.parse(prepared.spec.body.toString()), JSON.parse(JSON.stringify(patch.request.body.json, (k, v) => (v && v.kind === "runtime-reference" ? VALUES[v.type] : v))));
});

test("query values are encoded canonically and arrays repeat their key", async () => {
  const perms = await prepare(row("preflight/bucket/permissions"));
  const url = new URL(perms.spec.url);
  assert.ok(url.searchParams.getAll("permissions").length > 1);
  assert.equal(perms.spec.url.includes("permissions=storage.buckets.get&permissions="), true);
  const seed = await prepare(row("management/control-0/seed"));
  assert.ok(seed.spec.url.includes(`name=${encodeURIComponent(row("management/control-0/seed").request.objectName)}`));
  assert.equal(seed.spec.url.includes("&name=") || seed.spec.url.includes("?name="), true);
});

test("the builder options are a closed record and the manifest must be the reviewed full manifest", async () => {
  const { createTargetBuilder } = await load();
  for (const bad of [null, {}, { manifest }, { digestSalt: salt }, { manifest, digestSalt: salt, extra: 1 }, { manifest, digestSalt: "short" }, { manifest: { rows: [] }, digestSalt: salt }, { manifest: { ...manifest, sendAuthorized: true }, digestSalt: salt }]) {
    assert.throws(() => createTargetBuilder(bad), /invalid target builder options/);
  }
  assert.equal(sha("x").length, 64);
});

test("verify accepts only a target this builder issued, unchanged since", async () => {
  const b = await builder();
  const r = row("management/control-0/seed");
  const prepared = b.prepare(r, resolver());
  assert.equal(b.verify(prepared), true);
  assert.equal(b.verify({ ...prepared }), false);
  const other = (await builder()).prepare(r, resolver());
  assert.equal(b.verify(other), false);
  assert.equal(b.verify(null), false);
  assert.equal(b.verify({ rowId: r.id }), false);
  prepared.spec.body[0] ^= 1;
  assert.equal(b.verify(prepared), false);
  const fresh = b.prepare(row("management/control-0/delete"), resolver());
  assert.equal(b.verify(fresh), true);
  const swapped = Object.create(null);
  assert.equal(b.verify(swapped), false);
});

test("a resumable session row is sent to the session URL and nowhere else", async () => {
  const b = await builder();
  const finalize = manifest.rows.find((r) => r.request.headers["x-goog-upload-command"] === "upload, finalize");
  const name = finalize.request.objectName;
  const prepared = b.prepare(finalize, resolver());
  assert.equal(prepared.spec.url, sessionUrl(name));
  assert.equal(prepared.spec.method, "POST");
  assert.equal(prepared.spec.body.toString(), "next");
  assert.equal(prepared.redacted, `POST https://firebasestorage.googleapis.com/v0/b/${binding.bucket}/o?<ref:session-url>`);
  assert.equal(JSON.stringify(prepared).includes("CANARYUPLOADID"), false);
  assert.equal(prepared.redacted.includes("CANARYUPLOADID"), false);
  assert.equal(b.verify(prepared), true);
  const other = b.prepare(finalize, (reference) => sessionUrl(reference.expectedObjectName, { uploadId: "OTHERUPLOADID987654321" }));
  assert.notEqual(other.targetSha256, prepared.targetSha256);
  for (const bad of [
    sessionUrl(name, { name: "STORAGE-RULES/other-run/x.bin" }), sessionUrl(name, { name: "outside/x.bin" }), sessionUrl(name, { path: "/v0/b/other-bucket/o" }), sessionUrl(name, { path: `/v0/b/${binding.bucket}/o/x` }),
    sessionUrl(name, { protocol: "multipart" }), sessionUrl(name, { extra: "&surprise=1" }), sessionUrl(name, { extra: `&name=${encodeURIComponent(name)}` }), sessionUrl(name, { uploadId: "short" }), sessionUrl(name, { uploadId: "has space" }),
    sessionUrl(name).replace("https://", "http://"), sessionUrl(name).replace("firebasestorage", "evil"), `${sessionUrl(name)}#f`, sessionUrl(name).replace("https://", "https://u:p@"), sessionUrl(name).replace(".com/", ".com:8443/"),
    `${sessionUrl(name)}\r\nX: y`, "", "not a url",
  ]) assert.throws(() => b.prepare(finalize, () => bad), /invalid target row/, bad);
  assert.throws(() => b.prepare({ ...finalize, request: { ...finalize.request, method: "PATCH" } }, resolver()), /invalid target row/);
  assert.throws(() => b.prepare({ ...finalize, request: { ...finalize.request, path: "/v0/b/x/o" } }, resolver()), /invalid target row/);
  assert.throws(() => b.prepare({ ...finalize, request: { ...finalize.request, query: { name } } }, resolver()), /invalid target row/);
});

test("the comparison row carries the created download token in its query and hides it", async () => {
  const b = await builder();
  const comparison = manifest.rows.find((r) => r.request.query?.token?.kind === "firebase-download-token");
  const prepared = b.prepare(comparison, resolver());
  assert.ok(prepared.spec.url.includes(`token=${VALUES["download-token"]}`));
  assert.equal(prepared.redacted.includes(VALUES["download-token"]), false);
  assert.ok(prepared.redacted.includes("token=<ref:download-token>"));
  assert.equal(JSON.stringify(prepared).includes(VALUES["download-token"]), false);
  for (const bad of ["", "short", "has space 123456", "a\r\nb-12345678", "token,second-token", "x".repeat(129)]) {
    assert.throws(() => b.prepare(comparison, (reference) => (typeOf(reference) === "download-token" ? bad : valueFor(reference))), /invalid target row/, bad);
  }
});

test("a capability parameter can never be a literal in a row", async () => {
  const b = await builder();
  const seed = row("management/control-0/baseline-metadata");
  for (const key of ["token", "key", "upload_id", "access_token", "id_token", "refresh_token", "sig", "signature", "Token"]) {
    assert.throws(() => b.prepare({ ...seed, request: { ...seed.request, query: { [key]: "literal" } } }, resolver()), /invalid target row/, key);
  }
  const comparison = manifest.rows.find((r) => r.request.query?.token?.kind === "firebase-download-token");
  assert.throws(() => b.prepare({ ...comparison, request: { ...comparison.request, query: { alt: "media", token: "0a1b2c3d-1111-2222-3333-444455556666" } } }, resolver()), /invalid target row/);
});

test("a prepared target carries the project its request is billed to, and the digest binds it", async () => {
  const b = await builder();
  const rows = manifest.rows.filter((r) => !UNPREPARED(r));
  const projects = new Set();
  for (const r of rows) {
    const prepared = b.prepare(r, resolver());
    assert.equal(prepared.project, r.request.project ?? "fireemu-oracle-query", r.id);
    // Every prepared request names the project it is billed to; a declared case with none is a request against the query project.
    assert.ok(["fireemu-oracle-idp", "fireemu-oracle-query"].includes(prepared.project), r.id);
    projects.add(prepared.project);
  }
  assert.ok(projects.has("fireemu-oracle-query"));
  assert.ok([...projects].every((project) => ["fireemu-oracle-idp", "fireemu-oracle-query"].includes(project)));
  // A different project in the same request is a different target.
  const original = row("management/control-0/seed");
  const other = { ...original, request: { ...original.request, project: "fireemu-oracle-idp" } };
  assert.notEqual(b.prepare(other, resolver()).targetSha256, b.prepare(original, resolver()).targetSha256);
});

test("the billed project is one of the two sandbox projects and agrees with the project the path names", async () => {
  const b = await builder();
  const query = row("ruleset/v1/create");
  assert.equal(query.request.path.includes("/projects/fireemu-oracle-query/"), true);
  for (const project of ["fireemu-oracle-idp", "another-project", "", null, 7, "fireemu-oracle-query\n"]) {
    assert.throws(() => b.prepare({ ...query, request: { ...query.request, project } }, resolver()), /invalid target row/, String(project));
  }
  assert.doesNotThrow(() => b.prepare({ ...query, request: { ...query.request, project: "fireemu-oracle-query" } }, resolver()));
  // A row's headers cannot carry the quota project either.
  assert.throws(() => b.prepare({ ...query, request: { ...query.request, headers: { ...query.request.headers, "x-goog-user-project": "fireemu-oracle-idp" } } }, resolver()));
});

// Each test below pairs an accepted control with inputs that only one layer of the builder refuses, so every layer is
// exercised on its own rather than through a neighbour that rejects the same input.
const rejects = (b, r, message, resolve = resolver()) => assert.throws(() => b.prepare(r, resolve), /invalid target row/, message);
const objectAt = (id, objectName, segment = encodeURIComponent(objectName)) => { const r = row(id); return { ...r, request: { ...r.request, objectName, path: r.request.path.replace(/\/o\/[^/]+$/, `/o/${segment}`) } }; };

test("an object name outside the owned-name grammar is refused even when its path segment is canonical", async () => {
  const b = await builder();
  assert.doesNotThrow(() => b.prepare(objectAt("management/control-0/delete", `${binding.prefix}fresh/x.bin`), resolver()));
  for (const name of [`${binding.prefix}a\x01b.bin`, `${binding.prefix}a\x7fb.bin`, `${binding.prefix}a\x1fb.bin`, `${binding.prefix}a//b.bin`, `${binding.prefix}dir/`, `${binding.prefix}a\\b.bin`]) {
    rejects(b, objectAt("management/control-0/delete", name), JSON.stringify(name));
  }
});

test("an object path segment must be the exact canonical encoding of the row's object name", async () => {
  const b = await builder();
  const name = `${binding.prefix}fresh/a:b+o.bin`;
  assert.doesNotThrow(() => b.prepare(objectAt("management/control-0/baseline-metadata", name), resolver()));
  for (const segment of [encodeURIComponent(name).replace("o.bin", "%6F.bin"), encodeURIComponent(name).replace("%3A", ":"), encodeURIComponent(name).replace("%2B", "+")]) {
    rejects(b, objectAt("management/control-0/baseline-metadata", name, segment), segment);
  }
});

test("an upload names this row's own object, and that object must be owned", async () => {
  const b = await builder();
  for (const id of ["management/control-0/seed", "case/method-read-upload-absent/subject/subject"]) {
    const r = row(id);
    const named = (objectName, name = objectName) => ({ ...r, request: { ...r.request, objectName, query: { ...r.request.query, name } } });
    assert.doesNotThrow(() => b.prepare(named(`${binding.prefix}fresh/x.bin`), resolver()), id);
    rejects(b, named(r.request.objectName, `${binding.prefix}fresh/other.bin`), `${id} names another owned object`);
    rejects(b, named("outside/x.bin"), `${id} names an unowned object`);
    rejects(b, named(binding.prefix), `${id} names the bare prefix`);
  }
});

test("object, token and Rules list routes accept only their own query parameters and values", async () => {
  const b = await builder();
  const cases = [
    ["management/control-0/baseline-metadata", {}, [{ projection: "full" }, { alt: "media", userProject: "x" }, { ifGenerationMatch: "1" }]],
    ["management/control-0/baseline-media", { alt: "media" }, [{ alt: "json" }, { alt: "" }]],
    ["case/download-token-deny/setup/create-token", { create_token: "true" }, [{ create_token: "false" }, { create_token: "1" }]],
    ["preflight/rulesets-list/entry/1", { pageSize: "100" }, [{ pageSize: "50" }, { pageSize: "1000" }]],
  ];
  for (const [id, good, bads] of cases) {
    const r = row(id);
    assert.doesNotThrow(() => b.prepare({ ...r, request: { ...r.request, query: good } }, resolver()), id);
    for (const query of bads) rejects(b, { ...r, request: { ...r.request, query } }, `${id} ${JSON.stringify(query)}`);
  }
});

test("a Firestore create names its document id once, as a single literal", async () => {
  const b = await builder();
  const create = manifest.rows.find((r) => r.service === "firestore" && r.request.method === "POST");
  const id = create.request.query.documentId;
  assert.doesNotThrow(() => b.prepare({ ...create, request: { ...create.request, query: { documentId: id } } }, resolver()));
  // A one-element list stringifies to the same id and produces the same URL, but it is not the shape a create has.
  rejects(b, { ...create, request: { ...create.request, query: { documentId: [id] } } }, "list id");
});

test("a preflight-only route refuses a row of any other family", async () => {
  const b = await builder();
  const r = row("management/control-0/baseline-metadata");
  const bucketRead = { ...r, request: { ...r.request, path: `/storage/v1/b/${binding.bucket}`, query: {} } };
  assert.doesNotThrow(() => b.prepare({ ...bucketRead, family: "preflight" }, resolver()));
  rejects(b, bucketRead, "management row on the bucket metadata route");
  const database = { ...r, request: { ...r.request, origin: "https://firestore.googleapis.com", path: "/v1/projects/fireemu-oracle-query/databases/(default)", query: {} } };
  assert.doesNotThrow(() => b.prepare({ ...database, family: "preflight" }, resolver()));
  rejects(b, database, "management row on the database route");
});

test("a URL the parser would rewrite is refused, so the digest covers the bytes that are sent", async () => {
  const b = await builder();
  const r = row("management/control-0/delete");
  assert.doesNotThrow(() => b.prepare({ ...r, request: { ...r.request, query: { ifGenerationMatch: "1" } } }, resolver()));
  // encodeURIComponent keeps an apostrophe, and the URL parser escapes it in the query of a special scheme.
  rejects(b, { ...r, request: { ...r.request, query: { ifGenerationMatch: "1'" } } }, "apostrophe");
  const perms = row("preflight/bucket/permissions");
  rejects(b, { ...perms, request: { ...perms.request, query: { permissions: ["storage.buckets.get", "it's"] } } }, "apostrophe in a list");
});

test("a base64 body must be the canonical encoding of its bytes", async () => {
  const b = await builder();
  const seed = row("management/control-0/seed");
  assert.equal(b.prepare({ ...seed, request: { ...seed.request, body: { base64: "eA==" } } }, resolver()).spec.body.toString(), "x");
  for (const base64 of ["eB==", "eA=", "eA", "eA==\n"]) rejects(b, { ...seed, request: { ...seed.request, body: { base64 } } }, base64);
});

test("a reference must be of a kind its position allows and must wait for durable proof", async () => {
  const b = await builder();
  const list = row("rulesets-list/final/2");
  const token = list.request.query.pageToken;
  const listWith = (pageToken) => ({ ...list, request: { ...list.request, query: { ...list.request.query, pageToken } } });
  assert.doesNotThrow(() => b.prepare(listWith({ ...token }), resolver()));
  for (const type of ["ruleset-name", "ruleset-path", "session-url"]) rejects(b, listWith({ ...token, type }), `query ${type}`);
  for (const flag of [false, "true", 1]) rejects(b, listWith({ ...token, resolveOnlyAfterDurableProof: flag }), `proof flag ${flag}`);
  const publish = row("release/v1/publish");
  const bodyWith = (rulesetName) => ({ ...publish, request: { ...publish.request, body: { json: { ...publish.request.body.json, rulesetName } } } });
  assert.doesNotThrow(() => b.prepare(bodyWith({ ...publish.request.body.json.rulesetName }), resolver()));
  for (const type of ["generation", "metageneration", "update-time", "page-token", "download-token", "ruleset-path"]) rejects(b, bodyWith({ ...publish.request.body.json.rulesetName, type }), `body ${type}`);
  const source = row("ruleset/v1/read-source");
  rejects(b, { ...source, request: { ...source.request, path: VALUES["ruleset-path"] } }, "path reference beside a literal path");
});

test("a row must be a manifest row of a family this module carries, with a known credential", async () => {
  const b = await builder();
  const r = row("management/control-0/baseline-metadata");
  assert.doesNotThrow(() => b.prepare({ ...r }, resolver()));
  for (const family of ["auth", "credential-cache"]) rejects(b, { ...r, family }, family);
  for (const id of ["management/control-0/unknown", `${r.id} `]) rejects(b, { ...r, id }, id);
  for (const credential of ["root", "", "Admin", undefined]) rejects(b, { ...r, request: { ...r.request, credential } }, String(credential));
});

test("the binding's bucket and prefix must be well formed", async () => {
  const { createTargetBuilder } = await load();
  const withBinding = (delta) => ({ manifest: { ...manifest, binding: { ...manifest.binding, ...delta } }, digestSalt: salt });
  assert.doesNotThrow(() => createTargetBuilder(withBinding({ prefix: "STORAGE-RULES/other-run/", bucket: "other.bucket-1" })));
  for (const delta of [{ prefix: "other/" }, { prefix: "STORAGE-RULES/Run/" }, { prefix: "STORAGE-RULES/run" }, { prefix: "STORAGE-RULES/a/b/" }, { prefix: "STORAGE-RULES//" }, { bucket: "Bad_Bucket" }, { bucket: "ab" }, { bucket: "-bucket" }, { bucket: "bucket/x" }]) {
    assert.throws(() => createTargetBuilder(withBinding(delta)), /invalid target builder options/, JSON.stringify(delta));
  }
});

test("query parameters are closed: no empty list, no control character, no oversized value and no prototype key", async () => {
  const b = await builder();
  const perms = row("preflight/bucket/permissions");
  const permsWith = (permissions) => ({ ...perms, request: { ...perms.request, query: { permissions } } });
  assert.doesNotThrow(() => b.prepare(permsWith(["storage.buckets.get", "x".repeat(2048)]), resolver()));
  for (const permissions of [[], ["storage.buckets.get\n"], ["a\x00b"], ["a\x7fb"], ["x".repeat(2049)], "x".repeat(2049)]) rejects(b, permsWith(permissions), JSON.stringify(permissions).slice(0, 40));
  // An own "__proto__" key would set the prototype of the parsed query instead of adding a key, and so skip the route's closed key set.
  const media = row("management/control-0/baseline-media");
  rejects(b, { ...media, request: { ...media.request, query: JSON.parse('{"alt":"media","__proto__":"x"}') } }, "__proto__");
  for (const key of ["1x", "a-b", "_x", "x".repeat(65)]) rejects(b, { ...media, request: { ...media.request, query: { alt: "media", [key]: "1" } } }, key);
});

test("a resumable session URL must name this row's own object, and that object must be owned", async () => {
  const b = await builder();
  const finalize = manifest.rows.find((r) => r.request.headers["x-goog-upload-command"] === "upload, finalize");
  const at = (objectName) => ({ ...finalize, request: { ...finalize.request, objectName } });
  const fresh = `${binding.prefix}fresh/x.bin`;
  assert.doesNotThrow(() => b.prepare(at(fresh), () => sessionUrl(fresh)));
  rejects(b, finalize, "another owned object", () => sessionUrl(finalize.request.objectName, { name: fresh }));
  rejects(b, at("outside/x.bin"), "unowned object", () => sessionUrl("outside/x.bin"));
  rejects(b, at(binding.prefix), "bare prefix", () => sessionUrl(binding.prefix));
});

test("a request that names no project on its path is still billed only to a sandbox project", async () => {
  const b = await builder();
  const seed = row("management/control-0/seed");
  for (const project of ["fireemu-oracle-query", "fireemu-oracle-idp", undefined]) assert.doesNotThrow(() => b.prepare({ ...seed, request: { ...seed.request, project } }, resolver()), String(project));
  for (const project of ["another-project", "fireemu-oracle-sbx", "", null, 7, "fireemu-oracle-query\n"]) rejects(b, { ...seed, request: { ...seed.request, project } }, String(project));
});

test("a row refused for its method, origin, credential, family or id never reaches the resolver", async () => {
  const b = await builder();
  const del = row("management/control-0/delete");
  const log = [];
  b.prepare(del, resolver(log));
  assert.deepEqual(log, [["generation", del.id]]);
  const refused = [...["PUT", "HEAD", "get", "OPTIONS", undefined].map((method) => ({ ...del, request: { ...del.request, method } })), { ...del, request: { ...del.request, origin: 7 } }, { ...del, request: { ...del.request, credential: "root" } }, { ...del, family: "auth" }, { ...del, id: "management/control-0/unknown" }];
  for (const r of refused) {
    const calls = [];
    rejects(b, r, JSON.stringify([r.id, r.family, r.request.method, r.request.origin, r.request.credential]), resolver(calls));
    assert.deepEqual(calls, [], r.request.method);
  }
});

test("a query key that names an Object prototype member cannot reach or skip a route's closed key set", async () => {
  const b = await builder();
  const media = row("management/control-0/baseline-media");
  const withQuery = (query) => ({ ...media, request: { ...media.request, query } });
  for (const key of ["__proto__", "constructor", "prototype", "toString", "valueOf", "hasOwnProperty", "__defineGetter__"]) {
    // Parsed from JSON so `__proto__` is an own key, as a row loaded from a file would carry it.
    rejects(b, withQuery(JSON.parse(`{"alt":"media","${key}":"x"}`)), key);
    rejects(b, withQuery(JSON.parse(`{"${key}":"media"}`)), `${key} alone`);
  }
  assert.doesNotThrow(() => b.prepare(withQuery({ alt: "media" }), resolver()));
});

// Defence in depth for rows the reviewed manifest never carries: the layer that builds targets must not accept them either.
test("a row may carry only the four headers the reviewed manifest uses", async () => {
  const b = await builder();
  const get = row("management/control-0/baseline-metadata");
  const withHeaders = (headers) => ({ ...get, request: { ...get.request, headers } });
  for (const name of ["content-type", "x-goog-upload-protocol", "x-goog-upload-command", "x-goog-upload-offset"]) assert.doesNotThrow(() => b.prepare(withHeaders({ [name]: "value" }), resolver()), name);
  for (const name of ["x-http-method-override", "x-goog-encryption-key", "x-goog-api-client", "user-agent", "accept", "range", "if-match", "x-forwarded-for", "origin", "referer", "x-goog-user-project", "authorization", "x-goog-upload-url", "x-firebase-appcheck"]) rejects(b, withHeaders({ [name]: "value" }), name);
});

test("a release write names only this run's release and takes its Ruleset from a bound reference", async () => {
  const b = await builder();
  const create = row("release/v1/publish");
  const patch = row("release/v2/publish");
  const owned = `projects/fireemu-oracle-query/releases/firebase.storage/${binding.bucket}`;
  const ref = create.request.body.json.rulesetName;
  const withBody = (base, json) => ({ ...base, request: { ...base.request, body: { json } } });
  assert.doesNotThrow(() => b.prepare(create, resolver()));
  assert.doesNotThrow(() => b.prepare(patch, resolver()));
  for (const [name, json] of Object.entries({
    "another release": { name: "projects/fireemu-oracle-query/releases/cloud.firestore", rulesetName: ref },
    "another bucket": { name: `projects/fireemu-oracle-query/releases/firebase.storage/other-bucket`, rulesetName: ref },
    "the bucketless release": { name: "projects/fireemu-oracle-query/releases/firebase.storage", rulesetName: ref },
    "another project": { name: `projects/fireemu-oracle-idp/releases/firebase.storage/${binding.bucket}`, rulesetName: ref },
    "a literal Ruleset name": { name: owned, rulesetName: "projects/fireemu-oracle-query/rulesets/someone-elses" },
    "a wrong reference type": { name: owned, rulesetName: { ...ref, type: "generation" } },
    "an extra field": { name: owned, rulesetName: ref, extra: 1 },
    "a missing name": { rulesetName: ref },
    "a missing Ruleset": { name: owned },
    "a nested wrapper": { release: { name: owned, rulesetName: ref } },
  })) rejects(b, withBody(create, json), `create with ${name}`);
  for (const [name, json] of Object.entries({
    "another release": { release: { name: "projects/fireemu-oracle-query/releases/cloud.firestore", rulesetName: ref }, updateMask: "rulesetName" },
    "a literal Ruleset name": { release: { name: owned, rulesetName: "projects/fireemu-oracle-query/rulesets/x" }, updateMask: "rulesetName" },
    "another update mask": { release: { name: owned, rulesetName: ref }, updateMask: "name" },
    "no update mask": { release: { name: owned, rulesetName: ref } },
    "an extra release field": { release: { name: owned, rulesetName: ref, extra: 1 }, updateMask: "rulesetName" },
    "a flat body": { name: owned, rulesetName: ref },
    "an extra top field": { release: { name: owned, rulesetName: ref }, updateMask: "rulesetName", extra: 1 },
  })) rejects(b, withBody(patch, json), `patch with ${name}`);
});

test("a Ruleset read or delete needs the bound Ruleset path, never a literal one", async () => {
  const b = await builder();
  for (const id of ["ruleset/v1/delete", "ruleset/v1/read-source"]) {
    const base = row(id);
    assert.doesNotThrow(() => b.prepare(base, resolver()), id);
    const { pathReference, ...rest } = base.request;
    rejects(b, { ...base, request: { ...rest, path: "/v1/projects/fireemu-oracle-query/rulesets/someone-elses-ruleset" } }, `${id} literal`);
  }
});

test("a numeric project path must carry the project number of the project the request is billed to, and a key path its own key", async () => {
  const b = await builder();
  const numbers = { query: options.queryProjectNumber, idp: options.idpProjectNumber };
  const keys = { query: options.queryApiKeyId, idp: options.idpApiKeyId };
  for (const [name, id] of [["query", "preflight/query/project"], ["idp", "preflight/idp/project"], ["query", "preflight/query/permissions"], ["idp", "preflight/idp/permissions"], ["query", "preflight/query/iam"], ["query", "preflight/query/key-metadata"], ["idp", "preflight/idp/key-metadata"], ["query", "preflight/query/key-string"], ["idp", "preflight/idp/key-string"]]) {
    const base = row(id);
    assert.doesNotThrow(() => b.prepare(base, resolver()), id);
    const other = name === "query" ? "idp" : "query";
    rejects(b, { ...base, request: { ...base.request, path: base.request.path.replace(numbers[name], numbers[other]) } }, `${id} with the other project's number`);
    rejects(b, { ...base, request: { ...base.request, path: base.request.path.replace(numbers[name], "999999999999") } }, `${id} with an unknown number`);
    if (/keys\//.test(base.request.path)) {
      rejects(b, { ...base, request: { ...base.request, path: base.request.path.replace(keys[name], keys[other]) } }, `${id} with the other project's key`);
      rejects(b, { ...base, request: { ...base.request, path: base.request.path.replace(keys[name], "11111111-1111-4111-8111-111111111111") } }, `${id} with an unknown key`);
    }
  }
  // The billed project decides which number is expected.
  const base = row("preflight/query/project");
  rejects(b, { ...base, request: { ...base.request, project: "fireemu-oracle-idp" } }, "query number billed to idp");
});

test("only a ruleset-name reference is a release body reference, and no other body may carry a reference", async () => {
  const b = await builder();
  const create = row("release/v1/publish");
  const owned = `projects/fireemu-oracle-query/releases/firebase.storage/${binding.bucket}`;
  const ref = create.request.body.json.rulesetName;
  const withBody = (base, json) => ({ ...base, request: { ...base.request, body: { json } } });
  // A look-alike that is not a runtime reference would be sent as a literal object.
  rejects(b, withBody(create, { name: owned, rulesetName: { kind: "other", type: "ruleset-name", key: "v1", resolveOnlyAfterDurableProof: true } }), "look-alike kind");
  rejects(b, withBody(create, { name: owned, rulesetName: { ...ref, resolveOnlyAfterDurableProof: false } }), "unproven reference");
  rejects(b, withBody(create, { name: owned, rulesetName: { ...ref, extra: 1 } }), "extra reference field");
  // Another body carrying a reference of a kind the body position does not allow is refused whatever the row is.
  const test = manifest.rows.find((r) => r.family === "compile" && r.stage === "test");
  const source = test.request.body.json.source;
  for (const type of ["generation", "metageneration", "update-time", "page-token", "session-url", "download-token", "ruleset-path"]) {
    rejects(b, withBody(test, { source, extra: { kind: "runtime-reference", type, key: "k", resolveOnlyAfterDurableProof: true } }), `${type} in a test body`);
  }
  assert.doesNotThrow(() => b.prepare(withBody(test, { source, extra: { ...ref, key: "v1" } }), resolver()));
});

test("a preflight row with no billed project defaults to the query project, for its numeric path and its key path", async () => {
  const b = await builder();
  for (const id of ["preflight/query/project", "preflight/query/key-metadata", "preflight/query/key-string", "preflight/query/permissions", "preflight/query/iam"]) {
    const base = row(id);
    const { project, ...rest } = base.request;
    assert.doesNotThrow(() => b.prepare({ ...base, request: rest }, resolver()), id);
    assert.equal(b.prepare({ ...base, request: rest }, resolver()).project, "fireemu-oracle-query");
  }
  for (const id of ["preflight/idp/project", "preflight/idp/key-metadata", "preflight/idp/key-string", "preflight/idp/permissions"]) {
    const base = row(id);
    const { project, ...rest } = base.request;
    rejects(b, { ...base, request: rest }, `${id} without its project falls to the query project and its own number no longer fits`);
  }
});

test("a release write must carry a JSON body: a base64 body or none is refused, so the release-name binding cannot be bypassed", async () => {
  const b = await builder();
  const owned = `projects/fireemu-oracle-query/releases/firebase.storage/${binding.bucket}`;
  for (const id of ["release/v1/publish", "release/v2/publish"]) {
    const base = row(id);
    const other = Buffer.from(JSON.stringify({ name: "projects/fireemu-oracle-query/releases/cloud.firestore", rulesetName: "projects/fireemu-oracle-query/rulesets/x" })).toString("base64");
    const owning = Buffer.from(JSON.stringify({ name: owned })).toString("base64");
    for (const body of [{ base64: other }, { base64: owning }, { base64: "" }, null, undefined]) {
      const request = { ...base.request, body };
      if (body === undefined) delete request.body;
      rejects(b, { ...base, request }, `${id} with ${JSON.stringify(body)?.slice(0, 30)}`);
    }
    assert.doesNotThrow(() => b.prepare(base, resolver()), id);
  }
  // Reads and deletes of a release carry no body, and other bodies stay as they were.
  assert.doesNotThrow(() => b.prepare(row("release/restore/delete"), resolver()));
  assert.doesNotThrow(() => b.prepare(row("release/restore/owner-before-delete"), resolver()));
});
