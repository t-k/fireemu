import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { buildCorpus } from "./storage-rules/corpus.mjs";
import { buildFullRequestManifest } from "./storage-rules/full-manifest.mjs";

const closure = JSON.parse(readFileSync(new URL("../../spec/compatibility/closure/STORAGE-RULES.json", import.meta.url)));
const options = { runId: "local-run", sourceCommit: "a".repeat(40), queryProjectNumber: "1".repeat(12), idpProjectNumber: "2".repeat(12), queryApiKeyId: "00000000-0000-4000-8000-000000000001", idpApiKeyId: "00000000-0000-4000-8000-000000000002" };
const binding = { bucket: "synthetic-rules-bucket", prefix: "STORAGE-RULES/local-run/", uidA: "storage-rules-local-run-user-a", uidB: "storage-rules-local-run-user-b" };
const manifest = buildFullRequestManifest(buildCorpus(binding), closure, options);
const row = (id) => manifest.rows.find((r) => r.id === id) ?? assert.fail(id);
const load = () => import("./storage-rules/acceptance.mjs");
const response = (status, body = "", headers = {}) => ({ status, rawHeaders: Object.entries(headers).flatMap(([name, value]) => (Array.isArray(value) ? value : [value]).flatMap((one) => [name, one])), bytes: Buffer.from(typeof body === "string" ? body : JSON.stringify(body)) });
const json = (status, body, extra = {}) => response(status, body, { "Content-Type": "application/json; charset=UTF-8", ...extra });
const notFound = json(404, { error: { code: 404, message: "Document not found", status: "NOT_FOUND" } });
const TOKEN = "CANARY-DOWNLOAD-TOKEN-0123456789ab";
const SESSION_OBJECT = manifest.resources.sessions[0];
const sessionUrl = (over = {}) => {
  const query = { name: SESSION_OBJECT.objectName, upload_id: "CANARYUPLOADID0123456789", upload_protocol: "resumable", ...over.query };
  const search = Object.entries(query).filter(([, v]) => v !== undefined).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join("&");
  return `https://firebasestorage.googleapis.com${over.path ?? `/v0/b/${binding.bucket}/o`}?${search}`;
};

test("all remaining object, Firestore and session kinds are implemented except the preflight ones", async () => {
  const { ACCEPTANCE_KINDS, unimplementedKinds } = await load();
  for (const kind of ["gcs-patch", "gcs-prefix-list", "firebase-create-token", "session-start", "session-command", "firestore-read", "firestore-write"]) assert.equal(ACCEPTANCE_KINDS[kind].implemented, true, kind);
  assert.deepEqual(unimplementedKinds().filter((k) => !k.startsWith("preflight-")), ["credential-cache", "auth"]);
});

test("a patch is accepted only for the exact object with canonical versions", async () => {
  const { classifyResponse } = await load();
  const patch = manifest.rows.find((r) => r.request.operation === "patch" && r.stage === "setup" && r.service === "storage" && r.request.dialect === "gcs");
  const name = patch.request.objectName;
  const object = (extra = {}) => ({ kind: "storage#object", bucket: binding.bucket, name, size: "4", generation: "1700000000000001", metageneration: "2", ...extra });
  const good = classifyResponse(patch, json(200, object()));
  assert.equal(good.verdict, "accepted");
  assert.deepEqual({ ...good.facts }, { status: 200, generation: "1700000000000001", metageneration: "2" });
  for (const bad of [json(200, object({ name: `${name}x` })), json(200, object({ bucket: "other" })), json(200, object({ generation: "0" })), json(200, object({ metageneration: "01" })), json(200, object({ kind: "storage#objects" })), json(412, { error: { code: 412, message: "Precondition Failed" } }), json(404, {}), response(200, "")]) {
    assert.equal(classifyResponse(patch, bad).verdict, "unexpected");
  }
});

test("a prefix list reports counts only and never a name", async () => {
  const { classifyResponse } = await load();
  const list = row("management/prefix-empty");
  const empty = classifyResponse(list, json(200, { kind: "storage#objects" }));
  assert.equal(empty.verdict, "accepted");
  assert.deepEqual({ ...empty.facts }, { status: 200, itemCount: 0, prefixCount: 0, hasNextPage: false });
  const some = classifyResponse(list, json(200, { kind: "storage#objects", items: [{ kind: "storage#object", name: "STORAGE-RULES/local-run/a" }], prefixes: ["STORAGE-RULES/local-run/x/"], nextPageToken: "t" }));
  assert.deepEqual({ ...some.facts }, { status: 200, itemCount: 1, prefixCount: 1, hasNextPage: true });
  assert.equal(JSON.stringify(some).includes("local-run/a"), false);
  for (const bad of [json(200, { kind: "storage#bucket" }), json(200, { kind: "storage#objects", items: {} }), json(200, { kind: "storage#objects", items: [1] }), json(200, { kind: "storage#objects", prefixes: [7] }), json(200, { kind: "storage#objects", nextPageToken: 5 }), json(403, {}), response(200, "")]) {
    assert.equal(classifyResponse(list, bad).verdict, "unexpected");
  }
});

test("a token creation keeps the token out of the facts and in a non-enumerable secret", async () => {
  const { classifyResponse } = await load();
  const create = manifest.rows.find((r) => r.request.operation === "create-token");
  const name = create.request.objectName;
  const object = (extra = {}) => ({ name, bucket: binding.bucket, generation: "1700000000000001", metageneration: "1", downloadTokens: TOKEN, ...extra });
  const good = classifyResponse(create, json(200, object()));
  assert.equal(good.verdict, "accepted");
  assert.deepEqual({ ...good.facts }, { status: 200, generation: "1700000000000001", metageneration: "1", hasDownloadToken: true });
  assert.equal(JSON.stringify(good).includes(TOKEN), false);
  assert.equal(Object.keys(good).includes("secretFacts"), false);
  assert.equal(good.secretFacts.downloadTokens, TOKEN);
  assert.equal(Object.isFrozen(good.secretFacts), true);
  for (const bad of [json(200, object({ downloadTokens: "" })), json(200, (({ downloadTokens, ...rest }) => rest)(object())), json(200, object({ name: "other" })), json(200, object({ bucket: "other" })), json(200, object({ generation: "x" })), json(403, {}), response(200, "")]) {
    assert.equal(classifyResponse(create, bad).verdict, "unexpected");
  }
});

test("a session start needs the active status and one well-formed session URL, which stays secret", async () => {
  const { classifyResponse } = await load();
  const start = manifest.rows.find((r) => r.request.headers["x-goog-upload-command"] === "start" && r.request.objectName === SESSION_OBJECT.objectName);
  assert.ok(start);
  const good = (url = sessionUrl(), status = "active") => json(200, {}, { "X-Goog-Upload-URL": url, "X-Goog-Upload-Status": status });
  const ok = classifyResponse(start, good());
  assert.equal(ok.verdict, "accepted");
  assert.deepEqual({ ...ok.facts }, { status: 200, uploadStatus: "active" });
  assert.equal(JSON.stringify(ok).includes("CANARYUPLOADID"), false);
  assert.equal(ok.secretFacts.sessionUrl, sessionUrl());
  for (const bad of [
    good(sessionUrl(), "final"), good(sessionUrl({ query: { name: "other" } })), good(sessionUrl({ query: { upload_id: undefined } })), good(sessionUrl({ query: { upload_protocol: "multipart" } })), good(sessionUrl({ query: { extra: "1" } })),
    good(sessionUrl({ path: "/v0/b/other/o" })), good(sessionUrl({ path: `/v0/b/${binding.bucket}/o/x` })), good(sessionUrl().replace("https://", "http://")), good(sessionUrl().replace("firebasestorage", "evil")), good("not a url"),
    good(`${sessionUrl()}#frag`), good(sessionUrl().replace("https://", "https://user:pw@")), json(200, {}, { "X-Goog-Upload-Status": "active" }), json(200, {}, { "X-Goog-Upload-URL": sessionUrl() }),
    { ...good(), rawHeaders: [...good().rawHeaders, "x-goog-upload-url", sessionUrl()] }, json(403, {}), response(200, ""),
  ]) assert.equal(classifyResponse(start, bad).verdict, "unexpected");
});

test("a session query is active or final with at most four bytes received, and a cancel is only acknowledged", async () => {
  const { classifyResponse } = await load();
  const query = manifest.rows.find((r) => r.family === "recovery-session" && r.stage === "current");
  const cancel = manifest.rows.find((r) => r.family === "recovery-session" && r.stage === "cancel");
  const headers = (status, received) => ({ "X-Goog-Upload-Status": status, ...(received === undefined ? {} : { "X-Goog-Upload-Size-Received": received }) });
  assert.deepEqual({ ...classifyResponse(query, response(200, "", headers("active", "0"))).facts }, { status: 200, uploadStatus: "active", sizeReceived: 0 });
  assert.equal(classifyResponse(query, response(200, "", headers("final", "4"))).verdict, "final");
  assert.equal(classifyResponse(query, response(200, "", headers("active", "0"))).verdict, "active");
  for (const bad of [response(200, "", headers("active", "5")), response(200, "", headers("active", "-1")), response(200, "", headers("active", "01")), response(200, "", headers("active")), response(200, "", headers("cancelled", "0")), response(200, "", headers("weird", "0")), response(404, ""), response(200, "x", headers("active", "0")), { ...response(200, "", headers("active", "0")), rawHeaders: [...response(200, "", headers("active", "0")).rawHeaders, "x-goog-upload-status", "final"] }]) {
    assert.equal(classifyResponse(query, bad).verdict, "unexpected");
  }
  assert.equal(classifyResponse(cancel, response(200, "", headers("cancelled"))).verdict, "acknowledged");
  assert.equal(classifyResponse(cancel, response(200, "")).verdict, "acknowledged");
  for (const bad of [response(200, "", headers("active", "0")), response(404, ""), response(500, ""), response(200, "x", headers("cancelled"))]) assert.equal(classifyResponse(cancel, bad).verdict, "unexpected");
});

test("Firestore documents read as present with times, absent as NOT_FOUND, and write in their exact shape", async () => {
  const { classifyResponse } = await load();
  const read = row("recovery/document-0/current");
  const name = read.request.path.slice(4);
  const doc = (extra = {}) => ({ name, fields: { a: { stringValue: "x" } }, createTime: "2026-09-29T10:00:00.000000Z", updateTime: "2026-09-29T10:00:01.000000Z", ...extra });
  const present = classifyResponse(read, json(200, doc()));
  assert.equal(present.verdict, "present");
  assert.deepEqual({ ...present.facts }, { status: 200, documentName: name, createTime: "2026-09-29T10:00:00.000000Z", updateTime: "2026-09-29T10:00:01.000000Z" });
  assert.equal(JSON.stringify(present).includes("stringValue"), false);
  assert.equal(classifyResponse(read, notFound).verdict, "absent");
  for (const bad of [json(200, doc({ name: `${name}x` })), json(200, doc({ updateTime: "x" })), json(200, (({ updateTime, ...rest }) => rest)(doc())), json(200, doc({ surprise: 1 })), json(403, { error: { code: 403, message: "x", status: "PERMISSION_DENIED" } }), json(404, { error: { code: 404, message: "x" } }), response(200, "")]) {
    assert.equal(classifyResponse(read, bad).verdict, "unexpected");
  }
  const remove = row("recovery/document-0/delete");
  assert.equal(classifyResponse(remove, json(200, {})).verdict, "accepted");
  for (const bad of [json(200, doc()), notFound, response(200, ""), json(412, { error: { code: 412, message: "x", status: "FAILED_PRECONDITION" } })]) assert.equal(classifyResponse(remove, bad).verdict, "unexpected");
  const create = manifest.rows.find((r) => r.service === "firestore" && r.request.method === "POST");
  const created = `${create.request.path.slice(4)}/${create.request.query.documentId}`;
  assert.equal(classifyResponse(create, json(200, doc({ name: created }))).verdict, "accepted");
  assert.equal(classifyResponse(create, json(200, doc({ name: created }))).facts.updateTime, "2026-09-29T10:00:01.000000Z");
  assert.equal(classifyResponse(create, json(200, doc({ name: `${created}x` }))).verdict, "unexpected");
  const patch = manifest.rows.find((r) => r.service === "firestore" && r.request.method === "PATCH");
  assert.equal(classifyResponse(patch, json(200, doc({ name: patch.request.path.slice(4) }))).verdict, "accepted");
  assert.equal(classifyResponse(patch, json(200, doc({ name: `${patch.request.path.slice(4)}x` }))).verdict, "unexpected");
});
