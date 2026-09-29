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
const row = (id) => manifest.rows.find((r) => r.id === id) ?? assert.fail(id);
const sha = (value) => createHash("sha256").update(value).digest("hex");
const load = async () => {
  const module = await import("./storage-rules/acceptance.mjs");
  return module;
};
const response = (status, body = "", headers = {}) => ({ status, rawHeaders: Object.entries(headers).flat(), bytes: Buffer.from(typeof body === "string" ? body : JSON.stringify(body)) });
const json = (status, body, extra = {}) => response(status, body, { "Content-Type": "application/json; charset=UTF-8", ...extra });
const notFound = json(404, { error: { code: 404, message: "Requested entity was not found.", status: "NOT_FOUND" } });
const PROJECT = "fireemu-oracle-query";
const bucket = binding.bucket;
const createTime = "2026-09-29T10:00:00.123456Z";
const rulesetName = (id = "3f5a-abc") => `projects/${PROJECT}/rulesets/${id}`;
const ruleset = (content, extra = {}) => ({ name: rulesetName(), createTime, source: { files: [{ name: "storage.rules", content, fingerprint: "AbCd" }] }, metadata: { services: ["firebase.storage"] }, ...extra });
const releaseName = `projects/${PROJECT}/releases/firebase.storage/${bucket}`;
const release = (extra = {}) => ({ name: releaseName, rulesetName: rulesetName(), createTime, updateTime: createTime, ...extra });

const createRow = row("ruleset/v1/create");
const sentContent = createRow.request.body.json.source.files[0].content;

test("all nine Rules API kinds are implemented", async () => {
  const { ACCEPTANCE_KINDS, acceptanceKindOf } = await load();
  for (const kind of ["rules-test", "rules-release-read", "rules-release-create", "rules-release-patch", "rules-release-delete", "rules-ruleset-create", "rules-ruleset-read", "rules-ruleset-delete", "rules-list-page"]) {
    assert.equal(ACCEPTANCE_KINDS[kind].implemented, true, kind);
    assert.ok(manifest.rows.some((r) => acceptanceKindOf(r) === kind), kind);
  }
});

test("a created Ruleset is accepted only with the exact source that was sent", async () => {
  const { classifyResponse } = await load();
  const good = classifyResponse(createRow, json(200, ruleset(sentContent)));
  assert.equal(good.verdict, "accepted");
  assert.deepEqual({ ...good.facts }, { status: 200, rulesetName: rulesetName(), createTime, sourceSha256: sha(sentContent) });
  for (const bad of [
    json(200, ruleset(`${sentContent} `)), json(200, ruleset(sentContent, { name: `projects/other/rulesets/x` })), json(200, ruleset(sentContent, { name: "x" })), json(200, ruleset(sentContent, { createTime: "yesterday" })),
    json(200, ruleset(sentContent, { source: { files: [] } })), json(200, ruleset(sentContent, { source: { files: [{ name: "other.rules", content: sentContent }] } })),
    json(200, ruleset(sentContent, { source: { files: [{ name: "storage.rules", content: sentContent }, { name: "storage.rules", content: sentContent }] } })),
    json(200, ruleset(sentContent, { source: { files: [{ name: "storage.rules", content: 7 }] } })), json(400, { error: { code: 400, status: "INVALID_ARGUMENT", message: "x" } }), json(409, {}), response(200, "{}"), response(200, ""), notFound, response(500, ""),
  ]) assert.equal(classifyResponse(createRow, bad).verdict, "unexpected");
});

test("a Ruleset read is present with the source digest, absent only for the closed NOT_FOUND, and unexpected otherwise", async () => {
  const { classifyResponse } = await load();
  for (const id of ["ruleset/v1/read-source", "recovery/ruleset/v1/current"]) {
    const r = row(id);
    const present = classifyResponse(r, json(200, ruleset("rules text")));
    assert.equal(present.verdict, "present");
    assert.equal(present.facts.sourceSha256, sha("rules text"));
    assert.equal(present.facts.rulesetName, rulesetName());
    assert.equal(classifyResponse(r, notFound).verdict, "absent");
    for (const bad of [json(404, { error: { code: 404, message: "x" } }), json(404, { error: { code: 404, status: "OTHER", message: "x" } }), json(403, { error: { code: 403, status: "PERMISSION_DENIED", message: "x" } }), json(200, { name: "x" }), response(404, "<html/>", { "Content-Type": "text/html" })]) {
      assert.equal(classifyResponse(r, bad).verdict, "unexpected");
    }
  }
  const absence = row("ruleset/v1/absence");
  assert.equal(classifyResponse(absence, notFound).verdict, "absent");
});

test("a Ruleset delete is accepted only as an empty JSON object", async () => {
  const { classifyResponse } = await load();
  const del = row("ruleset/v1/delete");
  assert.equal(classifyResponse(del, json(200, {})).verdict, "accepted");
  assert.equal(classifyResponse(row("recovery/ruleset/v1/delete"), json(200, {})).verdict, "accepted");
  for (const bad of [json(200, { name: "x" }), json(204, ""), response(200, ""), notFound, json(403, { error: { code: 403, status: "PERMISSION_DENIED", message: "x" } }), json(200, [])]) assert.equal(classifyResponse(del, bad).verdict, "unexpected");
});

test("release reads name the release from the row's own path", async () => {
  const { classifyResponse } = await load();
  const bucketRead = row("release/v1/before");
  const bucketless = row("preflight/release/entry/bucketless");
  const present = classifyResponse(bucketRead, json(200, release()));
  assert.equal(present.verdict, "present");
  assert.deepEqual({ ...present.facts }, { status: 200, releaseName, rulesetName: rulesetName(), updateTime: createTime });
  assert.equal(classifyResponse(bucketRead, notFound).verdict, "absent");
  assert.equal(classifyResponse(bucketless, notFound).verdict, "absent");
  assert.equal(classifyResponse(bucketless, json(200, release({ name: `projects/${PROJECT}/releases/firebase.storage` }))).verdict, "present");
  for (const [r, bad] of [
    [bucketRead, json(200, release({ name: `projects/${PROJECT}/releases/firebase.storage` }))], [bucketRead, json(200, release({ name: `projects/${PROJECT}/releases/firebase.storage/other` }))],
    [bucketRead, json(200, release({ rulesetName: "x" }))], [bucketRead, json(200, release({ updateTime: "x" }))], [bucketRead, json(200, (({ updateTime, ...rest }) => rest)(release()))], [bucketRead, json(500, {})],
    [bucketless, json(200, release())],
  ]) assert.equal(classifyResponse(r, bad).verdict, "unexpected");
});

test("release create, patch and delete are accepted only in their exact shape", async () => {
  const { classifyResponse } = await load();
  const create = row("release/v1/publish");
  const patch = row("release/v2/publish");
  const del = row("release/restore/delete");
  assert.equal(classifyResponse(create, json(200, release())).verdict, "accepted");
  assert.equal(classifyResponse(patch, json(200, release())).verdict, "accepted");
  assert.equal(classifyResponse(del, json(200, {})).verdict, "accepted");
  for (const bad of [json(200, release({ name: "projects/other/releases/firebase.storage/x" })), json(409, { error: { code: 409, status: "ALREADY_EXISTS", message: "x" } }), notFound, response(200, ""), json(200, [])]) {
    assert.equal(classifyResponse(create, bad).verdict, "unexpected");
    assert.equal(classifyResponse(patch, bad).verdict, "unexpected");
  }
  for (const bad of [json(200, release()), notFound, json(204, ""), response(200, "")]) assert.equal(classifyResponse(del, bad).verdict, "unexpected");
});

test("a Rulesets list page reports counts and the next token, and rejects malformed pages", async () => {
  const { classifyResponse } = await load();
  const page = row("rulesets-list/final/1");
  const names = [1, 2, 3].map((n) => ({ name: rulesetName(`id-${n}`), createTime }));
  const withNext = classifyResponse(page, json(200, { rulesets: names, nextPageToken: "opaque_token-1" }));
  assert.equal(withNext.verdict, "accepted");
  const listed = names.map((entry) => ({ name: entry.name, services: [] }));
  assert.deepEqual({ ...withNext.facts }, { status: 200, count: 3, hasNextPage: true, nextPageToken: "opaque_token-1", rulesets: listed });
  assert.deepEqual({ ...classifyResponse(page, json(200, { rulesets: names })).facts }, { status: 200, count: 3, hasNextPage: false, rulesets: listed });
  assert.deepEqual({ ...classifyResponse(page, json(200, {})).facts }, { status: 200, count: 0, hasNextPage: false, rulesets: [] });
  const big = Array.from({ length: 100 }, (_, n) => ({ name: rulesetName(`id-${n}`), createTime }));
  assert.equal(classifyResponse(page, json(200, { rulesets: big })).facts.count, 100);
  for (const bad of [
    json(200, { rulesets: [...big, big[0]] }), json(200, { rulesets: [{ name: "x", createTime }] }), json(200, { rulesets: [{ name: rulesetName(), createTime: "x" }] }), json(200, { rulesets: {} }),
    json(200, { rulesets: names, nextPageToken: "" }), json(200, { rulesets: names, nextPageToken: "a b" }), json(200, { rulesets: names, nextPageToken: 7 }), json(200, { rulesets: names, extra: 1 }), json(403, {}), response(200, "[]"), notFound,
  ]) assert.equal(classifyResponse(page, bad).verdict, "unexpected");
});

test("a Rulesets list page takes the entries the way production lists them, with their services, and reports them sorted by name", async () => {
  const { classifyResponse } = await load();
  const page = row("preflight/rulesets-list/entry/1");
  const storage = { name: rulesetName("22b746af-a48a-458d-ab5c-7853473bc8c8"), createTime: "2026-09-25T11:08:54.358767Z", metadata: { services: ["firebase.storage"] } };
  const firestore = { name: rulesetName("d0abf7c6-b0b6-4163-8488-7c8a48ac5dd1"), createTime: "2026-09-23T23:02:05.839536Z", metadata: { services: ["cloud.firestore"] } };
  const outcome = classifyResponse(page, json(200, { rulesets: [firestore, storage] }));
  assert.equal(outcome.verdict, "accepted");
  assert.deepEqual({ ...outcome.facts }, { status: 200, count: 2, hasNextPage: false, rulesets: [{ name: storage.name, services: ["firebase.storage"] }, { name: firestore.name, services: ["cloud.firestore"] }] });
  // Services are reported sorted, an entry with empty or absent services reports none, and neither createTime nor a source ever reaches a fact.
  const both = { name: rulesetName("both"), createTime: storage.createTime, metadata: { services: ["firebase.storage", "cloud.firestore"] } };
  assert.deepEqual(classifyResponse(page, json(200, { rulesets: [both] })).facts.rulesets, [{ name: both.name, services: ["cloud.firestore", "firebase.storage"] }]);
  assert.deepEqual(classifyResponse(page, json(200, { rulesets: [{ ...both, metadata: {} }] })).facts.rulesets, [{ name: both.name, services: [] }]);
  assert.deepEqual(classifyResponse(page, json(200, { rulesets: [{ ...both, metadata: { services: [] } }] })).facts.rulesets, [{ name: both.name, services: [] }]);
  assert.equal(JSON.stringify(outcome.facts).includes("createTime"), false);
  for (const bad of [
    { ...storage, metadata: { services: ["firebase.storage"], extra: 1 } }, { ...storage, metadata: [] }, { ...storage, metadata: "x" }, { ...storage, metadata: null }, { ...storage, metadata: { services: "firebase.storage" } },
    { ...storage, metadata: { services: [5] } }, { ...storage, metadata: { services: ["Firebase Storage"] } }, { ...storage, metadata: { services: Array.from({ length: 9 }, (_, n) => `s${n}`) } }, { ...storage, source: {} }, { ...storage, extra: 1 },
  ]) assert.equal(classifyResponse(page, json(200, { rulesets: [bad] })).verdict, "unexpected", JSON.stringify(bad).slice(0, 80));
  assert.equal(classifyResponse(page, json(200, { rulesets: [{ ...storage, metadata: { services: Array.from({ length: 8 }, (_, n) => `s${n}`) } }] })).verdict, "accepted");
});

test("a source test answers accepted for no error, rejected for an error, unexpected otherwise", async () => {
  const { classifyResponse } = await load();
  const valid = manifest.rows.find((r) => r.family === "compile" && r.stage === "test");
  const issue = (severity) => ({ sourcePosition: { fileName: "storage.rules", line: 1, column: 2 }, description: "Unexpected token", severity });
  assert.deepEqual({ ...classifyResponse(valid, json(200, {})).facts }, { status: 200, issues: 0, errors: 0 });
  assert.equal(classifyResponse(valid, json(200, {})).verdict, "accepted");
  assert.equal(classifyResponse(valid, json(200, { issues: [issue("WARNING")] })).verdict, "accepted");
  const rejected = classifyResponse(valid, json(200, { issues: [issue("ERROR"), issue("WARNING")] }));
  assert.equal(rejected.verdict, "rejected");
  assert.deepEqual({ ...rejected.facts }, { status: 200, issues: 2, errors: 1 });
  const refused = classifyResponse(valid, json(400, { error: { code: 400, status: "INVALID_ARGUMENT", message: "bad rules" } }));
  assert.equal(refused.verdict, "rejected");
  assert.deepEqual({ ...refused.facts }, { status: 400, issues: 0, errors: 0 });
  for (const bad of [json(200, { issues: [{ severity: "FATAL", description: "x", sourcePosition: {} }] }), json(200, { issues: {} }), json(200, { extra: 1 }), json(200, { issues: [issue("ERROR")], testResults: [{ state: "SUCCESS" }], surprise: 1 }), json(403, { error: { code: 403, status: "PERMISSION_DENIED", message: "x" } }), json(400, { error: { code: 400, status: "OTHER", message: "x" } }), json(500, {}), response(200, "")]) {
    assert.equal(classifyResponse(valid, bad).verdict, "unexpected");
  }
});

test("no Rules API fact carries source text or a name beyond the reviewed fields", async () => {
  const { classifyResponse } = await load();
  const secretSource = "rules_version = '2'; // CANARY-SOURCE-TEXT";
  const created = classifyResponse(createRow, json(200, ruleset(secretSource)));
  assert.equal(created.verdict, "unexpected");
  const read = classifyResponse(row("ruleset/v1/read-source"), json(200, ruleset(secretSource)));
  assert.equal(JSON.stringify(read).includes("CANARY-SOURCE-TEXT"), false);
});

test("a Ruleset with a top-level field outside the published schema is unexpected", async () => {
  const { classifyResponse } = await load();
  assert.equal(classifyResponse(createRow, json(200, ruleset(sentContent))).verdict, "accepted");
  for (const r of [createRow, row("ruleset/v1/read-source")]) assert.equal(classifyResponse(r, json(200, ruleset(sentContent, { surprise: 1 }))).verdict, "unexpected");
});

test("an absence needs the HTTP status, error.code, error.status and a message to agree", async () => {
  const { classifyResponse } = await load();
  const read = row("ruleset/v1/read-source");
  const body = { error: { code: 404, message: "Requested entity was not found.", status: "NOT_FOUND" } };
  assert.equal(classifyResponse(read, json(404, body)).verdict, "absent");
  for (const bad of [json(200, body), json(403, body), json(500, body), json(404, { error: { code: 404, status: "NOT_FOUND" } }), json(404, { error: { code: 404, status: "NOT_FOUND", message: 7 } })]) {
    assert.equal(classifyResponse(read, bad).verdict, "unexpected");
  }
});

test("a Ruleset time must be a real time of day", async () => {
  const { classifyResponse } = await load();
  const read = row("ruleset/v1/read-source");
  for (const good of ["2026-09-29T00:00:00Z", "2026-09-29T23:59:59.999999999Z", "2026-09-29T19:00:00Z"]) assert.equal(classifyResponse(read, json(200, ruleset("x", { createTime: good }))).verdict, "present", good);
  for (const bad of ["2026-09-29T24:00:00Z", "2026-09-29T29:59:59Z", "2026-09-29T23:60:00Z", "2026-09-29T23:59:60Z"]) assert.equal(classifyResponse(read, json(200, ruleset("x", { createTime: bad }))).verdict, "unexpected", bad);
});
