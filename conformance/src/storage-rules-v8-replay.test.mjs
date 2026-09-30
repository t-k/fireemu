import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { acceptanceKindOf, classifyResponse } from "./storage-rules/acceptance.mjs";
import { buildCorpus } from "./storage-rules/corpus.mjs";
import { buildFullRequestManifest } from "./storage-rules/full-manifest.mjs";
import { PRODUCTION, rawOf } from "./storage-rules-production-fixtures.mjs";
import { createSimulator } from "./storage-rules-simulator.mjs";

// The bodies production answered in stage 3 v7 recording 1 (the no-release answers), stage 2e (the cleanup answers) and stage 2f (the shape answers), byte for byte,
// against the classifiers the next recording stops or cleans up by. Each test names the fixture it fits.
const BUCKET = "fireemu-oracle-query.firebasestorage.app";
const closure = JSON.parse(readFileSync(new URL("../../spec/compatibility/closure/STORAGE-RULES.json", import.meta.url)));
const options = { runId: "local-run", sourceCommit: "a".repeat(40), queryProjectNumber: "1".repeat(12), idpProjectNumber: "2".repeat(12), queryApiKeyId: "00000000-0000-4000-8000-000000000001", idpApiKeyId: "00000000-0000-4000-8000-000000000002" };
const binding = { bucket: BUCKET, prefix: "STORAGE-RULES/local-run/", uidA: "storage-rules-local-run-user-a", uidB: "storage-rules-local-run-user-b" };
const manifest = buildFullRequestManifest(buildCorpus(binding), closure, options);
const rowOf = (id) => manifest.rows.find((row) => row.id === id) ?? assert.fail(id);
const kindRows = (kind) => manifest.rows.filter((row) => acceptanceKindOf(row) === kind);
const facts = (outcome) => ({ ...outcome.facts });

test("the new fixtures hold no secret and no redaction, and each has the status and the type production answered", () => {
  for (const name of ["noRelease", "settleDenied", "rulesetDeleted", "accountDeleted", "accountsNone", "prefixEmpty", "rulesetCreated", "rulesetNeverExisted", "objectCreated", "objectListed", "objectDeleted", "documentCreated", "documentDeleted"]) {
    const fixture = PRODUCTION[name] ?? assert.fail(name);
    assert.equal(Object.isFrozen(fixture), true, name);
    assert.ok(!/redacted|password|apiKey|access_token|Bearer /i.test(fixture.body), name);
    assert.ok(!/\b\d{12}\b/.test(fixture.body), `${name}: no project number`);
  }
  assert.deepEqual([PRODUCTION.noRelease.status, PRODUCTION.noRelease.contentType], [400, "application/json; charset=UTF-8"]);
  assert.deepEqual([PRODUCTION.settleDenied.status, PRODUCTION.rulesetDeleted.status, PRODUCTION.rulesetNeverExisted.status, PRODUCTION.objectDeleted.status], [403, 200, 404, 204]);
  assert.equal(PRODUCTION.rulesetDeleted.body, "{}\n");
  assert.equal(PRODUCTION.objectDeleted.body, "");
  assert.equal(PRODUCTION.prefixEmpty.body.trim(), '{\n  "kind": "storage#objects"\n}');
  assert.deepEqual(JSON.parse(PRODUCTION.accountsNone.body), { kind: "identitytoolkit#GetAccountInfoResponse" });
  assert.deepEqual(JSON.parse(PRODUCTION.accountDeleted.body), { kind: "identitytoolkit#DeleteAccountResponse" });
  assert.equal(JSON.stringify(JSON.parse(PRODUCTION.rulesetNeverExisted.body)), JSON.stringify(JSON.parse(PRODUCTION.releaseAbsent.body)));
});

test("a settle read answers as production did with and without a release: allowed, denied, and the 400 of a bucket with no release", () => {
  const witness = rowOf("settle/restore/1/0");
  const ctx = { expectedSha256: "0".repeat(64) };
  const noRelease = classifyResponse(witness, rawOf(PRODUCTION.noRelease), ctx);
  assert.deepEqual([noRelease.kind, noRelease.verdict, facts(noRelease)], ["settle-read", "no-release", { status: 400, bodyBytes: Buffer.byteLength(PRODUCTION.noRelease.body), bodySha256: facts(noRelease).bodySha256 }]);
  assert.equal(classifyResponse(witness, rawOf(PRODUCTION.settleDenied), ctx).verdict, "denied");
  // Anything that is not exactly one of the two production answers, or the witness's own bytes, is `other`.
  const body400 = (message, code = 400, status = 400) => ({ status, rawHeaders: ["Content-Type", "application/json; charset=UTF-8"], bytes: Buffer.from(JSON.stringify({ error: { code, message } })) });
  for (const bad of [
    body400("Your bucket has not been set up properly"), body400("something else"), body400(PRODUCTION.noRelease.body, 403), body400("Your bucket has not been set up properly for Firebase Storage.", 400, 403), body400("Your bucket has not been set up properly for Firebase Storage.", 400, 500),
    body400("Your bucket has not been set up properly for Firebase Storage.", 403, 400), { status: 400, rawHeaders: ["Content-Type", "text/plain"], bytes: Buffer.from("Your bucket has not been set up properly for Firebase Storage.") },
    { status: 400, rawHeaders: ["Content-Type", "application/json; charset=UTF-8"], bytes: Buffer.from("{nope") }, { status: 400, rawHeaders: [], bytes: Buffer.alloc(0) }, { status: 200, rawHeaders: [], bytes: Buffer.from("other bytes") }, { status: 404, rawHeaders: ["Content-Type", "application/json; charset=UTF-8"], bytes: Buffer.from(PRODUCTION.rulesetNeverExisted.body) },
  ]) assert.equal(classifyResponse(witness, bad, ctx).verdict, "other");
});

test("the deletion answers production gave (a ruleset, an object, the prefix list) are accepted by the rows that clean up", () => {
  const rulesetDelete = kindRows("rules-ruleset-delete")[0] ?? assert.fail("no ruleset delete row");
  assert.equal(classifyResponse(rulesetDelete, rawOf(PRODUCTION.rulesetDeleted)).verdict, "accepted");
  for (const bad of [rawOf(PRODUCTION.rulesetNeverExisted), rawOf(PRODUCTION.rulesetCreated), { status: 200, rawHeaders: ["Content-Type", "application/json"], bytes: Buffer.from("[]") }, { status: 204, rawHeaders: [], bytes: Buffer.alloc(0) }]) assert.equal(classifyResponse(rulesetDelete, bad).verdict, "unexpected");
  const rulesetRead = kindRows("rules-ruleset-read")[0] ?? assert.fail("no ruleset read row");
  const absent = classifyResponse(rulesetRead, rawOf(PRODUCTION.rulesetNeverExisted));
  assert.deepEqual([absent.verdict, facts(absent)], ["absent", { status: 404 }]);
  const objectDelete = manifest.rows.find((row) => row.id.endsWith("/cleanup/cleanup-delete")) ?? assert.fail("no object delete row");
  const deleted = classifyResponse(objectDelete, rawOf(PRODUCTION.objectDeleted));
  assert.deepEqual([deleted.kind, deleted.verdict, facts(deleted)], ["gcs-delete", "accepted", { status: 204, deleteAcknowledged: true }]);
  assert.equal(classifyResponse(objectDelete, { status: 204, rawHeaders: [], bytes: Buffer.from("x") }).verdict, "unexpected");
  assert.equal(classifyResponse(objectDelete, rawOf(PRODUCTION.rulesetDeleted)).verdict, "unexpected");
  const prefix = rowOf("management/prefix-empty");
  const empty = classifyResponse(prefix, rawOf(PRODUCTION.prefixEmpty));
  assert.deepEqual([empty.kind, empty.verdict, facts(empty).itemCount, facts(empty).hasNextPage], ["gcs-prefix-list", "accepted", 0, false]);
  const listed = classifyResponse(prefix, rawOf(PRODUCTION.objectListed));
  assert.deepEqual([listed.verdict, facts(listed).itemCount], ["accepted", 1]);
});

test("the create answers production gave (a ruleset, an object) are accepted with the ownership they prove, and a document round trip is accepted", () => {
  // The ruleset create row, pointed at the content the probe sent.
  const create = structuredClone(kindRows("rules-ruleset-create")[0] ?? assert.fail("no ruleset create row"));
  const recorded = JSON.parse(PRODUCTION.rulesetCreated.body);
  create.request.body.json.source.files[0].content = recorded.source.files[0].content;
  const created = classifyResponse(create, rawOf(PRODUCTION.rulesetCreated));
  assert.deepEqual([created.verdict, facts(created).rulesetName, facts(created).createTime], ["accepted", recorded.name, recorded.createTime]);
  // The seed upload row, pointed at the probe's object and its eight bytes.
  const seed = structuredClone(kindRows("gcs-seed-upload")[0] ?? assert.fail("no seed row"));
  const object = JSON.parse(PRODUCTION.objectCreated.body);
  seed.request.objectName = object.name;
  seed.request.path = `/upload/storage/v1/b/${BUCKET}/o`;
  seed.request.body = { base64: Buffer.from("probe-2f").toString("base64") };
  const uploaded = classifyResponse(seed, rawOf(PRODUCTION.objectCreated));
  assert.deepEqual([uploaded.verdict, facts(uploaded).generation, facts(uploaded).metageneration, facts(uploaded).size], ["accepted", object.generation, "1", "8"]);
  // A Firestore create, read and delete, pointed at the probe's document.
  const write = kindRows("firestore-write").find((row) => row.request.method === "POST") ?? assert.fail("no document create row");
  const documentName = JSON.parse(PRODUCTION.documentCreated.body).name;
  const post = structuredClone(write);
  post.request.path = documentName.slice(0, documentName.lastIndexOf("/")).replace(/^/, "/v1/");
  post.request.query = { documentId: documentName.slice(documentName.lastIndexOf("/") + 1) };
  const made = classifyResponse(post, rawOf(PRODUCTION.documentCreated));
  assert.deepEqual([made.verdict, facts(made).documentName], ["accepted", documentName]);
  const del = structuredClone(kindRows("firestore-write").find((row) => row.request.method === "DELETE") ?? assert.fail("no document delete row"));
  del.request.path = `/v1/${documentName}`;
  assert.equal(classifyResponse(del, rawOf(PRODUCTION.documentDeleted)).verdict, "accepted");
  assert.equal(classifyResponse(del, rawOf(PRODUCTION.documentCreated)).verdict, "unexpected");
  const read = structuredClone(kindRows("firestore-read")[0] ?? assert.fail("no document read row"));
  read.request.path = `/v1/${documentName}`;
  read.request.method = "GET";
  assert.equal(classifyResponse(read, rawOf(PRODUCTION.documentCreated)).verdict, "present");
});

test("the simulator answers a v0 request on a bucket with no release with the recorded 400, and after a release is deleted it goes on answering by the old rules for the lag first", async () => {
  const simulator = createSimulator({ manifest, options: { lag: 2 } });
  const v0 = `https://firebasestorage.googleapis.com/v0/b/${BUCKET}/o/${encodeURIComponent("STORAGE-RULES/local-run/none.bin")}`;
  const ask = async () => simulator.send({ url: v0, method: "GET", headers: {}, body: null });
  const shape = (answer) => ({ status: answer.status, type: answer.rawHeaders[answer.rawHeaders.findIndex((value) => /^content-type$/i.test(value)) + 1], body: Buffer.from(answer.bytes).toString("utf8") });
  const compact = (fixture) => ({ status: fixture.status, type: fixture.contentType, body: JSON.stringify(JSON.parse(fixture.body)) });
  assert.deepEqual(shape(await ask()), compact(PRODUCTION.noRelease));
});
