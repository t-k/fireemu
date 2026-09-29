import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { classifyResponse } from "./storage-rules/acceptance.mjs";
import { buildCorpus } from "./storage-rules/corpus.mjs";
import { buildFullRequestManifest } from "./storage-rules/full-manifest.mjs";
import { ENTRY_RULESETS } from "./storage-rules/preflight-judge.mjs";
import { PRODUCTION, rawOf } from "./storage-rules-production-fixtures.mjs";
import { createSimulator } from "./storage-rules-simulator.mjs";

// Stage 3's classifiers against the bodies production actually returned (recorded by stage 2d and stage 2c-pre), byte for byte, and the simulator
// against the same bodies: the simulator's answers must have the production shape, so a whole-recording test cannot pass on an answer written to fit a classifier.
const BUCKET = "fireemu-oracle-query.firebasestorage.app";
const OBJECT = "STORAGE-RULES/probe-2d/absent-object.bin";
const closure = JSON.parse(readFileSync(new URL("../../spec/compatibility/closure/STORAGE-RULES.json", import.meta.url)));
const options = { runId: "probe-2d", sourceCommit: "a".repeat(40), queryProjectNumber: "1".repeat(12), idpProjectNumber: "2".repeat(12), queryApiKeyId: "00000000-0000-4000-8000-000000000001", idpApiKeyId: "00000000-0000-4000-8000-000000000002" };
const binding = { bucket: BUCKET, prefix: "STORAGE-RULES/probe-2d/", uidA: "storage-rules-probe-2d-user-a", uidB: "storage-rules-probe-2d-user-b" };
const manifest = buildFullRequestManifest(buildCorpus(binding), closure, options);
const rowOf = (id) => manifest.rows.find((row) => row.id === id) ?? assert.fail(id);
// The two object rows, pointed at the object the probe asked for (the answers name the object of the request).
const objectRow = (id) => { const row = structuredClone(rowOf(id)); row.request.objectName = OBJECT; row.request.path = `/storage/v1/b/${BUCKET}/o/${encodeURIComponent(OBJECT)}`; return row; };
const compile = manifest.rows.filter((row) => row.family === "compile" && row.stage === "test");
const documentRow = manifest.rows.find((row) => row.service === "firestore" && row.request.method === "GET");
const facts = (outcome) => ({ ...outcome.facts });

test("the recorded production bodies are exactly what the fixtures hold: no secret, no redaction, and the shapes production is known to use", () => {
  assert.deepEqual(Object.keys(PRODUCTION), ["rulesetList", "objectMetadataAbsent", "objectMediaAbsent", "rulesTestValid", "rulesTestInvalid", "documentAbsent", "releaseAbsent", "releaseBucketlessAbsent", "releasePresent"]);
  for (const fixture of Object.values(PRODUCTION)) {
    assert.equal(Object.isFrozen(fixture), true);
    assert.ok(!/redacted|password|apiKey|access_token|Bearer /i.test(fixture.body));
    assert.ok(!/\b\d{12}\b/.test(fixture.body), "no project number");
  }
  assert.equal(PRODUCTION.objectMediaAbsent.contentType, "text/html; charset=UTF-8");
  assert.equal(PRODUCTION.objectMediaAbsent.body, `No such object: ${BUCKET}/${OBJECT}`);
  assert.equal(PRODUCTION.objectMetadataAbsent.contentType, "application/json; charset=UTF-8");
  assert.equal(PRODUCTION.rulesTestValid.body.trim(), "{}");
  assert.equal(JSON.parse(PRODUCTION.rulesTestInvalid.body).issues[0].severity, "ERROR");
});

test("the Rulesets list production returned is accepted, with both entries' services, and it is the entry list the judge expects", () => {
  const outcome = classifyResponse(rowOf("preflight/rulesets-list/entry/1"), rawOf(PRODUCTION.rulesetList));
  assert.equal(outcome.verdict, "accepted");
  assert.deepEqual(facts(outcome), { status: 200, count: 2, hasNextPage: false, rulesets: ENTRY_RULESETS.map((entry) => ({ name: entry.name, services: [...entry.services] })) });
  for (const page of [1, 2, 10]) assert.equal(classifyResponse(rowOf(`rulesets-list/final/${page}`), rawOf(PRODUCTION.rulesetList)).verdict, "accepted");
});

test("an absent object is a JSON 404 for its metadata and a plain sentence for its media, and both are classified absent", () => {
  assert.deepEqual(facts(classifyResponse(objectRow("management/control-0/baseline-metadata"), rawOf(PRODUCTION.objectMetadataAbsent))), { status: 404 });
  assert.equal(classifyResponse(objectRow("management/control-0/baseline-metadata"), rawOf(PRODUCTION.objectMetadataAbsent)).verdict, "absent");
  assert.deepEqual(facts(classifyResponse(objectRow("management/control-0/baseline-media"), rawOf(PRODUCTION.objectMediaAbsent))), { status: 404 });
  assert.equal(classifyResponse(objectRow("management/control-0/baseline-media"), rawOf(PRODUCTION.objectMediaAbsent)).verdict, "absent");
  // The two are not interchangeable: the media answer is not a metadata absence, and the metadata answer is not a media absence.
  assert.equal(classifyResponse(objectRow("management/control-0/baseline-metadata"), rawOf(PRODUCTION.objectMediaAbsent)).verdict, "unexpected");
  assert.equal(classifyResponse(objectRow("management/control-0/baseline-media"), rawOf(PRODUCTION.objectMetadataAbsent)).verdict, "unexpected");
  // Every absence read the schedule declares for a media download takes the same classifier.
  for (const row of manifest.rows.filter((entry) => entry.request.operation === "get-media" && entry.request.dialect === "gcs" && entry.request.credential === "admin").slice(0, 25)) {
    const fitted = structuredClone(row);
    fitted.request.objectName = OBJECT;
    fitted.request.path = `/storage/v1/b/${BUCKET}/o/${encodeURIComponent(OBJECT)}`;
    assert.equal(classifyResponse(fitted, rawOf(PRODUCTION.objectMediaAbsent)).verdict, "absent", row.id);
  }
});

test("a valid source is accepted by the Rules test and an invalid one is rejected by a 200 answer with issues, as production answers", () => {
  const valid = classifyResponse(compile.find((row) => !row.id.includes("invalid")), rawOf(PRODUCTION.rulesTestValid));
  assert.equal(valid.verdict, "accepted");
  assert.deepEqual(facts(valid), { status: 200, issues: 0, errors: 0 });
  const invalid = classifyResponse(compile.find((row) => row.id.includes("invalid")), rawOf(PRODUCTION.rulesTestInvalid));
  assert.equal(invalid.verdict, "rejected");
  assert.deepEqual(facts(invalid), { status: 200, issues: 1, errors: 1 });
});

test("an absent document is a Firestore NOT_FOUND, and the two release reads production answered are classified as the entry expects", () => {
  const document = classifyResponse(documentRow, rawOf(PRODUCTION.documentAbsent));
  assert.equal(document.verdict, "absent");
  assert.deepEqual(facts(document), { status: 404 });
  for (const [id, fixture] of [["preflight/release/entry/bucket", PRODUCTION.releaseAbsent], ["preflight/release/entry/bucketless", PRODUCTION.releaseBucketlessAbsent]]) {
    const outcome = classifyResponse(rowOf(id), rawOf(fixture));
    assert.deepEqual([outcome.kind, outcome.verdict, facts(outcome)], ["rules-release-read", "absent", { status: 404 }]);
  }
  const present = classifyResponse(rowOf("release/v1/before"), rawOf(PRODUCTION.releasePresent));
  assert.equal(present.verdict, "present");
  assert.deepEqual(Object.keys(facts(present)).sort(), ["releaseName", "rulesetName", "status", "updateTime"]);
});

test("the simulator answers the same requests with the production shapes", () => {
  const simulator = createSimulator({ manifest, options: {} });
  const send = (method, url) => simulator.send({ url, method, headers: {}, body: null });
  const object = `https://storage.googleapis.com/storage/v1/b/${BUCKET}/o/${encodeURIComponent(OBJECT)}`;
  const shape = (answer) => ({ status: answer.status, type: answer.rawHeaders[answer.rawHeaders.findIndex((value) => /^content-type$/i.test(value)) + 1], body: Buffer.from(answer.bytes).toString("utf8") });
  // Object reads: identical to production, byte for byte (the bucket and the object are the same names).
  return Promise.all([send("GET", object), send("GET", `${object}?alt=media`), send("GET", `https://firestore.googleapis.com/v1/projects/fireemu-oracle-query/databases/(default)/documents/STORAGE-RULES/probe-2d-absent-document`)]).then(([metadata, media, document]) => {
    const compact = (fixture) => ({ status: fixture.status, type: fixture.contentType, body: JSON.stringify(JSON.parse(fixture.body)) });
    assert.deepEqual(shape(metadata), compact(PRODUCTION.objectMetadataAbsent));
    assert.deepEqual(shape(media), { status: 404, type: PRODUCTION.objectMediaAbsent.contentType, body: PRODUCTION.objectMediaAbsent.body });
    assert.deepEqual(shape(document), compact(PRODUCTION.documentAbsent));
  });
});

test("the simulator's Rulesets list has production's entry shape: the two known rulesets, each with services", async () => {
  const simulator = createSimulator({ manifest, options: {} });
  const answer = await simulator.send({ url: "https://firebaserules.googleapis.com/v1/projects/fireemu-oracle-query/rulesets?pageSize=100", method: "GET", headers: {}, body: null });
  const listed = JSON.parse(Buffer.from(answer.bytes).toString("utf8")).rulesets;
  const recorded = JSON.parse(PRODUCTION.rulesetList.body).rulesets;
  assert.deepEqual(listed.map((entry) => [entry.name, entry.metadata]), recorded.map((entry) => [entry.name, entry.metadata]));
  assert.deepEqual(listed.map((entry) => Object.keys(entry).sort()), recorded.map((entry) => Object.keys(entry).sort()));
});
