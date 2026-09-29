import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { buildCorpus } from "./storage-rules/corpus.mjs";
import { buildFullRequestManifest } from "./storage-rules/full-manifest.mjs";
import { createTargetBuilder } from "./storage-rules/target.mjs";
import { ALL_IDS, IDS, MAX_REQUESTS, PREFLIGHT_IDS, PROBE_IDS, probeCorpus, probeList } from "./storage-rules-probe/plan.mjs";
import { compileSources, isBucket, PROBE_DOCUMENT, PROBE_OBJECT, probeRequests } from "./storage-rules-probe/probe.mjs";
import { createProbeTargets } from "./storage-rules-probe/targets.mjs";
import { BUCKET, ownerDigest } from "./storage-rules-probe-support.mjs";

const closure = JSON.parse(readFileSync(new URL("../../spec/compatibility/closure/STORAGE-RULES.json", import.meta.url)));
const binding = { bucket: BUCKET, prefix: "STORAGE-RULES/probe-2d/", uidA: "storage-rules-probe-2d-user-a", uidB: "storage-rules-probe-2d-user-b" };
const options = { runId: "probe-2d", sourceCommit: "a".repeat(40), queryProjectNumber: "1".repeat(12), idpProjectNumber: "2".repeat(12), queryApiKeyId: "00000000-0000-4000-8000-000000000001", idpApiKeyId: "00000000-0000-4000-8000-000000000002" };
const manifest = buildFullRequestManifest(buildCorpus(binding), closure, options);
const builder = createTargetBuilder({ manifest, digestSalt: "6".repeat(64) });
const stage3 = (id) => builder.prepare(manifest.rows.find((row) => row.id === id) ?? assert.fail(id), () => assert.fail("no reference expected")).spec;
const probe = (key) => probeRequests(BUCKET).find((entry) => entry.key === key) ?? assert.fail(key);
const bodyText = (spec) => (spec.body === null ? null : spec.body.toString("utf8"));

test("the plan is eight requests, two preflight and six probe reads, with unique IDs and no recovery", () => {
  assert.equal(MAX_REQUESTS, 8);
  assert.deepEqual(PREFLIGHT_IDS, ["preflight/auth/owner-token", "preflight/owner/identity"]);
  assert.deepEqual(PROBE_IDS, ["probe/rulesets-list", "probe/object-metadata-absent", "probe/object-media-absent", "probe/rules-test-valid", "probe/rules-test-invalid", "probe/document-absent"]);
  assert.deepEqual(ALL_IDS, [...PREFLIGHT_IDS, ...PROBE_IDS]);
  assert.equal(new Set(ALL_IDS).size, 8);
  assert.deepEqual(new Set(Object.values(IDS)), new Set(ALL_IDS));
  for (const id of PROBE_IDS) assert.ok(!id.startsWith("preflight/") && !id.startsWith("recovery/"), id);
  assert.equal(Object.isFrozen(IDS) && Object.isFrozen(PREFLIGHT_IDS) && Object.isFrozen(PROBE_IDS) && Object.isFrozen(ALL_IDS), true);
});

test("the probe reads are exactly the requests stage 3 builds for the same routes", () => {
  // The rulesets list and the two `:test` calls are byte for byte the stage 3 rows.
  const list = stage3("preflight/rulesets-list/entry/1");
  assert.deepEqual([probe("list").method, probe("list").url, bodyText(probe("list"))], [list.method, list.url, bodyText(list)]);
  const compile = manifest.rows.filter((row) => row.family === "compile" && row.stage === "test");
  const valid = stage3(compile[0].id);
  const invalid = stage3(compile.find((row) => row.id.includes("invalid")).id);
  assert.deepEqual([probe("testValid").method, probe("testValid").url, bodyText(probe("testValid"))], [valid.method, valid.url, bodyText(valid)]);
  assert.deepEqual([probe("testInvalid").method, probe("testInvalid").url, bodyText(probe("testInvalid"))], [invalid.method, invalid.url, bodyText(invalid)]);
  assert.notEqual(probe("testValid").body.toString(), probe("testInvalid").body.toString());
  // The object reads and the document read differ only in the name they ask for.
  const controlName = manifest.resources.controls[0];
  const metadata = stage3("management/control-0/baseline-metadata");
  const media = stage3("management/control-0/baseline-media");
  const sameShape = (mine, theirs, mineName, theirName) => mine.url === theirs.url.replace(encodeURIComponent(theirName), encodeURIComponent(mineName)) && mine.method === theirs.method && bodyText(mine) === bodyText(theirs);
  assert.equal(sameShape(probe("metadata"), metadata, PROBE_OBJECT, controlName), true);
  assert.equal(sameShape(probe("media"), media, PROBE_OBJECT, controlName), true);
  assert.ok(media.url.endsWith("?alt=media") && !metadata.url.includes("?"));
  const documentRow = manifest.rows.find((row) => row.service === "firestore" && row.request.method === "GET");
  const documentSpec = stage3(documentRow.id);
  const documentName = documentRow.request.documentName;
  assert.equal(probe("document").url, documentSpec.url.replace(documentName.slice(documentName.indexOf("STORAGE-RULES/")), PROBE_DOCUMENT));
  assert.equal(probe("document").method, "GET");
  // The headers stage 3 sends with each shape are the ones the probe sends (a JSON body gets its content type, a read gets none).
  const targets = createProbeTargets({ bucket: BUCKET, digestSalt: "s".repeat(64) });
  assert.deepEqual({ ...targets.prepare(IDS.testValid).spec.headers }, { ...valid.headers });
  assert.deepEqual({ ...targets.prepare(IDS.list).spec.headers }, { ...list.headers });
});

test("the probe names an object and a document no run creates, and the two Rules sources come from stage 3's compile program", () => {
  assert.equal(PROBE_OBJECT, "STORAGE-RULES/probe-2d/absent-object.bin");
  assert.equal(PROBE_DOCUMENT, "STORAGE-RULES/probe-2d-absent-document");
  const sources = compileSources(BUCKET);
  const program = buildCorpus({ bucket: BUCKET, prefix: "STORAGE-RULES/probe-2d/", uidA: "storage-rules-probe-2d-user-a", uidB: "storage-rules-probe-2d-user-b" }).managementPrograms.find((entry) => entry.id === "storage-service-compile");
  assert.equal(sources.valid, program.validSources[0].content);
  assert.equal(sources.invalid, program.invalidSource.content);
  assert.notEqual(sources.valid, sources.invalid);
  assert.equal(Object.isFrozen(sources), true);
  assert.throws(() => compileSources("Bad Bucket"), /invalid bucket/);
  assert.equal(probeRequests(BUCKET).length, 6);
  assert.equal(Object.isFrozen(probeRequests(BUCKET)) && probeRequests(BUCKET).every((entry) => Object.isFrozen(entry)), true);
  for (const bucket of [BUCKET, "abc", "a.b-c_d9", "x".repeat(222)]) assert.equal(isBucket(bucket), true, bucket);
  for (const bucket of ["", "ab", "Abc", "-abc", "a b", "a/b", "x".repeat(223), null, 5]) assert.equal(isBucket(bucket), false, String(bucket));
});

test("the corpus lists every request with its method, URL and body digest, and its digest moves with the bucket and the owner", () => {
  const corpus = probeCorpus({ bucket: BUCKET, ownerEmailSha256: ownerDigest });
  assert.deepEqual(corpus.list.map((entry) => entry.id), ALL_IDS);
  assert.equal(corpus.list.find((entry) => entry.id === IDS.token).method, "POST");
  assert.equal(corpus.list.find((entry) => entry.id === IDS.identity).url, "https://www.googleapis.com/oauth2/v2/userinfo");
  for (const entry of probeList(BUCKET)) {
    const listed = corpus.list.find((item) => item.id === entry.id);
    assert.deepEqual([listed.method, listed.url], [entry.method, entry.url]);
    assert.equal(listed.bodySha256 === null, entry.body === null);
  }
  const digests = new Set([corpus.sha256]);
  for (const changed of [{ bucket: "other-bucket.appspot.com" }, { ownerEmailSha256: "f".repeat(64) }]) digests.add(probeCorpus({ bucket: BUCKET, ownerEmailSha256: ownerDigest, ...changed }).sha256);
  assert.equal(digests.size, 3);
  assert.equal(probeCorpus({ bucket: BUCKET, ownerEmailSha256: ownerDigest }).sha256, corpus.sha256);
  for (const spoiled of [{ bucket: "Bad", ownerEmailSha256: ownerDigest }, { bucket: BUCKET, ownerEmailSha256: "abc" }, { bucket: BUCKET, ownerEmailSha256: 5 }, { bucket: BUCKET }]) assert.throws(() => probeCorpus(spoiled), /invalid corpus input/);
  assert.equal(MAX_REQUESTS, corpus.list.length);
});

test("targets are built from exact sources, verify accepts only what was issued, and a prepared request keeps its spec out of a serialization", () => {
  const targets = createProbeTargets({ bucket: BUCKET, digestSalt: "s".repeat(64) });
  const shape = (prepared) => ({ rowId: prepared.rowId, credential: prepared.credential, project: prepared.project, method: prepared.spec.method, url: prepared.spec.url, body: bodyText(prepared.spec) });
  assert.deepEqual(shape(targets.prepareIdentity("a")), { rowId: "a", credential: "admin", project: "fireemu-oracle-query", method: "GET", url: "https://www.googleapis.com/oauth2/v2/userinfo", body: null });
  for (const entry of probeList(BUCKET)) assert.deepEqual(shape(targets.prepare(entry.id)), { rowId: entry.id, credential: "admin", project: "fireemu-oracle-query", method: entry.method, url: entry.url, body: bodyText(entry) });
  for (const id of [IDS.token, IDS.identity, "probe/other", "", undefined]) assert.throws(() => targets.prepare(id), /not a probe request/);
  assert.throws(() => createProbeTargets({ bucket: "Bad Bucket", digestSalt: "s" }), /invalid bucket/);
  const read = targets.prepare(IDS.list);
  assert.equal(targets.verify(read), true);
  assert.equal(createProbeTargets({ bucket: "other-bucket.appspot.com", digestSalt: "s".repeat(64) }).verify(read), false);
  for (const value of [null, undefined, {}, { ...read }, JSON.parse(JSON.stringify(read))]) assert.equal(targets.verify(value), false);
  assert.deepEqual(Object.keys(read), ["rowId", "credential", "project", "redacted", "targetSha256"]);
  assert.equal(JSON.stringify(read).includes("\"spec\""), false);
  assert.equal(Object.isFrozen(read) && Object.isFrozen(read.spec) && Object.isFrozen(read.spec.headers), true);
  assert.notEqual(createProbeTargets({ bucket: BUCKET, digestSalt: "t".repeat(64) }).prepare(IDS.list).targetSha256, read.targetSha256);
  assert.notEqual(targets.prepare(IDS.metadata).targetSha256, targets.prepare(IDS.media).targetSha256);
  assert.equal(targets.prepare(IDS.list).targetSha256, read.targetSha256);
});
