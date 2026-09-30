import assert from "node:assert/strict";
import test from "node:test";
import { ALL_IDS, IDS, MAX_REQUESTS, MODES, PREFLIGHT_IDS, releaseCorpus } from "./storage-rules-release/plan.mjs";
import { BUCKETLESS_RELEASE_NAME, bucketReleaseName, canonicalDigest, classifyRelease, classifyRuleset, isBucket, isEmptyOk, isRulesetName, makeSaved, parseSaved, savedSha256 } from "./storage-rules-release/release.mjs";
import { createReleaseTargets } from "./storage-rules-release/targets.mjs";
import { BUCKET, OTHER_RULESET, RELEASE_NAME, RULESET, RULESET_SOURCE, SOURCE_SHA, ownerDigest, releaseBody } from "./storage-rules-release-support.mjs";

const raw = (body, status = 200, type = "application/json; charset=UTF-8") => ({ status, rawHeaders: ["Content-Type", type], bytes: Buffer.from(typeof body === "string" ? body : JSON.stringify(body)) });
const notFound = { error: { code: 404, message: "Requested entity was not found.", status: "NOT_FOUND" } };
const rulesetBody = { name: RULESET, createTime: "2026-09-25T10:29:00.111111Z", source: RULESET_SOURCE };

test("names: a bucket is a lower-case bucket name, a ruleset one of the query project's, and the release name follows the bucket", () => {
  for (const bucket of [BUCKET, "abc", "a.b-c_d9", "x".repeat(222)]) assert.equal(isBucket(bucket), true, bucket);
  for (const bucket of ["", "ab", "Abc", "-abc", "a b", "a/b", "x".repeat(223), null, 5]) assert.equal(isBucket(bucket), false, String(bucket));
  assert.equal(bucketReleaseName(BUCKET), RELEASE_NAME);
  assert.throws(() => bucketReleaseName("Bad Bucket"), /invalid bucket/);
  assert.equal(BUCKETLESS_RELEASE_NAME, "projects/fireemu-oracle-query/releases/firebase.storage");
  for (const name of [RULESET, "projects/fireemu-oracle-query/rulesets/a_b-C9", `projects/fireemu-oracle-query/rulesets/${"a".repeat(128)}`]) assert.equal(isRulesetName(name), true, name);
  for (const name of ["", "projects/other/rulesets/x", "projects/fireemu-oracle-query/rulesets/", "projects/fireemu-oracle-query/rulesets/a/b", `projects/fireemu-oracle-query/rulesets/${"a".repeat(129)}`, "projects/fireemu-oracle-query/rulesets/x y", null]) assert.equal(isRulesetName(name), false, String(name));
});

test("a release read is present with its ruleset and a digest of its body, absent on a Google 404, and unexpected on anything else", () => {
  const body = releaseBody();
  const present = classifyRelease(raw(body), RELEASE_NAME);
  assert.equal(present.state, "present");
  assert.deepEqual({ ...present.release, bodySha256: undefined }, { ...body, bodySha256: undefined });
  assert.equal(present.release.bodySha256, canonicalDigest(body));
  // The digest ignores the order of the keys and depends on every value.
  assert.equal(classifyRelease(raw({ updateTime: body.updateTime, createTime: body.createTime, rulesetName: body.rulesetName, name: body.name }), RELEASE_NAME).release.bodySha256, present.release.bodySha256);
  assert.notEqual(classifyRelease(raw(releaseBody(OTHER_RULESET)), RELEASE_NAME).release.bodySha256, present.release.bodySha256);
  assert.equal(classifyRelease(raw(notFound, 404), RELEASE_NAME).state, "absent");
  assert.equal(Object.isFrozen(present) && Object.isFrozen(present.release), true);
  for (const [name, answer] of Object.entries({
    "extra field": raw({ ...body, extra: 1 }), "another name": raw({ ...body, name: `${RELEASE_NAME}x` }), "missing ruleset": raw({ name: body.name, createTime: body.createTime, updateTime: body.updateTime }),
    "ruleset of another project": raw({ ...body, rulesetName: "projects/other/rulesets/x" }), "bad create time": raw({ ...body, createTime: "yesterday" }), "bad update time": raw({ ...body, updateTime: "2026-02-30T00:00:00Z" }),
    "not JSON": raw("<html>"), "an array": raw([body]), "wrong content type": raw(body, 200, "text/plain"), "404 without the Google error": raw({ message: "nope" }, 404),
    "404 with another status": raw({ error: { code: 404, message: "x", status: "OTHER" } }, 404), "403": raw({ error: { code: 403, message: "no", status: "PERMISSION_DENIED" } }, 403), "500": raw(notFound, 500),
    "a 200 with the empty object": raw({}), "a 204": raw("", 204),
  })) assert.equal(classifyRelease(answer, RELEASE_NAME).state, "unexpected", name);
  // A raw response that is not in the transport's shape is unexpected, never an exception.
  for (const shape of [null, undefined, {}, { status: 200 }, { ...raw(body), extra: 1 }, { ...raw(body), bytes: "text" }, { ...raw(body), status: 99 }]) assert.equal(classifyRelease(shape, RELEASE_NAME).state, "unexpected");
  // The name of the answer must be the one asked for: the bucketless name is not the bucket's.
  assert.equal(classifyRelease(raw({ ...body, name: BUCKETLESS_RELEASE_NAME }), RELEASE_NAME).state, "unexpected");
  assert.equal(classifyRelease(raw({ ...body, name: BUCKETLESS_RELEASE_NAME }), BUCKETLESS_RELEASE_NAME).state, "present");
});

test("a ruleset read is present with a digest of its source, never the source, absent on a Google 404, and unexpected on anything else", () => {
  const present = classifyRuleset(raw(rulesetBody), RULESET);
  assert.equal(present.state, "present");
  assert.deepEqual(present.ruleset, { name: RULESET, createTime: rulesetBody.createTime, sourceSha256: SOURCE_SHA });
  assert.equal(JSON.stringify(present).includes("rules_version"), false);
  assert.equal(classifyRuleset(raw({ ...rulesetBody, metadata: { services: [] } }), RULESET).state, "present");
  assert.notEqual(classifyRuleset(raw({ ...rulesetBody, source: { files: [{ name: "storage.rules", content: "changed" }] } }), RULESET).ruleset.sourceSha256, SOURCE_SHA);
  assert.equal(classifyRuleset(raw(notFound, 404), RULESET).state, "absent");
  for (const [name, answer] of Object.entries({
    "extra field": raw({ ...rulesetBody, extra: 1 }), "another name": raw({ ...rulesetBody, name: OTHER_RULESET }), "no source": raw({ name: RULESET, createTime: rulesetBody.createTime }), "source not an object": raw({ ...rulesetBody, source: "text" }),
    "bad create time": raw({ ...rulesetBody, createTime: "x" }), "not JSON": raw("x"), "403": raw({ error: { code: 403, message: "no", status: "PERMISSION_DENIED" } }, 403), "404 without the Google error": raw({}, 404),
  })) assert.equal(classifyRuleset(answer, RULESET).state, "unexpected", name);
  assert.equal(classifyRuleset(null, RULESET).state, "unexpected");
  assert.equal(classifyRuleset(raw({ ...rulesetBody, name: "projects/other/rulesets/x" }), "projects/other/rulesets/x").state, "unexpected");
});

test("a deletion is accepted only as a 200 with the empty object", () => {
  assert.equal(isEmptyOk(raw({})), true);
  for (const answer of [raw({ a: 1 }), raw([]), raw({}, 204), raw({}, 404), raw("", 200), raw({}, 200, "text/plain"), null, {}]) assert.equal(isEmptyOk(answer), false);
});

test("the saved record is closed, tied to its bucket, and its digest is stable", () => {
  const release = { ...releaseBody(), bodySha256: canonicalDigest(releaseBody()) };
  const saved = makeSaved({ bucket: BUCKET, release, ruleset: { sourceSha256: SOURCE_SHA } });
  assert.deepEqual(saved, { schemaVersion: 1, bucket: BUCKET, name: RELEASE_NAME, rulesetName: RULESET, createTime: release.createTime, updateTime: release.updateTime, releaseBodySha256: release.bodySha256, rulesetSourceSha256: SOURCE_SHA });
  assert.equal(Object.isFrozen(saved), true);
  assert.equal(savedSha256(saved), savedSha256(JSON.parse(JSON.stringify(saved))));
  assert.equal(savedSha256(saved), savedSha256(Object.fromEntries(Object.entries(saved).reverse())));
  for (const key of Object.keys(saved)) {
    assert.throws(() => parseSaved({ ...saved, [key]: key === "schemaVersion" ? 2 : "x" }), /invalid saved release/, key);
    const { [key]: removed, ...without } = saved;
    assert.throws(() => parseSaved(without), /invalid saved release/, key);
  }
  for (const spoiled of [{ ...saved, extra: 1 }, { ...saved, name: `${RELEASE_NAME}x` }, { ...saved, bucket: "Bad" }, { ...saved, rulesetName: "projects/other/rulesets/x" }, { ...saved, releaseBodySha256: "abc" }, { ...saved, rulesetSourceSha256: "G".repeat(64) }, { ...saved, createTime: "x" }, null, [], "text", Object.create({ ...saved })]) {
    assert.throws(() => parseSaved(spoiled), /invalid saved release/);
  }
  assert.notEqual(savedSha256(makeSaved({ bucket: BUCKET, release: { ...release, rulesetName: OTHER_RULESET }, ruleset: { sourceSha256: SOURCE_SHA } })), savedSha256(saved));
  assert.notEqual(savedSha256(makeSaved({ bucket: BUCKET, release, ruleset: { sourceSha256: "e".repeat(64) } })), savedSha256(saved));
});

test("the plan: eleven requests at most for pre, eight for post, five preflight reads first, and ids that name their mode", () => {
  assert.deepEqual(MODES, ["pre", "post"]);
  assert.deepEqual(MAX_REQUESTS, { pre: 11, post: 8 });
  assert.equal(ALL_IDS.pre.length, 11);
  assert.equal(ALL_IDS.post.length, 8);
  assert.deepEqual(PREFLIGHT_IDS, ["preflight/auth/owner-token", "preflight/owner/identity", "preflight/ruleset/saved", "preflight/release/bucket", "preflight/release/bucketless"]);
  for (const mode of MODES) {
    assert.deepEqual(ALL_IDS[mode].slice(0, 5), PREFLIGHT_IDS);
    assert.equal(new Set(ALL_IDS[mode]).size, ALL_IDS[mode].length);
    assert.deepEqual(new Set(ALL_IDS[mode]), new Set(Object.values(IDS[mode])));
    for (const id of ALL_IDS[mode].slice(5)) assert.ok(!id.startsWith("preflight/"), id);
  }
  assert.deepEqual(ALL_IDS.pre.slice(5, 8), ["release/bucket/delete", "release/bucket/absence", "release/bucketless/absence"]);
  assert.deepEqual(ALL_IDS.pre.slice(8), ["recovery/release/bucket/current", "recovery/release/bucket/restore", "recovery/release/bucket/after"]);
  assert.deepEqual(ALL_IDS.post.slice(5), ["release/bucket/create", "release/bucket/after", "recovery/release/bucket/current"]);
  assert.equal(Object.isFrozen(IDS) && Object.isFrozen(IDS.pre) && Object.isFrozen(ALL_IDS) && Object.isFrozen(ALL_IDS.pre), true);
});

test("the corpus lists every request with its method, URL and body, and its digest moves with every input", () => {
  const base = { bucket: BUCKET, rulesetName: RULESET, ownerEmailSha256: ownerDigest };
  const pre = releaseCorpus({ mode: "pre", ...base });
  const post = releaseCorpus({ mode: "post", ...base, savedSha256: "5".repeat(64) });
  assert.deepEqual(pre.list.map((entry) => entry.id), ALL_IDS.pre);
  assert.deepEqual(post.list.map((entry) => entry.id), ALL_IDS.post);
  const at = (corpus, id) => corpus.list.find((entry) => entry.id === id);
  const releaseUrl = `https://firebaserules.googleapis.com/v1/${RELEASE_NAME}`;
  assert.deepEqual(at(pre, IDS.pre.remove), { id: IDS.pre.remove, method: "DELETE", url: releaseUrl });
  assert.deepEqual(at(pre, IDS.pre.restore), { id: IDS.pre.restore, method: "POST", url: "https://firebaserules.googleapis.com/v1/projects/fireemu-oracle-query/releases", body: { name: RELEASE_NAME, rulesetName: RULESET } });
  assert.deepEqual(at(post, IDS.post.create), { id: IDS.post.create, method: "POST", url: "https://firebaserules.googleapis.com/v1/projects/fireemu-oracle-query/releases", body: { name: RELEASE_NAME, rulesetName: RULESET } });
  assert.equal(at(pre, IDS.pre.bucketless).url, "https://firebaserules.googleapis.com/v1/projects/fireemu-oracle-query/releases/firebase.storage");
  assert.equal(at(pre, IDS.pre.ruleset).url, `https://firebaserules.googleapis.com/v1/${RULESET}`);
  assert.equal(at(pre, IDS.pre.identity).url, "https://www.googleapis.com/oauth2/v2/userinfo");
  assert.equal(at(pre, IDS.pre.token).method, "POST");
  for (const id of [IDS.pre.current, IDS.pre.restored, IDS.pre.absence, IDS.pre.bucket]) assert.deepEqual(at(pre, id), { id, method: "GET", url: releaseUrl });
  const digests = new Set([pre.sha256, post.sha256]);
  for (const changed of [{ bucket: "other-bucket.appspot.com" }, { rulesetName: OTHER_RULESET }, { ownerEmailSha256: "f".repeat(64) }]) {
    digests.add(releaseCorpus({ mode: "pre", ...base, ...changed }).sha256);
    digests.add(releaseCorpus({ mode: "post", ...base, ...changed, savedSha256: "5".repeat(64) }).sha256);
  }
  digests.add(releaseCorpus({ mode: "post", ...base, savedSha256: "6".repeat(64) }).sha256);
  assert.equal(digests.size, 9);
  assert.equal(releaseCorpus({ mode: "pre", ...base }).sha256, pre.sha256);
  for (const spoiled of [{ mode: "both", ...base }, { mode: "pre", ...base, bucket: "Bad" }, { mode: "pre", ...base, rulesetName: "x" }, { mode: "pre", ...base, ownerEmailSha256: "abc" }, { mode: "pre", ...base, savedSha256: "5".repeat(64) }, { mode: "post", ...base }, { mode: "post", ...base, savedSha256: "abc" }]) {
    assert.throws(() => releaseCorpus(spoiled), /invalid corpus input/);
  }
});

test("targets are built from exact sources: reads name a fixed resource, the deletion and the publication come only from a saved record of this bucket, and verify accepts only what was issued", () => {
  const targets = createReleaseTargets({ bucket: BUCKET, digestSalt: "s".repeat(64) });
  const saved = makeSaved({ bucket: BUCKET, release: { ...releaseBody(), bodySha256: canonicalDigest(releaseBody()) }, ruleset: { sourceSha256: SOURCE_SHA } });
  const shape = (prepared) => ({ rowId: prepared.rowId, credential: prepared.credential, project: prepared.project, method: prepared.spec.method, url: prepared.spec.url, headers: prepared.spec.headers, body: prepared.spec.body === null ? null : prepared.spec.body.toString("utf8") });
  assert.deepEqual(shape(targets.prepareIdentity("a")), { rowId: "a", credential: "admin", project: "fireemu-oracle-query", method: "GET", url: "https://www.googleapis.com/oauth2/v2/userinfo", headers: {}, body: null });
  assert.deepEqual(shape(targets.prepareRulesetRead("b", RULESET)), { rowId: "b", credential: "admin", project: "fireemu-oracle-query", method: "GET", url: `https://firebaserules.googleapis.com/v1/${RULESET}`, headers: {}, body: null });
  assert.equal(shape(targets.prepareBucketRead("c")).url, `https://firebaserules.googleapis.com/v1/${RELEASE_NAME}`);
  assert.equal(shape(targets.prepareBucketlessRead("d")).url, "https://firebaserules.googleapis.com/v1/projects/fireemu-oracle-query/releases/firebase.storage");
  assert.deepEqual(shape(targets.prepareDelete("e", saved)), { rowId: "e", credential: "admin", project: "fireemu-oracle-query", method: "DELETE", url: `https://firebaserules.googleapis.com/v1/${RELEASE_NAME}`, headers: {}, body: null });
  assert.deepEqual(shape(targets.preparePublish("f", saved)), { rowId: "f", credential: "admin", project: "fireemu-oracle-query", method: "POST", url: "https://firebaserules.googleapis.com/v1/projects/fireemu-oracle-query/releases", headers: { "content-type": "application/json; charset=utf-8" }, body: JSON.stringify({ name: RELEASE_NAME, rulesetName: RULESET }) });
  assert.equal(targets.releaseName, RELEASE_NAME);
  const other = createReleaseTargets({ bucket: "other-bucket.appspot.com", digestSalt: "s".repeat(64) });
  for (const method of ["prepareDelete", "preparePublish"]) {
    assert.throws(() => other[method]("x", saved), /not this bucket's/);
    assert.throws(() => targets[method]("x", { ...saved, extra: 1 }), /invalid saved release/);
    assert.throws(() => targets[method]("x", { ...saved, rulesetName: "nope" }), /invalid saved release/);
  }
  assert.throws(() => createReleaseTargets({ bucket: "Bad Bucket", digestSalt: "s" }), /invalid bucket/);
  const read = targets.prepareBucketRead("g");
  assert.equal(targets.verify(read), true);
  assert.equal(other.verify(read), false);
  for (const value of [null, undefined, {}, { ...read }, JSON.parse(JSON.stringify(read))]) assert.equal(targets.verify(value), false);
  assert.equal(Object.isFrozen(read) && Object.isFrozen(read.spec) && Object.isFrozen(read.spec.headers), true);
  // The digest binds the salt, the row and the request: the same request under another salt or row differs.
  const again = createReleaseTargets({ bucket: BUCKET, digestSalt: "t".repeat(64) });
  assert.notEqual(again.prepareBucketRead("g").targetSha256, read.targetSha256);
  assert.notEqual(targets.prepareBucketRead("h").targetSha256, read.targetSha256);
  assert.equal(targets.prepareBucketRead("g").targetSha256, read.targetSha256);
  assert.notEqual(targets.prepareDelete("g", saved).targetSha256, read.targetSha256);
  assert.equal(read.spec.body, null);
  // The request itself never shows in a serialization of the prepared target: the spec is not an enumerable property.
  assert.deepEqual(Object.keys(read), ["rowId", "credential", "project", "redacted", "targetSha256"]);
  assert.equal(JSON.stringify(read).includes("\"spec\""), false);
  assert.equal(Object.getOwnPropertyDescriptor(read, "spec").enumerable, false);
  assert.equal(read.redacted, `GET https://firebaserules.googleapis.com/v1/${RELEASE_NAME}`);
});
