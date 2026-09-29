import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, link, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { join, relative } from "node:path";
import test from "node:test";

// The explicitly named private packet of expected values (identity, projects, keys, bucket, database, policy baselines).
// The synthetic values below are fixtures; nothing here is a real sandbox value.
const sha = (value) => createHash("sha256").update(value).digest("hex");
const good = () => ({
  schemaVersion: 1,
  adcPath: "/private/adc/application_default_credentials.json",
  owner: { emailSha256: sha("owner@example.test"), subjectSha256: sha("owner-subject") },
  projects: {
    query: { projectId: "fireemu-oracle-query", projectNumber: "111111111111", apiKeyId: "fireemu-query-auth-20260925", apiKey: "Q".repeat(39), keyUid: "query-key-uid", apiTargets: ["identitytoolkit.googleapis.com", "securetoken.googleapis.com"], restrictionsSha256: sha("query-restrictions") },
    idp: { projectId: "fireemu-oracle-idp", projectNumber: "222222222222", apiKeyId: "00000000-0000-4000-8000-000000000002", apiKey: "I".repeat(39), keyUid: "idp-key-uid", apiTargets: ["identitytoolkit.googleapis.com", "securetoken.googleapis.com"], restrictionsSha256: sha("idp-restrictions") },
  },
  bucket: { name: "synthetic-rules-bucket", location: "US-CENTRAL1", uniformBucketLevelAccess: true, iamPolicySha256: sha("bucket-policy") },
  database: { locationId: "us-central1", type: "FIRESTORE_NATIVE" },
  queryProjectIamPolicySha256: sha("project-policy"),
});
const load = async () => {
  const module = await import("./storage-rules/private-inputs.mjs").catch((error) => { if (error.code === "ERR_MODULE_NOT_FOUND") return {}; throw error; });
  assert.equal(typeof module.parsePrivateInputs, "function");
  return module;
};

test("a complete private packet parses into a frozen record whose secrets are not enumerable", async () => {
  const { parsePrivateInputs } = await load();
  const inputs = parsePrivateInputs(good());
  assert.equal(Object.isFrozen(inputs), true);
  assert.equal(inputs.projects.query.projectNumber, "111111111111");
  assert.equal(inputs.projects.idp.keyUid, "idp-key-uid");
  assert.equal(inputs.bucket.name, "synthetic-rules-bucket");
  assert.equal(inputs.secrets.apiKeys.query, "Q".repeat(39));
  assert.equal(inputs.secrets.apiKeys.idp, "I".repeat(39));
  // The keys never appear when the record is serialised or listed.
  assert.equal(JSON.stringify(inputs).includes("Q".repeat(39)), false);
  assert.equal(Object.keys(inputs).includes("secrets"), false);
  assert.equal(Object.values(inputs.projects.query).includes("Q".repeat(39)), false);
});

test("the packet is a closed record: unknown, missing and mistyped fields are refused", async () => {
  const { parsePrivateInputs } = await load();
  const mutate = (fn) => { const value = good(); fn(value); return value; };
  const bad = {
    "not an object": null, "array": [], "extra top": mutate((v) => { v.extra = 1; }), "wrong version": mutate((v) => { v.schemaVersion = 2; }),
    "relative adc path": mutate((v) => { v.adcPath = "adc.json"; }), "adc path with NUL": mutate((v) => { v.adcPath = "/a\0b"; }), "adc path too long": mutate((v) => { v.adcPath = `/${"a".repeat(1100)}`; }),
    "owner extra": mutate((v) => { v.owner.email = "owner@example.test"; }), "owner digest upper": mutate((v) => { v.owner.emailSha256 = v.owner.emailSha256.toUpperCase(); }), "owner digest short": mutate((v) => { v.owner.subjectSha256 = "ab"; }),
    "project missing": mutate((v) => { delete v.projects.idp; }), "project extra": mutate((v) => { v.projects.other = v.projects.query; }),
    "wrong project id": mutate((v) => { v.projects.query.projectId = "fireemu-oracle-idp"; }), "zero project number": mutate((v) => { v.projects.query.projectNumber = "0123"; }), "project number not a string": mutate((v) => { v.projects.query.projectNumber = 111111111111; }),
    "same numbers": mutate((v) => { v.projects.idp.projectNumber = v.projects.query.projectNumber; }), "same key ids": mutate((v) => { v.projects.idp.apiKeyId = v.projects.query.apiKeyId; }), "same api keys": mutate((v) => { v.projects.idp.apiKey = v.projects.query.apiKey; }),
    "key id upper uuid": mutate((v) => { v.projects.query.apiKeyId = "0000000A-0000-4000-8000-00000000000A"; }), "key id upper custom": mutate((v) => { v.projects.query.apiKeyId = "Fireemu-query"; }), "key id digit first": mutate((v) => { v.projects.query.apiKeyId = "1abc"; }),
    "key id underscore": mutate((v) => { v.projects.query.apiKeyId = "a_b"; }), "key id 64 chars": mutate((v) => { v.projects.query.apiKeyId = `a${"b".repeat(63)}`; }), "key id empty": mutate((v) => { v.projects.query.apiKeyId = ""; }), "key id slash": mutate((v) => { v.projects.query.apiKeyId = "a/b"; }), "key id dot": mutate((v) => { v.projects.query.apiKeyId = "a.b"; }), "key id not a string": mutate((v) => { v.projects.query.apiKeyId = 5; }),
    "restriction digest missing": mutate((v) => { delete v.projects.query.restrictionsSha256; }), "restriction digest short": mutate((v) => { v.projects.query.restrictionsSha256 = "ab"; }), "restriction digest upper": mutate((v) => { v.projects.idp.restrictionsSha256 = v.projects.idp.restrictionsSha256.toUpperCase(); }), "restriction digest not a string": mutate((v) => { v.projects.idp.restrictionsSha256 = 5; }),
    "no identitytoolkit": mutate((v) => { v.projects.query.apiTargets = ["securetoken.googleapis.com"]; }), "no securetoken": mutate((v) => { v.projects.idp.apiTargets = ["identitytoolkit.googleapis.com"]; }), "no targets": mutate((v) => { v.projects.query.apiTargets = []; }), "targets without the services": mutate((v) => { v.projects.idp.apiTargets = ["a.googleapis.com", "b.googleapis.com"]; }),
    "api key short": mutate((v) => { v.projects.query.apiKey = "short"; }), "api key with space": mutate((v) => { v.projects.query.apiKey = `${"Q".repeat(20)} ${"Q".repeat(20)}`; }), "api key long": mutate((v) => { v.projects.query.apiKey = "Q".repeat(129); }),
    "key uid empty": mutate((v) => { v.projects.query.keyUid = ""; }), "key uid control": mutate((v) => { v.projects.query.keyUid = "a\nb"; }), "key uid long": mutate((v) => { v.projects.query.keyUid = "u".repeat(129); }),
    "targets unsorted": mutate((v) => { v.projects.query.apiTargets = ["b.googleapis.com", "a.googleapis.com"]; }), "targets duplicated": mutate((v) => { v.projects.query.apiTargets = ["a.googleapis.com", "a.googleapis.com"]; }),
    "targets not strings": mutate((v) => { v.projects.query.apiTargets = [1]; }), "targets not an array": mutate((v) => { v.projects.query.apiTargets = "a"; }), "too many targets": mutate((v) => { v.projects.query.apiTargets = [...Array.from({ length: 63 }, (_, i) => `s${String(i).padStart(2, "0")}.googleapis.com`), "identitytoolkit.googleapis.com", "securetoken.googleapis.com"].sort(); }),
    "bucket name upper": mutate((v) => { v.bucket.name = "Bucket"; }), "bucket name slash": mutate((v) => { v.bucket.name = "a/b"; }), "bucket location empty": mutate((v) => { v.bucket.location = ""; }),
    "uniform not bool": mutate((v) => { v.bucket.uniformBucketLevelAccess = "true"; }), "bucket policy digest": mutate((v) => { v.bucket.iamPolicySha256 = "x"; }),
    "database missing": mutate((v) => { delete v.database; }), "database location empty": mutate((v) => { v.database.locationId = ""; }), "database location control": mutate((v) => { v.database.locationId = "us\ncentral1"; }), "database type empty": mutate((v) => { v.database.type = ""; }), "project policy digest": mutate((v) => { v.queryProjectIamPolicySha256 = "x"; }),
  };
  for (const [name, value] of Object.entries(bad)) assert.throws(() => parsePrivateInputs(value), /invalid private inputs/, name);
  // null is allowed where the bucket's uniform access is unknown to the packet.
  assert.doesNotThrow(() => parsePrivateInputs(mutate((v) => { v.bucket.uniformBucketLevelAccess = null; })));
  // A custom key ID, a UUID, and a Browser key with many targets (up to 64) are all keys the run may use.
  for (const id of ["fireemu-query-auth-20260925", "a", `a${"b".repeat(62)}`, "00000000-0000-4000-8000-000000000001", "abc"]) assert.doesNotThrow(() => parsePrivateInputs(mutate((v) => { v.projects.query.apiKeyId = id; })), id);
  assert.doesNotThrow(() => parsePrivateInputs(mutate((v) => { v.projects.idp.apiTargets = [...Array.from({ length: 62 }, (_, i) => `s${String(i).padStart(2, "0")}.googleapis.com`), "identitytoolkit.googleapis.com", "securetoken.googleapis.com"].sort(); })));
  assert.equal(parsePrivateInputs(mutate(() => {})).projects.idp.restrictionsSha256, sha("idp-restrictions"));
});

test("getters, accessors, prototypes and inherited fields are not data", async () => {
  const { parsePrivateInputs } = await load();
  const withGetter = good();
  Object.defineProperty(withGetter, "bucket", { get: () => good().bucket, enumerable: true });
  assert.throws(() => parsePrivateInputs(withGetter), /invalid private inputs/);
  const inherited = Object.create({ schemaVersion: 1 });
  assert.throws(() => parsePrivateInputs(inherited), /invalid private inputs/);
  const proxied = new Proxy(good(), { get: (target, key) => target[key] });
  assert.throws(() => parsePrivateInputs(proxied), /invalid private inputs/);
  const hidden = good();
  Object.defineProperty(hidden, "hidden", { value: 1, enumerable: false });
  assert.throws(() => parsePrivateInputs(hidden), /invalid private inputs/);
});

test("only plain data is accepted: foreign prototypes, hidden expected fields, and proxied, padded or sparse arrays are refused", async () => {
  const { parsePrivateInputs } = await load();
  const mutate = (fn) => { const value = good(); fn(value); return value; };
  const target = "identitytoolkit.googleapis.com";
  const bad = {
    // Every expected field is an own enumerable data field, but the record is not a plain object.
    "null prototype": Object.assign(Object.create(null), good()),
    "foreign prototype": Object.setPrototypeOf(good(), Object.create(Object.prototype)),
    "nested null prototype": mutate((v) => { v.bucket = Object.assign(Object.create(null), v.bucket); }),
    // An array cannot pose as a record even with the plain object prototype.
    "array as a record": mutate((v) => { v.owner = Object.setPrototypeOf(Object.assign([], v.owner), Object.prototype); }),
    // An expected field that is present but not enumerable is not data.
    "hidden top field": mutate((v) => { Object.defineProperty(v, "bucket", { value: v.bucket, enumerable: false }); }),
    "hidden api key": mutate((v) => { Object.defineProperty(v.projects.query, "apiKey", { value: v.projects.query.apiKey, enumerable: false }); }),
    "proxied targets": mutate((v) => { v.projects.query.apiTargets = new Proxy([target], {}); }),
    "targets with an extra field": mutate((v) => { v.projects.query.apiTargets = Object.assign([target], { extra: "x" }); }),
    "sparse targets": mutate((v) => { const targets = []; targets[1] = target; v.projects.query.apiTargets = targets; }),
  };
  for (const [name, value] of Object.entries(bad)) assert.throws(() => parsePrivateInputs(value), /invalid private inputs/, name);
});

async function fixture(t, { mode = 0o600, body = JSON.stringify(good()), prepare } = {}) {
  const directory = await mkdtemp("/private/tmp/storage-rules-inputs-");
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, "inputs.json");
  await writeFile(path, body, { mode });
  await chmod(path, mode);
  if (prepare) await prepare({ directory, path });
  return { directory, path };
}

test("a private packet file must be a private regular file owned by this user, read once and pinned by digest", async (t) => {
  const { loadPrivateInputs } = await load();
  const { path } = await fixture(t);
  const inputs = await loadPrivateInputs({ path });
  assert.equal(inputs.projects.query.projectNumber, "111111111111");
  assert.equal(inputs.provenance.sha256, sha(JSON.stringify(good())));
  assert.equal(inputs.provenance.bytes, Buffer.byteLength(JSON.stringify(good())));
  assert.equal(Object.isFrozen(inputs.provenance), true);
});

test("a packet file that is group or world accessible, a link, a directory, foreign-owned, too large or not JSON is refused", async (t) => {
  const { loadPrivateInputs } = await load();
  for (const mode of [0o640, 0o604, 0o660, 0o666, 0o644]) {
    const { path } = await fixture(t, { mode });
    await assert.rejects(loadPrivateInputs({ path }), /private inputs file refused/, mode.toString(8));
  }
  const linked = await fixture(t, { prepare: async ({ directory, path }) => { await symlink(path, join(directory, "link.json")); } });
  await assert.rejects(loadPrivateInputs({ path: join(linked.directory, "link.json") }), /private inputs file refused/);
  const hard = await fixture(t, { prepare: async ({ directory, path }) => { await link(path, join(directory, "hard.json")); } });
  await assert.rejects(loadPrivateInputs({ path: hard.path }), /private inputs file refused/);
  await assert.rejects(loadPrivateInputs({ path: hard.directory }), /private inputs file refused/);
  const big = await fixture(t, { body: JSON.stringify({ ...good(), padding: "x".repeat(70000) }) });
  await assert.rejects(loadPrivateInputs({ path: big.path }), /private inputs file refused/);
  const notJson = await fixture(t, { body: "{ nope" });
  await assert.rejects(loadPrivateInputs({ path: notJson.path }), /private inputs file refused/);
  const dupe = await fixture(t, { body: JSON.stringify(good()).replace('"schemaVersion":1', '"schemaVersion":1,"schemaVersion":1') });
  await assert.rejects(loadPrivateInputs({ path: dupe.path }), /private inputs file refused/);
  await assert.rejects(loadPrivateInputs({ path: "relative.json" }), /private inputs file refused/);
  await assert.rejects(loadPrivateInputs({ path: join(linked.directory, "missing.json") }), /private inputs file refused/);
  const foreign = await fixture(t);
  await assert.rejects(loadPrivateInputs({ path: foreign.path, uid: process.getuid() + 1 }), /private inputs file refused/);
  for (const bad of [undefined, null, 1, {}]) await assert.rejects(loadPrivateInputs(bad), /private inputs file refused/);
});

test("a loaded packet keeps its API keys only under the non-enumerable secrets", async (t) => {
  const { loadPrivateInputs } = await load();
  const { path } = await fixture(t);
  const inputs = await loadPrivateInputs({ path });
  assert.equal(inputs.secrets.apiKeys.query, "Q".repeat(39));
  assert.equal(inputs.secrets.apiKeys.idp, "I".repeat(39));
  assert.equal(Object.getOwnPropertyDescriptor(inputs, "secrets").enumerable, false);
  assert.equal(Object.keys(inputs).includes("secrets"), false);
  assert.equal(JSON.stringify(inputs).includes("Q".repeat(39)), false);
  assert.equal(JSON.stringify({ ...inputs }).includes("I".repeat(39)), false);
});

test("a relative path is refused even when it names a valid private packet file", async (t) => {
  const { loadPrivateInputs, readAdcFile } = await load();
  const { path } = await fixture(t);
  const relativePath = relative(process.cwd(), path);
  assert.equal(relativePath.startsWith("/"), false);
  await assert.rejects(loadPrivateInputs({ path: relativePath }), /private inputs file refused/);
  const adc = await fixture(t, { body: JSON.stringify(ADC) });
  await assert.rejects(readAdcFile({ path: relative(process.cwd(), adc.path) }), /ADC file refused/);
});

test("a named pipe is refused at once instead of waiting for a writer", { timeout: 10000 }, async (t) => {
  const { loadPrivateInputs, readAdcFile } = await load();
  const { directory } = await fixture(t);
  const pipe = join(directory, "pipe.json");
  execFileSync("mkfifo", ["-m", "600", pipe]);
  await assert.rejects(loadPrivateInputs({ path: pipe }), /private inputs file refused/);
  await assert.rejects(readAdcFile({ path: pipe }), /ADC file refused/);
});

test("a packet file whose content is not a valid packet is refused with the same error and never echoes the content", async (t) => {
  const { loadPrivateInputs } = await load();
  const value = good();
  value.projects.query.apiKey = "SECRET-KEY-VALUE-SHOULD-NOT-LEAK";
  value.extra = 1;
  const { path } = await fixture(t, { body: JSON.stringify(value) });
  await assert.rejects(loadPrivateInputs({ path }), (error) => /private inputs file refused/.test(error.message) && !error.message.includes("SECRET-KEY-VALUE") && !String(error.stack).includes("SECRET-KEY-VALUE"));
});

const ADC = { type: "authorized_user", client_id: "synthetic-client.apps.googleusercontent.com", client_secret: "synthetic-client-secret-00001", refresh_token: "synthetic-refresh-token-00002", quota_project_id: "some-project", universe_domain: "googleapis.com" };

test("the ADC file is read with the same file checks and reduced to the four fields the credential cache takes", async (t) => {
  const { readAdcFile } = await load();
  const { path } = await fixture(t, { body: JSON.stringify(ADC) });
  const adc = await readAdcFile({ path });
  assert.deepEqual(Object.keys(adc).sort(), ["client_id", "client_secret", "refresh_token", "type"]);
  assert.equal(adc.type, "authorized_user");
  assert.equal(Object.isFrozen(adc), true);
  for (const body of [{ ...ADC, type: "service_account" }, { ...ADC, client_id: undefined }, { ...ADC, refresh_token: 5 }, [], "x"]) {
    const bad = await fixture(t, { body: JSON.stringify(body) });
    await assert.rejects(readAdcFile({ path: bad.path }), /ADC file refused/);
  }
  const open = await fixture(t, { mode: 0o644, body: JSON.stringify(ADC) });
  await assert.rejects(readAdcFile({ path: open.path }), /ADC file refused/);
  await assert.rejects(readAdcFile({ path: "adc.json" }), /ADC file refused/);
});

test("an ADC file that is not valid UTF-8 is refused even where the bytes sit in a field that is not kept", async (t) => {
  const { readAdcFile } = await load();
  const text = JSON.stringify({ ...ADC, quota_project_id: "INVALID" });
  const [head, tail] = text.split("INVALID");
  const { path } = await fixture(t, { body: Buffer.concat([Buffer.from(head), Buffer.from([0xff, 0xfe]), Buffer.from(tail)]) });
  await assert.rejects(readAdcFile({ path }), /ADC file refused/);
  // The same file with valid bytes there is read.
  const valid = await fixture(t, { body: text });
  assert.equal((await readAdcFile({ path: valid.path })).type, "authorized_user");
});

test("a repeated key is refused only within one object: a nested or sibling object may use the same key names", async (t) => {
  const { readAdcFile, loadPrivateInputs } = await load();
  const fields = JSON.stringify(ADC).slice(1, -1);
  const accepted = {
    "nested keys before the same top keys": `{"extra":{"type":"x","client_id":"y"},${fields}}`,
    "nested keys after the same top keys": `{${fields},"extra":{"type":"x","client_id":"y"}}`,
    "sibling objects with the same keys": `{"a":{"k":1},"b":{"k":2},${fields}}`,
    "an array of objects with the same keys": `{"list":[{"k":1},{"k":2}],${fields}}`,
    "a key name as a string value": `{"quota":"type","label":["type","type"],${fields}}`,
  };
  for (const [name, body] of Object.entries(accepted)) {
    const { path } = await fixture(t, { body });
    assert.equal((await readAdcFile({ path })).type, "authorized_user", name);
  }
  const refused = {
    "top key repeated after a nested object": `{${fields},"extra":{"a":1},"type":"authorized_user"}`,
    "repeated key inside a nested object": `{"extra":{"a":1,"b":2,"a":3},${fields}}`,
    "repeated key inside an object in an array": `{"list":[{"k":1},{"k":2,"k":3}],${fields}}`,
  };
  for (const [name, body] of Object.entries(refused)) {
    const { path } = await fixture(t, { body });
    await assert.rejects(readAdcFile({ path }), /ADC file refused/, name);
  }
  // The packet's two projects share every key name and are read.
  const { path } = await fixture(t);
  assert.equal((await loadPrivateInputs({ path })).projects.idp.projectId, "fireemu-oracle-idp");
});

test("run secrets are fresh, well-formed and never reused: the salt, four passwords and the two malformed credentials", async () => {
  const { generateRunSecrets } = await load();
  const a = generateRunSecrets();
  const b = generateRunSecrets();
  assert.match(a.digestSalt, /^[0-9a-f]{64}$/);
  assert.deepEqual(Object.keys(a.passwords).sort(), ["foreign-project-token", "revoked-token", "user-a", "user-b"]);
  for (const value of Object.values(a.passwords)) assert.match(value, /^[!-~]{20,128}$/);
  assert.deepEqual(Object.keys(a.malformed).sort(), ["malformed-oauth", "malformed-token"]);
  assert.match(a.malformed["malformed-token"], /^Firebase [!-~]{16,200}$/);
  assert.match(a.malformed["malformed-oauth"], /^Bearer ya29\.[!-~]{16,200}$/);
  assert.equal(new Set([a.digestSalt, ...Object.values(a.passwords), ...Object.values(a.malformed)]).size, 7);
  for (const key of ["digestSalt"]) assert.notEqual(a[key], b[key]);
  assert.notEqual(a.passwords["user-a"], b.passwords["user-a"]);
  // The generator is injectable so a run can be reproduced in a test, and a short source is refused.
  const fixed = generateRunSecrets({ randomBytes: (size) => Buffer.alloc(size, 7) });
  assert.equal(fixed.digestSalt, "07".repeat(32));
  assert.throws(() => generateRunSecrets({ randomBytes: () => Buffer.alloc(3) }), /invalid random source/);
  assert.throws(() => generateRunSecrets({ randomBytes: () => "x" }), /invalid random source/);
  // A source of the right size that is not a Buffer is refused too: its toString would not encode the bytes.
  assert.throws(() => generateRunSecrets({ randomBytes: (size) => "x".repeat(size) }), /invalid random source/);
  assert.throws(() => generateRunSecrets({ randomBytes: (size) => new Uint8Array(size).fill(7) }), /invalid random source/);
});
