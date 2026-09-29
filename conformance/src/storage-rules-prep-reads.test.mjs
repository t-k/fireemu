import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { bindPrepEntry, prepPaths } from "./storage-rules-prep/prep-reads.mjs";
import { loadPrivateInputs } from "./storage-rules/private-inputs.mjs";
import { ADC, API_KEYS, KEY_IDS, NUMBERS, OWNER_TOKEN, SUBJECT, privatePacket } from "./storage-rules-runner-support.mjs";
import { CODE_FILES, ENVELOPE_ID, PACKET_NAME, PIN_KEYS, SOURCE_COMMIT, cleanup, fakeRequestImpl, localInputs, prepAnswer, prepCodeDigests, prepCorpus, scratchCode } from "./storage-rules-prep-support.mjs";

// The stage 2a entry against a scratch main checkout and a fake wire: what it reads, takes and writes, and when it stops.
const closureText = readFileSync(new URL("../../spec/compatibility/closure/STORAGE-RULES.json", import.meta.url), "utf8");
const closure = JSON.parse(closureText);
const codeRoot = scratchCode(closureText);
process.on("exit", () => cleanup(codeRoot));
const digests = await prepCodeDigests(codeRoot);
const params = { bucket: privatePacket("/x").bucket.name, queryProjectNumber: NUMBERS.query, idpProjectNumber: NUMBERS.idp, sourceCommit: SOURCE_COMMIT };
const corpus = prepCorpus(closure, params);
const packet = { taskId: "STORAGE-RULES", packetName: PACKET_NAME, packetSha256: "1".repeat(64), sourceCommit: SOURCE_COMMIT, runnerSha256: digests.runnerSha256, manifestSha256: corpus.sha256, fixtureSchemaSha256: digests.fixtureSchemaSha256, projects: ["fireemu-oracle-idp", "fireemu-oracle-query"], maxRequests: 13, reserveUsd: 0.01 };
const review = { verdict: "APPROVE", must: [], should: [], ...Object.fromEntries(PIN_KEYS.map((key) => [key, packet[key]])), envelopeId: ENVELOPE_ID, withinEnvelope: true };
const ledger = [
  "- 2026-09-28 | 調整役への委任（本番の送信） | decision=APPROVE; local fixture | オーナー（ローカル試験） | private.md",
  "- 2026-09-28 | 調整役への委任（枠の承認） | decision=APPROVE; local fixture | オーナー（ローカル試験） | private.md",
  `- 2026-09-29 | STORAGE-RULES ${PACKET_NAME} envelope | envelopeId=${ENVELOPE_ID}; project=${packet.projects.join(",")}; maxRequests=13; reserveUsd=0.01; writes=none; iamConfig=none; retries=none; 根拠=2026-09-28 調整役への委任（本番の送信） | Claude（委任。オーナーの裁量の委任 2026-09-28） | private.md`,
  `- 2026-09-29 | STORAGE-RULES ${PACKET_NAME} | decision=APPROVE; ${PIN_KEYS.map((key) => `${key}=${packet[key]}`).join("; ")}; envelopeId=${ENVELOPE_ID} | Claude（委任。枠の内の承認し直し） | private.md`,
].join("\n");
const clock = { nowSeconds: () => 1_800_000_000, waitUntilSeconds: async () => {}, sleep: async () => {} };
const runId = "prep-test-run";

async function checkout(t, { ledgerText = ledger, answer = prepAnswer, gitHead = SOURCE_COMMIT, gitStatus = "", usage = [], local = localInputs } = {}) {
  const root = await mkdtemp("/private/tmp/storage-rules-prep-");
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, ".git"));
  await mkdir(join(root, "docs.local", "instructions"), { recursive: true });
  const runs = join(root, "docs.local", "runs");
  await mkdir(runs, { mode: 0o700 });
  await chmod(runs, 0o700);
  await mkdir(join(runs, "sandbox-locks"), { mode: 0o700 });
  await chmod(join(runs, "sandbox-locks"), 0o700);
  await writeFile(join(root, "docs.local", "instructions", "owner-decisions.md"), ledgerText, { mode: 0o644 });
  if (usage.length > 0) await writeFile(join(runs, "storage-rules-prep-usage.jsonl"), usage.map((id) => `${JSON.stringify({ packetSha256: packet.packetSha256, runId: id })}\n`).join(""), { mode: 0o600 });
  const adcPath = join(root, "adc.json");
  await writeFile(adcPath, JSON.stringify(ADC), { mode: 0o600 });
  const localPath = join(root, "local.json");
  await writeFile(localPath, JSON.stringify(local(adcPath)), { mode: 0o600 });
  const wire = [];
  const gitCalls = [];
  const git = async (where, args) => { gitCalls.push([where, ...args]); return args[0] === "rev-parse" ? `${gitHead}\n` : gitStatus; };
  const entry = bindPrepEntry({ root, codeRoot, requestImpl: fakeRequestImpl(answer, wire), clock, git });
  const options = { localPath, closure, runId, sourceCommit: SOURCE_COMMIT, packet: structuredClone(packet), review: structuredClone(review) };
  return { root, runs, entry, options, wire, gitCalls, adcPath, localPath, lockFiles: async () => (await readdir(join(runs, "sandbox-locks"))).sort() };
}
async function walk(directory) {
  const out = [];
  for (const name of await readdir(directory)) {
    const path = join(directory, name);
    if ((await stat(path)).isDirectory()) out.push(...await walk(path)); else out.push(path);
  }
  return out;
}

const answerWith = (bad) => (spec) => prepAnswer(spec, bad);
const EXPECTED_URLS = [
  ["POST", "https://oauth2.googleapis.com/token"],
  ["GET", "https://www.googleapis.com/oauth2/v2/userinfo"],
  ["GET", `https://apikeys.googleapis.com/v2/projects/${NUMBERS.query}/locations/global/keys`],
  ["GET", `https://apikeys.googleapis.com/v2/projects/${NUMBERS.idp}/locations/global/keys`],
  ["GET", `https://apikeys.googleapis.com/v2/projects/${NUMBERS.query}/locations/global/keys/${KEY_IDS.query}/keyString`],
  ["GET", `https://apikeys.googleapis.com/v2/projects/${NUMBERS.idp}/locations/global/keys/${KEY_IDS.idp}/keyString`],
  ["GET", "https://storage.googleapis.com/storage/v1/b/fireemu-fixture-rules-bucket"],
  ["GET", "https://storage.googleapis.com/storage/v1/b/fireemu-fixture-rules-bucket/iam?optionsRequestedPolicyVersion=3"],
  ["GET", "https://firestore.googleapis.com/v1/projects/fireemu-oracle-query/databases/(default)"],
  ["POST", `https://cloudresourcemanager.googleapis.com/v3/projects/${NUMBERS.query}:getIamPolicy`],
  ["POST", `https://cloudresourcemanager.googleapis.com/v3/projects/${NUMBERS.query}:testIamPermissions`],
  ["POST", `https://cloudresourcemanager.googleapis.com/v3/projects/${NUMBERS.idp}:testIamPermissions`],
  ["GET", "https://storage.googleapis.com/storage/v1/b/fireemu-fixture-rules-bucket/iam/testPermissions"],
];

test("thirteen reads, in order, each once, yield exactly the stage 3 inputs, and the locks are released", async (t) => {
  const f = await checkout(t);
  const result = await f.entry(f.options);
  assert.deepEqual([result.status, result.requests], ["finished", 13]);
  assert.deepEqual(f.wire.map((entry) => [entry.method, entry.url.split("?")[0]]), EXPECTED_URLS.map(([method, url]) => [method, url.split("?")[0]]));
  assert.equal(f.wire[7].url.split("?")[1], "optionsRequestedPolicyVersion=3");
  assert.match(f.wire[12].url.split("?")[1], /^permissions=storage\.buckets\.get/);
  // Every admin read carries the owner's token and the quota project of its own target; the token read and the key list have no body except the token form.
  const projectOf = (url) => (url.includes(NUMBERS.idp) ? "fireemu-oracle-idp" : "fireemu-oracle-query");
  for (const entry of f.wire.slice(1)) {
    assert.equal(entry.headers.authorization, `Bearer ${OWNER_TOKEN}`, entry.url);
    assert.equal(entry.headers["x-goog-user-project"], entry.url.includes("firestore") || entry.url.includes("storage.googleapis") || entry.url.includes("www.googleapis") ? "fireemu-oracle-query" : projectOf(entry.url), entry.url);
  }
  assert.equal(f.wire[0].headers.authorization, undefined);
  assert.equal(f.wire.filter((entry) => entry.body !== null && entry.body.length > 0).length, 4);
  const inputs = JSON.parse(await readFile(result.inputsPath, "utf8"));
  assert.deepEqual(inputs, privatePacket(f.adcPath));
  // The produced file is a valid stage 3 private inputs file.
  assert.equal((await loadPrivateInputs({ path: result.inputsPath })).projects.query.apiKeyId, KEY_IDS.query);
  assert.equal((await stat(result.inputsPath)).mode & 0o777, 0o600);
  assert.equal((await stat(join(f.runs, `storage-rules-prep-${runId}`))).mode & 0o777, 0o700);
  assert.equal(await readFile(join(f.runs, "storage-rules-prep-usage.jsonl"), "utf8"), `${JSON.stringify({ packetSha256: packet.packetSha256, runId })}\n`);
  assert.deepEqual(await f.lockFiles(), []);
  assert.deepEqual(f.gitCalls.map(([where, ...args]) => [where, args.join(" ")]), [[codeRoot, "rev-parse HEAD"], [codeRoot, "status --porcelain --untracked-files=no"]]);
});

test("the journals hold no secret: not the token, the key strings, the owner's address, the key IDs' strings or the project numbers' credentials", async (t) => {
  const f = await checkout(t);
  const result = await f.entry(f.options);
  const secrets = [OWNER_TOKEN, ADC.refresh_token, ADC.client_secret, API_KEYS.query, API_KEYS.idp, "owner@example.test", SUBJECT];
  const journals = (await walk(join(f.runs, `storage-rules-prep-${runId}`))).filter((file) => file !== result.inputsPath);
  assert.ok(journals.some((file) => file.endsWith("captures.jsonl")) && journals.some((file) => file.endsWith("reservations.jsonl")));
  for (const file of journals) {
    const text = (await readFile(file)).toString("latin1");
    for (const secret of secrets) for (const form of [secret, encodeURIComponent(secret), Buffer.from(secret).toString("base64"), Buffer.from(secret).toString("hex")]) assert.equal(text.includes(form), false, `${secret.slice(0, 12)} in ${file}`);
    assert.equal((await stat(file)).mode & 0o077, 0, file);
  }
});

const STOPS = [
  ["identity address unverified", { identity: { id: SUBJECT, email: "owner@example.test", verified_email: false } }, 2],
  ["query key list with two live keys", { "list-query": { keys: [{ name: `projects/${NUMBERS.query}/locations/global/keys/${KEY_IDS.query}`, uid: "a" }, { name: `projects/${NUMBERS.query}/locations/global/keys/${KEY_IDS.idp}`, uid: "b" }] } }, 3],
  ["query key list with a next page", { "list-query": { keys: [{ name: `projects/${NUMBERS.query}/locations/global/keys/${KEY_IDS.query}`, uid: "a" }], nextPageToken: "next" } }, 3],
  ["query key list with no key", { "list-query": {} }, 3],
  ["query key list that only holds a deleted key", { "list-query": { keys: [{ name: `projects/${NUMBERS.query}/locations/global/keys/${KEY_IDS.query}`, uid: "a", deleteTime: "2026-01-01T00:00:00Z" }] } }, 3],
  ["query key list that is not a list", { "list-query": { keys: "none" } }, 3],
  ["query key of another project", { "list-query": { keys: [{ name: `projects/${NUMBERS.idp}/locations/global/keys/${KEY_IDS.query}`, uid: "a" }] } }, 3],
  ["query key name that is not a UUID", { "list-query": { keys: [{ name: `projects/${NUMBERS.query}/locations/global/keys/not-a-uuid`, uid: "a" }] } }, 3],
  ["query key with a method restriction", { "list-query": { keys: [{ name: `projects/${NUMBERS.query}/locations/global/keys/${KEY_IDS.query}`, uid: "a", restrictions: { apiTargets: [{ service: "identitytoolkit.googleapis.com", methods: ["x"] }] } }] } }, 3],
  ["query key with another restriction", { "list-query": { keys: [{ name: `projects/${NUMBERS.query}/locations/global/keys/${KEY_IDS.query}`, uid: "a", restrictions: { browserKeyRestrictions: { allowedReferrers: ["*"] } } }] } }, 3],
  ["query key with a duplicated target", { "list-query": { keys: [{ name: `projects/${NUMBERS.query}/locations/global/keys/${KEY_IDS.query}`, uid: "a", restrictions: { apiTargets: [{ service: "a.googleapis.com" }, { service: "a.googleapis.com" }] } }] } }, 3],
  ["idp key list with two live keys", { "list-idp": { keys: [{ name: `projects/${NUMBERS.idp}/locations/global/keys/${KEY_IDS.idp}`, uid: "a" }, { name: `projects/${NUMBERS.idp}/locations/global/keys/${KEY_IDS.query}`, uid: "b" }] } }, 4],
  ["both projects report the same key ID", { "list-idp": { keys: [{ name: `projects/${NUMBERS.idp}/locations/global/keys/${KEY_IDS.query}`, uid: "b" }] } }, 4],
  ["query key string that is not the local one", { "keystring-query": { keyString: "Z".repeat(39) } }, 5],
  ["idp key string that is not the local one", { "keystring-idp": { keyString: "Z".repeat(39) } }, 6],
  ["a bucket of another project", { bucket: { kind: "storage#bucket", name: "fireemu-fixture-rules-bucket", projectNumber: "999999999999", location: "US-CENTRAL1" } }, 7],
  ["query permissions missing", { [`permissions-${NUMBERS.query}`]: { permissions: [] } }, 11],
  ["idp permissions missing", { [`permissions-${NUMBERS.idp}`]: { permissions: [] } }, 12],
  ["bucket permissions missing", { "bucket-permissions": { kind: "storage#testIamPermissionsResponse", permissions: [] } }, 13],
];
test("an unexpected answer ends the run at that request, writes no inputs and keeps the locks", async (t) => {
  for (const [name, bad, count] of STOPS) {
    const f = await checkout(t, { answer: answerWith(bad) });
    await assert.rejects(f.entry(f.options), Error, name);
    assert.equal(f.wire.length, count, name);
    assert.deepEqual(await walk(join(f.runs, `storage-rules-prep-${runId}`)).then((files) => files.filter((file) => file.endsWith("private-inputs.json"))), [], name);
    assert.deepEqual(await f.lockFiles(), ["fireemu-oracle-idp.lock", "fireemu-oracle-query.lock"], name);
    assert.equal((await readFile(join(f.runs, "storage-rules-prep-usage.jsonl"), "utf8")).length > 0, true, name);
  }
});

test("a key list that answers with an error status, a non-JSON body or a broken key entry ends the run there", async (t) => {
  const raw = (status, text) => (spec) => (/\/keys$/.test(spec.url) && spec.url.includes(NUMBERS.query) ? { status, rawHeaders: ["Content-Type", "application/json"], bytes: Buffer.from(text) } : prepAnswer(spec));
  for (const [status, text] of [[403, "{}"], [200, "not json"], [200, "[]"], [200, "null"], [200, JSON.stringify({ keys: [null] })], [200, JSON.stringify({ keys: [{ name: `projects/${NUMBERS.query}/locations/global/keys/${KEY_IDS.query}` }] })]]) {
    const f = await checkout(t, { answer: raw(status, text) });
    await assert.rejects(f.entry(f.options), Error, `${status} ${text}`);
    assert.equal(f.wire.length, 3, `${status} ${text}`);
  }
});

test("a deleted key next to the one live key is ignored", async (t) => {
  const live = keyEntry("query");
  const f = await checkout(t, { answer: answerWith({ "list-query": { keys: [{ name: `projects/${NUMBERS.query}/locations/global/keys/${KEY_IDS.idp}`, uid: "old", deleteTime: "2026-01-01T00:00:00Z" }, live] } }) });
  const result = await f.entry(f.options);
  assert.equal(result.requests, 13);
});
function keyEntry(which) {
  return { name: `projects/${NUMBERS[which]}/locations/global/keys/${KEY_IDS[which]}`, uid: `${which}-key-uid`, restrictions: { apiTargets: [{ service: "identitytoolkit.googleapis.com" }] } };
}
