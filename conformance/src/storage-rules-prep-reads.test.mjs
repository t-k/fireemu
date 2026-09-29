import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { bindPrepEntry, prepPaths } from "./storage-rules-prep/prep-reads.mjs";
import { loadPrivateInputs } from "./storage-rules/private-inputs.mjs";
import { ADC, API_KEYS, NUMBERS, OWNER_TOKEN, SUBJECT } from "./storage-rules-runner-support.mjs";
import { CODE_FILES, ENVELOPE_ID, PREP_KEYS, prepInputsFor, PACKET_NAME, PIN_KEYS, SOURCE_COMMIT, cleanup, fakeRequestImpl, localInputs, prepAnswer, prepCodeDigests, prepCorpus, scratchCode } from "./storage-rules-prep-support.mjs";

// The stage 2a entry against a scratch main checkout and a fake wire: what it reads, takes and writes, and when it stops.
const closureText = readFileSync(new URL("../../spec/compatibility/closure/STORAGE-RULES.json", import.meta.url), "utf8");
const closure = JSON.parse(closureText);
const codeRoot = scratchCode(closureText);
process.on("exit", () => cleanup(codeRoot));
const digests = await prepCodeDigests(codeRoot);
const BUCKET_NAME = "fireemu-fixture-rules-bucket";
const params = { bucket: BUCKET_NAME, queryProjectNumber: NUMBERS.query, idpProjectNumber: NUMBERS.idp, sourceCommit: SOURCE_COMMIT };
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

async function checkout(t, { ledgerText = ledger, answer = prepAnswer, gitHead = SOURCE_COMMIT, gitStatus = "", usage = [], local = localInputs, gitExtra = "", gitExtraPrep = "" } = {}) {
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
  const git = async (where, args) => { gitCalls.push([where, ...args]); return args[0] === "rev-parse" ? `${gitHead}\n` : args.includes("--ignored") ? (args.includes("conformance/src/storage-rules-prep") ? gitExtraPrep : gitExtra) : gitStatus; };
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
  ["GET", `https://apikeys.googleapis.com/v2/projects/${NUMBERS.query}/locations/global/keys/${PREP_KEYS.query}/keyString`],
  ["GET", `https://apikeys.googleapis.com/v2/projects/${NUMBERS.idp}/locations/global/keys/${PREP_KEYS.idp}/keyString`],
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
  assert.deepEqual(inputs, prepInputsFor(f.adcPath));
  // The produced file is a valid stage 3 private inputs file.
  assert.equal((await loadPrivateInputs({ path: result.inputsPath })).projects.query.apiKeyId, PREP_KEYS.query);
  assert.equal((await stat(result.inputsPath)).mode & 0o777, 0o600);
  assert.equal((await stat(join(f.runs, `storage-rules-prep-${runId}`))).mode & 0o777, 0o700);
  assert.equal(await readFile(join(f.runs, "storage-rules-prep-usage.jsonl"), "utf8"), `${JSON.stringify({ packetSha256: packet.packetSha256, runId })}\n`);
  assert.deepEqual(await f.lockFiles(), []);
  // The counter's terminal row says finished, and every read left its classified facts (never a secret) in the capture journal.
  const dir = join(f.runs, `storage-rules-prep-${runId}`);
  const reservationRows = (await readFile(join(dir, (await readdir(dir)).find((name) => name.endsWith("reservations.jsonl"))), "utf8")).split("\n").filter(Boolean).map((line) => JSON.parse(line));
  const terminal = reservationRows.filter((row) => JSON.stringify(row).includes("terminal"));
  assert.equal(terminal.length, 1);
  assert.match(JSON.stringify(terminal[0]), /"outcome":"finished"/);
  const captureRows = (await readFile(join(dir, (await readdir(dir)).find((name) => name.endsWith("captures.jsonl"))), "utf8")).split("\n").filter(Boolean).map((line) => JSON.parse(line));
  const facts = captureRows.filter((row) => row.event === "facts");
  assert.deepEqual(facts.map((row) => row.data.operationId).sort(), ["preflight/bucket/iam", "preflight/bucket/metadata", "preflight/bucket/permissions", "preflight/idp/key-list", "preflight/idp/key-string", "preflight/idp/permissions", "preflight/owner/identity", "preflight/query/database", "preflight/query/iam", "preflight/query/key-list", "preflight/query/key-string", "preflight/query/permissions"]);
  assert.equal(JSON.stringify(facts).includes(API_KEYS.query), false);
  assert.deepEqual(f.gitCalls.map(([where, ...args]) => [where, args.join(" ")]), [[codeRoot, "rev-parse HEAD"], [codeRoot, "status --porcelain --untracked-files=no"], [codeRoot, "status --porcelain --untracked-files=all --ignored -- conformance/src/storage-rules spec/compatibility/closure/STORAGE-RULES.json"], [codeRoot, "status --porcelain --untracked-files=all --ignored -- conformance/src/storage-rules-prep"]]);
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
  ["query key list with two live keys", { "list-query": { keys: [{ name: `projects/${NUMBERS.query}/locations/global/keys/${PREP_KEYS.query}`, uid: "a" }, { name: `projects/${NUMBERS.query}/locations/global/keys/${PREP_KEYS.idp}`, uid: "b" }] } }, 3],
  ["query key list with a next page", { "list-query": { keys: [{ name: `projects/${NUMBERS.query}/locations/global/keys/${PREP_KEYS.query}`, uid: "a" }], nextPageToken: "next" } }, 3],
  ["query key list with no key", { "list-query": {} }, 3],
  ["query key list that only holds a deleted key", { "list-query": { keys: [{ name: `projects/${NUMBERS.query}/locations/global/keys/${PREP_KEYS.query}`, uid: "a", deleteTime: "2026-01-01T00:00:00Z" }] } }, 3],
  ["query key list that is not a list", { "list-query": { keys: "none" } }, 3],
  ["query key of another project", { "list-query": { keys: [{ name: `projects/${NUMBERS.idp}/locations/global/keys/${PREP_KEYS.query}`, uid: "a" }] } }, 3],
  ["query key name that is not a UUID", { "list-query": { keys: [{ name: `projects/${NUMBERS.query}/locations/global/keys/not-a-uuid`, uid: "a" }] } }, 3],
  ["query key with a method restriction", { "list-query": { keys: [{ name: `projects/${NUMBERS.query}/locations/global/keys/${PREP_KEYS.query}`, uid: "a", restrictions: { apiTargets: [{ service: "identitytoolkit.googleapis.com", methods: ["x"] }] } }] } }, 3],
  ["query key with another restriction", { "list-query": { keys: [{ name: `projects/${NUMBERS.query}/locations/global/keys/${PREP_KEYS.query}`, uid: "a", restrictions: { browserKeyRestrictions: { allowedReferrers: ["*"] } } }] } }, 3],
  ["query key with a duplicated target", { "list-query": { keys: [{ name: `projects/${NUMBERS.query}/locations/global/keys/${PREP_KEYS.query}`, uid: "a", restrictions: { apiTargets: [{ service: "a.googleapis.com" }, { service: "a.googleapis.com" }] } }] } }, 3],
  ["idp key list with two live keys", { "list-idp": { keys: [{ name: `projects/${NUMBERS.idp}/locations/global/keys/${PREP_KEYS.idp}`, uid: "a" }, { name: `projects/${NUMBERS.idp}/locations/global/keys/${PREP_KEYS.query}`, uid: "b" }] } }, 4],
  ["both projects report the same key ID", { "list-idp": { keys: [{ name: `projects/${NUMBERS.idp}/locations/global/keys/${PREP_KEYS.query}`, uid: "b" }] } }, 4],
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
  for (const [status, text] of [[403, "{}"], [200, "not json"], [200, "[]"], [200, "null"], [200, JSON.stringify({ keys: [null] })], [200, JSON.stringify({ keys: [{ name: `projects/${NUMBERS.query}/locations/global/keys/${PREP_KEYS.query}` }] })]]) {
    const f = await checkout(t, { answer: raw(status, text) });
    await assert.rejects(f.entry(f.options), Error, `${status} ${text}`);
    assert.equal(f.wire.length, 3, `${status} ${text}`);
  }
});

test("a deleted key next to the one live key is ignored", async (t) => {
  const live = keyEntry("query");
  const f = await checkout(t, { answer: answerWith({ "list-query": { keys: [{ name: `projects/${NUMBERS.query}/locations/global/keys/${PREP_KEYS.idp}`, uid: "old", deleteTime: "2026-01-01T00:00:00Z" }, live] } }) });
  const result = await f.entry(f.options);
  assert.equal(result.requests, 13);
});
function keyEntry(which) {
  return { name: `projects/${NUMBERS[which]}/locations/global/keys/${PREP_KEYS[which]}`, uid: `${which}-key-uid`, restrictions: { apiTargets: [{ service: "identitytoolkit.googleapis.com" }] } };
}

test("the run is refused, before anything is created, unless the code, the schema, the corpus and the checkout reproduce the approval's pins", async (t) => {
  const cases = [
    ["runnerSha256", (f) => { f.options.packet.runnerSha256 = "0".repeat(64); }, /pin mismatch: runnerSha256/],
    ["fixtureSchemaSha256", (f) => { f.options.packet.fixtureSchemaSha256 = "0".repeat(64); }, /pin mismatch: fixtureSchemaSha256/],
    ["manifestSha256", (f) => { f.options.packet.manifestSha256 = "0".repeat(64); }, /pin mismatch: manifestSha256/],
    ["runner digest not hex", (f) => { f.options.packet.runnerSha256 = "X".repeat(64); }, /invalid prep options/],
    ["a digest with a suffix", (f) => { f.options.packet.manifestSha256 = `${f.options.packet.manifestSha256}0`; }, /invalid prep options/],
    ["a digest that is not a string", (f) => { f.options.packet.fixtureSchemaSha256 = 5; }, /invalid prep options/],
    ["the commit of the packet is another one", (f) => { f.options.packet.sourceCommit = "b".repeat(40); }, /invalid prep options/],
  ];
  for (const [name, change, message] of cases) {
    const f = await checkout(t);
    change(f);
    await assert.rejects(f.entry(f.options), message, name);
    assert.deepEqual(await readdir(f.runs), ["sandbox-locks"], name);
    assert.deepEqual(await f.lockFiles(), [], name);
    assert.equal(f.wire.length, 0, name);
  }
  const moved = await checkout(t, { gitHead: "b".repeat(40) });
  await assert.rejects(moved.entry(moved.options), /source commit mismatch/);
  const dirty = await checkout(t, { gitStatus: " M x\n" });
  await assert.rejects(dirty.entry(dirty.options), /working tree not clean/);
  const untrackedRunner = await checkout(t, { gitExtra: "?? conformance/src/storage-rules/driver.mjs\n" });
  await assert.rejects(untrackedRunner.entry(untrackedRunner.options), /untracked or ignored runner files/);
  const untrackedPrep = await checkout(t, { gitExtraPrep: "!! conformance/src/storage-rules-prep/scratch.mjs\n" });
  await assert.rejects(untrackedPrep.entry(untrackedPrep.options), /untracked or ignored runner files/);
  const brokenGit = await checkout(t);
  const broken = bindPrepEntry({ root: brokenGit.root, codeRoot, requestImpl() {}, clock, git: async (where, args) => { if (args.includes("conformance/src/storage-rules-prep")) throw new Error("git missing"); return args[0] === "rev-parse" ? `${SOURCE_COMMIT}\n` : ""; } });
  await assert.rejects(broken(brokenGit.options), /source commit unreadable/);
  for (const state of [moved, dirty, untrackedRunner, untrackedPrep, brokenGit]) { assert.deepEqual(await readdir(state.runs), ["sandbox-locks"]); assert.equal(state.wire.length, 0); }
  // A private-inputs change that moves the corpus (another bucket name) is caught as a manifest mismatch.
  const gitDown = await checkout(t);
  const down = bindPrepEntry({ root: gitDown.root, codeRoot, requestImpl() {}, clock, git: async () => { throw new Error("git missing"); } });
  await assert.rejects(down(gitDown.options), /source commit unreadable/);
  const emptyCode = await mkdtemp("/private/tmp/storage-rules-prep-empty-code-");
  t.after(() => rm(emptyCode, { recursive: true, force: true }));
  const noCode = await checkout(t);
  const blind = bindPrepEntry({ root: noCode.root, codeRoot: emptyCode, requestImpl() {}, clock, git: async () => "" });
  await assert.rejects(blind(noCode.options), /pin source refused/);
  for (const state of [gitDown, noCode]) assert.deepEqual(await readdir(state.runs), ["sandbox-locks"]);
  const other = await checkout(t, { local: (adc) => ({ ...localInputs(adc), bucket: { name: "another-bucket-name" } }) });
  await assert.rejects(other.entry(other.options), /pin mismatch: manifestSha256/);
  assert.equal(other.wire.length, 0);
});

test("a revoked approval, a wrong bound, a missing envelope and a second recording are refused with nothing sent", async (t) => {
  const revoked = await checkout(t, { ledgerText: `${ledger}\n- 2026-09-29 | STORAGE-RULES ${PACKET_NAME} | decision=REVOKED; packetSha256=${packet.packetSha256} | オーナー（ローカル試験） | private.md` });
  await assert.rejects(revoked.entry(revoked.options), /approval revoked/);
  // A revocation of the lane that is not a row of this packet (no decision field) still stops it, through the lane scan alone.
  const laneOnly = await checkout(t, { ledgerText: `${ledger}\n- 2026-09-29 | STORAGE-RULES | revoked | オーナー（ローカル試験） | note.md` });
  await assert.rejects(laneOnly.entry(laneOnly.options), /approval revoked/);
  assert.equal(laneOnly.wire.length, 0);
  const noEnvelope = await checkout(t, { ledgerText: ledger.split("\n").filter((line) => !line.includes("envelope |")).join("\n") });
  await assert.rejects(noEnvelope.entry(noEnvelope.options), /preceding owner envelope required/);
  const smallEnvelope = await checkout(t, { ledgerText: ledger.replace("maxRequests=13;", "maxRequests=12;") });
  await assert.rejects(smallEnvelope.entry(smallEnvelope.options), /packet exceeds owner envelope/);
  const cheapEnvelope = await checkout(t, { ledgerText: ledger.replace("reserveUsd=0.01;", "reserveUsd=0.005;") });
  await assert.rejects(cheapEnvelope.entry(cheapEnvelope.options), /packet exceeds owner envelope/);
  const stage3 = await checkout(t);
  stage3.options.packet = { ...stage3.options.packet, maxRequests: 12344, reserveUsd: 2 };
  stage3.options.review = { ...stage3.options.review };
  await assert.rejects(stage3.entry(stage3.options), /runner limit mismatch/);
  const projects = await checkout(t);
  projects.options.packet.projects = ["fireemu-oracle-query"];
  await assert.rejects(projects.entry(projects.options), /runner limit mismatch/);
  for (const state of [revoked, noEnvelope, smallEnvelope, cheapEnvelope, stage3, projects]) { assert.equal(state.wire.length, 0); assert.deepEqual(await state.lockFiles(), []); }
  // One recording per approval: a second run under the same packet is refused at its start.
  const second = await checkout(t, { usage: ["first-prep-run"] });
  await assert.rejects(second.entry(second.options), /recording budget exhausted/);
  assert.equal(second.wire.length, 0);
  assert.deepEqual(await second.lockFiles(), []);
});

test("a caller cannot name the ledger, the locks, the usage ledger, the run directory, the transport, the clock or the credentials", async (t) => {
  const f = await checkout(t);
  const overrides = { readLedger: async () => "", ledger: "/x", locks: {}, lockDir: "/x", usagePath: "/x", directory: "/x", transport: {}, clock, root: "/x", requestImpl() {}, adcPath: "/x", inputsPath: "/x", use() {} };
  for (const [name, value] of Object.entries(overrides)) await assert.rejects(f.entry({ ...f.options, [name]: value }), /invalid prep options/, name);
  for (const key of Object.keys(f.options)) { const { [key]: _, ...rest } = f.options; await assert.rejects(f.entry(rest), /invalid prep options/, key); }
  for (const bad of ["Bad Id", "", 5, "a".repeat(49)]) await assert.rejects(f.entry({ ...f.options, runId: bad }), /invalid prep options/, String(bad));
  assert.deepEqual(await readdir(f.runs), ["sandbox-locks"]);
  assert.equal(f.wire.length, 0);
});

test("the operator's local inputs file is a private, closed, plain file", async (t) => {
  const good = await checkout(t);
  const write = async (f, value, mode = 0o600) => { await writeFile(f.localPath, typeof value === "string" ? value : JSON.stringify(value), { mode }); await chmod(f.localPath, mode); };
  const base = (f) => localInputs(f.adcPath);
  const cases = {
    "wide mode": async (f) => write(f, base(f), 0o640),
    "not json": async (f) => write(f, "not json"),
    "extra key": async (f) => write(f, { ...base(f), extra: 1 }),
    "wrong version": async (f) => write(f, { ...base(f), schemaVersion: 2 }),
    "same numbers": async (f) => write(f, { ...base(f), projects: { query: { ...base(f).projects.query }, idp: { ...base(f).projects.idp, projectNumber: base(f).projects.query.projectNumber } } }),
    "same keys": async (f) => write(f, { ...base(f), projects: { query: base(f).projects.query, idp: { ...base(f).projects.idp, apiKey: base(f).projects.query.apiKey } } }),
    "bad number": async (f) => write(f, { ...base(f), projects: { query: { ...base(f).projects.query, projectNumber: "012" }, idp: base(f).projects.idp } }),
    "short key": async (f) => write(f, { ...base(f), projects: { query: { ...base(f).projects.query, apiKey: "short" }, idp: base(f).projects.idp } }),
    "relative adc": async (f) => write(f, { ...base(f), adcPath: "adc.json" }),
    "bad bucket": async (f) => write(f, { ...base(f), bucket: { name: "A" } }),
    "extra bucket key": async (f) => write(f, { ...base(f), bucket: { name: "some-bucket-name", extra: 1 } }),
    "a link": async (f) => { await rm(f.localPath); await symlink(f.adcPath, f.localPath); },
    "a link to a valid local file": async (f) => { const real = join(f.root, "real-local.json"); await writeFile(real, JSON.stringify(localInputs(f.adcPath)), { mode: 0o600 }); await rm(f.localPath); await symlink(real, f.localPath); },
    "a directory": async (f) => { await rm(f.localPath); await mkdir(f.localPath); },
    "missing": async (f) => rm(f.localPath),
  };
  void good;
  for (const [name, change] of Object.entries(cases)) {
    const f = await checkout(t);
    await change(f);
    await assert.rejects(f.entry(f.options), /local inputs file refused/, name);
    assert.equal(f.wire.length, 0, name);
    assert.deepEqual(await readdir(f.runs), ["sandbox-locks"], name);
  }
});

test("the ledger and the runs and lock directories must be private and plain, as for the stage 3 entry", async (t) => {
  const EXPECTED_REFUSAL = { "ledger group writable": /owner ledger refused|approval/, "ledger missing": /owner ledger refused/, "lock dir shared": /lock directory refused/, "runs dir shared": /runs directory refused/, "run directory exists": /run directory exists/, "legacy lock": /legacy shared lock exists/ };
  const cases = {
    "ledger group writable": async (f) => chmod(join(f.root, "docs.local", "instructions", "owner-decisions.md"), 0o664),
    "ledger missing": async (f) => rm(join(f.root, "docs.local", "instructions", "owner-decisions.md")),
    "lock dir shared": async (f) => chmod(join(f.runs, "sandbox-locks"), 0o750),
    "runs dir shared": async (f) => chmod(f.runs, 0o755),
    "run directory exists": async (f) => mkdir(join(f.runs, `storage-rules-prep-${runId}`), { mode: 0o700 }),
    "legacy lock": async (f) => writeFile(join(f.runs, "sandbox-ledger.jsonl.lock"), "{}\n", { mode: 0o600 }),
  };
  for (const [name, change] of Object.entries(cases)) {
    const f = await checkout(t);
    await change(f);
    let result = "ran";
    try { await f.entry(f.options); } catch (error) { result = error.message; }
    assert.match(result, EXPECTED_REFUSAL[name], name);
    assert.equal(f.wire.length, 0, name);
  }
});

test("the binding is a closed record for a main checkout, the real request function, a clock and git", async (t) => {
  const f = await checkout(t);
  const good = { root: f.root, codeRoot, requestImpl() {}, clock, git: async () => "" };
  assert.doesNotThrow(() => bindPrepEntry(good));
  for (const bad of [null, {}, { ...good, extra: 1 }, { root: f.root, codeRoot, requestImpl() {}, clock }, { ...good, codeRoot: 5 }, { ...good, git: 5 }, { ...good, requestImpl: 5 }, { ...good, root: 5 }, { ...good, clock: { nowSeconds() {} } }, { ...good, root: join(f.root, "docs.local") }]) {
    assert.throws(() => bindPrepEntry(bad), /invalid entry binding|entry root is not a main checkout|main repository root not found/);
  }
});

test("a global revocation stops the reads when it is written after the decision row, however many status lines cite the packet after it, and not when it came before", async (t) => {
  const global = "- 2026-09-30 | 全体 | decision=REVOKED; すべての本番送信承認を取り消す | オーナー（ローカル試験） | note.md";
  const status = `- 2026-09-30 | STORAGE-RULES ${PACKET_NAME} status | packetSha256=${packet.packetSha256}; outcome=noted | note.md`;
  const decision = ledger.split("\n").at(-1);
  const named = "- 2026-09-30 | 全体 | decision=REVOKED; すべてのレーン（FS-TRANSACTIONを含む）を取り消す | オーナー（ローカル試験） | note.md";
  for (const [name, text] of [["after", `${ledger}\n${global}`], ["after with a status line", `${ledger}\n${global}\n${status}`], ["after, naming another lane", `${ledger}\n${named}`], ["after a re-approval, again", `${ledger}\n${global}\n${decision}\n${global}`]]) {
    const f = await checkout(t, { ledgerText: text });
    await assert.rejects(f.entry(f.options), /approval revoked/, name);
    assert.equal(f.wire.length, 0, name);
  }
  // Before the decision row, or superseded by a later decision row, it does not stop the reads.
  for (const [name, text] of [["before", `${global}\n${ledger}`], ["superseded", `${ledger}\n${global}\n${decision}\n${status}`]]) {
    const f = await checkout(t, { ledgerText: text });
    assert.equal((await f.entry(f.options)).status, "finished", name);
  }
});
