import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { assembleInputs, keyFacts, keyListRequest, keyStringMatches, KEY_LIST_IDS, OWNER_TOKEN_ID, PREP_IDS, prepCorpus, selectKey, standardRows } from "./storage-rules-prep/plan.mjs";
import { createPrepTargets } from "./storage-rules-prep/targets.mjs";
import { createPrepHttpsTransport } from "./storage-rules-prep/transport.mjs";
import { PREP_KEYS, createHttpsRequestDouble, prepInputsFor } from "./storage-rules-prep-support.mjs";
import { API_KEYS, BUCKET, KEY_TARGETS, NUMBERS, SUBJECT, privatePacket } from "./storage-rules-runner-support.mjs";

const closure = JSON.parse(readFileSync(new URL("../../spec/compatibility/closure/STORAGE-RULES.json", import.meta.url), "utf8"));
const commit = "a".repeat(40);
const params = { bucket: BUCKET, queryProjectNumber: NUMBERS.query, idpProjectNumber: NUMBERS.idp, sourceCommit: commit, expectedKeyIds: { query: "fireemu-query-auth-20260925", idp: null } };
const sha = (text) => createHash("sha256").update(text).digest("hex");

test("thirteen declared requests, each with a distinct preflight ID, ordered token, identity, lists, key strings, bucket, database, IAM, permissions", () => {
  assert.equal(PREP_IDS.length, 13);
  assert.equal(new Set(PREP_IDS).size, 13);
  assert.ok(PREP_IDS.every((id) => /^preflight\/[A-Za-z0-9._/-]{1,150}$/.test(id)));
  assert.deepEqual(PREP_IDS.slice(0, 6), [OWNER_TOKEN_ID, "preflight/owner/identity", KEY_LIST_IDS.query, KEY_LIST_IDS.idp, "preflight/query/key-string", "preflight/idp/key-string"]);
  assert.equal(Object.isFrozen(PREP_IDS), true);
  assert.deepEqual(KEY_LIST_IDS, { query: "preflight/query/key-list", idp: "preflight/idp/key-list" });
});

test("the corpus digest follows every input the requests are built from, and the key IDs of the key-string reads are placeholders in it", () => {
  const base = prepCorpus(closure, params);
  assert.equal(base.list.length, 13);
  assert.match(base.sha256, /^[0-9a-f]{64}$/);
  assert.deepEqual(base.expectedKeyIds, { query: "fireemu-query-auth-20260925", idp: null });
  assert.equal(base.sha256, sha(JSON.stringify({ expectedKeyIds: base.expectedKeyIds, list: base.list })));
  assert.equal(prepCorpus(closure, params).sha256, base.sha256);
  for (const change of [{ bucket: "another-bucket-name" }, { queryProjectNumber: "333333333333" }, { idpProjectNumber: "444444444444" }, { sourceCommit: "b".repeat(40) }, { expectedKeyIds: { query: "another-key", idp: null } }, { expectedKeyIds: { query: "fireemu-query-auth-20260925", idp: "an-idp-key" } }, { expectedKeyIds: { query: null, idp: null } }]) {
    const moved = prepCorpus(closure, { ...params, ...change });
    // The source commit does not appear in a request, so it does not move the corpus; every other input (including the expected keys) does.
    assert.equal(moved.sha256 !== base.sha256, !("sourceCommit" in change), JSON.stringify(change));
  }
  const urls = Object.fromEntries(base.list.map((row) => [row.id, `${row.method} ${row.url}`]));
  assert.equal(urls[OWNER_TOKEN_ID], "POST https://oauth2.googleapis.com/token");
  assert.equal(urls[KEY_LIST_IDS.query], `GET https://apikeys.googleapis.com/v2/projects/${NUMBERS.query}/locations/global/keys`);
  assert.equal(urls[KEY_LIST_IDS.idp], `GET https://apikeys.googleapis.com/v2/projects/${NUMBERS.idp}/locations/global/keys`);
  assert.match(urls["preflight/query/key-string"], /\/keys\/00000000-0000-4000-8000-000000000001\/keyString$/);
  assert.equal(JSON.stringify(base.list).includes(PREP_KEYS.query), false);
  for (const bad of [{ query: "Bad", idp: null }, { query: "a_b", idp: null }, { query: "1abc", idp: null }, { query: "", idp: null }, { query: 5, idp: null }, { query: null, idp: "a/b" }, { query: `a${"b".repeat(63)}`, idp: null }]) assert.throws(() => prepCorpus(closure, { ...params, expectedKeyIds: bad }), /invalid expected key ID/, JSON.stringify(bad));
  assert.deepEqual(prepCorpus(closure, { ...params, expectedKeyIds: undefined }).expectedKeyIds, { query: null, idp: null });
  assert.deepEqual(base.list.find((row) => row.id === "preflight/query/iam").body, { json: { options: { requestedPolicyVersion: 3 } } });
  // The stage 3 preflight rows are the source of the standard requests.
  const { rows } = standardRows(closure, params);
  assert.equal(rows.size, 11);
  assert.equal(Object.isFrozen(base), true);
});

test("a key list request is an exact GET of one project's list", () => {
  const request = keyListRequest("query", NUMBERS.query);
  assert.deepEqual({ ...request }, { id: KEY_LIST_IDS.query, project: "fireemu-oracle-query", method: "GET", url: `https://apikeys.googleapis.com/v2/projects/${NUMBERS.query}/locations/global/keys`, credential: "admin" });
  assert.equal(keyListRequest("idp", NUMBERS.idp).project, "fireemu-oracle-idp");
  for (const [project, number] of [["other", "1"], ["query", "0"], ["query", "012"], ["query", "1/../2"], ["query", "1?x=1"], ["query", 5], ["query", "1".repeat(21)]]) assert.throws(() => keyListRequest(project, number), /invalid key list request/, `${project} ${number}`);
  assert.equal(Object.isFrozen(request), true);
});

test("the expected key is chosen from the live keys and the others are counted; without an expected key exactly one live key is needed; anything else is a stop", () => {
  const key = (id, extra = {}) => ({ name: `projects/${NUMBERS.query}/locations/global/keys/${id}`, uid: "u", ...extra });
  const browser = key("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d");
  const dedicated = key("fireemu-query-auth-20260925");
  const chosen = selectKey({ keys: [browser, dedicated] }, NUMBERS.query, "fireemu-query-auth-20260925");
  assert.deepEqual([chosen.keyId, chosen.otherLiveKeys], ["fireemu-query-auth-20260925", 1]);
  assert.equal(chosen.item, dedicated);
  assert.equal(Object.isFrozen(chosen), true);
  assert.equal(selectKey({ keys: [dedicated] }, NUMBERS.query, "fireemu-query-auth-20260925").otherLiveKeys, 0);
  assert.equal(selectKey({ keys: [key("old-key", { deleteTime: "2026-01-01T00:00:00Z" }), browser, dedicated] }, NUMBERS.query, "fireemu-query-auth-20260925").otherLiveKeys, 1);
  assert.equal(selectKey({ keys: [dedicated, browser] }, NUMBERS.query, "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d").keyId, "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d");
  // Without an expected key the project must have exactly one live key, of either shape of ID.
  assert.equal(selectKey({ keys: [browser] }, NUMBERS.query).keyId, "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d");
  assert.equal(selectKey({ keys: [dedicated, key("old", { deleteTime: "x" })] }, NUMBERS.query, null).keyId, "fireemu-query-auth-20260925");
  const stops = [
    [{ keys: [browser, dedicated], nextPageToken: "n" }, "fireemu-query-auth-20260925", /paged or malformed/], [{ keys: [dedicated], nextPageToken: "" }, null, /paged or malformed/], [null, null, /paged or malformed/], [[], null, /paged or malformed/], [{ keys: "x" }, null, /paged or malformed/],
    [{}, null, /found 0/], [{ keys: [] }, null, /found 0/], [{ keys: [browser, dedicated] }, null, /found 2/], [{ keys: [key("x-key", { deleteTime: "x" })] }, null, /found 0/], [{ keys: [null] }, null, /found 0/],
    [{ keys: [browser] }, "fireemu-query-auth-20260925", /not one live key/], [{ keys: [] }, "fireemu-query-auth-20260925", /not one live key/], [{}, "fireemu-query-auth-20260925", /not one live key/], [{ keys: [key("fireemu-query-auth-20260925", { deleteTime: "x" })] }, "fireemu-query-auth-20260925", /not one live key/], [{ keys: [dedicated, dedicated] }, "fireemu-query-auth-20260925", /found 2/],
    [{ keys: [{ name: `projects/${NUMBERS.idp}/locations/global/keys/fireemu-query-auth-20260925` }] }, "fireemu-query-auth-20260925", /not one live key/], [{ keys: [{ name: 5 }, {}] }, "fireemu-query-auth-20260925", /not one live key/],
    [{ keys: [dedicated] }, "Bad", /not a key ID/], [{ keys: [dedicated] }, "a_b", /not a key ID/], [{ keys: [dedicated] }, "a.b", /not a key ID/], [{ keys: [dedicated] }, "1abc", /not a key ID/], [{ keys: [dedicated] }, 5, /not a key ID/], [{ keys: [dedicated] }, "", /not a key ID/], [{ keys: [dedicated] }, `a${"b".repeat(63)}`, /not a key ID/], [{ keys: [dedicated] }, "a/b", /not a key ID/],
    [{ keys: [{ name: `projects/${NUMBERS.idp}/locations/global/keys/${PREP_KEYS.query}` }] }, null, /not the expected resource/], [{ keys: [{ name: `projects/${NUMBERS.query}/locations/global/keys/Abc` }] }, null, /not the expected resource/],
    [{ keys: [{ name: `projects/${NUMBERS.query}/locations/global/keys/1abc` }] }, null, /not the expected resource/], [{ keys: [{ name: `projects/${NUMBERS.query}/locations/global/keys/${"0".repeat(36)}` }] }, null, /not the expected resource/], [{ keys: [{}] }, null, /not the expected resource/], [{ keys: [{ name: 5 }] }, null, /not the expected resource/],
    [{ keys: [{ name: `projects/${NUMBERS.query}/locations/global/keys/` }] }, null, /not the expected resource/], [{ keys: [{ name: `projects/${NUMBERS.query}/locations/global/keys/a/b` }] }, null, /not the expected resource/],
  ];
  for (const [body, expected, message] of stops) assert.throws(() => selectKey(body, NUMBERS.query, expected), (error) => message.test(error.message) && error.stopCode === "preflight-failed", `${JSON.stringify(body)} ${expected}`);
});

test("a key's facts must be a live key that is not method restricted, allows both sign-in services in a strictly ascending list, and has a restriction digest", () => {
  const digest = "d".repeat(64);
  const facts = { uid: "u", deleted: false, apiTargets: ["a.googleapis.com", "identitytoolkit.googleapis.com", "securetoken.googleapis.com"], otherRestrictions: ["browserKeyRestrictions"], methodRestricted: false, restrictionsSha256: digest };
  assert.deepEqual(keyFacts(facts), { keyUid: "u", apiTargets: facts.apiTargets, restrictionsSha256: digest });
  assert.notEqual(keyFacts(facts).apiTargets, facts.apiTargets);
  // Another restriction (a Browser key's) is fine: it is recorded through the digest, not refused.
  assert.equal(keyFacts({ ...facts, otherRestrictions: [] }).keyUid, "u");
  const many = (count) => [...Array.from({ length: count }, (_, index) => `s${String(index).padStart(2, "0")}.googleapis.com`), "identitytoolkit.googleapis.com", "securetoken.googleapis.com"].sort();
  for (const change of [{ deleted: true }, { methodRestricted: true }, { uid: "" }, { uid: 5 }, { apiTargets: "x" }, { apiTargets: ["a", "a"] }, { apiTargets: ["securetoken.googleapis.com", "identitytoolkit.googleapis.com"] }, { apiTargets: ["identitytoolkit.googleapis.com"] }, { apiTargets: ["securetoken.googleapis.com"] }, { apiTargets: [] }, { restrictionsSha256: undefined }, { restrictionsSha256: "short" }, { restrictionsSha256: "D".repeat(64) }, { restrictionsSha256: 5 }, { apiTargets: many(63) }]) {
    assert.throws(() => keyFacts({ ...facts, ...change }), /key restrictions|key targets|sign-in services/, JSON.stringify(change));
  }
  assert.equal(keyFacts({ ...facts, apiTargets: many(62) }).apiTargets.length, 64);
});

test("a key string matches only the local one, compared as digests", () => {
  assert.equal(keyStringMatches("K".repeat(39), "K".repeat(39)), true);
  for (const [reported, local] of [["K".repeat(39), "L".repeat(39)], ["K".repeat(39), "K".repeat(38)], [5, "K"], ["K", null], [undefined, undefined]]) assert.equal(keyStringMatches(reported, local), false);
});

test("the private inputs are assembled from the reads, validated as stage 3 inputs, and refuse a key string that is not the local one", () => {
  const queryFacts = { keyUid: "query-key-uid", apiTargets: KEY_TARGETS.query, restrictionsSha256: privatePacket("/x/adc.json").projects.query.restrictionsSha256 };
  const idpFacts = { keyUid: "idp-key-uid", apiTargets: KEY_TARGETS.idp, restrictionsSha256: privatePacket("/x/adc.json").projects.idp.restrictionsSha256 };
  const input = {
    adcPath: "/x/adc.json", local: { numbers: NUMBERS, keys: API_KEYS },
    identity: { email: "owner@example.test", subject: SUBJECT },
    query: { keyId: PREP_KEYS.query, facts: queryFacts, keyString: API_KEYS.query }, idp: { keyId: PREP_KEYS.idp, facts: idpFacts, keyString: API_KEYS.idp },
    bucket: { name: BUCKET, facts: { location: "US-CENTRAL1", uniformBucketLevelAccess: true }, iamSha256: privatePacket("/x/adc.json").bucket.iamPolicySha256 },
    database: { locationId: "us-central1", type: "FIRESTORE_NATIVE" }, queryIamSha256: privatePacket("/x/adc.json").queryProjectIamPolicySha256,
  };
  assert.deepEqual(assembleInputs(input), prepInputsFor("/x/adc.json"));
  assert.throws(() => assembleInputs({ ...input, query: { ...input.query, keyString: "Z".repeat(39) } }), /local key string/);
  assert.throws(() => assembleInputs({ ...input, idp: { ...input.idp, keyString: "Z".repeat(39) } }), /local key string/);
  // A value stage 3 would refuse makes the assembly refuse.
  assert.throws(() => assembleInputs({ ...input, bucket: { ...input.bucket, iamSha256: "not a digest" } }));
  assert.throws(() => assembleInputs({ ...input, adcPath: "relative.json" }));
});

test("the targets prepare each request from an exact source and verify only what they issued", () => {
  const targets = createPrepTargets({ closure, params, digestSalt: "7".repeat(64) });
  const identity = targets.prepareStandard("preflight/owner/identity");
  assert.equal(identity.spec.url, "https://www.googleapis.com/oauth2/v2/userinfo");
  assert.equal(targets.verify(identity), true);
  const list = targets.prepareList("query");
  assert.equal(list.spec.url, `https://apikeys.googleapis.com/v2/projects/${NUMBERS.query}/locations/global/keys`);
  assert.deepEqual([list.spec.method, list.spec.body, list.credential, list.project], ["GET", null, "admin", "fireemu-oracle-query"]);
  assert.equal(targets.verify(list), true);
  assert.equal(targets.prepareList("idp").project, "fireemu-oracle-idp");
  // A copy, an edited spec, a foreign object and a list object with another URL are not verified.
  assert.equal(targets.verify({ ...list }), false);
  assert.equal(targets.verify({ ...identity }), false);
  assert.equal(targets.verify(null), false);
  assert.equal(targets.verify({}), false);
  const other = createPrepTargets({ closure, params, digestSalt: "8".repeat(64) });
  assert.equal(other.verify(list), false);
  assert.equal(other.verify(identity), false);
  // Standard requests exclude the lists, the key strings and the token; unknown IDs are refused.
  for (const id of [OWNER_TOKEN_ID, KEY_LIST_IDS.query, KEY_LIST_IDS.idp, "preflight/query/key-string", "preflight/idp/key-string", "preflight/query/project", "preflight/rulesets-list/entry/1", "nope"]) assert.throws(() => targets.prepareStandard(id), /not a standard request/, id);
  for (const project of ["other", "", undefined]) assert.throws(() => targets.prepareList(project), /invalid key list request/);
  // Every standard request of the corpus prepares and verifies.
  for (const id of PREP_IDS.filter((entry) => !["preflight/auth/owner-token", "preflight/query/key-list", "preflight/idp/key-list", "preflight/query/key-string", "preflight/idp/key-string"].includes(entry))) assert.equal(targets.verify(targets.prepareStandard(id)), true, id);
});

test("the key-string reads are prepared only after the two key IDs are learnt, once, and for those IDs", () => {
  const targets = createPrepTargets({ closure, params, digestSalt: "7".repeat(64) });
  const ids = { query: PREP_KEYS.query, idp: PREP_KEYS.idp };
  const query = targets.prepareKeyString("query", ids);
  assert.equal(query.spec.url, `https://apikeys.googleapis.com/v2/projects/${NUMBERS.query}/locations/global/keys/${PREP_KEYS.query}/keyString`);
  assert.equal(targets.verify(query), true);
  const idp = targets.prepareKeyString("idp", ids);
  assert.equal(idp.spec.url, `https://apikeys.googleapis.com/v2/projects/${NUMBERS.idp}/locations/global/keys/${PREP_KEYS.idp}/keyString`);
  assert.equal(idp.project, "fireemu-oracle-idp");
  assert.throws(() => targets.prepareKeyString("query", { query: PREP_KEYS.idp, idp: PREP_KEYS.query }), /key IDs changed/);
  for (const bad of [null, {}, { query: PREP_KEYS.query }, { query: "Bad", idp: "Worse" }, { query: "a/b", idp: PREP_KEYS.idp }, { query: 5, idp: PREP_KEYS.idp }, { query: PREP_KEYS.query, idp: PREP_KEYS.query }]) {
    const fresh = createPrepTargets({ closure, params, digestSalt: "7".repeat(64) });
    assert.throws(() => fresh.prepareKeyString("query", bad), /invalid key IDs/, JSON.stringify(bad));
  }
  // Before the IDs are learnt, a key-string object of another builder is not verified.
  const other = createPrepTargets({ closure, params, digestSalt: "7".repeat(64) });
  assert.equal(other.verify(query), false);
});

test("the prep transport allows the key list route for a plain GET only, and every stage 3 route as before", () => {
  const transport = createPrepHttpsTransport({ requestImpl() { throw new Error("must not send"); } });
  const list = (over = {}) => ({ url: `https://apikeys.googleapis.com/v2/projects/${NUMBERS.query}/locations/global/keys`, method: "GET", headers: { authorization: "Bearer x".padEnd(30, "x"), "x-goog-user-project": "fireemu-oracle-query" }, body: null, ...over });
  assert.doesNotThrow(() => transport.validate(list()));
  for (const bad of [list({ method: "POST" }), list({ url: `${list().url}?pageSize=100` }), list({ url: `${list().url}/`, }), list({ url: "https://apikeys.googleapis.com/v2/projects/abc/locations/global/keys" }), list({ url: "https://apikeys.googleapis.com/v2/projects/0/locations/global/keys" }), list({ url: "https://apikeys.googleapis.com/v2/projects/1/locations/global/keys/../keys" }), list({ url: "http://apikeys.googleapis.com/v2/projects/1/locations/global/keys" }), list({ url: "https://apikeys.googleapis.com/v2/projects/1/locations/us/keys" }), list({ body: Buffer.from("x") })]) {
    assert.throws(() => transport.validate(bad), (error) => error.notSent === true, JSON.stringify(bad.url));
  }
  // Keys are reachable by a UUID or a custom ID of the documented shape only, with or without keyString.
  const keyUrl = (id, tail = "") => `https://apikeys.googleapis.com/v2/projects/${NUMBERS.query}/locations/global/keys/${id}${tail}`;
  for (const id of ["fireemu-query-auth-20260925", "a", `a${"b".repeat(62)}`, PREP_KEYS.idp]) for (const tail of ["", "/keyString"]) assert.doesNotThrow(() => transport.validate({ url: keyUrl(id, tail), method: "GET", headers: {}, body: null }), `${id}${tail}`);
  for (const id of [`a${"b".repeat(63)}`, "1abc", "Abc", "a_b", "a.b", "", "0000000A-0000-4000-8000-00000000000A"]) assert.throws(() => transport.validate({ url: keyUrl(id), method: "GET", headers: {}, body: null }), (error) => error.notSent === true, id);
  // The stage 3 exact routes still hold, and a list POST or an other-origin list is refused.
  assert.doesNotThrow(() => transport.validate({ url: `https://apikeys.googleapis.com/v2/projects/${NUMBERS.query}/locations/global/keys/${PREP_KEYS.query}/keyString`, method: "GET", headers: {}, body: null }));
  assert.throws(() => transport.validate({ url: `https://example.com/v2/projects/${NUMBERS.query}/locations/global/keys`, method: "GET", headers: {}, body: null }), (error) => error.notSent === true);
});

test("the request double answers what it is told and records what it saw", async () => {
  const log = [];
  const impl = createHttpsRequestDouble((spec) => ({ status: 200, rawHeaders: ["Content-Type", "application/json"], bytes: Buffer.from(JSON.stringify({ url: spec.url })) }), log);
  const transport = createPrepHttpsTransport({ requestImpl: impl });
  const answer = await transport.send({ url: `https://apikeys.googleapis.com/v2/projects/${NUMBERS.query}/locations/global/keys`, method: "GET", headers: { accept: "application/json" }, body: null });
  assert.equal(answer.status, 200);
  assert.equal(log.length, 1);
});

test("the pin printer prints the four pins of a clean checkout and refuses an unclean one, a bad file and bad arguments without echoing the file", async (t) => {
  const { mkdtemp, mkdir, rm, writeFile, chmod } = await import("node:fs/promises");
  const { join } = await import("node:path");
  const { runPrepPrintPins } = await import("./storage-rules-prep/print-pins.mjs");
  const { prepCodeDigests } = await import("./storage-rules-prep/pins.mjs");
  const { scratchCode, localInputs } = await import("./storage-rules-prep-support.mjs");
  const root = scratchCode(JSON.stringify(closure));
  t.after(() => rm(root, { recursive: true, force: true }));
  const dir = await mkdtemp("/private/tmp/storage-rules-prep-pins-");
  t.after(() => rm(dir, { recursive: true, force: true }));
  const write = async (name, value, mode = 0o600) => { const path = join(dir, name); await writeFile(path, typeof value === "string" ? value : JSON.stringify(value), { mode }); await chmod(path, mode); return path; };
  const good = await write("local.json", localInputs("/x/adc.json"));
  const commit = "d".repeat(40);
  const gitFor = (status = "", extra = "", extraPrep = "") => async (where, args) => { assert.equal(where, root); return args[0] === "rev-parse" ? `${commit}\n` : args.includes("--ignored") ? (args.includes("conformance/src/storage-rules-prep") ? extraPrep : extra) : status; };
  const run = async (args, git) => { const seen = { out: "", err: "" }; const code = await runPrepPrintPins({ args, codeRoot: root, git, out: (text) => { seen.out += text; }, err: (text) => { seen.err += text; } }); return { code, ...seen }; };
  const ok = await run([good], gitFor());
  assert.equal(ok.code, 0);
  assert.equal(ok.err, "");
  const digests = await prepCodeDigests(root);
  const corpus = prepCorpus(closure, { bucket: BUCKET, queryProjectNumber: NUMBERS.query, idpProjectNumber: NUMBERS.idp, sourceCommit: commit, expectedKeyIds: { query: PREP_KEYS.query, idp: null } });
  assert.deepEqual(JSON.parse(ok.out), { sourceCommit: commit, runnerSha256: digests.runnerSha256, manifestSha256: corpus.sha256, fixtureSchemaSha256: digests.fixtureSchemaSha256 });
  assert.match(ok.out, /^\{\n  "sourceCommit": "d{40}",\n/);
  for (const [git, message] of [[gitFor(" M x\n"), /working tree not clean/], [gitFor("", "?? conformance/src/storage-rules/driver.mjs\n"), /untracked or ignored runner files/], [gitFor("", "", "?? conformance/src/storage-rules-prep/x.mjs\n"), /untracked or ignored runner files/]]) {
    const refused = await run([good], git);
    assert.equal(refused.code, 1);
    assert.equal(refused.out, "");
    assert.match(refused.err, message);
  }
  for (const args of [[], [good, "extra"]]) { const usage = await run(args, gitFor()); assert.deepEqual([usage.code, usage.out], [2, ""]); assert.match(usage.err, /usage/); }
  const bad = await write("bad.json", { ...localInputs("/x/adc.json"), extra: "SECRET-VALUE-XYZ" });
  const failed = await run([bad], gitFor());
  assert.deepEqual([failed.code, failed.out], [1, ""]);
  assert.match(failed.err, /local inputs file refused/);
  assert.equal(failed.err.includes("SECRET-VALUE-XYZ"), false);
  void mkdir;
});

test("the key ID grammar is the one the stage 3 private inputs accept, for the same candidates", async () => {
  const { parsePrivateInputs } = await import("./storage-rules/private-inputs.mjs");
  const { KEY_ID } = await import("./storage-rules-prep/plan.mjs");
  const base = privatePacket("/x/adc.json");
  const candidates = ["fireemu-query-auth-20260925", "a", "a1", `a${"b".repeat(62)}`, `a${"b".repeat(63)}`, "abc-def", "-abc", "1abc", "Abc", "aBc", "a_b", "a.b", "a b", "a/b", "", "00000000-0000-4000-8000-000000000001", "ffffffff-ffff-ffff-ffff-ffffffffffff", "0000000A-0000-4000-8000-00000000000A", "00000000-0000-4000-8000-00000000000", "00000000-0000-4000-8000-0000000000012", "abc$", "abc\n"];
  for (const id of candidates) {
    let stage3 = true;
    try { parsePrivateInputs({ ...base, projects: { ...base.projects, query: { ...base.projects.query, apiKeyId: id } } }); } catch { stage3 = false; }
    assert.equal(KEY_ID.test(id), stage3, JSON.stringify(id));
  }
});
