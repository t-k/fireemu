import assert from "node:assert/strict";
import test from "node:test";
import { ENTRY_RULESETS } from "./storage-rules/entry-rulesets.mjs";
import { judgeAnswer, JUDGE_KINDS } from "./storage-rules-restore/judge.mjs";
import { allIdsOf, preflightIdsOf, restoreCorpus, restoreRequests } from "./storage-rules-restore/plan.mjs";
import { parseState, stateSha256 } from "./storage-rules-restore/state.mjs";
import { createRestoreTargets } from "./storage-rules-restore/targets.mjs";
import { PRODUCTION, rawOf } from "./storage-rules-production-fixtures.mjs";
import { BUCKET, PREFIX, STATE, ownerDigest } from "./storage-rules-restore-support.mjs";

const state = parseState(STATE);
const json = (body, status = 200, type = "application/json; charset=UTF-8") => ({ status, rawHeaders: ["Content-Type", type], bytes: Buffer.from(JSON.stringify(body)) });
const request = (id) => restoreRequests(state).find((entry) => entry.id === id) ?? assert.fail(id);

test("the expected state is a closed, sorted record inside the run's namespace that names none of the kept rulesets", () => {
  assert.deepEqual(JSON.parse(JSON.stringify(state)), STATE);
  assert.equal(Object.isFrozen(state) && Object.isFrozen(state.objects) && Object.isFrozen(state.objects[0]) && Object.isFrozen(state.accounts) && Object.isFrozen(state.rulesets), true);
  const clone = () => structuredClone(STATE);
  const spoiled = {
    "extra field": { ...clone(), extra: 1 }, "no field": (({ accounts, ...rest }) => rest)(clone()), "version": { ...clone(), schemaVersion: 2 }, "run ID": { ...clone(), runId: "Bad Run" }, "invalid run ID with its own prefix": { ...clone(), runId: "Bad Run", runPrefix: "STORAGE-RULES/Bad Run/" }, "run ID a number with its own prefix": { ...clone(), runId: 5, runPrefix: "STORAGE-RULES/5/" }, "run ID too long": { ...clone(), runId: "a".repeat(49), runPrefix: `STORAGE-RULES/${"a".repeat(49)}/` }, "prefix": { ...clone(), runPrefix: "STORAGE-RULES/other/" },
    "bucket": { ...clone(), bucket: "Bad" }, "not arrays": { ...clone(), objects: {} }, "too many objects": { ...clone(), objects: Array.from({ length: 51 }, (_, index) => ({ name: `${PREFIX}${String(index).padStart(3, "0")}`, generation: "1" })) },
    "too many accounts": { ...clone(), accounts: Array.from({ length: 11 }, (_, index) => `storage-rules-${STATE.runId}-a${String.fromCharCode(97 + index)}`) }, "too many rulesets": { ...clone(), rulesets: Array.from({ length: 11 }, (_, index) => `projects/fireemu-oracle-query/rulesets/r${String(index).padStart(2, "0")}`) },
    "object outside the prefix": { ...clone(), objects: [{ name: "STORAGE-RULES/other/x", generation: "1" }] }, "object with a parent path": { ...clone(), objects: [{ name: `${PREFIX}../x`, generation: "1" }] }, "object ending in a slash": { ...clone(), objects: [{ name: `${PREFIX}dir/`, generation: "1" }] },
    "object with a space": { ...clone(), objects: [{ name: `${PREFIX}a b`, generation: "1" }] }, "object with a long name": { ...clone(), objects: [{ name: `${PREFIX}${"a".repeat(512)}`, generation: "1" }] }, "object with an extra key": { ...clone(), objects: [{ name: `${PREFIX}a`, generation: "1", extra: 1 }] },
    "generation zero": { ...clone(), objects: [{ name: `${PREFIX}a`, generation: "0" }] }, "generation with a sign": { ...clone(), objects: [{ name: `${PREFIX}a`, generation: "-1" }] }, "generation a number": { ...clone(), objects: [{ name: `${PREFIX}a`, generation: 5 }] },
    "objects unsorted": { ...clone(), objects: [...STATE.objects].reverse() }, "objects duplicated": { ...clone(), objects: [STATE.objects[0], STATE.objects[0]] },
    "account of another run": { ...clone(), accounts: ["storage-rules-other-user-a"] }, "account unsorted": { ...clone(), accounts: [...STATE.accounts].reverse() }, "account a number": { ...clone(), accounts: [5] },
    "the kept storage ruleset": { ...clone(), rulesets: [ENTRY_RULESETS[0].name] }, "the kept firestore ruleset": { ...clone(), rulesets: [ENTRY_RULESETS[1].name, ...STATE.rulesets].sort() }, "a ruleset of another project": { ...clone(), rulesets: ["projects/other/rulesets/x"] },
    "rulesets unsorted": { ...clone(), rulesets: [...STATE.rulesets].reverse() }, "rulesets duplicated": { ...clone(), rulesets: [STATE.rulesets[0], STATE.rulesets[0]] },
  };
  for (const [name, value] of Object.entries(spoiled)) assert.throws(() => parseState(value), /invalid expected state/, name);
  for (const bad of [null, undefined, [], "x", 5, Object.assign(Object.create(null), clone())]) assert.throws(() => parseState(bad), /invalid expected state/);
  const empty = { objects: [], accounts: [], rulesets: [] };
  assert.doesNotThrow(() => parseState({ ...clone(), ...empty }));
  for (const [runId, prefix] of [["Bad Run", "STORAGE-RULES/Bad Run/"], [5, "STORAGE-RULES/5/"], ["a".repeat(49), `STORAGE-RULES/${"a".repeat(49)}/`], ["", "STORAGE-RULES//"]]) assert.throws(() => parseState({ ...clone(), ...empty, runId, runPrefix: prefix }), /invalid expected state/, String(runId).slice(0, 10));
  assert.throws(() => parseState({ ...clone(), ...empty, bucket: "Bad Bucket" }), /invalid expected state/);
});

test("the state digest moves with every part of the state", () => {
  const base = stateSha256(state);
  assert.match(base, /^[0-9a-f]{64}$/);
  assert.equal(stateSha256(parseState(structuredClone(STATE))), base);
  const changed = [
    { ...STATE, runId: "stage3-other", runPrefix: "STORAGE-RULES/stage3-other/", objects: [], accounts: [], rulesets: [] }, { ...STATE, bucket: "other-bucket.appspot.com" },
    { ...STATE, objects: STATE.objects.map((object, index) => (index === 0 ? { ...object, generation: "1" } : object)) }, { ...STATE, objects: STATE.objects.slice(1) }, { ...STATE, accounts: STATE.accounts.slice(1) }, { ...STATE, rulesets: STATE.rulesets.slice(1) },
  ].map((value) => stateSha256(parseState(value)));
  assert.equal(new Set([base, ...changed]).size, changed.length + 1);
});

test("the plan is 39 requests for this state: 13 preflight, 14 deletions and 12 verification reads, in that order", () => {
  const requests = restoreRequests(state);
  assert.equal(requests.length, 37);
  assert.equal(allIdsOf(state).length, 39);
  assert.equal(new Set(allIdsOf(state)).size, 39);
  assert.deepEqual(preflightIdsOf(state).slice(0, 5), ["preflight/auth/owner-token", "preflight/owner/identity", "preflight/release/bucket", "preflight/release/bucketless", "preflight/rulesets/list"]);
  assert.equal(preflightIdsOf(state).length, 13);
  assert.deepEqual(requests.filter((entry) => entry.phase === "normal").map((entry) => entry.id.split("/").slice(0, 2).join("/")).filter((id, index, all) => all.indexOf(id) === index), ["cleanup/object", "cleanup/account", "cleanup/ruleset", "verify/object", "verify/accounts", "verify/rulesets", "verify/release", "verify/objects"]);
  assert.deepEqual(requests.map((entry) => entry.phase), [...Array(11).fill("preflight"), ...Array(26).fill("normal")]);
  for (const entry of requests) { assert.ok(!entry.id.startsWith("recovery/")); assert.equal(entry.phase === "preflight", entry.id.startsWith("preflight/")); assert.ok(JUDGE_KINDS.includes(entry.kind), entry.kind); }
  assert.equal(Object.isFrozen(requests) && requests.every((entry) => Object.isFrozen(entry)), true);
  assert.deepEqual(allIdsOf(state).slice(0, 2), ["preflight/auth/owner-token", "preflight/owner/identity"]);
});

test("each request is exactly the read or the deletion it names: URL, method and body", () => {
  const object = (index) => `https://storage.googleapis.com/storage/v1/b/${BUCKET}/o/${encodeURIComponent(STATE.objects[index].name)}`;
  const body = (id) => (request(id).body === null ? null : request(id).body.toString("utf8"));
  assert.deepEqual([request("preflight/release/bucket").method, request("preflight/release/bucket").url], ["GET", `https://firebaserules.googleapis.com/v1/projects/fireemu-oracle-query/releases/firebase.storage/${BUCKET}`]);
  assert.equal(request("preflight/release/bucketless").url, "https://firebaserules.googleapis.com/v1/projects/fireemu-oracle-query/releases/firebase.storage");
  assert.deepEqual([request("preflight/rulesets/list").method, request("preflight/rulesets/list").url], ["GET", "https://firebaserules.googleapis.com/v1/projects/fireemu-oracle-query/rulesets?pageSize=100"]);
  STATE.objects.forEach((entry, index) => {
    assert.deepEqual([request(`preflight/object/${index}`).method, request(`preflight/object/${index}`).url, request(`preflight/object/${index}`).kind], ["GET", object(index), "object-present"]);
    assert.deepEqual([request(`cleanup/object/${index}/delete`).method, request(`cleanup/object/${index}/delete`).url, request(`cleanup/object/${index}/delete`).kind], ["DELETE", `${object(index)}?ifGenerationMatch=${entry.generation}`, "object-delete"]);
    assert.deepEqual([request(`verify/object/${index}/absent`).method, request(`verify/object/${index}/absent`).url, request(`verify/object/${index}/absent`).kind], ["GET", object(index), "object-absent"]);
  });
  assert.deepEqual([request("preflight/accounts/lookup").method, request("preflight/accounts/lookup").url, body("preflight/accounts/lookup")], ["POST", "https://identitytoolkit.googleapis.com/v1/projects/fireemu-oracle-query/accounts:lookup", JSON.stringify({ localId: STATE.accounts })]);
  STATE.accounts.forEach((uid, index) => assert.deepEqual([request(`cleanup/account/${index}/delete`).method, request(`cleanup/account/${index}/delete`).url, body(`cleanup/account/${index}/delete`)], ["POST", "https://identitytoolkit.googleapis.com/v1/projects/fireemu-oracle-query/accounts:delete", JSON.stringify({ localId: uid })]));
  STATE.rulesets.forEach((name, index) => assert.deepEqual([request(`cleanup/ruleset/${index}/delete`).method, request(`cleanup/ruleset/${index}/delete`).url, request(`cleanup/ruleset/${index}/delete`).body], ["DELETE", `https://firebaserules.googleapis.com/v1/${name}`, null]));
  assert.equal(request("verify/accounts/lookup").url, request("preflight/accounts/lookup").url);
  assert.equal(body("verify/accounts/lookup"), body("preflight/accounts/lookup"));
  assert.deepEqual([request("verify/rulesets/list").url, request("verify/rulesets/list").kind], [request("preflight/rulesets/list").url, "rulesets-kept"]);
  assert.equal(request("verify/objects/list").url, `https://storage.googleapis.com/storage/v1/b/${BUCKET}/o?prefix=${encodeURIComponent(PREFIX)}&maxResults=1`);
  // A deletion never names a kept ruleset, and an object deletion never leaves the run's namespace.
  for (const entry of restoreRequests(state).filter((item) => item.method === "DELETE")) {
    assert.ok(!ENTRY_RULESETS.some((kept) => entry.url.includes(kept.name)), entry.id);
    if (entry.url.includes("/storage/v1/")) assert.ok(decodeURIComponent(entry.url).includes(PREFIX), entry.id);
  }
});

test("the corpus lists every request and its digest moves with the state and the owner", () => {
  const corpus = restoreCorpus({ state, ownerEmailSha256: ownerDigest });
  assert.deepEqual(corpus.list.map((entry) => entry.id), allIdsOf(state));
  assert.equal(corpus.list.find((entry) => entry.id === "preflight/auth/owner-token").method, "POST");
  assert.equal(corpus.list.find((entry) => entry.id === "preflight/owner/identity").url, "https://www.googleapis.com/oauth2/v2/userinfo");
  assert.equal(corpus.list.every((entry) => (entry.bodySha256 === null) === (restoreRequests(state).find((item) => item.id === entry.id)?.body === null || entry.id.startsWith("preflight/auth") || entry.id === "preflight/owner/identity")), true);
  const digests = new Set([corpus.sha256]);
  digests.add(restoreCorpus({ state, ownerEmailSha256: "f".repeat(64) }).sha256);
  digests.add(restoreCorpus({ state: parseState({ ...STATE, objects: STATE.objects.slice(1) }), ownerEmailSha256: ownerDigest }).sha256);
  digests.add(restoreCorpus({ state: parseState({ ...STATE, accounts: STATE.accounts.slice(1) }), ownerEmailSha256: ownerDigest }).sha256);
  digests.add(restoreCorpus({ state: parseState({ ...STATE, rulesets: STATE.rulesets.slice(1) }), ownerEmailSha256: ownerDigest }).sha256);
  assert.equal(digests.size, 5);
  assert.equal(restoreCorpus({ state, ownerEmailSha256: ownerDigest }).sha256, corpus.sha256);
  for (const bad of ["abc", 5, undefined]) assert.throws(() => restoreCorpus({ state, ownerEmailSha256: bad }), /invalid corpus input/);
});

test("targets are built from exact sources: only planned IDs, verify accepts only what was issued, and the spec stays out of a serialization", () => {
  const targets = createRestoreTargets({ state, digestSalt: "s".repeat(64) });
  for (const entry of restoreRequests(state)) {
    const prepared = targets.prepare(entry.id);
    assert.deepEqual([prepared.rowId, prepared.credential, prepared.project, prepared.spec.method, prepared.spec.url, prepared.spec.body === null ? null : prepared.spec.body.toString("utf8")], [entry.id, "admin", "fireemu-oracle-query", entry.method, entry.url, entry.body === null ? null : entry.body.toString("utf8")]);
    assert.deepEqual({ ...prepared.spec.headers }, entry.body === null ? {} : { "content-type": "application/json; charset=utf-8" });
    assert.equal(targets.verify(prepared), true);
    assert.deepEqual(targets.request(entry.id), entry);
  }
  assert.equal(targets.prepareIdentity("x").spec.url, "https://www.googleapis.com/oauth2/v2/userinfo");
  for (const id of ["preflight/auth/owner-token", "preflight/owner/identity", "cleanup/object/99/delete", "", undefined]) { assert.throws(() => targets.prepare(id), /not a planned request/); assert.throws(() => targets.request(id), /not a planned request/); }
  const read = targets.prepare("preflight/release/bucket");
  const forged = { rowId: read.rowId, credential: read.credential, project: read.project, redacted: read.redacted, targetSha256: read.targetSha256 };
  Object.defineProperty(forged, "spec", { value: read.spec, enumerable: false });
  assert.equal(targets.verify(forged), false);
  for (const value of [null, undefined, {}, { ...read }, JSON.parse(JSON.stringify(read))]) assert.equal(targets.verify(value), false);
  assert.equal(createRestoreTargets({ state, digestSalt: "t".repeat(64) }).verify(read), false);
  assert.deepEqual(Object.keys(read), ["rowId", "credential", "project", "redacted", "targetSha256"]);
  assert.equal(JSON.stringify(read).includes("\"spec\""), false);
  assert.equal(Object.isFrozen(read) && Object.isFrozen(read.spec) && Object.isFrozen(read.spec.headers), true);
  assert.notEqual(createRestoreTargets({ state, digestSalt: "t".repeat(64) }).prepare("preflight/release/bucket").targetSha256, read.targetSha256);
  assert.notEqual(targets.prepare("preflight/release/bucketless").targetSha256, read.targetSha256);
});

test("the judges accept exactly what the cleanup needs, by the production bodies where they were recorded", () => {
  const ctx = (id) => ({ state, request: request(id) });
  const notFound = (extra = {}) => json({ error: { code: 404, message: "Requested entity was not found.", status: "NOT_FOUND", ...extra } }, 404);
  // A release is absent on Google's 404 only (the bodies stage 2c-pre recorded).
  assert.equal(judgeAnswer("release-absent", rawOf(PRODUCTION.releaseAbsent), ctx("preflight/release/bucket")), true);
  assert.equal(judgeAnswer("release-absent", rawOf(PRODUCTION.releaseBucketlessAbsent), ctx("preflight/release/bucketless")), true);
  for (const bad of [rawOf(PRODUCTION.releasePresent), json({}), json({ error: { code: 404, message: "x", status: "OTHER" } }, 404), json(notFound().bytes, 403), { status: 404, rawHeaders: [], bytes: Buffer.alloc(0) }]) assert.equal(judgeAnswer("release-absent", bad, ctx("preflight/release/bucket")), false);
  // The Rulesets: with the run's own on entry, and only the two kept ones after.
  const KEPT_TIMES = ["2026-09-25T11:08:54.358767Z", "2026-09-23T23:02:05.839536Z"];
  const entryList = (names, services = ["firebase.storage"], times = KEPT_TIMES) => json({ rulesets: [...ENTRY_RULESETS.map((entry, index) => ({ name: entry.name, createTime: times[index], metadata: { services: [...entry.services] } })), ...names.map((name) => ({ name, createTime: "2026-09-30T00:23:49.178351Z", metadata: { services } }))] });
  assert.equal(judgeAnswer("rulesets-with-run", entryList(STATE.rulesets), ctx("preflight/rulesets/list")), true);
  assert.equal(judgeAnswer("rulesets-with-run", entryList([...STATE.rulesets].reverse()), ctx("preflight/rulesets/list")), true);
  for (const bad of [entryList(STATE.rulesets.slice(1)), entryList([...STATE.rulesets, "projects/fireemu-oracle-query/rulesets/aaaaaaaa-0000-4000-8000-000000000000"]), entryList([]), entryList(STATE.rulesets, ["cloud.firestore"]), entryList(STATE.rulesets, ["firebase.storage"], ["2026-09-25T11:08:54.358767Z", "2026-09-23T23:02:05.839537Z"]), entryList(STATE.rulesets, ["firebase.storage"], ["2026-09-25T11:08:54.358768Z", "2026-09-23T23:02:05.839536Z"]), rawOf(PRODUCTION.rulesetList), json({ rulesets: STATE.rulesets.map((name) => ({ name, createTime: "2026-09-30T00:23:49Z" })) }), json({ ...JSON.parse(entryList(STATE.rulesets).bytes), nextPageToken: "t" }), json({ ...JSON.parse(entryList(STATE.rulesets).bytes), extra: 1 }), json({}, 500)]) assert.equal(judgeAnswer("rulesets-with-run", bad, ctx("preflight/rulesets/list")), false);
  const withRunTimes = (times) => json({ rulesets: [...JSON.parse(entryList([]).bytes).rulesets, ...STATE.rulesets.map((name, index) => ({ name, createTime: times[index], metadata: { services: ["firebase.storage"] } }))] });
  assert.equal(judgeAnswer("rulesets-with-run", withRunTimes(STATE.rulesets.map(() => "2026-09-30T00:23:49.178351Z")), ctx("preflight/rulesets/list")), true);
  for (const times of [[5, "t", "t", "t"], [undefined, "t", "t", "t"], ["t", null, "t", "t"]]) assert.equal(judgeAnswer("rulesets-with-run", withRunTimes(times), ctx("preflight/rulesets/list")), false, JSON.stringify(times));
  assert.equal(judgeAnswer("rulesets-kept", rawOf(PRODUCTION.rulesetList), ctx("verify/rulesets/list")), true);
  for (const bad of [entryList(STATE.rulesets), json({ rulesets: [] }), json({ rulesets: JSON.parse(rawOf(PRODUCTION.rulesetList).bytes.toString()).rulesets.slice(0, 1) }), entryList([], ["firebase.storage"], ["2026-09-25T11:08:54.358767Z", "2026-09-23T23:02:05.839537Z"]), entryList([], ["firebase.storage"], ["2026-09-25T11:08:54.358768Z", "2026-09-23T23:02:05.839536Z"]), json({ ...JSON.parse(entryList([]).bytes), nextPageToken: "t" }), json({ ...JSON.parse(entryList([]).bytes), extra: 1 }), json({ rulesets: JSON.parse(entryList([]).bytes).rulesets.map((entry) => ({ ...entry, createTime: 5 })) }), json({ rulesets: JSON.parse(entryList([]).bytes).rulesets.map((entry) => ({ name: entry.name, createTime: entry.createTime })) }), json({ rulesets: JSON.parse(entryList([]).bytes).rulesets.map((entry) => ({ ...entry, metadata: { services: [5] } })) }), json({ rulesets: "x" }), json({}, 500)]) assert.equal(judgeAnswer("rulesets-kept", bad, ctx("verify/rulesets/list")), false);
  // Objects: present with the journaled name and generation; absent as the JSON 404 production answers; deleted as a bodiless 204.
  const present = (index, delta = {}) => json({ kind: "storage#object", bucket: BUCKET, name: STATE.objects[index].name, generation: STATE.objects[index].generation, metageneration: "2", size: "4", ...delta });
  assert.equal(judgeAnswer("object-present", present(0), ctx("preflight/object/0")), true);
  for (const bad of [present(0, { generation: "1" }), present(0, { name: STATE.objects[1].name }), present(0, { bucket: "other" }), present(0, { kind: "storage#bucket" }), present(1), rawOf(PRODUCTION.objectMetadataAbsent), json({}, 500)]) assert.equal(judgeAnswer("object-present", bad, ctx("preflight/object/0")), false);
  assert.equal(judgeAnswer("object-present", present(1), ctx("preflight/object/1")), true);
  assert.equal(judgeAnswer("object-absent", rawOf(PRODUCTION.objectMetadataAbsent), ctx("verify/object/0/absent")), true);
  for (const bad of [rawOf(PRODUCTION.objectMediaAbsent), present(0), json({ error: { code: 404, message: "x", errors: [] } }, 404), json({ error: { code: 404, message: "x", errors: [{ reason: "other" }] } }, 404), json({ error: { code: 403, message: "x", errors: [{ reason: "notFound" }] } }, 403)]) assert.equal(judgeAnswer("object-absent", bad, ctx("verify/object/0/absent")), false);
  assert.equal(judgeAnswer("object-delete", { status: 204, rawHeaders: [], bytes: Buffer.alloc(0) }, ctx("cleanup/object/0/delete")), true);
  for (const bad of [{ status: 204, rawHeaders: [], bytes: Buffer.from("x") }, { status: 200, rawHeaders: [], bytes: Buffer.alloc(0) }, json({}, 412), json({}, 404), json({})]) assert.equal(judgeAnswer("object-delete", bad, ctx("cleanup/object/0/delete")), false);
  // A ruleset deletion is a 200 JSON object (its body was not recorded before; the list that follows decides). An account deletion is the recorded 200 with the kind alone (auth-account/admin/delete, step delete).
  assert.equal(judgeAnswer("ruleset-delete", json({}), ctx("cleanup/ruleset/0/delete")), true);
  for (const bad of [json([]), json("x"), json({}, 400), json({}, 404), { status: 200, rawHeaders: ["Content-Type", "text/plain"], bytes: Buffer.from("{}") }, { status: 200, rawHeaders: [], bytes: Buffer.alloc(0) }]) assert.equal(judgeAnswer("ruleset-delete", bad, ctx("cleanup/ruleset/0/delete")), false);
  assert.equal(judgeAnswer("account-delete", json({ kind: "identitytoolkit#DeleteAccountResponse" }), ctx("cleanup/account/0/delete")), true);
  for (const bad of [json({}), json({ kind: "identitytoolkit#DeleteAccountResponse", extra: 1 }), json({ kind: "identitytoolkit#GetAccountInfoResponse" }), json({ kind: "identitytoolkit#DeleteAccountResponse" }, 400), json({ error: { code: 400, message: "USER_NOT_FOUND" } }, 400), json([])]) assert.equal(judgeAnswer("account-delete", bad, ctx("cleanup/account/0/delete")), false);
  // Accounts: exactly the three uids before, none after.
  const users = (uids) => json({ kind: "identitytoolkit#GetAccountInfoResponse", users: uids.map((localId) => ({ localId, email: "x@example.test" })) });
  assert.equal(judgeAnswer("accounts-present", users(STATE.accounts), ctx("preflight/accounts/lookup")), true);
  for (const kind of ["identitytoolkit#Other", undefined]) assert.equal(judgeAnswer("accounts-present", json({ kind, users: STATE.accounts.map((localId) => ({ localId })) }), ctx("preflight/accounts/lookup")), false, String(kind));
  assert.equal(judgeAnswer("accounts-present", json({ kind: "identitytoolkit#GetAccountInfoResponse", users: STATE.accounts.map((localId, index) => (index === 1 ? { localId: 5 } : { localId })) }), ctx("preflight/accounts/lookup")), false);
  assert.equal(judgeAnswer("accounts-present", json({ kind: "identitytoolkit#GetAccountInfoResponse", users: [...STATE.accounts.map((localId) => ({ localId })).slice(0, 2), null] }), ctx("preflight/accounts/lookup")), false);
  assert.equal(judgeAnswer("accounts-present", users([...STATE.accounts].reverse()), ctx("preflight/accounts/lookup")), true);
  for (const bad of [users(STATE.accounts.slice(1)), users([...STATE.accounts, "storage-rules-other-x"]), users([]), json({ kind: "identitytoolkit#GetAccountInfoResponse" }), json({ users: [{ email: "x" }] }), json({ users: "x" }), json({}, 400), users([STATE.accounts[0], STATE.accounts[0], STATE.accounts[1]])]) assert.equal(judgeAnswer("accounts-present", bad, ctx("preflight/accounts/lookup")), false);
  // The recorded production answer for a lookup of deleted accounts (auth-account/admin/batch-delete, step lookup-after-force): the kind alone.
  assert.equal(judgeAnswer("accounts-absent", json({ kind: "identitytoolkit#GetAccountInfoResponse" }), ctx("verify/accounts/lookup")), true);
  for (const bad of [users(STATE.accounts.slice(0, 1)), json({ users: "x" }), json({}), json({ users: [] }), json({ kind: "identitytoolkit#GetAccountInfoResponse", users: [] }), json({ kind: "identitytoolkit#GetAccountInfoResponse", extra: 1 }), json({ kind: "identitytoolkit#Other" }), json({}, 400), json({ error: { code: 400, message: "USER_NOT_FOUND" } }, 400), json([]), json({ kind: "identitytoolkit#GetAccountInfoResponse" }, 404)]) assert.equal(judgeAnswer("accounts-absent", bad, ctx("verify/accounts/lookup")), false);
  // The prefix list is empty.
  assert.equal(judgeAnswer("objects-empty", json({ kind: "storage#objects" }), ctx("verify/objects/list")), true);
  assert.equal(judgeAnswer("objects-empty", json({ kind: "storage#objects", items: [], prefixes: [] }), ctx("verify/objects/list")), true);
  for (const bad of [json({ kind: "storage#objects", items: [{ name: "x" }] }), json({ kind: "storage#objects", prefixes: ["x/"] }), json({ kind: "storage#objects", nextPageToken: "t" }), json({}), json({ kind: "storage#bucket" }), json({ kind: "storage#objects" }, 403)]) assert.equal(judgeAnswer("objects-empty", bad, ctx("verify/objects/list")), false);
  // A judge that cannot run (no context) refuses, and never accepts.
  for (const [kind, raw] of [["object-present", present(0)], ["rulesets-with-run", entryList(STATE.rulesets)], ["accounts-present", users(STATE.accounts)]]) for (const context of [undefined, {}, { state: null }]) assert.equal(judgeAnswer(kind, raw, context), false, kind);
  // Unknown kinds, and answers the transport could not have handed over, are never accepted.
  for (const kind of ["", "unknown", "constructor", "__proto__", undefined, null, 5, "json-ok"]) assert.equal(judgeAnswer(kind, json({}), ctx("cleanup/ruleset/0/delete")), false);
  for (const raw of [null, undefined, {}, { status: 200 }, { status: 200, rawHeaders: [], bytes: "text" }]) assert.equal(judgeAnswer("ruleset-delete", raw, ctx("cleanup/ruleset/0/delete")), false);
  assert.deepEqual([...JUDGE_KINDS].sort(), ["account-delete", "accounts-absent", "accounts-present", "object-absent", "object-delete", "object-present", "objects-empty", "release-absent", "ruleset-delete", "rulesets-kept", "rulesets-with-run"]);
});
