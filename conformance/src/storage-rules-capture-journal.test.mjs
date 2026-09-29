import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { appendFile, chmod, link, lstat, mkdir, mkdtemp, open, readFile, readdir, rename, rm, symlink, writeFile } from "node:fs/promises";
import { constants } from "node:fs";
import { join } from "node:path";
import test from "node:test";

const runId = "capture-test";
const sourceCommit = "ab".repeat(20);
const manifestDigest = "cd".repeat(32);
const digestSalt = "3".repeat(64);
const requestIds = ["preflight/owner", "case/a/subject/get", "case/a/subject/put", "recovery/case/a/get"];
const TOKEN = "CANARY-DOWNLOAD-0123456789abcdef";
const JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJDQU5BUlkifQ.Q0FOQVJZU0lHMDEyMzQ1Njc4OWFiY2RlZg";
const SESSION = "https://firebasestorage.googleapis.com/v0/b/b/o?name=x&upload_id=CANARYUPLOAD0123456789&upload_protocol=resumable";
const sha = (value) => createHash("sha256").update(value).digest("hex");
const intent = (operationId = requestIds[1], delta = {}) => ({ operationId, phase: "normal", targetSha256: "1".repeat(64), redactedTarget: "GET https://storage.googleapis.com/storage/v1/b/b/o/x?ifGenerationMatch=<ref:generation>", mutationKey: null, ...delta });
const response = (delta = {}) => ({ status: 200, rawHeaders: ["Content-Type", "application/json", "X-Goog-Upload-URL", SESSION], bytes: Buffer.from(JSON.stringify({ name: "n", downloadTokens: TOKEN, idToken: JWT })), ...delta });

async function fixture(t, { hooks = {}, before = null, delta = {} } = {}) {
  const directory = await mkdtemp("/private/tmp/storage-rules-capture-");
  const trace = [];
  const handles = [];
  let journal;
  t.after(async () => { if (journal) await journal.close().catch(() => {}); for (const handle of handles) await handle.close().catch(() => {}); await rm(directory, { recursive: true, force: true }); });
  if (before) await before({ directory });
  const io = {
    lstat,
    mkdir,
    open: async (name, flags, mode) => {
      const handle = await open(name, hooks.flags ? hooks.flags(name, flags) : flags, mode);
      handles.push(handle);
      const kind = name === directory ? "directory" : name.endsWith("/blobs") ? "blobs" : name.includes("/blobs/") ? "blob" : "journal";
      trace.push({ event: "open", kind });
      return {
        stat: (...args) => handle.stat(...args),
        write: async (...args) => { trace.push({ event: "write", kind }); return hooks.write ? hooks.write(handle, args, kind) : handle.write(...args); },
        sync: async () => { trace.push({ event: "sync", kind }); return hooks.sync ? hooks.sync(handle, kind) : handle.sync(); },
        close: async () => { trace.push({ event: "close", kind }); return handle.close(); },
      };
    },
  };
  const module = await import("./storage-rules/capture-journal.mjs").catch((error) => { if (error.code === "ERR_MODULE_NOT_FOUND") return {}; throw error; });
  assert.equal(typeof module.createCaptureJournal, "function");
  journal = await module.createCaptureJournal({ directory, runId, sourceCommit, manifestDigest, digestSalt, requestIds, io, ...delta });
  const rows = async () => (await readFile(join(directory, "captures.jsonl"), "utf8")).split("\n").filter(Boolean).map((line) => JSON.parse(line));
  return { journal, directory, trace, rows };
}

test("creation makes a private journal and blob directory and records the declared IDs", async (t) => {
  const ctx = await fixture(t);
  const rows = await ctx.rows();
  assert.deepEqual(rows.map((row) => row.event), ["opened"]);
  assert.deepEqual(rows[0].data, { requestCount: requestIds.length, requestIdsSha256: sha(JSON.stringify(requestIds)) });
  assert.equal((await lstat(join(ctx.directory, "captures.jsonl"))).mode & 0o777, 0o600);
  assert.equal((await lstat(join(ctx.directory, "blobs"))).mode & 0o777, 0o700);
  assert.deepEqual(ctx.journal.snapshot(), { busy: false, uncertain: false, closed: false, events: 1, intents: 0, responses: 0, sendAuthorized: false });
});

for (const [label, before] of [
  ["an existing journal file", async ({ directory }) => writeFile(join(directory, "captures.jsonl"), "old\n", { mode: 0o600 })],
  ["a symlinked journal", async ({ directory }) => symlink("/private/tmp/never-used", join(directory, "captures.jsonl"))],
  ["an existing blob directory", async ({ directory }) => mkdir(join(directory, "blobs"), { mode: 0o700 })],
  ["a group-readable run directory", async ({ directory }) => chmod(directory, 0o750)],
]) {
  test(`${label} is refused and nothing is replaced`, async (t) => {
    await assert.rejects(fixture(t, { before }), /capture journal creation failed/);
  });
}

test("invalid options are refused before anything is created", async (t) => {
  for (const delta of [{ directory: "relative/dir" }, { runId: "Bad Run" }, { sourceCommit: "x" }, { manifestDigest: "y" }, { digestSalt: "short" }, { requestIds: [] }, { requestIds: ["a", "a"] }, { requestIds: ["bad id"] }, { extra: 1 }]) {
    await assert.rejects(fixture(t, { delta }), /invalid capture journal input/);
  }
});

test("intent, response, facts, proof and note append closed rows in one sequence", async (t) => {
  const ctx = await fixture(t);
  await ctx.journal.writeIntent(intent());
  await ctx.journal.writeResponse({ operationId: requestIds[1], attempt: 1, response: response() });
  await ctx.journal.writeFacts({ operationId: requestIds[1], kind: "gcs-metadata-read", verdict: "present", facts: { status: 200, generation: "1700000000000001", hasDownloadToken: true } });
  await ctx.journal.writeProof({ runId, type: "generation", key: "STORAGE-RULES/run/a.bin", operationId: requestIds[1], attempt: 1, valueSha256: "2".repeat(64) });
  await ctx.journal.writeNote({ operationId: requestIds[1], text: "settled" });
  const rows = await ctx.rows();
  assert.deepEqual(rows.map((row) => [row.event, row.sequence]), [["opened", 1], ["intent", 2], ["response", 3], ["facts", 4], ["proof", 5], ["note", 6]]);
  assert.ok(rows.every((row) => row.schemaVersion === 1 && row.runId === runId && row.sourceCommit === sourceCommit && row.manifestDigest === manifestDigest));
  const captured = rows[2].data;
  assert.equal(captured.targetSha256, "1".repeat(64));
  assert.equal(captured.status, 200);
  const blob = await readFile(join(ctx.directory, "blobs", `${captured.blob.sha256}.bin`));
  assert.equal(sha(blob), captured.blob.sha256);
  assert.equal(blob.length, captured.blob.bytes);
  assert.equal(captured.originalSha256.length, 64);
  assert.ok(captured.spans.length >= 2);
  assert.equal((await lstat(join(ctx.directory, "blobs", `${captured.blob.sha256}.bin`))).mode & 0o777, 0o600);
  assert.deepEqual(ctx.journal.snapshot(), { busy: false, uncertain: false, closed: false, events: 6, intents: 1, responses: 1, sendAuthorized: false });
});

test("a blob is written and synced, then its directory synced, before the response row is written", async (t) => {
  const ctx = await fixture(t);
  await ctx.journal.writeIntent(intent());
  const before = ctx.trace.length;
  await ctx.journal.writeResponse({ operationId: requestIds[1], attempt: 1, response: response() });
  const events = ctx.trace.slice(before).map((entry) => `${entry.event}:${entry.kind}`);
  const firstJournalWrite = events.indexOf("write:journal");
  assert.ok(events.indexOf("write:blob") >= 0 && events.indexOf("write:blob") < events.indexOf("sync:blob") && events.indexOf("sync:blob") < events.indexOf("sync:blobs") && events.indexOf("sync:blobs") < firstJournalWrite);
  assert.ok(events.indexOf("sync:journal") > firstJournalWrite);
});

test("events are refused out of order, twice, for undeclared operations and with malformed input", async (t) => {
  const ctx = await fixture(t);
  const j = ctx.journal;
  await assert.rejects(j.writeResponse({ operationId: requestIds[1], attempt: 1, response: response() }), /event refused/);
  await assert.rejects(j.writeFacts({ operationId: requestIds[1], kind: "k", verdict: "present", facts: {} }), /event refused/);
  await assert.rejects(j.writeIntent(intent("case/undeclared/get")), /event refused/);
  for (const delta of [{ phase: "other" }, { targetSha256: "x" }, { mutationKey: 7 }, { mutationKey: "bad key" }, { extra: 1 }]) await assert.rejects(j.writeIntent(intent(requestIds[1], delta)), /event refused/);
  await j.writeIntent(intent());
  await assert.rejects(j.writeIntent(intent()), /event refused/);
  for (const delta of [{ attempt: 0 }, { attempt: 1.5 }, { response: response({ status: 99 }) }, { response: response({ status: 600 }) }, { response: response({ rawHeaders: ["a"] }) }, { response: response({ bytes: "x" }) }, { response: { ...response(), extra: 1 } }]) {
    await assert.rejects(j.writeResponse({ operationId: requestIds[1], attempt: 1, response: response(), ...delta }), /event refused/);
  }
  await assert.rejects(j.writeResponse({ operationId: requestIds[2], attempt: 1, response: response() }), /event refused/);
  await j.writeResponse({ operationId: requestIds[1], attempt: 1, response: response() });
  await assert.rejects(j.writeResponse({ operationId: requestIds[1], attempt: 2, response: response() }), /event refused/);
  const accessor = Object.defineProperty({ ...intent(requestIds[2]) }, "phase", { enumerable: true, get() { return "normal"; } });
  await assert.rejects(j.writeIntent(accessor), /event refused/);
  assert.equal(j.snapshot().uncertain, false);
  assert.deepEqual((await ctx.rows()).map((row) => row.event), ["opened", "intent", "response"]);
});

test("bearer material is redacted or refused in every writer", async (t) => {
  const ctx = await fixture(t);
  const j = ctx.journal;
  await assert.rejects(j.writeIntent(intent(requestIds[1], { redactedTarget: `GET https://x/o?token=${TOKEN}` })), /event refused/);
  await assert.rejects(j.writeIntent(intent(requestIds[1], { redactedTarget: `GET ${SESSION}` })), /event refused/);
  await j.writeIntent(intent());
  await j.writeResponse({ operationId: requestIds[1], attempt: 1, response: response() });
  await assert.rejects(j.writeFacts({ operationId: requestIds[1], kind: "k", verdict: "present", facts: { link: `https://x/o?token=${TOKEN}` } }), /event refused/);
  await assert.rejects(j.writeFacts({ operationId: requestIds[1], kind: "k", verdict: "present", facts: { nested: { deep: [JWT] } } }), /event refused/);
  await assert.rejects(j.writeProof({ runId, type: "page-token", key: `k?token=${TOKEN}`, operationId: requestIds[1], attempt: 1, valueSha256: "2".repeat(64) }), /event refused/);
  await j.writeNote({ operationId: null, text: `failed with ${JWT} at ${SESSION} token=${TOKEN}` });
  const all = (await readFile(join(ctx.directory, "captures.jsonl"), "utf8")) + (await Promise.all((await readdir(join(ctx.directory, "blobs"))).map((name) => readFile(join(ctx.directory, "blobs", name), "utf8")))).join("");
  for (const secret of [TOKEN, JWT, "CANARYUPLOAD0123456789", SESSION]) assert.equal(all.includes(secret), false, secret);
  assert.equal(all.includes("STORAGE") || all.includes("generation"), true);
});

test("facts are limited to plain JSON of bounded size", async (t) => {
  const ctx = await fixture(t);
  await ctx.journal.writeIntent(intent());
  await ctx.journal.writeResponse({ operationId: requestIds[1], attempt: 1, response: response() });
  const facts = (facts) => ctx.journal.writeFacts({ operationId: requestIds[1], kind: "k", verdict: "present", facts });
  for (const bad of [{ f: () => 1 }, { n: 1.5 }, { n: Infinity }, { s: "x".repeat(4097) }, Object.create({ inherited: 1 }), { a: new Array(65).fill(1) }, JSON.parse(`{${'"a":'.repeat(1)}{"b":{"c":{"d":{"e":{"f":{"g":{"h":1}}}}}}}}`)]) await assert.rejects(facts(bad), /event refused/);
  await facts({ ok: true, nested: { list: [1, "two", null, false] } });
});

test("a failing journal write leaves the journal uncertain and refuses everything after", async (t) => {
  let fail = false;
  const ctx = await fixture(t, { hooks: { write: (handle, args, kind) => { if (fail && kind === "journal") throw new Error("disk full"); return handle.write(...args); } } });
  await ctx.journal.writeIntent(intent());
  fail = true;
  await assert.rejects(ctx.journal.writeResponse({ operationId: requestIds[1], attempt: 1, response: response() }), /capture journal uncertain/);
  fail = false;
  await assert.rejects(ctx.journal.writeNote({ operationId: null, text: "x" }), /event refused/);
  assert.equal(ctx.journal.snapshot().uncertain, true);
});

test("a failing blob sync leaves the journal uncertain and no response row", async (t) => {
  const ctx = await fixture(t, { hooks: { sync: (handle, kind) => { if (kind === "blob") throw new Error("io error"); return handle.sync(); } } });
  await ctx.journal.writeIntent(intent());
  await assert.rejects(ctx.journal.writeResponse({ operationId: requestIds[1], attempt: 1, response: response() }), /capture journal uncertain/);
  assert.deepEqual((await ctx.rows()).map((row) => row.event), ["opened", "intent"]);
  assert.equal(ctx.journal.snapshot().uncertain, true);
});

test("a partial write is completed before the row is acknowledged", async (t) => {
  const ctx = await fixture(t, { hooks: { write: (handle, [bytes, offset, length, position], kind) => handle.write(bytes, offset, kind === "journal" ? Math.min(length, 7) : length, position) } });
  await ctx.journal.writeIntent(intent());
  await ctx.journal.writeResponse({ operationId: requestIds[1], attempt: 1, response: response() });
  assert.deepEqual((await ctx.rows()).map((row) => row.event), ["opened", "intent", "response"]);
});

test("a second event during an in-flight write is refused without a row", async (t) => {
  let release; const gate = new Promise((resolve) => { release = resolve; });
  let hold = false;
  const ctx = await fixture(t, { hooks: { write: async (handle, args, kind) => { if (hold && kind === "journal") await gate; return handle.write(...args); } } });
  hold = true;
  const first = ctx.journal.writeIntent(intent());
  await assert.rejects(ctx.journal.writeNote({ operationId: null, text: "x" }), /event refused/);
  release();
  await first;
  assert.deepEqual((await ctx.rows()).map((row) => row.event), ["opened", "intent"]);
});

test("replacing or linking the journal file makes the next event uncertain", async (t) => {
  const ctx = await fixture(t);
  await ctx.journal.writeIntent(intent());
  const path = join(ctx.directory, "captures.jsonl");
  await link(path, join(ctx.directory, "second-name"));
  await assert.rejects(ctx.journal.writeNote({ operationId: null, text: "x" }), /capture journal uncertain/);
  const other = await fixture(t);
  await other.journal.writeIntent(intent());
  const replaced = join(other.directory, "captures.jsonl");
  const copy = await readFile(replaced);
  await rename(replaced, join(other.directory, "moved"));
  await writeFile(replaced, copy, { mode: 0o600 });
  await assert.rejects(other.journal.writeNote({ operationId: null, text: "x" }), /capture journal uncertain/);
});

test("identical redacted bodies share one blob and a different body gets its own", async (t) => {
  const ctx = await fixture(t);
  for (const [index, id] of [requestIds[1], requestIds[2]].entries()) {
    await ctx.journal.writeIntent(intent(id, { targetSha256: String(index + 1).repeat(64) }));
    await ctx.journal.writeResponse({ operationId: id, attempt: index + 1, response: response({ bytes: Buffer.from("same body") }) });
  }
  assert.equal((await readdir(join(ctx.directory, "blobs"))).length, 1);
  await ctx.journal.writeIntent(intent(requestIds[3], { phase: "recovery" }));
  await ctx.journal.writeResponse({ operationId: requestIds[3], attempt: 3, response: response({ bytes: Buffer.from("other body") }) });
  assert.equal((await readdir(join(ctx.directory, "blobs"))).length, 2);
});

test("close is idempotent, refuses events afterwards and refuses while busy", async (t) => {
  const ctx = await fixture(t);
  await ctx.journal.close();
  await ctx.journal.close();
  await assert.rejects(ctx.journal.writeIntent(intent()), /event refused/);
  assert.equal(ctx.journal.snapshot().closed, true);
});

// Credential evidence: the cache's and the session's proofs and the fixture accounts' receipts, as closed digest-only events.
const ownerProof = { status: "OWNER_OAUTH_LOCAL_ONLY", sendAuthorized: false, operationId: "preflight/auth/owner-token", sourceUrl: "https://oauth2.googleapis.com/token", fetchedAt: 1790553600, expiresAt: 1790557200, tokenDigest: "a".repeat(64) };
const keysProof = { status: "SIGNING_KEYS_LOCAL_ONLY", sendAuthorized: false, operationId: "auth-shared/signing-keys/1", sourceUrl: "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com", fetchedAt: 1790553600, expiresAt: 1790557200, keyDigests: { synthetic: "b".repeat(64) } };
const sessionProof = { status: "SIGNED_FIXTURE_LOCAL_ONLY", sendAuthorized: false, principal: "user-a", project: "fireemu-oracle-query", uid: "storage-rules-capture-test-user-a", issuedAt: 1790553599, expiresAt: 1790557199, authenticatedAt: 1790553599, revocationBoundary: null, tokenDigest: "c".repeat(64), signingKeyDigest: "d".repeat(64), keyFetchedAt: 1790553590, keyExpiresAt: 1790555600, claims: { email_verified: true, role: "reader", level: 7 } };
const ownership = { account: "user-a", project: "fireemu-oracle-query", uid: "storage-rules-capture-test-user-a", runPrefix: "storage-rules-capture-test", emailSha256: "e".repeat(64), creationRequestId: "auth/user-a/create" };
const cleanup = { account: "user-a", project: "fireemu-oracle-query", uid: "storage-rules-capture-test-user-a", absent: true, requestId: "auth/user-a/absence" };

test("credential proofs, ownership receipts and cleanup receipts are journalled as their own closed events", async (t) => {
  const ctx = await fixture(t);
  for (const proof of [ownerProof, keysProof, sessionProof]) await ctx.journal.writeCredentialProof(proof);
  await ctx.journal.writeOwnership(ownership);
  await ctx.journal.writeCleanup(cleanup);
  const rows = (await ctx.rows()).slice(1);
  assert.deepEqual(rows.map((row) => row.event), ["credential-proof", "credential-proof", "credential-proof", "ownership", "cleanup"]);
  assert.deepEqual(rows[0].data, ownerProof);
  assert.deepEqual(rows[2].data, sessionProof);
  assert.deepEqual(rows[3].data, ownership);
  assert.deepEqual(rows[4].data, cleanup);
  assert.equal(ctx.journal.snapshot().uncertain, false);
});

test("a credential proof must be a plain digest-only record of a local-only status and never carry bearer material", async (t) => {
  const ctx = await fixture(t);
  const j = ctx.journal;
  const refused = [
    null, [], "x", { ...ownerProof, sendAuthorized: true }, { ...ownerProof, status: "owner" }, { ...ownerProof, status: undefined }, (({ status, ...rest }) => rest)(ownerProof),
    { ...ownerProof, accessToken: "ya29.CANARYaccessToken0123456789abcdefABCDEF" }, { ...ownerProof, idToken: JWT }, { ...ownerProof, note: `Bearer ${TOKEN}` },
    { ...ownerProof, fetchedAt: 1.5 }, { ...ownerProof, deep: { a: { b: { c: { d: { e: { f: { g: 1 } } } } } } } },
    Object.defineProperty({ ...ownerProof }, "hidden", { value: 1, enumerable: false }), { ...ownerProof, big: "x".repeat(5000) },
  ];
  for (const bad of refused) await assert.rejects(j.writeCredentialProof(bad), /event refused/, JSON.stringify(bad)?.slice(0, 60));
  assert.equal(j.snapshot().uncertain, false);
  assert.equal((await ctx.rows()).length, 1);
});

test("an ownership receipt has exactly its keys, a known account and project, and a digest instead of an address", async (t) => {
  const ctx = await fixture(t);
  const j = ctx.journal;
  for (const bad of [
    { ...ownership, email: "storage-rules-capture-test-user-a@example.com" }, (({ emailSha256, ...rest }) => rest)(ownership), { ...ownership, extra: 1 }, { ...ownership, account: "root" }, { ...ownership, project: "other-project" },
    { ...ownership, uid: "" }, { ...ownership, uid: "u".repeat(129) }, { ...ownership, runPrefix: "other" }, { ...ownership, runPrefix: "storage-rules-other-run" }, (({ runPrefix, ...rest }) => rest)(ownership), { ...ownership, uid: "a b" }, { ...ownership, emailSha256: "E".repeat(64) }, { ...ownership, emailSha256: "e".repeat(63) },
    { ...ownership, creationRequestId: "case/a/subject" }, { ...ownership, creationRequestId: "auth/user-a/create\n" }, { ...ownership, uid: JWT }, null,
  ]) await assert.rejects(j.writeOwnership(bad), /event refused/, JSON.stringify(bad)?.slice(0, 60));
  for (const account of ["user-a", "user-b", "revoked-token", "foreign-project-token"]) await j.writeOwnership({ ...ownership, account, project: account === "foreign-project-token" ? "fireemu-oracle-idp" : "fireemu-oracle-query", creationRequestId: account === "foreign-project-token" ? "auth/foreign-project-token/sign-up" : `auth/${account}/create` });
  assert.equal((await ctx.rows()).length, 5);
  // The foreign project's account gets a server-chosen UID, so only the other accounts' UIDs carry the run prefix.
  await j.writeOwnership({ ...ownership, account: "foreign-project-token", project: "fireemu-oracle-idp", uid: "serverChosenUid123", creationRequestId: "auth/foreign-project-token/sign-up" });
  await assert.rejects(j.writeOwnership({ ...ownership, uid: "serverChosenUid123" }), /event refused/);
});

test("a cleanup receipt has exactly its keys, states absence and names its request", async (t) => {
  const ctx = await fixture(t);
  const j = ctx.journal;
  for (const bad of [
    { ...cleanup, absent: false }, { ...cleanup, absent: "true" }, { ...cleanup, extra: 1 }, (({ requestId, ...rest }) => rest)(cleanup), { ...cleanup, account: "root" }, { ...cleanup, project: "x" },
    { ...cleanup, requestId: "" }, { ...cleanup, requestId: "auth/user-a/absence\n" }, { ...cleanup, uid: JWT }, null,
  ]) await assert.rejects(j.writeCleanup(bad), /event refused/, JSON.stringify(bad)?.slice(0, 60));
  await j.writeCleanup({ ...cleanup, requestId: "recovery/auth/user-a/absence" });
  assert.equal((await ctx.rows()).length, 2);
});

test("credential events follow the journal's gate: no event while another is in flight, none after close, and a failed sync leaves it uncertain", async (t) => {
  let fail = false;
  const ctx = await fixture(t, { hooks: { sync: async (handle, kind) => { if (fail && kind === "journal") throw new Error("disk"); return handle.sync(); } } });
  await ctx.journal.writeOwnership(ownership);
  fail = true;
  await assert.rejects(ctx.journal.writeCleanup(cleanup), /capture journal uncertain/);
  assert.equal(ctx.journal.snapshot().uncertain, true);
  await assert.rejects(ctx.journal.writeCredentialProof(ownerProof), /event refused/);
});

// Journal integrity: every check that runs before a write must stop the write, so a changed run directory never receives a byte.
test("a journal replaced at its path is refused before a byte reaches the old or the new file", async (t) => {
  const ctx = await fixture(t);
  await ctx.journal.writeIntent(intent());
  const path = join(ctx.directory, "captures.jsonl");
  const before = await readFile(path);
  await rename(path, join(ctx.directory, "moved"));
  await writeFile(path, before, { mode: 0o600 });
  await assert.rejects(ctx.journal.writeNote({ operationId: null, text: "x" }), /capture journal uncertain/);
  assert.deepEqual(await readFile(join(ctx.directory, "moved")), before);
  assert.deepEqual(await readFile(path), before);
});

test("a run directory replaced by another one holding the same journal and blob directory is refused", async (t) => {
  const ctx = await fixture(t);
  await ctx.journal.writeIntent(intent());
  const old = `${ctx.directory}-old`;
  t.after(() => rm(old, { recursive: true, force: true }));
  const before = await readFile(join(ctx.directory, "captures.jsonl"));
  await rename(ctx.directory, old);
  await mkdir(ctx.directory, { mode: 0o700 });
  await rename(join(old, "blobs"), join(ctx.directory, "blobs"));
  await rename(join(old, "captures.jsonl"), join(ctx.directory, "captures.jsonl"));
  await assert.rejects(ctx.journal.writeNote({ operationId: null, text: "x" }), /capture journal uncertain/);
  assert.deepEqual(await readFile(join(ctx.directory, "captures.jsonl")), before);
});

test("bytes appended to the journal by anyone else make the next event uncertain and add nothing", async (t) => {
  const ctx = await fixture(t);
  await ctx.journal.writeIntent(intent());
  const path = join(ctx.directory, "captures.jsonl");
  await appendFile(path, "{\"foreign\":true}\n");
  const before = await readFile(path);
  await assert.rejects(ctx.journal.writeNote({ operationId: null, text: "x" }), /capture journal uncertain/);
  assert.deepEqual(await readFile(path), before);
  assert.equal(ctx.journal.snapshot().uncertain, true);
});

test("a blob directory that became group-accessible makes the next event uncertain and adds nothing", async (t) => {
  const ctx = await fixture(t);
  await ctx.journal.writeIntent(intent());
  const before = await readFile(join(ctx.directory, "captures.jsonl"));
  await chmod(join(ctx.directory, "blobs"), 0o750);
  await assert.rejects(ctx.journal.writeNote({ operationId: null, text: "x" }), /capture journal uncertain/);
  assert.deepEqual(await readFile(join(ctx.directory, "captures.jsonl")), before);
});

test("a blob open that does not yield a fresh empty file is refused and the existing file is left alone", async (t) => {
  // A file system that ignores O_EXCL hands back an existing file; the blob must not be written into it.
  const ctx = await fixture(t, { hooks: { flags: (name, flags) => (name.includes("/blobs/") ? flags & ~constants.O_EXCL : flags) } });
  const body = Buffer.from("fresh body");
  const blobPath = join(ctx.directory, "blobs", `${sha(body)}.bin`);
  await writeFile(blobPath, "stale content that is longer", { mode: 0o600 });
  await ctx.journal.writeIntent(intent());
  await assert.rejects(ctx.journal.writeResponse({ operationId: requestIds[1], attempt: 1, response: response({ rawHeaders: [], bytes: body }) }), /capture journal uncertain/);
  assert.equal(await readFile(blobPath, "utf8"), "stale content that is longer");
  assert.deepEqual((await ctx.rows()).map((row) => row.event), ["opened", "intent"]);
});

test("a row over the row size limit is never written, even when each field is within its own bound", async (t) => {
  const ctx = await fixture(t);
  await ctx.journal.writeIntent(intent());
  await ctx.journal.writeResponse({ operationId: requestIds[1], attempt: 1, response: response() });
  await assert.rejects(ctx.journal.writeFacts({ operationId: requestIds[1], kind: "k", verdict: "present", facts: { list: new Array(64).fill("x".repeat(4096)) } }), /capture journal uncertain/);
  assert.deepEqual((await ctx.rows()).map((row) => row.event), ["opened", "intent", "response"]);
});

test("a note is limited to 4096 characters", async (t) => {
  const ctx = await fixture(t);
  await assert.rejects(ctx.journal.writeNote({ operationId: null, text: "n".repeat(4097) }), /event refused/);
  await assert.rejects(ctx.journal.writeNote({ operationId: null, text: "" }), /event refused/);
  await ctx.journal.writeNote({ operationId: null, text: "n".repeat(4096) });
  assert.deepEqual((await ctx.rows()).map((row) => row.data.text?.length), [undefined, 4096]);
});

test("facts need a closed kind and verdict", async (t) => {
  const ctx = await fixture(t);
  await ctx.journal.writeIntent(intent());
  await ctx.journal.writeResponse({ operationId: requestIds[1], attempt: 1, response: response() });
  const facts = (kind, verdict) => ctx.journal.writeFacts({ operationId: requestIds[1], kind, verdict, facts: {} });
  for (const verdict of ["", "Present", "pre sent", "present\n", "v".repeat(25), "absent2", 7, null]) await assert.rejects(facts("k", verdict), /event refused/, String(verdict));
  for (const kind of ["", "Kind", "k k", "k".repeat(49), 7]) await assert.rejects(facts(kind, "present"), /event refused/, String(kind));
  await facts("k".repeat(48), "v".repeat(24));
  assert.equal((await ctx.rows()).length, 4);
});

test("a proof names this run", async (t) => {
  const ctx = await fixture(t);
  const proof = { runId, type: "generation", key: "STORAGE-RULES/run/a.bin", operationId: requestIds[1], attempt: 1, valueSha256: "2".repeat(64) };
  for (const other of ["other-run", `${runId}x`, runId.toUpperCase()]) await assert.rejects(ctx.journal.writeProof({ ...proof, runId: other }), /event refused/, other);
  await ctx.journal.writeProof(proof);
  assert.equal((await ctx.rows()).length, 2);
});

test("a credential proof must state sendAuthorized false, a bounded status and at most 8192 characters", async (t) => {
  const ctx = await fixture(t);
  const j = ctx.journal;
  const sized = (length) => {
    const base = JSON.stringify({ ...ownerProof, a: "", b: "" }).length;
    return { ...ownerProof, a: "a".repeat(4096), b: "b".repeat(length - base - 4096) };
  };
  assert.equal(JSON.stringify(sized(8193)).length, 8193);
  for (const bad of [(({ sendAuthorized, ...rest }) => rest)(ownerProof), { ...ownerProof, sendAuthorized: null }, { ...ownerProof, sendAuthorized: 0 }, { ...ownerProof, status: `S${"T".repeat(64)}` }, { ...ownerProof, status: "OK" }, { ...ownerProof, status: "_OWNER" }, sized(8193)]) {
    await assert.rejects(j.writeCredentialProof(bad), /event refused/, JSON.stringify(bad).slice(0, 60));
  }
  await j.writeCredentialProof(sized(8192));
  await j.writeCredentialProof({ ...ownerProof, status: `S${"T".repeat(63)}` });
  await j.writeCredentialProof({ ...ownerProof, status: "OKK" });
  assert.equal((await ctx.rows()).length, 4);
});

test("the foreign project's account escapes only the run prefix rule, never the UID, prefix or bearer checks", async (t) => {
  const ctx = await fixture(t);
  const j = ctx.journal;
  const foreign = { ...ownership, account: "foreign-project-token", project: "fireemu-oracle-idp", uid: "serverChosenUid123", creationRequestId: "auth/foreign-project-token/sign-up" };
  for (const bad of [{ ...foreign, uid: "" }, { ...foreign, uid: "a b" }, { ...foreign, uid: "u".repeat(129) }, { ...foreign, uid: "uid\n" }, { ...foreign, runPrefix: "other" }, { ...foreign, runPrefix: "storage-rules-Bad" }, { ...foreign, uid: JWT }]) {
    await assert.rejects(j.writeOwnership(bad), /event refused/, JSON.stringify(bad).slice(0, 80));
  }
  await j.writeOwnership({ ...foreign, uid: "u".repeat(128) });
  assert.equal((await ctx.rows()).length, 2);
});

test("a run prefix owns only UIDs that continue it after a dash", async (t) => {
  const ctx = await fixture(t);
  const j = ctx.journal;
  for (const bad of [
    // Another run whose name extends this one.
    { ...ownership, uid: "storage-rules-capture-test2-user-a" }, { ...ownership, uid: "storage-rules-capture-test" },
    // A prefix outside the storage-rules namespace, even when the UID follows it.
    { ...ownership, runPrefix: "other", uid: "other-user-a" }, { ...ownership, runPrefix: "storage-rules-", uid: "storage-rules--user-a" },
    // A UID that carries bearer material after a valid prefix.
    { ...ownership, uid: "storage-rules-capture-test-ya29.CANARYaccessToken0123456789" },
  ]) await assert.rejects(j.writeOwnership(bad), /event refused/, JSON.stringify(bad).slice(0, 100));
  assert.equal((await ctx.rows()).length, 1);
});

test("a cleanup receipt's UID must be a plain UID of bounded length", async (t) => {
  const ctx = await fixture(t);
  const j = ctx.journal;
  for (const uid of ["", "a b", "u".repeat(129), "uid\n", 7]) await assert.rejects(j.writeCleanup({ ...cleanup, uid }), /event refused/, String(uid));
  for (const account of ["user-a", "user-b", "revoked-token", "foreign-project-token"]) await j.writeCleanup({ ...cleanup, account, project: account === "foreign-project-token" ? "fireemu-oracle-idp" : "fireemu-oracle-query", uid: "u".repeat(128) });
  assert.equal((await ctx.rows()).length, 5);
});

// The target of a delegated request is bound durably as a salted HMAC over what is recorded, without the credential.
import { createHmac } from "node:crypto";
const targetInput = (delta = {}) => ({ operationId: "case/a/subject/get", method: "POST", url: "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=AIzaCANARYAPIKEY0123456789abcdefghijklm", headers: { "content-type": "application/json", accept: "application/json", authorization: `Bearer ya29.${"C".repeat(30)}`, "x-goog-user-project": "fireemu-oracle-idp" }, body: Buffer.from('{"password":"CANARY-PASSWORD-VALUE-0123"}'), ...delta });
const recompute = (data, salt = digestSalt) => createHmac("sha256", Buffer.from(salt, "hex")).update("delegated-target\0").update(JSON.stringify({ operationId: data.operationId, method: data.method, url: data.url, headers: data.headers, bodyHmac: data.bodyHmac })).digest("hex");

test("a delegated target is journalled as its redacted URL, its non-credential headers and salted HMACs of the body and of the whole record", async (t) => {
  const ctx = await fixture(t);
  await ctx.journal.writeDelegatedTarget(targetInput());
  const row = (await ctx.rows()).at(-1);
  assert.equal(row.event, "delegated-target");
  assert.deepEqual(Object.keys(row.data).sort(), ["bodyHmac", "headers", "method", "operationId", "targetHmac", "url"]);
  assert.equal(row.data.operationId, "case/a/subject/get");
  assert.equal(row.data.method, "POST");
  assert.equal(row.data.url, "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=<redacted:url-parameter>");
  assert.deepEqual(row.data.headers, [["accept", "application/json"], ["content-type", "application/json"], ["x-goog-user-project", "fireemu-oracle-idp"]]);
  assert.equal(row.data.bodyHmac, createHmac("sha256", Buffer.from(digestSalt, "hex")).update("delegated-body\0").update(targetInput().body).digest("hex"));
  assert.equal(row.data.targetHmac, recompute(row.data));
  const text = JSON.stringify(row);
  for (const secret of ["AIzaCANARY", "ya29.", "CANARY-PASSWORD", "authorization", "Bearer"]) assert.equal(text.includes(secret), false, secret);
});

test("the delegated target HMAC follows every recorded part and the salt, and a body-less request records no body HMAC", async (t) => {
  const ctx = await fixture(t);
  const seen = [];
  for (const delta of [{}, { operationId: "case/a/subject/put" }, { method: "GET", body: null }, { url: "https://identitytoolkit.googleapis.com/v1/accounts:signUp" }, { headers: { accept: "application/json" } }, { body: Buffer.from("other") }, { body: null }]) {
    await ctx.journal.writeDelegatedTarget(targetInput(delta));
    const data = (await ctx.rows()).at(-1).data;
    assert.equal(data.targetHmac, recompute(data), JSON.stringify(Object.keys(delta)));
    seen.push(data.targetHmac);
    if (delta.body === null) assert.equal(data.bodyHmac, null);
  }
  assert.equal(new Set(seen).size, seen.length);
  assert.notEqual(recompute((await ctx.rows()).at(-1).data, "7".repeat(64)), seen.at(-1));
});

test("a delegated target keeps no credential-bearing header of any kind and redacts every other header that is not public", async (t) => {
  const ctx = await fixture(t);
  await ctx.journal.writeDelegatedTarget(targetInput({ headers: { accept: "application/json", cookie: "session=CANARY-COOKIE", "proxy-authorization": "Basic CANARY-PROXY", authorization: "Bearer CANARY-BEARER", "x-secret-thing": "CANARY-SECRET-VALUE" } }));
  const data = (await ctx.rows()).at(-1).data;
  assert.deepEqual(data.headers.map(([name]) => name), ["accept", "x-secret-thing"]);
  assert.match(data.headers[1][1], /^<redacted:header:[0-9a-f]{64}>$/);
  assert.equal(JSON.stringify(data).includes("CANARY"), false);
});

test("a delegated target takes only plain data: a body that is a Buffer in name only, and headers that are not an ordinary record, are refused", async (t) => {
  const ctx = await fixture(t);
  const j = ctx.journal;
  const spoofed = Buffer.from("body");
  Object.setPrototypeOf(spoofed, Object.create(Buffer.prototype));
  const hidden = { accept: "application/json" };
  Object.defineProperty(hidden, "x-hidden", { value: "v", enumerable: false });
  class Headers { constructor() { this.accept = "application/json"; } }
  for (const bad of [targetInput({ body: spoofed }), targetInput({ headers: Object.assign(Object.create(null), { accept: "application/json" }) }), targetInput({ headers: new Headers() }), targetInput({ headers: hidden })]) {
    await assert.rejects(j.writeDelegatedTarget(bad), /event refused/);
  }
  assert.equal((await ctx.rows()).filter((row) => row.event === "delegated-target").length, 0);
});

test("a delegated target refuses an undeclared operation, a bad method, a bad body, bad headers and anything past the size limits", async (t) => {
  const ctx = await fixture(t);
  const j = ctx.journal;
  for (const bad of [
    targetInput({ operationId: "case/undeclared/get" }), targetInput({ method: "TRACE" }), targetInput({ method: "post" }), targetInput({ url: 5 }), targetInput({ url: `https://x/${"a".repeat(5000)}` }),
    targetInput({ body: "text" }), targetInput({ body: Buffer.alloc(300 * 1024) }), targetInput({ headers: null }), targetInput({ headers: [] }), targetInput({ headers: { Accept: "x" } }), targetInput({ headers: { accept: 5 } }),
    targetInput({ headers: { accept: "a\nb" } }), targetInput({ headers: Object.fromEntries(Array.from({ length: 65 }, (_, i) => [`x-h${i}`, "v"])) }), { ...targetInput(), extra: 1 }, (({ url, ...rest }) => rest)(targetInput()), null,
  ]) await assert.rejects(j.writeDelegatedTarget(bad), /event refused/, JSON.stringify(bad)?.slice(0, 50));
  assert.equal(j.snapshot().uncertain, false);
  assert.equal((await ctx.rows()).filter((row) => row.event === "delegated-target").length, 0);
});
