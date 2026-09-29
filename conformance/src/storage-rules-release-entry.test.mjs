import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, readFile, readdir, rename, rm, stat, symlink, writeFile } from "node:fs/promises";
import { linkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { bindReleaseEntry, SAVED_FILE } from "./storage-rules-release/release-entry.mjs";
import { releaseCorpus } from "./storage-rules-release/plan.mjs";
import { releaseCodeDigests } from "./storage-rules-release/pins.mjs";
import { canonicalDigest, makeSaved, savedSha256 } from "./storage-rules-release/release.mjs";
import { ADC, BUCKET, OTHER_RULESET, OWNER_TOKEN, PIN_KEYS, RELEASE_NAME, RULESET, SOURCE_COMMIT, SOURCE_SHA, cleanup, createReleaseWorld, fakeRequestImpl, ownerDigest, postLocal, preLocal, releaseBody, scratchCode } from "./storage-rules-release-support.mjs";

// The stage 2c entry against a scratch main checkout and a fake Firebase Rules world: what it reads, writes and leaves, and when it stops or recovers.
const codeRoot = scratchCode();
process.on("exit", () => cleanup(codeRoot));
const digests = await releaseCodeDigests(codeRoot);
const LIMITS = { pre: 11, post: 8 };
const clock = { nowSeconds: () => 1_800_000_000, waitUntilSeconds: async () => {}, sleep: async () => {} };
const runId = "release-test-run";
const savedRecord = () => makeSaved({ bucket: BUCKET, release: { ...releaseBody(), bodySha256: canonicalDigest(releaseBody()) }, ruleset: { sourceSha256: SOURCE_SHA } });

const packetFor = (mode, saved) => {
  const corpus = mode === "pre"
    ? releaseCorpus({ mode, bucket: BUCKET, rulesetName: RULESET, ownerEmailSha256: ownerDigest })
    : releaseCorpus({ mode, bucket: BUCKET, rulesetName: saved.rulesetName, ownerEmailSha256: ownerDigest, savedSha256: savedSha256(saved) });
  return { taskId: "STORAGE-RULES", packetName: `stage2c-${mode}-v1`, packetSha256: (mode === "pre" ? "1" : "2").repeat(64), sourceCommit: SOURCE_COMMIT, runnerSha256: digests.runnerSha256, manifestSha256: corpus.sha256, fixtureSchemaSha256: digests.fixtureSchemaSha256, projects: ["fireemu-oracle-query"], maxRequests: LIMITS[mode], reserveUsd: 0.5 };
};
const ledgerFor = (mode, packet) => {
  const envelopeId = `STORAGE-RULES-stage2c-${mode}-v1-001`;
  return [
    "- 2026-09-28 | 調整役への委任（本番の送信） | decision=APPROVE; local fixture | オーナー（ローカル試験） | private.md",
    "- 2026-09-28 | 調整役への委任（枠の承認） | decision=APPROVE; local fixture | オーナー（ローカル試験） | private.md",
    `- 2026-09-29 | STORAGE-RULES ${packet.packetName} envelope | envelopeId=${envelopeId}; project=fireemu-oracle-query; maxRequests=${LIMITS[mode]}; reserveUsd=0.5; writes=the query bucket release; iamConfig=none; retries=none; onStop=locks-held; 根拠=2026-09-28 調整役への委任（本番の送信） | Claude（委任。オーナーの裁量の委任 2026-09-28） | private.md`,
    `- 2026-09-29 | STORAGE-RULES ${packet.packetName} | decision=APPROVE; ${PIN_KEYS.map((key) => `${key}=${packet[key]}`).join("; ")}; envelopeId=${envelopeId} | Claude（委任。枠の内の承認し直し） | private.md`,
  ].join("\n");
};

async function checkout(t, { mode = "pre", world = createReleaseWorld(), gitHead = SOURCE_COMMIT, gitStatus = "", gitExtra = "", gitExtraRelease = "", gitThrows = false, usage = [], saved = savedRecord(), mutatePacket = (packet) => packet, ledgerText } = {}) {
  const root = await mkdtemp("/private/tmp/storage-rules-release-");
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, ".git"));
  await mkdir(join(root, "docs.local", "instructions"), { recursive: true });
  const runs = join(root, "docs.local", "runs");
  await mkdir(runs, { mode: 0o700 });
  await chmod(runs, 0o700);
  await mkdir(join(runs, "sandbox-locks"), { mode: 0o700 });
  await chmod(join(runs, "sandbox-locks"), 0o700);
  const packet = mutatePacket(packetFor(mode, saved));
  const review = { verdict: "APPROVE", must: [], should: [], ...Object.fromEntries(PIN_KEYS.map((key) => [key, packet[key]])), envelopeId: `STORAGE-RULES-stage2c-${mode}-v1-001`, withinEnvelope: true };
  await writeFile(join(root, "docs.local", "instructions", "owner-decisions.md"), ledgerText ?? ledgerFor(mode, packetFor(mode, saved)), { mode: 0o644 });
  if (usage.length > 0) await writeFile(join(runs, "storage-rules-release-usage.jsonl"), usage.map((id) => `${JSON.stringify({ packetSha256: packet.packetSha256, runId: id })}\n`).join(""), { mode: 0o600 });
  const adcPath = join(root, "adc.json");
  await writeFile(adcPath, JSON.stringify(ADC), { mode: 0o600 });
  const savedPath = join(root, "saved.json");
  await writeFile(savedPath, JSON.stringify(saved), { mode: 0o600 });
  const localPath = join(root, "local.json");
  await writeFile(localPath, JSON.stringify(mode === "pre" ? preLocal(adcPath) : postLocal(adcPath, savedPath)), { mode: 0o600 });
  const wire = [];
  const gitCalls = [];
  const git = async (where, args) => { gitCalls.push([where, ...args]); if (gitThrows) throw new Error("git failed"); if (args[0] === "rev-parse") return `${gitHead}\n`; if (args.includes("--ignored")) return args.includes("conformance/src/storage-rules-release") ? gitExtraRelease : gitExtra; return gitStatus; };
  const entry = bindReleaseEntry({ root, codeRoot, requestImpl: fakeRequestImpl((spec) => world.answer(spec), wire), clock, git });
  const options = { mode, localPath, runId, sourceCommit: SOURCE_COMMIT, packet: structuredClone(packet), review: structuredClone(review) };
  return { root, runs, entry, options, wire, world, gitCalls, localPath, savedPath, saved, adcPath, lockFiles: async () => (await readdir(join(runs, "sandbox-locks"))).sort() };
}
const runDir = (f) => join(f.runs, `storage-rules-release-${runId}`);
const journalText = async (f) => (await Promise.all((await walk(runDir(f))).map((path) => readFile(path, "utf8").catch(() => "")))).join("\n");
async function walk(directory) {
  const out = [];
  for (const name of await readdir(directory)) {
    const path = join(directory, name);
    if ((await stat(path)).isDirectory()) out.push(...await walk(path)); else out.push(path);
  }
  return out;
}
// The facts the run wrote, in order: what each read or write of the run concluded, without secrets.
const factsOf = async (f) => (await readFile(join(runDir(f), "captures.jsonl"), "utf8")).split("\n").filter(Boolean).map((line) => JSON.parse(line)).flatMap((row) => { const data = row.data ?? row; return data.facts !== undefined && data.kind !== undefined ? [{ operationId: data.operationId, kind: data.kind, verdict: data.verdict, facts: data.facts }] : []; });
const urls = (f) => f.wire.map((entry) => `${entry.method} ${new URL(entry.url).pathname}`);
const lockedOnce = ["fireemu-oracle-query.lock"];

test("pre: the release is saved, deleted and read back as absent, and the lock is released", async (t) => {
  const f = await checkout(t);
  let savedWhenDeleted = null;
  f.world.hook.delete = () => { savedWhenDeleted = readFile(join(runDir(f), SAVED_FILE), "utf8").catch(() => null); return undefined; };
  const result = await f.entry(f.options);
  assert.equal(result.status, "finished");
  assert.equal(result.changed, true);
  assert.equal(result.released, true);
  assert.equal(result.requests, 8);
  assert.equal(result.mode, "pre");
  assert.equal(f.world.release, null);
  assert.equal(f.world.bucketless, null);
  assert.deepEqual(f.world.posts, []);
  assert.deepEqual(await f.lockFiles(), []);
  // The saved record is durable before the deletion, private, and exactly what the release and the ruleset said.
  const text = await savedWhenDeleted;
  assert.notEqual(text, null);
  const saved = JSON.parse(text);
  assert.deepEqual(saved, f.saved);
  assert.equal(result.savedSha256, savedSha256(saved));
  assert.equal((await stat(join(runDir(f), SAVED_FILE))).mode & 0o777, 0o600);
  assert.deepEqual(urls(f).slice(0, 2), ["POST /token", "GET /oauth2/v2/userinfo"]);
  assert.deepEqual(urls(f).slice(2), [
    `GET /v1/${RULESET}`, `GET /v1/${RELEASE_NAME}`, "GET /v1/projects/fireemu-oracle-query/releases/firebase.storage",
    `DELETE /v1/${RELEASE_NAME}`, `GET /v1/${RELEASE_NAME}`, "GET /v1/projects/fireemu-oracle-query/releases/firebase.storage",
  ]);
  // The owner's bearer travels on every request but the token refresh, and the quota project on every one but userinfo.
  for (const entry of f.wire.slice(1)) {
    assert.equal(entry.headers.authorization, `Bearer ${OWNER_TOKEN}`);
    if (new URL(entry.url).pathname === "/oauth2/v2/userinfo") assert.equal(Object.hasOwn(entry.headers, "x-goog-user-project"), false);
    else assert.equal(entry.headers["x-goog-user-project"], "fireemu-oracle-query", entry.url);
  }
  // Nothing private reaches the journals.
  const journals = await journalText(f);
  assert.equal(journals.includes(OWNER_TOKEN), false);
  assert.equal(journals.includes("owner@example.test"), false);
});

test("pre: what the packet does not describe stops the run before anything is deleted and keeps nothing changed", async (t) => {
  const cases = {
    "the bucket release is absent": (world) => { world.release = null; },
    "the bucket release points at another ruleset": (world) => { world.release = releaseBody(OTHER_RULESET); },
    "a bucketless release exists": (world) => { world.bucketless = { name: "projects/fireemu-oracle-query/releases/firebase.storage", rulesetName: RULESET, createTime: "2026-09-25T10:30:00Z", updateTime: "2026-09-25T10:30:00Z" }; },
    "the ruleset is gone": (world) => { world.hook.ruleset = () => world.json({ error: { code: 404, message: "gone", status: "NOT_FOUND" } }, 404); },
    "the ruleset answer is not a ruleset": (world) => { world.hook.ruleset = () => world.json({ name: RULESET }); },
    "the owner is someone else": (world) => { world.hook.identity = { id: "1", email: "other@example.test", verified_email: true }; },
    "the owner is unverified": (world) => { world.hook.identity = { id: "1", email: "owner@example.test", verified_email: false }; },
    "the release answer has an extra field": (world) => { world.hook.read = (w, which) => (which === "bucket" ? w.json({ ...releaseBody(), extra: 1 }) : undefined); },
    "the release answer names another release": (world) => { world.hook.read = (w, which) => (which === "bucket" ? w.json({ ...releaseBody(), name: "projects/fireemu-oracle-query/releases/firebase.storage/other.appspot.com" }) : undefined); },
    "the release read is a server error": (world) => { world.hook.read = (w, which) => (which === "bucket" ? w.json({ error: { code: 500, message: "boom", status: "INTERNAL" } }, 500) : undefined); },
  };
  for (const [name, arrange] of Object.entries(cases)) {
    const f = await checkout(t);
    arrange(f.world);
    const before = structuredClone(f.world.release);
    await assert.rejects(f.entry(f.options), undefined, name);
    assert.equal(f.world.deletes, 0, name);
    assert.deepEqual(f.world.posts, [], name);
    assert.deepEqual(f.world.release, before, name);
    assert.equal(urls(f).some((line) => line.startsWith("DELETE")), false, name);
  }
});

test("pre: a deletion the service refuses is recovered by finding the release unchanged", async (t) => {
  const f = await checkout(t);
  f.world.hook.delete = (world) => { world.deletes; return world.json({ error: { code: 403, message: "no", status: "PERMISSION_DENIED" } }, 403); };
  const before = structuredClone(f.world.release);
  const result = await f.entry(f.options);
  assert.equal(result.status, "recovered");
  assert.equal(result.changed, false);
  assert.deepEqual(f.world.release, before);
  assert.deepEqual(f.world.posts, []);
  assert.equal(f.world.deletes, 1);
  assert.deepEqual(urls(f).slice(-2), [`DELETE /v1/${RELEASE_NAME}`, `GET /v1/${RELEASE_NAME}`]);
});

test("pre: a deletion whose answer is lost is recovered by publishing the saved release again, once, and reading it back, and the lock stays", async (t) => {
  const f = await checkout(t);
  f.world.hook.delete = (world) => { world.release = null; throw new Error("connection lost"); };
  // A lost attempt keeps the project lock even when the recovery proves the release back: it is released by hand after the journal is read.
  await assert.rejects(f.entry(f.options), /cannot confirm project lock closure/);
  assert.deepEqual(f.world.posts, [{ name: RELEASE_NAME, rulesetName: RULESET }]);
  assert.equal(f.world.release.rulesetName, RULESET);
  assert.equal(f.world.release.name, RELEASE_NAME);
  assert.equal(f.world.deletes, 1);
  assert.deepEqual(urls(f).slice(-4), [`DELETE /v1/${RELEASE_NAME}`, `GET /v1/${RELEASE_NAME}`, "POST /v1/projects/fireemu-oracle-query/releases", `GET /v1/${RELEASE_NAME}`]);
  assert.deepEqual(await f.lockFiles(), lockedOnce);
  assert.match(await journalText(f), /recovered/);
});

test("pre: a bucketless release that appears after the deletion sends the run to the recovery, which puts the saved release back", async (t) => {
  const f = await checkout(t);
  f.world.hook.read = (world, which) => (which === "bucketless" && world.deletes === 1 ? world.json({ name: "projects/fireemu-oracle-query/releases/firebase.storage", rulesetName: OTHER_RULESET, createTime: "2026-09-29T14:00:00Z", updateTime: "2026-09-29T14:00:00Z" }) : undefined);
  const result = await f.entry(f.options);
  assert.equal(result.status, "recovered");
  assert.deepEqual(f.world.posts, [{ name: RELEASE_NAME, rulesetName: RULESET }]);
  assert.equal(f.world.release.rulesetName, RULESET);
});

test("pre: a release that is still there after its deletion is recovered as unchanged", async (t) => {
  const f = await checkout(t);
  f.world.hook.delete = (world) => world.json({});
  const result = await f.entry(f.options);
  assert.equal(result.status, "recovered");
  assert.equal(f.world.release.rulesetName, RULESET);
  assert.deepEqual(f.world.posts, []);
});

test("pre: a recovery that finds another ruleset, or cannot publish the saved release again, touches nothing more and keeps the lock", async (t) => {
  const arrange = {
    "another ruleset appeared": (world) => { world.hook.delete = (w) => { w.release = releaseBody(OTHER_RULESET); throw new Error("connection lost"); }; },
    "the publication is refused": (world) => { world.hook.delete = (w) => { w.release = null; throw new Error("connection lost"); }; world.hook.post = (w) => w.json({ error: { code: 403, message: "no", status: "PERMISSION_DENIED" } }, 403); },
    "the publication answers another ruleset": (world) => { world.hook.delete = (w) => { w.release = null; throw new Error("connection lost"); }; world.hook.post = (w, body) => w.json({ ...releaseBody(OTHER_RULESET), name: body.name }); },
    "the release read back is another ruleset": (world) => {
      world.hook.delete = (w) => { w.release = null; throw new Error("connection lost"); };
      world.hook.post = (w, body) => { w.release = releaseBody(OTHER_RULESET); return w.json(releaseBody(body.rulesetName)); };
    },
    "the current read is unexpected": (world) => { world.hook.delete = (w) => { throw new Error("connection lost"); }; world.hook.read = (w, which) => (w.deletes === 1 && which === "bucket" ? w.json({ error: { code: 500, message: "boom", status: "INTERNAL" } }, 500) : undefined); },
  };
  for (const [name, set] of Object.entries(arrange)) {
    const f = await checkout(t);
    set(f.world);
    await assert.rejects(f.entry(f.options), undefined, name);
    assert.equal(f.world.deletes, 1, name);
    assert.ok(f.world.posts.length <= 1, name);
    assert.deepEqual(await f.lockFiles(), lockedOnce, name);
  }
});

test("post: the saved release is published again from the saved record and read back, and the lock is released", async (t) => {
  const f = await checkout(t, { mode: "post", world: createReleaseWorld({ release: null }) });
  const result = await f.entry(f.options);
  assert.equal(result.status, "finished");
  assert.equal(result.changed, true);
  assert.equal(result.mode, "post");
  assert.equal(result.requests, 7);
  assert.deepEqual(f.world.posts, [{ name: RELEASE_NAME, rulesetName: RULESET }]);
  assert.equal(f.world.release.rulesetName, RULESET);
  assert.equal(f.world.deletes, 0);
  assert.deepEqual(await f.lockFiles(), []);
  assert.deepEqual(urls(f).slice(2), [`GET /v1/${RULESET}`, `GET /v1/${RELEASE_NAME}`, "GET /v1/projects/fireemu-oracle-query/releases/firebase.storage", "POST /v1/projects/fireemu-oracle-query/releases", `GET /v1/${RELEASE_NAME}`]);
  for (const entry of f.wire.slice(1)) assert.equal(entry.headers.authorization, `Bearer ${OWNER_TOKEN}`);
});

test("post: a release that is already the saved one makes the run a no-op, so it can be run again as a recovery", async (t) => {
  const f = await checkout(t, { mode: "post" });
  const result = await f.entry(f.options);
  assert.equal(result.status, "finished");
  assert.equal(result.changed, false);
  assert.equal(result.requests, 5);
  assert.deepEqual(f.world.posts, []);
  assert.equal(f.world.deletes, 0);
});

test("post: what the saved record does not describe stops the run before anything is published", async (t) => {
  const cases = {
    "another ruleset is published": (world) => { world.release = releaseBody(OTHER_RULESET); },
    "the ruleset source changed": (world) => { world.ruleset.source = { files: [{ name: "storage.rules", content: "changed" }] }; world.release = null; },
    "the ruleset is gone": (world) => { world.release = null; world.hook.ruleset = () => world.json({ error: { code: 404, message: "gone", status: "NOT_FOUND" } }, 404); },
    "a bucketless release exists": (world) => { world.release = null; world.bucketless = { name: "projects/fireemu-oracle-query/releases/firebase.storage", rulesetName: RULESET, createTime: "2026-09-25T10:30:00Z", updateTime: "2026-09-25T10:30:00Z" }; },
    "the owner is someone else": (world) => { world.release = null; world.hook.identity = { id: "1", email: "other@example.test", verified_email: true }; },
  };
  for (const [name, arrange] of Object.entries(cases)) {
    const f = await checkout(t, { mode: "post" });
    arrange(f.world);
    await assert.rejects(f.entry(f.options), undefined, name);
    assert.deepEqual(f.world.posts, [], name);
  }
});

test("post: a publication that fails is recovered by one read: the saved release is there, or the run stops and keeps the lock", async (t) => {
  const lost = await checkout(t, { mode: "post", world: createReleaseWorld({ release: null }) });
  lost.world.hook.post = (world, body) => { world.release = { name: body.name, rulesetName: body.rulesetName, createTime: "2026-09-29T14:00:00.000000Z", updateTime: "2026-09-29T14:00:00.000000Z" }; throw new Error("connection lost"); };
  await assert.rejects(lost.entry(lost.options), /cannot confirm project lock closure/);
  assert.equal(lost.world.posts.length, 1);
  assert.equal(lost.world.release.rulesetName, RULESET);
  assert.deepEqual(await lost.lockFiles(), lockedOnce);
  assert.match(await journalText(lost), /recovered/);
  for (const [name, hook] of Object.entries({
    "refused": (world) => world.json({ error: { code: 403, message: "no", status: "PERMISSION_DENIED" } }, 403),
    "another ruleset answered": (world, body) => world.json({ ...releaseBody(OTHER_RULESET), name: body.name }),
  })) {
    const f = await checkout(t, { mode: "post", world: createReleaseWorld({ release: null }) });
    f.world.hook.post = hook;
    await assert.rejects(f.entry(f.options), undefined, name);
    assert.equal(f.world.posts.length, 1, name);
    assert.deepEqual(await f.lockFiles(), lockedOnce, name);
  }
});

test("the approval binds the run to its mode, its pins and its saved record", async (t) => {
  // A packet of the other mode, with the same pins otherwise, is not an approval of this run.
  const wrongName = await checkout(t, { mode: "post", world: createReleaseWorld({ release: null }), mutatePacket: (packet) => ({ ...packet, packetName: "stage2c-pre-v1" }) });
  await assert.rejects(wrongName.entry(wrongName.options));
  assert.equal(wrongName.wire.length, 0);
  // Limits of the other mode are refused (post cannot use pre's 11 requests, nor the other way).
  for (const [mode, maxRequests] of [["post", 11], ["pre", 8]]) {
    const f = await checkout(t, { mode, world: createReleaseWorld({ release: mode === "pre" ? releaseBody() : null }), mutatePacket: (packet) => ({ ...packet, maxRequests }) });
    await assert.rejects(f.entry(f.options));
    assert.equal(f.wire.length, 0);
  }
  // A saved record other than the one approved changes the corpus digest, so the pin no longer matches.
  const f = await checkout(t, { mode: "post", world: createReleaseWorld({ release: null }) });
  const other = makeSaved({ bucket: BUCKET, release: { ...releaseBody(OTHER_RULESET), bodySha256: canonicalDigest(releaseBody(OTHER_RULESET)) }, ruleset: { sourceSha256: SOURCE_SHA } });
  await writeFile(f.savedPath, JSON.stringify(other), { mode: 0o600 });
  await assert.rejects(f.entry(f.options), /pin mismatch: manifestSha256/);
  assert.equal(f.wire.length, 0);
  assert.deepEqual(await readdir(f.runs), ["sandbox-locks"]);
});

test("pins are recomputed before anything is created, and any mismatch, dirty tree or untracked runner file refuses the run", async (t) => {
  for (const [name, options] of Object.entries({
    "runner pin": { mutatePacket: (packet) => ({ ...packet, runnerSha256: "0".repeat(64) }), message: /pin mismatch: runnerSha256/ },
    "fixture schema pin": { mutatePacket: (packet) => ({ ...packet, fixtureSchemaSha256: "0".repeat(64) }), message: /pin mismatch: fixtureSchemaSha256/ },
    "manifest pin": { mutatePacket: (packet) => ({ ...packet, manifestSha256: "0".repeat(64) }), message: /pin mismatch: manifestSha256/ },
    "head is not the source commit": { gitHead: "b".repeat(40), message: /./ },
    "tracked change": { gitStatus: " M conformance/src/storage-rules/x.mjs\n", message: /./ },
    "untracked runner file of stage 3": { gitExtra: "?? conformance/src/storage-rules/extra.mjs\n", message: /untracked or ignored runner files/ },
    "untracked runner file of stage 2c": { gitExtraRelease: "?? conformance/src/storage-rules-release/extra.mjs\n", message: /untracked or ignored runner files/ },
    "git fails": { gitThrows: true, message: /source commit unreadable$/ },
  })) {
    const f = await checkout(t, options);
    await assert.rejects(f.entry(f.options), options.message, name);
    assert.equal(f.wire.length, 0, name);
    assert.deepEqual(await readdir(f.runs), ["sandbox-locks"], name);
    assert.deepEqual(await f.lockFiles(), [], name);
  }
});

test("the local inputs and the saved record are private, closed, and checked before anything is created", async (t) => {
  const cases = {
    "local inputs readable by others": async (f) => { await chmod(f.localPath, 0o644); },
    "local inputs is a symlink": async (f) => { await rm(f.localPath); await symlink(f.adcPath, f.localPath); },
    "local inputs with an extra field": async (f) => { await writeFile(f.localPath, JSON.stringify({ ...JSON.parse(await readFile(f.localPath, "utf8")), extra: 1 }), { mode: 0o600 }); },
    "local inputs with a bad bucket": async (f) => { await writeFile(f.localPath, JSON.stringify({ ...JSON.parse(await readFile(f.localPath, "utf8")), bucket: "Bad Bucket" }), { mode: 0o600 }); },
    "local inputs with a ruleset of another project": async (f) => { await writeFile(f.localPath, JSON.stringify({ ...JSON.parse(await readFile(f.localPath, "utf8")), expectedRulesetName: "projects/other/rulesets/x" }), { mode: 0o600 }); },
  };
  for (const [name, spoil] of Object.entries(cases)) {
    const f = await checkout(t);
    await spoil(f);
    await assert.rejects(f.entry(f.options), /local inputs file refused/, name);
    assert.equal(f.wire.length, 0, name);
  }
  const postCases = {
    "saved record readable by others": async (f) => { await chmod(f.savedPath, 0o644); },
    "saved record with an extra field": async (f) => { await writeFile(f.savedPath, JSON.stringify({ ...f.saved, extra: 1 }), { mode: 0o600 }); },
    "saved record of another release": async (f) => { await writeFile(f.savedPath, JSON.stringify({ ...f.saved, name: "projects/fireemu-oracle-query/releases/firebase.storage/other.appspot.com" }), { mode: 0o600 }); },
    "saved record that is not JSON": async (f) => { await writeFile(f.savedPath, "nope", { mode: 0o600 }); },
    "saved path relative": async (f) => { await writeFile(f.localPath, JSON.stringify({ ...JSON.parse(await readFile(f.localPath, "utf8")), savedPath: "saved.json" }), { mode: 0o600 }); },
  };
  for (const [name, spoil] of Object.entries(postCases)) {
    const f = await checkout(t, { mode: "post", world: createReleaseWorld({ release: null }) });
    await spoil(f);
    await assert.rejects(f.entry(f.options), /local inputs file refused/, name);
    assert.equal(f.wire.length, 0, name);
  }
});

test("an approval that is revoked, missing or already used refuses the run", async (t) => {
  const revoked = await checkout(t, { ledgerText: `${ledgerFor("pre", packetFor("pre", savedRecord()))}\n- 2026-09-29 | STORAGE-RULES stage2c-pre-v1 | decision=REVOKED; reason=test | Claude | private.md` });
  await assert.rejects(revoked.entry(revoked.options));
  assert.equal(revoked.wire.length, 0);
  const missing = await checkout(t, { ledgerText: "" });
  await assert.rejects(missing.entry(missing.options));
  assert.equal(missing.wire.length, 0);
  const used = await checkout(t, { usage: ["an-earlier-run"] });
  await assert.rejects(used.entry(used.options), /recording budget exhausted/);
  assert.equal(used.wire.filter((entry) => entry.method === "DELETE").length, 0);
  assert.equal(used.world.deletes, 0);
});

test("a revocation written while the run is going stops the very next request", async (t) => {
  const f = await checkout(t);
  const ledgerPath = join(f.root, "docs.local", "instructions", "owner-decisions.md");
  f.world.hook.delete = (world) => { throw new Error("unused"); };
  f.world.hook.ruleset = () => { writeFile(ledgerPath, `${ledgerFor("pre", packetFor("pre", f.saved))}\n- 2026-09-29 | STORAGE-RULES stage2c-pre-v1 | decision=REVOKED | Claude | private.md`, { mode: 0o644 }).catch(() => {}); return undefined; };
  const before = structuredClone(f.world.release);
  await assert.rejects(f.entry(f.options));
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(f.world.deletes, 0);
  assert.deepEqual(f.world.release, before);
});

const bodyDigest = canonicalDigest(releaseBody());
const releaseFact = (operationId, body, verdict = "present") => ({ operationId, kind: "rules-release-read", verdict, facts: body === null ? { status: 404 } : { status: 200, releaseName: body.name, rulesetName: body.rulesetName, createTime: body.createTime, updateTime: body.updateTime, bodySha256: canonicalDigest(body) } });
const rulesetFact = { operationId: "preflight/ruleset/saved", kind: "rules-ruleset-read", verdict: "present", facts: { status: 200, rulesetName: RULESET, createTime: "2026-09-25T10:29:00.111111Z", sourceSha256: SOURCE_SHA } };
const absent = (operationId) => releaseFact(operationId, null, "absent");
const restored = (n) => ({ name: RELEASE_NAME, rulesetName: RULESET, createTime: `2026-09-29T14:00:0${n}.000000Z`, updateTime: `2026-09-29T14:00:0${n}.000000Z` });
const refused = (world) => world.json({ error: { code: 403, message: "no", status: "PERMISSION_DENIED" } }, 403);
const broken = (world) => world.json({ error: { code: 500, message: "boom", status: "INTERNAL" } }, 500);

test("pre: the facts the run journals are what each read and write concluded, in order", async (t) => {
  const f = await checkout(t);
  await f.entry(f.options);
  assert.equal(bodyDigest, canonicalDigest(f.saved.name === RELEASE_NAME ? releaseBody() : null));
  assert.deepEqual(await factsOf(f), [rulesetFact, releaseFact("preflight/release/bucket", releaseBody()), absent("preflight/release/bucketless"), absent("release/bucket/absence"), absent("release/bucketless/absence")]);
});

test("pre: a deletion answered with an error after it was applied is recovered by publishing the release again, and the run reports it as unchanged", async (t) => {
  const f = await checkout(t);
  f.world.hook.delete = (world) => { world.release = null; return broken(world); };
  const result = await f.entry(f.options);
  assert.deepEqual([result.status, result.changed, result.released], ["recovered", false, true]);
  assert.deepEqual(f.world.posts, [{ name: RELEASE_NAME, rulesetName: RULESET }]);
  assert.deepEqual(await factsOf(f), [rulesetFact, releaseFact("preflight/release/bucket", releaseBody()), absent("preflight/release/bucketless"), absent("recovery/release/bucket/current"), releaseFact("recovery/release/bucket/after", restored(1))]);
  assert.deepEqual(await f.lockFiles(), []);
});

test("pre: a refused deletion is recovered as unchanged and journals the release it found", async (t) => {
  const f = await checkout(t);
  f.world.hook.delete = refused;
  const result = await f.entry(f.options);
  assert.deepEqual([result.status, result.changed], ["recovered", false]);
  assert.deepEqual((await factsOf(f)).slice(3), [releaseFact("recovery/release/bucket/current", releaseBody())]);
});

test("pre: each way the recovery cannot finish ends the run for the reason it names, and keeps the lock", async (t) => {
  const cases = [
    ["another ruleset appeared", (world) => { world.hook.delete = (w) => { w.release = releaseBody(OTHER_RULESET); throw new Error("connection lost"); }; }, /neither the saved one nor absent/],
    ["the publication is refused", (world) => { world.hook.delete = (w) => { w.release = null; throw new Error("connection lost"); }; world.hook.post = refused; }, /could not be published again/],
    ["the publication answers another ruleset while the release is right", (world) => { world.hook.delete = (w) => { w.release = null; throw new Error("connection lost"); }; world.hook.post = (w, body) => { w.release = releaseBody(body.rulesetName); return w.json(releaseBody(OTHER_RULESET)); }; }, /could not be published again/],
    ["the release read back is another ruleset", (world) => { world.hook.delete = (w) => { w.release = null; throw new Error("connection lost"); }; world.hook.post = (w, body) => { w.release = releaseBody(OTHER_RULESET); return w.json(releaseBody(body.rulesetName)); }; }, /published release is not the saved one/],
    ["the release read back is absent", (world) => { world.hook.delete = (w) => { w.release = null; throw new Error("connection lost"); }; world.hook.post = (w, body) => w.json(releaseBody(body.rulesetName)); }, /published release is not the saved one/],
    ["the current read is unexpected", (world) => { world.hook.delete = () => { throw new Error("connection lost"); }; world.hook.read = (w, which) => (w.deletes === 1 && which === "bucket" ? broken(w) : undefined); }, /neither the saved one nor absent/],
  ];
  for (const [name, set, reason] of cases) {
    const f = await checkout(t);
    set(f.world);
    await assert.rejects(f.entry(f.options), reason, name);
    assert.equal(f.world.deletes, 1, name);
    assert.ok(f.world.posts.length <= 1, name);
    assert.deepEqual(await f.lockFiles(), lockedOnce, name);
  }
});

test("pre: a revocation written after the deletion was attempted stops the run without a single recovery request, and keeps the lock", async (t) => {
  const f = await checkout(t);
  const ledgerPath = join(f.root, "docs.local", "instructions", "owner-decisions.md");
  f.world.hook.delete = (world) => { world.release = null; writeFileSync(ledgerPath, `${ledgerFor("pre", packetFor("pre", f.saved))}\n- 2026-09-29 | STORAGE-RULES stage2c-pre-v1 | decision=REVOKED | Claude | private.md`); return world.json({}); };
  await assert.rejects(f.entry(f.options), /admission refused/);
  assert.equal(f.world.deletes, 1);
  assert.deepEqual(f.world.posts, []);
  assert.deepEqual(urls(f).slice(-1), [`DELETE /v1/${RELEASE_NAME}`]);
  assert.deepEqual(await f.lockFiles(), lockedOnce);
  assert.match(await journalText(f), /needs-recovery/);
});

test("post: the facts the run journals, for a publication, for a release that is already there, and for a recovery", async (t) => {
  const f = await checkout(t, { mode: "post", world: createReleaseWorld({ release: null }) });
  await f.entry(f.options);
  assert.deepEqual(await factsOf(f), [rulesetFact, absent("preflight/release/bucket"), absent("preflight/release/bucketless"), releaseFact("release/bucket/after", restored(1))]);
  const there = await checkout(t, { mode: "post" });
  await there.entry(there.options);
  assert.deepEqual(await factsOf(there), [rulesetFact, releaseFact("preflight/release/bucket", releaseBody()), absent("preflight/release/bucketless")]);
  const recovered = await checkout(t, { mode: "post", world: createReleaseWorld({ release: null }) });
  recovered.world.hook.post = (world, body) => { world.release = { name: body.name, rulesetName: body.rulesetName, createTime: "2026-09-29T14:00:07.000000Z", updateTime: "2026-09-29T14:00:07.000000Z" }; return broken(world); };
  const result = await recovered.entry(recovered.options);
  assert.deepEqual([result.status, result.changed, result.released], ["recovered", true, true]);
  assert.deepEqual((await factsOf(recovered)).slice(3), [releaseFact("recovery/release/bucket/current", { name: RELEASE_NAME, rulesetName: RULESET, createTime: "2026-09-29T14:00:07.000000Z", updateTime: "2026-09-29T14:00:07.000000Z" })]);
});

test("post: each way a publication fails ends the run for the reason it names, and keeps the lock when the answer was lost", async (t) => {
  // The answer names another ruleset but the release is right: the recovery finds the saved release and the run ends recovered.
  const wrongAnswer = await checkout(t, { mode: "post", world: createReleaseWorld({ release: null }) });
  wrongAnswer.world.hook.post = (w, body) => { w.release = releaseBody(body.rulesetName); return w.json(releaseBody(OTHER_RULESET)); };
  const result = await wrongAnswer.entry(wrongAnswer.options);
  assert.deepEqual([result.status, result.changed, result.released], ["recovered", true, true]);
  const cases = {
    "the release read back is another ruleset": (world) => { world.hook.post = (w, body) => { w.release = releaseBody(OTHER_RULESET); return w.json(releaseBody(body.rulesetName)); }; },
    "the publication is refused": (world) => { world.hook.post = refused; },
    "the publication is accepted but nothing is there": (world) => { world.hook.post = (w, body) => w.json(releaseBody(body.rulesetName)); },
    "the publication is lost and nothing is there": (world) => { world.hook.post = () => { throw new Error("connection lost"); }; },
  };
  for (const [name, set] of Object.entries(cases)) {
    const f = await checkout(t, { mode: "post", world: createReleaseWorld({ release: null }) });
    set(f.world);
    await assert.rejects(f.entry(f.options), /saved release is not there/, name);
    assert.equal(f.world.posts.length, 1, name);
    assert.deepEqual(await f.lockFiles(), lockedOnce, name);
  }
});

test("the identity answer must be well-formed UTF-8, and the run stops before the ruleset is read", async (t) => {
  const f = await checkout(t);
  f.world.hook.any = (world, spec) => (new URL(spec.url).pathname === "/oauth2/v2/userinfo" ? { status: 200, rawHeaders: ["Content-Type", "application/json"], bytes: Buffer.concat([Buffer.from('{"id":"1","email":"owner@example.test","verified_email":true,"note":"'), Buffer.from([0xff]), Buffer.from('"}')]) } : undefined);
  await assert.rejects(f.entry(f.options));
  assert.equal(f.wire.length, 2);
  assert.equal(f.world.deletes, 0);
});

test("the owner ledger, the local inputs and the runs directory must be private files and directories of this user, and small", async (t) => {
  const cases = {
    "ledger writable by others": async (f) => { await chmod(join(f.root, "docs.local", "instructions", "owner-decisions.md"), 0o666); return /owner ledger refused/; },
    "ledger writable by the group": async (f) => { await chmod(join(f.root, "docs.local", "instructions", "owner-decisions.md"), 0o664); return /owner ledger refused/; },
    "ledger too large": async (f) => { await writeFile(join(f.root, "docs.local", "instructions", "owner-decisions.md"), Buffer.alloc(8 * 1024 * 1024 + 1, 0x20), { mode: 0o644 }); return /owner ledger refused/; },
    "ledger is not UTF-8": async (f) => { await writeFile(join(f.root, "docs.local", "instructions", "owner-decisions.md"), Buffer.concat([Buffer.from(ledgerFor("pre", packetFor("pre", f.saved)) + "\n"), Buffer.from([0xff])]), { mode: 0o644 }); return /owner ledger refused|admission refused/; },
    "local inputs hard-linked": async (f) => { linkSync(f.localPath, join(f.root, "local-link.json")); return /local inputs file refused/; },
    "local inputs too large": async (f) => { await writeFile(f.localPath, Buffer.concat([Buffer.from(JSON.stringify(preLocal(f.adcPath))), Buffer.alloc(64 * 1024, 0x20)]), { mode: 0o600 }); return /local inputs file refused/; },
    "local inputs is not UTF-8": async (f) => { await writeFile(f.localPath, Buffer.concat([Buffer.from(JSON.stringify(preLocal(f.adcPath)).replace(f.adcPath, `${f.adcPath}\u0000`).replace("\\u0000", "")), Buffer.from([0x20, 0xff])]), { mode: 0o600 }); return /local inputs file refused/; },
    "the ADC path is relative": async (f) => { await writeFile(f.localPath, JSON.stringify({ ...preLocal(f.adcPath), adcPath: "adc.json" }), { mode: 0o600 }); return /local inputs file refused/; },
    "the owner digest is short": async (f) => { await writeFile(f.localPath, JSON.stringify({ ...preLocal(f.adcPath), ownerEmailSha256: "abc" }), { mode: 0o600 }); return /local inputs file refused/; },
    "the runs directory is open to others": async (f) => { await chmod(f.runs, 0o755); return /runs directory refused/; },
    "the lock directory is open to others": async (f) => { await chmod(join(f.runs, "sandbox-locks"), 0o755); return /lock directory refused/; },
    "the lock directory is missing": async (f) => { await rm(join(f.runs, "sandbox-locks"), { recursive: true }); return /lock directory missing/; },
    "the runs directory is a symlink": async (f) => { await rename(f.runs, `${f.runs}-real`); await symlink(`${f.runs}-real`, f.runs); return /runs directory refused/; },
    "the run directory exists": async (f) => { await mkdir(join(f.runs, `storage-rules-release-${runId}`), { mode: 0o700 }); return /run directory exists/; },
    "the run directory cannot be created": async (f) => { await chmod(f.runs, 0o500); return /run directory refused/; },
  };
  for (const [name, spoil] of Object.entries(cases)) {
    const f = await checkout(t);
    const message = await spoil(f);
    await assert.rejects(f.entry(f.options), message, name);
    assert.equal(f.wire.length, 0, name);
    assert.equal(f.world.deletes, 0, name);
    await chmod(f.runs, 0o700).catch(() => {});
  }
});

test("the entry's own inputs are closed records: bad bindings and bad options are refused before anything is read", async (t) => {
  const f = await checkout(t);
  const binding = { root: f.root, codeRoot, requestImpl: () => {}, clock, git: async () => "" };
  for (const bad of [null, undefined, [], "x", { ...binding, extra: 1 }, { ...binding, root: 5 }, { ...binding, codeRoot: 5 }, { ...binding, git: 5 }, { ...binding, requestImpl: 5 }, { ...binding, clock: { nowSeconds: () => 1 } }, { ...binding, clock: null }, Object.assign(Object.create(null), binding)]) {
    assert.throws(() => bindReleaseEntry(bad), /invalid entry binding/);
  }
  const { root, ...withoutRoot } = binding;
  assert.throws(() => bindReleaseEntry(withoutRoot), /invalid entry binding/);
  assert.throws(() => bindReleaseEntry({ ...binding, root: join(f.root, "docs.local") }), /entry root is not a main checkout/);
  const spoiled = [
    null, undefined, [], "x", { ...f.options, extra: 1 }, { ...f.options, mode: "both" }, { ...f.options, mode: undefined }, { ...f.options, localPath: 5 }, { ...f.options, runId: 5 }, { ...f.options, runId: "Bad Id" }, { ...f.options, runId: "" },
    { ...f.options, sourceCommit: 5 }, { ...f.options, sourceCommit: "abc" }, { ...f.options, sourceCommit: "A".repeat(40) }, { ...f.options, packet: { ...f.options.packet, sourceCommit: "b".repeat(40) } }, { ...f.options, packet: [] }, { ...f.options, packet: null }, { ...f.options, packet: Object.create(null) },
    { ...f.options, review: 5 }, { ...f.options, review: [] }, { ...f.options, review: null }, { ...f.options, review: Object.create(null) },
    ...["runnerSha256", "fixtureSchemaSha256", "manifestSha256"].flatMap((key) => [{ ...f.options, packet: { ...f.options.packet, [key]: "abc" } }, { ...f.options, packet: { ...f.options.packet, [key]: "G".repeat(64) } }, { ...f.options, packet: { ...f.options.packet, [key]: 5 } }]),
  ];
  for (const options of spoiled) await assert.rejects(f.entry(options), /invalid release options/, JSON.stringify(options)?.slice(0, 80));
  assert.equal(f.wire.length, 0);
  assert.deepEqual(await readdir(f.runs), ["sandbox-locks"]);
});
