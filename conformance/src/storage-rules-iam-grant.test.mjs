import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from "node:fs/promises";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { bindIamEntry } from "./storage-rules-iam/iam-grant.mjs";
import { iamCorpus } from "./storage-rules-iam/plan.mjs";
import { iamCodeDigests } from "./storage-rules-iam/pins.mjs";
import { ADC, ENVELOPE_ID, GRANT_ROLE, MEMBER, NUMBERS, OTHER_BINDINGS, OWNER_SUBJECT, OWNER_TOKEN, PACKET_NAME, PIN_KEYS, SOURCE_COMMIT, cleanup, createIamWorld, fakeRequestImpl, localInputs, ownerDigest, scratchCode } from "./storage-rules-iam-support.mjs";

// The stage 2b entry against a scratch main checkout and a fake IAM world: what it reads, writes and leaves, and when it stops or recovers.
const codeRoot = scratchCode();
process.on("exit", () => cleanup(codeRoot));
const digests = await iamCodeDigests(codeRoot);
const corpus = iamCorpus({ projectNumber: NUMBERS.query, ownerEmailSha256: ownerDigest });
const packet = { taskId: "STORAGE-RULES", packetName: PACKET_NAME, packetSha256: "1".repeat(64), sourceCommit: SOURCE_COMMIT, runnerSha256: digests.runnerSha256, manifestSha256: corpus.sha256, fixtureSchemaSha256: digests.fixtureSchemaSha256, projects: ["fireemu-oracle-query"], maxRequests: 8, reserveUsd: 1 };
const review = { verdict: "APPROVE", must: [], should: [], ...Object.fromEntries(PIN_KEYS.map((key) => [key, packet[key]])), envelopeId: ENVELOPE_ID, withinEnvelope: true };
const ledger = [
  "- 2026-09-28 | 調整役への委任（本番の送信） | decision=APPROVE; local fixture | オーナー（ローカル試験） | private.md",
  "- 2026-09-28 | 調整役への委任（枠の承認） | decision=APPROVE; local fixture | オーナー（ローカル試験） | private.md",
  `- 2026-09-29 | STORAGE-RULES ${PACKET_NAME} envelope | envelopeId=${ENVELOPE_ID}; project=fireemu-oracle-query; maxRequests=8; reserveUsd=1; writes=one project IAM binding, the Storage service agent on the Firestore-reading role, only if absent; iamConfig=one binding added and read back, removed again if the result is wrong; retries=none; onStop=locks-held; 根拠=2026-09-28 調整役への委任（本番の送信） | Claude（委任。オーナーの裁量の委任 2026-09-28） | private.md`,
  `- 2026-09-29 | STORAGE-RULES ${PACKET_NAME} | decision=APPROVE; ${PIN_KEYS.map((key) => `${key}=${packet[key]}`).join("; ")}; envelopeId=${ENVELOPE_ID} | Claude（委任。枠の内の承認し直し） | private.md`,
].join("\n");
const clock = { nowSeconds: () => 1_800_000_000, waitUntilSeconds: async () => {}, sleep: async () => {} };
const runId = "iam-test-run";

async function checkout(t, { world = createIamWorld(), ledgerText = ledger, gitHead = SOURCE_COMMIT, gitStatus = "", gitExtra = "", usage = [], local = localInputs } = {}) {
  const root = await mkdtemp("/private/tmp/storage-rules-iam-");
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, ".git"));
  await mkdir(join(root, "docs.local", "instructions"), { recursive: true });
  const runs = join(root, "docs.local", "runs");
  await mkdir(runs, { mode: 0o700 });
  await chmod(runs, 0o700);
  await mkdir(join(runs, "sandbox-locks"), { mode: 0o700 });
  await chmod(join(runs, "sandbox-locks"), 0o700);
  await writeFile(join(root, "docs.local", "instructions", "owner-decisions.md"), ledgerText, { mode: 0o644 });
  if (usage.length > 0) await writeFile(join(runs, "storage-rules-iam-usage.jsonl"), usage.map((id) => `${JSON.stringify({ packetSha256: packet.packetSha256, runId: id })}\n`).join(""), { mode: 0o600 });
  const adcPath = join(root, "adc.json");
  await writeFile(adcPath, JSON.stringify(ADC), { mode: 0o600 });
  const localPath = join(root, "local.json");
  await writeFile(localPath, JSON.stringify(local(adcPath)), { mode: 0o600 });
  const wire = [];
  const gitCalls = [];
  const git = async (where, args) => { gitCalls.push([where, ...args]); return args[0] === "rev-parse" ? `${gitHead}\n` : args.includes("--ignored") ? gitExtra : gitStatus; };
  const entry = bindIamEntry({ root, codeRoot, requestImpl: fakeRequestImpl((spec) => world.answer(spec), wire), clock, git });
  const options = { localPath, runId, sourceCommit: SOURCE_COMMIT, packet: structuredClone(packet), review: structuredClone(review) };
  return { root, runs, entry, options, wire, world, gitCalls, localPath, lockFiles: async () => (await readdir(join(runs, "sandbox-locks"))).sort() };
}
async function walk(directory) {
  const out = [];
  for (const name of await readdir(directory)) {
    const path = join(directory, name);
    if ((await stat(path)).isDirectory()) out.push(...await walk(path)); else out.push(path);
  }
  return out;
}
const canonical = (bindings) => JSON.stringify(bindings.map((b) => ({ role: b.role, members: [...b.members].sort(), condition: b.condition ?? null })).sort((a, b) => (JSON.stringify([a.role, a.condition]) < JSON.stringify([b.role, b.condition]) ? -1 : 1)));
const lockedBoth = ["fireemu-oracle-query.lock"];
const journals = async (f) => { const dir = join(f.runs, `storage-rules-iam-${runId}`); return { dir, files: await readdir(dir) }; };

test("the grant is added once, read back, and the lock is released", async (t) => {
  const f = await checkout(t);
  const before = canonical(f.world.bindings);
  const result = await f.entry(f.options);
  assert.deepEqual({ ...result }, { status: "finished", changed: true, requests: 5, released: true });
  assert.deepEqual(f.wire.map((entry) => [entry.method, new URL(entry.url).pathname]), [["POST", "/token"], ["GET", "/oauth2/v2/userinfo"], ["POST", `/v3/projects/${NUMBERS.query}:getIamPolicy`], ["POST", `/v3/projects/${NUMBERS.query}:setIamPolicy`], ["POST", `/v3/projects/${NUMBERS.query}:getIamPolicy`]]);
  // Exactly one write: the policy as it was with the member added to the role's unconditional binding, the etag it was read with, and only bindings and etag written.
  assert.equal(f.world.sets.length, 1);
  const sent = f.world.sets[0];
  assert.equal(sent.updateMask, "bindings,etag");
  assert.equal(sent.policy.version, 3);
  assert.equal(sent.policy.etag, "BwYAAAAA");
  assert.deepEqual(Object.keys(sent).sort(), ["policy", "updateMask"]);
  assert.deepEqual(Object.keys(sent.policy).sort(), ["bindings", "etag", "version"]);
  const granted = f.world.bindings.find((b) => b.role === GRANT_ROLE);
  assert.deepEqual(granted, { role: GRANT_ROLE, members: [MEMBER] });
  assert.equal(f.world.bindings.length, OTHER_BINDINGS.length + 1);
  assert.equal(canonical(f.world.bindings.filter((b) => b.role !== GRANT_ROLE)), before);
  assert.deepEqual(await f.lockFiles(), []);
  assert.equal(await readFile(join(f.runs, "storage-rules-iam-usage.jsonl"), "utf8"), `${JSON.stringify({ packetSha256: packet.packetSha256, runId })}\n`);
  // Every request carries the owner's token and the query project as quota project, except the token request itself.
  // The one exception is the owner's own userinfo, which is not a project-billed API (with the header it answers 403 USER_PROJECT_DENIED).
  for (const entry of f.wire.slice(1)) {
    assert.equal(entry.headers.authorization, `Bearer ${OWNER_TOKEN}`);
    if (entry.url === "https://www.googleapis.com/oauth2/v2/userinfo") assert.equal(Object.hasOwn(entry.headers, "x-goog-user-project"), false);
    else assert.equal(entry.headers["x-goog-user-project"], "fireemu-oracle-query", entry.url);
  }
  assert.deepEqual(f.wire.filter((entry) => !Object.hasOwn(entry.headers, "x-goog-user-project")).map((entry) => entry.url), [f.wire[0].url, "https://www.googleapis.com/oauth2/v2/userinfo"]);
});

test("an existing binding for the role gets the member appended, and every other binding, member and condition stays", async (t) => {
  const world = createIamWorld({ bindings: [...OTHER_BINDINGS, { role: GRANT_ROLE, members: ["serviceAccount:other@example.test"] }, { role: GRANT_ROLE, members: ["user:c@example.test"], condition: { title: "cond", expression: "true" } }] });
  const f = await checkout(t, { world });
  const result = await f.entry(f.options);
  assert.equal(result.changed, true);
  const roleBindings = f.world.bindings.filter((b) => b.role === GRANT_ROLE);
  assert.deepEqual(roleBindings.map((b) => [b.members, b.condition ?? null]), [[["serviceAccount:other@example.test", MEMBER], null], [["user:c@example.test"], { title: "cond", expression: "true" }]]);
  assert.equal(f.world.bindings.length, OTHER_BINDINGS.length + 2);
});

test("a grant that is already there is left alone: no write, finished, changed false", async (t) => {
  const world = createIamWorld({ bindings: [...OTHER_BINDINGS, { role: GRANT_ROLE, members: [MEMBER] }] });
  const f = await checkout(t, { world });
  const result = await f.entry(f.options);
  assert.deepEqual({ ...result }, { status: "finished", changed: false, requests: 3, released: true });
  assert.equal(world.sets.length, 0);
  assert.deepEqual(await f.lockFiles(), []);
});

test("an ambiguous grant (conditional, or twice) stops at the read before, with nothing written and the lock kept", async (t) => {
  for (const bindings of [[...OTHER_BINDINGS, { role: GRANT_ROLE, members: [MEMBER], condition: { title: "c", expression: "true" } }], [...OTHER_BINDINGS, { role: GRANT_ROLE, members: [MEMBER, MEMBER] }], [...OTHER_BINDINGS, { role: GRANT_ROLE, members: [MEMBER] }, { role: GRANT_ROLE, members: [MEMBER, "user:z@example.test"] }]]) {
    const world = createIamWorld({ bindings });
    const f = await checkout(t, { world });
    await assert.rejects(f.entry(f.options), /preflight failed/);
    assert.equal(world.sets.length, 0);
    assert.equal(f.wire.length, 3);
    assert.deepEqual(await f.lockFiles(), lockedBoth);
    const { dir, files } = await journals(f);
    assert.match(await readFile(join(dir, files.find((name) => name.endsWith("reservations.jsonl"))), "utf8"), /preflight-failed/);
  }
});

test("another owner, an unverified address or a malformed identity stops at the identity read, before the policy is read", async (t) => {
  for (const identity of [{ id: "1", email: "someone-else@example.test", verified_email: true }, { id: "1", email: "owner@example.test", verified_email: false }, { id: "1", verified_email: true }, "x", { id: "1", email: 5, verified_email: true }]) {
    const world = createIamWorld();
    world.hook.identity = identity;
    const f = await checkout(t, { world });
    await assert.rejects(f.entry(f.options), /preflight failed/);
    assert.equal(f.wire.length, 2);
    assert.equal(world.reads, 0);
    assert.equal(world.sets.length, 0);
  }
});

test("a policy that cannot be read (error status, wrong shape) stops at the read before with nothing written", async (t) => {
  for (const bad of [() => ({ status: 403, rawHeaders: ["Content-Type", "application/json"], bytes: Buffer.from("{}") }), () => ({ status: 200, rawHeaders: ["Content-Type", "application/json"], bytes: Buffer.from("[]") }), () => ({ status: 200, rawHeaders: ["Content-Type", "application/json"], bytes: Buffer.from(JSON.stringify({ bindings: [{ role: "r", members: "x" }], etag: "e" })) }), () => ({ status: 200, rawHeaders: ["Content-Type", "application/json"], bytes: Buffer.from(JSON.stringify({ bindings: [] })) })]) {
    const world = createIamWorld();
    world.hook.read = bad;
    const f = await checkout(t, { world });
    await assert.rejects(f.entry(f.options), /preflight failed/);
    assert.equal(f.wire.length, 3);
    assert.equal(world.sets.length, 0);
  }
});

test("a write the service rejects leaves the policy as it was: the recovery reads it, finds nothing to undo, and releases the lock", async (t) => {
  for (const status of [403, 409, 400, 500]) {
    const world = createIamWorld();
    world.hook.set = () => ({ status, rawHeaders: ["Content-Type", "application/json"], bytes: Buffer.from("{}") });
    const f = await checkout(t, { world });
    const result = await f.entry(f.options);
    assert.deepEqual({ ...result }, { status: "recovered", changed: false, requests: 5, released: true }, String(status));
    assert.equal(world.sets.length, 1);
    assert.deepEqual(await f.lockFiles(), []);
    assert.equal(world.bindings.some((b) => b.role === GRANT_ROLE), false);
  }
});

test("a write whose answer is lost after it was applied is recovered (the grant it made is removed and read back absent), and the lock stays because an attempt was lost", async (t) => {
  const world = createIamWorld();
  const before = canonical(world.bindings);
  world.hook.set = (w, body, count) => { if (count === 1) { w.bindings = structuredClone(body.policy.bindings); w.bump(); throw new Error("connection reset"); } return undefined; };
  const f = await checkout(t, { world });
  await assert.rejects(f.entry(f.options), /cannot confirm project lock closure/);
  assert.equal(world.sets.length, 2);
  assert.equal(canonical(world.bindings), before);
  assert.equal(world.reads, 3);
  assert.deepEqual(f.wire.map((entry) => new URL(entry.url).pathname.replace(`/v3/projects/${NUMBERS.query}:`, "")), ["/token", "/oauth2/v2/userinfo", "getIamPolicy", "setIamPolicy", "getIamPolicy", "setIamPolicy", "getIamPolicy"]);
  // The removal is written with the etag of the policy just read, and the counter closed as recovered.
  assert.equal(world.sets[1].policy.etag, "BwYAAAAAx");
  assert.equal(world.sets[1].policy.bindings.some((b) => b.members.includes(MEMBER)), false);
  assert.deepEqual(await f.lockFiles(), lockedBoth);
  const { dir, files } = await journals(f);
  assert.match(await readFile(join(dir, files.find((name) => name.endsWith("reservations.jsonl"))), "utf8"), /"outcome":"recovered"/);
});

test("a lost write that was not applied is recovered with nothing to undo, and the lock stays because an attempt was lost", async (t) => {
  const world = createIamWorld();
  world.hook.set = () => { throw new Error("connection reset"); };
  const f = await checkout(t, { world });
  await assert.rejects(f.entry(f.options), /cannot confirm project lock closure/);
  assert.equal(world.sets.length, 1);
  assert.equal(world.reads, 2);
  assert.deepEqual(await f.lockFiles(), lockedBoth);
  const { dir, files } = await journals(f);
  assert.match(await readFile(join(dir, files.find((name) => name.endsWith("reservations.jsonl"))), "utf8"), /"outcome":"recovered"/);
});

test("a policy after the write that is not the policy before with the grant is undone, and undone only when nothing else changed", async (t) => {
  // Someone else's change lands between the write and the read back: the recovery sees a policy that is neither, touches nothing and keeps the lock.
  const world = createIamWorld();
  world.hook.beforeRead = (w) => { if (w.sets.length === 1 && w.reads === 2) { w.bindings.push({ role: "roles/viewer", members: ["user:new@example.test"] }); w.bump(); } };
  const f = await checkout(t, { world });
  await assert.rejects(f.entry(f.options), /neither the one before nor the one before with the grant/);
  assert.equal(world.sets.length, 1);
  assert.deepEqual(await f.lockFiles(), lockedBoth);
  assert.equal(world.bindings.some((b) => b.role === GRANT_ROLE), true);
  // The journal closed as needs-recovery.
  const { dir, files } = await journals(f);
  const text = await readFile(join(dir, files.find((name) => name.endsWith("reservations.jsonl"))), "utf8");
  assert.match(text, /needs-recovery/);
});

test("a write that lands but reads back as another policy is undone when only the grant differs", async (t) => {
  // The read back is wrong once (a stale answer), the recovery reads the truth: the policy before with the grant, which is then removed.
  const world = createIamWorld();
  const before = canonical(world.bindings);
  world.hook.read = (w, count) => (count === 2 ? { status: 200, rawHeaders: ["Content-Type", "application/json"], bytes: Buffer.from(JSON.stringify({ etag: "stale", bindings: [] })) } : undefined);
  const f = await checkout(t, { world });
  const result = await f.entry(f.options);
  assert.deepEqual({ ...result }, { status: "recovered", changed: false, requests: 8, released: true });
  assert.equal(canonical(world.bindings), before);
  assert.equal(world.sets.length, 2);
});

test("a removal the service rejects, or a removal that reads back wrong, keeps the lock and is needs-recovery", async (t) => {
  for (const mode of ["rejected", "lost", "readback"]) {
    const world = createIamWorld();
    world.hook.set = (w, body, count) => {
      if (count === 1) { w.bindings = structuredClone(body.policy.bindings); w.bump(); throw new Error("connection reset"); }
      if (mode === "rejected") return { status: 403, rawHeaders: ["Content-Type", "application/json"], bytes: Buffer.from("{}") };
      if (mode === "lost") throw new Error("connection reset");
      w.bindings = structuredClone(body.policy.bindings); w.bump(); w.bindings.push({ role: "roles/viewer", members: ["user:late@example.test"] });
      return { status: 200, rawHeaders: ["Content-Type", "application/json"], bytes: Buffer.from(JSON.stringify(w.policyBody())) };
    };
    const f = await checkout(t, { world });
    await assert.rejects(f.entry(f.options), Error, mode);
    // The removal is tried once; it is read back only when the service said it was applied.
    assert.equal(f.wire.length, { rejected: 6, lost: 6, readback: 7 }[mode], mode);
    assert.deepEqual(await f.lockFiles(), lockedBoth, mode);
    const { dir, files } = await journals(f);
    assert.match(await readFile(join(dir, files.find((name) => name.endsWith("reservations.jsonl"))), "utf8"), /needs-recovery/, mode);
  }
});

test("the journals hold no token, refresh secret or owner address, and the facts hold counts and digests only", async (t) => {
  const f = await checkout(t);
  await f.entry(f.options);
  const { dir } = await journals(f);
  const secrets = [OWNER_TOKEN, ADC.refresh_token, ADC.client_secret, "owner@example.test", OWNER_SUBJECT];
  for (const file of await walk(dir)) {
    const text = (await readFile(file)).toString("latin1");
    for (const secret of secrets) for (const form of [secret, encodeURIComponent(secret), Buffer.from(secret).toString("base64"), Buffer.from(secret).toString("hex")]) assert.equal(text.includes(form), false, `${secret.slice(0, 14)} in ${file}`);
    assert.equal((await stat(file)).mode & 0o077, 0, file);
  }
  const captures = (await readFile(join(dir, (await readdir(dir)).find((name) => name.endsWith("captures.jsonl"))), "utf8")).split("\n").filter(Boolean).map((line) => JSON.parse(line));
  const facts = captures.filter((row) => row.event === "facts");
  assert.deepEqual(facts.map((row) => [row.data.operationId, row.data.facts.grant]), [["preflight/query/iam-before", "absent"], ["iam/query/after", "present"]]);
  assert.equal(facts[1].data.facts.bindings, facts[0].data.facts.bindings + 1);
  assert.notEqual(facts[0].data.facts.policySha256, facts[1].data.facts.policySha256);
  assert.equal(JSON.stringify(facts).includes(MEMBER), false);
  assert.equal(JSON.stringify(facts).includes("user:"), false);
});

test("the run is refused, before anything is created, unless the code, the schema, the corpus and the checkout reproduce the approval's pins", async (t) => {
  const cases = [
    ["runnerSha256", (f) => { f.options.packet.runnerSha256 = "0".repeat(64); }, /pin mismatch: runnerSha256/],
    ["fixtureSchemaSha256", (f) => { f.options.packet.fixtureSchemaSha256 = "0".repeat(64); }, /pin mismatch: fixtureSchemaSha256/],
    ["manifestSha256", (f) => { f.options.packet.manifestSha256 = "0".repeat(64); }, /pin mismatch: manifestSha256/],
    ["runner digest not hex", (f) => { f.options.packet.runnerSha256 = "X".repeat(64); }, /invalid iam options/],
    ["a digest with a suffix", (f) => { f.options.packet.manifestSha256 = `${f.options.packet.manifestSha256}0`; }, /invalid iam options/],
    ["a digest that is not a string", (f) => { f.options.packet.fixtureSchemaSha256 = 5; }, /invalid iam options/],
    ["the commit of the packet is another one", (f) => { f.options.packet.sourceCommit = "b".repeat(40); }, /invalid iam options/],
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
  // The stage 2b directory is hashed too, so an untracked or ignored file there is refused by its own check.
  const ignoredIam = await checkout(t);
  const iamOnly = bindIamEntry({ root: ignoredIam.root, codeRoot, requestImpl() {}, clock, git: async (where, args) => (args[0] === "rev-parse" ? `${SOURCE_COMMIT}\n` : args.includes("conformance/src/storage-rules-iam") ? "!! conformance/src/storage-rules-iam/scratch.mjs\n" : "") });
  await assert.rejects(iamOnly(ignoredIam.options), /untracked or ignored runner files/);
  const brokenGit = await checkout(t);
  const broken = bindIamEntry({ root: brokenGit.root, codeRoot, requestImpl() {}, clock, git: async () => { throw new Error("git missing"); } });
  await assert.rejects(broken(brokenGit.options), /source commit unreadable/);
  const halfGit = await checkout(t);
  const half = bindIamEntry({ root: halfGit.root, codeRoot, requestImpl() {}, clock, git: async (where, args) => { if (args.includes("conformance/src/storage-rules-iam")) throw new Error("git missing"); return args[0] === "rev-parse" ? `${SOURCE_COMMIT}\n` : ""; } });
  await assert.rejects(half(halfGit.options), /source commit unreadable/);
  const emptyCode = await mkdtemp("/private/tmp/storage-rules-iam-empty-code-");
  t.after(() => rm(emptyCode, { recursive: true, force: true }));
  const noCode = await checkout(t);
  const blind = bindIamEntry({ root: noCode.root, codeRoot: emptyCode, requestImpl() {}, clock, git: async () => "" });
  await assert.rejects(blind(noCode.options), /pin source refused/);
  const other = await checkout(t, { local: (adc) => ({ ...localInputs(adc), projectNumber: "999999999999" }) });
  await assert.rejects(other.entry(other.options), /pin mismatch: manifestSha256/);
  const otherOwner = await checkout(t, { local: (adc) => ({ ...localInputs(adc), ownerEmailSha256: "0".repeat(64) }) });
  await assert.rejects(otherOwner.entry(otherOwner.options), /pin mismatch: manifestSha256/);
  for (const state of [moved, dirty, untrackedRunner, ignoredIam, brokenGit, halfGit, noCode, other, otherOwner]) { assert.deepEqual(await readdir(state.runs), ["sandbox-locks"]); assert.equal(state.wire.length, 0); }
});

test("a revoked approval, a wrong bound, a missing envelope and a second recording are refused with nothing sent", async (t) => {
  const stopped = async (state, message) => { await assert.rejects(state.entry(state.options), message); assert.equal(state.wire.length, 0); assert.deepEqual(await state.lockFiles(), []); };
  await stopped(await checkout(t, { ledgerText: `${ledger}\n- 2026-09-29 | STORAGE-RULES ${PACKET_NAME} | decision=REVOKED; packetSha256=${packet.packetSha256} | オーナー（ローカル試験） | note.md` }), /approval revoked/);
  await stopped(await checkout(t, { ledgerText: `${ledger}\n- 2026-09-29 | STORAGE-RULES | revoked | オーナー（ローカル試験） | note.md` }), /approval revoked/);
  await stopped(await checkout(t, { ledgerText: `${ledger}\n- 2026-09-30 | 全体 | decision=REVOKED; すべて取り消す | オーナー（ローカル試験） | note.md` }), /approval revoked/);
  await stopped(await checkout(t, { ledgerText: ledger.split("\n").filter((line) => !line.includes("envelope |")).join("\n") }), /preceding owner envelope required/);
  await stopped(await checkout(t, { ledgerText: ledger.replace("maxRequests=8;", "maxRequests=7;") }), /packet exceeds owner envelope/);
  await stopped(await checkout(t, { ledgerText: ledger.replace("reserveUsd=1;", "reserveUsd=0.5;") }), /packet exceeds owner envelope/);
  await stopped(await checkout(t, { ledgerText: ledger.replace("project=fireemu-oracle-query;", "project=fireemu-oracle-idp,fireemu-oracle-query;") }), /packet exceeds owner envelope/);
  await stopped(await checkout(t, { ledgerText: `${ledger}\n- 2026-09-30 | 調整役への委任（本番の送信） | decision=REVOKED | オーナー（直接） | note.md` }), /delegation revoked/);
  for (const [label, changed] of [["stage 3 limits", { maxRequests: 12344, reserveUsd: 2, projects: ["fireemu-oracle-idp", "fireemu-oracle-query"] }], ["stage 2a limits", { maxRequests: 13, reserveUsd: 0.01, projects: ["fireemu-oracle-idp", "fireemu-oracle-query"] }], ["two projects", { projects: ["fireemu-oracle-idp", "fireemu-oracle-query"] }], ["idp only", { projects: ["fireemu-oracle-idp"] }], ["more requests", { maxRequests: 9 }], ["a bigger reserve", { reserveUsd: 2 }]]) {
    const state = await checkout(t);
    state.options.packet = { ...state.options.packet, ...changed };
    await stopped(state, /runner limit mismatch/);
    void label;
  }
  const second = await checkout(t, { usage: ["first-iam-run"] });
  await assert.rejects(second.entry(second.options), /recording budget exhausted/);
  assert.equal(second.wire.length, 0);
  assert.deepEqual(await second.lockFiles(), []);
});

test("a global revocation stops the grant only when it is written after the decision row", async (t) => {
  const global = "- 2026-09-30 | 全体 | decision=REVOKED; すべての本番送信承認を取り消す | オーナー（ローカル試験） | note.md";
  const status = `- 2026-09-30 | STORAGE-RULES ${PACKET_NAME} status | packetSha256=${packet.packetSha256}; outcome=noted | note.md`;
  const decision = ledger.split("\n").at(-1);
  for (const [name, text] of [["after", `${ledger}\n${global}`], ["after with a status line", `${ledger}\n${global}\n${status}`]]) {
    const f = await checkout(t, { ledgerText: text });
    await assert.rejects(f.entry(f.options), /approval revoked/, name);
    assert.equal(f.wire.length, 0, name);
  }
  for (const [name, text] of [["before", `${global}\n${ledger}`], ["superseded", `${ledger}\n${global}\n${decision}\n${status}`]]) {
    const f = await checkout(t, { ledgerText: text });
    assert.equal((await f.entry(f.options)).status, "finished", name);
  }
});

test("a caller cannot name the ledger, the locks, the usage ledger, the run directory, the transport, the clock, the credentials or the policy", async (t) => {
  const f = await checkout(t);
  const overrides = { readLedger: async () => "", ledger: "/x", locks: {}, lockDir: "/x", usagePath: "/x", directory: "/x", transport: {}, clock, root: "/x", requestImpl() {}, adcPath: "/x", inputsPath: "/x", policy: {}, member: "user:x", role: "roles/owner", body: {}, use() {} };
  for (const [name, value] of Object.entries(overrides)) await assert.rejects(f.entry({ ...f.options, [name]: value }), /invalid iam options/, name);
  for (const key of Object.keys(f.options)) { const { [key]: _, ...rest } = f.options; await assert.rejects(f.entry(rest), /invalid iam options/, key); }
  for (const bad of ["Bad Id", "", 5, "a".repeat(49)]) await assert.rejects(f.entry({ ...f.options, runId: bad }), /invalid iam options/, String(bad));
  assert.deepEqual(await readdir(f.runs), ["sandbox-locks"]);
  assert.equal(f.wire.length, 0);
});

test("the operator's local inputs file is a private, closed, plain file with a project number and an owner digest", async (t) => {
  const write = async (f, value, mode = 0o600) => { await writeFile(f.localPath, typeof value === "string" ? value : JSON.stringify(value), { mode }); await chmod(f.localPath, mode); };
  const cases = {
    "wide mode": async (f) => write(f, localInputs("/x/adc.json"), 0o640), "not json": async (f) => write(f, "not json"), "extra key": async (f) => write(f, { ...localInputs("/x/adc.json"), extra: 1 }),
    "missing key": async (f) => write(f, { schemaVersion: 1, adcPath: "/x/adc.json", projectNumber: NUMBERS.query }), "wrong version": async (f) => write(f, { ...localInputs("/x/adc.json"), schemaVersion: 2 }),
    "bad number": async (f) => write(f, { ...localInputs("/x/adc.json"), projectNumber: "012" }), "number not a string": async (f) => write(f, { ...localInputs("/x/adc.json"), projectNumber: 111111111111 }),
    "bad digest": async (f) => write(f, { ...localInputs("/x/adc.json"), ownerEmailSha256: "abc" }), "upper digest": async (f) => write(f, { ...localInputs("/x/adc.json"), ownerEmailSha256: ownerDigest.toUpperCase() }),
    "relative adc": async (f) => write(f, { ...localInputs("/x/adc.json"), adcPath: "adc.json" }), "missing": async (f) => rm(f.localPath),
    "a directory": async (f) => { await rm(f.localPath); await mkdir(f.localPath); },
    "a link to a valid file": async (f) => { const real = join(f.root, "real.json"); await writeFile(real, JSON.stringify(localInputs(join(f.root, "adc.json"))), { mode: 0o600 }); await rm(f.localPath); await symlink(real, f.localPath); },
  };
  for (const [name, change] of Object.entries(cases)) {
    const f = await checkout(t);
    await change(f);
    await assert.rejects(f.entry(f.options), /local inputs file refused/, name);
    assert.equal(f.wire.length, 0, name);
    assert.deepEqual(await readdir(f.runs), ["sandbox-locks"], name);
  }
});

test("the ledger and the runs and lock directories must be private and plain, as for the stage 3 entry", async (t) => {
  const cases = {
    "ledger group writable": [async (f) => chmod(join(f.root, "docs.local", "instructions", "owner-decisions.md"), 0o664), /owner ledger refused/],
    "ledger missing": [async (f) => rm(join(f.root, "docs.local", "instructions", "owner-decisions.md")), /owner ledger refused/],
    "lock dir shared": [async (f) => chmod(join(f.runs, "sandbox-locks"), 0o750), /lock directory refused/],
    "runs dir shared": [async (f) => chmod(f.runs, 0o755), /runs directory refused/],
    "run directory exists": [async (f) => mkdir(join(f.runs, `storage-rules-iam-${runId}`), { mode: 0o700 }), /run directory exists/],
    "legacy lock": [async (f) => writeFile(join(f.runs, "sandbox-ledger.jsonl.lock"), "{}\n", { mode: 0o600 }), /legacy shared lock exists/],
    "the query lock is held": [async (f) => writeFile(join(f.runs, "sandbox-locks", "fireemu-oracle-query.lock"), "{}\n", { mode: 0o600 }), /project lock exists/],
  };
  for (const [name, [change, message]] of Object.entries(cases)) {
    const f = await checkout(t);
    await change(f);
    await assert.rejects(f.entry(f.options), message, name);
    assert.equal(f.wire.length, 0, name);
  }
  // The idp lock is not this run's business: it is taken by nobody and does not stop it.
  const f = await checkout(t);
  await writeFile(join(f.runs, "sandbox-locks", "fireemu-oracle-idp.lock"), "{}\n", { mode: 0o600 });
  assert.equal((await f.entry(f.options)).status, "finished");
});

test("the binding is a closed record for a main checkout, the real request function, a clock and git", async (t) => {
  const f = await checkout(t);
  const good = { root: f.root, codeRoot, requestImpl() {}, clock, git: async () => "" };
  assert.doesNotThrow(() => bindIamEntry(good));
  for (const bad of [null, {}, { ...good, extra: 1 }, { root: f.root, codeRoot, requestImpl() {}, clock }, { ...good, codeRoot: 5 }, { ...good, git: 5 }, { ...good, requestImpl: 5 }, { ...good, root: 5 }, { ...good, clock: { nowSeconds() {} } }, { ...good, root: join(f.root, "docs.local") }]) {
    assert.throws(() => bindIamEntry(bad), /invalid entry binding|entry root is not a main checkout|main repository root not found/);
  }
});

test("a run that succeeds leaves the classified facts of the recovery-free path and asks git the exact questions", async (t) => {
  const f = await checkout(t);
  await f.entry(f.options);
  assert.deepEqual(f.gitCalls.map(([where, ...args]) => [where, args.join(" ")]), [[codeRoot, "rev-parse HEAD"], [codeRoot, "status --porcelain --untracked-files=no"], [codeRoot, "status --porcelain --untracked-files=all --ignored -- conformance/src/storage-rules spec/compatibility/closure/STORAGE-RULES.json"], [codeRoot, "status --porcelain --untracked-files=all --ignored -- conformance/src/storage-rules-iam"]]);
});

test("a recovery journals what it found: the policy now, and the policy after the removal", async (t) => {
  const world = createIamWorld();
  world.hook.set = (w, body, count) => { if (count === 1) { w.bindings = structuredClone(body.policy.bindings); w.bump(); throw new Error("connection reset"); } return undefined; };
  const f = await checkout(t, { world });
  await assert.rejects(f.entry(f.options), /cannot confirm project lock closure/);
  const { dir } = await journals(f);
  const captures = (await readFile(join(dir, (await readdir(dir)).find((name) => name.endsWith("captures.jsonl"))), "utf8")).split("\n").filter(Boolean).map((line) => JSON.parse(line));
  const facts = captures.filter((row) => row.event === "facts").map((row) => [row.data.operationId, row.data.facts.grant]);
  assert.deepEqual(facts, [["preflight/query/iam-before", "absent"], ["recovery/iam/query/current", "present"], ["recovery/iam/query/absent", "absent"]]);
});

test("an unreadable policy in the recovery, or a ledger revoked while the grant is in flight, ends the run as needs-recovery and keeps the lock", async (t) => {
  // The write is lost after it was applied, and the recovery cannot read the policy back.
  const unreadable = createIamWorld();
  unreadable.hook.set = (w, body) => { w.bindings = structuredClone(body.policy.bindings); w.bump(); throw new Error("connection reset"); };
  unreadable.hook.read = (w, count) => (count === 2 ? { status: 200, rawHeaders: ["Content-Type", "application/json"], bytes: Buffer.from("not json") } : undefined);
  const a = await checkout(t, { world: unreadable });
  await assert.rejects(a.entry(a.options), /could not be read back/);
  assert.deepEqual(await a.lockFiles(), lockedBoth);
  const first = await journals(a);
  assert.match(await readFile(join(first.dir, first.files.find((name) => name.endsWith("reservations.jsonl"))), "utf8"), /needs-recovery/);
  // The owner revokes the approval while the grant is in flight: nothing more is sent, and the journal still says needs-recovery.
  const revoking = createIamWorld();
  const b = await checkout(t, { world: revoking });
  revoking.hook.set = (w, body) => { writeFileSync(join(b.root, "docs.local", "instructions", "owner-decisions.md"), `${ledger}\n- 2026-09-30 | STORAGE-RULES | revoked | オーナー（ローカル試験） | note.md`); return undefined; };
  await assert.rejects(b.entry(b.options), /admission refused/);
  assert.equal(b.wire.length, 4);
  assert.deepEqual(await b.lockFiles(), lockedBoth);
  const second = await journals(b);
  assert.match(await readFile(join(second.dir, second.files.find((name) => name.endsWith("reservations.jsonl"))), "utf8"), /needs-recovery/);
});
