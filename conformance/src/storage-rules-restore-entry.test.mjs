import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, readdir, rename, rm, symlink, writeFile } from "node:fs/promises";
import { linkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { bindRestoreEntry, readLocalInputs } from "./storage-rules-restore/restore-entry.mjs";
import { allIdsOf, restoreCorpus, restoreRequests } from "./storage-rules-restore/plan.mjs";
import { restoreCodeDigests } from "./storage-rules-restore/pins.mjs";
import { parseState } from "./storage-rules-restore/state.mjs";
import { ADC, BUCKET, OWNER_EMAIL, OWNER_SUBJECT, OWNER_TOKEN, PIN_KEYS, SOURCE_COMMIT, STATE, cleanup, createRestoreWorld, fakeRequestImpl, ownerDigest, restoreLocal, scratchCode } from "./storage-rules-restore-support.mjs";

// The stage 2e entry against a scratch main checkout and a fake production that holds the expected state: what it reads, deletes, writes and leaves, and when it stops.
const codeRoot = scratchCode();
process.on("exit", () => cleanup(codeRoot));
const digests = await restoreCodeDigests(codeRoot);
const clock = { nowSeconds: () => 1_800_000_000, waitUntilSeconds: async () => {}, sleep: async () => {} };
const runId = "restore-test-run";
const state = parseState(STATE);
const corpus = restoreCorpus({ state, ownerEmailSha256: ownerDigest });
const packet = { taskId: "STORAGE-RULES", packetName: "stage2e-restore-v1", packetSha256: "1".repeat(64), sourceCommit: SOURCE_COMMIT, runnerSha256: digests.runnerSha256, manifestSha256: corpus.sha256, fixtureSchemaSha256: digests.fixtureSchemaSha256, projects: ["fireemu-oracle-query"], maxRequests: 39, reserveUsd: 0.25 };
const ENVELOPE = "STORAGE-RULES-stage2e-restore-v1-001";
const review = { verdict: "APPROVE", must: [], should: [], ...Object.fromEntries(PIN_KEYS.map((key) => [key, packet[key]])), envelopeId: ENVELOPE, withinEnvelope: true };
const ledger = [
  "- 2026-09-28 | 調整役への委任（本番の送信） | decision=APPROVE; local fixture | オーナー（ローカル試験） | private.md",
  "- 2026-09-28 | 調整役への委任（枠の承認） | decision=APPROVE; local fixture | オーナー（ローカル試験） | private.md",
  `- 2026-09-30 | STORAGE-RULES stage2e-restore-v1 envelope | envelopeId=${ENVELOPE}; project=fireemu-oracle-query; maxRequests=39; reserveUsd=0.25; writes=deletes only the journaled objects, accounts and rulesets; iamConfig=none; retries=none; onStop=locks-held; 根拠=2026-09-28 調整役への委任（本番の送信） | Claude（委任。オーナーの裁量の委任 2026-09-28） | private.md`,
  `- 2026-09-30 | STORAGE-RULES stage2e-restore-v1 | decision=APPROVE; ${PIN_KEYS.map((key) => `${key}=${packet[key]}`).join("; ")}; envelopeId=${ENVELOPE} | Claude（委任。枠の内の承認し直し） | private.md`,
].join("\n");

async function checkout(t, { world = createRestoreWorld(), gitHead = SOURCE_COMMIT, gitStatus = "", gitExtra = "", gitExtraRestore = "", gitThrows = false, usage = [], mutatePacket = (value) => value, ledgerText = ledger, stateValue = STATE } = {}) {
  const root = await mkdtemp("/private/tmp/storage-rules-restore-");
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, ".git"));
  await mkdir(join(root, "docs.local", "instructions"), { recursive: true });
  const runs = join(root, "docs.local", "runs");
  await mkdir(runs, { mode: 0o700 });
  await chmod(runs, 0o700);
  await mkdir(join(runs, "sandbox-locks"), { mode: 0o700 });
  await chmod(join(runs, "sandbox-locks"), 0o700);
  const used = mutatePacket(structuredClone(packet));
  await writeFile(join(root, "docs.local", "instructions", "owner-decisions.md"), ledgerText, { mode: 0o644 });
  if (usage.length > 0) await writeFile(join(runs, "storage-rules-restore-usage.jsonl"), usage.map((id) => `${JSON.stringify({ packetSha256: used.packetSha256, runId: id })}\n`).join(""), { mode: 0o600 });
  const adcPath = join(root, "adc.json");
  await writeFile(adcPath, JSON.stringify(ADC), { mode: 0o600 });
  const statePath = join(root, "state.json");
  await writeFile(statePath, JSON.stringify(stateValue), { mode: 0o600 });
  const localPath = join(root, "local.json");
  await writeFile(localPath, JSON.stringify(restoreLocal(adcPath, statePath)), { mode: 0o600 });
  const wire = [];
  const git = async (where, args) => { if (gitThrows) throw new Error("git failed"); if (args[0] === "rev-parse") return `${gitHead}\n`; if (args.includes("--ignored")) return args.includes("conformance/src/storage-rules-restore") ? gitExtraRestore : gitExtra; return gitStatus; };
  const entry = bindRestoreEntry({ root, codeRoot, requestImpl: fakeRequestImpl((spec) => world.answer(spec), wire), clock, git });
  const options = { localPath, runId, sourceCommit: SOURCE_COMMIT, packet: used, review: structuredClone(review) };
  return { root, runs, entry, options, wire, world, localPath, adcPath, statePath, ledgerPath: join(root, "docs.local", "instructions", "owner-decisions.md"), lockFiles: async () => (await readdir(join(runs, "sandbox-locks"))).sort() };
}
const runDir = (f) => join(f.runs, `storage-rules-restore-${runId}`);
const readLines = async (f, name) => (await readFile(join(runDir(f), name), "utf8")).split("\n").filter(Boolean).map((line) => JSON.parse(line));
const factsOf = async (f) => (await readLines(f, "captures.jsonl")).flatMap((row) => { const data = row.data ?? row; return data.facts !== undefined && data.kind === "restore-answer" ? [{ operationId: data.operationId, facts: data.facts }] : []; });
const terminalOf = async (f) => (await readLines(f, "reservations.jsonl")).at(-1).data.outcome;
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const urls = (f) => f.wire.map((entry) => `${entry.method} ${new URL(entry.url).host}${new URL(entry.url).pathname}${new URL(entry.url).search}`);
const lockedOnce = ["fireemu-oracle-query.lock"];
const requests = restoreRequests(state);
const byId = (id) => requests.find((entry) => entry.id === id);
const at = (id) => (spec) => spec.method === byId(id).method && spec.url === byId(id).url && (byId(id).body === null || spec.body.equals(byId(id).body));
const second = (id) => { let seen = 0; return (spec) => at(id)(spec) && ++seen === 2; };
const cleanWorld = (world) => world.objects.size === 0 && world.accounts.size === 0 && world.rulesets.size === 0;

test("a clean run reads everything first, deletes the objects, then the accounts, then the rulesets, verifies, and releases the lock", async (t) => {
  const f = await checkout(t);
  const result = await f.entry(f.options);
  assert.deepEqual([result.status, result.changed, result.released, result.requests], ["finished", true, true, 39]);
  assert.equal(await terminalOf(f), "finished");
  assert.deepEqual(await f.lockFiles(), []);
  assert.equal(cleanWorld(f.world), true);
  assert.deepEqual(urls(f), ["POST oauth2.googleapis.com/token", "GET www.googleapis.com/oauth2/v2/userinfo", ...requests.map((entry) => `${entry.method} ${new URL(entry.url).host}${new URL(entry.url).pathname}${new URL(entry.url).search}`)]);
  // The writes are exactly the planned deletions, in the order of the state: objects, accounts, rulesets. Every delete of an object carries its generation.
  assert.deepEqual(f.world.deletes, [...STATE.objects.map((object) => object.name), ...STATE.accounts, ...STATE.rulesets]);
  assert.deepEqual(f.wire.filter((entry) => entry.method === "DELETE" && entry.url.includes("/storage/")).map((entry) => new URL(entry.url).searchParams.get("ifGenerationMatch")), STATE.objects.map((object) => object.generation));
  // Nothing is created or updated: the only body-carrying requests are the token refresh, the account lookups and the account deletions.
  assert.deepEqual(f.wire.filter((entry) => entry.body !== null).map((entry) => new URL(entry.url).pathname), ["/token", "/v1/projects/fireemu-oracle-query/accounts:lookup", ...STATE.accounts.map(() => "/v1/projects/fireemu-oracle-query/accounts:delete"), "/v1/projects/fireemu-oracle-query/accounts:lookup"]);
  // The kept rulesets are never named by a deletion.
  assert.equal(f.wire.some((entry) => entry.method === "DELETE" && /22b746af|d0abf7c6/.test(entry.url)), false);
  for (const entry of f.wire.slice(1)) {
    assert.equal(entry.headers.authorization, `Bearer ${OWNER_TOKEN}`);
    if (new URL(entry.url).pathname === "/oauth2/v2/userinfo") assert.equal(Object.hasOwn(entry.headers, "x-goog-user-project"), false);
    else assert.equal(entry.headers["x-goog-user-project"], "fireemu-oracle-query", entry.url);
  }
  const facts = await factsOf(f);
  assert.deepEqual(facts.map((fact) => fact.operationId), allIdsOf(state).slice(2));
  assert.ok(facts.every((fact) => fact.facts.expected === true && fact.facts.bodySha256.length === 64));
  const del = facts.find((fact) => fact.operationId === "cleanup/object/0/delete").facts;
  assert.deepEqual(del, { status: 204, bodyBytes: 0, bodySha256: sha(Buffer.alloc(0)), expected: true });
  const journals = (await Promise.all((await readdir(runDir(f))).filter((name) => name.endsWith(".jsonl")).map((name) => readFile(join(runDir(f), name), "utf8")))).join("\n");
  assert.equal(journals.includes(OWNER_TOKEN), false);
  assert.equal(journals.includes(OWNER_EMAIL), false);
});

test("a second run against the cleaned state deletes nothing: the reads no longer match", async (t) => {
  const world = createRestoreWorld();
  const first = await checkout(t, { world });
  await first.entry(first.options);
  const second = await checkout(t, { world });
  await assert.rejects(second.entry(second.options));
  assert.equal(world.deletes.length, STATE.objects.length + STATE.accounts.length + STATE.rulesets.length);
  assert.equal(await terminalOf(second), "preflight-failed");
});

test("a state that differs from the journal stops the run before the first deletion and keeps the lock", async (t) => {
  const world = (change) => { const value = createRestoreWorld(); change(value); return value; };
  const spoiled = {
    "an owned object is already gone": world((w) => w.objects.delete(STATE.objects[3].name)),
    "an object has another generation": world((w) => w.objects.set(STATE.objects[2].name, "1")),
    "an account is already gone": world((w) => w.accounts.delete(STATE.accounts[1])),
    "a ruleset is already gone": world((w) => w.rulesets.delete(STATE.rulesets[0])),
    "there is a ruleset of the run that the journal does not name": world((w) => w.rulesets.add("projects/fireemu-oracle-query/rulesets/aaaaaaaa-0000-4000-8000-000000000000")),
    "a release exists for the bucket": (() => { const w = createRestoreWorld(); w.hook.any = (spec) => (spec.method === "GET" && spec.url.endsWith(`/releases/firebase.storage/${BUCKET}`) ? w.json({ name: "x", rulesetName: "y" }) : undefined); return w; })(),
    "a release exists without a bucket": (() => { const w = createRestoreWorld(); w.hook.any = (spec) => (spec.method === "GET" && spec.url.endsWith("/releases/firebase.storage") ? w.json({ name: "x", rulesetName: "y" }) : undefined); return w; })(),
    "the rulesets list is paged": (() => { const w = createRestoreWorld(); w.hook.any = (spec) => (spec.url.endsWith("/rulesets?pageSize=100") ? w.json({ rulesets: [], nextPageToken: "t" }) : undefined); return w; })(),
  };
  for (const [name, world] of Object.entries(spoiled)) {
    const f = await checkout(t, { world });
    await assert.rejects(f.entry(f.options), undefined, name);
    assert.deepEqual(world.deletes, [], name);
    assert.equal(f.wire.some((entry) => entry.method === "DELETE"), false, name);
    assert.equal(await terminalOf(f), "preflight-failed", name);
    assert.deepEqual(await f.lockFiles(), lockedOnce, name);
  }
});

test("an owner who is not the expected one, or is unverified, stops the run before any read of the state", async (t) => {
  for (const identity of [{ id: "1", email: "other@example.test", verified_email: true }, { id: OWNER_SUBJECT, email: OWNER_EMAIL, verified_email: false }, { id: OWNER_SUBJECT }]) {
    const f = await checkout(t);
    f.world.hook.any = (spec) => (new URL(spec.url).pathname === "/oauth2/v2/userinfo" ? f.world.json(identity) : undefined);
    await assert.rejects(f.entry(f.options));
    assert.deepEqual(urls(f), ["POST oauth2.googleapis.com/token", "GET www.googleapis.com/oauth2/v2/userinfo"]);
  }
  const f = await checkout(t);
  f.world.hook.any = (spec) => (new URL(spec.url).pathname === "/oauth2/v2/userinfo" ? { status: 200, rawHeaders: ["Content-Type", "application/json"], bytes: Buffer.concat([Buffer.from('{"id":"1","email":"owner@example.test","verified_email":true,"note":"'), Buffer.from([0xff]), Buffer.from('"}')]) } : undefined);
  await assert.rejects(f.entry(f.options));
  assert.deepEqual(urls(f), ["POST oauth2.googleapis.com/token", "GET www.googleapis.com/oauth2/v2/userinfo"]);
});

test("a lost connection at any deletion stops the run there, sends nothing after it, and keeps the lock with a needs-recovery end", async (t) => {
  const writes = requests.filter((entry) => entry.method !== "GET" && !entry.id.startsWith("preflight/") && !entry.id.startsWith("verify/"));
  assert.equal(writes.length, 14);
  for (const write of writes) {
    const f = await checkout(t);
    let lost = 0;
    f.world.hook.any = (spec) => { if (at(write.id)(spec)) { lost++; throw new Error("connection lost"); } return undefined; };
    await assert.rejects(f.entry(f.options), undefined, write.id);
    assert.equal(lost, 1, write.id);
    const sent = urls(f);
    assert.equal(sent.length, 2 + requests.findIndex((entry) => entry.id === write.id) + 1, write.id);
    assert.equal(await terminalOf(f), "needs-recovery", write.id);
    assert.deepEqual(await f.lockFiles(), lockedOnce, write.id);
  }
});

test("an unexpected answer to a deletion stops the run there as needs-recovery: 412, 404, 500 and a body where none is expected", async (t) => {
  const answers = {
    "precondition failed": (world) => world.json({ error: { code: 412, message: "Precondition Failed" } }, 412),
    "not found": (world) => world.json({ error: { code: 404, message: "x" } }, 404),
    "server error": (world) => world.json({ error: { code: 500, message: "boom" } }, 500),
    "a body on the 204": () => ({ status: 204, rawHeaders: [], bytes: Buffer.from("x") }),
    "a 200": () => ({ status: 200, rawHeaders: [], bytes: Buffer.alloc(0) }),
  };
  for (const [name, answer] of Object.entries(answers)) {
    const f = await checkout(t);
    f.world.hook.any = (spec) => (at("cleanup/object/2/delete")(spec) ? answer(f.world) : undefined);
    await assert.rejects(f.entry(f.options), /unexpected answer at cleanup\/object\/2\/delete/, name);
    assert.equal(f.world.calls[`DELETE storage.googleapis.com/storage/v1/b/${BUCKET}/o/${encodeURIComponent(STATE.objects[3].name)}?ifGenerationMatch=${STATE.objects[3].generation}`] ?? 0, 0, name);
    assert.equal(await terminalOf(f), "needs-recovery", name);
    assert.deepEqual(await f.lockFiles(), lockedOnce, name);
  }
});

test("a verification read that shows something left ends the run as needs-recovery, after every deletion was sent once", async (t) => {
  const remaining = {
    "an object came back": (f) => { const hit = second("verify/object/4/absent"); f.world.hook.any = (spec) => (hit(spec) ? f.world.json({ kind: "storage#object", bucket: BUCKET, name: STATE.objects[4].name, generation: "9", metageneration: "1" }) : undefined); return "verify/object/4/absent"; },
    "an account is still there": (f) => { const hit = second("verify/accounts/lookup"); f.world.hook.any = (spec) => (hit(spec) ? f.world.json({ kind: "identitytoolkit#GetAccountInfoResponse", users: [{ localId: STATE.accounts[0] }] }) : undefined); return "verify/accounts/lookup"; },
    "a ruleset is still listed": (f) => { const hit = second("verify/rulesets/list"); f.world.hook.any = (spec) => (hit(spec) ? f.world.json({ rulesets: [{ name: STATE.rulesets[0], createTime: "2026-09-30T00:23:49Z", metadata: { services: ["firebase.storage"] } }] }) : undefined); return "verify/rulesets/list"; },
    "a release has appeared": (f) => { const hit = second("verify/release/bucket"); f.world.hook.any = (spec) => (hit(spec) ? f.world.json({ name: "x", rulesetName: "y" }) : undefined); return "verify/release/bucket"; },
    "an object is listed under the prefix": (f) => { f.world.hook.any = (spec) => (at("verify/objects/list")(spec) ? f.world.json({ kind: "storage#objects", items: [{ name: "x" }] }) : undefined); return "verify/objects/list"; },
  };
  for (const [name, prepare] of Object.entries(remaining)) {
    const f = await checkout(t);
    const id = prepare(f);
    await assert.rejects(f.entry(f.options), new RegExp(`unexpected answer at ${id}`), name);
    assert.equal(f.world.deletes.length, 14, name);
    assert.equal(await terminalOf(f), "needs-recovery", name);
    assert.deepEqual(await f.lockFiles(), lockedOnce, name);
  }
});

test("a revocation written while the cleanup is going stops the very next request", async (t) => {
  const f = await checkout(t);
  let revoked = false;
  f.world.hook.any = (spec) => { if (!revoked && at("cleanup/object/1/delete")(spec)) { revoked = true; writeFileSync(f.ledgerPath, `${ledger}\n- 2026-09-30 | STORAGE-RULES stage2e-restore-v1 | decision=REVOKED | Claude | private.md`); } return undefined; };
  await assert.rejects(f.entry(f.options), /admission refused/);
  assert.equal(f.world.deletes.length, 2);
  assert.equal(await terminalOf(f), "needs-recovery");
  assert.deepEqual(await f.lockFiles(), lockedOnce);
});

test("the approval binds the cleanup to its name, its limits and its pins", async (t) => {
  for (const [name, mutate] of Object.entries({
    "another packet name": (value) => ({ ...value, packetName: "stage2d-probe-v1" }), "more requests": (value) => ({ ...value, maxRequests: 40 }), "fewer requests": (value) => ({ ...value, maxRequests: 38 }),
    "a larger reserve": (value) => ({ ...value, reserveUsd: 0.5 }), "another project": (value) => ({ ...value, projects: ["fireemu-oracle-idp"] }), "two projects": (value) => ({ ...value, projects: ["fireemu-oracle-query", "fireemu-oracle-idp"] }),
  })) {
    const f = await checkout(t, { mutatePacket: mutate });
    await assert.rejects(f.entry(f.options), undefined, name);
    assert.equal(f.wire.length, 0, name);
  }
  for (const [name, mutate] of Object.entries({
    "runner pin": (value) => ({ ...value, runnerSha256: "0".repeat(64) }), "fixture pin": (value) => ({ ...value, fixtureSchemaSha256: "0".repeat(64) }), "manifest pin": (value) => ({ ...value, manifestSha256: "0".repeat(64) }),
  })) {
    const f = await checkout(t, { mutatePacket: mutate });
    await assert.rejects(f.entry(f.options), /pin mismatch/, name);
    assert.equal(f.wire.length, 0, name);
    assert.deepEqual(await readdir(f.runs), ["sandbox-locks"], name);
  }
  const revoked = await checkout(t, { ledgerText: `${ledger}\n- 2026-09-30 | STORAGE-RULES stage2e-restore-v1 | decision=REVOKED | Claude | private.md` });
  await assert.rejects(revoked.entry(revoked.options));
  assert.equal(revoked.wire.length, 0);
  const missing = await checkout(t, { ledgerText: "" });
  await assert.rejects(missing.entry(missing.options));
  assert.equal(missing.wire.length, 0);
  const used = await checkout(t, { usage: ["an-earlier-run"] });
  await assert.rejects(used.entry(used.options), /recording budget exhausted/);
  assert.equal(used.world.deletes.length, 0);
});

test("a state that is not the approved size is refused before anything is created", async (t) => {
  const bigger = { ...STATE, objects: [...STATE.objects, { name: `${STATE.runPrefix}zz-extra.bin`, generation: "5" }] };
  const f = await checkout(t, { stateValue: bigger });
  await assert.rejects(f.entry(f.options), /pin mismatch: manifestSha256|the plan is not the approved size/);
  assert.equal(f.wire.length, 0);
  assert.deepEqual(await readdir(f.runs), ["sandbox-locks"]);
  const smaller = { ...STATE, accounts: STATE.accounts.slice(1) };
  const g = await checkout(t, { stateValue: smaller });
  await assert.rejects(g.entry(g.options), /the plan is not the approved size/);
  assert.equal(g.wire.length, 0);
});

test("pins are recomputed before anything is created, and a dirty tree, an untracked runner file or a git failure refuses the run", async (t) => {
  for (const [name, options, message] of [
    ["head is not the source commit", { gitHead: "b".repeat(40) }, /./], ["tracked change", { gitStatus: " M conformance/src/storage-rules/x.mjs\n" }, /./],
    ["untracked runner file of stage 3", { gitExtra: "?? conformance/src/storage-rules/extra.mjs\n" }, /untracked or ignored runner files/],
    ["untracked runner file of stage 2e", { gitExtraRestore: "?? conformance/src/storage-rules-restore/extra.mjs\n" }, /untracked or ignored runner files/],
    ["git fails", { gitThrows: true }, /source commit unreadable$/],
  ]) {
    const f = await checkout(t, options);
    await assert.rejects(f.entry(f.options), message, name);
    assert.equal(f.wire.length, 0, name);
    assert.deepEqual(await readdir(f.runs), ["sandbox-locks"], name);
    assert.deepEqual(await f.lockFiles(), [], name);
  }
});

test("the local inputs, the state file, the owner ledger and the runs directory must be private, closed and small, and the option records are closed", async (t) => {
  const local = (f, delta) => JSON.stringify({ ...restoreLocal(f.adcPath, f.statePath), ...delta });
  const spoiled = {
    "local inputs readable by others": async (f) => { await chmod(f.localPath, 0o644); return /local inputs file refused/; },
    "local inputs is a symlink": async (f) => { await rm(f.localPath); await symlink(f.adcPath, f.localPath); return /local inputs file refused/; },
    "local inputs hard-linked": async (f) => { linkSync(f.localPath, join(f.root, "local-link.json")); return /local inputs file refused/; },
    "local inputs with an extra field": async (f) => { await writeFile(f.localPath, local(f, { extra: 1 }), { mode: 0o600 }); return /local inputs file refused/; },
    "local inputs with a short digest": async (f) => { await writeFile(f.localPath, local(f, { ownerEmailSha256: "abc" }), { mode: 0o600 }); return /local inputs file refused/; },
    "local inputs with a relative ADC path": async (f) => { await writeFile(f.localPath, local(f, { adcPath: "adc.json" }), { mode: 0o600 }); return /local inputs file refused/; },
    "local inputs with a relative state path": async (f) => { await writeFile(f.localPath, local(f, { statePath: "state.json" }), { mode: 0o600 }); return /local inputs file refused/; },
    "local inputs too large": async (f) => { await writeFile(f.localPath, Buffer.concat([Buffer.from(local(f, {})), Buffer.alloc(64 * 1024, 0x20)]), { mode: 0o600 }); return /local inputs file refused/; },
    "the state file readable by others": async (f) => { await chmod(f.statePath, 0o644); return /local inputs file refused/; },
    "the state file is missing": async (f) => { await rm(f.statePath); return /local inputs file refused/; },
    "the state file names a kept ruleset": async (f) => { await writeFile(f.statePath, JSON.stringify({ ...STATE, rulesets: ["projects/fireemu-oracle-query/rulesets/22b746af-0000-4000-8000-000000000000"] }), { mode: 0o600 }); return /local inputs file refused|the plan is not the approved size/; },
    "the state file is not JSON": async (f) => { await writeFile(f.statePath, "not json", { mode: 0o600 }); return /local inputs file refused/; },
    "ledger writable by others": async (f) => { await chmod(f.ledgerPath, 0o666); return /owner ledger refused/; },
    "ledger is not UTF-8": async (f) => { await writeFile(f.ledgerPath, Buffer.concat([Buffer.from(`${ledger}\n`), Buffer.from([0xff])]), { mode: 0o644 }); return /owner ledger refused/; },
    "ledger too large": async (f) => { await writeFile(f.ledgerPath, Buffer.alloc(8 * 1024 * 1024 + 1, 0x20), { mode: 0o644 }); return /owner ledger refused/; },
    "the runs directory is open to others": async (f) => { await chmod(f.runs, 0o755); return /runs directory refused/; },
    "the lock directory is open to others": async (f) => { await chmod(join(f.runs, "sandbox-locks"), 0o755); return /lock directory refused/; },
    "the lock directory is missing": async (f) => { await rm(join(f.runs, "sandbox-locks"), { recursive: true }); return /lock directory missing/; },
    "the runs directory is a symlink": async (f) => { await rename(f.runs, `${f.runs}-real`); await symlink(`${f.runs}-real`, f.runs); return /runs directory refused/; },
    "the run directory exists": async (f) => { await mkdir(join(f.runs, `storage-rules-restore-${runId}`), { mode: 0o700 }); return /run directory exists/; },
    "the run directory cannot be created": async (f) => { await chmod(f.runs, 0o500); return /run directory refused/; },
  };
  for (const [name, spoil] of Object.entries(spoiled)) {
    const f = await checkout(t);
    const message = await spoil(f);
    await assert.rejects(f.entry(f.options), message, name);
    assert.equal(f.wire.length, 0, name);
    await chmod(f.runs, 0o700).catch(() => {});
  }
  const f = await checkout(t);
  const binding = { root: f.root, codeRoot, requestImpl: () => {}, clock, git: async () => "" };
  for (const bad of [null, undefined, [], "x", { ...binding, extra: 1 }, { ...binding, root: 5 }, { ...binding, codeRoot: 5 }, { ...binding, git: 5 }, { ...binding, requestImpl: 5 }, { ...binding, clock: { nowSeconds: () => 1 } }, { ...binding, clock: null }]) assert.throws(() => bindRestoreEntry(bad), /invalid entry binding/);
  assert.throws(() => bindRestoreEntry({ ...binding, root: join(f.root, "docs.local") }), /entry root is not a main checkout/);
  for (const options of [null, undefined, [], "x", { ...f.options, extra: 1 }, { ...f.options, localPath: 5 }, { ...f.options, runId: 5 }, { ...f.options, runId: "Bad Id" }, { ...f.options, sourceCommit: 5 }, { ...f.options, sourceCommit: "abc" }, { ...f.options, sourceCommit: "b".repeat(40) },
    ...["runnerSha256", "fixtureSchemaSha256", "manifestSha256"].flatMap((key) => [{ ...f.options, packet: { ...f.options.packet, [key]: "abc" } }, { ...f.options, packet: { ...f.options.packet, [key]: 5 } }])]) {
    await assert.rejects(f.entry(options), /invalid restore options/, JSON.stringify(options)?.slice(0, 80));
  }
  assert.equal(f.wire.length, 0);
});

test("the local inputs reader accepts exactly the closed private file and returns the validated state", async (t) => {
  const dir = await mkdtemp("/private/tmp/storage-rules-restore-local-");
  t.after(() => rm(dir, { recursive: true, force: true }));
  const statePath = join(dir, "state.json");
  await writeFile(statePath, JSON.stringify(STATE), { mode: 0o600 });
  const path = join(dir, "local.json");
  await writeFile(path, JSON.stringify(restoreLocal("/x/adc.json", statePath)), { mode: 0o600 });
  const local = await readLocalInputs(path);
  assert.deepEqual({ ...local, state: JSON.parse(JSON.stringify(local.state)) }, { adcPath: "/x/adc.json", ownerEmailSha256: ownerDigest, state: STATE });
  assert.equal(Object.isFrozen(local), true);
  await assert.rejects(readLocalInputs(join(dir, "missing.json")), /local inputs file refused/);
  await assert.rejects(readLocalInputs(5), /local inputs file refused/);
});
