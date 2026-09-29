import assert from "node:assert/strict";
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { withAssembledRun } from "./storage-rules/assemble-run.mjs";
import { buildCorpus } from "./storage-rules/corpus.mjs";
import { buildFullRequestManifest } from "./storage-rules/full-manifest.mjs";
import { ADC, BUCKET, KEY_IDS, NUMBERS, OWNER_TOKEN, API_KEYS, SUBJECT, endpoints, fakeIdentity, privatePacket } from "./storage-rules-runner-support.mjs";
import { createSimulator } from "./storage-rules-simulator.mjs";

// The assembled runner against a simulated wire: a private packet, an approval in a ledger, locks, a usage record, real journals.
const closure = JSON.parse(readFileSync(new URL("../../spec/compatibility/closure/STORAGE-RULES.json", import.meta.url)));
const runId = "runner-test";
const sourceCommit = "a".repeat(40);
const pins = ["packetSha256", "sourceCommit", "runnerSha256", "manifestSha256", "fixtureSchemaSha256"];
const packet = { taskId: "STORAGE-RULES", packetName: "stage3-v1", packetSha256: "1".repeat(64), sourceCommit, runnerSha256: "2".repeat(64), manifestSha256: "3".repeat(64), fixtureSchemaSha256: "4".repeat(64), projects: ["fireemu-oracle-idp", "fireemu-oracle-query"], maxRequests: 12344, reserveUsd: 2 };
const envelopeId = "STORAGE-RULES-stage3-v1-001";
const review = { verdict: "APPROVE", must: [], should: [], ...Object.fromEntries(pins.map((key) => [key, packet[key]])), envelopeId, withinEnvelope: true };
const ledger = [
  "- 2026-09-28 | 調整役への委任（本番の送信） | decision=APPROVE; local fixture | オーナー（ローカル試験） | private.md",
  "- 2026-09-28 | 調整役への委任（枠の承認） | decision=APPROVE; local fixture | オーナー（ローカル試験） | private.md",
  `- 2026-09-28 | STORAGE-RULES stage3-v1 envelope | envelopeId=${envelopeId}; project=${packet.projects.join(",")}; maxRequests=12344; reserveUsd=2; writes=owned fixtures; iamConfig=Storage release only; retries=none; 根拠=2026-09-28 調整役への委任（本番の送信） | Claude（委任。オーナーの裁量の委任 2026-09-28） | private.md`,
  `- 2026-09-28 | STORAGE-RULES stage3-v1 | decision=APPROVE; ${pins.map((key) => `${key}=${packet[key]}`).join("; ")}; envelopeId=${envelopeId} | Claude（委任。枠の内の承認し直し） | private.md`,
].join("\n");
const manifestFor = () => buildFullRequestManifest(buildCorpus({ bucket: BUCKET, prefix: `STORAGE-RULES/${runId}/`, uidA: `storage-rules-${runId}-user-a`, uidB: `storage-rules-${runId}-user-b` }), closure, { runId, sourceCommit, queryProjectNumber: NUMBERS.query, idpProjectNumber: NUMBERS.idp, queryApiKeyId: KEY_IDS.query, idpApiKeyId: KEY_IDS.idp });
const manifest = manifestFor();
const invalidContent = manifest.rows.filter((r) => r.family === "compile" && r.stage === "test").at(-1).request.body.json.source.files[0].content;

async function fixture(t, { packetMode = 0o600, ledgerText = ledger, usageRuns = [], bad = {}, hook } = {}) {
  const root = await mkdtemp("/private/tmp/storage-rules-runner-");
  t.after(() => rm(root, { recursive: true, force: true }));
  const adcPath = join(root, "adc.json");
  await writeFile(adcPath, JSON.stringify(ADC), { mode: 0o600 });
  const inputsPath = join(root, "inputs.json");
  await writeFile(inputsPath, JSON.stringify(privatePacket(adcPath)), { mode: 0o600 });
  await chmod(inputsPath, packetMode);
  const usagePath = join(root, "usage.jsonl");
  if (usageRuns.length > 0) await writeFile(usagePath, usageRuns.map((id) => `${JSON.stringify({ packetSha256: packet.packetSha256, runId: id })}\n`).join(""), { mode: 0o600 });
  const directory = join(root, "run");
  await mkdir(directory, { mode: 0o700 });
  const lockDir = join(root, "sandbox-locks");
  const clock = { now: Math.floor(Date.now() / 1000) };
  const identity = fakeIdentity(clock);
  const simulator = createSimulator({ manifest, options: { invalidContent } });
  const sent = { count: 0, urls: [] };
  const send = endpoints({ simulator, clock, identity, bad, hook });
  const transport = { validate() {}, send: async (spec) => { sent.count++; sent.urls.push(spec.url); return send(spec); } };
  const options = {
    inputsPath, closure, runId, sourceCommit, packet: structuredClone(packet), review: structuredClone(review), readLedger: async () => ledgerText,
    locks: { lockDir, legacyLockPath: join(root, "sandbox-ledger.jsonl.lock"), pid: process.pid, acquiredAt: "2026-09-29T00:00:00Z" }, usagePath, directory, transport,
    clock: { nowSeconds: () => clock.now, waitUntilSeconds: async (value) => { clock.now = Math.max(clock.now, value); }, sleep: async () => {} },
  };
  const lockFiles = async () => (await readdir(lockDir).catch(() => [])).sort();
  const usage = async () => (await readFile(usagePath, "utf8").catch(() => "")).split("\n").filter(Boolean).map((line) => JSON.parse(line).runId);
  return { root, options, sent, lockFiles, usage, directory, simulator, identity, clock };
}
async function walk(directory) {
  const out = [];
  for (const name of await readdir(directory)) {
    const path = join(directory, name);
    if ((await lstat(path)).isDirectory()) out.push(...await walk(path)); else out.push(path);
  }
  return out;
}

test("a preflight fact that differs from the private packet stops the run at that probe, before anything is admitted, and keeps the locks", async (t) => {
  const f = await fixture(t, { bad: { identity: { id: SUBJECT, email: "someone-else@example.test", verified_email: true } } });
  let result;
  let state;
  await assert.rejects(withAssembledRun(f.options, async (run) => {
    result = await run.run();
    state = run.gate.snapshot();
  }), /closure not confirmed; project locks retained|project locks retained/);
  assert.deepEqual([result.status, result.reason, result.detail.rowId], ["stopped", "preflight refused", "preflight/owner/identity"]);
  assert.equal(result.needsRecovery, false);
  assert.equal(state.mode, "closed");
  assert.ok(f.sent.count <= 4, String(f.sent.count));
  assert.deepEqual(await f.usage(), [runId]);
  assert.deepEqual(await f.lockFiles(), ["fireemu-oracle-idp.lock", "fireemu-oracle-query.lock"]);
  // The journals hold the stop, and nothing secret: not the owner's address, the API keys, or any credential.
  const files = await walk(f.directory);
  assert.ok(files.some((file) => file.endsWith("captures.jsonl")) && files.some((file) => file.endsWith("reservations.jsonl")));
  for (const file of files) {
    const text = (await readFile(file)).toString("latin1");
    for (const secret of ["someone-else@example.test", "owner@example.test", SUBJECT, API_KEYS.query, API_KEYS.idp, OWNER_TOKEN, ADC.refresh_token, ADC.client_secret]) assert.equal(text.includes(secret), false, `${secret.slice(0, 12)} in ${file.slice(f.directory.length)}`);
    assert.equal((await lstat(file)).mode & 0o077, 0, file);
  }
});

test("a private packet file that is group readable is refused before any lock, marker, journal or request", async (t) => {
  const f = await fixture(t, { packetMode: 0o640 });
  await assert.rejects(withAssembledRun(f.options, async () => assert.fail("must not run")), /private inputs file refused/);
  assert.deepEqual(await f.lockFiles(), []);
  assert.deepEqual(await f.usage(), []);
  assert.deepEqual(await readdir(f.directory), []);
  assert.equal(f.sent.count, 0);
});

test("a revoked approval stops the run before its first request, marks nothing and releases the locks", async (t) => {
  const f = await fixture(t, { ledgerText: `${ledger}\n- 2026-09-29 | STORAGE-RULES stage3-v1 | decision=REVOKED; packetSha256=${packet.packetSha256} | オーナー（ローカル試験） | private.md` });
  let result;
  await withAssembledRun(f.options, async (run) => { result = await run.run(); });
  assert.deepEqual([result.status, result.reason], ["stopped", "admission refused"]);
  assert.equal(f.sent.count, 0);
  assert.deepEqual(await f.usage(), []);
  assert.deepEqual(await f.lockFiles(), []);
});

test("a third recording under one approval is refused at its start with nothing sent or marked", async (t) => {
  const f = await fixture(t, { usageRuns: ["first-run", "second-run"] });
  let result;
  await withAssembledRun(f.options, async (run) => { result = await run.run(); });
  assert.deepEqual([result.status, result.reason], ["stopped", "admission refused"]);
  assert.equal(f.sent.count, 0);
  assert.deepEqual(await f.usage(), ["first-run", "second-run"]);
  assert.deepEqual(await f.lockFiles(), []);
});

test("the options are a closed record checked before any file is touched, and a caller that fails releases what it did not use", async (t) => {
  const f = await fixture(t);
  for (const bad of [null, {}, { ...f.options, extra: 1 }, { ...f.options, runId: "Bad Id" }, { ...f.options, sourceCommit: "abc" }, { ...f.options, packet: { ...f.options.packet, sourceCommit: "c".repeat(40) } }, { ...f.options, transport: { send() {} } }, { ...f.options, clock: { nowSeconds() {} } }, { ...f.options, readLedger: undefined }]) {
    await assert.rejects(withAssembledRun(bad, async () => assert.fail("must not run")), /invalid assembled run options/);
  }
  assert.deepEqual(await f.lockFiles(), []);
  assert.deepEqual(await f.usage(), []);
  await assert.rejects(withAssembledRun(f.options, async () => { throw new Error("caller failed"); }), /caller failed/);
  // The run was marked started (the admission begins only at the gate's start, which the caller never reached), so nothing is marked and the locks are gone.
  assert.deepEqual(await f.usage(), []);
  assert.deepEqual(await f.lockFiles(), []);
  assert.equal(f.sent.count, 0);
});

// Every row syncs several files, so this run takes over a minute; run it with STORAGE_RULES_SLOW_TESTS=1.
test("a whole recording through the assembled runner finishes, cleans up, marks the run, releases the locks and leaves no secret", { skip: !process.env.STORAGE_RULES_SLOW_TESTS && "set STORAGE_RULES_SLOW_TESTS=1" }, async (t) => {
  const f = await fixture(t);
  let result;
  await withAssembledRun(f.options, async (run) => {
    result = await run.run();
    assert.equal(result.status, "finished", JSON.stringify(result));
    run.confirmCleanClose(result);
  });
  const state = f.simulator.state();
  assert.deepEqual({ objects: state.objects, rulesets: state.rulesets, release: state.release, documents: state.documents }, { objects: 0, rulesets: 0, release: null, documents: 0 });
  assert.equal(f.identity.users.size, 0);
  assert.deepEqual(await f.usage(), [runId]);
  assert.deepEqual(await f.lockFiles(), []);
  const secrets = [OWNER_TOKEN, ADC.refresh_token, ADC.client_secret, API_KEYS.query, API_KEYS.idp, "owner@example.test", SUBJECT, ...f.simulator.secrets(), ...f.identity.secrets(), "@example.com"];
  for (const file of await walk(f.directory)) {
    const text = (await readFile(file)).toString("latin1");
    for (const secret of secrets) for (const form of [secret, encodeURIComponent(secret), Buffer.from(secret).toString("base64"), Buffer.from(secret).toString("hex")]) assert.equal(text.includes(form), false, `${secret.slice(0, 14)} in ${file.slice(f.directory.length)}`);
  }
});
