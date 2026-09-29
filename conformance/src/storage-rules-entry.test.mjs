import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile, chmod } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { bindStorageRulesEntry, mainRepositoryRoot, pinnedPaths, withStorageRulesRecording } from "./storage-rules/entry.mjs";
import { ADC, BUCKET, privatePacket } from "./storage-rules-runner-support.mjs";

// The real entry point against a scratch main checkout: which files it reads, takes and writes, and what a caller cannot name.
const closure = JSON.parse(readFileSync(new URL("../../spec/compatibility/closure/STORAGE-RULES.json", import.meta.url)));
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
const clock = { nowSeconds: () => 1_800_000_000, waitUntilSeconds: async () => {}, sleep: async () => {} };
const runId = "entry-test";

async function checkout(t, { ledgerText = ledger, ledgerMode = 0o644, usage = [] } = {}) {
  const root = await mkdtemp("/private/tmp/storage-rules-entry-");
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, ".git"));
  await mkdir(join(root, "docs.local", "instructions"), { recursive: true });
  const runs = join(root, "docs.local", "runs");
  await mkdir(runs, { mode: 0o700 });
  await chmod(runs, 0o700);
  await mkdir(join(runs, "sandbox-locks"), { mode: 0o700 });
  await chmod(join(runs, "sandbox-locks"), 0o700);
  await writeFile(join(root, "docs.local", "instructions", "owner-decisions.md"), ledgerText, { mode: ledgerMode });
  await chmod(join(root, "docs.local", "instructions", "owner-decisions.md"), ledgerMode);
  if (usage.length > 0) await writeFile(join(runs, "storage-rules-recording-usage.jsonl"), usage.map((id) => `${JSON.stringify({ packetSha256: packet.packetSha256, runId: id })}\n`).join(""), { mode: 0o600 });
  const adcPath = join(root, "adc.json");
  await writeFile(adcPath, JSON.stringify(ADC), { mode: 0o600 });
  const inputsPath = join(root, "inputs.json");
  await writeFile(inputsPath, JSON.stringify(privatePacket(adcPath)), { mode: 0o600 });
  const wire = [];
  const requestImpl = (...args) => { wire.push(args); throw new Error("the wire must not be reached"); };
  const entry = bindStorageRulesEntry({ root, requestImpl, clock });
  const options = { inputsPath, closure, runId, sourceCommit, packet: structuredClone(packet), review: structuredClone(review) };
  return { root, runs, entry, options, wire };
}

test("the paths are constants under the main checkout root", () => {
  const paths = pinnedPaths("/repo");
  assert.deepEqual({ ...paths, runDirectory: paths.runDirectory("r-1") }, {
    ownerLedger: "/repo/docs.local/instructions/owner-decisions.md", lockDir: "/repo/docs.local/runs/sandbox-locks", legacyLockPath: "/repo/docs.local/runs/sandbox-ledger.jsonl.lock",
    usagePath: "/repo/docs.local/runs/storage-rules-recording-usage.jsonl", runsDir: "/repo/docs.local/runs", runDirectory: "/repo/docs.local/runs/storage-rules-r-1",
  });
  assert.equal(Object.isFrozen(paths), true);
});

test("the main checkout is found above a linked worktree, whose .git is a file", async (t) => {
  const root = await mkdtemp("/private/tmp/storage-rules-entry-root-");
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, ".git"));
  const worktree = join(root, ".worktree", "feature");
  await mkdir(join(worktree, "conformance", "src", "storage-rules"), { recursive: true });
  await writeFile(join(worktree, ".git"), "gitdir: elsewhere\n");
  assert.equal(mainRepositoryRoot(join(worktree, "conformance", "src", "storage-rules")), root);
  assert.equal(mainRepositoryRoot(root), root);
  await assert.rejects(async () => mainRepositoryRoot("/private/tmp/storage-rules-no-such-root-anywhere"), /main repository root not found/);
});

test("the real binding of this file resolves to a main checkout that has the runs directory the recordings use", async () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const root = mainRepositoryRoot(here);
  assert.equal((await stat(join(root, ".git"))).isDirectory(), true);
  assert.equal(typeof withStorageRulesRecording, "function");
});

test("the binding is a closed record for a main checkout, the real request function and a clock", async (t) => {
  const f = await checkout(t);
  const good = { root: f.root, requestImpl() {}, clock };
  assert.doesNotThrow(() => bindStorageRulesEntry(good));
  const linked = join(f.root, ".worktree", "wt");
  await mkdir(linked, { recursive: true });
  await writeFile(join(linked, ".git"), "gitdir: x\n");
  for (const bad of [null, {}, { ...good, extra: 1 }, { root: f.root, requestImpl: good.requestImpl }, { ...good, root: "relative" }, { ...good, root: `${f.root}/` }, { ...good, root: linked }, { ...good, root: 5 }, { ...good, requestImpl: 5 }, { ...good, clock: { nowSeconds() {} } }, { ...good, clock: [] }]) {
    assert.throws(() => bindStorageRulesEntry(bad), /invalid entry binding|entry root is not a main checkout/);
  }
});

test("a caller cannot name the ledger, the locks, the usage ledger, the run directory, the transport or the clock", async (t) => {
  const f = await checkout(t);
  const overrides = { readLedger: async () => "", ledger: "/x", ledgerPath: "/x", locks: {}, lockDir: "/x", legacyLockPath: "/x", usagePath: "/x", directory: "/x", transport: { send() {}, validate() {} }, clock, root: "/x", requestImpl() {} };
  for (const [name, value] of Object.entries(overrides)) await assert.rejects(f.entry({ ...f.options, [name]: value }, async () => assert.fail("must not run")), /invalid storage rules recording options/, name);
  // Nor can a required option be left out or renamed, or the callback be something else.
  for (const key of Object.keys(f.options)) { const { [key]: _, ...rest } = f.options; await assert.rejects(f.entry(rest, async () => assert.fail("must not run")), /invalid storage rules recording options/, key); }
  await assert.rejects(f.entry(f.options, "not a function"), /invalid storage rules recording options/);
  await assert.rejects(f.entry({ ...f.options, runId: "Bad Id" }, async () => assert.fail("must not run")), /invalid storage rules recording options/);
  assert.deepEqual(await readdir(f.runs), ["sandbox-locks"]);
  assert.equal(f.wire.length, 0);
});

test("a run reads the pinned ledger, takes the pinned locks, marks the pinned usage ledger and writes its journals in a private run directory", async (t) => {
  const f = await checkout(t, { usage: ["first-run", "second-run"] });
  let seen;
  let result;
  await f.entry(f.options, async (run) => {
    seen = { locks: (await readdir(join(f.runs, "sandbox-locks"))).sort(), directoryMode: (await stat(join(f.runs, `storage-rules-${runId}`))).mode & 0o777 };
    result = await run.run();
  });
  // The third recording under this approval is refused by the pinned usage ledger, so the approval read from the pinned owner ledger was valid.
  assert.deepEqual([result.status, result.reason], ["stopped", "admission refused"]);
  assert.deepEqual(seen, { locks: ["fireemu-oracle-idp.lock", "fireemu-oracle-query.lock"], directoryMode: 0o700 });
  assert.deepEqual(await readdir(join(f.runs, "sandbox-locks")), []);
  assert.equal(await readFile(join(f.runs, "storage-rules-recording-usage.jsonl"), "utf8"), ["first-run", "second-run"].map((id) => `${JSON.stringify({ packetSha256: packet.packetSha256, runId: id })}\n`).join(""));
  assert.ok((await readdir(join(f.runs, `storage-rules-${runId}`))).length >= 2);
  assert.equal(f.wire.length, 0);
});

test("a first recording is marked in the pinned usage ledger, and the wire is only the injected request function", async (t) => {
  const f = await checkout(t);
  let result;
  await assert.rejects(f.entry(f.options, async (run) => { result = await run.run(); }));
  // The first request (the owner's OAuth token refresh) reached the injected request function, which the test made throw: the attempt stops and keeps the locks.
  assert.equal(f.wire.length >= 1, true);
  assert.equal(result.status, "stopped");
  assert.equal(await readFile(join(f.runs, "storage-rules-recording-usage.jsonl"), "utf8"), `${JSON.stringify({ packetSha256: packet.packetSha256, runId })}\n`);
  assert.deepEqual((await readdir(join(f.runs, "sandbox-locks"))).sort(), ["fireemu-oracle-idp.lock", "fireemu-oracle-query.lock"]);
  const [url, requestOptions] = f.wire[0];
  assert.equal(new URL(url).origin, "https://oauth2.googleapis.com");
  assert.deepEqual([requestOptions.method, requestOptions.agent, requestOptions.rejectUnauthorized], ["POST", false, true]);
});

test("a run directory that already exists, a missing or shared runs or lock directory, and a refused ledger stop the run before any lock or marker", async (t) => {
  const f = await checkout(t);
  await mkdir(join(f.runs, `storage-rules-${runId}`), { mode: 0o700 });
  await assert.rejects(f.entry(f.options, async () => assert.fail("must not run")), /run directory exists/);
  const g = await checkout(t);
  await chmod(join(g.runs, "sandbox-locks"), 0o750);
  await assert.rejects(g.entry(g.options, async () => assert.fail("must not run")), /lock directory refused/);
  const h = await checkout(t);
  await rm(join(h.runs, "sandbox-locks"), { recursive: true });
  await assert.rejects(h.entry(h.options, async () => assert.fail("must not run")), /lock directory missing/);
  const i = await checkout(t);
  await chmod(i.runs, 0o755);
  await assert.rejects(i.entry(i.options, async () => assert.fail("must not run")), /runs directory refused/);
  for (const state of [g, h, i]) assert.equal(state.wire.length, 0);
  assert.deepEqual(await readdir(join(f.runs, "sandbox-locks")), []);
});

test("the owner ledger must be a plain file of this user that nobody else can write", async (t) => {
  for (const setup of [
    async (f) => chmod(join(f.root, "docs.local", "instructions", "owner-decisions.md"), 0o664),
    async (f) => chmod(join(f.root, "docs.local", "instructions", "owner-decisions.md"), 0o646),
    async (f) => { const path = join(f.root, "docs.local", "instructions", "owner-decisions.md"); await rm(path); await symlink(join(f.root, "elsewhere.md"), path); await writeFile(join(f.root, "elsewhere.md"), ledger); },
    async (f) => { const path = join(f.root, "docs.local", "instructions", "owner-decisions.md"); await rm(path); await mkdir(path); },
    async (f) => rm(join(f.root, "docs.local", "instructions", "owner-decisions.md")),
    async (f) => writeFile(join(f.root, "docs.local", "instructions", "owner-decisions.md"), Buffer.from([0xff, 0xfe, 0x41])),
  ]) {
    const f = await checkout(t);
    await setup(f);
    let result;
    await f.entry(f.options, async (run) => { result = await run.run(); });
    assert.deepEqual([result.status, result.reason], ["stopped", "admission refused"]);
    assert.equal(f.wire.length, 0);
    assert.equal((await readFile(join(f.runs, "storage-rules-recording-usage.jsonl"), "utf8").catch(() => "")), "");
  }
});
