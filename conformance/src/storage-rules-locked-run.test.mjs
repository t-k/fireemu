import assert from "node:assert/strict";
import { lstat, mkdir, mkdtemp, readdir, readFile, rm, unlink, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { createAdmission } from "./storage-rules/admission.mjs";
import { buildCorpus } from "./storage-rules/corpus.mjs";
import { createController } from "./storage-rules/controller.mjs";
import { createDispatchGate } from "./storage-rules/dispatch-gate.mjs";
import { buildFullRequestManifest } from "./storage-rules/full-manifest.mjs";
import { createResourceLedger } from "./storage-rules/resource-ledger.mjs";
import { createRunLedger } from "./storage-rules/run-ledger.mjs";
import { buildRecoverySchedule, buildSchedule } from "./storage-rules/schedule.mjs";
import { buildRefTables, createRuntimeRefStore } from "./storage-rules/runtime-refs.mjs";
import { createTargetBuilder } from "./storage-rules/target.mjs";
import { createSimulator } from "./storage-rules-simulator.mjs";

// The project locks and the live admission as one: the lock check is part of every request's admission, the run's only
// transport goes through the lease, and the locks are released only after a clean terminal state was confirmed.
const closure = JSON.parse(readFileSync(new URL("../../spec/compatibility/closure/STORAGE-RULES.json", import.meta.url)));
const options = { runId: "local-run", sourceCommit: "a".repeat(40), queryProjectNumber: "1".repeat(12), idpProjectNumber: "2".repeat(12), queryApiKeyId: "00000000-0000-4000-8000-000000000001", idpApiKeyId: "00000000-0000-4000-8000-000000000002" };
const binding = { bucket: "synthetic-rules-bucket", prefix: "STORAGE-RULES/local-run/", uidA: "storage-rules-local-run-user-a", uidB: "storage-rules-local-run-user-b" };
const manifest = buildFullRequestManifest(buildCorpus(binding), closure, options);
const salt = "6".repeat(64);
const invalidContent = manifest.rows.filter((r) => r.family === "compile" && r.stage === "test").at(-1).request.body.json.source.files[0].content;
const delegatedRow = (row) => ["auth", "credential-cache"].includes(row.family);
const preflightIds = manifest.preflightIds.filter((id) => !id.startsWith("preflight/auth/"));

const pins = ["packetSha256", "sourceCommit", "runnerSha256", "manifestSha256", "fixtureSchemaSha256"];
const packet = { taskId: "STORAGE-RULES", packetName: "stage3-v1", packetSha256: "a".repeat(64), sourceCommit: "b".repeat(40), runnerSha256: "c".repeat(64), manifestSha256: "d".repeat(64), fixtureSchemaSha256: "e".repeat(64), projects: ["fireemu-oracle-idp", "fireemu-oracle-query"], maxRequests: 12344, reserveUsd: 2 };
const envelopeId = "STORAGE-RULES-stage3-v1-001";
const review = { verdict: "APPROVE", must: [], should: [], ...Object.fromEntries(pins.map((key) => [key, packet[key]])), envelopeId, withinEnvelope: true };
const delegatedActor = "Claude（委任。オーナーの裁量の委任 2026-09-28）";
const ledger = [
  "- 2026-09-28 | 調整役への委任（本番の送信） | decision=APPROVE; local fixture | オーナー（ローカル試験） | private.md",
  "- 2026-09-28 | 調整役への委任（枠の承認） | decision=APPROVE; local fixture | オーナー（ローカル試験） | private.md",
  `- 2026-09-28 | STORAGE-RULES stage3-v1 envelope | envelopeId=${envelopeId}; project=${packet.projects.join(",")}; maxRequests=12344; reserveUsd=2; writes=owned fixtures; iamConfig=Storage release only; retries=none; 根拠=2026-09-28 調整役への委任（本番の送信） | ${delegatedActor} | private.md`,
  `- 2026-09-28 | STORAGE-RULES stage3-v1 | decision=APPROVE; ${pins.map((key) => `${key}=${packet[key]}`).join("; ")}; envelopeId=${envelopeId} | Claude（委任。枠の内の承認し直し） | private.md`,
].join("\n");
const load = async () => {
  const module = await import("./storage-rules/locked-run.mjs").catch((error) => { if (error.code === "ERR_MODULE_NOT_FOUND") return {}; throw error; });
  for (const name of ["withLockedAdmission", "leaseTransport", "confirmCleanClose"]) assert.equal(typeof module[name], "function", name);
  return module;
};

async function scratch(t) {
  const root = await mkdtemp("/private/tmp/storage-rules-locked-");
  t.after(() => rm(root, { recursive: true, force: true }));
  return { root, lockDir: join(root, "sandbox-locks"), legacyLockPath: join(root, "sandbox-ledger.jsonl.lock") };
}
const lockOptions = (dirs, delta = {}) => ({ projects: [...packet.projects], lockDir: dirs.lockDir, legacyLockPath: dirs.legacyLockPath, taskId: packet.taskId, packetId: packet.packetName, sourceCommit: packet.sourceCommit, pid: process.pid, acquiredAt: "2026-09-29T00:00:00Z", ...delta });
const params = (dirs, delta = {}, lockDelta = {}) => ({ locks: lockOptions(dirs, lockDelta), readLedger: async () => ledger, packet: structuredClone(packet), review: structuredClone(review), ...delta });
const lockFiles = async (dirs) => (await readdir(dirs.lockDir).catch(() => [])).sort();

// A whole controller over the simulator, its only transport going through the lease.
async function assemble({ lease, admission, simulatorOptions = {} }, { transportHook = () => {} } = {}) {
  const { leaseTransport } = await load();
  const simulator = createSimulator({ manifest, options: { invalidContent, ...simulatorOptions } });
  const trace = [];
  const capture = { writeIntent: async () => {}, writeResponse: async () => {}, writeFacts: async () => {}, writeProof: async () => {}, writeNote: async () => {}, snapshot: () => ({ uncertain: false }) };
  const targets = createTargetBuilder({ manifest, digestSalt: salt });
  const tables = buildRefTables(manifest);
  const refs = createRuntimeRefStore({ tables, runId: options.runId, digestSalt: salt, writeProof: (proof) => capture.writeProof(proof) });
  const objects = createResourceLedger({ manifest });
  const run = createRunLedger({ manifest, objects });
  const calls = { count: 0 };
  const transport = leaseTransport(lease, { send: async (spec) => { calls.count++; await transportHook(spec, calls.count); return simulator.send(spec); } });
  const gate = createDispatchGate({
    reservations: { onStarted: async () => {}, onReserve: async (r) => { trace.push(r.operationId); }, onTerminal: async (r) => { trace.push(`terminal:${r.outcome}`); } },
    capture, transport, targets, credentials: { headersFor: () => ({}) }, preflightIds, admission,
  });
  const noop = async () => {};
  const controller = createController({
    manifest, schedule: buildSchedule(manifest), recoverySchedule: buildRecoverySchedule(manifest), gate, targets, refs, tables, objects, run, capture,
    delegates: { "preflight-cache": noop, "credential-cache": noop, "prepare-query": noop, "foreign-signup": noop, "foreign-cleanup": noop, "cleanup-query": noop, "recover-accounts": noop },
    wait: async () => {}, credentials: { fresh: () => true }, judgePreflight: (row, outcome) => outcome.verdict !== "unexpected",
  });
  return { controller, gate, simulator, trace, calls };
}

test("a whole recording under real locks checks the locks with every request and releases them after a confirmed clean close", async (t) => {
  const { withLockedAdmission, confirmCleanClose } = await load();
  const dirs = await scratch(t);
  let held = null;
  let outcome;
  const result = await withLockedAdmission(params(dirs), async ({ admission, lease }) => {
    held = await lockFiles(dirs);
    const h = await assemble({ lease, admission });
    outcome = await h.controller.run();
    assert.equal(outcome.status, "finished", JSON.stringify(outcome));
    // Every request was preceded by a check: the ledger and the locks.
    assert.equal(admission.snapshot().checks, h.gate.snapshot().requests + 1);
    assert.equal(admission.snapshot().refused, false);
    confirmCleanClose(lease, outcome);
    return "done";
  });
  assert.equal(result, "done");
  assert.deepEqual(held, ["fireemu-oracle-idp.lock", "fireemu-oracle-query.lock"]);
  assert.deepEqual(await lockFiles(dirs), []);
});

test("a lock file replaced in the middle of a run stops the very next request and the locks stay", async (t) => {
  const { withLockedAdmission } = await load();
  const dirs = await scratch(t);
  let outcome;
  let sentAfter = null;
  await assert.rejects(withLockedAdmission(params(dirs), async ({ admission, lease }) => {
    let swapped = false;
    const h = await assemble({ lease, admission }, { transportHook: async (spec, count) => {
      if (count === 30 && !swapped) {
        swapped = true;
        const path = join(dirs.lockDir, "fireemu-oracle-query.lock");
        const body = await readFile(path, "utf8");
        await unlink(path);
        await writeFile(path, body, { mode: 0o600 });
      }
    } });
    outcome = await h.controller.run();
    sentAfter = h.calls.count;
  }), /project locks retained|closure not confirmed/);
  assert.equal(outcome.status, "stopped");
  assert.equal(outcome.reason, "admission refused");
  assert.equal(sentAfter, 30);
  assert.deepEqual(await lockFiles(dirs), ["fireemu-oracle-idp.lock", "fireemu-oracle-query.lock"]);
});

test("a lock file removed before the first request stops the run before anything is sent", async (t) => {
  const { withLockedAdmission } = await load();
  const dirs = await scratch(t);
  let outcome;
  let calls = -1;
  await withLockedAdmission(params(dirs), async ({ admission, lease }) => {
    await unlink(join(dirs.lockDir, "fireemu-oracle-idp.lock"));
    const h = await assemble({ lease, admission });
    outcome = await h.controller.run();
    calls = h.calls.count;
  }).catch(() => {});
  assert.equal(outcome.reason, "admission refused");
  assert.equal(calls, 0);
});

test("the lock set must be exactly this packet's: projects, task, packet name and source commit, checked before any lock is taken", async (t) => {
  const { withLockedAdmission } = await load();
  const dirs = await scratch(t);
  const cases = {
    "one project": { projects: ["fireemu-oracle-query"] }, "a third project": { projects: ["fireemu-oracle-events", "fireemu-oracle-idp", "fireemu-oracle-query"] }, "another project": { projects: ["fireemu-oracle-idp", "fireemu-oracle-sbx"] },
    "another task": { taskId: "STORAGE-OBJECT" }, "another packet": { packetId: "stage3-v2" }, "another commit": { sourceCommit: "c".repeat(40) },
  };
  for (const [name, delta] of Object.entries(cases)) {
    let entered = false;
    await assert.rejects(withLockedAdmission(params(dirs, {}, delta), async () => { entered = true; }), /lock set does not match the packet/, name);
    assert.equal(entered, false, name);
    assert.deepEqual(await lockFiles(dirs), [], name);
  }
  // The order the projects are listed in does not matter; the lock module sorts them.
  await withLockedAdmission(params(dirs, {}, { projects: [...packet.projects].reverse() }), async () => {});
  assert.deepEqual(await lockFiles(dirs), []);
});

test("an approval that is not valid takes no lock and enters nothing", async (t) => {
  const { withLockedAdmission } = await load();
  const dirs = await scratch(t);
  let entered = false;
  // The admission is created with the run, so a run that never checks it never sends; a missing ledger reader is refused at once.
  await assert.rejects(withLockedAdmission(params(dirs, { readLedger: undefined }), async () => { entered = true; }), /invalid admission options/);
  assert.equal(entered, false);
  assert.deepEqual(await lockFiles(dirs), []);
  await assert.rejects(withLockedAdmission(null, async () => {}), /invalid locked run options/);
  await assert.rejects(withLockedAdmission(params(dirs), undefined), /invalid locked run options/);
  await assert.rejects(withLockedAdmission({ ...params(dirs), extra: 1 }, async () => {}), /invalid locked run options/);
});

test("a stop is recovered under the same locks and they are released only after the recovery closed clean", async (t) => {
  const { withLockedAdmission, confirmCleanClose } = await load();
  const dirs = await scratch(t);
  let stopped;
  let recovered;
  await withLockedAdmission(params(dirs), async ({ admission, lease }) => {
    const h = await assemble({ lease, admission, simulatorOptions: { invalidContent: "never matches anything" } });
    stopped = await h.controller.run();
    assert.equal(stopped.status, "stopped");
    // A stopped run does not release the locks.
    assert.throws(() => confirmCleanClose(lease, stopped), /not a clean close/);
    recovered = await h.controller.recover();
    assert.equal(recovered.status, "recovered", JSON.stringify(recovered));
    confirmCleanClose(lease, recovered);
  });
  assert.deepEqual(await lockFiles(dirs), []);
});

test("a stop that is not recovered leaves the locks in place", async (t) => {
  const { withLockedAdmission } = await load();
  const dirs = await scratch(t);
  await assert.rejects(withLockedAdmission(params(dirs), async ({ admission, lease }) => {
    const h = await assemble({ lease, admission, simulatorOptions: { invalidContent: "never matches anything" } });
    assert.equal((await h.controller.run()).status, "stopped");
  }), /closure not confirmed; project locks retained/);
  assert.deepEqual(await lockFiles(dirs), ["fireemu-oracle-idp.lock", "fireemu-oracle-query.lock"]);
});

test("a transport failure keeps the locks even after a clean recovery", async (t) => {
  const { withLockedAdmission, confirmCleanClose } = await load();
  const dirs = await scratch(t);
  await assert.rejects(withLockedAdmission(params(dirs), async ({ admission, lease }) => {
    const h = await assemble({ lease, admission }, { transportHook: async (spec, count) => { if (count === 60) throw new Error("connection reset"); } });
    const stopped = await h.controller.run();
    assert.equal(stopped.reason, "outcome uncertain");
    const recovered = await h.controller.recover();
    if (recovered.status === "recovered") confirmCleanClose(lease, recovered);
  }), /outbound attempt failed|cannot confirm|project locks retained/);
  assert.deepEqual(await lockFiles(dirs), ["fireemu-oracle-idp.lock", "fireemu-oracle-query.lock"]);
});

test("only a finished or recovered result confirms the close, and only through this run's lease", async (t) => {
  const { confirmCleanClose } = await load();
  const calls = [];
  const lease = { confirmClosed: () => calls.push("closed") };
  for (const bad of [null, undefined, {}, { status: "stopped" }, { status: "stopped", needsRecovery: true }, { status: "refused" }, { status: "recovered ", }, { status: "FINISHED" }]) assert.throws(() => confirmCleanClose(lease, bad), /not a clean close/);
  assert.deepEqual(calls, []);
  confirmCleanClose(lease, { status: "finished" });
  confirmCleanClose(lease, { status: "recovered" });
  assert.deepEqual(calls, ["closed", "closed"]);
  assert.throws(() => confirmCleanClose({}, { status: "finished" }), /invalid lease/);
  assert.throws(() => confirmCleanClose(null, { status: "finished" }), /invalid lease/);
});

test("the lease transport sends through the lease exactly once per request and returns the answer", async () => {
  const { leaseTransport } = await load();
  const seen = [];
  const lease = { dispatch: async (send) => { seen.push("dispatch"); return send(); } };
  const transport = leaseTransport(lease, { send: async (spec) => { seen.push(spec.url); return { status: 200 }; } });
  assert.deepEqual(await transport.send({ url: "https://x/" }), { status: 200 });
  assert.deepEqual(seen, ["dispatch", "https://x/"]);
  assert.equal(Object.isFrozen(transport), true);
  assert.deepEqual(Object.keys(transport), ["send"]);
  for (const bad of [[null, { send() {} }], [{}, { send() {} }], [lease, {}], [lease, null]]) assert.throws(() => leaseTransport(...bad), /invalid lease transport/);
});
