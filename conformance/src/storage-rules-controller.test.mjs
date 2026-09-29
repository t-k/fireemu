import assert from "node:assert/strict";
import { lstat, mkdir, mkdtemp, open, rm } from "node:fs/promises";
import { readFileSync } from "node:fs";
import test from "node:test";
import { STOP_CODES, tagged } from "./storage-rules/stop-codes.mjs";
import { createCaptureJournal } from "./storage-rules/capture-journal.mjs";
import { buildCorpus } from "./storage-rules/corpus.mjs";
import { createController } from "./storage-rules/controller.mjs";
import { createDispatchGate } from "./storage-rules/dispatch-gate.mjs";
import { buildFullRequestManifest } from "./storage-rules/full-manifest.mjs";
import { createReservationJournal } from "./storage-rules/reservation-journal.mjs";
import { createResourceLedger } from "./storage-rules/resource-ledger.mjs";
import { createRunLedger } from "./storage-rules/run-ledger.mjs";
import { buildRefTables, createRuntimeRefStore } from "./storage-rules/runtime-refs.mjs";
import { buildRecoverySchedule, buildSchedule } from "./storage-rules/schedule.mjs";
import { createTargetBuilder } from "./storage-rules/target.mjs";
import { createSimulator } from "./storage-rules-simulator.mjs";

const closure = JSON.parse(readFileSync(new URL("../../spec/compatibility/closure/STORAGE-RULES.json", import.meta.url)));
const options = { runId: "local-run", sourceCommit: "a".repeat(40), queryProjectNumber: "1".repeat(12), idpProjectNumber: "2".repeat(12), queryApiKeyId: "00000000-0000-4000-8000-000000000001", idpApiKeyId: "00000000-0000-4000-8000-000000000002" };
const binding = { bucket: "synthetic-rules-bucket", prefix: "STORAGE-RULES/local-run/", uidA: "storage-rules-local-run-user-a", uidB: "storage-rules-local-run-user-b" };
const manifest = buildFullRequestManifest(buildCorpus(binding), closure, options);
const salt = "8".repeat(64);
const BEARER = "SIM-BEARER-CANARY-0123456789abcdef";
const invalidContent = manifest.rows.find((r) => r.family === "compile" && r.stage === "test" && r === manifest.rows.filter((x) => x.family === "compile" && x.stage === "test").at(-1)).request.body.json.source.files[0].content;
const delegated = (row) => ["auth", "credential-cache"].includes(row.family);
const counted = manifest.rows.filter((r) => !delegated(r));
const preflightIds = manifest.preflightIds.filter((id) => !id.startsWith("preflight/auth/"));

function memoryCapture() {
  const events = [];
  return {
    events,
    writeIntent: async (r) => { events.push(["intent", r.operationId]); }, writeResponse: async (r) => { events.push(["response", r.operationId]); }, writeFacts: async (r) => { events.push(["facts", r.operationId, r.verdict]); },
    writeProof: async (r) => { events.push(["proof", r.type]); }, writeNote: async (r) => { events.push(["note", r.text]); }, writeDelegatedTarget: async () => {}, snapshot: () => ({ uncertain: false }),
  };
}

// `adjust` receives the controller options the harness built and returns the options the controller gets, so a test can
// replace one collaborator (a gate or ledger wrapper, another recovery schedule) while the harness keeps the originals.
async function harness({ capture = memoryCapture(), simulatorOptions = {}, credentialsFresh = () => true, ensure, waits = [], delegates = {}, judge, adjust = (built) => built } = {}) {
  const simulator = createSimulator({ manifest, options: { invalidContent, ...simulatorOptions } });
  const targets = createTargetBuilder({ manifest, digestSalt: salt });
  const tables = buildRefTables(manifest);
  const refs = createRuntimeRefStore({ tables, runId: options.runId, digestSalt: salt, writeProof: (proof) => capture.writeProof(proof) });
  const objects = createResourceLedger({ manifest });
  const run = createRunLedger({ manifest, objects });
  const trace = [];
  const reservations = { onStarted: async () => { trace.push("started"); }, onReserve: async (r) => { trace.push(r.operationId); }, onTerminal: async (r) => { trace.push(`terminal:${r.outcome}`); } };
  const gate = createDispatchGate({ reservations: harnessReservations ?? reservations, capture, transport: simulator, targets, credentials: { headersFor: (c) => (c === "anonymous" ? {} : { authorization: `Bearer ${BEARER}` }) }, preflightIds, admission: { check: async () => ({ admitted: true }), begin: async () => ({ admitted: true }) } });
  const noop = async () => {};
  const controller = createController(adjust({
    manifest, schedule: buildSchedule(manifest), recoverySchedule: buildRecoverySchedule(manifest), gate, targets, refs, tables, objects, run, capture,
    delegates: { "preflight-cache": noop, "credential-cache": noop, "prepare-query": noop, "foreign-signup": noop, "foreign-cleanup": noop, "cleanup-query": noop, "recover-accounts": noop, ...delegates },
    wait: async (ms) => { waits.push(ms); }, credentials: { fresh: credentialsFresh, ...(ensure ? { ensure } : {}) }, judgePreflight: judge ?? ((row, outcome) => outcome.verdict !== "unexpected"),
  }));
  return { controller, simulator, gate, objects, run, refs, capture, trace, waits };
}
let harnessReservations = null;

test("a whole recording runs against the simulator, cleans up everything it created and finishes", async () => {
  const h = await harness();
  const result = await h.controller.run();
  assert.equal(result.status, "finished", JSON.stringify(result));
  const state = h.simulator.state();
  assert.deepEqual({ objects: state.objects, rulesets: state.rulesets, release: state.release, documents: state.documents }, { objects: 0, rulesets: 0, release: null, documents: 0 });
  assert.ok(state.sessions.every((s) => s === "final" || s === "cancelled"));
  assert.deepEqual([...h.objects.residual()], []);
  assert.equal(h.gate.snapshot().mode, "closed");
  assert.ok(h.trace.at(-1) === "terminal:finished");
  const sent = h.trace.filter((entry) => !["started"].includes(entry) && !entry.startsWith("terminal"));
  assert.equal(new Set(sent).size, sent.length);
  assert.equal(result.requests, sent.length);
  assert.ok(sent.length > 4000 && sent.length <= 4638 + 0);
  assert.ok(result.skipped.length > 0);
  assert.ok(h.waits.length > 0 && h.waits.every((ms) => ms === manifest.restoration.intervalMs));
  assert.ok(sent.every((id) => counted.some((r) => r.id === id)));
  // Every classified response leaves its durable facts, in the order the requests left.
  assert.deepEqual(h.capture.events.filter((event) => event[0] === "facts").map((event) => event[1]), sent);
});

// The number (1-based) of the first simulator call whose log line matches, from a completed dry run.
async function firstCall(pattern, from = 0) {
  const h = await harness();
  await h.controller.run();
  const index = h.simulator.state().log.findIndex((line, i) => i >= from && pattern.test(line));
  assert.ok(index >= 0, String(pattern));
  return index + 1;
}
const response = (status, body = {}) => ({ status, rawHeaders: ["Content-Type", "application/json"], bytes: Buffer.from(JSON.stringify(body)), startedAtMs: 1, finishedAtMs: 2 });

test("stale credentials stop the first row that needs a fresh user token, and the writes already made keep the counter open", async () => {
  const h = await harness({ credentialsFresh: () => false });
  const result = await h.controller.run();
  const firstCase = manifest.rows.find((r) => r.family === "declared" && r.programId === manifest.publication.v1[0] && r.requires.includes("canonical-program-state-and-fresh-credential"));
  assert.deepEqual([result.status, result.reason, result.detail.rowId], ["stopped", "guard failed", firstCase.id]);
  assert.deepEqual(result.detail.tokens, ["canonical-program-state-and-fresh-credential"]);
  assert.equal(result.needsRecovery, true);
  assert.equal(h.gate.snapshot().mode, "normal");
  assert.equal(h.trace.some((id) => id.startsWith("terminal")), false);
  assert.equal(h.simulator.state().rulesets, 4);
});

test("a refused preflight, a foreign entry release or a malformed answer stops before admission", async () => {
  const refused = await harness({ judge: (row) => row.id !== "preflight/query/project" });
  const one = await refused.controller.run();
  assert.deepEqual([one.status, one.reason, one.detail.rowId], ["stopped", "preflight refused", "preflight/query/project"]);
  assert.equal(refused.trace.at(-1), "terminal:preflight-failed");
  const releaseCall = await firstCall(/GET firebaserules\.googleapis\.com\/v1\/projects\/fireemu-oracle-query\/releases\/firebase\.storage\/synthetic-rules-bucket/);
  const foreign = await harness({ simulatorOptions: { failures: new Map([[releaseCall, () => response(200, { name: "projects/fireemu-oracle-query/releases/firebase.storage/synthetic-rules-bucket", rulesetName: "projects/fireemu-oracle-query/rulesets/x", createTime: "2026-09-29T10:00:00Z", updateTime: "2026-09-29T10:00:00Z" })]]) } });
  const two = await foreign.controller.run();
  assert.deepEqual([two.status, two.reason, two.detail.rowId], ["stopped", "preflight refused", "preflight/release/entry/bucket"]);
  assert.equal(foreign.trace.at(-1), "terminal:preflight-failed");
  const malformed = await harness({ simulatorOptions: { failures: new Map([[1, () => ({ status: 200, rawHeaders: ["a"], bytes: Buffer.alloc(0) })]]) } });
  const three = await malformed.controller.run();
  assert.equal(three.status, "stopped");
  assert.equal(three.reason, "preflight refused");
  assert.equal(malformed.trace.at(-1), "terminal:preflight-failed");
});

test("a dirty namespace is refused: an object that exists before the run stops it at the baseline read", async () => {
  const controls = manifest.resources.controls;
  const h = await harness({ simulatorOptions: { preexisting: [controls[0]] } });
  const result = await h.controller.run();
  assert.deepEqual([result.status, result.reason, result.detail.rowId], ["stopped", "unexpected verdict", "management/control-0/baseline-metadata"]);
  assert.equal(result.needsRecovery, false);
  assert.equal(h.objects.object(controls[0]).owned, false);
  // Nothing was written, so the controller closes the counter itself.
  assert.equal(h.gate.snapshot().mode, "closed");
  assert.equal(h.trace.at(-1), "terminal:stopped-no-mutation");
});

test("an unexpected seed answer stops the run, leaves the counter open and the object unowned", async () => {
  const call = await firstCall(/^POST storage\.googleapis\.com\/upload/);
  const h = await harness({ simulatorOptions: { failures: new Map([[call, () => response(412, { error: { code: 412, message: "Precondition Failed" } })]]) } });
  const result = await h.controller.run();
  assert.deepEqual([result.status, result.reason], ["stopped", "unexpected verdict"]);
  assert.equal(result.needsRecovery, true);
  assert.equal(h.gate.snapshot().mode, "normal");
  const seed = h.objects.object(manifest.resources.controls[0]);
  assert.equal(seed.owned, false);
  assert.equal(h.trace.some((id) => id.startsWith("terminal")), false);
});

test("a lost connection on a write leaves the outcome uncertain and moves the counter to recovery, without a second attempt", async () => {
  const call = await firstCall(/^POST storage\.googleapis\.com\/upload/);
  const h = await harness({ simulatorOptions: { failures: new Map([[call, "throw"]]) } });
  const result = await h.controller.run();
  assert.deepEqual([result.status, result.reason], ["stopped", "outcome uncertain"]);
  assert.equal(result.needsRecovery, true);
  assert.equal(h.gate.snapshot().mode, "recovery");
  const sends = h.trace.filter((id) => id === "management/control-0/seed");
  assert.equal(sends.length, 1);
  assert.equal(h.simulator.state().calls, call);
});

test("a publication that never settles ends the wait after thirty cycles and stops the run", async () => {
  const waits = [];
  const h = await harness({ simulatorOptions: { lag: 1000 }, waits });
  const result = await h.controller.run();
  assert.deepEqual([result.status, result.reason, result.detail.name], ["stopped", "settle exhausted", "v1"]);
  assert.equal(waits.length, 29);
  assert.equal(result.needsRecovery, true);
  assert.equal(h.run.snapshot().settled.v1, "exhausted");
});

test("a valid source the service rejects, or the invalid one it accepts, stops the compile phase", async () => {
  const tests = manifest.rows.filter((r) => r.family === "compile" && r.stage === "test");
  const validContent = tests[0].request.body.json.source.files[0].content;
  const rejectedValid = await harness({ simulatorOptions: { invalidContent: validContent } });
  const one = await rejectedValid.controller.run();
  assert.deepEqual([one.status, one.reason, one.detail.rowId], ["stopped", "unexpected verdict", tests[0].id]);
  const acceptedInvalid = await harness({ simulatorOptions: { invalidContent: "never matches anything" } });
  const two = await acceptedInvalid.controller.run();
  assert.deepEqual([two.status, two.reason, two.detail.rowId], ["stopped", "unexpected verdict", tests.at(-1).id]);
});

test("a capture failure after a send stops the run and no further request leaves", async () => {
  const capture = memoryCapture();
  let responses = 0;
  const original = capture.writeResponse;
  capture.writeResponse = async (r) => { if (++responses === 25) throw new Error("disk full"); return original(r); };
  const h = await harness({ capture });
  const result = await h.controller.run();
  assert.deepEqual([result.status, result.reason], ["stopped", "capture failed"]);
  assert.equal(h.gate.snapshot().poisoned, true);
  assert.equal(h.trace.filter((id) => !["started"].includes(id) && !id.startsWith("terminal")).length, 25);
});

test("a gate failure is mapped to its stop reason by the stop code it carries, never by its message", async () => {
  const cases = [
    [tagged(STOP_CODES.admissionRefused, "anything"), "admission refused"],
    [tagged(STOP_CODES.preflightFailed, "anything"), "preflight refused"],
    [tagged(STOP_CODES.outcomeUncertain, "anything"), "outcome uncertain"],
    [tagged(STOP_CODES.captureFailed, "anything"), "capture failed"],
    // The same words without the code are just a request that was not sent.
    [new Error("admission refused: revoked"), "not sent"],
    [new Error("preflight failed: preflight/x"), "not sent"],
    [new Error("request outcome uncertain"), "not sent"],
    [new Error("capture journal uncertain"), "not sent"],
    [new Error("dispatch gate is poisoned"), "not sent"],
    [Object.assign(new Error("x"), { stopCode: "admission-refused-typo" }), "not sent"],
  ];
  for (const [error, reason] of cases) {
    const h = await harness({ adjust: (built) => ({ ...built, gate: { ...built.gate, send: async () => { throw error; } } }) });
    const result = await h.controller.run();
    assert.deepEqual([result.status, result.reason], ["stopped", reason], `${error.message} ${error.stopCode}`);
  }
  // The gate's start is mapped the same way: a coded refusal is a stop, and the same words without the code are not swallowed.
  const refused = tagged(STOP_CODES.admissionRefused, "refused");
  const h = await harness({ adjust: (built) => ({ ...built, gate: { ...built.gate, start: async () => { throw refused; } } }) });
  const result = await h.controller.run();
  assert.deepEqual([result.status, result.reason], ["stopped", "admission refused"]);
  const plain = new Error("admission refused: by message only");
  const g = await harness({ adjust: (built) => ({ ...built, gate: { ...built.gate, start: async () => { throw plain; } } }) });
  await assert.rejects(g.controller.run(), (thrown) => thrown === plain);
});

test("a schedule step without its delegate stops the run, and the options are a closed record", async () => {
  const h = await harness({ delegates: { "prepare-query": undefined } });
  const result = await h.controller.run();
  assert.deepEqual([result.status, result.reason, result.detail.op], ["stopped", "delegate missing", "prepare-query"]);
  const mod = await import("./storage-rules/controller.mjs");
  for (const bad of [null, {}, { manifest }, { ...(await harness()).controller }]) assert.throws(() => mod.createController(bad), /invalid controller options/);
  // Only the non-sending draft manifest may be driven.
  for (const sendAuthorized of [true, undefined]) await assert.rejects(harness({ adjust: (built) => ({ ...built, manifest: { ...manifest, sendAuthorized } }) }), /invalid controller options/);
});

test("every request the controller sends is one the schedule names, exactly once", async () => {
  const h = await harness();
  const result = await h.controller.run();
  assert.equal(result.status, "finished");
  const schedule = buildSchedule(manifest);
  const scheduled = new Set([...schedule.preflight, ...schedule.steps.flatMap((step) => (step.type === "row" ? [step.id] : step.rowIds))]);
  const sent = h.trace.filter((id) => !["started"].includes(id) && !id.startsWith("terminal"));
  assert.ok(sent.every((id) => scheduled.has(id)));
  assert.equal(new Set(sent).size, sent.length);
  assert.equal(sent.some((id) => id.startsWith("recovery/")), false);
  const skippedAndSent = result.skipped.filter((id) => sent.includes(id));
  assert.deepEqual(skippedAndSent, []);
});

test("a credential provider's ensure hook runs before the freshness check of every row and a failure stops the run", async () => {
  const order = [];
  const h = await harness({ ensure: async (row) => { order.push(["ensure", row.id]); }, credentialsFresh: (row) => { order.push(["fresh", row.id]); return true; } });
  const result = await h.controller.run();
  assert.equal(result.status, "finished");
  assert.ok(order.length > 4000);
  for (let index = 0; index < order.length; index += 2) {
    assert.equal(order[index][0], "ensure");
    assert.deepEqual([order[index + 1][0], order[index + 1][1]], ["fresh", order[index][1]]);
  }
  let calls = 0;
  const failing = await harness({ ensure: async () => { if (++calls === 30) throw new Error("refresh failed"); } });
  const stopped = await failing.controller.run();
  assert.deepEqual([stopped.status, stopped.reason], ["stopped", "credential refresh failed"]);
  assert.equal(failing.trace.filter((id) => id !== "started").length <= 40, true);
});

// Recovery: the same controller, ledgers and gate finish what a stopped run left behind, using only the declared recovery rows.
const clean = { objects: 0, rulesets: 0, release: null, documents: 0 };
const cleanOf = (h) => { const state = h.simulator.state(); return { objects: state.objects, rulesets: state.rulesets, release: state.release, documents: state.documents }; };
const sentIds = (h) => h.trace.filter((id) => id !== "started" && !id.startsWith("terminal"));

test("after a stop with the release published, recovery removes everything the run made and closes as recovered", async () => {
  const h = await harness({ credentialsFresh: () => false });
  const stopped = await h.controller.run();
  assert.equal(stopped.needsRecovery, true);
  assert.ok(h.simulator.state().rulesets > 0 && h.simulator.state().objects > 0 && h.simulator.state().release !== null);
  const before = sentIds(h).length;
  const result = await h.controller.recover();
  assert.equal(result.status, "recovered", JSON.stringify(result));
  assert.deepEqual(cleanOf(h), clean);
  assert.deepEqual([...h.objects.residual()], []);
  assert.equal(h.trace.at(-1), "terminal:recovered");
  assert.equal(h.gate.snapshot().mode, "closed");
  const recoverySent = sentIds(h).slice(before);
  assert.ok(recoverySent.length > 0 && recoverySent.every((id) => id.startsWith("recovery/")));
  assert.equal(new Set(sentIds(h)).size, sentIds(h).length);
  assert.equal(result.requests, recoverySent.length);
  assert.ok(recoverySent.length <= 2000);
  assert.equal(recoverySent.at(-1), "recovery/management/prefix-empty");
});

test("recovery never sends a second delete for a resource whatever ID carries it", async () => {
  const h = await harness({ credentialsFresh: () => false });
  await h.controller.run();
  await h.controller.recover();
  const deletes = h.simulator.state().log.filter((line) => /^DELETE /.test(line));
  assert.equal(new Set(deletes).size, deletes.length);
});

test("recovery after a lost connection continues in the counter's recovery mode", async () => {
  const call = await firstCall(/^POST storage\.googleapis\.com\/upload/);
  const h = await harness({ simulatorOptions: { failures: new Map([[call, "throw"]]) } });
  const stopped = await h.controller.run();
  assert.equal(stopped.reason, "outcome uncertain");
  assert.equal(h.gate.snapshot().mode, "recovery");
  const result = await h.controller.recover();
  // The uncertain create is not owned, so recovery never deletes it and reports what remains.
  assert.ok(["recovered", "stopped"].includes(result.status), JSON.stringify(result));
  assert.equal(h.gate.snapshot().mode, "closed");
  const afterFailure = sentIds(h).slice(sentIds(h).indexOf("management/control-0/seed") + 1);
  assert.ok(afterFailure.every((id) => id.startsWith("recovery/")));
});

test("a recovery step that meets a surprise stops recovery and closes as needs-recovery", async () => {
  const h = await harness({ credentialsFresh: () => false });
  await h.controller.run();
  const calls = h.simulator.state().calls;
  // The recovery's first request fails with a server error: nothing recovery may assume, so it stops.
  const failing = await harness({ credentialsFresh: () => false, simulatorOptions: { failures: new Map([[calls + 1, () => response(500, { error: { code: 500, message: "boom" } })]]) } });
  await failing.controller.run();
  const before = sentIds(failing).length;
  const result = await failing.controller.recover();
  assert.equal(result.status, "stopped");
  // The request count covers this recovery only, not the run before it.
  assert.equal(result.requests, sentIds(failing).length - before);
  assert.ok(["unexpected verdict", "check failed", "guard failed", "unclassifiable response"].includes(result.reason), result.reason);
  assert.equal(failing.trace.at(-1), "terminal:needs-recovery");
  assert.equal(failing.gate.snapshot().mode, "closed");
  assert.equal((await failing.controller.recover()).status, "refused");
});

// The number (1-based) of the simulator call that carries the row `nth` after the first row matching, from a dry run.
async function callAfter(predicate, offset = 1) {
  const h = await harness();
  await h.controller.run();
  const index = sentIds(h).findIndex((id) => predicate(manifest.rows.find((r) => r.id === id)));
  assert.ok(index >= 0);
  return index + offset + 1;
}
const failWith500 = (call) => ({ failures: new Map([[call, () => response(500, { error: { code: 500, message: "boom" } })]]) });

test("a stop before any release was written skips the release group but still restores the witnesses before deleting them", async () => {
  const h = await harness({ simulatorOptions: { invalidContent: "never matches anything" } });
  const stopped = await h.controller.run();
  assert.equal(stopped.reason, "unexpected verdict");
  assert.ok(h.simulator.state().objects > 0);
  const before = sentIds(h).length;
  const result = await h.controller.recover();
  assert.equal(result.status, "recovered", JSON.stringify(result));
  assert.deepEqual(cleanOf(h), clean);
  const recoverySent = sentIds(h).slice(before);
  assert.equal(recoverySent.some((id) => id.startsWith("recovery/release/")), false);
  // The disabled group is reported as skipped, row by row.
  for (const stage of ["owner-before-delete", "delete", "bucket-absence", "bucketless-absence"]) assert.ok(result.skipped.includes(`recovery/release/restore/${stage}`), stage);
  // The witness deletion is guarded by the four owner readbacks, which follow the restore settle.
  assert.equal(recoverySent.filter((id) => id.startsWith("recovery/management/restore-owner-media/")).length, 4);
  assert.ok(recoverySent.some((id) => id.startsWith("recovery/settle/restore/")));
  assert.ok(recoverySent.findIndex((id) => id.startsWith("recovery/settle/")) < recoverySent.findIndex((id) => id.startsWith("recovery/management/restore-owner-media/")));
  assert.ok(recoverySent.findIndex((id) => id.startsWith("recovery/management/restore-owner-media/3")) < recoverySent.findIndex((id) => id.startsWith("recovery/object-")));
  assert.equal(recoverySent.some((id) => id.startsWith("recovery/object-")), true);
  assert.equal(h.trace.at(-1), "terminal:recovered");
});

test("a stop after an open upload session cancels it once and verifies it", async () => {
  const start = (r) => r.request.headers?.["x-goog-upload-command"] === "start";
  const call = await callAfter(start, 1);
  const h = await harness({ simulatorOptions: failWith500(call) });
  const stopped = await h.controller.run();
  assert.equal(stopped.status, "stopped");
  assert.ok(h.simulator.state().sessions.some((state) => state === "active"), JSON.stringify(h.simulator.state().sessions));
  const result = await h.controller.recover();
  assert.equal(result.status, "recovered", JSON.stringify(result));
  assert.ok(h.simulator.state().sessions.every((state) => state === "final" || state === "cancelled"));
  assert.deepEqual(cleanOf(h), clean);
  const cancels = sentIds(h).filter((id) => /^recovery\/session\/.*\/cancel$/.test(id));
  assert.equal(cancels.length, 1);
});

test("a stop after a document write recovers the document", async () => {
  const write = (r) => r.service === "firestore" && ["PATCH", "POST", "PUT"].includes(r.request.method);
  const call = await callAfter(write, 1);
  const h = await harness({ simulatorOptions: failWith500(call) });
  const stopped = await h.controller.run();
  assert.equal(stopped.status, "stopped");
  assert.ok(h.simulator.state().documents > 0);
  const result = await h.controller.recover();
  assert.equal(result.status, "recovered", JSON.stringify(result));
  assert.deepEqual(cleanOf(h), clean);
});

test("a release delete that failed is never retried, and recovery reports the release it cannot prove gone", async () => {
  const call = await firstCall(/^DELETE firebaserules\.googleapis\.com\/v1\/projects\/fireemu-oracle-query\/releases\/firebase\.storage\/synthetic-rules-bucket/);
  const h = await harness({ simulatorOptions: failWith500(call) });
  const stopped = await h.controller.run();
  assert.equal(stopped.status, "stopped");
  const result = await h.controller.recover();
  assert.equal(result.status, "stopped");
  assert.equal(h.trace.at(-1), "terminal:needs-recovery");
  assert.equal(sentIds(h).some((id) => id === "recovery/release/restore/delete"), false);
  assert.notEqual(h.simulator.state().release, null);
});

test("recovery refuses to start before admission or after a close, and sends nothing", async () => {
  const fresh = await harness();
  const none = await fresh.controller.recover();
  assert.equal(none.status, "refused");
  assert.equal(fresh.simulator.state().calls, 0);
  const done = await harness();
  await done.controller.run();
  const calls = done.simulator.state().calls;
  const after = await done.controller.recover();
  assert.equal(after.status, "refused");
  assert.equal(done.simulator.state().calls, calls);
});

test("recovery is enabled by ledger facts: a run stopped before any write recovers nothing and sends no delete", async () => {
  const h = await harness({ judge: (row) => row.id !== "preflight/query/project" });
  await h.controller.run();
  const calls = h.simulator.state().calls;
  const result = await h.controller.recover();
  assert.equal(result.status, "refused");
  assert.equal(h.simulator.state().calls, calls);
});

// The IDs one completed dry run sent, in order. Until an injected answer changes the run, a row's simulator call number is
// its position here plus one.
let dryRunSent = null;
async function dryRun() {
  if (dryRunSent === null) { const h = await harness(); await h.controller.run(); dryRunSent = sentIds(h); }
  return dryRunSent;
}
async function callOf(id) { const index = (await dryRun()).indexOf(id); assert.ok(index >= 0, id); return index + 1; }
const rowOf = (id) => manifest.rows.find((r) => r.id === id);
async function firstSent(predicate) { const id = (await dryRun()).find((sent) => predicate(rowOf(sent))); assert.ok(id); return id; }
const answerAt = (call, answer) => ({ failures: new Map([[call, answer]]) });
const objectPresent = (row) => response(200, { kind: "storage#object", bucket: binding.bucket, name: row.request.objectName, generation: "1700000000000999", metageneration: "1", size: "4" });
const mediaPresent = () => ({ status: 200, rawHeaders: ["Content-Type", "text/plain"], bytes: Buffer.from("seed"), startedAtMs: 1, finishedAtMs: 2 });
const rpcNotFound = () => response(404, { error: { code: 404, message: "Requested entity was not found.", status: "NOT_FOUND" } });
const rulesetPresent = () => response(200, { name: "projects/fireemu-oracle-query/rulesets/foreign", createTime: "2026-09-29T10:00:00.000000Z", source: { files: [{ name: "storage.rules", content: "x" }] } });
const serverError = () => response(500, { error: { code: 500, message: "boom" } });

test("each row kind stops the run on a verdict its step must not accept", async () => {
  const baseline = await firstSent((r) => r.family === "declared" && r.stage === "baseline" && r.request.operation === "get-metadata");
  const cleanupAbsence = await firstSent((r) => r.family === "declared" && r.stage === "cleanup" && /absence/.test(r.id) && r.request.operation === "get-metadata");
  const verify = await firstSent((r) => r.family === "session-verify");
  const cases = [
    // Reads that must find nothing: a case baseline, a control's baseline media, a case cleanup and a control's final absence.
    [baseline, objectPresent],
    ["management/control-0/baseline-media", mediaPresent],
    [cleanupAbsence, objectPresent],
    ["management/control-0/absence-metadata", objectPresent],
    ["management/control-0/absence-media", mediaPresent],
    // A created Ruleset must read back, a deleted one must be gone, and the release must exist before its removal.
    ["ruleset/v1/read-source", rpcNotFound],
    ["ruleset/v1/absence", rulesetPresent],
    ["release/restore/owner-before-delete", rpcNotFound],
    // A session query answers active or final, nothing else.
    [verify, serverError],
  ];
  for (const [id, answer] of cases) {
    const h = await harness({ simulatorOptions: answerAt(await callOf(id), () => answer(rowOf(id))) });
    const result = await h.controller.run();
    assert.deepEqual([result.status, result.reason, result.detail.rowId], ["stopped", "unexpected verdict", id], id);
  }
});

const sessionActive = () => ({ status: 200, rawHeaders: ["X-Goog-Upload-Status", "active", "X-Goog-Upload-Size-Received", "0"], bytes: Buffer.alloc(0), startedAtMs: 1, finishedAtMs: 2 });

test("a session that still answers active after its cancel stops the run at once", async () => {
  const verify = await firstSent((r) => r.family === "session-verify");
  const h = await harness({ simulatorOptions: answerAt(await callOf(verify), sessionActive) });
  const result = await h.controller.run();
  assert.deepEqual([result.status, result.reason, result.detail.rowId], ["stopped", "unexpected verdict", verify]);
  // Nothing is sent after the surprise: the verify row is the last request of the run.
  assert.equal(sentIds(h).at(-1), verify);
  assert.equal(result.needsRecovery, true);
});

test("recovery stops when a session still answers active after its cancel", async () => {
  const start = (r) => r.request.headers?.["x-goog-upload-command"] === "start";
  const call = await callAfter(start, 1);
  const dry = await harness({ simulatorOptions: failWith500(call) });
  await dry.controller.run();
  await dry.controller.recover();
  const terminal = sentIds(dry).find((id) => /^recovery\/session\/.*\/terminal$/.test(id));
  assert.ok(terminal);
  const terminalCall = sentIds(dry).indexOf(terminal) + 1;
  const h = await harness({ simulatorOptions: { failures: new Map([[call, () => response(500, { error: { code: 500, message: "boom" } })], [terminalCall, sessionActive]]) } });
  await h.controller.run();
  const result = await h.controller.recover();
  assert.deepEqual([result.status, result.reason, result.detail.rowId], ["stopped", "unexpected verdict", terminal]);
  assert.equal(h.trace.at(-1), "terminal:needs-recovery");
});

test("an untouched run whose first read failed leaves the counter open, says so, counts the read and is closed clean by recovery", async () => {
  const id = "management/control-0/baseline-metadata";
  const h = await harness({ simulatorOptions: answerAt(await callOf(id), "throw") });
  const result = await h.controller.run();
  assert.deepEqual([result.status, result.reason, result.detail.rowId], ["stopped", "outcome uncertain", id]);
  // Nothing was written, but the counter flipped to recovery and no terminal row was written: the run is not closed.
  assert.equal(h.gate.snapshot().mode, "recovery");
  assert.equal(h.trace.some((entry) => entry.startsWith("terminal:")), false);
  assert.equal(result.needsRecovery, true);
  // The result counts every reservation the counter made, the uncertain read included.
  assert.equal(result.requests, sentIds(h).length);
  assert.equal(result.requests, h.gate.snapshot().requests);
  const recovered = await h.controller.recover();
  assert.equal(recovered.status, "recovered", JSON.stringify(recovered));
  assert.equal(h.trace.at(-1), "terminal:recovered");
  assert.equal(recovered.requests, sentIds(h).length - result.requests);
});

test("a result never claims a recovery is unneeded while the counter is open", async () => {
  // A read that fails after a write: the writes make the recovery needed; a run stopped before admission is closed and needs none.
  const write = await harness({ simulatorOptions: failWith500(await callAfter((r) => r.request.method === "PATCH" || r.request.operation === "seed", 1)) });
  assert.equal((await write.controller.run()).needsRecovery, true);
  const refused = await harness({ judge: (row) => row.id !== "preflight/query/project" });
  const one = await refused.controller.run();
  assert.equal(one.needsRecovery, false);
  assert.equal(refused.gate.snapshot().mode, "closed");
});

test("a settle read that is neither allowed nor denied stops the run at once, in a publication settle and in a restore settle, in a run and in recovery", async () => {
  const publication = await firstSent((r) => r.family === "settle" && r.phase === "normal" && r.programId === "v1");
  for (const answer of [serverError, () => response(404, { error: { code: 404, message: "Not Found." } }), () => response(429, { error: { code: 429, message: "quota" } }), () => response(401, { error: { code: 401, message: "auth" } }), () => ({ status: 200, rawHeaders: ["Content-Type", "text/plain"], bytes: Buffer.from("not the seed") })]) {
    const h = await harness({ simulatorOptions: answerAt(await callOf(publication), answer) });
    const result = await h.controller.run();
    assert.deepEqual([result.status, result.reason, result.detail.rowId], ["stopped", "unexpected verdict", publication]);
    assert.equal(sentIds(h).at(-1), publication);
  }
  const restore = await firstSent((r) => r.family === "settle" && r.phase === "normal" && r.programId === "restore");
  const h = await harness({ simulatorOptions: answerAt(await callOf(restore), serverError) });
  const stopped = await h.controller.run();
  assert.deepEqual([stopped.reason, stopped.detail.rowId], ["unexpected verdict", restore]);
  // The same in recovery: the restore settle stops recovery on its first odd answer.
  const dry = await harness({ credentialsFresh: () => false });
  await dry.controller.run();
  await dry.controller.recover();
  const recoverySettle = sentIds(dry).find((id) => id.startsWith("recovery/settle/restore/"));
  assert.ok(recoverySettle);
  const recoveryCall = sentIds(dry).indexOf(recoverySettle) + 1;
  const stale = await harness({ credentialsFresh: () => false, simulatorOptions: answerAt(recoveryCall, serverError) });
  await stale.controller.run();
  const recovered = await stale.controller.recover();
  assert.deepEqual([recovered.status, recovered.reason, recovered.detail.rowId], ["stopped", "unexpected verdict", recoverySettle]);
});

test("a response that fails its post-response check stops the run as a failed check", async () => {
  // A publication's after-read must name the Ruleset the run created; a missing release fails that check.
  const after = await harness({ simulatorOptions: answerAt(await callOf("release/v1/after"), rpcNotFound) });
  const one = await after.controller.run();
  assert.deepEqual([one.status, one.reason, one.detail.rowId, one.detail.tokens], ["stopped", "check failed", "release/v1/after", ["release-name-and-created-ruleset-match"]]);
  // The entry Ruleset list must be a single page.
  const entry = await harness({ simulatorOptions: answerAt(await callOf("preflight/rulesets-list/entry/1"), () => response(200, { nextPageToken: "next" })) });
  const two = await entry.controller.run();
  assert.deepEqual([two.status, two.reason, two.detail.rowId, two.detail.tokens], ["stopped", "check failed", "preflight/rulesets-list/entry/1", ["entry-page-has-no-next-token"]]);
});

test("a response the classifier cannot read stops the run as unclassifiable", async () => {
  const id = "management/control-0/baseline-metadata";
  const h = await harness({ simulatorOptions: answerAt(await callOf(id), () => ({ status: 200, rawHeaders: ["a"], bytes: Buffer.alloc(0) })) });
  const result = await h.controller.run();
  assert.deepEqual([result.status, result.reason, result.detail.rowId], ["stopped", "unclassifiable response", id]);
});

test("a created download token that comes back as a list of tokens stops the run before it is bound", async () => {
  const id = await firstSent((r) => r.request.operation === "create-token");
  const row = rowOf(id);
  const h = await harness({ simulatorOptions: answerAt(await callOf(id), () => response(200, { name: row.request.objectName, bucket: binding.bucket, generation: "1700000000000999", metageneration: "1", size: "4", contentType: "text/plain", downloadTokens: "token-one,token-two" })) });
  const result = await h.controller.run();
  assert.deepEqual([result.status, result.reason, result.detail.rowId], ["stopped", "more than one download token", id]);
});

test("the final Ruleset list follows each page token to the next page and stops after ten pages", async () => {
  const first = await callOf("rulesets-list/final/1");
  const tokens = [];
  const failures = new Map(Array.from({ length: 10 }, (_, index) => [first + index, (spec) => { tokens.push(new URL(spec.url).searchParams.get("pageToken")); return response(200, { nextPageToken: `page-${index + 2}` }); }]));
  const h = await harness({ simulatorOptions: { failures } });
  const result = await h.controller.run();
  assert.deepEqual([result.status, result.reason], ["stopped", "more than ten Ruleset pages"]);
  assert.deepEqual(tokens, [null, ...Array.from({ length: 9 }, (_, index) => `page-${index + 2}`)]);
  assert.deepEqual(sentIds(h).slice(-10), Array.from({ length: 10 }, (_, index) => `rulesets-list/final/${index + 1}`));
});

// Seams: the ledgers and the recovery schedule are the controller's collaborators, so a test can make one answer what
// today's manifest never makes it answer and prove the controller's own guard behind it.
const ledgerAnswering = (built, answer) => Object.freeze({ ...built.run, ...answer(built.run) });

test("a settle read the ledgers would skip stops the run instead of counting as a cycle", async () => {
  const skipSettle = (run) => ({ evaluate: (row, tokens) => { const seen = run.evaluate(row, tokens); return row.family === "settle" ? Object.freeze({ ...seen, decision: "skip", failed: Object.freeze([Object.freeze({ token: "all-four-controls-confirmed-and-retained", outcome: "skip" })]) }) : seen; } });
  const h = await harness({ adjust: (built) => ({ ...built, run: ledgerAnswering(built, skipSettle) }) });
  const result = await h.controller.run();
  assert.deepEqual([result.status, result.reason, result.detail.rowId], ["stopped", "settle read skipped", "settle/v1/1/0"]);
});

test("a write the run ledger recorded keeps the counter open even when no object was written", async () => {
  const oneWrite = (run) => ({ snapshot: () => Object.freeze({ ...run.snapshot(), mutations: 1 }) });
  const h = await harness({ simulatorOptions: { preexisting: [manifest.resources.controls[0]] }, adjust: (built) => ({ ...built, run: ledgerAnswering(built, oneWrite) }) });
  const result = await h.controller.run();
  assert.deepEqual([result.status, result.reason, result.needsRecovery], ["stopped", "unexpected verdict", true]);
  assert.equal(h.gate.snapshot().mode, "normal");
  assert.equal(h.trace.some((id) => id.startsWith("terminal")), false);
});

test("an update time is bound with the run ledger's own deletable answer, so a document it does not call deletable is never deleted", async () => {
  // Today a document read is deletable whenever a delete's guards pass; a ledger that says otherwise must still be obeyed.
  const neverDeletable = (run) => ({ document: (name) => Object.freeze({ ...run.document(name), deletable: false }) });
  const h = await harness({ adjust: (built) => ({ ...built, run: ledgerAnswering(built, neverDeletable) }) });
  const result = await h.controller.run();
  const del = await firstSent((r) => r.service === "firestore" && r.request.method === "DELETE");
  assert.deepEqual([result.status, result.reason, result.detail.rowId, result.detail.cause], ["stopped", "target unavailable", del, "reference is not deletable"]);
  assert.equal(sentIds(h).includes(del), false);
});

test("recovery runs once: after a recovery whose close failed, a second call is refused and sends nothing", async () => {
  let failFinish = false;
  const flaky = (gate) => Object.freeze({ ...gate, finish: async (outcome) => { if (failFinish) { failFinish = false; throw new Error("journal unavailable"); } return gate.finish(outcome); } });
  const h = await harness({ credentialsFresh: () => false, adjust: (built) => ({ ...built, gate: flaky(built.gate) }) });
  await h.controller.run();
  failFinish = true;
  await assert.rejects(h.controller.recover(), /journal unavailable/);
  assert.equal(h.gate.snapshot().mode, "recovery");
  const calls = h.simulator.state().calls;
  const again = await h.controller.recover();
  assert.deepEqual([again.status, again.reason], ["refused", "recovery already attempted"]);
  assert.equal(h.simulator.state().calls, calls);
});

test("an error that is not a stop escapes recovery and leaves the counter open", async () => {
  const capture = memoryCapture();
  let failFacts = false;
  const original = capture.writeFacts;
  capture.writeFacts = async (r) => { if (failFacts) throw new Error("facts journal unavailable"); return original(r); };
  const h = await harness({ capture, credentialsFresh: () => false });
  await h.controller.run();
  failFacts = true;
  await assert.rejects(h.controller.recover(), /facts journal unavailable/);
  assert.equal(h.gate.snapshot().mode, "recovery");
  assert.equal(h.trace.some((id) => id.startsWith("terminal")), false);
});

test("a recovery whose final owned-prefix check was skipped closes as needs-recovery, not recovered", async () => {
  // The reviewed schedule never gates the final check; one that did would skip it after a run that wrote no release.
  const reviewed = buildRecoverySchedule(manifest);
  const gated = Object.freeze({ steps: Object.freeze([...reviewed.steps.slice(0, -1), Object.freeze({ ...reviewed.steps.at(-1), enabledBy: "release-written" })]) });
  const h = await harness({ simulatorOptions: { invalidContent: "never matches anything" }, adjust: (built) => ({ ...built, recoverySchedule: gated }) });
  await h.controller.run();
  const result = await h.controller.recover();
  assert.deepEqual([result.status, result.reason, result.needsRecovery], ["stopped", "owned-prefix check skipped", true]);
  assert.ok(result.skipped.includes("recovery/management/prefix-empty"));
  assert.equal(sentIds(h).includes("recovery/management/prefix-empty"), false);
  assert.equal(h.trace.at(-1), "terminal:needs-recovery");
});

test("a release read whose outcome is uncertain enables the release absence reads in recovery, whose guard then stops it", async () => {
  const h = await harness({ simulatorOptions: answerAt(await callOf("compile/release/before"), "throw") });
  const stopped = await h.controller.run();
  assert.deepEqual([stopped.reason, stopped.detail.rowId], ["outcome uncertain", "compile/release/before"]);
  const result = await h.controller.recover();
  // No release write was attempted, so only the absence group is enabled; the uncertain release refuses its first read.
  assert.deepEqual([result.status, result.reason, result.detail.rowId, result.detail.tokens, result.requests], ["stopped", "guard failed", "recovery/release/restore/bucket-absence", ["restore-without-unowned-release-change"], 0]);
  assert.deepEqual(result.skipped, ["recovery/release/restore/owner-before-delete", "recovery/release/restore/delete"]);
  assert.equal(h.trace.at(-1), "terminal:needs-recovery");
});

test("owner readbacks count per witness, so a recovery that repeats two of them still reads all four before deleting the witnesses", async () => {
  // The run stops before the third owner readback is sent, so the witnesses stay confirmed.
  const h = await harness({ ensure: async (row) => { if (row.id === "management/restore-owner-media/2") throw new Error("refresh failed"); } });
  const stopped = await h.controller.run();
  assert.deepEqual([stopped.reason, stopped.detail.rowId], ["credential refresh failed", "management/restore-owner-media/2"]);
  assert.equal(h.run.snapshot().ownerMedia, 2);
  const result = await h.controller.recover();
  assert.equal(result.status, "recovered", JSON.stringify(result));
  // Repeating the first two readbacks does not stand in for the other two: all four are read before any witness goes.
  const readbacks = sentIds(h).filter((id) => id.startsWith("recovery/management/restore-owner-media/"));
  assert.deepEqual(readbacks, [0, 1, 2, 3].map((index) => `recovery/management/restore-owner-media/${index}`));
  assert.ok(sentIds(h).indexOf(readbacks.at(-1)) < sentIds(h).findIndex((id) => /^recovery\/object-\d+\/delete$/.test(id)));
  assert.deepEqual(cleanOf(h), clean);
});

test("a session whose start outcome is uncertain is recovered, not skipped", async () => {
  const id = await firstSent((r) => r.request.headers?.["x-goog-upload-command"] === "start");
  const caseId = rowOf(id).programId;
  const h = await harness({ simulatorOptions: answerAt(await callOf(id), "throw") });
  const stopped = await h.controller.run();
  assert.deepEqual([stopped.reason, stopped.detail.rowId], ["outcome uncertain", id]);
  const result = await h.controller.recover();
  assert.equal(result.skipped.includes(`recovery/session/${caseId}/current`), false, JSON.stringify(result));
});

test("a generation read after an uncertain metadata patch never feeds the recovery delete", async () => {
  const id = await firstSent((r) => r.request.dialect === "gcs" && r.request.operation === "patch");
  const name = rowOf(id).request.objectName;
  const h = await harness({ simulatorOptions: answerAt(await callOf(id), "throw") });
  const stopped = await h.controller.run();
  assert.deepEqual([stopped.reason, stopped.detail.rowId], ["outcome uncertain", id]);
  const result = await h.controller.recover();
  const del = manifest.rows.find((r) => r.family === "recovery-object" && r.stage === "delete" && r.request.objectName === name);
  assert.deepEqual([result.status, result.reason, result.detail.rowId, result.detail.cause], ["stopped", "target unavailable", del.id, "reference is not deletable"]);
  assert.ok(h.simulator.objects().includes(name));
});

async function walk(directory) {
  const { readdir } = await import("node:fs/promises");
  const out = [];
  for (const name of await readdir(directory)) {
    const path = `${directory}/${name}`;
    if ((await lstat(path)).isDirectory()) out.push(...await walk(path)); else out.push(path);
  }
  return out;
}

// Every row syncs several files, so this run takes over a minute; run it with STORAGE_RULES_SLOW_TESTS=1.
test("a whole recording with the real journals leaves no bearer value anywhere in the run directory", { skip: !process.env.STORAGE_RULES_SLOW_TESTS && "set STORAGE_RULES_SLOW_TESTS=1" }, async (t) => {
  const directory = await mkdtemp("/private/tmp/storage-rules-controller-");
  t.after(() => rm(directory, { recursive: true, force: true }));
  const requestIds = counted.map((r) => r.id);
  const reservations = await createReservationJournal({ directory, runId: options.runId, sourceCommit: options.sourceCommit, manifestDigest: manifest.sha256, requestIds, preflightIds, io: { open, lstat } });
  const capture = await createCaptureJournal({ directory, runId: options.runId, sourceCommit: options.sourceCommit, manifestDigest: manifest.sha256, digestSalt: salt, requestIds, io: { open, lstat, mkdir } });
  harnessReservations = { onStarted: reservations.onStarted, onReserve: reservations.onReserve, onTerminal: reservations.onTerminal };
  try {
    const h = await harness({ capture });
    const result = await h.controller.run();
    assert.equal(result.status, "finished", JSON.stringify(result));
    await capture.close(); await reservations.close();
    const secrets = [BEARER, ...h.simulator.secrets()];
    assert.ok(secrets.length > 10);
    const files = await walk(directory);
    assert.ok(files.some((f) => f.endsWith("reservations.jsonl")) && files.some((f) => f.endsWith("captures.jsonl")) && files.filter((f) => f.includes("/blobs/")).length > 100);
    for (const file of files) {
      const text = (await (await import("node:fs/promises")).readFile(file)).toString("latin1");
      for (const secret of secrets) for (const form of [secret, encodeURIComponent(secret), Buffer.from(secret).toString("base64")]) assert.equal(text.includes(form), false, `${secret.slice(0, 12)} in ${file.slice(directory.length)}`);
      assert.equal((await lstat(file)).mode & 0o077, 0, file);
    }
    const rows = (await (await import("node:fs/promises")).readFile(`${directory}/captures.jsonl`, "utf8")).split("\n").filter(Boolean).map((line) => JSON.parse(line));
    assert.ok(rows.filter((row) => row.event === "response").length > 4000);
    assert.ok(rows.some((row) => row.event === "proof") && rows.some((row) => row.event === "facts"));
  } finally { harnessReservations = null; }
});
