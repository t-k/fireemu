import assert from "node:assert/strict";
import { lstat, mkdir, mkdtemp, open, rm } from "node:fs/promises";
import { readFileSync } from "node:fs";
import test from "node:test";
import { createCaptureJournal } from "./storage-rules/capture-journal.mjs";
import { buildCorpus } from "./storage-rules/corpus.mjs";
import { createController } from "./storage-rules/controller.mjs";
import { createDispatchGate } from "./storage-rules/dispatch-gate.mjs";
import { buildFullRequestManifest } from "./storage-rules/full-manifest.mjs";
import { createReservationJournal } from "./storage-rules/reservation-journal.mjs";
import { createResourceLedger } from "./storage-rules/resource-ledger.mjs";
import { createRunLedger } from "./storage-rules/run-ledger.mjs";
import { buildRefTables, createRuntimeRefStore } from "./storage-rules/runtime-refs.mjs";
import { buildSchedule } from "./storage-rules/schedule.mjs";
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
    writeProof: async (r) => { events.push(["proof", r.type]); }, writeNote: async (r) => { events.push(["note", r.text]); }, snapshot: () => ({ uncertain: false }),
  };
}

async function harness({ capture = memoryCapture(), simulatorOptions = {}, credentialsFresh = () => true, waits = [], delegates = {}, judge } = {}) {
  const simulator = createSimulator({ manifest, options: { invalidContent, ...simulatorOptions } });
  const targets = createTargetBuilder({ manifest, digestSalt: salt });
  const tables = buildRefTables(manifest);
  const refs = createRuntimeRefStore({ tables, runId: options.runId, digestSalt: salt, writeProof: (proof) => capture.writeProof(proof) });
  const objects = createResourceLedger({ manifest });
  const run = createRunLedger({ manifest, objects });
  const trace = [];
  const reservations = { onStarted: async () => { trace.push("started"); }, onReserve: async (r) => { trace.push(r.operationId); }, onTerminal: async (r) => { trace.push(`terminal:${r.outcome}`); } };
  const gate = createDispatchGate({ reservations: harnessReservations ?? reservations, capture, transport: simulator, targets, credentials: { headersFor: (c) => (c === "anonymous" ? {} : { authorization: `Bearer ${BEARER}` }) }, preflightIds });
  const noop = async () => {};
  const controller = createController({
    manifest, schedule: buildSchedule(manifest), gate, targets, refs, tables, objects, run, capture,
    delegates: { "preflight-cache": noop, "credential-cache": noop, "prepare-query": noop, "foreign-signup": noop, "foreign-cleanup": noop, "cleanup-query": noop, ...delegates },
    wait: async (ms) => { waits.push(ms); }, credentials: { fresh: credentialsFresh }, judgePreflight: judge ?? ((row, outcome) => outcome.verdict !== "unexpected"),
  });
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

test("a schedule step without its delegate stops the run, and the options are a closed record", async () => {
  const h = await harness({ delegates: { "prepare-query": undefined } });
  const result = await h.controller.run();
  assert.deepEqual([result.status, result.reason, result.detail.op], ["stopped", "delegate missing", "prepare-query"]);
  const mod = await import("./storage-rules/controller.mjs");
  for (const bad of [null, {}, { manifest }, { ...(await harness()).controller }]) assert.throws(() => mod.createController(bad), /invalid controller options/);
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
