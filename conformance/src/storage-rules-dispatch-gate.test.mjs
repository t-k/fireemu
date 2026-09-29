import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { buildCorpus } from "./storage-rules/corpus.mjs";
import { buildFullRequestManifest } from "./storage-rules/full-manifest.mjs";
import { createTargetBuilder } from "./storage-rules/target.mjs";

const closure = JSON.parse(readFileSync(new URL("../../spec/compatibility/closure/STORAGE-RULES.json", import.meta.url)));
const options = { runId: "local-run", sourceCommit: "a".repeat(40), queryProjectNumber: "1".repeat(12), idpProjectNumber: "2".repeat(12), queryApiKeyId: "00000000-0000-4000-8000-000000000001", idpApiKeyId: "00000000-0000-4000-8000-000000000002" };
const binding = { bucket: "synthetic-rules-bucket", prefix: "STORAGE-RULES/local-run/", uidA: "storage-rules-local-run-user-a", uidB: "storage-rules-local-run-user-b" };
const manifest = buildFullRequestManifest(buildCorpus(binding), closure, options);
const salt = "6".repeat(64);
const BEARER = "CANARY-BEARER-0123456789abcdef";
const VALUES = { generation: "1700000000000001", metageneration: "1", "update-time": "2026-09-29T10:00:00Z", "ruleset-name": "projects/fireemu-oracle-query/rulesets/abc", "page-token": "next" };
const typeOf = (reference) => reference.type ?? { "firestore-update-time": "update-time", "gcs-object-generation": "generation" }[reference.kind];
const resolver = (reference) => VALUES[typeOf(reference)];
const row = (id) => manifest.rows.find((r) => r.id === id) ?? assert.fail(id);
const ok = { status: 200, rawHeaders: ["Content-Type", "application/json"], bytes: Buffer.from("{}"), startedAtMs: 1, finishedAtMs: 2 };
// The gate admits through the preflight rows the target builder can prepare; the cache rows are carried by their own module.
const preflightIds = manifest.preflightIds.filter((id) => !manifest.rows.find((r) => r.id === id).family.startsWith("credential"));
const normalMeta = { phase: "normal", mutationKey: null, accept: null };
const recoveryMeta = { phase: "recovery", mutationKey: null, accept: null };
const preflightMeta = { phase: "preflight", mutationKey: null, accept: () => true };
const READ = "management/control-0/baseline-metadata";
const READ2 = "management/control-0/baseline-media";
const WRITE = "management/control-0/seed";

async function harness(delta = {}) {
  const { createDispatchGate } = await import("./storage-rules/dispatch-gate.mjs").catch((error) => { if (error.code === "ERR_MODULE_NOT_FOUND") return {}; throw error; });
  assert.equal(typeof createDispatchGate, "function");
  const trace = [];
  const state = { uncertain: false };
  const targets = createTargetBuilder({ manifest, digestSalt: salt });
  const reservations = { onStarted: async () => { trace.push(["started"]); }, onReserve: async (r) => { trace.push(["reserved", r.operationId, r.phase]); }, onTerminal: async (r) => { trace.push(["terminal", r.outcome]); } };
  const capture = {
    writeIntent: async (r) => { trace.push(["intent", r.operationId, r.phase, r.targetSha256, r.redactedTarget, r.mutationKey]); },
    writeResponse: async (r) => { trace.push(["response", r.operationId, r.attempt, r.response.status]); },
    writeNote: async (r) => { trace.push(["note", r.operationId, r.text]); },
    writeDelegatedTarget: async () => {},
    snapshot: () => Object.freeze({ ...state }),
  };
  const transport = { validate() {}, send: async (spec) => { trace.push(["transport", spec.method, spec.url, JSON.stringify(spec.headers)]); return ok; } };
  const credentials = { headersFor: (credential) => (credential === "anonymous" ? {} : { authorization: `Bearer ${BEARER}` }) };
  const gate = createDispatchGate({ reservations: { ...reservations, ...delta.reservations }, capture: { ...capture, ...delta.capture }, transport: { ...transport, ...delta.transport }, targets: { ...targets, ...delta.targets }, credentials: { ...credentials, ...delta.credentials }, preflightIds, admission: (() => { const a = { check: async () => { trace.push(["admission"]); return { admitted: true }; }, ...delta.admission }; a.begin ??= a.check; return a; })() });
  const prepare = (id) => targets.prepare(row(id), resolver);
  const admit = async () => {
    await gate.start({ runId: options.runId });
    for (const id of preflightIds) await gate.send(prepare(id), preflightMeta);
    gate.admit();
  };
  return { gate, trace, state, targets, prepare, admit };
}
const events = (trace, name) => trace.filter((entry) => entry[0] === name);

test("a request leaves only after its intent and its reservation are durable, and its response is captured after", async () => {
  const h = await harness();
  await h.admit();
  h.trace.length = 0;
  const prepared = h.prepare(READ);
  const { raw, attempt } = await h.gate.send(prepared, normalMeta);
  assert.deepEqual(h.trace.map((entry) => entry[0]), ["admission", "intent", "reserved", "transport", "response"]);
  assert.equal(raw.status, 200);
  assert.equal(attempt, preflightIds.length + 1);
  assert.deepEqual(h.trace[1].slice(1, 3), [READ, "normal"]);
  assert.equal(h.trace[1][3], prepared.targetSha256);
  assert.equal(h.trace[1][4], prepared.redacted);
  assert.equal(h.trace[4][2], attempt);
  assert.equal(Object.hasOwn(raw, "startedAtMs"), false);
});

test("credential headers reach the transport and nothing else", async () => {
  const h = await harness();
  await h.admit();
  h.trace.length = 0;
  await h.gate.send(h.prepare(READ), normalMeta);
  const sent = events(h.trace, "transport")[0];
  assert.ok(sent[3].includes(BEARER));
  assert.equal(JSON.stringify(h.trace.filter((entry) => entry[0] !== "transport")).includes(BEARER), false);
  h.trace.length = 0;
  const anonymous = h.prepare("settle/v1/1/0");
  await h.gate.send(anonymous, normalMeta);
  assert.equal(JSON.parse(events(h.trace, "transport")[0][3]).authorization, undefined);
});

test("the credential provider is told which project the request is billed to", async () => {
  const seen = [];
  const h = await harness({ credentials: { headersFor: (credential, context) => { seen.push([credential, context.project, Object.isFrozen(context)]); return credential === "anonymous" ? {} : { authorization: "Bearer t", "x-goog-user-project": context.project }; } } });
  await h.admit();
  h.trace.length = 0;
  const prepared = h.prepare(READ);
  await h.gate.send(prepared, normalMeta);
  const call = h.trace.find((entry) => entry[0] === "transport");
  assert.equal(JSON.parse(call[3])["x-goog-user-project"], prepared.project);
  assert.ok(seen.some(([credential, project, frozen]) => credential === prepared.credential && project === prepared.project && frozen));
});

test("the quota project header always equals the target's project, whatever the provider returns", async () => {
  for (const project of ["fireemu-oracle-idp", "another-project", "", "fireemu-oracle-query\n"]) {
    let wrong = false;
    const h = await harness({ credentials: { headersFor: (credential, context) => ({ authorization: "Bearer t", "x-goog-user-project": wrong ? project : context.project }) } });
    await h.admit();
    wrong = true;
    const prepared = h.prepare(READ);
    h.trace.length = 0;
    await assert.rejects(h.gate.send(prepared, normalMeta), /invalid credential headers/);
    assert.equal(h.trace.some((entry) => entry[0] === "transport"), false);
  }
  const ok = await harness({ credentials: { headersFor: (credential, context) => ({ authorization: "Bearer t", "x-goog-user-project": context.project }) } });
  await ok.admit();
  await ok.gate.send(ok.prepare(READ), normalMeta);
});

test("a target the transport refuses is not sent and costs nothing: no admission, intent, reservation or counter movement", async () => {
  let refuse = false;
  const h = await harness({ transport: { validate: () => { if (refuse) throw new Error("invalid HTTP transport input"); } } });
  await h.admit();
  const before = h.gate.snapshot();
  refuse = true;
  h.trace.length = 0;
  await assert.rejects(h.gate.send(h.prepare(READ), normalMeta), /request not sent/);
  assert.deepEqual(h.trace, []);
  const after = h.gate.snapshot();
  assert.deepEqual([after.mode, after.requests, after.normal, after.recovery, after.poisoned], [before.mode, before.requests, before.normal, before.recovery, false]);
  // The gate is still usable for a target the transport accepts.
  refuse = false;
  await h.gate.send(h.prepare(READ), normalMeta);
});

test("an input refusal by the transport itself is reported as not sent, never as an uncertain outcome", async () => {
  const notSent = Object.assign(new Error("invalid HTTP transport input"), { notSent: true });
  // Preflight IDs are sent by admit(), so the refusal surfaces there: it must not be the uncertain-outcome error.
  await assert.rejects(harness({ transport: { send: async () => { throw notSent; } } }).then((x) => x.admit()), (error) => error === notSent);
  await assert.rejects(harness({ transport: { send: async () => { throw new Error("connection reset"); } } }).then((x) => x.admit()), /request outcome uncertain/);
});

test("only a strict notSent marker turns a transport failure into not sent", async () => {
  for (const marker of [1, "yes", {}, "true"]) {
    const error = Object.assign(new Error("odd failure"), { notSent: marker });
    await assert.rejects(harness({ transport: { send: async () => { throw error; } } }).then((x) => x.admit()), /request outcome uncertain/, JSON.stringify(marker));
  }
});

test("credential headers are closed to the two allowed names and printable values, and a refusal sends nothing", async () => {
  for (const headers of [{ cookie: "a=b" }, { authorization: "x\r\nX: y" }, { authorization: 7 }, { authorization: "" }, { "x-other": "1" }, null, []]) {
    const h = await harness({ credentials: { headersFor: () => headers } });
    await h.admit().catch(() => {});
    const sentBefore = events(h.trace, "transport").length;
    await assert.rejects(h.gate.send(h.prepare(READ), normalMeta), /./);
    assert.equal(events(h.trace, "transport").length, sentBefore);
  }
});

test("nothing is sent when the reservation cannot be made durable", async () => {
  const h = await harness({ reservations: { onReserve: async (r) => { if (r.phase === "normal") throw new Error("disk full"); } } });
  await h.admit();
  h.trace.length = 0;
  await assert.rejects(h.gate.send(h.prepare(READ), normalMeta), /disk full/);
  assert.deepEqual(h.trace.map((entry) => entry[0]), ["admission", "intent", "note"]);
  assert.equal(h.gate.snapshot().mode, "journal-uncertain");
});

test("the run's start goes through the admission's begin, and every later request through its check", async () => {
  const calls = [];
  const h = await harness({ admission: { begin: async () => { calls.push("begin"); return { admitted: true }; }, check: async () => { calls.push("check"); return { admitted: true }; } } });
  await h.gate.start({ runId: options.runId });
  assert.deepEqual(calls, ["begin"]);
  await h.gate.send(h.prepare(manifest.preflightIds[0]), preflightMeta);
  assert.deepEqual(calls, ["begin", "check"]);
  // A refused begin marks the gate as refused and starts nothing.
  const refused = await harness({ admission: { begin: async () => { throw new Error("admission refused: recording budget exhausted"); }, check: async () => ({ admitted: true }) } });
  await assert.rejects(refused.gate.start({ runId: options.runId }), /recording budget exhausted/);
  assert.equal(refused.gate.snapshot().admissionRefused, true);
  assert.equal(refused.gate.snapshot().mode, "not-started");
  const silent = await harness({ admission: { begin: async () => undefined, check: async () => ({ admitted: true }) } });
  await assert.rejects(silent.gate.start({ runId: options.runId }), /admission refused/);
  assert.equal(silent.gate.snapshot().admissionRefused, true);
});

test("at send time only an explicit admitted answer lets a request go", async () => {
  for (const answer of [null, {}, { admitted: false }, { admitted: "yes" }, { admitted: 1 }, "admitted", 1]) {
    let deny = false;
    const h = await harness({ admission: { check: async () => (deny ? answer : { admitted: true }) } });
    await h.admit();
    deny = true;
    h.trace.length = 0;
    await assert.rejects(h.gate.send(h.prepare(READ), normalMeta), /admission refused/, JSON.stringify(answer));
    assert.equal(h.gate.snapshot().admissionRefused, true);
    assert.deepEqual(h.trace.filter((entry) => ["intent", "reserved", "transport"].includes(entry[0])), []);
  }
});

test("a refused admission stops a request before its intent, its reservation and its send", async () => {
  let refuse = false;
  const h = await harness({ admission: { check: async () => { if (refuse) throw new Error("admission refused: revoked"); return { admitted: true }; } } });
  await h.admit();
  refuse = true;
  h.trace.length = 0;
  await assert.rejects(h.gate.send(h.prepare(READ), normalMeta), /admission refused/);
  assert.deepEqual(h.trace, []);
});

test("an admission that does not answer admitted stops the request and the start", async () => {
  for (const answer of [undefined, null, {}, { admitted: false }, { admitted: "yes" }]) {
    const h = await harness({ admission: { check: async () => answer } });
    await assert.rejects(h.gate.start({ runId: options.runId }), /admission refused/);
    assert.equal(h.gate.snapshot().mode, "not-started");
    assert.deepEqual(h.trace.filter((entry) => ["intent", "reserved", "transport"].includes(entry[0])), []);
  }
  let calls = 0;
  const h = await harness({ admission: { check: async () => (++calls > 1 + preflightIds.length ? undefined : { admitted: true }) } });
  await h.admit();
  h.trace.length = 0;
  await assert.rejects(h.gate.send(h.prepare(READ), normalMeta), /admission refused/);
  assert.deepEqual(h.trace, []);
});

test("an intent failure stops before any reservation or request", async () => {
  let fail = false;
  const h = await harness({ capture: { writeIntent: async (r) => { if (fail) throw new Error("capture uncertain"); } } });
  await h.admit();
  fail = true;
  h.trace.length = 0;
  await assert.rejects(h.gate.send(h.prepare(READ), normalMeta), /capture uncertain/);
  assert.deepEqual(h.trace, [["admission"]]);
});

test("an uncertain capture journal refuses the request before its intent", async () => {
  const h = await harness();
  await h.admit();
  h.state.uncertain = true;
  h.trace.length = 0;
  await assert.rejects(h.gate.send(h.prepare(READ), normalMeta), /capture journal is uncertain/);
  assert.deepEqual(h.trace, []);
});

test("a target changed after its intent is refused at the last step, so nothing is sent", async () => {
  let hook = async () => {};
  const h = await harness({ capture: { writeIntent: async (r) => { await hook(r); } } });
  await h.admit();
  const victim = h.prepare(WRITE);
  hook = async () => { victim.spec.body[0] ^= 1; };
  h.trace.length = 0;
  await assert.rejects(h.gate.send(victim, normalMeta), /target changed after its intent/);
  assert.equal(events(h.trace, "transport").length, 0);
  assert.equal(events(h.trace, "reserved").length, 1);
});

test("a forged or altered prepared target is refused before anything is written", async () => {
  const h = await harness();
  await h.admit();
  h.trace.length = 0;
  const genuine = h.prepare(READ);
  for (const forged of [null, {}, { ...genuine }, Object.freeze({ rowId: READ, credential: "admin", targetSha256: genuine.targetSha256, redacted: genuine.redacted })]) {
    await assert.rejects(h.gate.send(forged, normalMeta), /invalid dispatch request/);
  }
  assert.deepEqual(h.trace, []);
});

test("the request must belong to the counter's current mode", async () => {
  const h = await harness();
  await h.admit();
  h.trace.length = 0;
  await assert.rejects(h.gate.send(h.prepare("recovery/object-0/metadata"), normalMeta), /request phase does not match the counter/);
  await assert.rejects(h.gate.send(h.prepare(READ), recoveryMeta), /request phase does not match the counter/);
  await assert.rejects(h.gate.send(h.prepare(preflightIds[0]), preflightMeta), /request phase does not match the counter/);
  await assert.rejects(h.gate.send(h.prepare("recovery/object-0/metadata"), recoveryMeta), /request phase does not match the counter/);
  assert.deepEqual(h.trace, []);
  h.gate.enterRecovery();
  await assert.rejects(h.gate.send(h.prepare(READ), normalMeta), /request phase does not match the counter/);
  await h.gate.send(h.prepare("recovery/object-0/metadata"), recoveryMeta);
  assert.equal(events(h.trace, "transport").length, 1);
});

test("a preflight ID is sent only as a preflight and a preflight only for a preflight ID, refused before anything is written", async () => {
  const h = await harness();
  await h.gate.start({ runId: options.runId });
  h.trace.length = 0;
  await assert.rejects(h.gate.send(h.prepare(READ), preflightMeta), /request phase does not match the counter/);
  assert.deepEqual(h.trace, []);
  assert.equal(h.gate.snapshot().mode, "preflight");
  for (const id of preflightIds) await h.gate.send(h.prepare(id), preflightMeta);
  h.gate.admit();
  h.trace.length = 0;
  await assert.rejects(h.gate.send(h.prepare(preflightIds[0]), normalMeta), /request phase does not match the counter/);
  assert.deepEqual(h.trace, []);
  assert.equal(h.gate.snapshot().mode, "normal");
});

test("a request whose reservation lands in another phase than its intent is refused at the last step, so nothing is sent", async () => {
  let hook = async () => {};
  const h = await harness({ capture: { writeIntent: async (r) => { h.trace.push(["intent", r.operationId, r.phase]); await hook(); } } });
  await h.admit();
  // The counter moves to recovery while the normal request's intent is written: its reservation is then a recovery one.
  hook = async () => { hook = async () => {}; h.gate.enterRecovery(); };
  h.trace.length = 0;
  await assert.rejects(h.gate.send(h.prepare(READ), normalMeta), /dispatch is not armed/);
  assert.deepEqual(events(h.trace, "intent").map((entry) => entry.slice(1)), [[READ, "normal"]]);
  assert.deepEqual(events(h.trace, "reserved").map((entry) => entry.slice(1)), [[READ, "recovery"]]);
  assert.equal(events(h.trace, "transport").length, 0);
  assert.match(events(h.trace, "note")[0][2], /^request not sent: dispatch is not armed/);
});

test("a transport failure leaves the outcome uncertain, notes it, moves to recovery and never repeats the request", async () => {
  let calls = 0; let armedFailure = false;
  const h = await harness({ transport: { send: async () => { calls++; if (armedFailure) { armedFailure = false; throw new Error(`socket closed for token=${BEARER}`); } return ok; } } });
  await h.admit();
  h.trace.length = 0; calls = 0; armedFailure = true;
  await assert.rejects(h.gate.send(h.prepare(WRITE), { phase: "normal", mutationKey: "object|x|create|management/control-0/seed", accept: null }), /request outcome uncertain/);
  const note = events(h.trace, "note")[0];
  assert.match(note[2], /outcome unknown/);
  assert.equal(h.gate.snapshot().mode, "recovery");
  assert.equal(events(h.trace, "response").length, 0);
  assert.equal(calls, 1);
  await assert.rejects(h.gate.send(h.prepare(WRITE), normalMeta), /request phase does not match the counter/);
  assert.equal(calls, 1);
  assert.equal(events(h.trace, "intent")[0][5], "object|x|create|management/control-0/seed");
});

test("a capture failure after the request poisons the gate for every later request", async () => {
  let fail = false;
  const h = await harness({ capture: { writeResponse: async () => { if (fail) throw new Error("disk full"); } } });
  await h.admit();
  fail = true;
  await assert.rejects(h.gate.send(h.prepare(READ), normalMeta), /capture failed after send/);
  assert.equal(h.gate.snapshot().poisoned, true);
  h.trace.length = 0;
  fail = false;
  await assert.rejects(h.gate.send(h.prepare(READ2), normalMeta), /dispatch gate is poisoned/);
  h.gate.enterRecovery();
  await assert.rejects(h.gate.send(h.prepare("recovery/object-0/metadata"), recoveryMeta), /dispatch gate is poisoned/);
  assert.deepEqual(h.trace, []);
});

test("two requests never overlap", async () => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  let hold = false;
  const h = await harness({ transport: { send: async () => { if (hold) await gate; return ok; } } });
  await h.admit();
  hold = true;
  const first = h.gate.send(h.prepare(READ), normalMeta);
  await assert.rejects(h.gate.send(h.prepare(READ2), normalMeta), /concurrent dispatch is forbidden/);
  release();
  await first;
  assert.equal(h.gate.snapshot().busy, false);
});

test("a preflight the caller refuses keeps its captured response, closes the counter and does not poison the gate", async () => {
  const h = await harness();
  await h.gate.start({ runId: options.runId });
  await assert.rejects(h.gate.send(h.prepare(preflightIds[0]), { phase: "preflight", mutationKey: null, accept: () => false }), /preflight failed/);
  assert.deepEqual(events(h.trace, "response").map((entry) => entry[1]), [preflightIds[0]]);
  assert.deepEqual(events(h.trace, "terminal"), [["terminal", "preflight-failed"]]);
  assert.equal(h.gate.snapshot().poisoned, false);
  assert.equal(events(h.trace, "note").length, 0);
});

test("the request description is a closed record", async () => {
  const h = await harness();
  await h.admit();
  const prepared = h.prepare(READ);
  for (const meta of [null, {}, { phase: "normal", mutationKey: null }, { ...normalMeta, extra: 1 }, { phase: "other", mutationKey: null, accept: null }, { phase: "normal", mutationKey: 7, accept: null }, { phase: "normal", mutationKey: null, accept: () => true }, { phase: "preflight", mutationKey: null, accept: null }]) {
    await assert.rejects(h.gate.send(prepared, meta), /invalid dispatch request/);
  }
});

test("gate options are a closed record of the required parts", async () => {
  const { createDispatchGate } = await import("./storage-rules/dispatch-gate.mjs");
  const targets = createTargetBuilder({ manifest, digestSalt: salt });
  const good = { reservations: { onStarted() {}, onReserve() {}, onTerminal() {} }, capture: { writeIntent() {}, writeResponse() {}, writeNote() {}, writeDelegatedTarget() {}, snapshot() {} }, transport: { validate() {}, send() {} }, targets, credentials: { headersFor() {} }, preflightIds, admission: { check() {}, begin() {} } };
  assert.doesNotThrow(() => createDispatchGate(good));
  for (const bad of [null, {}, { ...good, extra: 1 }, { ...good, transport: {} }, { ...good, capture: { ...good.capture, writeNote: undefined } }, { ...good, targets: { prepare() {} } }, { ...good, credentials: {} }, { ...good, admission: undefined }, { ...good, admission: {} }, { ...good, admission: { check() {} } }, { ...good, admission: { begin() {} } }, { ...good, transport: { send() {} } }, { ...good, transport: { validate() {} } }, { ...good, reservations: { ...good.reservations, onTerminal: 1 } }]) {
    assert.throws(() => createDispatchGate(bad), /invalid dispatch gate options/);
  }
  // Every single required function matters on its own.
  for (const part of ["reservations", "capture", "transport", "credentials", "admission"]) {
    for (const name of Object.keys(good[part])) assert.throws(() => createDispatchGate({ ...good, [part]: { ...good[part], [name]: undefined } }), /invalid dispatch gate options/, `${part}.${name}`);
  }
});

test("a finished counter refuses everything", async () => {
  const h = await harness();
  await h.admit();
  await h.gate.finish("finished");
  h.trace.length = 0;
  await assert.rejects(h.gate.send(h.prepare(READ), normalMeta), /./);
  assert.equal(events(h.trace, "transport").length, 0);
});
