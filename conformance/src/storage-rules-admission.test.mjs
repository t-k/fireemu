import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { buildCorpus } from "./storage-rules/corpus.mjs";
import { createController } from "./storage-rules/controller.mjs";
import { createDispatchGate } from "./storage-rules/dispatch-gate.mjs";
import { buildFullRequestManifest } from "./storage-rules/full-manifest.mjs";
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
const salt = "9".repeat(64);
const invalidContent = manifest.rows.filter((r) => r.family === "compile" && r.stage === "test").at(-1).request.body.json.source.files[0].content;
const delegated = (row) => ["auth", "credential-cache"].includes(row.family);
const preflightIds = manifest.preflightIds.filter((id) => !id.startsWith("preflight/auth/"));

const packet = {
  taskId: "STORAGE-RULES", packetName: "stage3-v1", packetSha256: "a".repeat(64), sourceCommit: "b".repeat(40), runnerSha256: "c".repeat(64), manifestSha256: "d".repeat(64), fixtureSchemaSha256: "e".repeat(64),
  projects: ["fireemu-oracle-idp", "fireemu-oracle-query"], maxRequests: 12344, reserveUsd: 2,
};
const pins = ["packetSha256", "sourceCommit", "runnerSha256", "manifestSha256", "fixtureSchemaSha256"];
const envelopeId = "STORAGE-RULES-stage3-v1-001";
const review = { verdict: "APPROVE", must: [], should: [], ...Object.fromEntries(pins.map((key) => [key, packet[key]])), envelopeId, withinEnvelope: true };
const coordinator = "Claude（委任。枠の内の承認し直し）";
const delegatedActor = "Claude（委任。オーナーの裁量の委任 2026-09-28）";
const rows = {
  delegation365: "- 2026-09-28 | 調整役への委任（本番の送信） | decision=APPROVE; local fixture | オーナー（ローカル試験） | private.md",
  delegation395: "- 2026-09-28 | 調整役への委任（枠の承認） | decision=APPROVE; local fixture | オーナー（ローカル試験） | private.md",
  envelope: `- 2026-09-28 | STORAGE-RULES stage3-v1 envelope | envelopeId=${envelopeId}; project=${packet.projects.join(",")}; maxRequests=12344; reserveUsd=2; writes=owned fixtures; iamConfig=Storage release only; retries=none; 根拠=2026-09-28 調整役への委任（本番の送信） | ${delegatedActor} | private.md`,
  decision: `- 2026-09-28 | STORAGE-RULES stage3-v1 | decision=APPROVE; ${pins.map((key) => `${key}=${packet[key]}`).join("; ")}; envelopeId=${envelopeId} | ${coordinator} | private.md`,
};
const goodLedger = [rows.delegation365, rows.delegation395, rows.envelope, rows.decision].join("\n");
const revoked = (topic) => `- 2026-09-29 | ${topic} | decision=REVOKED; 根拠=local fixture | オーナー（ローカル試験） | private.md`;

const load = async () => (await import("./storage-rules/admission.mjs").catch(() => ({}))).createAdmission ?? assert.fail("createAdmission missing");
const admissionOptions = (extra = {}) => {
  let text = goodLedger;
  const state = { text: () => text, set: (value) => { text = value; }, lockCalls: 0, lockResult: true };
  return { state, options: { readLedger: async () => state.text(), packet: structuredClone(packet), review: structuredClone(review), locks: { verify: async () => { state.lockCalls++; return state.lockResult; } }, ...extra } };
};

test("a live owner-ledger approval, version and lock admit the run", async () => {
  const createAdmission = await load();
  const { options: opts, state } = admissionOptions();
  const admission = createAdmission(opts);
  const seen = await admission.check();
  assert.equal(seen.admitted, true);
  assert.equal(seen.envelopeId, envelopeId);
  assert.equal(state.lockCalls, 1);
  assert.equal(admission.snapshot().refused, false);
});

test("each missing part of the approval refuses admission", async () => {
  const createAdmission = await load();
  const cases = {
    "no decision row": [rows.delegation365, rows.delegation395, rows.envelope].join("\n"),
    "no envelope row": [rows.delegation365, rows.delegation395, rows.decision].join("\n"),
    "no 365 delegation": [rows.delegation395, rows.envelope, rows.decision].join("\n"),
    "no 395 delegation": [rows.delegation365, rows.envelope, rows.decision].join("\n"),
    "another version only": goodLedger.replaceAll("stage3-v1", "stage3-v2"),
    "wrong pin": goodLedger.replace(`packetSha256=${packet.packetSha256}`, `packetSha256=${"f".repeat(64)}`),
    "empty ledger": "",
  };
  for (const [label, text] of Object.entries(cases)) {
    const { options: opts, state } = admissionOptions();
    state.set(text);
    await assert.rejects(() => createAdmission(opts).check(), /admission refused/, label);
  }
});

test("a revocation in any spelling refuses admission", async () => {
  const createAdmission = await load();
  const spellings = [
    revoked("STORAGE-RULES stage3-v1"), revoked("storage-rules stage3-v1").replace("REVOKED", "revoked"), revoked("STORAGE-RULES（読み取り）"), revoked("ＳＴＯＲＡＧＥ－ＲＵＬＥＳ"),
    `- 2026-09-29 | STORAGE-RULES | revoked; packetSha256=${packet.packetSha256.toUpperCase()} | オーナー | private.md`,
    `- 2026-09-29 | 調整役への委任（本番の送信） | decision=REVOKED | オーナー（ローカル試験） | private.md`,
    `- 2026-09-29 | 調整役への委任（枠の承認） | revoked | オーナー（ローカル試験） | private.md`,
    `- 2026-09-29 | ${"x"} | revoked ${packet.sourceCommit.slice(0, 8)} | オーナー | private.md`,
    `- 2026-09-29 | x | revoked ${envelopeId} | オーナー | private.md`,
  ];
  for (const line of spellings) {
    const { options: opts, state } = admissionOptions();
    state.set(`${goodLedger}\n${line}`);
    await assert.rejects(() => createAdmission(opts).check(), /admission refused/, line);
  }
  // Another version's revocation does not stop this one.
  const { options: opts, state } = admissionOptions();
  state.set(`${goodLedger}\n${revoked("STORAGE-RULES stage3-v0")}`);
  assert.equal((await createAdmission(opts).check()).admitted, true);
});

test("a lock that is not proven held refuses admission", async () => {
  const createAdmission = await load();
  for (const result of [false, undefined, null, 1, "true", {}]) {
    const { options: opts, state } = admissionOptions();
    state.lockResult = result;
    await assert.rejects(() => createAdmission(opts).check(), /admission refused/, String(result));
  }
  const thrown = admissionOptions({ locks: { verify: async () => { throw new Error("ownership changed"); } } });
  await assert.rejects(() => createAdmission(thrown.options).check(), /admission refused/);
});

test("an unreadable ledger refuses admission", async () => {
  const createAdmission = await load();
  for (const readLedger of [async () => { throw new Error("EIO"); }, async () => undefined, async () => 42, async () => "a\0b"]) {
    const { options: opts } = admissionOptions({ readLedger });
    await assert.rejects(() => createAdmission(opts).check(), /admission refused/);
  }
  // A synchronous reader is accepted too.
  assert.equal((await createAdmission(admissionOptions({ readLedger: () => goodLedger }).options).check()).admitted, true);
});

test("a refusal is permanent even when the ledger looks valid again", async () => {
  const createAdmission = await load();
  const { options: opts, state } = admissionOptions();
  const admission = createAdmission(opts);
  await admission.check();
  state.set(`${goodLedger}\n${revoked("STORAGE-RULES stage3-v1")}`);
  await assert.rejects(() => admission.check(), /admission refused/);
  assert.equal(admission.snapshot().refused, true);
  state.set(goodLedger);
  await assert.rejects(() => admission.check(), /admission refused/);
  assert.equal(state.lockCalls, 1);
});

test("the packet and review are copied when the admission is created", async () => {
  const createAdmission = await load();
  const { options: opts } = admissionOptions();
  const admission = createAdmission(opts);
  opts.packet.maxRequests = 1;
  opts.review.verdict = "REJECT";
  assert.equal((await admission.check()).admitted, true);
});

test("admission options are closed", async () => {
  const createAdmission = await load();
  const { options: good } = admissionOptions();
  assert.doesNotThrow(() => createAdmission(good));
  for (const bad of [undefined, null, {}, { ...good, extra: 1 }, { ...good, readLedger: 1 }, { ...good, locks: {} }, { ...good, locks: undefined }, { ...good, packet: null }, { ...good, review: null }]) {
    assert.throws(() => createAdmission(bad), /invalid admission options/);
  }
});

function memoryCapture() {
  return { writeIntent: async () => {}, writeResponse: async () => {}, writeFacts: async () => {}, writeProof: async () => {}, writeNote: async () => {}, snapshot: () => ({ uncertain: false }) };
}

async function harness(admissionOverrides = {}) {
  const capture = memoryCapture();
  const simulator = createSimulator({ manifest, options: { invalidContent } });
  const transportCalls = { count: 0 };
  const hooks = { after: async () => {} };
  const transport = { send: async (request) => { transportCalls.count++; const answer = await simulator.send(request); await hooks.after(request); return answer; } };
  const targets = createTargetBuilder({ manifest, digestSalt: salt });
  const tables = buildRefTables(manifest);
  const refs = createRuntimeRefStore({ tables, runId: options.runId, digestSalt: salt, writeProof: (proof) => capture.writeProof(proof) });
  const objects = createResourceLedger({ manifest });
  const run = createRunLedger({ manifest, objects });
  const created = admissionOptions(admissionOverrides);
  const createAdmission = await load();
  const admission = createAdmission(created.options);
  const started = { count: 0 };
  const reservations = { onStarted: async () => { started.count++; }, onReserve: async () => {}, onTerminal: async () => {} };
  const gate = createDispatchGate({ reservations, capture, transport, targets, credentials: { headersFor: (c) => (c === "anonymous" ? {} : { authorization: "Bearer SIM" }) }, preflightIds, admission });
  const noop = async () => {};
  const controller = createController({
    manifest, schedule: buildSchedule(manifest), gate, targets, refs, tables, objects, run, capture,
    delegates: { "preflight-cache": noop, "credential-cache": noop, "prepare-query": noop, "foreign-signup": noop, "foreign-cleanup": noop, "cleanup-query": noop },
    wait: async () => {}, credentials: { fresh: () => true }, judgePreflight: (row, outcome) => outcome.verdict !== "unexpected",
  });
  return { controller, gate, admission, transportCalls, started, hooks, state: created.state, simulator };
}

test("a missing approval stops the run before the first request", async () => {
  const h = await harness();
  h.state.set("");
  const result = await h.controller.run();
  assert.equal(result.status, "stopped");
  assert.equal(result.reason, "admission refused");
  assert.equal(result.needsRecovery, false);
  assert.equal(h.transportCalls.count, 0);
  assert.equal(h.started.count, 0);
  assert.equal(h.gate.snapshot().mode, "not-started");
});

test("a revoked approval stops the run before the first request", async () => {
  const h = await harness();
  h.state.set(`${goodLedger}\n${revoked("STORAGE-RULES")}`);
  const result = await h.controller.run();
  assert.equal(result.reason, "admission refused");
  assert.equal(h.transportCalls.count, 0);
});

test("a lock that is not held stops the run before the first request", async () => {
  const h = await harness();
  h.state.lockResult = false;
  const result = await h.controller.run();
  assert.equal(result.reason, "admission refused");
  assert.equal(h.transportCalls.count, 0);
});

test("a revocation in the middle of a run stops it before the next mutation", async () => {
  const h = await harness();
  let mutations = 0;
  let revokedAt = null;
  // Revoke once the run has created its first object; no mutating request may follow.
  h.hooks.after = async (request) => {
    if (revokedAt !== null) { if (!["GET", "HEAD"].includes(request.method)) mutations++; return; }
    if (h.simulator.state().objects > 0) { h.state.set(`${goodLedger}\n${revoked("STORAGE-RULES stage3-v1")}`); revokedAt = h.transportCalls.count; }
  };
  const result = await h.controller.run();
  assert.equal(result.status, "stopped");
  assert.equal(result.reason, "admission refused");
  assert.equal(mutations, 0);
  assert.equal(h.transportCalls.count, revokedAt);
  assert.equal(result.needsRecovery, true);
});

test("a revocation in the middle of a run stops the very next request, a read included", async () => {
  const h = await harness();
  let requests = 0;
  h.hooks.after = async () => {
    requests++;
    if (requests === 20) h.state.set(`${goodLedger}\n${revoked("STORAGE-RULES stage3-v1")}`);
  };
  const result = await h.controller.run();
  assert.equal(result.reason, "admission refused");
  assert.equal(requests, 20);
  assert.equal(h.transportCalls.count, 20);
});

test("a refused admission leaves the gate closed to every later request", async () => {
  const h = await harness();
  h.state.set("");
  await h.controller.run();
  await assert.rejects(() => h.gate.start({ runId: options.runId }), /admission refused/);
  assert.equal(h.transportCalls.count, 0);
});

test("the gate requires an admission", async () => {
  const gateOptions = (admission) => ({ reservations: { onStarted() {}, onReserve() {}, onTerminal() {} }, capture: memoryCapture(), transport: { send() {} }, targets: { verify() {}, prepare() {} }, credentials: { headersFor() {} }, preflightIds, ...(admission === undefined ? {} : { admission }) });
  assert.throws(() => createDispatchGate(gateOptions()), /invalid dispatch gate options/);
  assert.throws(() => createDispatchGate(gateOptions({})), /invalid dispatch gate options/);
  assert.doesNotThrow(() => createDispatchGate(gateOptions({ check: async () => ({ admitted: true }) })));
});
