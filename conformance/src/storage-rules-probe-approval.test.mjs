import assert from "node:assert/strict";
import test from "node:test";
import { PROBE_APPROVAL_LIMITS, PROBE_RECORDINGS_PER_APPROVAL, validateProbeApproval } from "./storage-rules-probe/approval.mjs";
import { createProbeAdmission } from "./storage-rules-probe/admission.mjs";
import { PIN_KEYS } from "./storage-rules-probe-support.mjs";

const pins = { packetSha256: "1".repeat(64), sourceCommit: "a".repeat(40), runnerSha256: "2".repeat(64), manifestSha256: "3".repeat(64), fixtureSchemaSha256: "4".repeat(64) };
const packetOf = (delta = {}) => ({ taskId: "STORAGE-RULES", packetName: "stage2d-probe-v1", ...pins, projects: ["fireemu-oracle-query"], maxRequests: 8, reserveUsd: 0.01, ...delta });
const reviewOf = (packet, delta = {}) => ({ verdict: "APPROVE", must: [], should: [], ...Object.fromEntries(PIN_KEYS.map((key) => [key, packet[key]])), envelopeId: "E-1", withinEnvelope: true, ...delta });
const DELEGATIONS = ["- 2026-09-28 | 調整役への委任（本番の送信） | decision=APPROVE; x | オーナー（ローカル試験） | p.md", "- 2026-09-28 | 調整役への委任（枠の承認） | decision=APPROVE; x | オーナー（ローカル試験） | p.md"];
const ledgerOf = (packet, { max = packet.maxRequests, reserve = 0.01, project = "fireemu-oracle-query", decision = "APPROVE" } = {}) => [
  ...DELEGATIONS,
  `- 2026-09-30 | STORAGE-RULES ${packet.packetName} envelope | envelopeId=E-1; project=${project}; maxRequests=${max}; reserveUsd=${reserve}; writes=none; iamConfig=none; retries=none; 根拠=2026-09-28 調整役への委任（本番の送信） | Claude（委任。オーナーの裁量の委任 2026-09-28） | p.md`,
  `- 2026-09-30 | STORAGE-RULES ${packet.packetName} | decision=${decision}; ${PIN_KEYS.map((key) => `${key}=${packet[key]}`).join("; ")}; envelopeId=E-1 | Claude（委任。枠の内の承認し直し） | p.md`,
].join("\n");
const check = ({ packet = packetOf(), review, ledger, ...rest } = {}) => validateProbeApproval({ ledgerText: ledger ?? ledgerOf(packet, rest), packet, review: review ?? reviewOf(packet) });

test("the limits are one recording, the query project alone, US$0.01 and eight requests", () => {
  assert.equal(PROBE_RECORDINGS_PER_APPROVAL, 1);
  assert.deepEqual(PROBE_APPROVAL_LIMITS, { projects: ["fireemu-oracle-query"], maxRequests: 8, reserveUsd: 0.01 });
  assert.equal(Object.isFrozen(PROBE_APPROVAL_LIMITS) && Object.isFrozen(PROBE_APPROVAL_LIMITS.projects), true);
});

test("a probe approval is valid only under a stage2d-probe name, inside its limits and with an envelope that covers it", () => {
  const ok = check();
  assert.equal(ok.status, "APPROVAL_BOUND_LOCAL_ONLY");
  assert.equal(ok.sendAuthorized, false);
  assert.equal(ok.envelopeId, "E-1");
  for (const name of ["stage2d-probe", "stage2d-probev1", "stage2c-pre-v1", "stage2b-v1", "xstage2d-probe-v1", "Stage2d-probe-v1"]) assert.throws(() => check({ packet: packetOf({ packetName: name }) }), /invalid packet data/, name);
  for (const delta of [{ maxRequests: 9 }, { maxRequests: 7 }, { reserveUsd: 0.02 }, { reserveUsd: 0.005 }, { reserveUsd: 1 }, { projects: ["fireemu-oracle-idp"] }, { projects: ["fireemu-oracle-query", "fireemu-oracle-idp"] }, { projects: [] }]) {
    assert.throws(() => check({ packet: packetOf(delta) }), /runner limit mismatch/, JSON.stringify(delta));
  }
  assert.throws(() => check({ max: 7 }), /packet exceeds owner envelope/);
  assert.throws(() => check({ reserve: 0.005 }), /packet exceeds owner envelope/);
  assert.throws(() => check({ project: "fireemu-oracle-idp" }), /packet exceeds owner envelope/);
  assert.doesNotThrow(() => check({ max: 20, reserve: 5 }));
  assert.throws(() => check({ reserve: 10.5 }), /delegated envelope exceeds US\$10/);
  for (const bad of ["abc", "0", "01", "-1", "1.5", "9".repeat(20)]) assert.throws(() => check({ max: bad }), /invalid envelope bound/, `max ${bad}`);
  for (const bad of ["abc", "-1", "0", "0.0", "1.", ".5", "1.1234567", "NaN", "Infinity"]) assert.throws(() => check({ reserve: bad }), /invalid envelope bound/, `reserve ${bad}`);
});

test("the packet's identity, the review's pins and the ledger's decision are checked", () => {
  for (const delta of [{ taskId: "OTHER" }, { taskId: 5 }, { packetName: 5 }, { packetName: null }, { sourceCommit: "abc" }, { runnerSha256: "abc" }, { manifestSha256: 5 }]) {
    const packet = packetOf(delta);
    assert.throws(() => validateProbeApproval({ ledgerText: ledgerOf(packetOf()), packet, review: reviewOf(packet) }), /invalid packet data/, JSON.stringify(delta));
  }
  for (const projects of [[5], [null], [{}], ["fireemu-oracle-query", 5]]) assert.throws(() => validateProbeApproval({ ledgerText: ledgerOf(packetOf()), packet: packetOf({ projects }), review: reviewOf(packetOf()) }), /invalid packet project data/, JSON.stringify(projects));
  assert.throws(() => validateProbeApproval({ ledgerText: 5, packet: packetOf(), review: reviewOf(packetOf()) }), /invalid approval options data/);
  assert.throws(() => validateProbeApproval({ ledgerText: "a\0b", packet: packetOf(), review: reviewOf(packetOf()) }), /invalid approval options data/);
  assert.throws(() => validateProbeApproval({ ledgerText: "", packet: packetOf(), review: reviewOf(packetOf()), mode: "pre" }), /invalid approval options data/);
  for (const delta of [{ verdict: "REQUEST CHANGES" }, { must: ["x"] }, { should: ["x"] }, { runnerSha256: "9".repeat(64) }, { envelopeId: "E-2" }, { withinEnvelope: false }]) assert.throws(() => check({ review: reviewOf(packetOf(), delta) }), undefined, JSON.stringify(delta));
  assert.throws(() => check({ decision: "REVOKED" }), /approval revoked/);
  assert.throws(() => check({ ledger: "" }), /matching owner approval required/);
  assert.throws(() => check({ ledger: `${ledgerOf(packetOf())}\n- 2026-09-30 | STORAGE-RULES stage2d-probe-v1 | decision=REVOKED | Claude | p.md` }), /approval revoked/);
  assert.throws(() => check({ ledger: ledgerOf(packetOf()).replace(`runnerSha256=${pins.runnerSha256}`, `runnerSha256=${"8".repeat(64)}`) }), /decision pin mismatch/);
  assert.throws(() => check({ ledger: ledgerOf(packetOf()).split("\n").slice(1).join("\n") }), /delegated envelope authority required/);
});

test("the admission refuses each option that is missing or of the wrong kind", () => {
  const options = () => ({ readLedger: async () => "", packet: packetOf(), review: reviewOf(packetOf()), locks: { verify: async () => true }, runId: "run-1", usage: { startedRunIds: async () => [], markStarted: async () => {} } });
  assert.doesNotThrow(() => createProbeAdmission(options()));
  const spoiled = [
    { readLedger: 5 }, { readLedger: undefined }, { locks: {} }, { locks: { verify: 5 } }, { locks: undefined }, { packet: [] }, { packet: null }, { packet: 5 }, { review: [] }, { review: null }, { review: 5 },
    { runId: 5 }, { runId: "Bad Id" }, { runId: "" }, { runId: "a".repeat(49) }, { usage: {} }, { usage: { startedRunIds: async () => [] } }, { usage: { markStarted: async () => {} } }, { usage: { startedRunIds: 5, markStarted: async () => {} } }, { usage: { startedRunIds: async () => [], markStarted: 5 } }, { usage: undefined },
  ];
  for (const delta of spoiled) assert.throws(() => createProbeAdmission({ ...options(), ...delta }), /invalid admission options/, JSON.stringify(Object.keys(delta)));
  for (const bad of [null, [], 5, "x", Object.assign(Object.create(null), options())]) assert.throws(() => createProbeAdmission(bad), /invalid admission options/);
  assert.throws(() => createProbeAdmission({ ...options(), extra: 1 }), /invalid admission options/);
  assert.throws(() => createProbeAdmission({ ...options(), mode: "pre" }), /invalid admission options/);
});
