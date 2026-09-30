import assert from "node:assert/strict";
import test from "node:test";
import { SHAPE_APPROVAL_LIMITS, SHAPE_RECORDINGS_PER_APPROVAL, validateShapeApproval } from "./storage-rules-shape/approval.mjs";
import { createShapeAdmission } from "./storage-rules-shape/admission.mjs";
import { PIN_KEYS } from "./storage-rules-shape-support.mjs";

const pins = { packetSha256: "1".repeat(64), sourceCommit: "a".repeat(40), runnerSha256: "2".repeat(64), manifestSha256: "3".repeat(64), fixtureSchemaSha256: "4".repeat(64) };
const packetOf = (delta = {}) => ({ taskId: "STORAGE-RULES", packetName: "stage2f-shape-v1", ...pins, projects: ["fireemu-oracle-query"], maxRequests: 19, reserveUsd: 0.15, ...delta });
const reviewOf = (packet, delta = {}) => ({ verdict: "APPROVE", must: [], should: [], ...Object.fromEntries(PIN_KEYS.map((key) => [key, packet[key]])), envelopeId: "E-1", withinEnvelope: true, ...delta });
const DELEGATIONS = ["- 2026-09-28 | 調整役への委任（本番の送信） | decision=APPROVE; x | オーナー（ローカル試験） | p.md", "- 2026-09-28 | 調整役への委任（枠の承認） | decision=APPROVE; x | オーナー（ローカル試験） | p.md"];
const ledgerOf = (packet, { max = packet.maxRequests, reserve = 0.15, project = "fireemu-oracle-query", decision = "APPROVE" } = {}) => [
  ...DELEGATIONS,
  `- 2026-09-30 | STORAGE-RULES ${packet.packetName} envelope | envelopeId=E-1; project=${project}; maxRequests=${max}; reserveUsd=${reserve}; writes=none; iamConfig=none; retries=none; 根拠=2026-09-28 調整役への委任（本番の送信） | Claude（委任。オーナーの裁量の委任 2026-09-28） | p.md`,
  `- 2026-09-30 | STORAGE-RULES ${packet.packetName} | decision=${decision}; ${PIN_KEYS.map((key) => `${key}=${packet[key]}`).join("; ")}; envelopeId=E-1 | Claude（委任。枠の内の承認し直し） | p.md`,
].join("\n");
const check = ({ packet = packetOf(), review, ledger, ...rest } = {}) => validateShapeApproval({ ledgerText: ledger ?? ledgerOf(packet, rest), packet, review: review ?? reviewOf(packet) });

test("the limits are one recording, the query project alone, US$0.15 and 19 requests", () => {
  assert.equal(SHAPE_RECORDINGS_PER_APPROVAL, 1);
  assert.deepEqual(SHAPE_APPROVAL_LIMITS, { projects: ["fireemu-oracle-query"], maxRequests: 19, reserveUsd: 0.15 });
  assert.equal(Object.isFrozen(SHAPE_APPROVAL_LIMITS) && Object.isFrozen(SHAPE_APPROVAL_LIMITS.projects), true);
});

test("a shape approval is valid only under a stage2f-shape name, inside its limits and with an envelope that covers it", () => {
  const ok = check();
  assert.equal(ok.status, "APPROVAL_BOUND_LOCAL_ONLY");
  assert.equal(ok.sendAuthorized, false);
  assert.equal(ok.envelopeId, "E-1");
  for (const name of ["stage2f-shape", "stage2f-shapev1", "stage2c-pre-v1", "stage2b-v1", "xstage2f-shape-v1", "Stage2e-restore-v1", "stage2e-restore-v1"]) assert.throws(() => check({ packet: packetOf({ packetName: name }) }), /invalid packet data/, name);
  for (const delta of [{ maxRequests: 20 }, { maxRequests: 18 }, { reserveUsd: 0.16 }, { reserveUsd: 0.14 }, { reserveUsd: 1 }, { projects: ["fireemu-oracle-idp"] }, { projects: ["fireemu-oracle-query", "fireemu-oracle-idp"] }, { projects: [] }]) {
    assert.throws(() => check({ packet: packetOf(delta) }), /runner limit mismatch/, JSON.stringify(delta));
  }
  assert.throws(() => check({ max: 18 }), /packet exceeds owner envelope/);
  assert.throws(() => check({ reserve: 0.14 }), /packet exceeds owner envelope/);
  assert.throws(() => check({ project: "fireemu-oracle-idp" }), /packet exceeds owner envelope/);
  assert.doesNotThrow(() => check({ max: 100, reserve: 5 }));
  assert.throws(() => check({ reserve: 10.5 }), /delegated envelope exceeds US\$10/);
  for (const bad of ["abc", "0", "01", "-1", "1.5", "9".repeat(20)]) assert.throws(() => check({ max: bad }), /invalid envelope bound/, `max ${bad}`);
  for (const bad of ["abc", "-1", "0", "0.0", "1.", ".5", "1.1234567", "NaN", "Infinity"]) assert.throws(() => check({ reserve: bad }), /invalid envelope bound/, `reserve ${bad}`);
});

test("the packet's identity, the review's pins and the ledger's decision are checked", () => {
  for (const delta of [{ taskId: "OTHER" }, { taskId: 5 }, { packetName: 5 }, { packetName: null }, { sourceCommit: "abc" }, { runnerSha256: "abc" }, { manifestSha256: 5 }]) {
    const packet = packetOf(delta);
    assert.throws(() => validateShapeApproval({ ledgerText: ledgerOf(packetOf()), packet, review: reviewOf(packet) }), /invalid packet data/, JSON.stringify(delta));
  }
  for (const projects of [[5], [null], [{}], ["fireemu-oracle-query", 5]]) assert.throws(() => validateShapeApproval({ ledgerText: ledgerOf(packetOf()), packet: packetOf({ projects }), review: reviewOf(packetOf()) }), /invalid packet project data/, JSON.stringify(projects));
  assert.throws(() => validateShapeApproval({ ledgerText: 5, packet: packetOf(), review: reviewOf(packetOf()) }), /invalid approval options data/);
  assert.throws(() => validateShapeApproval({ ledgerText: "a\0b", packet: packetOf(), review: reviewOf(packetOf()) }), /invalid approval options data/);
  assert.throws(() => validateShapeApproval({ ledgerText: "", packet: packetOf(), review: reviewOf(packetOf()), mode: "pre" }), /invalid approval options data/);
  for (const delta of [{ verdict: "REQUEST CHANGES" }, { must: ["x"] }, { should: ["x"] }, { runnerSha256: "9".repeat(64) }, { envelopeId: "E-2" }, { withinEnvelope: false }]) assert.throws(() => check({ review: reviewOf(packetOf(), delta) }), undefined, JSON.stringify(delta));
  assert.throws(() => check({ decision: "REVOKED" }), /approval revoked/);
  assert.throws(() => check({ ledger: "" }), /matching owner approval required/);
  assert.throws(() => check({ ledger: `${ledgerOf(packetOf())}\n- 2026-09-30 | STORAGE-RULES stage2f-shape-v1 | decision=REVOKED | Claude | p.md` }), /approval revoked/);
  assert.throws(() => check({ ledger: ledgerOf(packetOf()).replace(`runnerSha256=${pins.runnerSha256}`, `runnerSha256=${"8".repeat(64)}`) }), /decision pin mismatch/);
  assert.throws(() => check({ ledger: ledgerOf(packetOf()).split("\n").slice(1).join("\n") }), /delegated envelope authority required/);
});

test("the admission refuses each option that is missing or of the wrong kind", () => {
  const options = () => ({ readLedger: async () => "", packet: packetOf(), review: reviewOf(packetOf()), locks: { verify: async () => true }, runId: "run-1", usage: { startedRunIds: async () => [], markStarted: async () => {} } });
  assert.doesNotThrow(() => createShapeAdmission(options()));
  const spoiled = [
    { readLedger: 5 }, { readLedger: undefined }, { locks: {} }, { locks: { verify: 5 } }, { locks: undefined }, { packet: [] }, { packet: null }, { packet: 5 }, { review: [] }, { review: null }, { review: 5 },
    { runId: 5 }, { runId: "Bad Id" }, { runId: "" }, { runId: "a".repeat(49) }, { usage: {} }, { usage: { startedRunIds: async () => [] } }, { usage: { markStarted: async () => {} } }, { usage: { startedRunIds: 5, markStarted: async () => {} } }, { usage: { startedRunIds: async () => [], markStarted: 5 } }, { usage: undefined },
  ];
  for (const delta of spoiled) assert.throws(() => createShapeAdmission({ ...options(), ...delta }), /invalid admission options/, JSON.stringify(Object.keys(delta)));
  for (const bad of [null, [], 5, "x", Object.assign(Object.create(null), options())]) assert.throws(() => createShapeAdmission(bad), /invalid admission options/);
  assert.throws(() => createShapeAdmission({ ...options(), extra: 1 }), /invalid admission options/);
  assert.throws(() => createShapeAdmission({ ...options(), mode: "pre" }), /invalid admission options/);
});
