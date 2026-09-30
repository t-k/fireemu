import assert from "node:assert/strict";
import test from "node:test";
import { RELEASE_APPROVAL_LIMITS, RELEASE_RECORDINGS_PER_APPROVAL, validateReleaseApproval } from "./storage-rules-release/approval.mjs";
import { createReleaseAdmission } from "./storage-rules-release/admission.mjs";
import { PIN_KEYS } from "./storage-rules-release-support.mjs";

const pins = { packetSha256: "1".repeat(64), sourceCommit: "a".repeat(40), runnerSha256: "2".repeat(64), manifestSha256: "3".repeat(64), fixtureSchemaSha256: "4".repeat(64) };
const packetOf = (mode, delta = {}) => ({ taskId: "STORAGE-RULES", packetName: `stage2c-${mode}-v1`, ...pins, projects: ["fireemu-oracle-query"], maxRequests: RELEASE_APPROVAL_LIMITS[mode].maxRequests, reserveUsd: 0.5, ...delta });
const reviewOf = (packet, delta = {}) => ({ verdict: "APPROVE", must: [], should: [], ...Object.fromEntries(PIN_KEYS.map((key) => [key, packet[key]])), envelopeId: "E-1", withinEnvelope: true, ...delta });
const DELEGATIONS = ["- 2026-09-28 | 調整役への委任（本番の送信） | decision=APPROVE; x | オーナー（ローカル試験） | p.md", "- 2026-09-28 | 調整役への委任（枠の承認） | decision=APPROVE; x | オーナー（ローカル試験） | p.md"];
const ledgerOf = (packet, { max = packet.maxRequests, reserve = 0.5, project = "fireemu-oracle-query", decision = "APPROVE" } = {}) => [
  ...DELEGATIONS,
  `- 2026-09-29 | STORAGE-RULES ${packet.packetName} envelope | envelopeId=E-1; project=${project}; maxRequests=${max}; reserveUsd=${reserve}; writes=x; iamConfig=none; retries=none; 根拠=2026-09-28 調整役への委任（本番の送信） | Claude（委任。オーナーの裁量の委任 2026-09-28） | p.md`,
  `- 2026-09-29 | STORAGE-RULES ${packet.packetName} | decision=${decision}; ${PIN_KEYS.map((key) => `${key}=${packet[key]}`).join("; ")}; envelopeId=E-1 | Claude（委任。枠の内の承認し直し） | p.md`,
].join("\n");
const check = (mode, { packet = packetOf(mode), review, ledger, ...rest } = {}) => validateReleaseApproval({ ledgerText: ledger ?? ledgerOf(packet, rest), packet, review: review ?? reviewOf(packet), mode });

test("the limits are one recording, the query project alone, US$0.5, eleven requests for pre and eight for post", () => {
  assert.equal(RELEASE_RECORDINGS_PER_APPROVAL, 1);
  assert.deepEqual(RELEASE_APPROVAL_LIMITS, { pre: { projects: ["fireemu-oracle-query"], maxRequests: 11, reserveUsd: 0.5 }, post: { projects: ["fireemu-oracle-query"], maxRequests: 8, reserveUsd: 0.5 } });
  assert.equal(Object.isFrozen(RELEASE_APPROVAL_LIMITS) && Object.isFrozen(RELEASE_APPROVAL_LIMITS.pre) && Object.isFrozen(RELEASE_APPROVAL_LIMITS.pre.projects), true);
});

test("an approval of a mode is valid for that mode alone", () => {
  for (const mode of ["pre", "post"]) {
    const ok = check(mode);
    assert.equal(ok.status, "APPROVAL_BOUND_LOCAL_ONLY");
    assert.equal(ok.sendAuthorized, false);
    assert.equal(ok.envelopeId, "E-1");
  }
  const pre = packetOf("pre");
  assert.throws(() => validateReleaseApproval({ ledgerText: ledgerOf(pre), packet: pre, review: reviewOf(pre), mode: "post" }), /invalid packet data/);
  const post = packetOf("post");
  assert.throws(() => validateReleaseApproval({ ledgerText: ledgerOf(post), packet: post, review: reviewOf(post), mode: "pre" }), /invalid packet data/);
  for (const mode of ["both", undefined, "", "toString", "__proto__"]) assert.throws(() => validateReleaseApproval({ ledgerText: "", packet: pre, review: reviewOf(pre), mode }), /invalid approval options data/);
  assert.throws(() => validateReleaseApproval({ ledgerText: "", packet: pre, review: reviewOf(pre) }), /invalid approval options data/);
  for (const name of ["stage2c-pre", "stage2c-prev1", "stage2b-v1", "xstage2c-pre-v1"]) {
    const packet = packetOf("pre", { packetName: name });
    assert.throws(() => check("pre", { packet }), /invalid packet data/, name);
  }
});

test("the packet must stay inside its mode's limits, and the envelope must cover the packet", () => {
  for (const [mode, delta] of [["pre", { maxRequests: 12 }], ["pre", { maxRequests: 8 }], ["post", { maxRequests: 9 }], ["post", { maxRequests: 11 }], ["pre", { reserveUsd: 1 }], ["pre", { reserveUsd: 0.4 }], ["pre", { projects: ["fireemu-oracle-idp"] }], ["pre", { projects: ["fireemu-oracle-query", "fireemu-oracle-idp"] }], ["pre", { projects: [] }]]) {
    assert.throws(() => check(mode, { packet: packetOf(mode, delta) }), /runner limit mismatch/, JSON.stringify([mode, delta]));
  }
  assert.throws(() => check("pre", { max: 10 }), /packet exceeds owner envelope/);
  assert.throws(() => check("post", { max: 7 }), /packet exceeds owner envelope/);
  assert.throws(() => check("pre", { reserve: 0.4 }), /packet exceeds owner envelope/);
  assert.doesNotThrow(() => check("pre", { max: 20, reserve: 5 }));
  assert.throws(() => check("pre", { reserve: 10.5 }), /delegated envelope exceeds US\$10/);
  assert.throws(() => check("pre", { project: "fireemu-oracle-idp" }), /packet exceeds owner envelope/);
});

test("the review must be a clean APPROVE with the packet's pins, and a revoked or missing decision refuses", () => {
  const packet = packetOf("pre");
  for (const delta of [{ verdict: "REQUEST CHANGES" }, { must: ["x"] }, { should: ["x"] }, { runnerSha256: "9".repeat(64) }, { envelopeId: "E-2" }, { withinEnvelope: false }]) {
    assert.throws(() => check("pre", { review: reviewOf(packet, delta) }), undefined, JSON.stringify(delta));
  }
  assert.throws(() => check("pre", { decision: "REVOKED" }), /approval revoked/);
  assert.throws(() => check("pre", { ledger: "" }), /matching owner approval required/);
  assert.throws(() => check("pre", { ledger: `${ledgerOf(packet)}\n- 2026-09-29 | STORAGE-RULES stage2c-pre-v1 | decision=REVOKED | Claude | p.md` }), /approval revoked/);
  assert.throws(() => check("pre", { ledger: ledgerOf(packet).replace(`runnerSha256=${pins.runnerSha256}`, `runnerSha256=${"8".repeat(64)}`) }), /decision pin mismatch/);
  assert.throws(() => check("pre", { ledger: ledgerOf(packet).split("\n").slice(1).join("\n") }), /delegated envelope authority required/);
});

test("the admission needs its mode and the closed options", () => {
  const options = () => ({ readLedger: async () => "", packet: packetOf("pre"), review: reviewOf(packetOf("pre")), locks: { verify: async () => true }, runId: "run-1", usage: { startedRunIds: async () => [], markStarted: async () => {} }, mode: "pre" });
  assert.doesNotThrow(() => createReleaseAdmission(options()));
  for (const mode of ["both", undefined, "PRE"]) assert.throws(() => createReleaseAdmission({ ...options(), mode }), /invalid admission options/);
  const { mode, ...without } = options();
  assert.throws(() => createReleaseAdmission(without), /invalid admission options/);
  assert.throws(() => createReleaseAdmission({ ...options(), extra: 1 }), /invalid admission options/);
});

test("the packet's identity and the envelope's bounds are checked before the approval is granted", () => {
  for (const delta of [{ taskId: "OTHER" }, { taskId: 5 }, { packetName: 5 }, { packetName: null }, { packetName: "Stage2c-pre-v1" }, { packetName: `stage2c-pre-${"a".repeat(60)}` }, { sourceCommit: "abc" }, { runnerSha256: "abc" }, { manifestSha256: 5 }]) {
    const packet = packetOf("pre", delta);
    assert.throws(() => validateReleaseApproval({ ledgerText: ledgerOf(packetOf("pre")), packet, review: reviewOf(packet), mode: "pre" }), /invalid packet data/, JSON.stringify(delta));
  }
  assert.throws(() => validateReleaseApproval({ ledgerText: 5, packet: packetOf("pre"), review: reviewOf(packetOf("pre")), mode: "pre" }), /invalid approval options data/);
  assert.throws(() => validateReleaseApproval({ ledgerText: "a\0b", packet: packetOf("pre"), review: reviewOf(packetOf("pre")), mode: "pre" }), /invalid approval options data/);
  for (const bad of ["abc", "0", "01", "-1", "1.5", "9".repeat(20)]) assert.throws(() => check("pre", { max: bad }), /invalid envelope bound/, `max ${bad}`);
  for (const bad of ["abc", "-1", "0", "0.0", "1.", ".5", "1.1234567", "NaN", "Infinity"]) assert.throws(() => check("pre", { reserve: bad }), /invalid envelope bound/, `reserve ${bad}`);
  for (const good of ["0.5", "0.500000", "1", "10", "3.25"]) assert.doesNotThrow(() => check("pre", { reserve: good }), `reserve ${good}`);
});

test("the admission refuses each option that is missing or of the wrong kind", () => {
  const options = () => ({ readLedger: async () => "", packet: packetOf("pre"), review: reviewOf(packetOf("pre")), locks: { verify: async () => true }, runId: "run-1", usage: { startedRunIds: async () => [], markStarted: async () => {} }, mode: "pre" });
  const spoiled = [
    { readLedger: 5 }, { readLedger: undefined }, { locks: {} }, { locks: { verify: 5 } }, { locks: undefined }, { packet: [] }, { packet: null }, { packet: 5 }, { review: [] }, { review: null }, { review: 5 },
    { runId: 5 }, { runId: "Bad Id" }, { runId: "" }, { runId: "a".repeat(49) }, { usage: {} }, { usage: { startedRunIds: async () => [] } }, { usage: { markStarted: async () => {} } }, { usage: { startedRunIds: 5, markStarted: async () => {} } }, { usage: { startedRunIds: async () => [], markStarted: 5 } }, { usage: undefined },
  ];
  for (const delta of spoiled) assert.throws(() => createReleaseAdmission({ ...options(), ...delta }), /invalid admission options/, JSON.stringify(Object.keys(delta)));
  for (const bad of [null, [], 5, "x", Object.assign(Object.create(null), options())]) assert.throws(() => createReleaseAdmission(bad), /invalid admission options/);
});
