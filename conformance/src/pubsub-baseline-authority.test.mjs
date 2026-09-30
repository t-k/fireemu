import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { test } from "node:test";
import { assertWriteAuthority } from "../pubsub-production/authority-check.mjs";
const target = new URL("../pubsub-production/baseline-authority.mjs", import.meta.url);
const pins = {
  packetSha256: "a".repeat(64),
  manifestSha256: "b".repeat(64),
  runnerSha256: "c".repeat(64),
  sourceCommit: "d".repeat(40),
};
const subject = "PUBSUB-EVENTARC fixture-baseline-002",
  envelopeId = "PUBSUB-EVENTARC-fixture-baseline-002";
function ledger() {
  return [
    "- 2026-09-28 | 調整役への委任（本番の送信） | decision=APPROVE; historical owner prose. | オーナー（direct） | source",
    "- 2026-09-28 | 調整役への委任（枠の承認） | decision=APPROVE; historical owner prose. | オーナー（direct） | source",
    `- 2026-09-30 | ${subject} envelope | envelopeId=${envelopeId}; project=fireemu-oracle-idp; maxRequests=3; maxCredentialCliInvocations=1; maxWallSeconds=600; reserveUsd=0.01; writes=none; iamConfig=none; retries=none; readScope=project-identity-project-policy-pubsub-service-account; 根拠=2026-09-28 調整役への委任（本番の送信） | Claude（委任。オーナーの裁量の委任 2026-09-28） | packet`,
    `- 2026-09-30 | ${subject} | decision=APPROVE; ${Object.entries({ ...pins, envelopeId })
      .map(([k, v]) => `${k}=${v}`)
      .join("; ")} | Claude（委任。枠の内の承認し直し） | packet`,
  ];
}
const input = (lines = ledger(), extra = {}) => ({
  ledgerText: lines.join("\n"),
  decisionLine: 4,
  pins,
  envelopeId,
  subject,
  maxRequests: 3,
  reserveUsd: 0.01,
  ...extra,
});
async function check(lines, extra) {
  assert.ok(existsSync(target), "isolated baseline authority is missing");
  return (await import(target.href)).assertBaselineAuthority(input(lines, extra));
}
test("fixed baseline requires exact version, read-only envelope and both authentic owner delegations", async () => {
  assert.deepEqual(await check(ledger()), { decisionLine: 4, envelopeId });
  for (const index of [0, 1, 2, 3]) {
    const lines = ledger();
    lines[index] = lines[index]
      .replace("APPROVE", "DENY")
      .replace("maxRequests=3", "maxRequests=2");
    await assert.rejects(check(lines));
  }
  for (const actor of ["attacker", "Claude", "Claude（委任）"]) {
    const lines = ledger();
    lines[3] = lines[3].replace("Claude（委任。枠の内の承認し直し）", actor);
    await assert.rejects(check(lines));
  }
});
test("baseline never accepts writer permissions, alternate scopes or changed fixed bounds", async () => {
  for (const [old, value] of [
    ["writes=none", "writes=owned-topic-subscription"],
    ["iamConfig=none", "iamConfig=allowed"],
    ["retries=none", "retries=allowed"],
    [
      "readScope=project-identity-project-policy-pubsub-service-account",
      "readScope=arbitrary-post",
    ],
    ["project=fireemu-oracle-idp", "project=other"],
    ["maxRequests=3", "maxRequests=4"],
    ["maxCredentialCliInvocations=1", "maxCredentialCliInvocations=2"],
    ["maxWallSeconds=600", "maxWallSeconds=601"],
    ["reserveUsd=0.01", "reserveUsd=NaN"],
    ["reserveUsd=0.01", "reserveUsd=11"],
    ["reserveUsd=0.01", "reserveUsd=0"],
    ["根拠=2026-09-28 調整役への委任（本番の送信）", "根拠=wrong"],
  ]) {
    const lines = ledger();
    lines[2] = lines[2].replace(old, value);
    await assert.rejects(check(lines));
  }
  await assert.rejects(check(ledger(), { subject: "PUBSUB-EVENTARC shape-001" }));
  const changedSubject = "PUBSUB-EVENTARC shape-001";
  const retyped = ledger().map((line) => line.replace(subject, changedSubject));
  await assert.rejects(check(retyped, { subject: changedSubject }));
  await assert.rejects(check(ledger(), { envelopeId: "PUBSUB-EVENTARC-shape-001" }));
  await assert.rejects(check(ledger(), { maxRequests: 2 }));
  await assert.rejects(check(ledger(), { reserveUsd: 0 }));
  assert.throws(() => assertWriteAuthority(input()));
});
test("all four pins are mandatory, closed, syntactically valid and exactly matched", async () => {
  for (const key of Object.keys(pins)) {
    const absent = { ...pins };
    delete absent[key];
    await assert.rejects(check(ledger(), { pins: absent }));
    await assert.rejects(check(ledger(), { pins: { ...pins, [key]: "bad" } }));
    const malformed = ledger();
    malformed[3] = malformed[3].replace(`${key}=${pins[key]}`, `${key}=bad`);
    await assert.rejects(check(malformed, { pins: { ...pins, [key]: "bad" } }));
    await assert.rejects(
      check(ledger(), { pins: { ...pins, [key]: "e".repeat(pins[key].length) } }),
    );
  }
  await assert.rejects(check(ledger(), { pins: { ...pins, optionalPolicy: "anything" } }));
  const extra = ledger();
  extra[3] = extra[3].replace("decision=APPROVE;", "decision=APPROVE; optionalPolicy=anything;");
  await assert.rejects(check(extra, { pins: { ...pins, optionalPolicy: "anything" } }));
  await assert.rejects(check(ledger(), { decisionLine: 0 }));
});
test("duplicate or ambiguous approvals, envelopes and grants are refused", async () => {
  for (const [index, old, value] of [
    [3, "decision=APPROVE", "NOT decision=APPROVE"],
    [3, "decision=APPROVE", "decision=APPROVE; decision = DENY"],
    [
      3,
      `packetSha256=${pins.packetSha256}`,
      `packetSha256=${pins.packetSha256}; packetSha256=${pins.packetSha256}`,
    ],
    [2, "maxRequests=3", "maxRequests=3; maxRequests=3"],
    [0, "historical owner prose.", "historical owner prose.; decision = DENY"],
  ]) {
    const lines = ledger();
    lines[index] = lines[index].replace(old, value);
    await assert.rejects(check(lines));
  }
  const duplicate = ledger();
  duplicate.splice(2, 0, duplicate[2]);
  await assert.rejects(check(duplicate, { decisionLine: 5 }));
  const noEnvelope = ledger();
  noEnvelope[2] = "no envelope";
  await assert.rejects(check(noEnvelope));
});
test("current version, lane-wide, normalized delegation and later global stops revoke baseline", async () => {
  for (const row of [
    `PUBSUB-EVENTARC REVOKED packetSha256=${pins.packetSha256}`,
    `PUBSUB-EVENTARC REVOKED envelopeId=${envelopeId}`,
    "PUBSUB-EVENTARC REVOKED",
    "調整役への委任 ＲＥＶＯＫＥＤ",
    "all production stop",
    "全体の送信を停止",
  ])
    await assert.rejects(check([...ledger(), row]));
  const old = "e".repeat(64),
    lines = ledger();
  lines.splice(
    2,
    0,
    `- 2026-09-30 | PUBSUB-EVENTARC old | decision=APPROVE; packetSha256=${old} | owner | old`,
    `- 2026-09-30 | PUBSUB-EVENTARC old | REVOKED packetSha256=${old} | owner | old`,
  );
  assert.equal((await check(lines, { decisionLine: 6 })).decisionLine, 6);
});
test("owner-written envelope does not waive delegated decision's two owner grants", async () => {
  const lines = ledger();
  lines[2] = lines[2].replace(
    "Claude（委任。オーナーの裁量の委任 2026-09-28）",
    "オーナー（direct）",
  );
  assert.equal((await check(lines)).decisionLine, 4);
  for (const index of [0, 1]) {
    const missing = [...lines];
    missing[index] = "missing grant";
    await assert.rejects(check(missing));
  }
});
test("later universal stops dominate consumed old pins and delegation context", async () => {
  const old = "e".repeat(64);
  for (const stop of [
    `all production stop PUBSUB-EVENTARC packetSha256=${old}`,
    "all production stop including 調整役への委任",
  ]) {
    const lines = ledger();
    lines.splice(
      2,
      0,
      `- 2026-09-30 | PUBSUB-EVENTARC old | decision=APPROVE; packetSha256=${old} | owner | old`,
    );
    await assert.rejects(check([...lines, stop], { decisionLine: 5 }));
  }
});
