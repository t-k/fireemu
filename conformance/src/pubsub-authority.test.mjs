import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { test } from "node:test";
const target = new URL("../pubsub-production/authority-check.mjs", import.meta.url);
const pins = {
  packetSha256: "a".repeat(64),
  manifestSha256: "b".repeat(64),
  runnerSha256: "c".repeat(64),
  sourceCommit: "d".repeat(40),
};
const envelopeId = "PUBSUB-EVENTARC-shape-001";
const subject = "PUBSUB-EVENTARC shape-001";
function ledger() {
  return [
    "- 2026-09-28 | 調整役への委任（本番の送信） | decision=APPROVE; | オーナー（direct） | source",
    "- 2026-09-28 | 調整役への委任（枠の承認） | decision=APPROVE; | オーナー（direct） | source",
    `- 2026-09-30 | ${subject} envelope | envelopeId=${envelopeId}; project=fireemu-oracle-idp; maxRequests=16; reserveUsd=0.02; writes=owned-topic-subscription; iamConfig=none; retries=none; 根拠=2026-09-28 調整役への委任（本番の送信） | Claude（委任。オーナーの裁量の委任 2026-09-28） | packet`,
    `- 2026-09-30 | ${subject} | decision=APPROVE; ${Object.entries({ ...pins, envelopeId })
      .map(([k, v]) => `${k}=${v}`)
      .join("; ")} | Claude（委任。枠の内の承認し直し） | packet`,
  ];
}
async function check(lines, extra = {}) {
  assert.ok(existsSync(target), "write authority checker is missing");
  const { assertWriteAuthority } = await import(target.href);
  return assertWriteAuthority({
    ledgerText: lines.join("\n"),
    decisionLine: 4,
    pins,
    envelopeId,
    subject,
    maxRequests: 16,
    reserveUsd: 0.02,
    ...extra,
  });
}
test("writer requires the exact version, preceding bounded envelope and both owner delegations", async () => {
  assert.equal((await check(ledger())).decisionLine, 4);
  for (const index of [0, 1, 2, 3]) {
    const lines = ledger();
    lines[index] = lines[index]
      .replace("APPROVE", "DENY")
      .replace("maxRequests=16", "maxRequests=15");
    await assert.rejects(check(lines));
  }
  await assert.rejects(check(ledger(), { pins: { ...pins, sourceCommit: "e".repeat(40) } }));
});
test("normalized delegation revocation and global stops block the next write", async () => {
  for (const row of [
    "全てのレーン REVOKED",
    "all production stop",
    "全体の送信を停止",
    "調整役への委任 ＲＥＶＯＫＥＤ",
    "調整役への委任を撤回",
  ]) {
    await assert.rejects(check([...ledger(), row]));
  }
});
test("writer also refuses later universal stops naming old pins or delegation", async () => {
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
test("consumed old own packets and other lane revocations do not revoke this fresh packet", async () => {
  const old = "e".repeat(64);
  const lines = ledger();
  lines.splice(
    2,
    0,
    `- 2026-09-30 | PUBSUB-EVENTARC old | decision=APPROVE; packetSha256=${old} | owner | old`,
    `- 2026-09-30 | PUBSUB-EVENTARC old | REVOKED packetSha256=${old} | owner | old`,
  );
  assert.equal((await check(lines, { decisionLine: 6 })).decisionLine, 6);
  assert.equal(
    (await check([...ledger(), `SCHEDULED-FUNCTIONS REVOKED packetSha256=${old}`])).decisionLine,
    4,
  );
  assert.equal(
    (await check([...ledger(), `EVENTARC-other REVOKED packetSha256=${old}`])).decisionLine,
    4,
  );
  await assert.rejects(
    check([...ledger(), `PUBSUB-EVENTARC REVOKED packetSha256=${pins.packetSha256}`]),
  );
});
test("negative, ambiguous duplicate fields and oversized delegated budget are refused", async () => {
  for (const edit of [
    (s) => s.replace("decision=APPROVE", "NOT decision=APPROVE"),
    (s) => s.replace("decision=APPROVE", "decision=APPROVE; decision=DENY"),
    (s) =>
      s.replace(
        `packetSha256=${pins.packetSha256}`,
        `packetSha256=${"f".repeat(64)}; packetSha256=${pins.packetSha256}`,
      ),
  ]) {
    const lines = ledger();
    lines[3] = edit(lines[3]);
    await assert.rejects(check(lines));
  }
  const lines = ledger();
  lines[2] = lines[2].replace("reserveUsd=0.02", "reserveUsd=11");
  await assert.rejects(check(lines));
});

test("an envelope refusing writes cannot authorize an owned-resource writer", async () => {
  for (const edit of [
    ["writes=owned-topic-subscription", "writes=none"],
    ["iamConfig=none", "iamConfig=allowed"],
    ["retries=none", "retries=allowed"],
  ]) {
    const lines = ledger();
    lines[2] = lines[2].replace(...edit);
    await assert.rejects(check(lines));
  }
});

test("a delegated decision requires both grants even under an owner-written envelope", async () => {
  const lines = ledger();
  lines[2] = lines[2].replace(
    "Claude（委任。オーナーの裁量の委任 2026-09-28）",
    "オーナー（direct）",
  );
  assert.equal((await check(lines)).decisionLine, 4);
  for (const index of [0, 1]) {
    const noGrant = [...lines];
    noGrant[index] = "owner grant absent";
    await assert.rejects(check(noGrant));
  }
});

test("historical owner grants allow their explanatory prose without relaxing version fields", async () => {
  const lines = ledger();
  lines[0] = lines[0].replace(
    "decision=APPROVE;",
    "decision=APPROVE; The owner delegates sandbox sends within the stated budget.",
  );
  lines[1] = lines[1].replace(
    "decision=APPROVE;",
    "decision=APPROVE; The owner delegates envelope decisions; the actor is specified below.",
  );
  assert.equal((await check(lines)).decisionLine, 4);
});

test("grant prose cannot hide a second normalized decision key", async () => {
  for (const suffix of ["decision = DENY;", "decision\t= DENY;"]) {
    const lines = ledger();
    lines[0] = lines[0].replace("decision=APPROVE;", `decision=APPROVE; ${suffix}`);
    await assert.rejects(check(lines));
  }
});
