import assert from "node:assert/strict";
import test from "node:test";
import { validatePresendApproval } from "./storage-object/approval.mjs";

const pins = {
  packetSha256: "abcdef12".repeat(8),
  sourceCommit: "abcdef34".repeat(5),
  runnerSha256: "abcdef56".repeat(8),
  planSha256: "abcdef78".repeat(8),
  corpusSha256: "abcdef90".repeat(8),
  rulesSourceSha256: "abcdefab".repeat(8),
};
const packet = {
  taskId: "STORAGE-OBJECT",
  packetName: "stage3-v2",
  ...pins,
  projectId: "example-query",
  maxRequests: 6000,
  reserveUsd: 1,
};
const runner = { projectId: packet.projectId, maxRequests: 6000, reserveUsd: 1 };
const owner = "オーナー（synthetic local fixture）";
const coordinator = "Claude（委任。枠の内の承認し直し）";
const envelopeActor = "Claude（委任。オーナーの裁量の委任 2026-09-28）";
const envelopeId = "STORAGE-OBJECT-stage3-v2-002";
const scope = "調整役への委任（本番の送信）";
const frameScope = "調整役への委任（枠の承認）";
const fields = (record) =>
  Object.entries(record)
    .map(([key, value]) => `${key}=${value}`)
    .join("; ");
const row = (subject, data, actor = owner) =>
  `- 2026-09-28 | ${subject} | ${fields(data)} | ${actor} | synthetic.md`;
const basis = (subject) => row(subject, { decision: "APPROVE" });
const decision = (actor = owner) =>
  row(
    "STORAGE-OBJECT stage3-v2",
    { decision: "APPROVE", ...pins, ...(actor === coordinator ? { envelopeId } : {}) },
    actor,
  );
const envelope = () =>
  row(
    "STORAGE-OBJECT stage3-v2 envelope",
    {
      envelopeId,
      project: packet.projectId,
      maxRequests: 6000,
      reserveUsd: 1,
      writes: "owned resources",
      iamConfig: "fixed Rules cleanup",
      retries: "none",
      根拠: `2026-09-28 ${scope}`,
    },
    envelopeActor,
  );
const review = (delegated) => ({
  verdict: "APPROVE",
  must: [],
  should: [],
  ...pins,
  envelopeId: delegated ? envelopeId : null,
  withinEnvelope: delegated,
});
const direct = () => decision();
const delegated = () =>
  [basis(scope), basis(frameScope), envelope(), decision(coordinator)].join("\n");
const validate = (ledgerText, delegatedReview = false) =>
  validatePresendApproval({ ledgerText, packet, runner, review: review(delegatedReview) });
const fullwidth = (text) =>
  text.replace(/[!-~]/g, (character) => String.fromCharCode(character.charCodeAt(0) + 0xfee0));
const revoked = (subject, body = "revoked") =>
  `- 2026-09-29 | ${subject} | ${body} | ${owner} | synthetic-revocation.md`;

const directDenials = [
  ["lowercase marker", revoked("storage-object stage3-v2")],
  ["fullwidth marker and topic", fullwidth(revoked("STORAGE-OBJECT stage3-v2", "ＲＥＶＯＫＥＤ"))],
  ["ASCII parentheses and correction suffix", revoked("STORAGE-OBJECT stage3-v2 (訂正)")],
  ["four-column revocation", `- 2026-09-29 | storage-object | revoked | ${owner}`],
  [
    "marker in the actor column",
    `- 2026-09-29 | STORAGE-OBJECT | cancelled | ${owner} revoked | synthetic.md`,
  ],
  ["topic only in the body", revoked("別のtopic", "revoked STORAGE-OBJECT")],
  ["parent topic without a concrete version", revoked("STORAGE-OBJECT")],
  ["current packet SHA outside the topic", revoked("別のtopic", `revoked ${pins.packetSha256}`)],
  [
    "uppercase current packet SHA",
    revoked("別のtopic", `revoked packetSha256=${pins.packetSha256.toUpperCase()}`),
  ],
  [
    "fullwidth current packet SHA",
    fullwidth(revoked("別のtopic", `revoked packetSha256=${pins.packetSha256}`)),
  ],
  ["source-only full commit", revoked("別のtopic", `revoked sourceCommit=${pins.sourceCommit}`)],
  [
    "uppercase source-only commit",
    revoked("別のtopic", `revoked sourceCommit=${pins.sourceCommit.toUpperCase()}`),
  ],
  [
    "source prefix of eight hexadecimal digits",
    revoked("別のtopic", `revoked sourceCommit=${pins.sourceCommit.slice(0, 8)}`),
  ],
  [
    "source prefix of nine hexadecimal digits",
    revoked("別のtopic", `revoked ${pins.sourceCommit.slice(0, 9)}`),
  ],
  [
    "partial other packet is not an exception",
    revoked("STORAGE-OBJECT", "revoked packetSha256=11223344…"),
  ],
  [
    "current source still binds a different complete packet",
    revoked(
      "STORAGE-OBJECT",
      `revoked packetSha256=${"1".repeat(64)}; sourceCommit=${pins.sourceCommit}`,
    ),
  ],
];
for (const [name, line] of directDenials)
  test(`a direct approval rejects ${name}`, () => {
    assert.throws(() => validate(`${direct()}\n${line}`), /revoked/i);
  });

const delegatedDenials = [
  ["original delegation scope", revoked(scope)],
  ["frame delegation scope", revoked(frameScope)],
  ["ASCII delegation parentheses", revoked("調整役への委任(枠の承認)")],
  ["delegation correction suffix", revoked("調整役への委任（本番の送信）（訂正）")],
  ["delegation only in the body", revoked("別のtopic", "revoked 調整役への委任")],
  ["four-column delegation", `- 2026-09-29 | 調整役への委任 | revoked | ${owner}`],
  ["fullwidth delegation marker", fullwidth(revoked("調整役への委任(枠の承認)"))],
  ["current envelope outside the topic", revoked("別のtopic", `revoked envelopeId=${envelopeId}`)],
  [
    "case-folded current envelope",
    revoked("別のtopic", `revoked envelopeId=${envelopeId.toLowerCase()}`),
  ],
  [
    "partial other envelope is not an exception",
    revoked("STORAGE-OBJECT", "revoked envelopeId=STORAGE-OBJECT-stage3-v2…"),
  ],
];
for (const [name, line] of delegatedDenials)
  test(`a coordinator envelope rejects ${name}`, () => {
    assert.throws(() => validate(`${delegated()}\n${line}`, true), /revoked/i);
  });

test("a coordinator envelope requires both exact preceding owner delegation scopes", () => {
  assert.equal(validate(delegated(), true).sendAuthorized, false);
  for (const missing of [scope, frameScope]) {
    const ledger = [
      basis(missing === scope ? frameScope : scope),
      envelope(),
      decision(coordinator),
    ].join("\n");
    assert.throws(() => validate(ledger, true), /delegation basis/i);
  }
  for (const badBasis of [
    basis(frameScope).replace("decision=APPROVE", "decision=REQUEST_CHANGES"),
    basis(frameScope).replace(owner, coordinator),
    basis(frameScope).replace("2026-09-28", "2026-09-27"),
  ])
    assert.throws(
      () => validate([basis(scope), badBasis, envelope(), decision(coordinator)].join("\n"), true),
      /delegation basis/i,
    );
  assert.throws(
    () =>
      validate(
        [basis(scope), envelope(), decision(coordinator), basis(frameScope)].join("\n"),
        true,
      ),
    /delegation basis/i,
  );
});

const unaffected = [
  [
    "an unrelated lane",
    revoked("FUNCTIONS-EVENTS recovery（訂正）", "revoked packetSha256=11223344…"),
  ],
  [
    "a complete other packet",
    revoked("STORAGE-OBJECT stage3-v1", `revoked packetSha256=${"1".repeat(64)}（consumed）`),
  ],
  [
    "a complete other packet using the same topic",
    revoked("STORAGE-OBJECT stage3-v2", `revoked packetSha256=${"1".repeat(64)}（consumed）`),
  ],
  [
    "a seven-digit source reference in another lane",
    revoked("別のtopic", `revoked sourceCommit=${pins.sourceCommit.slice(0, 7)}`),
  ],
  [
    "a non-prefix source substring in another lane",
    revoked("別のtopic", `revoked sourceCommit=${pins.sourceCommit.slice(2, 10)}`),
  ],
];
for (const [name, line] of unaffected)
  test(`a direct approval remains bound with ${name}`, () => {
    assert.equal(validate(`${direct()}\n${line}`).sendAuthorized, false);
  });

test("a consumed complete other envelope does not invalidate this version", () => {
  const oldId = "STORAGE-OBJECT-stage3-v1-001";
  const old = row(
    "STORAGE-OBJECT stage3-v1 envelope",
    { envelopeId: oldId, project: packet.projectId },
    owner,
  );
  assert.equal(
    validate(
      `${old}\n${delegated()}\n${revoked("STORAGE-OBJECT", `revoked envelopeId=${oldId}（consumed）`)}`,
      true,
    ).sendAuthorized,
    false,
  );
});

test("direct owner authority does not rely on a revoked coordinator delegation", () => {
  assert.equal(validate(`${direct()}\n${revoked(frameScope)}`).sendAuthorized, false);
});

test("an envelope reference revokes even when its ID does not repeat the lane label", () => {
  const id = "OBSERVATION-002";
  const ledgerText = delegated().replaceAll(envelopeId, id);
  const input = { ledgerText, packet, runner, review: { ...review(true), envelopeId: id } };
  assert.equal(validatePresendApproval(input).sendAuthorized, false);
  assert.throws(
    () =>
      validatePresendApproval({
        ...input,
        ledgerText: `${ledgerText}\n${revoked("別のtopic", `revoked envelopeId=${id}`)}`,
      }),
    /revoked/i,
  );
});

for (const suffix of ["g", "_backup", "…"])
  test(`a different packet digest followed by ${suffix} is not a complete consumed reference`, () => {
    assert.throws(
      () =>
        validate(
          `${direct()}\n${revoked("STORAGE-OBJECT", `revoked packetSha256=${"1".repeat(64)}${suffix}`)}`,
        ),
      /revoked/i,
    );
  });

for (const length of [8, 63, 65])
  test(`a different packet reference of ${length} hexadecimal digits cannot exempt a parent revocation`, () => {
    assert.throws(
      () =>
        validate(
          `${direct()}\n${revoked("STORAGE-OBJECT", `revoked packetSha256=${"1".repeat(length)}`)}`,
        ),
      /revoked/i,
    );
  });

test("a known different envelope ID followed by a fragment suffix is not a complete consumed reference", () => {
  const oldId = "LEGACY-005";
  const old = row("STORAGE-OBJECT stage3-v1 envelope", { envelopeId: oldId }, owner);
  assert.throws(
    () =>
      validate(
        `${old}\n${delegated()}\n${revoked("STORAGE-OBJECT", `revoked envelopeId=${oldId}#suffix`)}`,
        true,
      ),
    /revoked/i,
  );
});
