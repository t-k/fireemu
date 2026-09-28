import assert from "node:assert/strict";
import test from "node:test";
import { validatePresendApproval } from "./storage-object/approval.mjs";

const pins = [
  "packetSha256",
  "sourceCommit",
  "runnerSha256",
  "planSha256",
  "corpusSha256",
  "rulesSourceSha256",
];
const packet = {
  taskId: "STORAGE-OBJECT",
  packetName: "stage3-v1",
  projectId: "example-query",
  maxRequests: 5600,
  reserveUsd: 9,
  ...Object.fromEntries(
    pins.map((key, index) => [key, `${index + 1}`.repeat(key === "sourceCommit" ? 40 : 64)]),
  ),
};
const runner = {
  projectId: packet.projectId,
  maxRequests: packet.maxRequests,
  reserveUsd: packet.reserveUsd,
};
const review = {
  verdict: "APPROVE",
  must: [],
  should: [],
  ...Object.fromEntries(pins.map((key) => [key, packet[key]])),
  envelopeId: null,
  withinEnvelope: false,
};
const owner = "オーナー（ローカル試験）",
  coordinator = "Claude（委任。枠の内の承認し直し）";
const envelopeId = "STORAGE-OBJECT-stage3-v1-001";
const inEnvelope = { ...review, envelopeId, withinEnvelope: true };
const fields = (values) =>
  Object.entries(values)
    .map(([key, value]) => `${key}=${value}`)
    .join("; ");
const row = (subject, values, actor = owner) =>
  `- 2026-09-28 | ${subject} | ${fields(values)} | ${actor} | private-packet.md`;
const decision = (values = {}, actor = owner) =>
  row(
    "STORAGE-OBJECT stage3-v1",
    {
      decision: "APPROVE",
      ...Object.fromEntries(pins.map((key) => [key, packet[key]])),
      ...values,
    },
    actor,
  );
const envelope = (values = {}, actor = owner) =>
  row(
    "STORAGE-OBJECT stage3-v1 envelope",
    {
      envelopeId,
      project: packet.projectId,
      maxRequests: packet.maxRequests,
      reserveUsd: packet.reserveUsd,
      writes: "owned run objects and accounts",
      iamConfig: "fixed Rules cleanup only",
      retries: "none",
      ...values,
    },
    actor,
  );
const delegated = (values = {}) => decision({ envelopeId, ...values }, coordinator);
const validate = (ledgerText, overrides = {}) =>
  validatePresendApproval({ ledgerText, packet, review, runner, ...overrides });

test("a concrete owner approval binds all review and packet pins without authorizing a send", () => {
  const result = validate(decision());
  assert.equal(result.status, "APPROVAL_BOUND_LOCAL_ONLY");
  assert.equal(result.sendAuthorized, false);
  assert.equal(result.decisionLine, 1);
  assert.equal(result.envelopeId, null);
});
test("an owner envelope at the exact request and budget limits covers the delegated version", () => {
  const result = validate(`${envelope()}\n${delegated()}`, { review: inEnvelope });
  assert.equal(result.envelopeId, envelopeId);
  assert.equal(result.envelopeLine, 1);
  assert.equal(result.decisionLine, 2);
  assert.equal(result.sendAuthorized, false);
});
test("a larger owner envelope covers a smaller packet and runner", () => {
  assert.equal(
    validate(`${envelope({ maxRequests: 5601, reserveUsd: 10 })}\n${delegated()}`, {
      review: inEnvelope,
    }).envelopeId,
    envelopeId,
  );
});
for (const [label, values] of [
  ["one request", { maxRequests: 5599 }],
  ["reservation", { reserveUsd: 8.999999 }],
  ["project", { project: "example-idp" }],
]) {
  test(`exceeding the owner envelope in ${label} rejects`, () => {
    assert.throws(
      () => validate(`${envelope(values)}\n${delegated()}`, { review: inEnvelope }),
      /exceeds owner envelope/,
    );
  });
}
for (const [label, delta] of [
  ["packet request", { packet: { ...packet, maxRequests: 5601 } }],
  ["runner request", { runner: { ...runner, maxRequests: 5601 } }],
  ["packet reservation", { packet: { ...packet, reserveUsd: 10 } }],
  ["runner reservation", { runner: { ...runner, reserveUsd: 10 } }],
  ["runner project", { runner: { ...runner, projectId: "example-idp" } }],
]) {
  test(`${label} cannot diverge from the reviewed concrete packet`, () => {
    assert.throws(
      () => validate(`${envelope()}\n${delegated()}`, { review: inEnvelope, ...delta }),
      /runner limit mismatch/,
    );
  });
}
for (const delta of [
  { verdict: "APPROVE_WITH_CHANGES" },
  { must: ["fix required"] },
  { should: ["fix recommended"] },
]) {
  test(`a review with ${Object.keys(delta)[0]} outstanding rejects`, () => {
    assert.throws(() => validate(decision(), { review: { ...review, ...delta } }), /clean APPROVE/);
  });
}
for (const key of pins) {
  test(`review and decision must bind the exact ${key}`, () => {
    const wrong = "f".repeat(key === "sourceCommit" ? 40 : 64);
    assert.throws(() => validate(decision({ [key]: wrong })), /decision pin mismatch/);
    assert.throws(
      () => validate(decision(), { review: { ...review, [key]: wrong } }),
      /review pin mismatch/,
    );
  });
}
for (const body of [
  "decision=REVOKED",
  "REVOKED",
  "REVOKED packetSha256=unrelated",
  "decision=REVOKED; decision=APPROVE",
]) {
  test(`a later same-packet revocation rejects without requiring pins: ${body}`, () => {
    const ledgerText = `${decision()}\n- 2026-09-28 | STORAGE-OBJECT stage3-v1 | ${body} | ${owner} | revoke.md`;
    assert.throws(() => validate(ledgerText), /revoked|malformed|duplicate/);
  });
}
test("a revoked envelope cannot authorize a later delegated decision", () => {
  assert.throws(
    () =>
      validate(
        `${envelope()}\n${row("STORAGE-OBJECT stage3-v1 envelope", { decision: "REVOKED" })}\n${delegated()}`,
        { review: inEnvelope },
      ),
    /revoked/,
  );
});
test("another packet's revocation does not revoke this concrete packet", () => {
  const result = validate(
    `${decision()}\n${row("STORAGE-OBJECT other-packet", { decision: "REVOKED" })}`,
  );
  assert.equal(result.decisionLine, 1);
});
test("a newer mismatched decision cannot fall back to an older matching version", () => {
  assert.throws(
    () => validate(`${decision()}\n${decision({ packetSha256: "f".repeat(64) })}`),
    /decision pin mismatch/,
  );
});
test("delegation requires a preceding owner envelope and explicit in-envelope review", () => {
  for (const ledgerText of [
    delegated(),
    `${delegated()}\n${envelope()}`,
    `${envelope({}, coordinator)}\n${delegated()}`,
  ])
    assert.throws(() => validate(ledgerText, { review: inEnvelope }), /preceding owner envelope/);
  assert.throws(() => validate(`${envelope()}\n${delegated()}`), /in-envelope review/);
});
test("an envelope cannot be ambiguous, incomplete or marked for changes", () => {
  assert.throws(
    () => validate(`${envelope()}\n${envelope()}\n${delegated()}`, { review: inEnvelope }),
    /ambiguous/,
  );
  for (const key of ["writes", "iamConfig", "retries"])
    assert.throws(
      () =>
        validate(`${envelope().replace(new RegExp(`; ${key}=[^;|]+`), "")}\n${delegated()}`, {
          review: inEnvelope,
        }),
      /envelope schema/,
    );
  assert.throws(
    () =>
      validate(`${envelope({ decision: "REQUEST_CHANGES" })}\n${delegated()}`, {
        review: inEnvelope,
      }),
    /not approved/,
  );
});
test("duplicate fields and malformed target rows cannot hide later decisions", () => {
  assert.throws(
    () => validate(decision().replace("decision=APPROVE", "decision=APPROVE; decision=APPROVE")),
    /duplicate/,
  );
  assert.throws(
    () =>
      validate(
        `${decision()}\n- 2026-09-28 | STORAGE-OBJECT stage3-v1 | broken | extra | ${owner} | bad.md`,
      ),
    /malformed/,
  );
});
test("numeric bounds must be finite, positive and request counts must be safe integers", () => {
  for (const value of ["NaN", "Infinity", "1e9", "5600.5", "9007199254740993", "0", "-1"])
    assert.throws(
      () => validate(`${envelope({ maxRequests: value })}\n${delegated()}`, { review: inEnvelope }),
      /invalid envelope bound/,
    );
  for (const value of ["NaN", "Infinity", "9e0", "0", "-1"])
    assert.throws(
      () => validate(`${envelope({ reserveUsd: value })}\n${delegated()}`, { review: inEnvelope }),
      /invalid envelope bound/,
    );
  assert.throws(
    () => validate(decision(), { runner: { ...runner, maxRequests: NaN } }),
    /invalid runner/,
  );
  assert.throws(
    () => validate(decision(), { packet: { ...packet, reserveUsd: Infinity } }),
    /invalid packet/,
  );
});
test("hidden data and getters reject without executing the getter", () => {
  let invoked = false;
  const options = { ledgerText: decision(), review, runner };
  Object.defineProperty(options, "packet", {
    enumerable: true,
    get() {
      invoked = true;
      return packet;
    },
  });
  assert.throws(() => validatePresendApproval(options), /invalid approval/);
  assert.equal(invoked, false);
  assert.throws(
    () =>
      validate(decision(), {
        packet: Object.defineProperty({ ...packet }, "secret", { value: "hidden" }),
      }),
    /invalid packet/,
  );
  const must = [];
  Object.defineProperty(must, Symbol("unreviewed"), { value: true });
  assert.throws(() => validate(decision(), { review: { ...review, must } }), /invalid review/);
});
test("a non-owner concrete decision and malformed SHA pins reject", () => {
  assert.throws(() => validate(decision({}, "untrusted")), /owner approval/);
  assert.throws(
    () => validate(decision(), { packet: { ...packet, sourceCommit: "x".repeat(40) } }),
    /invalid packet/,
  );
});

const delegatedEnvelopeActor = "Claude（委任。オーナーの裁量の委任 2026-09-28）";
const delegationReference = "2026-09-28 調整役への委任（本番の送信）";
const basisSubject = "調整役への委任（本番の送信）";
const basis = (actor = owner, date = "2026-09-28") =>
  `- ${date} | ${basisSubject} | decision=APPROVE; sandbox delegation within USD10 | ${actor} | delegation.md`;
const delegatedEnvelope = (values = {}, actor = delegatedEnvelopeActor) =>
  envelope({ 根拠: delegationReference, ...values }, actor);
const delegatedLedger = (values = {}) => `${basis()}\n${delegatedEnvelope(values)}\n${delegated()}`;

for (const actor of [owner, "オーナー"]) {
  test(`the exact delegated envelope actor binds a real owner basis: ${actor}`, () => {
    const result = validate(`${basis(actor)}\n${delegatedEnvelope()}\n${delegated()}`, {
      review: inEnvelope,
    });
    assert.equal(result.envelopeLine, 2);
    assert.equal(result.decisionLine, 3);
    assert.equal(result.delegationLine, 1);
    assert.equal(result.sendAuthorized, false);
  });
}
test("the USD10 delegated envelope boundary covers a smaller concrete reservation", () => {
  assert.equal(
    validate(delegatedLedger({ reserveUsd: 10 }), { review: inEnvelope }).envelopeId,
    envelopeId,
  );
});
test("a delegated envelope above USD10 rejects even when the concrete packet is smaller", () => {
  assert.throws(
    () => validate(delegatedLedger({ reserveUsd: 10.000001 }), { review: inEnvelope }),
    /delegated envelope reservation/,
  );
});
test("owner envelopes retain their authority above the delegation ceiling", () => {
  assert.equal(
    validate(`${envelope({ reserveUsd: 11 })}\n${delegated()}`, { review: inEnvelope }).envelopeId,
    envelopeId,
  );
});
for (const actor of [
  "Claude（委任）",
  "Claude（委任。オーナーの裁量の委任2026-09-28）",
  `${delegatedEnvelopeActor} extra`,
]) {
  test(`a near-match delegated envelope actor rejects: ${actor}`, () => {
    assert.throws(
      () =>
        validate(`${basis()}\n${delegatedEnvelope({}, actor)}\n${delegated()}`, {
          review: inEnvelope,
        }),
      /preceding owner envelope/,
    );
  });
}
for (const [label, reference] of [
  ["wrong date", "2026-09-27 調整役への委任（本番の送信）"],
  ["wrong subject", "2026-09-28 調整役への委任（別の送信）"],
  ["extra suffix", `${delegationReference} extra`],
]) {
  test(`a delegated envelope with ${label} in its reference rejects`, () => {
    assert.throws(
      () => validate(delegatedLedger({ 根拠: reference }), { review: inEnvelope }),
      /delegation reference/,
    );
  });
}
test("a delegated actor cannot omit its basis token", () => {
  assert.throws(
    () =>
      validate(`${basis()}\n${envelope({}, delegatedEnvelopeActor)}\n${delegated()}`, {
        review: inEnvelope,
      }),
    /delegation reference/,
  );
});
for (const [label, prefix] of [
  ["missing", ""],
  ["non-owner", basis(coordinator)],
  ["wrong date", basis(owner, "2026-09-27")],
  ["wrong subject", basis().replace(basisSubject, "調整役への委任（別の送信）")],
  ["malformed columns", basis().replace("| delegation.md", "| extra | delegation.md")],
]) {
  test(`a ${label} owner delegation basis rejects`, () => {
    assert.throws(
      () => validate(`${prefix}\n${delegatedEnvelope()}\n${delegated()}`, { review: inEnvelope }),
      /owner delegation basis/,
    );
  });
}
test("a later owner revocation of the delegation basis rejects", () => {
  const revoked = `- 2026-09-29 | ${basisSubject} | REVOKED | ${owner} | revoked.md`;
  assert.throws(
    () => validate(`${delegatedLedger()}\n${revoked}`, { review: inEnvelope }),
    /delegation revoked/,
  );
});
test("a delegated envelope still requires the concrete version actor and clean pinned review", () => {
  assert.throws(
    () =>
      validate(
        `${basis()}\n${delegatedEnvelope()}\n${decision({ envelopeId }, delegatedEnvelopeActor)}`,
        {
          review: inEnvelope,
        },
      ),
    /owner approval/,
  );
  assert.throws(
    () => validate(delegatedLedger(), { review: { ...inEnvelope, should: ["remaining"] } }),
    /clean APPROVE/,
  );
});
test("revocation and concrete limits remain binding with a delegated envelope", () => {
  assert.throws(
    () =>
      validate(
        `${delegatedLedger()}\n${row("STORAGE-OBJECT stage3-v1", { decision: "REVOKED" })}`,
        {
          review: inEnvelope,
        },
      ),
    /revoked/,
  );
  assert.throws(
    () => validate(delegatedLedger({ maxRequests: 5599 }), { review: inEnvelope }),
    /exceeds owner envelope/,
  );
});
