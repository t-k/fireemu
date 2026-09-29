import assert from "node:assert/strict";
import test from "node:test";

const packet = {
  taskId: "STORAGE-RULES",
  packetName: "stage3-v1",
  packetSha256: "a".repeat(64),
  sourceCommit: "b".repeat(40),
  runnerSha256: "c".repeat(64),
  manifestSha256: "d".repeat(64),
  fixtureSchemaSha256: "e".repeat(64),
  projects: ["fireemu-oracle-idp", "fireemu-oracle-query"],
  maxRequests: 12328,
  reserveUsd: 2,
};
const pins = ["packetSha256", "sourceCommit", "runnerSha256", "manifestSha256", "fixtureSchemaSha256"];
const review = { verdict: "APPROVE", must: [], should: [], ...Object.fromEntries(pins.map((key) => [key, packet[key]])), envelopeId: null, withinEnvelope: false };
const envelopeId = "STORAGE-RULES-stage3-v1-001";
const coordinator = "Claude（委任。枠の内の承認し直し）";
const delegatedEnvelopeActor = "Claude（委任。オーナーの裁量の委任 2026-09-28）";
const delegationReference = "2026-09-28 調整役への委任（本番の送信）";
const delegationRow = "- 2026-09-28 | 調整役への委任（本番の送信） | decision=APPROVE; local delegation fixture | オーナー（ローカル試験） | private-delegation.md";
const delegationRow395 = "- 2026-09-28 | 調整役への委任（枠の承認） | decision=APPROVE; local delegation fixture | オーナー（ローカル試験） | private-delegation.md";
const delegationRows = `${delegationRow}\n${delegationRow395}`;

function envelope(values = {}) {
  const fields = { envelopeId, project: packet.projects.join(","), maxRequests: packet.maxRequests, reserveUsd: packet.reserveUsd, writes: "owned fixtures", iamConfig: "Storage release only", retries: "zero", ...values };
  return `- 2026-09-28 | STORAGE-RULES stage3-v1 envelope | ${Object.entries(fields).map(([key, value]) => `${key}=${value}`).join("; ")} | オーナー（ローカル試験） | private-envelope.md`;
}

function decision({ actor = "オーナー（ローカル試験）", values = {}, subject = "STORAGE-RULES stage3-v1" } = {}) {
  const fields = { decision: "APPROVE", ...Object.fromEntries(pins.map((key) => [key, packet[key]])), ...values };
  return `- 2026-09-28 | ${subject} | ${Object.entries(fields).map(([key, value]) => `${key}=${value}`).join("; ")} | ${actor} | private-packet.md`;
}

function delegatedEnvelope({ values = {}, actor = delegatedEnvelopeActor } = {}) {
  return envelope({ "根拠": delegationReference, ...values }).replace("オーナー（ローカル試験）", actor);
}

function delegatedLedger({ basis = delegationRows, values = {}, actor = delegatedEnvelopeActor } = {}) {
  return [basis, delegatedEnvelope({ values, actor }), decision({ actor: coordinator, values: { envelopeId } })].filter(Boolean).join("\n");
}

async function load() {
  const module = await import("./storage-rules/approval.mjs").catch(() => ({}));
  assert.equal(typeof module.validatePresendApproval, "function");
  return module.validatePresendApproval;
}

test("a concrete owner decision binds every review and packet pin", async () => {
  const validate = await load();
  const result = validate({ ledgerText: `# Local ledger\n\n${decision()}\n`, packet, review });
  assert.equal(result.status, "APPROVAL_BOUND_LOCAL_ONLY");
  assert.equal(result.decisionLine, 3);
  assert.equal(result.envelopeId, null);
  assert.equal(result.sendAuthorized, false);
});

test("a coordinator decision binds to a preceding owner envelope and an in-envelope review", async () => {
  const validate = await load();
  const ledgerText = `${envelope()}\n${decision({ actor: coordinator, values: { envelopeId } })}\n`;
  const result = validate({ ledgerText, packet, review: { ...review, envelopeId, withinEnvelope: true } });
  assert.equal(result.status, "APPROVAL_BOUND_LOCAL_ONLY");
  assert.equal(result.decisionLine, 2);
  assert.equal(result.envelopeLine, 1);
  assert.equal(result.envelopeId, envelopeId);
});

for (const reserveUsd of [2, 10]) {
  test(`a coordinator envelope with reserveUsd=${reserveUsd} binds to the owner's recorded delegation`, async () => {
    const validate = await load();
    const result = validate({ ledgerText: delegatedLedger({ values: { reserveUsd } }), packet, review: { ...review, envelopeId, withinEnvelope: true } });
    assert.equal(result.envelopeLine, 3);
    assert.equal(result.decisionLine, 4);
    assert.equal(result.envelopeId, envelopeId);
    assert.equal(result.sendAuthorized, false);
  });
}

for (const basis of [
  "",
  `${delegationRow.replace("オーナー（ローカル試験）", delegatedEnvelopeActor)}\n${delegationRow395}`,
  `${delegationRow.replace("2026-09-28 |", "2026-09-27 |")}\n${delegationRow395}`,
  `${delegationRow}\n${delegationRow395.replace("2026-09-28 |", "2026-09-27 |")}`,
  delegationRow,
  delegationRow395,
  `${delegationRow395}\n${delegationRow395}`,
]) {
  test("a delegated envelope requires the referenced owner delegation row", async () => {
    const validate = await load();
    assert.throws(() => validate({ ledgerText: delegatedLedger({ basis }), packet, review: { ...review, envelopeId, withinEnvelope: true } }), /delegated envelope authority required/);
  });
}

for (const reference of [undefined, "2026-09-27 調整役への委任（本番の送信）", `${delegationReference} extra`]) {
  test("a delegated envelope requires the exact delegation reference token", async () => {
    const validate = await load();
    let ledgerText = delegatedLedger({ values: { "根拠": reference } });
    if (reference === undefined) ledgerText = ledgerText.replace(`; 根拠=undefined`, "");
    assert.throws(() => validate({ ledgerText, packet, review: { ...review, envelopeId, withinEnvelope: true } }), /delegated envelope authority required/);
  });
}

for (const actor of [coordinator, "Claude（委任）", `${delegatedEnvelopeActor} extra`]) {
  test("only the exact delegated envelope actor can use the new owner delegation", async () => {
    const validate = await load();
    assert.throws(() => validate({ ledgerText: delegatedLedger({ actor }), packet, review: { ...review, envelopeId, withinEnvelope: true } }), /preceding .*envelope required/);
  });
}

test("a delegated envelope cannot exceed the US$10 task ceiling", async () => {
  const validate = await load();
  assert.throws(() => validate({ ledgerText: delegatedLedger({ values: { reserveUsd: "10.000001" } }), packet, review: { ...review, envelopeId, withinEnvelope: true } }), /delegated envelope exceeds US\$10/);
});

for (const body of ["decision=REVOKED", "decision=REQUEST_CHANGES"]) {
  test("a non-approved owner delegation cannot authorize a coordinator envelope", async () => {
    const validate = await load();
    assert.throws(() => validate({ ledgerText: delegatedLedger({ basis: `${delegationRow.replace("decision=APPROVE", body)}\n${delegationRow395}` }), packet, review: { ...review, envelopeId, withinEnvelope: true } }), /delegated envelope authority required/);
  });
}

test("an ambiguous owner delegation cannot authorize a coordinator envelope", async () => {
  const validate = await load();
  assert.throws(() => validate({ ledgerText: delegatedLedger({ basis: `${delegationRows}\n${delegationRow.replace("decision=APPROVE", "decision=REVOKED")}` }), packet, review: { ...review, envelopeId, withinEnvelope: true } }), /delegated envelope authority required/);
});

test("duplicate decisions in the owner delegation cannot hide its revocation", async () => {
  const validate = await load();
  const basis = `${delegationRow.replace("decision=APPROVE", "decision=APPROVE; decision=REVOKED")}\n${delegationRow395}`;
  assert.throws(() => validate({ ledgerText: delegatedLedger({ basis }), packet, review: { ...review, envelopeId, withinEnvelope: true } }), /delegated envelope authority required/);
});

for (const body of ["decision=REVOKED", "decision=REQUEST_CHANGES", "decision=APPROVE; decision=REVOKED"]) {
  for (const placement of ["before", "after"]) {
    test(`a later owner delegation ${body} is refused ${placement} the envelope decision`, async () => {
      const validate = await load();
      const withdrawal = delegationRow.replace("2026-09-28 |", "2026-09-29 |").replace("decision=APPROVE", body);
      const ledgerText = placement === "before" ? delegatedLedger({ basis: `${delegationRows}\n${withdrawal}` }) : `${delegatedLedger()}\n${withdrawal}`;
      assert.throws(() => validate({ ledgerText, packet, review: { ...review, envelopeId, withinEnvelope: true } }), /delegated envelope authority required/);
    });
  }
}

test("a malformed later owner delegation cannot hide its revocation", async () => {
  const validate = await load();
  const withdrawal = delegationRow.replace("2026-09-28 |", "2026-09-29 |").replace("decision=APPROVE", "decision=REVOKED").replace("| オーナー", "| extra | オーナー");
  assert.throws(() => validate({ ledgerText: `${delegatedLedger()}\n${withdrawal}`, packet, review: { ...review, envelopeId, withinEnvelope: true } }), /delegated envelope authority required/);
});

test("a later approval cannot revive the referenced owner delegation after revocation", async () => {
  const validate = await load();
  const withdrawal = delegationRow.replace("2026-09-28 |", "2026-09-29 |").replace("decision=APPROVE", "decision=REVOKED");
  const reapproval = delegationRow.replace("2026-09-28 |", "2026-09-30 |");
  assert.throws(() => validate({ ledgerText: `${delegatedLedger()}\n${withdrawal}\n${reapproval}`, packet, review: { ...review, envelopeId, withinEnvelope: true } }), /delegated envelope authority required/);
});

test("a malformed owner delegation cannot authorize a coordinator envelope", async () => {
  const validate = await load();
  const basis = `${delegationRow.replace("| オーナー", "| extra | オーナー")}\n${delegationRow395}`;
  assert.throws(() => validate({ ledgerText: delegatedLedger({ basis }), packet, review: { ...review, envelopeId, withinEnvelope: true } }), /delegated envelope authority required/);
});

test("an owner envelope remains accepted independently of the delegation proof", async () => {
  const validate = await load();
  const ledgerText = `${envelope({ reserveUsd: 11 })}\n${decision({ actor: coordinator, values: { envelopeId } })}`;
  assert.equal(validate({ ledgerText, packet, review: { ...review, envelopeId, withinEnvelope: true } }).sendAuthorized, false);
});

test("a later revocation rejects the exact same packet approval", async () => {
  const validate = await load();
  const ledgerText = `${decision()}\n${decision({ values: { decision: "REVOKED" } })}\n`;
  assert.throws(() => validate({ ledgerText, packet, review }), /approval revoked/);
});

test("a same-packet owner reapproval cannot bypass a recorded revocation", async () => {
  const validate = await load();
  const ledgerText = `${decision()}\n${decision({ values: { decision: "REVOKED" } })}\n${decision()}`;
  assert.throws(() => validate({ ledgerText, packet, review }), /approval revoked/);
});

test("a revoked envelope row cannot supply delegated authority", async () => {
  const validate = await load();
  const ledgerText = `${envelope({ decision: "REVOKED" })}\n${decision({ actor: coordinator, values: { envelopeId } })}`;
  assert.throws(() => validate({ ledgerText, packet, review: { ...review, envelopeId, withinEnvelope: true } }), /approval revoked/);
});

for (const field of ["writes", "iamConfig", "retries"]) {
  test(`an owner envelope without ${field} is refused`, async () => {
    const validate = await load();
    const truncated = envelope().replace(new RegExp(`; ${field}=[^;|]+`), "");
    const ledgerText = `${truncated}\n${decision({ actor: coordinator, values: { envelopeId } })}`;
    assert.throws(() => validate({ ledgerText, packet, review: { ...review, envelopeId, withinEnvelope: true } }), /invalid owner envelope schema/);
  });
}

test("an envelope marked REQUEST_CHANGES cannot supply delegated authority", async () => {
  const validate = await load();
  const ledgerText = `${envelope({ decision: "REQUEST_CHANGES" })}\n${decision({ actor: coordinator, values: { envelopeId } })}`;
  assert.throws(() => validate({ ledgerText, packet, review: { ...review, envelopeId, withinEnvelope: true } }), /owner envelope not approved/);
});

for (const [name, delta] of [
  ["non-APPROVE verdict", { verdict: "REQUEST_CHANGES" }],
  ["remaining Must", { must: ["repair required"] }],
  ["remaining Should", { should: ["repair recommended"] }],
]) {
  test(`a review with ${name} cannot admit the packet`, async () => {
    const validate = await load();
    assert.throws(() => validate({ ledgerText: decision(), packet, review: { ...review, ...delta } }), /clean APPROVE review required/);
  });
}

test("matching malformed SHA pins cannot pass the approval check", async () => {
  const validate = await load();
  const invalid = "x".repeat(64);
  assert.throws(() => validate({ ledgerText: decision({ values: { packetSha256: invalid } }), packet: { ...packet, packetSha256: invalid }, review: { ...review, packetSha256: invalid } }), /invalid packet data/);
});

test("hidden packet data is refused", async () => {
  const validate = await load();
  const hidden = Object.defineProperty({ ...packet }, "credential", { value: "local-test-only" });
  assert.throws(() => validate({ ledgerText: decision(), packet: hidden, review }), /invalid packet data/);
});

test("an option getter is refused without invoking it", async () => {
  const validate = await load();
  let touched = false;
  const options = { ledgerText: decision(), review };
  Object.defineProperty(options, "packet", { enumerable: true, get() { touched = true; return packet; } });
  assert.throws(() => validate(options), /invalid approval options data/);
  assert.equal(touched, false);
});

test("hidden review data is refused", async () => {
  const validate = await load();
  const hidden = Object.defineProperty({ ...review }, Symbol("unreviewed"), { value: true });
  assert.throws(() => validate({ ledgerText: decision(), packet, review: hidden }), /invalid review data/);
});

test("project array accessors are refused without invoking them", async () => {
  const validate = await load();
  let touched = false;
  const projects = [...packet.projects];
  Object.defineProperty(projects, "0", { enumerable: true, get() { touched = true; return "fireemu-oracle-idp"; } });
  assert.throws(() => validate({ ledgerText: decision(), packet: { ...packet, projects }, review }), /invalid packet project data/);
  assert.equal(touched, false);
});

test("a single comma-combined project cannot replace the two-project set", async () => {
  const validate = await load();
  assert.throws(() => validate({ ledgerText: decision(), packet: { ...packet, projects: [packet.projects.join(",")] }, review }), /runner limit mismatch/);
});

test("project objects are refused without calling toString", async () => {
  const validate = await load();
  let touched = false;
  const project = { toString() { touched = true; return "fireemu-oracle-idp"; } };
  assert.throws(() => validate({ ledgerText: decision(), packet: { ...packet, projects: [project, "fireemu-oracle-query"] }, review }), /invalid packet project data/);
  assert.equal(touched, false);
});

for (const [key, value] of [
  ["maxRequests", "NaN"], ["maxRequests", "Infinity"], ["maxRequests", "1e9"], ["maxRequests", "12328.5"],
  ["reserveUsd", "NaN"], ["reserveUsd", "Infinity"], ["reserveUsd", "2e0"],
]) {
  test(`an envelope with ${key}=${value} is refused`, async () => {
    const validate = await load();
    const ledgerText = `${envelope({ [key]: value })}\n${decision({ actor: coordinator, values: { envelopeId } })}`;
    assert.throws(() => validate({ ledgerText, packet, review: { ...review, envelopeId, withinEnvelope: true } }), /invalid envelope bound/);
  });
}

for (const delta of [{ maxRequests: 100 }, { reserveUsd: 1 }, { projects: ["fireemu-oracle-query"] }]) {
  test(`the packet cannot change runner limits: ${Object.keys(delta)[0]}`, async () => {
    const validate = await load();
    assert.throws(() => validate({ ledgerText: decision(), packet: { ...packet, ...delta }, review }), /runner limit mismatch/);
  });
}

test("a newer concrete approval cannot fall back to an older matching SHA", async () => {
  const validate = await load();
  const ledgerText = `${decision()}\n${decision({ values: { packetSha256: "f".repeat(64) } })}`;
  assert.throws(() => validate({ ledgerText, packet, review }), /decision pin mismatch/);
});

test("duplicate decision fields cannot hide a revocation", async () => {
  const validate = await load();
  const ambiguous = decision().replace("decision=APPROVE", "decision=REVOKED; decision=APPROVE");
  assert.throws(() => validate({ ledgerText: ambiguous, packet, review }), /approval revoked/);
});

test("a malformed target row cannot hide a later revocation", async () => {
  const validate = await load();
  const ledgerText = `${decision()}\n- 2026-09-28 | STORAGE-RULES stage3-v1 | decision=REVOKED | extra | オーナー（local） | packet.md`;
  assert.throws(() => validate({ ledgerText, packet, review }), /approval revoked/);
});

test("a revoked envelope cannot be revived by a later coordinator decision", async () => {
  const validate = await load();
  const ledgerText = `${envelope()}\n- 2026-09-28 | STORAGE-RULES stage3-v1 envelope | decision=REVOKED | オーナー（local） | envelope.md\n${decision({ actor: coordinator, values: { envelopeId } })}`;
  assert.throws(() => validate({ ledgerText, packet, review: { ...review, envelopeId, withinEnvelope: true } }), /approval revoked/);
});

for (const [key, value] of [["project", "fireemu-oracle-query"], ["maxRequests", "12327"], ["reserveUsd", "1.999999"]]) {
  test(`an owner envelope cannot be exceeded in ${key}`, async () => {
    const validate = await load();
    const ledgerText = `${envelope({ [key]: value })}\n${decision({ actor: coordinator, values: { envelopeId } })}`;
    assert.throws(() => validate({ ledgerText, packet, review: { ...review, envelopeId, withinEnvelope: true } }), /packet exceeds owner envelope/);
  });
}

for (const key of pins) {
  test(`a decision with a different ${key} is refused`, async () => {
    const validate = await load();
    assert.throws(() => validate({ ledgerText: decision({ values: { [key]: "f".repeat(key === "sourceCommit" ? 40 : 64) } }), packet, review }), /decision pin mismatch/);
  });
  test(`a review with a different ${key} is refused`, async () => {
    const validate = await load();
    assert.throws(() => validate({ ledgerText: decision(), packet, review: { ...review, [key]: "f".repeat(key === "sourceCommit" ? 40 : 64) } }), /review pin mismatch/);
  });
}

test("a coordinator cannot approve without the owner's envelope", async () => {
  const validate = await load();
  assert.throws(() => validate({ ledgerText: decision({ actor: coordinator, values: { envelopeId } }), packet, review: { ...review, envelopeId, withinEnvelope: true } }), /preceding owner envelope required/);
});

test("an envelope written after the coordinator decision is refused", async () => {
  const validate = await load();
  const ledgerText = `${decision({ actor: coordinator, values: { envelopeId } })}\n${envelope()}`;
  assert.throws(() => validate({ ledgerText, packet, review: { ...review, envelopeId, withinEnvelope: true } }), /preceding owner envelope required/);
});

test("a delegated review must explicitly affirm the same envelope", async () => {
  const validate = await load();
  const ledgerText = `${envelope()}\n${decision({ actor: coordinator, values: { envelopeId } })}`;
  assert.throws(() => validate({ ledgerText, packet, review: { ...review, envelopeId } }), /in-envelope review required/);
});

test("duplicate envelope IDs cannot supply conflicting owner bounds", async () => {
  const validate = await load();
  const ledgerText = `${envelope()}\n${envelope({ maxRequests: "100" })}\n${decision({ actor: coordinator, values: { envelopeId } })}`;
  assert.throws(() => validate({ ledgerText, packet, review: { ...review, envelopeId, withinEnvelope: true } }), /ambiguous owner envelope/);
});

test("a direct owner approval cannot use a review bound to another envelope", async () => {
  const validate = await load();
  assert.throws(() => validate({ ledgerText: decision(), packet, review: { ...review, envelopeId, withinEnvelope: true } }), /direct review envelope mismatch/);
});

test("another packet's revocation does not revoke this packet", async () => {
  const validate = await load();
  const other = { packetSha256: "9".repeat(64), sourceCommit: "8".repeat(40) };
  const ledgerText = `${decision()}\n${decision({ subject: "STORAGE-RULES other-packet", values: { decision: "REVOKED", ...other } })}`;
  assert.equal(validate({ ledgerText, packet, review }).sendAuthorized, false);
});

// Revocation spellings (docs.local/issues/open/sandbox-approval-gates-fail-open-on-revocation-spellings.md, rules 1-5).
function note(subject, body, tail = " | オーナー（local） | note.md") {
  return `- 2026-09-29 | ${subject} | ${body}${tail}`;
}
const sha = packet.packetSha256;
const laneSubject = "STORAGE-RULES stage3-v1";
const laneRevocations = {
  "lowercase revoked": note(laneSubject, `revoked packetSha256=${sha}`),
  "mixed case Revoked": note(laneSubject, `Revoked packetSha256=${sha}`),
  "full-width REVOKED": note(laneSubject, `ＲＥＶＯＫＥＤ packetSha256=${sha}`),
  "REVOKED with a correction suffix": note(laneSubject, `REVOKED（訂正） packetSha256=${sha}`),
  "REVOKED with a full-width colon": note(laneSubject, `REVOKED：packetSha256=${sha}`),
  "four columns": `- 2026-09-29 | ${laneSubject} | decision=REVOKED; packetSha256=${sha} | note.md`,
  "six columns": `- 2026-09-29 | ${laneSubject} | decision=REVOKED; packetSha256=${sha} | オーナー（local） | note.md | extra`,
  "upper-case digest": note(laneSubject, `decision=REVOKED; packetSha256=${sha.toUpperCase()}`),
  "packet SHA only under another subject": note("anything else", `REVOKED packetSha256=${sha}`),
  "full source commit only": note("anything else", `REVOKED sourceCommit=${packet.sourceCommit}`),
  "eight-digit source commit prefix": note("anything else", `REVOKED ${packet.sourceCommit.slice(0, 8)}`),
  "upper-case source commit prefix": note("anything else", `REVOKED ${"B".repeat(12)}`),
  "revoked in a later column": note(laneSubject, `packetSha256=${sha}; 理由=test; REVOKED`),
  "full-width subject spelling": note("ＳＴＯＲＡＧＥ－ＲＵＬＥＳ　stage3-v1", "decision=REVOKED"),
  "lane-wide row": note("STORAGE-RULES", "REVOKED"),
  "lane-wide row with a full-width qualifier": note("STORAGE-RULES（訂正）", "REVOKED"),
  "lane-wide row with an ASCII qualifier": note("STORAGE-RULES(訂正)", "REVOKED"),
  "lane-wide row with two qualifiers": note("STORAGE-RULES（訂正）（取消）", "REVOKED"),
  "lane-wide row with a spaced qualifier": note("STORAGE-RULES （取消）", "revoked"),
  "lane-wide row with an empty qualifier": note("STORAGE-RULES（）", "REVOKED"),
  "lane-wide row with a leading qualifier": note("（訂正）STORAGE-RULES", "REVOKED"),
  "lane-wide row with a nested qualifier": note("STORAGE-RULES（訂正（旧））", "REVOKED"),
  "lane-wide row with a middle qualifier": note("STORAGE-（訂正）RULES", "REVOKED"),
  "subject with a full-width qualifier": note("STORAGE-RULES stage3-v1（取消）", "REVOKED"),
  "subject with an ASCII qualifier": note("STORAGE-RULES stage3-v1(取消)", "revoked"),
  "free text line": `Note: REVOKED ${sha} by the owner`,
};
for (const [name, row] of Object.entries(laneRevocations)) {
  for (const placement of ["before", "after"]) {
    test(`a revocation spelled as ${name} stops the approval ${placement} it`, async () => {
      const validate = await load();
      const ledgerText = placement === "before" ? `${row}\n${decision()}` : `${decision()}\n${row}`;
      assert.throws(() => validate({ ledgerText, packet, review }), /approval revoked/);
    });
  }
}

test("an envelope ID named on a revoked line stops a delegated approval", async () => {
  const validate = await load();
  const ledgerText = `${envelope()}\n${decision({ actor: coordinator, values: { envelopeId } })}\n${note("anything else", `revoked ${envelopeId.toLowerCase()}`)}`;
  assert.throws(() => validate({ ledgerText, packet, review: { ...review, envelopeId, withinEnvelope: true } }), /approval revoked/);
});

for (const [name, row] of Object.entries({
  "another lane with other hashes": note("STORAGE-OBJECT stage3-v1", `decision=REVOKED; packetSha256=${"9".repeat(64)}; sourceCommit=${"8".repeat(40)}`),
  "another packet of this lane with other hashes": note("STORAGE-RULES other-packet", `REVOKED packetSha256=${"9".repeat(64)}`),
  "prose without an identifier": "A revoked test user is only mentioned in this note.",
  "a similar but different commit prefix": note("anything else", `REVOKED ${"b".repeat(7)}0`),
  "another packet of this lane with a full-width qualifier": note("STORAGE-RULES other-packet（訂正）", `REVOKED packetSha256=${"9".repeat(64)}`),
  "another packet of this lane with an ASCII qualifier": note("STORAGE-RULES other-packet(取消)", `REVOKED packetSha256=${"9".repeat(64)}`),
  "another lane with a qualifier": note("STORAGE-OBJECT（訂正）", "REVOKED"),
  "a longer task name with a qualifier": note("STORAGE-RULES-EXTRA（訂正）", "REVOKED"),
})) {
  test(`a revocation of ${name} does not stop this approval`, async () => {
    const validate = await load();
    assert.equal(validate({ ledgerText: `${decision()}\n${row}`, packet, review }).sendAuthorized, false);
  });
}

const delegationRevocations = {
  "the send delegation": note("調整役への委任（本番の送信）", "decision=REVOKED"),
  "lowercase revoked": note("調整役への委任（本番の送信）", "revoked"),
  "half-width parentheses": note("調整役への委任(本番の送信)", "REVOKED"),
  "the envelope delegation": note("調整役への委任（枠の承認）", "decision=REVOKED"),
  "a correction suffix": note("調整役への委任（枠の承認）（訂正）", "REVOKED"),
  "an unscoped delegation": note("調整役への委任", "REVOKED"),
  "four columns": "- 2026-09-29 | 調整役への委任（枠の承認） | decision=REVOKED | note.md",
  "the marker inside the body only": note("owner note", "調整役への委任は revoked"),
  "full-width REVOKED": note("調整役への委任（本番の送信）", "ＲＥＶＯＫＥＤ"),
};
for (const [name, row] of Object.entries(delegationRevocations)) {
  for (const placement of ["before", "after"]) {
    test(`a delegation revocation (${name}) refuses coordinator rows ${placement} them`, async () => {
      const validate = await load();
      const ledgerText = placement === "before" ? `${row}\n${delegatedLedger()}` : `${delegatedLedger()}\n${row}`;
      assert.throws(() => validate({ ledgerText, packet, review: { ...review, envelopeId, withinEnvelope: true } }), /delegated envelope authority required/);
    });
  }
  test(`a delegation revocation (${name}) also refuses a coordinator decision inside an owner envelope`, async () => {
    const validate = await load();
    const ledgerText = `${envelope()}\n${decision({ actor: coordinator, values: { envelopeId } })}\n${row}`;
    assert.throws(() => validate({ ledgerText, packet, review: { ...review, envelopeId, withinEnvelope: true } }), /delegated envelope authority required/);
  });
  test(`a delegation revocation (${name}) leaves a direct owner approval valid`, async () => {
    const validate = await load();
    assert.equal(validate({ ledgerText: `${decision()}\n${row}`, packet, review }).sendAuthorized, false);
  });
}

test("a delegated envelope needs both the send and the envelope delegation rows", async () => {
  const validate = await load();
  const options = { packet, review: { ...review, envelopeId, withinEnvelope: true } };
  assert.equal(validate({ ledgerText: delegatedLedger(), ...options }).sendAuthorized, false);
  for (const basis of [delegationRow, delegationRow395]) {
    assert.throws(() => validate({ ledgerText: delegatedLedger({ basis }), ...options }), /delegated envelope authority required/);
  }
});

test("the revocation scanner constants agree with the constants the approval uses", async () => {
  const module = await import("./storage-rules/ledger-revocation.mjs").catch(() => ({}));
  assert.equal(module.DELEGATION_SUBJECTS?.send, "調整役への委任（本番の送信）");
  assert.equal(module.DELEGATION_SUBJECTS?.envelope, "調整役への委任（枠の承認）");
  assert.equal(typeof module.normalizeLedgerText, "function");
  for (const subject of Object.values(module.DELEGATION_SUBJECTS ?? {})) {
    assert.ok(module.normalizeLedgerText(subject).includes(module.NORMALIZED_DELEGATION_MARKER));
    assert.ok(module.normalizeLedgerText(subject.replaceAll("（", "(").replaceAll("）", ")")).includes(module.NORMALIZED_DELEGATION_MARKER));
  }
  assert.equal(module.NORMALIZED_DELEGATION_MARKER, module.normalizeLedgerText("調整役への委任"));
  assert.equal(module.normalizeLedgerText("ＲＥＶＯＫＥＤ（Ａ）"), "revoked(a)");
});

test("the historical revocation allowlist is closed and every entry carries a reason", async () => {
  const module = await import("./storage-rules/ledger-revocation.mjs").catch(() => ({}));
  const list = module.HISTORICAL_REVOCATION_ALLOWLIST;
  assert.ok(Array.isArray(list) && Object.isFrozen(list));
  for (const entry of list) {
    assert.deepEqual(Object.keys(entry).sort(), ["reason", "sha256"]);
    assert.match(entry.sha256, /^[0-9a-f]{64}$/);
    assert.ok(typeof entry.reason === "string" && entry.reason.length >= 20);
  }
  assert.equal(new Set(list.map((entry) => entry.sha256)).size, list.length);
});

test("an allowlisted historical row is ignored only when its SHA-256 matches exactly", async () => {
  const module = await import("./storage-rules/ledger-revocation.mjs").catch(() => ({}));
  const line = "- 2026-09-27 | STORAGE-RULES | historical prose about a revoked test user | オーナー（local） | note.md";
  const scan = (text, allowlist) => module.scanRevocations({ ledgerText: text, taskId: "STORAGE-RULES", subject: laneSubject, packetSha256: sha, sourceCommit: packet.sourceCommit, envelopeId: null, allowlist });
  assert.deepEqual(scan(line, []).lane, [1]);
  const allowlist = [{ sha256: module.rowSha256(line), reason: "historical prose, not a revocation of any packet" }];
  assert.deepEqual(scan(line, allowlist).lane, []);
  assert.deepEqual(scan(`${line} `, allowlist).lane, [1]);
  assert.deepEqual(scan(line.replace("2026-09-27", "2026-09-28"), allowlist).lane, [1]);
  assert.deepEqual(scan(`${line}\n${line}`, allowlist).lane, []);
});

test("the scanner compares the packet SHA and the source commit case-insensitively", async () => {
  const module = await import("./storage-rules/ledger-revocation.mjs").catch(() => ({}));
  const scan = (text) => module.scanRevocations({ ledgerText: text, taskId: "STORAGE-RULES", subject: laneSubject, packetSha256: sha.toUpperCase(), sourceCommit: packet.sourceCommit.toUpperCase(), envelopeId: envelopeId.toUpperCase() });
  assert.deepEqual(scan(`revoked ${sha}`).lane, [1]);
  assert.deepEqual(scan(`revoked ${packet.sourceCommit.slice(0, 8)}`).lane, [1]);
  assert.deepEqual(scan(`revoked ${envelopeId.toLowerCase()}`).lane, [1]);
});

test("a malformed or duplicated target row that revokes nothing is still refused", async () => {
  const validate = await load();
  const malformed = `${decision()}\n- 2026-09-29 | ${laneSubject} | decision=APPROVE | extra | オーナー（local） | note.md`;
  assert.throws(() => validate({ ledgerText: malformed, packet, review }), /malformed target ledger row/);
  const duplicated = decision().replace("decision=APPROVE", "decision=APPROVE; decision=APPROVE");
  assert.throws(() => validate({ ledgerText: duplicated, packet, review }), /duplicate ledger field/);
});

test("the approved request limit is the declared ID count per recording, doubled for two recordings", async () => {
  const counter = await import("./storage-rules/request-counter.mjs");
  const approval = await import("./storage-rules/approval.mjs");
  assert.equal(counter.DECLARED_REQUESTS_PER_RECORDING, 6164);
  assert.equal(approval.DRAFT_STAGE3_APPROVAL_LIMITS.maxRequests, 2 * 6164);
  assert.equal(approval.DRAFT_STAGE3_APPROVAL_LIMITS.maxRequests, 12328);
  const validate = await load();
  assert.throws(() => validate({ ledgerText: decision(), packet: { ...packet, maxRequests: 13296 }, review }), /runner limit mismatch/);
});
