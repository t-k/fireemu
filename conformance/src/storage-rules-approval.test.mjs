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
  maxRequests: 13296,
  reserveUsd: 2,
};
const pins = ["packetSha256", "sourceCommit", "runnerSha256", "manifestSha256", "fixtureSchemaSha256"];
const review = { verdict: "APPROVE", must: [], should: [], ...Object.fromEntries(pins.map((key) => [key, packet[key]])), envelopeId: null, withinEnvelope: false };
const envelopeId = "STORAGE-RULES-stage3-v1-001";
const coordinator = "Claude（委任。枠の内の承認し直し）";

function envelope(values = {}) {
  const fields = { envelopeId, project: packet.projects.join(","), maxRequests: packet.maxRequests, reserveUsd: packet.reserveUsd, writes: "owned fixtures", iamConfig: "Storage release only", retries: "zero", ...values };
  return `- 2026-09-28 | STORAGE-RULES stage3-v1 envelope | ${Object.entries(fields).map(([key, value]) => `${key}=${value}`).join("; ")} | オーナー（ローカル試験） | private-envelope.md`;
}

function decision({ actor = "オーナー（ローカル試験）", values = {}, subject = "STORAGE-RULES stage3-v1" } = {}) {
  const fields = { decision: "APPROVE", ...Object.fromEntries(pins.map((key) => [key, packet[key]])), ...values };
  return `- 2026-09-28 | ${subject} | ${Object.entries(fields).map(([key, value]) => `${key}=${value}`).join("; ")} | ${actor} | private-packet.md`;
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
  ["maxRequests", "NaN"], ["maxRequests", "Infinity"], ["maxRequests", "1e9"], ["maxRequests", "13296.5"],
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
  assert.throws(() => validate({ ledgerText: ambiguous, packet, review }), /duplicate ledger field/);
});

test("a malformed target row cannot hide a later revocation", async () => {
  const validate = await load();
  const ledgerText = `${decision()}\n- 2026-09-28 | STORAGE-RULES stage3-v1 | decision=REVOKED | extra | オーナー（local） | packet.md`;
  assert.throws(() => validate({ ledgerText, packet, review }), /malformed target ledger row/);
});

test("a revoked envelope cannot be revived by a later coordinator decision", async () => {
  const validate = await load();
  const ledgerText = `${envelope()}\n- 2026-09-28 | STORAGE-RULES stage3-v1 envelope | decision=REVOKED | オーナー（local） | envelope.md\n${decision({ actor: coordinator, values: { envelopeId } })}`;
  assert.throws(() => validate({ ledgerText, packet, review: { ...review, envelopeId, withinEnvelope: true } }), /approval revoked/);
});

for (const [key, value] of [["project", "fireemu-oracle-query"], ["maxRequests", "13295"], ["reserveUsd", "1.999999"]]) {
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
  const ledgerText = `${decision()}\n${decision({ subject: "STORAGE-RULES other-packet", values: { decision: "REVOKED" } })}`;
  assert.equal(validate({ ledgerText, packet, review }).sendAuthorized, false);
});
