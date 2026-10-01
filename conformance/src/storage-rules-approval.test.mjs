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
  maxRequests: 12344,
  reserveUsd: 2,
};
const pins = [
  "packetSha256",
  "sourceCommit",
  "runnerSha256",
  "manifestSha256",
  "fixtureSchemaSha256",
];
const review = {
  verdict: "APPROVE",
  must: [],
  should: [],
  ...Object.fromEntries(pins.map((key) => [key, packet[key]])),
  envelopeId: null,
  withinEnvelope: false,
};
const envelopeId = "STORAGE-RULES-stage3-v1-001";
const coordinator = "Claude（委任。枠の内の承認し直し）";
const delegatedEnvelopeActor = "Claude（委任。オーナーの裁量の委任 2026-09-28）";
const delegationReference = "2026-09-28 調整役への委任（本番の送信）";
const delegationRow =
  "- 2026-09-28 | 調整役への委任（本番の送信） | decision=APPROVE; local delegation fixture | オーナー（ローカル試験） | private-delegation.md";
const delegationRow395 =
  "- 2026-09-28 | 調整役への委任（枠の承認） | decision=APPROVE; local delegation fixture | オーナー（ローカル試験） | private-delegation.md";
const delegationRows = `${delegationRow}\n${delegationRow395}`;

function envelope(values = {}) {
  const fields = {
    envelopeId,
    project: packet.projects.join(","),
    maxRequests: packet.maxRequests,
    reserveUsd: packet.reserveUsd,
    writes: "owned fixtures",
    iamConfig: "Storage release only",
    retries: "zero",
    ...values,
  };
  return `- 2026-09-28 | STORAGE-RULES stage3-v1 envelope | ${Object.entries(fields)
    .map(([key, value]) => `${key}=${value}`)
    .join("; ")} | オーナー（ローカル試験） | private-envelope.md`;
}

function decision({
  actor = "オーナー（ローカル試験）",
  values = {},
  subject = "STORAGE-RULES stage3-v1",
} = {}) {
  const fields = {
    decision: "APPROVE",
    ...Object.fromEntries(pins.map((key) => [key, packet[key]])),
    ...values,
  };
  return `- 2026-09-28 | ${subject} | ${Object.entries(fields)
    .map(([key, value]) => `${key}=${value}`)
    .join("; ")} | ${actor} | private-packet.md`;
}

function delegatedEnvelope({ values = {}, actor = delegatedEnvelopeActor } = {}) {
  return envelope({ 根拠: delegationReference, ...values }).replace(
    "オーナー（ローカル試験）",
    actor,
  );
}

function delegatedLedger({
  basis = delegationRows,
  values = {},
  actor = delegatedEnvelopeActor,
} = {}) {
  return [
    basis,
    delegatedEnvelope({ values, actor }),
    decision({ actor: coordinator, values: { envelopeId } }),
  ]
    .filter(Boolean)
    .join("\n");
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
  const result = validate({
    ledgerText,
    packet,
    review: { ...review, envelopeId, withinEnvelope: true },
  });
  assert.equal(result.status, "APPROVAL_BOUND_LOCAL_ONLY");
  assert.equal(result.decisionLine, 2);
  assert.equal(result.envelopeLine, 1);
  assert.equal(result.envelopeId, envelopeId);
});

for (const reserveUsd of [2, 10]) {
  test(`a coordinator envelope with reserveUsd=${reserveUsd} binds to the owner's recorded delegation`, async () => {
    const validate = await load();
    const result = validate({
      ledgerText: delegatedLedger({ values: { reserveUsd } }),
      packet,
      review: { ...review, envelopeId, withinEnvelope: true },
    });
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
    assert.throws(
      () =>
        validate({
          ledgerText: delegatedLedger({ basis }),
          packet,
          review: { ...review, envelopeId, withinEnvelope: true },
        }),
      /delegated envelope authority required/,
    );
  });
}

for (const reference of [
  undefined,
  "2026-09-27 調整役への委任（本番の送信）",
  `${delegationReference} extra`,
]) {
  test("a delegated envelope requires the exact delegation reference token", async () => {
    const validate = await load();
    let ledgerText = delegatedLedger({ values: { 根拠: reference } });
    if (reference === undefined) ledgerText = ledgerText.replace(`; 根拠=undefined`, "");
    assert.throws(
      () =>
        validate({ ledgerText, packet, review: { ...review, envelopeId, withinEnvelope: true } }),
      /delegated envelope authority required/,
    );
  });
}

for (const actor of [coordinator, "Claude（委任）", `${delegatedEnvelopeActor} extra`]) {
  test("only the exact delegated envelope actor can use the new owner delegation", async () => {
    const validate = await load();
    assert.throws(
      () =>
        validate({
          ledgerText: delegatedLedger({ actor }),
          packet,
          review: { ...review, envelopeId, withinEnvelope: true },
        }),
      /preceding .*envelope required/,
    );
  });
}

test("a delegated envelope cannot exceed the US$10 task ceiling", async () => {
  const validate = await load();
  assert.throws(
    () =>
      validate({
        ledgerText: delegatedLedger({ values: { reserveUsd: "10.000001" } }),
        packet,
        review: { ...review, envelopeId, withinEnvelope: true },
      }),
    /delegated envelope exceeds US\$10/,
  );
});

for (const body of ["decision=REVOKED", "decision=REQUEST_CHANGES"]) {
  test("a non-approved owner delegation cannot authorize a coordinator envelope", async () => {
    const validate = await load();
    assert.throws(
      () =>
        validate({
          ledgerText: delegatedLedger({
            basis: `${delegationRow.replace("decision=APPROVE", body)}\n${delegationRow395}`,
          }),
          packet,
          review: { ...review, envelopeId, withinEnvelope: true },
        }),
      /delegated envelope authority required/,
    );
  });
}

test("an ambiguous owner delegation cannot authorize a coordinator envelope", async () => {
  const validate = await load();
  assert.throws(
    () =>
      validate({
        ledgerText: delegatedLedger({
          basis: `${delegationRows}\n${delegationRow.replace("decision=APPROVE", "decision=REVOKED")}`,
        }),
        packet,
        review: { ...review, envelopeId, withinEnvelope: true },
      }),
    /delegated envelope authority required/,
  );
});

test("duplicate decisions in the owner delegation cannot hide its revocation", async () => {
  const validate = await load();
  const basis = `${delegationRow.replace("decision=APPROVE", "decision=APPROVE; decision=REVOKED")}\n${delegationRow395}`;
  assert.throws(
    () =>
      validate({
        ledgerText: delegatedLedger({ basis }),
        packet,
        review: { ...review, envelopeId, withinEnvelope: true },
      }),
    /delegated envelope authority required/,
  );
});

for (const body of [
  "decision=REVOKED",
  "decision=REQUEST_CHANGES",
  "decision=APPROVE; decision=REVOKED",
]) {
  for (const placement of ["before", "after"]) {
    test(`a later owner delegation ${body} is refused ${placement} the envelope decision`, async () => {
      const validate = await load();
      const withdrawal = delegationRow
        .replace("2026-09-28 |", "2026-09-29 |")
        .replace("decision=APPROVE", body);
      const ledgerText =
        placement === "before"
          ? delegatedLedger({ basis: `${delegationRows}\n${withdrawal}` })
          : `${delegatedLedger()}\n${withdrawal}`;
      assert.throws(
        () =>
          validate({ ledgerText, packet, review: { ...review, envelopeId, withinEnvelope: true } }),
        /delegated envelope authority required/,
      );
    });
  }
}

test("a malformed later owner delegation cannot hide its revocation", async () => {
  const validate = await load();
  const withdrawal = delegationRow
    .replace("2026-09-28 |", "2026-09-29 |")
    .replace("decision=APPROVE", "decision=REVOKED")
    .replace("| オーナー", "| extra | オーナー");
  assert.throws(
    () =>
      validate({
        ledgerText: `${delegatedLedger()}\n${withdrawal}`,
        packet,
        review: { ...review, envelopeId, withinEnvelope: true },
      }),
    /delegated envelope authority required/,
  );
});

test("a later approval cannot revive the referenced owner delegation after revocation", async () => {
  const validate = await load();
  const withdrawal = delegationRow
    .replace("2026-09-28 |", "2026-09-29 |")
    .replace("decision=APPROVE", "decision=REVOKED");
  const reapproval = delegationRow.replace("2026-09-28 |", "2026-09-30 |");
  assert.throws(
    () =>
      validate({
        ledgerText: `${delegatedLedger()}\n${withdrawal}\n${reapproval}`,
        packet,
        review: { ...review, envelopeId, withinEnvelope: true },
      }),
    /delegated envelope authority required/,
  );
});

test("a malformed owner delegation cannot authorize a coordinator envelope", async () => {
  const validate = await load();
  const basis = `${delegationRow.replace("| オーナー", "| extra | オーナー")}\n${delegationRow395}`;
  assert.throws(
    () =>
      validate({
        ledgerText: delegatedLedger({ basis }),
        packet,
        review: { ...review, envelopeId, withinEnvelope: true },
      }),
    /delegated envelope authority required/,
  );
});

test("an owner envelope remains accepted independently of the delegation proof", async () => {
  const validate = await load();
  const ledgerText = `${envelope({ reserveUsd: 11 })}\n${decision({ actor: coordinator, values: { envelopeId } })}`;
  assert.equal(
    validate({ ledgerText, packet, review: { ...review, envelopeId, withinEnvelope: true } })
      .sendAuthorized,
    false,
  );
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
  assert.throws(
    () => validate({ ledgerText, packet, review: { ...review, envelopeId, withinEnvelope: true } }),
    /approval revoked/,
  );
});

for (const field of ["writes", "iamConfig", "retries"]) {
  test(`an owner envelope without ${field} is refused`, async () => {
    const validate = await load();
    const truncated = envelope().replace(new RegExp(`; ${field}=[^;|]+`), "");
    const ledgerText = `${truncated}\n${decision({ actor: coordinator, values: { envelopeId } })}`;
    assert.throws(
      () =>
        validate({ ledgerText, packet, review: { ...review, envelopeId, withinEnvelope: true } }),
      /invalid owner envelope schema/,
    );
  });
}

test("an envelope marked REQUEST_CHANGES cannot supply delegated authority", async () => {
  const validate = await load();
  const ledgerText = `${envelope({ decision: "REQUEST_CHANGES" })}\n${decision({ actor: coordinator, values: { envelopeId } })}`;
  assert.throws(
    () => validate({ ledgerText, packet, review: { ...review, envelopeId, withinEnvelope: true } }),
    /owner envelope not approved/,
  );
});

for (const [name, delta] of [
  ["non-APPROVE verdict", { verdict: "REQUEST_CHANGES" }],
  ["remaining Must", { must: ["repair required"] }],
  ["remaining Should", { should: ["repair recommended"] }],
]) {
  test(`a review with ${name} cannot admit the packet`, async () => {
    const validate = await load();
    assert.throws(
      () => validate({ ledgerText: decision(), packet, review: { ...review, ...delta } }),
      /clean APPROVE review required/,
    );
  });
}

test("matching malformed SHA pins cannot pass the approval check", async () => {
  const validate = await load();
  const invalid = "x".repeat(64);
  assert.throws(
    () =>
      validate({
        ledgerText: decision({ values: { packetSha256: invalid } }),
        packet: { ...packet, packetSha256: invalid },
        review: { ...review, packetSha256: invalid },
      }),
    /invalid packet data/,
  );
});

test("hidden packet data is refused", async () => {
  const validate = await load();
  const hidden = Object.defineProperty({ ...packet }, "credential", { value: "local-test-only" });
  assert.throws(
    () => validate({ ledgerText: decision(), packet: hidden, review }),
    /invalid packet data/,
  );
});

test("an option getter is refused without invoking it", async () => {
  const validate = await load();
  let touched = false;
  const options = { ledgerText: decision(), review };
  Object.defineProperty(options, "packet", {
    enumerable: true,
    get() {
      touched = true;
      return packet;
    },
  });
  assert.throws(() => validate(options), /invalid approval options data/);
  assert.equal(touched, false);
});

test("hidden review data is refused", async () => {
  const validate = await load();
  const hidden = Object.defineProperty({ ...review }, Symbol("unreviewed"), { value: true });
  assert.throws(
    () => validate({ ledgerText: decision(), packet, review: hidden }),
    /invalid review data/,
  );
});

test("project array accessors are refused without invoking them", async () => {
  const validate = await load();
  let touched = false;
  const projects = [...packet.projects];
  Object.defineProperty(projects, "0", {
    enumerable: true,
    get() {
      touched = true;
      return "fireemu-oracle-idp";
    },
  });
  assert.throws(
    () => validate({ ledgerText: decision(), packet: { ...packet, projects }, review }),
    /invalid packet project data/,
  );
  assert.equal(touched, false);
});

test("a single comma-combined project cannot replace the two-project set", async () => {
  const validate = await load();
  assert.throws(
    () =>
      validate({
        ledgerText: decision(),
        packet: { ...packet, projects: [packet.projects.join(",")] },
        review,
      }),
    /runner limit mismatch/,
  );
});

test("project objects are refused without calling toString", async () => {
  const validate = await load();
  let touched = false;
  const project = {
    toString() {
      touched = true;
      return "fireemu-oracle-idp";
    },
  };
  assert.throws(
    () =>
      validate({
        ledgerText: decision(),
        packet: { ...packet, projects: [project, "fireemu-oracle-query"] },
        review,
      }),
    /invalid packet project data/,
  );
  assert.equal(touched, false);
});

for (const [key, value] of [
  ["maxRequests", "NaN"],
  ["maxRequests", "Infinity"],
  ["maxRequests", "1e9"],
  ["maxRequests", "12344.5"],
  ["reserveUsd", "NaN"],
  ["reserveUsd", "Infinity"],
  ["reserveUsd", "2e0"],
]) {
  test(`an envelope with ${key}=${value} is refused`, async () => {
    const validate = await load();
    const ledgerText = `${envelope({ [key]: value })}\n${decision({ actor: coordinator, values: { envelopeId } })}`;
    assert.throws(
      () =>
        validate({ ledgerText, packet, review: { ...review, envelopeId, withinEnvelope: true } }),
      /invalid envelope bound/,
    );
  });
}

for (const delta of [
  { maxRequests: 100 },
  { reserveUsd: 1 },
  { projects: ["fireemu-oracle-query"] },
]) {
  test(`the packet cannot change runner limits: ${Object.keys(delta)[0]}`, async () => {
    const validate = await load();
    assert.throws(
      () => validate({ ledgerText: decision(), packet: { ...packet, ...delta }, review }),
      /runner limit mismatch/,
    );
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
  assert.throws(
    () => validate({ ledgerText, packet, review: { ...review, envelopeId, withinEnvelope: true } }),
    /approval revoked/,
  );
});

for (const [key, value] of [
  ["project", "fireemu-oracle-query"],
  ["maxRequests", "12343"],
  ["reserveUsd", "1.999999"],
]) {
  test(`an owner envelope cannot be exceeded in ${key}`, async () => {
    const validate = await load();
    const ledgerText = `${envelope({ [key]: value })}\n${decision({ actor: coordinator, values: { envelopeId } })}`;
    assert.throws(
      () =>
        validate({ ledgerText, packet, review: { ...review, envelopeId, withinEnvelope: true } }),
      /packet exceeds owner envelope/,
    );
  });
}

for (const key of pins) {
  test(`a decision with a different ${key} is refused`, async () => {
    const validate = await load();
    assert.throws(
      () =>
        validate({
          ledgerText: decision({ values: { [key]: "f".repeat(key === "sourceCommit" ? 40 : 64) } }),
          packet,
          review,
        }),
      /decision pin mismatch/,
    );
  });
  test(`a review with a different ${key} is refused`, async () => {
    const validate = await load();
    assert.throws(
      () =>
        validate({
          ledgerText: decision(),
          packet,
          review: { ...review, [key]: "f".repeat(key === "sourceCommit" ? 40 : 64) },
        }),
      /review pin mismatch/,
    );
  });
}

test("a coordinator cannot approve without the owner's envelope", async () => {
  const validate = await load();
  assert.throws(
    () =>
      validate({
        ledgerText: decision({ actor: coordinator, values: { envelopeId } }),
        packet,
        review: { ...review, envelopeId, withinEnvelope: true },
      }),
    /preceding owner envelope required/,
  );
});

test("an envelope written after the coordinator decision is refused", async () => {
  const validate = await load();
  const ledgerText = `${decision({ actor: coordinator, values: { envelopeId } })}\n${envelope()}`;
  assert.throws(
    () => validate({ ledgerText, packet, review: { ...review, envelopeId, withinEnvelope: true } }),
    /preceding owner envelope required/,
  );
});

test("a delegated review must explicitly affirm the same envelope", async () => {
  const validate = await load();
  const ledgerText = `${envelope()}\n${decision({ actor: coordinator, values: { envelopeId } })}`;
  assert.throws(
    () => validate({ ledgerText, packet, review: { ...review, envelopeId } }),
    /in-envelope review required/,
  );
});

test("duplicate envelope IDs cannot supply conflicting owner bounds", async () => {
  const validate = await load();
  const ledgerText = `${envelope()}\n${envelope({ maxRequests: "100" })}\n${decision({ actor: coordinator, values: { envelopeId } })}`;
  assert.throws(
    () => validate({ ledgerText, packet, review: { ...review, envelopeId, withinEnvelope: true } }),
    /ambiguous owner envelope/,
  );
});

test("a direct owner approval cannot use a review bound to another envelope", async () => {
  const validate = await load();
  assert.throws(
    () =>
      validate({
        ledgerText: decision(),
        packet,
        review: { ...review, envelopeId, withinEnvelope: true },
      }),
    /direct review envelope mismatch/,
  );
});

test("another packet's revocation does not revoke this packet", async () => {
  const validate = await load();
  const other = { packetSha256: "9".repeat(64), sourceCommit: "8".repeat(40) };
  const consumed = `- 2026-09-28 | STORAGE-RULES other-packet | decision=REVOKED; packetSha256=${other.packetSha256}; sourceCommit=${other.sourceCommit} | オーナー（local） | packet.md`;
  const ledgerText = `${decision({ subject: "STORAGE-RULES other-packet", values: other })}\n${decision()}\n${consumed}`;
  assert.equal(validate({ ledgerText, packet, review }).sendAuthorized, false);
});

// The envelope and version lines the packet template asks the coordinator to write, filled in with test values: the gate must admit exactly those.
test("the packet template's own envelope and version lines are admitted, and a semicolon inside a value is refused", async () => {
  const validate = await load();
  const name = "stage3-v2";
  const id = "STORAGE-RULES-stage3-v2-001";
  const writes =
    "owned objects under STORAGE-RULES/<run>/, run documents, run Auth users incl. validSince, at most 4 Rulesets per recording, bucket-specific firebase.storage release create/update/delete ending absent";
  const iam =
    "none (IAM read-only preflight, no API enablement, no Firestore Rules, index, Auth config or API key change)";
  const envelopeLine = (iamConfig) =>
    `- 2026-09-29 | STORAGE-RULES ${name} envelope | envelopeId=${id}; project=${packet.projects.join(",")}; maxRequests=12344; reserveUsd=2; writes=${writes}; iamConfig=${iamConfig}; retries=none; onStop=needs-recovery-lock-held; 根拠=${delegationReference} | ${delegatedEnvelopeActor} | private.md`;
  const versionLine = `- 2026-09-29 | STORAGE-RULES ${name} | decision=APPROVE; ${pins.map((key) => `${key}=${packet[key]}`).join("; ")}; envelopeId=${id} | ${coordinator} | private.md`;
  const named = { ...packet, packetName: name };
  const reviewed = { ...review, envelopeId: id, withinEnvelope: true };
  const admitted = validate({
    ledgerText: [delegationRows, envelopeLine(iam), versionLine].join("\n"),
    packet: named,
    review: reviewed,
  });
  assert.deepEqual(
    [admitted.status, admitted.envelopeId, admitted.sendAuthorized],
    ["APPROVAL_BOUND_LOCAL_ONLY", id, false],
  );
  // The same envelope with semicolons inside the parenthesis is a malformed row, not an admission.
  assert.throws(
    () =>
      validate({
        ledgerText: [
          delegationRows,
          envelopeLine(iam.replaceAll(", no ", "; no ")),
          versionLine,
        ].join("\n"),
        packet: named,
        review: reviewed,
      }),
    /malformed target ledger row/,
  );
  // A pipe inside a value moves the columns and is refused as well.
  assert.throws(() =>
    validate({
      ledgerText: [delegationRows, envelopeLine(`${iam} | x`), versionLine].join("\n"),
      packet: named,
      review: reviewed,
    }),
  );
});

// Revocation spellings (docs.local/issues/open/sandbox-approval-gates-fail-open-on-revocation-spellings.md, rules 1-5).
function note(subject, body, tail = " | オーナー（local） | note.md") {
  return `- 2026-09-29 | ${subject} | ${body}${tail}`;
}
const sha = packet.packetSha256;
const laneSubject = "STORAGE-RULES stage3-v1";
const laneName = "STORAGE-RULES";
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
  "eight-digit source commit prefix": note(
    "anything else",
    `REVOKED ${packet.sourceCommit.slice(0, 8)}`,
  ),
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
  assert.throws(
    () => validate({ ledgerText, packet, review: { ...review, envelopeId, withinEnvelope: true } }),
    /approval revoked/,
  );
});

for (const [name, row] of Object.entries({
  "another lane with other hashes": note(
    "STORAGE-OBJECT stage3-v1",
    `decision=REVOKED; packetSha256=${"9".repeat(64)}; sourceCommit=${"8".repeat(40)}`,
  ),
  "another packet of this lane with other hashes": note(
    "STORAGE-RULES other-packet",
    `REVOKED packetSha256=${"9".repeat(64)}`,
  ),
  "another packet of this lane with a full-width qualifier": note(
    "STORAGE-RULES other-packet（訂正）",
    `REVOKED packetSha256=${"9".repeat(64)}`,
  ),
  "another packet of this lane with an ASCII qualifier": note(
    "STORAGE-RULES other-packet(取消)",
    `REVOKED packetSha256=${"9".repeat(64)}`,
  ),
  "another lane with a qualifier": note("STORAGE-OBJECT（訂正）", "REVOKED"),
})) {
  test(`a revocation of ${name} does not stop this approval`, async () => {
    const validate = await load();
    // Another packet of this lane was approved earlier in the ledger, so its consumed revocation is one of its own.
    const earlier = decision({
      subject: "STORAGE-RULES other-packet",
      values: { packetSha256: "9".repeat(64), sourceCommit: "8".repeat(40) },
    });
    assert.equal(
      validate({ ledgerText: `${earlier}\n${decision()}\n${row}`, packet, review }).sendAuthorized,
      false,
    );
  });
}

// A consumed revocation names this lane and only key-bound pins that an earlier approval line of this lane in the same ledger carries.
const foreignSha = "9f".repeat(32);
// The retry flow: a consumed revocation of version 1 is written under the lane subject, then version 2 is approved under the same subject.
const v1 = {
  packetSha256: foreignSha,
  runnerSha256: "8e".repeat(32),
  manifestSha256: "7d".repeat(32),
  fixtureSchemaSha256: "6c".repeat(32),
  sourceCommit: "5b".repeat(20),
};
const v1EnvelopeId = "STORAGE-RULES-stage3-v1-000";
const v1Approval = () => decision({ values: { ...v1, envelopeId: v1EnvelopeId } });
for (const [name, row] of Object.entries({
  "five columns": note(laneSubject, `REVOKED packetSha256=${foreignSha}`),
  "four columns": `- 2026-09-29 | ${laneSubject} | REVOKED packetSha256=${foreignSha} | note.md`,
  "a decision field": note(laneSubject, `decision=REVOKED; packetSha256=${foreignSha}`),
  "lower-case and full-width": note(laneSubject, `ｒｅｖｏｋｅｄ packetSha256=${foreignSha}`),
  "upper-case key and digest": note(
    laneSubject,
    `REVOKED PACKETSHA256=${foreignSha.toUpperCase()}`,
  ),
  "another envelope ID": note(laneSubject, `decision=REVOKED; envelopeId=${v1EnvelopeId}`),
  "another digest and envelope ID": note(
    laneSubject,
    `decision=REVOKED; packetSha256=${foreignSha}; envelopeId=${v1EnvelopeId}`,
  ),
  "the envelope subject": note(
    `${laneSubject} envelope`,
    `decision=REVOKED; packetSha256=${foreignSha}`,
  ),
  "the bare lane": note("STORAGE-RULES", `decision=REVOKED; packetSha256=${foreignSha}`),
  "the lane with a qualifier": note("STORAGE-RULES（訂正）", `REVOKED packetSha256=${foreignSha}`),
  "two version 1 pins": note(
    "STORAGE-RULES",
    `REVOKED packetSha256=${foreignSha}; runnerSha256=${v1.runnerSha256}`,
  ),
  "the version 1 commit": note(
    laneSubject,
    `decision=REVOKED; packetSha256=${foreignSha}; sourceCommit=${v1.sourceCommit}`,
  ),
})) {
  test(`a consumed revocation of version 1 (${name}) does not stop version 2, before or after its approval`, async () => {
    const validate = await load();
    assert.equal(
      validate({ ledgerText: [v1Approval(), decision(), row].join("\n"), packet, review })
        .sendAuthorized,
      false,
    );
    assert.equal(
      validate({ ledgerText: [v1Approval(), row, decision()].join("\n"), packet, review })
        .sendAuthorized,
      false,
    );
  });
}

test("a version 1 approval, its consumed revocation and a version 2 approval under one subject approve version 2", async () => {
  const validate = await load();
  const consumed = note(
    laneSubject,
    `decision=REVOKED; packetSha256=${v1.packetSha256}; sourceCommit=${v1.sourceCommit}`,
  );
  const ledgerText = [decision({ values: v1 }), consumed, decision()].join("\n");
  assert.equal(validate({ ledgerText, packet, review }).decisionLine, 3);
  // Version 1 itself stays revoked.
  const packetV1 = { ...packet, ...v1 };
  assert.throws(
    () => validate({ ledgerText, packet: packetV1, review: { ...review, ...v1 } }),
    /approval revoked/,
  );
});

test("a delegated version 1 envelope, its consumed revocation and a version 2 envelope approve version 2", async () => {
  const validate = await load();
  const consumed = note(
    laneSubject,
    `decision=REVOKED; packetSha256=${v1.packetSha256}; envelopeId=${v1EnvelopeId}`,
  );
  const consumedEnvelope = note(
    `${laneSubject} envelope`,
    `decision=REVOKED; envelopeId=${v1EnvelopeId}`,
  );
  const ledgerText = [
    delegationRows,
    delegatedEnvelope({ values: { envelopeId: v1EnvelopeId } }),
    decision({ actor: coordinator, values: { ...v1, envelopeId: v1EnvelopeId } }),
    consumed,
    consumedEnvelope,
    delegatedEnvelope(),
    decision({ actor: coordinator, values: { envelopeId } }),
  ].join("\n");
  assert.equal(
    validate({ ledgerText, packet, review: { ...review, envelopeId, withinEnvelope: true } })
      .envelopeId,
    envelopeId,
  );
});

// The reviewer's probes (R1 to R8): a line that names the lane and is not a well-formed consumed revocation stops the approval.
const reviewDigest = "ab".repeat(32);
const stops = {
  "R1 a subject that does not name the lane, the body does": note(
    "全体",
    "decision=REVOKED; STORAGE-RULESの送信承認を取り消す",
  ),
  "R2 the lane with a stage label": note("STORAGE-RULES stage 3", "decision=REVOKED"),
  "R3 the lane with another label": note("STORAGE-RULES send", "decision=REVOKED"),
  "R4 this version's own subject citing a review digest": note(
    laneSubject,
    `decision=REVOKED; 理由=presend review ${reviewDigest} found a leak`,
  ),
  "R5 the bare lane with a review digest": note(
    "STORAGE-RULES",
    `decision=REVOKED; review=${reviewDigest}`,
  ),
  "R6 this version's own subject with a packet prefix and a review digest": note(
    laneSubject,
    `decision=REVOKED; packet=${packet.packetSha256.slice(0, 12)}; review=${reviewDigest}`,
  ),
  "R7 an unrelated topic with this version's manifest pin": note(
    "unrelated",
    `REVOKED manifestSha256=${packet.manifestSha256}`,
  ),
  "R8 an unrelated topic with a packet prefix": note(
    "unrelated",
    `REVOKED packet ${packet.packetSha256.slice(0, 16)}`,
  ),
  "a runner pin prefix": note("unrelated", `REVOKED ${packet.runnerSha256.slice(0, 8)}`),
  "a fixture schema pin prefix": note(
    "unrelated",
    `REVOKED ${packet.fixtureSchemaSha256.slice(0, 10)}`,
  ),
  "a source commit prefix": note("unrelated", `REVOKED ${packet.sourceCommit.slice(0, 8)}`),
  "the lane with the digest unbound to a key": note("STORAGE-RULES", `REVOKED ${foreignSha}`),
  "the lane with the digest under another key": note(
    "STORAGE-RULES",
    `REVOKED review=${foreignSha}`,
  ),
  "the lane with a digest bound to the wrong pin": note(
    "STORAGE-RULES",
    `REVOKED runnerSha256=${foreignSha}`,
  ),
  "the lane with a version 1 digest and a review digest": note(
    "STORAGE-RULES",
    `REVOKED packetSha256=${foreignSha}; review=${reviewDigest}`,
  ),
  "the lane with a digest that no earlier approval carries": note(
    "STORAGE-RULES",
    `REVOKED packetSha256=${"cd".repeat(32)}`,
  ),
  "the lane with a spaced assignment": note(
    "STORAGE-RULES",
    `REVOKED packetSha256 = ${foreignSha}`,
  ),
  "the lane with a colon assignment": note("STORAGE-RULES", `REVOKED packetSha256: ${foreignSha}`),
  "the lane with a truncated version 1 digest": note(
    "STORAGE-RULES",
    `REVOKED packetSha256=${foreignSha.slice(0, 63)}`,
  ),
  "the lane with a longer hex run": note("STORAGE-RULES", `REVOKED packetSha256=${foreignSha}0`),
  "the lane with no digest": note(laneSubject, "REVOKED"),
  "a longer task name that contains the lane's (fail closed)": note(
    "STORAGE-RULES-EXTRA（訂正）",
    "REVOKED",
  ),
  "the lane with a version 1 digest and this version's runner digest": note(
    laneSubject,
    `decision=REVOKED; packetSha256=${foreignSha}; runnerSha256=${packet.runnerSha256}`,
  ),
  "the lane with a version 1 digest and this version's packet digest": note(
    laneSubject,
    `decision=REVOKED; packetSha256=${foreignSha}; packetSha256=${sha}`,
  ),
  "the lane with a version 1 digest and this version's commit prefix": note(
    laneSubject,
    `decision=REVOKED; packetSha256=${foreignSha}; ${packet.sourceCommit.slice(0, 8)}`,
  ),
  "the lane with a free text line": `Note: STORAGE-RULES REVOKED ${foreignSha} by the owner`,
  "the word revocation": note("STORAGE-RULES", "decision=revocation"),
  "the word revoke": note(laneSubject, "revoke this packet"),
  "the word withdrawn": note("STORAGE-RULES", "withdrawn"),
  "the word withdraw": note(laneSubject, "withdraw the approval"),
  "the upper-case word WITHDRAWN": note("STORAGE-RULES", "WITHDRAWN"),
  "the full-width word withdrawn": note("STORAGE-RULES", "ｗｉｔｈｄｒａｗｎ"),
  "the word 取消": note("STORAGE-RULES", "承認を取消"),
  "the word 取り消し": note(laneSubject, "承認の取り消し"),
  "the word 取り消す": note("STORAGE-RULES", "承認を取り消す"),
  "the word 撤回": note("STORAGE-RULES", "承認を撤回"),
  "the word 撤回 in another column": `- 2026-09-29 | 全体 | STORAGE-RULES stage3-v1を撤回 | オーナー（local） | note.md`,
  "the lane with a version 1 digest and a commit that is not key-bound": note(
    "STORAGE-RULES",
    `REVOKED packetSha256=${foreignSha}; see ${"c3".repeat(20)}`,
  ),
  "the lane with a version 1 digest and a 64-digit digest that is not key-bound": note(
    "STORAGE-RULES",
    `REVOKED packetSha256=${foreignSha}; see ${"d4".repeat(32)}`,
  ),
  "the lane with a version 1 digest and an envelope ID that is not key-bound": note(
    "STORAGE-RULES",
    `REVOKED packetSha256=${foreignSha}; see ${v1EnvelopeId}`,
  ),
  "the lane with a version 1 envelope and this version's": note(
    laneSubject,
    `decision=REVOKED; envelopeId=${v1EnvelopeId}; envelopeId=${envelopeId}`,
  ),
};
for (const [name, row] of Object.entries(stops)) {
  test(`a revocation line (${name}) stops this approval whatever else the ledger holds`, async () => {
    const validate = await load();
    assert.throws(
      () => validate({ ledgerText: [v1Approval(), decision(), row].join("\n"), packet, review }),
      /approval revoked/,
    );
    assert.throws(
      () => validate({ ledgerText: [v1Approval(), row, decision()].join("\n"), packet, review }),
      /approval revoked/,
    );
    assert.throws(
      () => validate({ ledgerText: [row, decision()].join("\n"), packet, review }),
      /approval revoked/,
    );
  });
}

// A revocation that applies to every lane and names none of them still ends this lane's approval, when it was written after the decision.
test("a global revocation written after the decision stops the approval, and one written before it does not", async () => {
  const validate = await load();
  const after = {
    "the whole sandbox program": note("全体", "decision=REVOKED; すべての本番送信承認を取り消す"),
    "a bare all": note("all", "revoked"),
    "an empty subject": "- 2026-09-29 |  | decision=REVOKED | オーナー | note.md",
    "a revocation word in the body only": note("owner note", "本番送信を全て撤回する"),
    "a withdrawal": note("sandbox", "withdrawn: all sends"),
    "a revocation with a review digest": note(
      "review",
      `decision=REVOKED; review=${"ab".repeat(32)}`,
    ),
    rescind: note("sandbox", "rescind every approval"),
    "prose without an identifier": "A revoked test user is only mentioned in this note.",
    "a similar but different commit prefix": note("anything else", `REVOKED ${"b".repeat(7)}0`),
    中止: note("全体", "承認を中止"),
    無効: note("全体", "承認は無効"),
    取り下げ: note("全体", "承認を取り下げ"),
    // Hyphenated or cased subjects that are scope words, not lanes: the scanner fails closed.
    "all-lanes": note("all-lanes", "REVOKED 全ての送信の承認"),
    "ALL-LANES": note("ALL-LANES", "all approvals revoked"),
    "sandbox-oracles": note("sandbox-oracles", "全ての承認を取り消す"),
    "sandbox-wide": note("sandbox-wide", "revoke every approval"),
    "every-lane": note("every-lane", "REVOKED"),
    "global-stop": note("global-stop", "全ての送信を中止"),
    "a bare lane family with a universal word": note("codex", "全レーンの送信を中止"),
    "a bare pubsub with a universal word": note("pubsub", "revoke all sends"),
    "a scope word in a qualifier": note("Overall-plan", "withdrawn"),
    everything: note("everything-stops", "revoked"),
    entire: note("entire-program", "取消"),
    whole: note("whole-sandbox", "withdrawn"),
    "a trailing hyphen is not a lane name": note("some-lane-", "revoked"),
  };
  for (const [name, row] of Object.entries(after)) {
    assert.throws(
      () => validate({ ledgerText: [decision(), row].join("\n"), packet, review }),
      /approval revoked/,
      name,
    );
    assert.throws(
      () =>
        validate({
          ledgerText: [decision(), "- 2026-09-29 | unrelated | fine | note.md", row].join("\n"),
          packet,
          review,
        }),
      /approval revoked/,
      `${name} later`,
    );
    // Written before the approval, it was superseded by it.
    assert.equal(
      validate({ ledgerText: [row, decision()].join("\n"), packet, review }).sendAuthorized,
      false,
      `${name} before`,
    );
  }
});

// A lane the scanner has no name for (the ledger grew PUBSUB-EVENTARC and SCHEDULED-FUNCTIONS after it was written) is still another topic: a REVOKED line names its own topic in the subject
// column and is global only in the explicit global forms. One such line written after this lane's decision (the lane's own approval stays valid; a global one would void it).
// Each bare lane-family name is a topic of its own when the line has no universal word, and global when it has one (fail closed).
test("a bare lane-family subject revokes its own topic, unless the line says all", async () => {
  const validate = await load();
  for (const family of [
    "pubsub",
    "functions",
    "storage",
    "auth",
    "fs",
    "hosting",
    "firestore",
    "app-check",
    "codex",
    "fe",
    "ci",
    "CODEX",
    "Functions",
  ]) {
    assert.equal(
      validate({
        ledgerText: [decision(), note(family, "decision=REVOKED")].join("\n"),
        packet,
        review,
      }).sendAuthorized,
      false,
      family,
    );
    assert.throws(
      () =>
        validate({
          ledgerText: [decision(), note(family, "全レーンの承認を取り消す")].join("\n"),
          packet,
          review,
        }),
      /approval revoked/,
      `${family} with a universal word`,
    );
  }
});

test("a REVOKED line of a lane the scanner does not know is not a global revocation, however the lane is named", async () => {
  const validate = await load();
  const rows = {
    "PUBSUB-EVENTARC": note(
      "PUBSUB-EVENTARC preflight-002",
      "decision=REVOKED; packetSha256=" + "9".repeat(64) + "（使った）",
    ),
    "PUBSUB-EVENTARC envelope": note(
      "PUBSUB-EVENTARC preflight-002 envelope",
      "REVOKED envelopeId=PUBSUB-EVENTARC-preflight-002-001",
    ),
    "SCHEDULED-FUNCTIONS": note(
      "SCHEDULED-FUNCTIONS stage1",
      "REVOKED packetSha256=" + "8".repeat(64),
    ),
    "a bare pubsub": note("pubsub", "revoked"),
    "a lane with a qualifier": note("SCHEDULED-FUNCTIONS（訂正）", "取消"),
    "a worker lane": note("codex-lane7 stage2", "withdrawn"),
    "a new lane that follows the naming": note("GCS-LIFECYCLE record-1", "撤回"),
    "a universal word in the prose of another lane's line": note(
      "PUBSUB-EVENTARC preflight-002",
      "REVOKED（全ての要求を使い切った。every request was sent）",
    ),
    "an envelope line of another lane that mentions a revocation": note(
      "SCHEDULED-FUNCTIONS stage1 envelope",
      "envelopeId=SCHEDULED-FUNCTIONS-stage1-001; 取消は全て調整役が行う",
    ),
  };
  for (const [name, row] of Object.entries(rows)) {
    assert.equal(
      validate({ ledgerText: [decision(), row].join("\n"), packet, review }).sendAuthorized,
      false,
      name,
    );
    assert.equal(
      validate({
        ledgerText: [decision(), "- 2026-09-29 | unrelated | fine | note.md", row].join("\n"),
        packet,
        review,
      }).sendAuthorized,
      false,
      `${name} later`,
    );
    assert.equal(
      validate({ ledgerText: [row, decision(), row].join("\n"), packet, review }).sendAuthorized,
      false,
      `${name} around`,
    );
  }
  // The explicit global forms still void the approval, next to lines of such lanes.
  for (const global of [
    note("全体", "decision=REVOKED; すべて取り消す"),
    note("all", "revoked"),
    note("sandbox", "withdrawn: all sends"),
    "- 2026-09-29 |  | decision=REVOKED | オーナー | note.md",
  ]) {
    assert.throws(
      () =>
        validate({
          ledgerText: [decision(), rows["PUBSUB-EVENTARC"], global].join("\n"),
          packet,
          review,
        }),
      /approval revoked/,
      global,
    );
  }
});

test("a revocation that names another lane, and delegation lines, are not global revocations of this lane", async () => {
  const validate = await load();
  for (const row of [
    note("STORAGE-OBJECT stage3-v1", "decision=REVOKED"),
    note("FS-TRANSACTION p10-grpc-boundary", "revoked"),
    note("AUTH-FEDERATION record-followup", "取消"),
    note("FUNCTIONS-EVENTS stage2", "withdrawn"),
    note("HOSTING-CONFIG x", "撤回"),
    note("FIRESTORE-RULES x", "revoked"),
    note("APP-CHECK-PROXY x", "revoked"),
    note("FS-DATA-WRITE x", "REVOKED"),
    note("AUTH-ACCOUNT x", "REVOKED"),
    note("FUNCTIONS-HTTP x", "REVOKED"),
  ]) {
    assert.equal(
      validate({ ledgerText: [decision(), row].join("\n"), packet, review }).sendAuthorized,
      false,
      row,
    );
  }
  // The delegation rows' own prose uses 中止, 無効 and 取り下げ; only the narrower revocation words revoke a delegation.
  for (const word of ["中止", "無効", "取り下げ", "rescind"]) {
    assert.equal(
      validate({
        ledgerText: `${delegatedLedger()}\n${note("owner note", `調整役への委任について: ${word}`)}`,
        packet,
        review: { ...review, envelopeId, withinEnvelope: true },
      }).sendAuthorized,
      false,
      word,
    );
  }
  // A delegation revocation ends coordinator rows, not an owner approval.
  assert.equal(
    validate({
      ledgerText: [decision(), note("調整役への委任（本番の送信）", "decision=REVOKED")].join("\n"),
      packet,
      review,
    }).sendAuthorized,
    false,
  );
});

test("a global revocation needs a real decision line to follow, and a lane name inside a longer word is not another lane", async () => {
  const validate = await load();
  const global = note("全体", "decision=REVOKED; すべて取り消す");
  // With no approval at all the approval is missing, not revoked.
  assert.throws(
    () => validate({ ledgerText: global, packet, review }),
    /matching owner approval required/,
  );
  // Only the full packet digest makes a decision line: a status line that shows just its prefix does not move the decision.
  const prefixNote = note("status", `packet ${packet.packetSha256.slice(0, 8)} was reviewed`);
  assert.throws(
    () => validate({ ledgerText: [decision(), global, prefixNote].join("\n"), packet, review }),
    /approval revoked/,
  );
  // A lane-like fragment inside a longer word does not name another lane.
  for (const text of [
    "the sub-auth-thing revoked",
    "prefs-x revoked",
    "myfs-data revoked",
    "xstorage-object revoked",
    "unhosting-x revoked",
  ]) {
    assert.throws(
      () => validate({ ledgerText: [decision(), note("all", text)].join("\n"), packet, review }),
      /approval revoked/,
      text,
    );
  }
});

test("a global revocation is measured against the decision row, so a later line that cites the packet digest cannot cancel it", async () => {
  const validate = await load();
  const global = note("全体", "decision=REVOKED; すべての本番送信承認を取り消す");
  for (const status of [
    note(
      `${laneSubject} status`,
      `recording run-one finished; packetSha256=${packet.packetSha256}; outcome=finished`,
    ),
    note("owner note", `hold note for ${packet.packetSha256}`),
    `- 2026-09-29 | unrelated | see ${packet.packetSha256} | note.md`,
  ]) {
    assert.throws(
      () => validate({ ledgerText: [decision(), global, status].join("\n"), packet, review }),
      /approval revoked/,
      status,
    );
    assert.throws(
      () =>
        validate({ ledgerText: [decision(), global, status, status].join("\n"), packet, review }),
      /approval revoked/,
      `${status} twice`,
    );
  }
  // A new decision row written after the global revocation supersedes it, and the status lines after that do not matter.
  const status = note(`${laneSubject} status`, `packetSha256=${packet.packetSha256}`);
  assert.equal(
    validate({ ledgerText: [decision(), global, decision(), status].join("\n"), packet, review })
      .sendAuthorized,
    false,
  );
  // A revocation written after the decision and before nothing else is measured from the last decision row, not the first.
  assert.throws(
    () =>
      validate({ ledgerText: [decision(), global, decision(), global].join("\n"), packet, review }),
    /approval revoked/,
  );
});

test("a global revocation that says all and names other lanes as examples still stops the lane; naming one other lane alone does not", async () => {
  const validate = await load();
  for (const text of [
    "すべてのレーン（FS-TRANSACTIONを含む）の本番送信承認を取り消す",
    "revoke all approvals, including FS-TRANSACTION and AUTH-MFA",
    "every lane incl. FUNCTIONS-EVENTS is revoked",
    "全レーンの承認を取消（AUTH-FEDERATIONを含む）",
    "全部撤回。例: HOSTING-CONFIG",
  ]) {
    assert.throws(
      () =>
        validate({
          ledgerText: [decision(), note("全体", `decision=REVOKED; ${text}`)].join("\n"),
          packet,
          review,
        }),
      /approval revoked/,
      text,
    );
    assert.equal(
      validate({
        ledgerText: [note("全体", `decision=REVOKED; ${text}`), decision()].join("\n"),
        packet,
        review,
      }).sendAuthorized,
      false,
      `${text} before`,
    );
  }
  for (const text of [
    "FS-TRANSACTIONの承認を取り消す",
    "revoked: the AUTH-MFA packet",
    "smallest revoked step of FS-RULES",
    "the ballpark revoke of FUNCTIONS-HTTP",
  ]) {
    assert.equal(
      validate({ ledgerText: [decision(), note("owner", text)].join("\n"), packet, review })
        .sendAuthorized,
      false,
      text,
    );
  }
});

test("a stop word that is not one of the revocation words does not revoke, by design", async () => {
  // The owner's revocation words are fixed; a lane that is named with the plain word 停止 (as a procedure step or a status) is not stopped, because such lines are common.
  const validate = await load();
  for (const text of ["本番送信を停止する", "停止条件を確認", "保留にする"]) {
    assert.equal(
      validate({ ledgerText: [decision(), note("STORAGE-RULES", text)].join("\n"), packet, review })
        .sendAuthorized,
      false,
      text,
    );
    assert.equal(
      validate({ ledgerText: [decision(), note("全体", text)].join("\n"), packet, review })
        .sendAuthorized,
      false,
      `${text} global`,
    );
  }
});

test("an approval line of another lane that only mentions this lane does not feed the earlier pins a consumed revocation may cite", async () => {
  const validate = await load();
  const consumed = note(laneSubject, `decision=REVOKED; packetSha256=${foreignSha}`);
  for (const subject of [
    "FS-TRANSACTION expiry-retry-04",
    "Codex lanes to Sonnet lanes",
    "owner note about STORAGE-RULES",
    "xSTORAGE-RULES stage3-v1",
  ]) {
    const other = note(
      subject,
      `decision=APPROVE; packetSha256=${foreignSha}; also covers ${laneName}`,
    );
    assert.throws(
      () => validate({ ledgerText: [other, consumed, decision()].join("\n"), packet, review }),
      /approval revoked/,
      subject,
    );
  }
  // The lane's own subject, with a qualifier in parentheses, does feed them.
  const own = note(`${laneSubject}（訂正）`, `decision=APPROVE; packetSha256=${foreignSha}`);
  assert.equal(
    validate({ ledgerText: [own, consumed, decision()].join("\n"), packet, review }).sendAuthorized,
    false,
  );
});

test("only the lane's approval and envelope lines feed the earlier pins a consumed revocation may cite", async () => {
  const validate = await load();
  const status = note(laneSubject, `status update: packetSha256=${foreignSha} was reviewed`);
  const consumed = note(laneSubject, `decision=REVOKED; packetSha256=${foreignSha}`);
  assert.throws(
    () => validate({ ledgerText: [status, consumed, decision()].join("\n"), packet, review }),
    /approval revoked/,
  );
  assert.equal(
    validate({ ledgerText: [v1Approval(), consumed, decision()].join("\n"), packet, review })
      .sendAuthorized,
    false,
  );
  // A subject that only mentions the word envelope is not an envelope row.
  const notEnvelope = note(`${laneSubject} envelopes (draft)`, `packetSha256=${foreignSha}`);
  assert.throws(
    () => validate({ ledgerText: [notEnvelope, consumed, decision()].join("\n"), packet, review }),
    /approval revoked/,
  );
  const envelopeRow = note(`${laneSubject} envelope`, `envelopeId=${v1EnvelopeId}; project=x`);
  const consumedEnvelope = note(laneSubject, `decision=REVOKED; envelopeId=${v1EnvelopeId}`);
  assert.equal(
    validate({ ledgerText: [envelopeRow, consumedEnvelope, decision()].join("\n"), packet, review })
      .sendAuthorized,
    false,
  );
});

test("every revocation word also makes a consumed revocation of an earlier version, when it is well formed", async () => {
  const validate = await load();
  for (const word of [
    "revoked",
    "revocation",
    "revoke",
    "withdrawn",
    "withdraw",
    "取消",
    "取り消し",
    "撤回",
  ]) {
    const consumed = note(laneSubject, `decision=${word}; packetSha256=${foreignSha}`);
    assert.equal(
      validate({ ledgerText: [v1Approval(), consumed, decision()].join("\n"), packet, review })
        .sendAuthorized,
      false,
      word,
    );
    const unbound = note(laneSubject, `decision=${word}`);
    assert.throws(
      () =>
        validate({ ledgerText: [v1Approval(), unbound, decision()].join("\n"), packet, review }),
      /approval revoked/,
      word,
    );
  }
});

test("the delegation is revoked by every revocation word too", async () => {
  const validate = await load();
  for (const word of [
    "revoked",
    "revocation",
    "revoke",
    "withdrawn",
    "withdraw",
    "取消",
    "取り消し",
    "撤回",
    "WITHDRAWN",
  ]) {
    for (const subject of [
      "調整役への委任（本番の送信）",
      "調整役への委任（枠の承認）",
      "調整役への委任",
    ]) {
      assert.throws(
        () =>
          validate({
            ledgerText: `${delegatedLedger()}\n${note(subject, `decision=${word}`)}`,
            packet,
            review: { ...review, envelopeId, withinEnvelope: true },
          }),
        /delegation revoked|approval revoked|delegated envelope authority required/,
        `${subject} ${word}`,
      );
    }
  }
});

test("a consumed revocation must follow the approval line whose pins it names, and that line must be this lane's", async () => {
  const validate = await load();
  const consumed = note(laneSubject, `decision=REVOKED; packetSha256=${foreignSha}`);
  assert.throws(
    () => validate({ ledgerText: [consumed, v1Approval(), decision()].join("\n"), packet, review }),
    /approval revoked/,
  );
  const otherLane = decision({ subject: "STORAGE-OBJECT stage3-v1", values: v1 });
  assert.throws(
    () => validate({ ledgerText: [otherLane, consumed, decision()].join("\n"), packet, review }),
    /approval revoked/,
  );
  // An earlier line that is itself a revocation does not count as an approval.
  const revokedEarlier = note(laneSubject, `decision=REVOKED; packetSha256=${foreignSha}`);
  assert.throws(
    () =>
      validate({ ledgerText: [revokedEarlier, consumed, decision()].join("\n"), packet, review }),
    /approval revoked/,
  );
  assert.equal(
    validate({ ledgerText: [v1Approval(), consumed, decision()].join("\n"), packet, review })
      .sendAuthorized,
    false,
  );
});

test("a keyed revocation of this version's own envelope stops a delegated approval even though earlier lines carry that envelope ID", async () => {
  const validate = await load();
  for (const row of [
    note(laneSubject, `decision=REVOKED; envelopeId=${envelopeId}`),
    note(`${laneSubject} envelope`, `decision=REVOKED; envelopeId=${envelopeId.toLowerCase()}`),
    note("unrelated", `REVOKED envelopeId=${envelopeId}`),
  ]) {
    assert.throws(
      () =>
        validate({
          ledgerText: `${delegatedLedger()}\n${row}`,
          packet,
          review: { ...review, envelopeId, withinEnvelope: true },
        }),
      /approval revoked/,
      row,
    );
  }
});

// Envelope IDs only mean something to a delegated approval that has one.
for (const [name, row] of Object.entries({
  "a foreign envelope ID and this version's": note(
    laneSubject,
    `decision=REVOKED; envelopeId=${v1EnvelopeId}; envelopeId=${envelopeId}`,
  ),
  "an envelope ID that is a prefix of this version's": note(
    laneSubject,
    `decision=REVOKED; envelopeId=${envelopeId.slice(0, -1)}`,
  ),
  "an envelope ID that extends this version's": note(
    laneSubject,
    `decision=REVOKED; envelopeId=${envelopeId}0`,
  ),
})) {
  test(`a revoked line under this subject with ${name} still stops a delegated approval`, async () => {
    const validate = await load();
    assert.throws(
      () =>
        validate({
          ledgerText: `${delegatedLedger()}\n${row}`,
          packet,
          review: { ...review, envelopeId, withinEnvelope: true },
        }),
      /approval revoked/,
    );
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
      const ledgerText =
        placement === "before" ? `${row}\n${delegatedLedger()}` : `${delegatedLedger()}\n${row}`;
      assert.throws(
        () =>
          validate({ ledgerText, packet, review: { ...review, envelopeId, withinEnvelope: true } }),
        /delegated envelope authority required/,
      );
    });
  }
  test(`a delegation revocation (${name}) also refuses a coordinator decision inside an owner envelope`, async () => {
    const validate = await load();
    const ledgerText = `${envelope()}\n${decision({ actor: coordinator, values: { envelopeId } })}\n${row}`;
    assert.throws(
      () =>
        validate({ ledgerText, packet, review: { ...review, envelopeId, withinEnvelope: true } }),
      /delegated envelope authority required/,
    );
  });
  test(`a delegation revocation (${name}) leaves a direct owner approval valid`, async () => {
    const validate = await load();
    assert.equal(
      validate({ ledgerText: `${decision()}\n${row}`, packet, review }).sendAuthorized,
      false,
    );
  });
}

test("a delegated envelope needs both the send and the envelope delegation rows", async () => {
  const validate = await load();
  const options = { packet, review: { ...review, envelopeId, withinEnvelope: true } };
  assert.equal(validate({ ledgerText: delegatedLedger(), ...options }).sendAuthorized, false);
  for (const basis of [delegationRow, delegationRow395]) {
    assert.throws(
      () => validate({ ledgerText: delegatedLedger({ basis }), ...options }),
      /delegated envelope authority required/,
    );
  }
});

test("the revocation scanner constants agree with the constants the approval uses", async () => {
  const module = await import("./storage-rules/ledger-revocation.mjs").catch(() => ({}));
  assert.equal(module.DELEGATION_SUBJECTS?.send, "調整役への委任（本番の送信）");
  assert.equal(module.DELEGATION_SUBJECTS?.envelope, "調整役への委任（枠の承認）");
  assert.equal(typeof module.normalizeLedgerText, "function");
  for (const subject of Object.values(module.DELEGATION_SUBJECTS ?? {})) {
    assert.ok(module.normalizeLedgerText(subject).includes(module.NORMALIZED_DELEGATION_MARKER));
    assert.ok(
      module
        .normalizeLedgerText(subject.replaceAll("（", "(").replaceAll("）", ")"))
        .includes(module.NORMALIZED_DELEGATION_MARKER),
    );
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
  const line =
    "- 2026-09-27 | STORAGE-RULES | historical prose about a revoked test user | オーナー（local） | note.md";
  const scan = (text, allowlist) =>
    module.scanRevocations({
      ledgerText: text,
      taskId: "STORAGE-RULES",
      pins: Object.fromEntries(pins.map((key) => [key, packet[key]])),
      envelopeId: null,
      allowlist,
    });
  assert.deepEqual(scan(line, []).lane, [1]);
  const allowlist = [
    { sha256: module.rowSha256(line), reason: "historical prose, not a revocation of any packet" },
  ];
  assert.deepEqual(scan(line, allowlist).lane, []);
  assert.deepEqual(scan(`${line} `, allowlist).lane, [1]);
  assert.deepEqual(scan(line.replace("2026-09-27", "2026-09-28"), allowlist).lane, [1]);
  assert.deepEqual(scan(`${line}\n${line}`, allowlist).lane, []);
});

test("the scanner compares the packet SHA and the source commit case-insensitively", async () => {
  const module = await import("./storage-rules/ledger-revocation.mjs").catch(() => ({}));
  const scan = (text) =>
    module.scanRevocations({
      ledgerText: text,
      taskId: "STORAGE-RULES",
      pins: Object.fromEntries(pins.map((key) => [key, packet[key].toUpperCase()])),
      envelopeId: envelopeId.toUpperCase(),
    });
  assert.deepEqual(scan(`revoked ${sha}`).lane, [1]);
  assert.deepEqual(scan(`revoked ${packet.sourceCommit.slice(0, 8)}`).lane, [1]);
  assert.deepEqual(scan(`revoked ${envelopeId.toLowerCase()}`).lane, [1]);
});

test("a malformed or duplicated target row that revokes nothing is still refused", async () => {
  const validate = await load();
  const malformed = `${decision()}\n- 2026-09-29 | ${laneSubject} | decision=APPROVE | extra | オーナー（local） | note.md`;
  assert.throws(
    () => validate({ ledgerText: malformed, packet, review }),
    /malformed target ledger row/,
  );
  const duplicated = decision().replace("decision=APPROVE", "decision=APPROVE; decision=APPROVE");
  assert.throws(
    () => validate({ ledgerText: duplicated, packet, review }),
    /duplicate ledger field/,
  );
});

test("the approved request limit is the declared ID count per recording, doubled for two recordings", async () => {
  const counter = await import("./storage-rules/request-counter.mjs");
  const approval = await import("./storage-rules/approval.mjs");
  assert.equal(counter.DECLARED_REQUESTS_PER_RECORDING, 6172);
  assert.equal(approval.DRAFT_STAGE3_APPROVAL_LIMITS.maxRequests, 2 * 6172);
  assert.equal(approval.DRAFT_STAGE3_APPROVAL_LIMITS.maxRequests, 12344);
  const validate = await load();
  assert.throws(
    () => validate({ ledgerText: decision(), packet: { ...packet, maxRequests: 12328 }, review }),
    /runner limit mismatch/,
  );
});
