import assert from "node:assert/strict";
import { test } from "node:test";

import { covers, fields, packetApproval } from "./auth-federation/approval.mjs";

const DIGEST = "a".repeat(64);
const COMMIT = "b".repeat(40);
const RUNNER = { project: "fireemu-oracle-idp", maxRequests: 400, reserveUsd: 1 };
const ASK = {
  parent: "AUTH-FEDERATION",
  packet: "record-oidc",
  digest: DIGEST,
  commit: COMMIT,
  runner: RUNNER,
};
const OWNER = "オーナー（直接の返答「承認」）";
const envelope = (extra = "") =>
  `- 2026-09-28 | AUTH-FEDERATION record-oidc envelope | envelopeId=AUTH-FEDERATION-record-oidc-1; project=fireemu-oracle-idp; maxRequests=500; reserveUsd=2; writes=run providers and accounts${extra} | ${OWNER} | packet.md`;
const delegated = (extra = {}) => {
  const values = {
    decision: "APPROVE",
    envelopeId: "AUTH-FEDERATION-record-oidc-1",
    packetSha256: DIGEST,
    sourceCommit: COMMIT,
    ...extra,
  };
  const body = Object.entries(values)
    .map(([k, v]) => `${k}=${v}`)
    .join("; ");
  return `- 2026-09-28 | AUTH-FEDERATION record-oidc | ${body} | Claude（委任。枠の内の承認し直し） | packet.md`;
};

test("the owner's line for the version approves it", () => {
  const line = `- 2026-09-28 | AUTH-FEDERATION | record-oidc APPROVED ${DIGEST}（…） | ${OWNER} | x`;
  assert.deepEqual(packetApproval(line, ASK), { kind: "owner", line });
  assert.equal(packetApproval(line.replace(OWNER, "Claude（委任）"), ASK), undefined);
  assert.equal(packetApproval(line.replace("record-oidc", "record-oidc-draft"), ASK), undefined);
  assert.equal(
    packetApproval(
      `${line}\n- 2026-09-28 | AUTH-FEDERATION | record-oidc REVOKED ${DIGEST} | 調整役 | x`,
      ASK,
    ),
    undefined,
  );
});

test("the owner's envelope with the coordinator's version line approves it", () => {
  const both = `${envelope()}\n${delegated()}`;
  assert.deepEqual(packetApproval(both, ASK), {
    kind: "envelope",
    line: delegated(),
    envelopeId: "AUTH-FEDERATION-record-oidc-1",
  });
  const refused = {
    "no envelope": delegated(),
    "the version line first": `${delegated()}\n${envelope()}`,
    "an envelope not the owner's": `${envelope().replace(OWNER, "Claude（委任）")}\n${delegated()}`,
    "another envelope": `${envelope()}\n${delegated({ envelopeId: "AUTH-FEDERATION-record-oidc-2" })}`,
    "another digest": `${envelope()}\n${delegated({ packetSha256: "c".repeat(64) })}`,
    "another commit": `${envelope()}\n${delegated({ sourceCommit: "c".repeat(40) })}`,
    "not APPROVE": `${envelope()}\n${delegated({ decision: "REQUEST_CHANGES" })}`,
    "a version line by the owner's decider column": `${envelope()}\n${delegated().replace("Claude（委任。枠の内の承認し直し）", "someone")}`,
    "the envelope revoked": `${envelope()}\n${delegated()}\n- 2026-09-28 | AUTH-FEDERATION record-oidc envelope | REVOKED envelopeId=AUTH-FEDERATION-record-oidc-1 | ${OWNER} | x`,
    "the version revoked": `${envelope()}\n${delegated()}\n- 2026-09-28 | AUTH-FEDERATION record-oidc | REVOKED ${DIGEST} | 調整役 | x`,
  };
  for (const [name, text] of Object.entries(refused)) {
    assert.equal(packetApproval(text, ASK), undefined, name);
  }
});

test("an envelope must cover the runner's project and limits", () => {
  const envelopeFields = fields(envelope().split(" | ")[2]);
  assert.equal(envelopeFields.maxRequests, "500");
  assert.ok(covers(envelopeFields, RUNNER));
  assert.ok(covers({ ...envelopeFields, maxRequests: "400", reserveUsd: "1" }, RUNNER));
  for (const [name, change] of Object.entries({
    "another project": { project: "fireemu-oracle-sbx" },
    "fewer requests": { maxRequests: "399" },
    "a smaller reserve": { reserveUsd: "0.5" },
    "no limit": { maxRequests: undefined },
    "not a number": { reserveUsd: "two" },
    "a hexadecimal limit": { maxRequests: "0x1F4" },
    "an exponent": { maxRequests: "1e3" },
  })) {
    assert.ok(!covers({ ...envelopeFields, ...change }, RUNNER), name);
  }
  // The pair is refused when the envelope does not cover the runner.
  const narrow = envelope().replace("maxRequests=500", "maxRequests=100");
  assert.equal(packetApproval(`${narrow}\n${delegated()}`, ASK), undefined);
  assert.throws(() => packetApproval("", { ...ASK, commit: "abc" }), /40 hex/);
});

const DELEGATE = "Claude（委任。オーナーの裁量の委任 2026-09-28）";
const BASIS_TOKEN = "根拠=2026-09-28 調整役への委任（本番の送信）";
const BASIS =
  "- 2026-09-28 | 調整役への委任（本番の送信） | decision=APPROVE; 費用がUS$10以内なら任せる | オーナー（このセッションへの直接の返答） | x";
const coordinatorEnvelope = ({ reserve = "2", decider = DELEGATE, token = BASIS_TOKEN } = {}) =>
  `- 2026-09-28 | AUTH-FEDERATION record-oidc envelope | envelopeId=AUTH-FEDERATION-record-oidc-1; project=fireemu-oracle-idp; maxRequests=500; reserveUsd=${reserve}; writes=run providers and accounts; ${token} | ${decider} | packet.md`;

test("the coordinator's envelope line counts under the owner's delegation (addendum of 2026-09-28)", () => {
  const ledger = (...lines) => lines.join("\n");
  const approved = packetApproval(ledger(BASIS, coordinatorEnvelope(), delegated()), ASK);
  assert.equal(approved?.kind, "envelope");
  assert.equal(approved?.envelopeId, "AUTH-FEDERATION-record-oidc-1");
  // Every condition is needed: the basis line (by the owner), the exact decider, the token and
  // a reserve of at most US$10.
  for (const [what, text] of [
    ["no basis line", ledger(coordinatorEnvelope(), delegated())],
    [
      "a basis line not by the owner",
      ledger(BASIS.replace("オーナー（このセッションへの直接の返答）", "調整役"), coordinatorEnvelope(), delegated()),
    ],
    ["another decider", ledger(BASIS, coordinatorEnvelope({ decider: "Claude（委任）" }), delegated())],
    ["no basis token", ledger(BASIS, coordinatorEnvelope({ token: "note=none" }), delegated())],
    ["a reserve over US$10", ledger(BASIS, coordinatorEnvelope({ reserve: "10.5" }), delegated())],
  ]) {
    assert.equal(packetApproval(text, ASK), undefined, what);
  }
  assert.equal(
    packetApproval(ledger(BASIS, coordinatorEnvelope({ reserve: "10" }), delegated()), ASK)?.kind,
    "envelope",
    "exactly US$10",
  );
  // The owner's envelope line still approves as before.
  assert.equal(packetApproval(ledger(envelope(), delegated()), ASK)?.kind, "envelope");
});
