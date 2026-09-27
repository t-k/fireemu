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
