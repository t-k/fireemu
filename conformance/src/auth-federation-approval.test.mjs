import assert from "node:assert/strict";
import { test } from "node:test";

import {
  REVOCATION_TOKENS,
  covers,
  fields,
  norm,
  packetApproval,
} from "./auth-federation/approval.mjs";

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
// The owner's delegation of envelope approvals (owner ledger line 395).
const ENVELOPES =
  "- 2026-09-28 | 調整役への委任（枠の承認） | decision=APPROVE; (イ) 枠の承認も任せる | オーナー（このセッションへの直接の返答） | x";
const coordinatorEnvelope = ({ reserve = "2", decider = DELEGATE, token = BASIS_TOKEN } = {}) =>
  `- 2026-09-28 | AUTH-FEDERATION record-oidc envelope | envelopeId=AUTH-FEDERATION-record-oidc-1; project=fireemu-oracle-idp; maxRequests=500; reserveUsd=${reserve}; writes=run providers and accounts; ${token} | ${decider} | packet.md`;

test("the coordinator's envelope line counts under the owner's delegation (addendum of 2026-09-28)", () => {
  const ledger = (...lines) => lines.join("\n");
  const approved = packetApproval(
    ledger(BASIS, ENVELOPES, coordinatorEnvelope(), delegated()),
    ASK,
  );
  assert.equal(approved?.kind, "envelope");
  assert.equal(approved?.envelopeId, "AUTH-FEDERATION-record-oidc-1");
  // Every condition is needed: the basis line (by the owner), the exact decider, the token and
  // a reserve of at most US$10.
  for (const [what, text] of [
    ["no basis line", ledger(ENVELOPES, coordinatorEnvelope(), delegated())],
    ["no envelope delegation (line 395)", ledger(BASIS, coordinatorEnvelope(), delegated())],
    [
      "an envelope delegation not by the owner",
      ledger(
        BASIS,
        ENVELOPES.replace("オーナー（このセッションへの直接の返答）", "調整役"),
        coordinatorEnvelope(),
        delegated(),
      ),
    ],
    [
      "a basis line not by the owner",
      ledger(
        BASIS.replace("オーナー（このセッションへの直接の返答）", "調整役"),
        ENVELOPES,
        coordinatorEnvelope(),
        delegated(),
      ),
    ],
    [
      "another decider",
      ledger(BASIS, ENVELOPES, coordinatorEnvelope({ decider: "Claude（委任）" }), delegated()),
    ],
    [
      "no basis token",
      ledger(BASIS, ENVELOPES, coordinatorEnvelope({ token: "note=none" }), delegated()),
    ],
    [
      "a reserve over US$10",
      ledger(BASIS, ENVELOPES, coordinatorEnvelope({ reserve: "10.5" }), delegated()),
    ],
  ]) {
    assert.equal(packetApproval(text, ASK), undefined, what);
  }
  assert.equal(
    packetApproval(
      ledger(BASIS, ENVELOPES, coordinatorEnvelope({ reserve: "10" }), delegated()),
      ASK,
    )?.kind,
    "envelope",
    "exactly US$10",
  );
  // The owner's envelope line still approves as before.
  assert.equal(packetApproval(ledger(envelope(), delegated()), ASK)?.kind, "envelope");
});

test("any spelling of a revocation withdraws what it names, and fails closed (pre-send review M1)", () => {
  const ledger = (...lines) => lines.join("\n");
  const base = [BASIS, ENVELOPES, coordinatorEnvelope(), delegated()];
  assert.equal(packetApproval(ledger(...base), ASK)?.kind, "envelope", "the baseline approves");
  const fullWidth = (text) =>
    [...text]
      .map((c) => (c >= "!" && c <= "~" ? String.fromCharCode(c.charCodeAt(0) + 0xfee0) : c))
      .join("");
  const refused = {
    "the version, canonical": `- 2026-09-29 | AUTH-FEDERATION record-oidc | REVOKED packetSha256=${DIGEST} | 調整役 | x`,
    "the envelope, canonical": `- 2026-09-29 | AUTH-FEDERATION record-oidc envelope | REVOKED envelopeId=AUTH-FEDERATION-record-oidc-1 | ${OWNER} | x`,
    "the sending delegation": `- 2026-09-29 | 調整役への委任（本番の送信） | REVOKED | オーナー（直接） | x`,
    "the envelope delegation": `- 2026-09-29 | 調整役への委任（枠の承認） | REVOKED | オーナー（直接） | x`,
    "the delegation, decision=revoked": `- 2026-09-29 | 調整役への委任（本番の送信） | decision=revoked | オーナー（直接） | x`,
    "the delegation, full-width parentheses and word": `- 2026-09-29 | 調整役への委任(本番の送信) | ${fullWidth("REVOKED")} | オーナー | x`,
    "a lower-case word": `- 2026-09-29 | AUTH-FEDERATION record-oidc | revoked packetSha256=${DIGEST} | 調整役 | x`,
    "a correction suffix": `- 2026-09-29 | AUTH-FEDERATION record-oidc（訂正） | REVOKED packetSha256=${DIGEST} | 調整役 | x`,
    "a lower-case topic": `- 2026-09-29 | auth-federation record-oidc | REVOKED packetSha256=${DIGEST} | 調整役 | x`,
    "a full-width topic": `- 2026-09-29 | ${fullWidth("AUTH-FEDERATION")} record-oidc | REVOKED packetSha256=${DIGEST} | 調整役 | x`,
    "a full-width word": `- 2026-09-29 | AUTH-FEDERATION record-oidc | ${fullWidth("REVOKED")} packetSha256=${DIGEST} | 調整役 | x`,
    "an upper-case digest": `- 2026-09-29 | AUTH-FEDERATION record-oidc | REVOKED packetSha256=${DIGEST.toUpperCase()} | 調整役 | x`,
    "the commit only": `- 2026-09-29 | AUTH-FEDERATION record-oidc | REVOKED sourceCommit=${COMMIT} | 調整役 | x`,
    "an 8-digit commit prefix": `- 2026-09-29 | AUTH-FEDERATION record-oidc | REVOKED ${COMMIT.slice(0, 8)} | 調整役 | x`,
    "a lower-case envelope ID": `- 2026-09-29 | AUTH-FEDERATION record-oidc envelope | REVOKED envelopeId=auth-federation-record-oidc-1 | ${OWNER} | x`,
    "two spaces after the dash": `-  2026-09-29 | AUTH-FEDERATION record-oidc | REVOKED packetSha256=${DIGEST} | 調整役 | x`,
    "four columns": `- 2026-09-29 | AUTH-FEDERATION record-oidc | REVOKED packetSha256=${DIGEST} | 調整役`,
    "no leading date": `- AUTH-FEDERATION record-oidc | REVOKED packetSha256=${DIGEST} | 調整役 | x`,
    "a bare revocation of the packet": `- 2026-09-29 | AUTH-FEDERATION record-oidc | REVOKED | 調整役 | x`,
    "a bare revocation of the parent": `- 2026-09-29 | AUTH-FEDERATION | REVOKED | 調整役 | x`,
    "a revocation before the approval": null,
  };
  for (const [name, line] of Object.entries(refused)) {
    const text =
      line === null
        ? ledger(
            `- 2026-09-28 | AUTH-FEDERATION record-oidc | REVOKED packetSha256=${DIGEST} | 調整役 | x`,
            ...base,
          )
        : ledger(...base, line);
    assert.equal(packetApproval(text, ASK), undefined, name);
  }
  // The digest named by a prefix of at least 8 hex digits, with another full hash on the line
  // or under another topic (pre-send re-review R-S1).
  for (const [name, line] of Object.entries({
    "a digest prefix beside another full hash": `- 2026-09-29 | AUTH-FEDERATION record-oidc | REVOKED packetSha256=${DIGEST.slice(0, 8)}…（${"c".repeat(64)}に置き換え） | 調整役 | x`,
    "a digest prefix under another topic": `- 2026-09-29 | AUTH-FEDERATION（c） | REVOKED ${DIGEST.slice(0, 8)}… | 調整役 | x`,
  })) {
    assert.equal(packetApproval(ledger(...base, line), ASK), undefined, name);
  }
  // A revocation of another version or packet leaves this one approved.
  for (const [name, line] of Object.entries({
    "another digest": `- 2026-09-29 | AUTH-FEDERATION record-oidc | REVOKED packetSha256=${"c".repeat(64)} | 調整役 | x`,
    "another packet": `- 2026-09-29 | AUTH-FEDERATION record-saml | REVOKED | 調整役 | x`,
    "another parent's envelope": `- 2026-09-29 | FS-TRANSACTION p10 envelope | REVOKED envelopeId=FS-TRANSACTION-p10-001 | 調整役 | x`,
  })) {
    assert.equal(packetApproval(ledger(...base, line), ASK)?.kind, "envelope", name);
  }
  // A delegation revocation leaves the owner's own envelope standing.
  assert.equal(
    packetApproval(
      ledger(
        BASIS,
        ENVELOPES,
        envelope(),
        delegated(),
        "- 2026-09-29 | 調整役への委任（本番の送信） | REVOKED | オーナー | x",
      ),
      ASK,
    )?.kind,
    "envelope",
  );
});

test("the revocation constants are compared in their normalized form", () => {
  // NFKC and lower case on both sides: a full-width or upper-case constant could not match.
  for (const token of REVOCATION_TOKENS) assert.equal(norm(token), token, token);
  assert.equal(norm("ＲＥＶＯＫＥＤ"), "revoked");
  assert.equal(norm("調整役への委任（本番の送信）"), "調整役への委任(本番の送信)");
  assert.equal(norm("ＡＵＴＨ－ＦＥＤＥＲＡＴＩＯＮ"), "auth-federation");
});
