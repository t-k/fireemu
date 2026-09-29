"""Cancellation precedes filtered approval and retains explicit unrelated scopes."""

import pytest

import txn_sandbox_admission as shared
from txn_idle_grpc_authority import authorize as authorize_idle
from txn_retry_grpc_authority import authorize as authorize_retry

PACKET = "a" * 64
OTHER_PACKET = "d" * 64
ENVELOPE = "FS-TRANSACTION-boundary-synthetic-001"


@pytest.mark.parametrize("prefix", ["REVOKED", "decision=REVOKED"])
@pytest.mark.parametrize("separator", [" ", "; ", "（", "(", "：", ":"])
def test_unicode_delimiters_revoke_the_named_packet(prefix, separator):
    assert shared._revoked_packet(
        prefix + separator + "packetSha256=" + PACKET + "）", PACKET, ENVELOPE
    )


@pytest.mark.parametrize("word", ["NOT_REVOKED", "REVOKEDNESS", "PREVOKED"])
def test_other_identifier_words_do_not_become_revocation(word):
    assert not shared._is_revocation(word)


@pytest.mark.parametrize(
    "decision",
    [
        f"REVOKED; packetSha256={OTHER_PACKET}; envelopeId={ENVELOPE}",
        f"REVOKED（envelopeId={ENVELOPE}; packetSha256={OTHER_PACKET}）",
        "REVOKED; packetSha256=broken",
        "REVOKED; packetSha256=",
        f"REVOKED; packetSha256={OTHER_PACKET}; packetSha256={OTHER_PACKET}",
        f"REVOKED; packetSha256={OTHER_PACKET}; envelopeId=",
        f"REVOKED; envelopeId=other; envelopeId=other",
        f"REVOKED（global cancellation; runnerSha256={OTHER_PACKET}）",
        f"REVOKED; packetSha256={OTHER_PACKET}z",
        f"REVOKED; packetSha256={OTHER_PACKET}; envelopeId:broken",
        f"REVOKED; packetSha256={OTHER_PACKET}; envelopeId",
        f"REVOKED; packetSha256={OTHER_PACKET}; envelopeId :=other",
        f"REVOKED; packetSha256={OTHER_PACKET}; ENVELOPEID=other",
        "REVOKED; envelopeId=other; packetSha256:broken",
        "REVOKED; envelopeId=other; packetSha256",
        "REVOKED; envelopeId=other; closurePacketSha256:broken",
        "REVOKED; envelopeId=other; PACKETSHA256=" + OTHER_PACKET,
    ],
)
def test_matching_envelope_or_malformed_scope_cannot_be_shadowed(decision):
    assert shared._revoked_packet(decision, PACKET, ENVELOPE)


@pytest.mark.parametrize(
    "decision",
    [
        f"REVOKED（packetSha256={OTHER_PACKET}）",
        "REVOKED; envelopeId=FS-TRANSACTION-other-001",
        f"REVOKED; packetSha256={OTHER_PACKET}; envelopeId=FS-TRANSACTION-other-001",
        f"REVOKED; closurePacketSha256={OTHER_PACKET}",
        "REVOKED; envelopeId=FS-TRANSACTION-envelopeId-001",
        "REVOKED; envelopeId=FS-TRANSACTION-packetSha256-001",
        "REVOKED; envelopeId=FS-TRANSACTION-closurePacketSha256-001",
        "REVOKED; envelopeId=envelopeId",
        "REVOKED; envelopeId=packetSha256",
        "REVOKED; envelopeId=closurePacketSha256",
    ],
)
def test_valid_other_packet_and_envelope_scopes_remain_unrelated(decision):
    assert not shared._revoked_packet(decision, PACKET, ENVELOPE)


def authority_fixture(kind):
    family = {"legacy": "expiry-retry-04", "retry": "p09-grpc-retry", "idle": "p10-grpc-idle"}[kind]
    pins = {
        "packetName": family,
        "packetId": "synthetic-packet",
        "packetSha256": PACKET,
        "sourceCommit": "b" * 40,
        "runnerSha256": "c" * 64,
        "packetPath": "docs.local/reviews/synthetic.json",
        "envelopeId": "FS-TRANSACTION-" + family + "-001",
        "envelopePath": "docs.local/reviews/synthetic-envelope.md",
        "requestsPerRecording": 48,
        "estimatedUsdPerRecording": 0.01,
    }
    fields = "; ".join(
        f"{key}={pins[key]}"
        for key in ["envelopeId", "packetSha256", "sourceCommit", "runnerSha256", "requestsPerRecording", "estimatedUsdPerRecording"]
    )
    approval = f'- 2026-09-29 | FS-TRANSACTION {family} | decision=APPROVE; {fields}; recordings=2 | オーナー（synthetic） | {pins["packetPath"]}\n'
    if kind == "legacy":
        approval += f'- 2026-09-29 | FS-TRANSACTION {family} envelope | envelopeId={pins["envelopeId"]}; project=fireemu-oracle-sbx/(default); maxRequests=96; reserveUsd=0.04; writes=owned-five-documents; iamConfig=none; retries=none; onStop=needs-recovery-lock-held | オーナー（synthetic） | {pins["envelopePath"]}\n'
    function = {"legacy": shared._owner_approval, "retry": authorize_retry, "idle": authorize_idle}[kind]
    return function, approval, pins


@pytest.mark.parametrize("kind", ["legacy", "retry", "idle"])
@pytest.mark.parametrize("before", [False, True])
@pytest.mark.parametrize("shape", ["correction-topic", "recovery-topic", "short-row", "extra-column", "unrelated-topic"])
@pytest.mark.parametrize("scope", ["packet", "envelope", "malformed", "colon-envelope", "bare-envelope", "wrong-assignment", "case-envelope", "colon-packet", "bare-packet", "colon-closure", "case-packet"])
def test_every_current_authority_stops_raw_cancellation_before_approval(kind, before, shape, scope):
    function, approval, pins = authority_fixture(kind)
    decisions = {
        "packet": "packetSha256=" + pins["packetSha256"],
        "envelope": "envelopeId=" + pins["envelopeId"],
        "malformed": "packetSha256=broken",
        "colon-envelope": f"packetSha256={OTHER_PACKET}; envelopeId:broken",
        "bare-envelope": f"packetSha256={OTHER_PACKET}; envelopeId",
        "wrong-assignment": f"packetSha256={OTHER_PACKET}; envelopeId :=other",
        "case-envelope": f"packetSha256={OTHER_PACKET}; ENVELOPEID=other",
        "colon-packet": "envelopeId=other; packetSha256:broken",
        "bare-packet": "envelopeId=other; packetSha256",
        "colon-closure": "envelopeId=other; closurePacketSha256:broken",
        "case-packet": f"envelopeId=other; PACKETSHA256={OTHER_PACKET}",
    }
    topic = "AUTH-OTHER" if shape == "unrelated-topic" else "FS-TRANSACTION " + pins["packetName"] + (" correction" if shape == "correction-topic" else " recovery closure")
    row = f"- 2026-09-29 | {topic} | REVOKED（{decisions[scope]}） | オーナー（synthetic） | synthetic.md\n"
    if shape == "short-row":
        row = " | ".join(row.rstrip().split(" | ")[:3]) + "\n"
    elif shape == "extra-column":
        row = row.rstrip() + " | extra\n"
    function(approval, pins)
    # A valid unrelated topic with no matching identity is intentionally out of scope.
    if shape == "unrelated-topic" and scope not in ("packet", "envelope"):
        assert function(approval + row, pins) == function(approval, pins)
        return
    with pytest.raises(ValueError, match="[Rr][Ee][Vv][Oo][Kk][Ee][Dd]"):
        function(row + approval if before else approval + row, pins)


@pytest.mark.parametrize("kind", ["legacy", "retry", "idle"])
def test_other_scoped_cancellation_does_not_invalidate_current_approval(kind):
    function, approval, pins = authority_fixture(kind)
    row = f"- 2026-09-29 | FS-TRANSACTION {pins['packetName']} | REVOKED（packetSha256={OTHER_PACKET}; envelopeId=FS-TRANSACTION-other-001） | オーナー（synthetic） | other.json\n"
    assert function(approval + row, pins) == function(approval, pins)


def test_raw_matching_envelope_is_not_a_prefix_match_for_another_envelope():
    pins = {"packetSha256": PACKET, "envelopeId": ENVELOPE}
    shared.reject_revocations(
        f"- 2026-09-29 | AUTH-OTHER | REVOKED; envelopeId={ENVELOPE}0 | owner | other.json",
        pins,
    )


def test_plain_global_cancellation_ignores_unrelated_evidence_hashes():
    pins = {"packetSha256": PACKET, "envelopeId": ENVELOPE}
    with pytest.raises(ValueError, match="[Rr][Ee][Vv][Oo][Kk][Ee][Dd]"):
        shared.reject_revocations(
            f"- 2026-09-29 | FS-TRANSACTION | REVOKED（global; inspectionSha256={OTHER_PACKET}） | owner | other.json",
            pins,
        )
