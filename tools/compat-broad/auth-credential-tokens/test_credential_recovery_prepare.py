"""Offline tests for the Auth packet05 recovery preparation boundary."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import credential_recovery as recovery
import credential_recovery_prepare as prepare
from broad_contract import digest
from test_credential_recovery import _parent, _provenance


class _ReadOnlyLedger:
    def __init__(self, parent: dict, *, used_nonce: str | None = None) -> None:
        self.path = Path("/private/ledger").resolve()
        self.identity = "l" * 64
        self.parent = copy.deepcopy(parent)
        self.used_nonce = used_nonce
        self.calls: list[str] = []

    def bound_claim(self, ticket: dict) -> dict:
        self.calls.append("bound_claim")
        assert ticket == self.parent["ticket"]
        return copy.deepcopy(self.parent["claim"])

    def snapshot(self) -> dict:
        self.calls.append("snapshot")
        rows = {}
        if self.used_nonce is not None:
            rows["prior"] = {
                "claim": {
                    "campaignId": recovery.CAMPAIGN,
                    "nonceDigest": digest(self.used_nonce),
                },
                "recoveryChildren": [],
            }
        return {"identity": self.identity, "reservations": rows}


def _ledger_parent() -> dict:
    parent = _parent()
    claim = {
        key: value for key, value in parent["claim"].items() if key != "claimDigest"
    }
    parent["claim"] = {**claim, "claimDigest": digest(claim)}
    return parent


def test_preparation_compiles_fresh_authority_bundle_without_mutating_ledger() -> None:
    parent = _ledger_parent()
    ledger = _ReadOnlyLedger(parent)
    before = copy.deepcopy(ledger.snapshot())

    bundle = prepare.prepare_packet(
        parent,
        ledger=ledger,
        provenance=_provenance(),
        recovery_nonce="fedcba9876543210fedcba9876543210",
        now=1000.0,
    )

    assert bundle["kind"] == prepare.PACKET_KIND
    assert bundle["productionExecuted"] is False
    assert bundle["productionAllowed"] is False
    assert bundle["parentEvidence"] == recovery._parent_snapshot(parent)["evidence"]
    assert (
        bundle["immutableParent"]["sourceCommit"]
        == parent["immutableParent"]["sourceCommit"]
    )
    assert bundle["plan"]["recoveryNonce"] != parent["immutableParent"]["nonce"]
    recovery.validate_authority_bundle(
        bundle["plan"],
        permission=bundle["permission"],
        o7=bundle["o7"],
        o8=bundle["o8"],
        now=1000.0,
    )
    assert "idToken" not in json.dumps(bundle)
    assert "refreshToken" not in json.dumps(bundle)
    assert ledger.snapshot() == before
    assert ledger.calls.count("bound_claim") == 1
    assert ledger.calls.count("snapshot") == 3


def test_preparation_refuses_a_nonce_already_present_in_ledger() -> None:
    parent = _ledger_parent()
    ledger = _ReadOnlyLedger(parent, used_nonce="fedcba9876543210fedcba9876543210")

    with pytest.raises(recovery.RecoveryRefusal, match="fresh|reserved"):
        prepare.prepare_packet(
            parent,
            ledger=ledger,
            provenance=_provenance(),
            recovery_nonce="fedcba9876543210fedcba9876543210",
            now=1000.0,
        )


@pytest.mark.parametrize("authority", ["permission", "o7", "o8"])
def test_preparation_refuses_authority_bundle_before_its_issued_at(
    authority: str,
) -> None:
    parent = _ledger_parent()
    bundle = prepare.prepare_packet(
        parent,
        ledger=_ReadOnlyLedger(parent),
        provenance=_provenance(),
        recovery_nonce="fedcba9876543210fedcba9876543210",
        now=1000.0,
    )

    bundle[authority]["issuedAt"] = 1001.0
    if authority == "permission":
        permission_digest = digest(bundle["permission"])
        bundle["o7"]["permissionDigest"] = permission_digest
        bundle["o8"]["permissionDigest"] = permission_digest
    with pytest.raises(recovery.RecoveryRefusal, match="active|issued|ordering"):
        recovery.validate_authority_bundle(
            bundle["plan"],
            permission=bundle["permission"],
            o7=bundle["o7"],
            o8=bundle["o8"],
            now=999.0,
        )


def test_preparation_normalizes_malformed_nested_parent_to_secret_free_refusal() -> (
    None
):
    parent = _ledger_parent()
    parent["gate"]["jobs"] = None

    with pytest.raises(recovery.RecoveryRefusal, match="malformed|parent"):
        prepare.prepare_packet(
            parent,
            ledger=_ReadOnlyLedger(parent),
            provenance=_provenance(),
            recovery_nonce="fedcba9876543210fedcba9876543210",
            now=1000.0,
        )


def test_write_packet_creates_private_redacted_artifacts_without_printing_bundle(
    tmp_path: Path,
) -> None:
    parent = _ledger_parent()
    bundle = prepare.prepare_packet(
        parent,
        ledger=_ReadOnlyLedger(parent),
        provenance=_provenance(),
        recovery_nonce="fedcba9876543210fedcba9876543210",
        now=1000.0,
    )
    output = tmp_path / "packet"

    result = prepare.write_packet(bundle, output)

    assert result == output
    assert output.stat().st_mode & 0o077 == 0
    assert {path.name for path in output.iterdir()} == {
        "packet.json",
        "plan.json",
        "permission.json",
        "o7.json",
        "o8.json",
        "parent-evidence.json",
    }
    packet = json.loads((output / "packet.json").read_text())
    assert packet["productionExecuted"] is False
    assert packet["parentEvidence"] == bundle["parentEvidence"]
    assert "idToken" not in (output / "packet.json").read_text()


def test_preparation_output_cannot_be_created_inside_canonical_ledger(
    tmp_path: Path,
) -> None:
    parent = _ledger_parent()
    ledger = _ReadOnlyLedger(parent)

    with pytest.raises(recovery.RecoveryRefusal, match="outside canonical Ledger"):
        prepare._assert_output_detached(ledger.path / "prepared", ledger)
