"""Offline tests for the Auth packet05 recovery preparation boundary."""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import credential_recovery as recovery
import credential_recovery_prepare as prepare
from broad_contract import digest
from test_credential_recovery import _authorities, _parent, _provenance


class _ReadOnlyLedger:
    def __init__(self, parent: dict, *, used_nonce: str | None = None, canonical_gate: dict | None = None) -> None:
        self.path = Path("/private/ledger").resolve()
        self.identity = "l" * 64
        self.parent = copy.deepcopy(parent)
        self.used_nonce = used_nonce
        self.canonical_gate = copy.deepcopy(canonical_gate or parent["gate"])
        self.calls: list[str] = []

    def bound_claim(self, ticket: dict) -> dict:
        self.calls.append("bound_claim")
        assert ticket == self.parent["ticket"]
        return copy.deepcopy(self.parent["claim"])

    def bound_gate(self, ticket: dict) -> dict:
        self.calls.append("bound_gate")
        assert ticket == self.parent["ticket"]
        return copy.deepcopy(self.canonical_gate)

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
        rows[self.parent["ticket"]["reservation"]] = {
            "claim": copy.deepcopy(self.parent["claim"]),
            "claimDigest": digest(self.parent["claim"]),
            "state": "held",
            "generation": copy.deepcopy(self.parent["generation"]),
        }
        return {"identity": self.identity, "reservations": rows}


def _ledger_parent() -> dict:
    parent = _parent()
    claim = {
        key: value for key, value in parent["claim"].items() if key != "claimDigest"
    }
    parent["claim"] = {**claim, "claimDigest": digest(claim)}
    return parent


def _source_inputs(tmp_path: Path, parent: dict) -> tuple[Path, dict]:
    source_root = tmp_path / "clean-source"
    for relative in {
        recovery.WORKER_ENTRY,
        recovery.TRANSPORT_ENTRY,
        recovery.LAUNCHER_ENTRY,
        "tools/compat-broad/auth-credential-tokens/credential_recovery.py",
    }:
        destination = source_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(HERE.parents[2] / relative, destination)
    subprocess.run(["git", "-C", str(source_root), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(source_root), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(source_root), "config", "user.name", "Auth test"], check=True)
    subprocess.run(["git", "-C", str(source_root), "add", "tools"], check=True)
    subprocess.run(["git", "-C", str(source_root), "commit", "-qm", "source"], check=True)
    commit = subprocess.check_output(["git", "-C", str(source_root), "rev-parse", "HEAD"], text=True).strip()
    source_inputs = {}
    for relative in (recovery.WORKER_ENTRY, recovery.TRANSPORT_ENTRY, recovery.LAUNCHER_ENTRY):
        source_inputs[relative] = hashlib.sha256((source_root / relative).read_bytes()).hexdigest()
    parent["generation"]["sourceDigests"] = {
        "worker.py": source_inputs[recovery.WORKER_ENTRY],
        "transport.py": source_inputs[recovery.TRANSPORT_ENTRY],
    }
    parent["immutableParent"]["sourceCommit"] = commit
    parent["generation"]["sourceCommit"] = commit
    provenance = _provenance()
    provenance["sourceCommit"] = commit
    provenance["sourceInputs"] = source_inputs
    for key, relative in (("worker", recovery.WORKER_ENTRY), ("transport", recovery.TRANSPORT_ENTRY), ("launcher", recovery.LAUNCHER_ENTRY)):
        provenance[key]["sha256"] = source_inputs[relative]
    provenance["generation"]["sourceCommit"] = commit
    recovery_digest = hashlib.sha256((source_root / "tools/compat-broad/auth-credential-tokens/credential_recovery.py").read_bytes()).hexdigest()
    provenance["generation"]["sourceDigests"] = {
        "worker.py": source_inputs[recovery.WORKER_ENTRY],
        "transport.py": source_inputs[recovery.TRANSPORT_ENTRY],
        "recovery.py": recovery_digest,
    }
    provenance["generation"]["collectorSourceDigest"] = recovery_digest
    return source_root, provenance


def _reviewed(parent: dict, provenance: dict) -> tuple[dict, dict, dict]:
    plan = recovery.compile_recovery_plan(
        parent,
        recovery_nonce="fedcba9876543210fedcba9876543210",
        provenance=provenance,
        now=1000.0,
    )
    return _authorities(plan)


def test_preparation_compiles_fresh_authority_bundle_without_mutating_ledger(tmp_path: Path) -> None:
    parent = _ledger_parent()
    source_root, provenance = _source_inputs(tmp_path, parent)
    permission, o7, o8 = _reviewed(parent, provenance)
    ledger = _ReadOnlyLedger(parent)
    before = copy.deepcopy(ledger.snapshot())

    bundle = prepare.prepare_packet(
        parent,
        ledger=ledger,
        provenance=provenance,
        source_root=source_root,
        permission=permission,
        o7=o7,
        o8=o8,
        recovery_nonce="fedcba9876543210fedcba9876543210",
        now=1000.0,
        authority_now=1001.0,
    )

    assert bundle["kind"] == prepare.PACKET_KIND
    assert bundle["productionExecuted"] is False
    assert bundle["productionAllowed"] is False
    assert bundle["reviewRequest"]["reviewedArtifactsRequired"] is True
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
        now=1001.0,
    )
    assert "idToken" not in json.dumps(bundle)
    assert "refreshToken" not in json.dumps(bundle)
    assert ledger.snapshot() == before
    assert ledger.calls.count("bound_claim") == 1
    assert ledger.calls.count("snapshot") == 3


def test_preparation_requires_separately_reviewed_authority_documents(tmp_path: Path) -> None:
    parent = _ledger_parent()
    source_root, provenance = _source_inputs(tmp_path, parent)

    with pytest.raises(recovery.RecoveryRefusal, match="reviewed|authority"):
        prepare.prepare_packet(
            parent,
            ledger=_ReadOnlyLedger(parent),
            provenance=provenance,
            source_root=source_root,
            recovery_nonce="fedcba9876543210fedcba9876543210",
            now=1000.0,
            permission=None,
            o7=None,
            o8=None,
        )


def test_review_draft_is_available_before_separate_authority_review(tmp_path: Path) -> None:
    parent = _ledger_parent()
    source_root, provenance = _source_inputs(tmp_path, parent)

    draft = prepare.prepare_review_draft(
        parent,
        ledger=_ReadOnlyLedger(parent),
        provenance=provenance,
        source_root=source_root,
        recovery_nonce="fedcba9876543210fedcba9876543210",
        now=1000.0,
    )

    assert draft["reviewRequest"]["reviewedArtifactsRequired"] is True
    assert "permission" not in draft
    assert "o7" not in draft
    assert "o8" not in draft
    output = prepare.write_review_draft(draft, tmp_path / "draft")
    assert (output / "review-request.json").is_file()


def test_preparation_refuses_a_nonce_already_present_in_ledger(tmp_path: Path) -> None:
    parent = _ledger_parent()
    source_root, provenance = _source_inputs(tmp_path, parent)
    permission, o7, o8 = _reviewed(parent, provenance)
    ledger = _ReadOnlyLedger(parent, used_nonce="fedcba9876543210fedcba9876543210")

    with pytest.raises(recovery.RecoveryRefusal, match="fresh|reserved"):
        prepare.prepare_packet(
            parent,
            ledger=ledger,
            provenance=provenance,
            source_root=source_root,
            permission=permission,
            o7=o7,
            o8=o8,
            recovery_nonce="fedcba9876543210fedcba9876543210",
            now=1000.0,
        )


def test_preparation_rejects_future_reviewed_o7_and_o8(tmp_path: Path) -> None:
    parent = _ledger_parent()
    source_root, provenance = _source_inputs(tmp_path, parent)
    permission, o7, o8 = _reviewed(parent, provenance)
    o7["issuedAt"] = 1100.0
    o8["issuedAt"] = 1100.0

    with pytest.raises(recovery.RecoveryRefusal, match="active|issued"):
        prepare.prepare_packet(
            parent,
            ledger=_ReadOnlyLedger(parent),
            provenance=provenance,
            source_root=source_root,
            permission=permission,
            o7=o7,
            o8=o8,
            recovery_nonce="fedcba9876543210fedcba9876543210",
            now=1000.0,
            authority_now=1001.0,
        )


def test_preparation_refuses_source_checkout_digest_drift(tmp_path: Path) -> None:
    parent = _ledger_parent()
    source_root, provenance = _source_inputs(tmp_path, parent)
    permission, o7, o8 = _reviewed(parent, provenance)
    (source_root / recovery.WORKER_ENTRY).write_text("drift")

    with pytest.raises(recovery.RecoveryRefusal, match="source checkout|digest"):
        prepare.prepare_packet(
            parent,
            ledger=_ReadOnlyLedger(parent),
            provenance=provenance,
            source_root=source_root,
            permission=permission,
            o7=o7,
            o8=o8,
            recovery_nonce="fedcba9876543210fedcba9876543210",
            now=1000.0,
            authority_now=1001.0,
        )


def test_preparation_reconstructs_parent_gate_from_canonical_ledger_binding(tmp_path: Path) -> None:
    parent = _ledger_parent()
    canonical_gate = copy.deepcopy(parent["gate"])
    source_root, provenance = _source_inputs(tmp_path, parent)
    tampered = copy.deepcopy(parent)
    tampered["gate"]["plan"]["nonce"] = "f" * 32
    permission, o7, o8 = _reviewed(parent, provenance)

    bundle = prepare.prepare_packet(
        tampered,
        ledger=_ReadOnlyLedger(parent, canonical_gate=canonical_gate),
        provenance=provenance,
        source_root=source_root,
        permission=permission,
        o7=o7,
        o8=o8,
        recovery_nonce="fedcba9876543210fedcba9876543210",
        now=1000.0,
        authority_now=1001.0,
    )

    assert bundle["parentEvidence"] == recovery._parent_snapshot(parent)["evidence"]


@pytest.mark.parametrize("authority", ["permission", "o7", "o8"])
def test_preparation_refuses_authority_bundle_before_its_issued_at(
    authority: str,
    tmp_path: Path,
) -> None:
    parent = _ledger_parent()
    _source_root, provenance = _source_inputs(tmp_path, parent)
    permission, o7, o8 = _reviewed(parent, provenance)
    plan = recovery.compile_recovery_plan(parent, recovery_nonce="fedcba9876543210fedcba9876543210", provenance=provenance, now=1000.0)

    reviewed = {"permission": permission, "o7": o7, "o8": o8}
    reviewed[authority]["issuedAt"] = 1001.0
    if authority == "permission":
        permission_digest = digest(reviewed["permission"])
        reviewed["o7"]["permissionDigest"] = permission_digest
        reviewed["o8"]["permissionDigest"] = permission_digest
    with pytest.raises(recovery.RecoveryRefusal, match="active|issued|ordering"):
        recovery.validate_authority_bundle(
            plan,
            permission=reviewed["permission"],
            o7=reviewed["o7"],
            o8=reviewed["o8"],
            now=999.0,
        )


def test_preparation_normalizes_malformed_nested_parent_to_secret_free_refusal(tmp_path: Path) -> None:
    parent = _ledger_parent()
    parent["gate"]["jobs"] = None
    source_root, provenance = _source_inputs(tmp_path, parent)

    with pytest.raises(recovery.RecoveryRefusal, match="malformed|parent"):
        prepare.prepare_packet(
            parent,
            ledger=_ReadOnlyLedger(parent),
            provenance=provenance,
            source_root=source_root,
            permission=None,
            o7=None,
            o8=None,
            recovery_nonce="fedcba9876543210fedcba9876543210",
            now=1000.0,
        )


def test_write_packet_creates_private_redacted_artifacts_without_printing_bundle(
    tmp_path: Path,
) -> None:
    parent = _ledger_parent()
    source_root, provenance = _source_inputs(tmp_path, parent)
    permission, o7, o8 = _reviewed(parent, provenance)
    bundle = prepare.prepare_packet(
        parent,
        ledger=_ReadOnlyLedger(parent),
        provenance=provenance,
        source_root=source_root,
        permission=permission,
        o7=o7,
        o8=o8,
        recovery_nonce="fedcba9876543210fedcba9876543210",
        now=1000.0,
        authority_now=1001.0,
    )
    output = tmp_path / "packet"

    result = prepare.write_packet(bundle, output)

    assert result == output
    assert output.stat().st_mode & 0o077 == 0
    assert {path.name for path in output.iterdir()} == {
        "packet.json",
        "review-request.json",
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
