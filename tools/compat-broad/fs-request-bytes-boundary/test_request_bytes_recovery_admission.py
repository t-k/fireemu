"""TDD coverage for the closed request-byte recovery issuer boundary."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "o8-core"))
sys.path.insert(0, str(HERE.parent / "production-admission"))

import o8_admission
import pytest
import request_bytes_descriptor as parent_descriptor
import request_bytes_recovery_admission as recovery
from broad_contract import digest
from test_recovery_extensions import _recovery_fixture


def bound_fixture():
    parent = {"claimDigest": "c" * 64, "campaignId": recovery.CAMPAIGN}
    claim = {
        "campaignId": recovery.CAMPAIGN,
        "parentClaimDigest": parent["claimDigest"],
        "permissionDigest": digest({"permission": "child"}),
        "budget": dict(recovery.CHILD_BUDGET),
    }
    envelope = {"permissionDigest": claim["permissionDigest"]}
    ticket = {
        "ledgerPath": "/tmp/ledger",
        "ledgerIdentity": "d" * 64,
        "reservation": "e" * 64,
        "claimDigest": digest(claim),
        "envelopeDigest": digest(envelope),
        "parentReservation": "f" * 64,
    }
    return {
        "ticket": ticket,
        "childClaim": claim,
        "newEnvelope": envelope,
        "parentClaim": parent,
        "parentIdentity": {
            "ledgerPath": ticket["ledgerPath"],
            "ledgerIdentity": ticket["ledgerIdentity"],
            "reservation": ticket["parentReservation"],
            "claimDigest": parent["claimDigest"],
            "envelopeDigest": "1" * 64,
        },
        "deadline": 1234,
        "state": "allocated",
    }


def test_recovery_descriptor_keeps_stable_campaign_and_85_budget():
    descriptor = recovery.descriptor()
    assert descriptor.campaign_id == "FS-LIMIT-API-REQUEST-BYTES"
    assert descriptor.budget == {
        "requests": 85,
        "accounts": 0,
        "resources": 51,
        "costMicrousd": 85,
    }
    sources = descriptor.source_map()
    assert "tools/compat-broad/production-admission/reservations.py" in sources
    assert "tools/compat-broad/shared_gate.py" in sources
    assert "tools/compat-broad/fs-request-bytes-boundary/request_bytes_recovery_admission.py" in sources


def test_bound_child_requires_exact_ticket_claim_and_parent_binding():
    bound = bound_fixture()
    assert recovery.validate_bound_child(bound)["childClaim"] == bound["childClaim"]
    tamper_fields = {
        "ticket": "claimDigest",
        "childClaim": "budget",
        "newEnvelope": "permissionDigest",
        "parentIdentity": "reservation",
    }
    for key, field in tamper_fields.items():
        altered = bound_fixture()
        altered[key] = dict(altered[key])
        altered[key][field] = "tampered"
        with pytest.raises(ValueError):
            recovery.validate_bound_child(altered)


def test_real_o7_core_issues_opaque_child_capability(tmp_path):
    child_gate_plan = {
        "campaignId": recovery.CAMPAIGN,
        "nonce": "0123456789abcdef0123456789abcdef",
        "recoveryRequests": 85,
        "costMicrousd": 85,
    }
    permission = {
        "kind": recovery.descriptor().permission_kind,
        "wallSeconds": recovery.descriptor().campaign_seconds,
        "recoverySeconds": recovery.descriptor().recovery_seconds,
    }
    parent = {"claimDigest": "c" * 64, "campaignId": recovery.CAMPAIGN}
    envelope = {"permissionDigest": digest(permission), "limits": dict(recovery.CHILD_BUDGET)}
    claim = {
        "campaignId": recovery.CAMPAIGN,
        "parentClaimDigest": parent["claimDigest"],
        "permissionDigest": digest(permission),
        "gatePlanDigest": digest(child_gate_plan),
        "budget": dict(recovery.CHILD_BUDGET),
    }
    ticket = {
        "ledgerPath": str(tmp_path / "ledger"),
        "ledgerIdentity": "d" * 64,
        "reservation": "e" * 64,
        "claimDigest": digest(claim),
        "envelopeDigest": digest(envelope),
        "parentReservation": "f" * 64,
    }
    bound = {
        "ticket": ticket,
        "childClaim": claim,
        "newEnvelope": envelope,
        "parentClaim": parent,
        "parentIdentity": {
            "ledgerPath": ticket["ledgerPath"],
            "ledgerIdentity": ticket["ledgerIdentity"],
            "reservation": ticket["parentReservation"],
            "claimDigest": parent["claimDigest"],
            "envelopeDigest": "1" * 64,
        },
        "deadline": time.time() + 1000,
        "state": "allocated",
    }
    child_plan = {
        "campaignId": recovery.CAMPAIGN,
        "nonce": child_gate_plan["nonce"],
        "childClaimDigest": digest(claim),
        "childTicketDigest": digest(ticket),
        "recoveryRequests": 85,
        "costMicrousd": 85,
    }
    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"offline-child-artifact")
    manifest = {"kind": recovery.descriptor().manifest_kind}
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_bytes(json.dumps(manifest).encode())
    inputs = recovery.freeze_inputs(
        bound,
        child_plan,
        child_gate_plan,
        permission,
        source_commit="0" * 40,
        artifact_sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
    )
    manifest["inputsDigest"] = inputs["inputsDigest"]
    manifest_bytes = json.dumps(manifest).encode()
    manifest_path.write_bytes(manifest_bytes)
    approval = {
        "kind": recovery.descriptor().approval_kind,
        "status": "approved",
        "manifestSha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "inputsDigest": inputs["inputsDigest"],
        "permissionDigest": inputs["permissionDigest"],
        "sourceCommit": inputs["sourceCommit"],
        "sourceInputsDigest": digest(inputs["sourceInputs"]),
        "artifactSha256": inputs["artifactSha256"],
        "planDigest": inputs["planDigest"],
        "nonceDigest": digest(child_plan["nonce"]),
        "ledgerRoot": str((tmp_path / "ledger").resolve()),
        "launcherSha256": hashlib.sha256(
            (Path(__file__).with_name("request_bytes_o8.py")).read_bytes()
        ).hexdigest(),
        "artifactProfile": recovery.descriptor().artifact_profile,
        "campaignId": recovery.CAMPAIGN,
        "windowStartsAt": time.time() - 1,
        "windowExpiresAt": time.time() + 4000,
        "executionHost": o8_admission.execution_host(),
    }
    binding, binding_digest = parent_descriptor.worker_binding()
    capability = recovery.issue_production_capability(
        bound=bound,
        child_plan=child_plan,
        child_gate_plan=child_gate_plan,
        inputs=inputs,
        approval=approval,
        manifest=manifest,
        manifest_bytes=manifest_bytes,
        manifest_path=manifest_path,
        permission=permission,
        ledger_root=tmp_path / "ledger",
        artifact_path=artifact,
        launcher_path=Path(__file__).with_name("request_bytes_o8.py"),
        binding=binding,
        binding_digest=binding_digest,
    )
    assert type(capability).__name__ == "ProductionWireCapability"
    assert capability.campaign_id == recovery.CAMPAIGN
    assert capability.inputs_digest == inputs["inputsDigest"]
    expired = copy.deepcopy(approval)
    expired["windowStartsAt"] = time.time() - 4000
    expired["windowExpiresAt"] = time.time() - 1
    with pytest.raises(ValueError, match="window expired"):
        o8_admission.validate_o7_admission(
            recovery.descriptor(),
            inputs=inputs,
            approval=expired,
            manifest=manifest,
            manifest_bytes=manifest_bytes,
            manifest_path=manifest_path,
            permission=permission,
            ledger_root=tmp_path / "ledger",
            artifact_path=artifact,
            launcher_path=Path(__file__).with_name("request_bytes_o8.py"),
        )
    with pytest.raises(ValueError, match="worker source digest"):
        recovery.descriptor().binding_verifier(
            binding + b"tampered", binding_digest, inputs["sourceInputs"]
        )
    altered_inputs = copy.deepcopy(inputs)
    altered_inputs["sourceInputs"]["tools/compat-broad/shared_gate.py"] = "0" * 64
    with pytest.raises(ValueError, match="frozen approval binding"):
        o8_admission.validate_frozen_inputs(recovery.descriptor(), altered_inputs)


def test_real_ledger_child_reader_binds_issuer_input(tmp_path):
    ledger, parent_ticket, child, envelope, parent_plan, child_plan = _recovery_fixture(tmp_path)
    child_ticket = ledger.begin_recovery_extension(
        parent_ticket, child, envelope, parent_plan, child_plan, now=1100
    )
    bound = ledger.bound_recovery_claim(child_ticket)
    assert recovery.validate_bound_child(bound)["ticket"] == child_ticket
    forged = dict(child_ticket, claimDigest="0" * 64)
    with pytest.raises(ValueError, match="exact persisted recovery child ticket"):
        ledger.bound_recovery_claim(forged)
