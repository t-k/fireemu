import hashlib
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/production-admission"))

import o8_admission
import reservations
import shared_gate
from broad_contract import digest
from rev3_o8 import (
    CAMPAIGN_ID,
    SELECTOR,
    compile_plan,
    descriptor_for_plan,
    freeze_inputs,
    reservation_claim,
    validate_frozen_inputs,
    validate_o7_admission,
    verify_source_snapshot,
)

NONCE = "fedcba9876543210fedcba9876543210"


def _synthetic_source_repo(tmp_path, source_inputs):
    root = tmp_path / "synthetic-source"
    for name in source_inputs:
        source = ROOT / name
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
    subprocess.run(
        ["git", "-C", str(root), "config", "user.email", "fixture@example.invalid"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(root), "config", "user.name", "Offline Fixture"],
        check=True,
    )
    subprocess.run(["git", "-C", str(root), "add", *source_inputs], check=True)
    subprocess.run(
        ["git", "-C", str(root), "commit", "-qm", "offline source fixture"],
        check=True,
    )
    commit = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
    ).strip()
    return root, commit


def _synthetic_o7(tmp_path):
    plan = compile_plan(NONCE)
    descriptor = descriptor_for_plan(plan)
    artifact = tmp_path / "retained-artifact.bin"
    artifact.write_bytes(b"offline synthetic fixture; no production permission")
    artifact_sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
    source_inputs = descriptor.source_map()
    source_root, source_commit = _synthetic_source_repo(tmp_path, source_inputs)
    permission = descriptor.permission_bindings(
        plan,
        source_commit,
        artifact_sha,
        source_inputs,
        "b" * 64,
        credential_principal={
            "clientId": "offline-fixture-client",
            "verifiedEmail": "fixture@example.invalid",
            "requiredScopes": ["https://www.googleapis.com/auth/cloud-platform"],
            "requiredRole": "roles/firebaseauth.admin",
        },
        api_key_project_number="592603257417",
    )
    inputs = freeze_inputs(
        descriptor,
        permission,
        plan,
        source_commit=source_commit,
        source_root=source_root,
        artifact_sha256=artifact_sha,
    )
    manifest = {
        "kind": descriptor.manifest_kind,
        "inputsDigest": inputs["inputsDigest"],
        "fixtureOnly": True,
    }
    manifest_bytes = json.dumps(manifest, sort_keys=True).encode()
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_bytes(manifest_bytes)
    ledger_root = tmp_path / "synthetic-ledger"
    launcher = tmp_path / "synthetic-launcher"
    launcher.write_bytes(b"fixture launcher")
    approval = {
        "kind": descriptor.approval_kind,
        "status": "approved",
        "manifestSha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "inputsDigest": inputs["inputsDigest"],
        "permissionDigest": inputs["permissionDigest"],
        "sourceCommit": inputs["sourceCommit"],
        "sourceInputsDigest": digest(inputs["sourceInputs"]),
        "artifactSha256": inputs["artifactSha256"],
        "planDigest": inputs["planDigest"],
        "nonceDigest": digest(plan["nonce"]),
        "ledgerRoot": str(ledger_root.resolve()),
        "launcherSha256": o8_admission.regular_file_digest(launcher),
        "artifactProfile": descriptor.artifact_profile,
        "windowStartsAt": time.time() - 1,
        "windowExpiresAt": time.time() + descriptor.window_seconds + 60,
        "executionHost": o8_admission.execution_host(),
        "campaignId": CAMPAIGN_ID,
    }
    return {
        "descriptor": descriptor,
        "source_root": source_root,
        "plan": plan,
        "inputs": inputs,
        "permission": permission,
        "approval": approval,
        "manifest": manifest,
        "manifest_bytes": manifest_bytes,
        "manifest_path": manifest_path,
        "artifact_path": artifact,
        "launcher_path": launcher,
        "ledger_root": ledger_root,
    }


def test_rev3_o7_synthetic_fixture_validates_exact_source_and_gate_claim(tmp_path):
    fixture = _synthetic_o7(tmp_path)
    validate_frozen_inputs(fixture["inputs"], fixture["descriptor"])
    admitted = validate_o7_admission(
        descriptor=fixture["descriptor"],
        inputs=fixture["inputs"],
        approval=fixture["approval"],
        manifest=fixture["manifest"],
        manifest_bytes=fixture["manifest_bytes"],
        manifest_path=fixture["manifest_path"],
        permission=fixture["permission"],
        ledger_root=fixture["ledger_root"],
        artifact_path=fixture["artifact_path"],
        launcher_path=fixture["launcher_path"],
        source_root=fixture["source_root"],
    )

    assert admitted["campaignId"] == CAMPAIGN_ID
    assert fixture["plan"]["selector"] == SELECTOR
    assert len(fixture["plan"]["caseIds"]) == 17
    assert set(fixture["descriptor"].source_map()) >= {
        "tools/auth-pending-lifetime-window/window_recorder.py",
        "tools/auth-pending-lifetime-window/rev3_gate.py",
        "tools/auth-password-maximum/maximum_recorder.py",
        "tools/auth-pending-revocation/revocation_recorder.py",
        "tools/compat-broad/shared_gate.py",
        "tools/compat-broad/production-admission/reservations.py",
        "tools/compat-broad/o8-core/o8_admission.py",
    }
    assert fixture["permission"]["credentialContract"]["principalRequired"] is True
    assert fixture["permission"]["credentialContract"]["principal"]["requiredRole"] == (
        "roles/firebaseauth.admin"
    )
    assert fixture["permission"]["recoveryContract"]["seconds"] == 300
    shared_gate.create(tmp_path / "synthetic-gate", fixture["plan"])
    claim = reservation_claim(
        fixture["inputs"],
        gate_path=tmp_path / "gate",
        gate_plan=fixture["plan"],
        descriptor=fixture["descriptor"],
        source_root=fixture["source_root"],
    )
    assert claim["campaignId"] == CAMPAIGN_ID
    assert claim["durationSeconds"] == 1500
    assert claim["manifestDigest"] == fixture["inputs"]["planDigest"]
    assert claim["gatePlanDigest"] == digest(fixture["plan"])
    assert any(lock["mode"] == "EXCLUSIVE" for lock in claim["locks"])
    now = time.time()
    envelope = {
        "permissionDigest": fixture["inputs"]["permissionDigest"],
        "issuedAt": now - 1,
        "expiresAt": now + 1900,
        "limits": claim["budget"],
        "concurrency": 1,
        "scopes": claim["locks"],
    }
    ledger = reservations.Ledger.create(fixture["ledger_root"])
    ticket = ledger.reserve(envelope, claim, fixture["plan"], now=now)
    shared_gate.create(tmp_path / "gate", fixture["plan"])
    state = ledger.snapshot()
    reservation = state["reservations"][ticket["reservation"]]
    assert reservation["state"] == "held"
    assert reservation["claim"] == claim
    with pytest.raises(ValueError, match="production worker binding unavailable"):
        o8_admission.issue_production_capability(
            fixture["descriptor"],
            inputs=fixture["inputs"],
            approval=fixture["approval"],
            manifest=fixture["manifest"],
            manifest_bytes=fixture["manifest_bytes"],
            manifest_path=fixture["manifest_path"],
            permission=fixture["permission"],
            ledger_root=fixture["ledger_root"],
            artifact_path=fixture["artifact_path"],
            launcher_path=fixture["launcher_path"],
            binding=b"synthetic fixture only",
            binding_digest="0" * 64,
        )
    with pytest.raises(ValueError, match="dispatch and recovery adapter unavailable"):
        fixture["descriptor"].collector(
            None,
            fixture["plan"],
            tmp_path / "private-output",
            sleeper=None,
        )
    with pytest.raises(ValueError, match="production transport adapter unavailable"):
        fixture["descriptor"].transport_bound(
            {"method": "POST"}, binding=b"", binding_digest="0" * 64
        )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda plan: plan.update(selector="pending-age-300-v1"),
        lambda plan: plan.update(campaignId="AUTH-MFA-AGE-TOTP-01-v2"),
        lambda plan: plan.update(caseIds=plan["caseIds"][:-1]),
        lambda plan: plan.update(caseDigest="0" * 64),
        lambda plan: plan.update(wallSeconds=1501),
    ],
)
def test_rev3_admission_rejects_unbound_plan_variants(tmp_path, mutation):
    fixture = _synthetic_o7(tmp_path)
    changed_plan = json.loads(json.dumps(fixture["plan"]))
    mutation(changed_plan)
    changed_inputs = dict(fixture["inputs"], plan=changed_plan)
    with pytest.raises(ValueError):
        validate_frozen_inputs(changed_inputs, fixture["descriptor"])


def test_rev3_source_snapshot_rejects_dirty_or_wrong_commit(tmp_path):
    fixture = _synthetic_o7(tmp_path)
    verify_source_snapshot(
        fixture["source_root"],
        fixture["inputs"]["sourceCommit"],
        fixture["inputs"]["sourceInputs"],
    )
    (fixture["source_root"] / "unexpected.py").write_text("dirty\n", encoding="utf-8")
    with pytest.raises(ValueError, match="clean frozen source snapshot required"):
        verify_source_snapshot(
            fixture["source_root"],
            fixture["inputs"]["sourceCommit"],
            fixture["inputs"]["sourceInputs"],
        )
    with pytest.raises(ValueError, match="clean frozen source snapshot required"):
        verify_source_snapshot(
            fixture["source_root"],
            "0" * 40,
            fixture["inputs"]["sourceInputs"],
        )


def test_rev3_permission_requires_owner_principal_and_bound_api_project(tmp_path):
    fixture = _synthetic_o7(tmp_path)
    principal = {
        "clientId": "offline-fixture-client",
        "verifiedEmail": "fixture@example.invalid",
        "requiredScopes": ["https://www.googleapis.com/auth/cloud-platform"],
        "requiredRole": "roles/firebaseauth.admin",
    }
    with pytest.raises(
        ValueError, match="owner-supplied credential principal required"
    ):
        fixture["descriptor"].permission_bindings(
            fixture["plan"],
            fixture["inputs"]["sourceCommit"],
            fixture["inputs"]["artifactSha256"],
            fixture["inputs"]["sourceInputs"],
            fixture["permission"]["authConfigBaselineDigest"],
            credential_principal=None,
            api_key_project_number=fixture["plan"]["project"],
        )
    with pytest.raises(ValueError, match="API key project number differs"):
        fixture["descriptor"].permission_bindings(
            fixture["plan"],
            fixture["inputs"]["sourceCommit"],
            fixture["inputs"]["artifactSha256"],
            fixture["inputs"]["sourceInputs"],
            fixture["permission"]["authConfigBaselineDigest"],
            credential_principal=principal,
            api_key_project_number="0",
        )
    with pytest.raises(
        ValueError, match="Auth configuration baseline SHA-256 required"
    ):
        fixture["descriptor"].permission_bindings(
            fixture["plan"],
            fixture["inputs"]["sourceCommit"],
            fixture["inputs"]["artifactSha256"],
            fixture["inputs"]["sourceInputs"],
            "z" * 64,
            credential_principal=principal,
            api_key_project_number="592603257417",
        )
