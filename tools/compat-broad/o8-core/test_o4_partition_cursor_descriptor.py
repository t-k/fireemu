"""Offline dry run of the O4 partition/cursor descriptor.

Nothing here reaches production: no credential, no origin, no Ledger and no
collector run. The synthetic approval is built from local files in tmp_path, and
every production member of the descriptor is left unwired so that it refuses.
"""

import hashlib
import json
import sys
import time
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/fs-query-partition-cursor"))
sys.path.insert(0, str(HERE))

import o4_partition_cursor_descriptor as o4
import o8_admission
import partition_cursor_manifest
from broad_contract import digest


def synthetic(tmp_path, descriptor):
    """A complete O7 artifact set for the dry run, built from local files only."""
    permission = {
        "kind": o4.PERMISSION_KIND,
        "wallSeconds": o4.CAMPAIGN_SECONDS,
        "recoverySeconds": o4.RECOVERY_SECONDS,
    }
    plan = descriptor.plan_compiler("a" * 32)
    inputs = o8_admission.freeze_inputs(
        descriptor,
        permission,
        plan,
        source_commit="0" * 40,
        artifact_sha256="b" * 64,
    )
    manifest = {"kind": o4.MANIFEST_KIND, "inputsDigest": inputs["inputsDigest"]}
    manifest_bytes = json.dumps(manifest).encode()
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_bytes(manifest_bytes)
    artifact_path = tmp_path / "artifact"
    artifact_path.write_bytes(b"synthetic artifact")
    launcher_path = tmp_path / "launcher.py"
    launcher_path.write_bytes(b"# synthetic launcher\n")
    ledger = tmp_path / "ledger"
    now = time.time()
    approval = {
        "kind": o4.APPROVAL_KIND,
        "status": "approved",
        "campaignId": descriptor.campaign_id,
        "manifestSha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "inputsDigest": inputs["inputsDigest"],
        "permissionDigest": inputs["permissionDigest"],
        "sourceCommit": inputs["sourceCommit"],
        "sourceInputsDigest": digest(inputs["sourceInputs"]),
        "artifactSha256": inputs["artifactSha256"],
        "planDigest": inputs["planDigest"],
        "nonceDigest": digest(plan["nonce"]),
        "ledgerRoot": str(ledger.resolve(strict=False)),
        "launcherSha256": hashlib.sha256(launcher_path.read_bytes()).hexdigest(),
        "artifactProfile": o4.ARTIFACT_PROFILE,
        "windowStartsAt": now - 1,
        "windowExpiresAt": now + 4 * (o4.CAMPAIGN_SECONDS + o4.RECOVERY_SECONDS),
        "executionHost": o8_admission.execution_host(),
    }
    return {
        "inputs": inputs,
        "approval": approval,
        "manifest": manifest,
        "manifest_bytes": manifest_bytes,
        "manifest_path": manifest_path,
        "permission": permission,
        "ledger_root": ledger,
        "artifact_path": artifact_path,
        "launcher_path": launcher_path,
    }


def retained_for(inputs, manifest_path):
    def validator(artifact_path, path, profile):
        assert profile == o4.ARTIFACT_PROFILE
        return {
            "artifactSha256": inputs["artifactSha256"],
            "retainedManifestSha256": hashlib.sha256(
                Path(path).read_bytes()
            ).hexdigest(),
        }

    return validator


def test_the_o4_frozen_inputs_cover_the_lane_and_the_shared_closure(tmp_path):
    descriptor = o4.descriptor()
    bindings = synthetic(tmp_path, descriptor)
    inputs = bindings["inputs"]
    sources = inputs["sourceInputs"]
    assert inputs["kind"] == o4.FROZEN_INPUTS_KIND
    assert inputs["bounds"]["totalRequests"] == 47
    assert set(partition_cursor_manifest.source_inputs()) <= set(sources)
    for name in (*o4.SHARED_CLOSURE, o4.COLLECTOR_ENTRY, o4.COMPARATOR_ENTRY):
        assert sources[name] == hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
    o8_admission.validate_frozen_inputs(descriptor, inputs)
    generation = o8_admission.abort_generation(descriptor, inputs)
    assert set(generation["sourceDigests"]) == {
        "shared_gate.py",
        "reservations.py",
        "partition_cursor_collector.py",
        "partition_cursor_comparator.py",
    }


def test_a_synthetic_o4_approval_passes_the_shared_o7_check_set(tmp_path):
    """The generic admission core carries a second campaign unchanged."""
    bindings = synthetic(tmp_path, o4.descriptor())
    descriptor = o4.descriptor(
        retained_artifact_validator=retained_for(
            bindings["inputs"], bindings["manifest_path"]
        )
    )
    admitted = o8_admission.validate_o7_admission(descriptor, **bindings)
    assert admitted["campaignId"] == "FS-QUERY-PARTITION-CURSOR-04"
    assert admitted["ledgerRoot"] == str(bindings["ledger_root"].resolve(strict=False))


def test_a_commit_approval_cannot_be_admitted_by_the_o4_descriptor(tmp_path):
    bindings = synthetic(tmp_path, o4.descriptor())
    descriptor = o4.descriptor(
        retained_artifact_validator=retained_for(
            bindings["inputs"], bindings["manifest_path"]
        )
    )
    for override in (
        {"campaignId": "FS-DATA-WRITE-COMMIT-TRANSFORMS-03"},
        {"kind": "commit-o8-approval-v1"},
        {"artifactProfile": "repaired-567565bdd"},
    ):
        with pytest.raises(ValueError):
            o8_admission.validate_o7_admission(
                descriptor,
                **{**bindings, "approval": {**bindings["approval"], **override}},
            )


def test_every_unwired_o4_member_refuses(tmp_path):
    """An admitted O4 descriptor still cannot collect, compare or transmit."""
    descriptor = o4.descriptor()
    for member in ("collector", "comparator", "transport_bound", "binding_verifier"):
        with pytest.raises(PermissionError, match="not wired"):
            getattr(descriptor, member)()
    with pytest.raises(PermissionError, match="not wired"):
        descriptor.retained_artifact_validator("artifact", "manifest", "profile")
    assert descriptor.forbidden_transports() == ()


def test_the_o4_lane_admission_stays_closed(tmp_path):
    """This descriptor does not open the lane's own admission."""
    status = partition_cursor_manifest.admission_status(
        o4.descriptor().plan_compiler("a" * 32)
    )
    assert status["productionReady"] is False
    with pytest.raises(PermissionError):
        status["admit"]()


def test_an_o4_capability_cannot_be_issued_without_a_reviewed_archive(tmp_path):
    bindings = synthetic(tmp_path, o4.descriptor())
    descriptor = o4.descriptor(
        retained_artifact_validator=retained_for(
            bindings["inputs"], bindings["manifest_path"]
        )
    )
    with pytest.raises(PermissionError, match="worker archive closure"):
        o8_admission.issue_production_capability(
            descriptor, binding=7, binding_digest="c" * 64, **bindings
        )
