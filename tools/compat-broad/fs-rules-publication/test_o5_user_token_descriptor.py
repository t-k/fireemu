"""Offline dry run of the user-token O8 descriptor.

Nothing here reaches production: no credential, no origin, no Ledger and no
process. The synthetic approval is built from local files in tmp_path, and
the members that would reach a wire are left refusing.
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/production-admission"))
sys.path.insert(0, str(HERE))

import o5_user_token_descriptor as lane
import o8_admission
from broad_contract import digest
from o5_user_token_campaign import _SOURCE_FILES, admission, manifest
from o5_user_token_case import CAMPAIGN
from o5_user_token_collector import ROLE_PRODUCTION
from o8_campaign import REQUIRED_MEMBERS, CampaignDescriptor
from test_o5_user_token_collector import Transport
from test_o5_user_token_collector_bound import (
    PRODUCTION_ENDPOINT,
    acquisition_for,
)

NONCE = "a" * 32


def synthetic(tmp_path, descriptor):
    """A complete O7 artifact set for the dry run, built from local files only."""
    plan = descriptor.plan_compiler(NONCE)
    artifact_path = tmp_path / "artifact"
    artifact_path.write_bytes(b"synthetic artifact")
    artifact_sha256 = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
    inputs_seed = descriptor.source_map()
    permission = descriptor.permission_bindings(
        plan, "0" * 40, artifact_sha256, inputs_seed
    )
    inputs = o8_admission.freeze_inputs(
        descriptor,
        permission,
        plan,
        source_commit="0" * 40,
        artifact_sha256=artifact_sha256,
    )
    manifest_value = {
        "kind": lane.MANIFEST_KIND,
        "inputsDigest": inputs["inputsDigest"],
    }
    manifest_bytes = json.dumps(manifest_value).encode()
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_bytes(manifest_bytes)
    launcher_path = tmp_path / "launcher.py"
    launcher_path.write_bytes(b"# synthetic launcher\n")
    ledger = tmp_path / "ledger"
    now = time.time()
    approval = {
        "kind": lane.APPROVAL_KIND,
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
        "artifactProfile": descriptor.artifact_profile,
        "windowStartsAt": now - 1,
        "windowExpiresAt": now + 4 * descriptor.window_seconds,
        "executionHost": o8_admission.execution_host(),
    }
    return {
        "inputs": inputs,
        "approval": approval,
        "manifest": manifest_value,
        "manifest_bytes": manifest_bytes,
        "manifest_path": manifest_path,
        "permission": permission,
        "ledger_root": ledger,
        "artifact_path": artifact_path,
        "launcher_path": launcher_path,
    }


def test_the_descriptor_constructs_with_every_required_member() -> None:
    descriptor = lane.descriptor()
    assert descriptor.campaign_id == CAMPAIGN
    assert descriptor.binds_campaign_id
    assert descriptor.window_seconds == 900
    assert descriptor.artifact_profile.startswith("o5-user-token-")
    for name in REQUIRED_MEMBERS:
        assert getattr(descriptor, name) is not None


@pytest.mark.parametrize("member", REQUIRED_MEMBERS)
def test_a_descriptor_missing_any_member_is_refused_at_construction(member) -> None:
    members = lane.descriptor().members()
    members[member] = None
    with pytest.raises(ValueError, match="requires every member"):
        CampaignDescriptor(**members)


def test_the_frozen_inputs_cover_the_lane_and_the_shared_closure(tmp_path) -> None:
    descriptor = lane.descriptor()
    bindings = synthetic(tmp_path, descriptor)
    inputs = bindings["inputs"]
    sources = inputs["sourceInputs"]
    assert inputs["kind"] == lane.FROZEN_INPUTS_KIND
    for name in _SOURCE_FILES:
        assert f"{lane.LANE_DIRECTORY}/{name}" in sources
    for name in (*lane.SHARED_SOURCES, *lane.ABORT_CLOSURE_SOURCES):
        assert sources[name] == hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
    assert inputs["bounds"]["observationRequests"] == 26
    assert inputs["bounds"]["totalRequests"] == descriptor.budget["requests"]
    o8_admission.validate_frozen_inputs(descriptor, inputs)
    generation = o8_admission.abort_generation(descriptor, inputs)
    assert set(generation["sourceDigests"]) == {
        "shared_gate.py",
        "reservations.py",
        "o8_admission.py",
        "o5_user_token_collector.py",
        "o5_user_token_comparator_v2.py",
        "o5_user_token_descriptor.py",
    }


def test_the_frozen_plan_is_the_lane_compiled_case_for_the_nonce(tmp_path) -> None:
    descriptor = lane.descriptor()
    inputs = synthetic(tmp_path, descriptor)["inputs"]
    assert inputs["plan"]["campaignId"] == CAMPAIGN
    assert inputs["plan"]["nonce"] == NONCE
    assert inputs["plan"] == lane.plan_compiler(NONCE)
    assert o8_admission.campaign_identity(descriptor, inputs) == CAMPAIGN


def test_a_synthetic_approval_passes_the_shared_o7_check_set(tmp_path) -> None:
    descriptor = lane.descriptor()
    bindings = synthetic(tmp_path, descriptor)
    admitted = o8_admission.validate_o7_admission(descriptor, **bindings)
    assert admitted["campaignId"] == CAMPAIGN
    assert admitted["ledgerRoot"] == str(bindings["ledger_root"].resolve(strict=False))
    assert (
        admitted["retained"]["artifactSha256"] == bindings["inputs"]["artifactSha256"]
    )


@pytest.mark.parametrize(
    "override",
    [
        {"campaignId": "FS-LIMIT-API-REQUEST-BYTES"},
        {"kind": "request-bytes-o8-approval-v1"},
        {"artifactProfile": "request-bytes-000000000"},
        {"status": "pending"},
    ],
)
def test_another_campaign_approval_cannot_be_admitted(tmp_path, override) -> None:
    descriptor = lane.descriptor()
    bindings = synthetic(tmp_path, descriptor)
    with pytest.raises(ValueError):
        o8_admission.validate_o7_admission(
            descriptor,
            **{**bindings, "approval": {**bindings["approval"], **override}},
        )


def test_a_permission_with_another_window_is_refused(tmp_path) -> None:
    descriptor = lane.descriptor()
    bindings = synthetic(tmp_path, descriptor)
    permission = {**bindings["permission"], "wallSeconds": 1200}
    with pytest.raises(ValueError):
        o8_admission.validate_o7_admission(
            descriptor, **{**bindings, "permission": permission}
        )


def test_the_permission_bindings_name_the_collector_and_the_comparator(
    tmp_path,
) -> None:
    descriptor = lane.descriptor()
    permission = synthetic(tmp_path, descriptor)["permission"]
    assert permission["kind"] == lane.PERMISSION_KIND
    assert (
        permission["collectorSha256"]
        == hashlib.sha256((ROOT / lane.COLLECTOR_ENTRY).read_bytes()).hexdigest()
    )
    assert (
        permission["comparatorSha256"]
        == hashlib.sha256((ROOT / lane.COMPARATOR_ENTRY).read_bytes()).hexdigest()
    )
    assert (
        permission["campaignManifestDigest"]
        == manifest(lane.PROJECT, lane.DATABASE, NONCE, lane.PLACEHOLDER_TENANT)[
            "manifestDigest"
        ]
    )
    assert permission["wallSeconds"] == 600
    assert permission["recoverySeconds"] == 300
    assert permission["budget"]["accounts"] == 4
    assert permission["budget"]["costMicrousd"] == 1_000_000


def test_lock_scopes_hold_the_ruleset_exclusively_and_the_nonce_subtree() -> None:
    plan = lane.plan_compiler(NONCE)
    scopes = lane.lock_scopes(plan)
    modes = {scope["key"]: scope["mode"] for scope in scopes}
    assert modes[f"project/{lane.PROJECT}/firestore/(default)/ruleset"] == "EXCLUSIVE"
    assert (
        modes[
            f"project/{lane.PROJECT}/firestore/(default)/documents/o5-user-token/n{NONCE}/cases/*"
        ]
        == "WRITE"
    )
    assert len(modes) == len(scopes)
    from reservations import _locks, conflicts

    _locks(scopes)
    # Another campaign's read of the ruleset conflicts with this exclusive hold.
    other = {
        "key": f"project/{lane.PROJECT}/firestore/(default)/ruleset",
        "mode": "READ",
    }
    assert conflicts(scopes[1], other)


def test_every_unwired_member_refuses() -> None:
    descriptor = lane.descriptor()
    for member in ("transport_bound", "binding_verifier"):
        with pytest.raises(PermissionError, match="not wired"):
            getattr(descriptor, member)()
    assert descriptor.forbidden_transports() == (lane.transport_bound,)


def test_a_capability_cannot_be_issued_without_a_worker_binding(tmp_path) -> None:
    descriptor = lane.descriptor()
    bindings = synthetic(tmp_path, descriptor)
    with pytest.raises(PermissionError, match="worker archive closure"):
        o8_admission.issue_production_capability(
            descriptor, binding=b"worker", binding_digest="c" * 64, **bindings
        )


def test_the_lane_admission_stays_closed() -> None:
    gate = admission(manifest(lane.PROJECT, lane.DATABASE, NONCE))
    assert gate["productionReady"] is False
    with pytest.raises(PermissionError):
        gate["admit"]()


def test_an_injected_local_transport_is_accepted_and_the_wire_member_is_not() -> None:
    descriptor = lane.descriptor()
    plan = lane.plan_compiler(NONCE)
    local = Transport(plan, endpoint=PRODUCTION_ENDPOINT)
    assert o8_admission.reject_production_transport(descriptor, local) is local

    def reaching(request):
        return lane.transport_bound(request)

    with pytest.raises(ValueError, match="must not reach the production wire"):
        o8_admission.reject_production_transport(descriptor, reaching)


def test_the_collector_member_runs_the_lane_collector_bound() -> None:
    descriptor = lane.descriptor()
    plan = lane.plan_compiler(NONCE)
    transport = Transport(plan, endpoint=PRODUCTION_ENDPOINT)
    bundle = descriptor.collector(
        plan,
        transport,
        run_id="dry-run",
        acquisition=acquisition_for(plan, ROLE_PRODUCTION),
    )
    assert bundle["provenance"]["role"] == ROLE_PRODUCTION
    assert bundle["recordingComplete"] is True
    assert bundle["budget"]["deadlineSeconds"] == 600.0
    assert bundle["budget"]["recoveryDeadlineSeconds"] == 900.0
    assert bundle["productionReady"] is False
    unbound = Transport(plan)
    refused = descriptor.collector(
        plan,
        unbound,
        run_id="unbound",
        acquisition=acquisition_for(plan, ROLE_PRODUCTION),
    )
    assert refused["abort"] == "unbound-receipt"


def test_the_descriptor_module_is_bound_by_the_campaign_manifest() -> None:
    assert "o5_user_token_descriptor.py" in _SOURCE_FILES
    assert "o5_user_token_comparator_v2.py" in _SOURCE_FILES
