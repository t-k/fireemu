"""Offline dry run of the user-token O8 descriptor.

Nothing here reaches production. Synthetic approval and private Ledger state
are built in tmp_path; bounded worker processes reach only loopback fixtures.
"""

from __future__ import annotations

import hashlib
import json
import os
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
import o5_user_token_remote_transport as remote
import o8_admission
import shared_gate
from broad_contract import digest
from o5_user_token_campaign import (
    _SOURCE_FILES,
    admission,
    admitted_manifest_digest,
    manifest,
)
from o5_user_token_case import CAMPAIGN, compile_case
from o5_user_token_collector import (
    ROLE_LOCAL_SHADOW,
    ROLE_PRODUCTION,
    collect,
)
from o5_user_token_comparator_v2 import REFUSED
from o8_campaign import REQUIRED_MEMBERS, CampaignDescriptor
from reservations import Ledger
from test_o5_user_token_collector import Transport
from test_o5_user_token_collector_bound import (
    acquisition_for,
    bound,
    bound_transport,
)

NONCE = "a" * 32


@pytest.mark.parametrize("dimension", ["requests", "costMicrousd"])
def test_whole_schedule_ledger_reserve_rejects_shortfall_without_state_change(
    tmp_path, dimension
):
    plan = lane.plan_compiler(NONCE)
    compiled = lane.gate_plan(plan)
    ledger = Ledger.create(tmp_path / "private-ledger")
    now = time.time()
    limits = {"requests": 144, "accounts": 7, "resources": 14, "costMicrousd": 144}
    limits[dimension] -= 1
    envelope = {
        "permissionDigest": digest({"kind": "local-rules-budget-test"}),
        "issuedAt": now - 1,
        "expiresAt": now + 1200,
        "limits": limits,
        "concurrency": 1,
        "scopes": lane.lock_scopes(plan),
    }
    claim = {
        "campaignId": CAMPAIGN,
        "manifestDigest": digest(plan),
        "nonceDigest": digest(plan["nonce"]),
        "gatePath": str((tmp_path / "gate").resolve()),
        "gatePlanDigest": digest(compiled),
        "locks": lane.lock_scopes(plan),
        "budget": dict(limits),
        "durationSeconds": 600,
    }
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="sub-budget"):
        ledger.reserve(envelope, claim, compiled)
    assert ledger.snapshot() == before
    assert not (tmp_path / "gate").exists()
    envelope["limits"][dimension] += 1
    claim["budget"][dimension] += 1
    ticket = ledger.reserve(envelope, claim, compiled)
    assert ticket["claimDigest"] == digest(claim)


def test_closed_schedule_accounts_for_every_wire_exchange_and_one_cleanup(tmp_path):
    plan = lane.plan_compiler(NONCE)
    compiled = lane.gate_plan(plan)
    assert compiled["jobs"] == {
        "rules-management": {"resources": [], "observation": [], "recovery": []}
    }
    management = compiled["management"]
    observation = management["observation"]
    recovery = management["recovery"]
    assert observation[0]["id"] == "setup/account/owner-a/signup"
    assert observation[8]["id"] == "setup/account/owner-a/signin"
    assert observation[9]["id"] == "setup/fixture/owned-a"
    assert len(observation) == 71
    assert len(recovery) == 73
    assert management["totalRequests"] == 144
    assert compiled["observationRequests"] == 71
    assert compiled["costMicrousd"] == 144
    assert lane.budget()["requests"] == 144
    assert lane.budget()["resources"] == 14
    assert sum(slot["timeout"] + 0.25 for slot in observation) == 289.75
    assert sum(slot["timeout"] + 0.25 for slot in recovery) == 264.25
    assert len({slot["id"] for slot in observation + recovery}) == 144
    assert sum(slot["id"].startswith("cleanup/") for slot in recovery) == 63
    assert not any("setup-recovery" in slot["id"] for slot in recovery)
    ids = [slot["id"] for slot in observation]
    first_b = next(row for row in plan["observation"] if row["ruleset"] == "B")
    assert ids.index("patch-b-executable") + 1 == ids.index(f"data/{first_b['index']}")
    assert ids.index(f"data/{first_b['index'] - 1}") < ids.index("create-b")
    shared_gate.create(tmp_path / "compiled-gate", compiled)


def test_cleanup_dependencies_bind_only_compiled_creation_and_mutation_slots():
    plan = lane.plan_compiler(NONCE)
    compiled = lane.gate_plan(plan)
    assert compiled["rulesCompilerSources"] == {
        name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
        for name in ("o5_user_token_case.py", "o5_user_token_campaign.py")
    }
    contract = compiled["rulesManagementContract"]
    subjects = {subject["id"]: subject for subject in contract["subjects"]}
    assert len(subjects) == 21
    assert contract["tenantId"] == plan["tenant"]
    assert contract["rulesets"] == {
        label.lower(): digest(value["source"])
        for label, value in plan["rulesets"].items()
    }
    for subject_id, subject in subjects.items():
        effects = [
            (slot["id"], effect["action"])
            for slot in compiled["management"]["observation"]
            for effect in slot["effects"]
            if effect["subject"] == subject_id
        ]
        assert subject["creationSlots"] == [
            slot for slot, action in effects if action == "create"
        ]
        assert subject["mutationSlots"] == [
            slot for slot, action in effects if action in {"write", "delete"}
        ]
        assert subject["creationSlots"]
    for slot in compiled["management"]["recovery"][:63]:
        subject_id = slot["id"].removeprefix("cleanup/").rsplit("/", 1)[0]
        assert slot["dependency"] == {
            "subject": subject_id,
            "step": slot["id"].rsplit("/", 1)[-1],
        }
        assert subject_id in subjects
    assert subjects["account/owner-a"]["creationSlots"] == [
        "setup/account/owner-a/signup"
    ]
    assert (
        "setup/account/owner-a/claim-update"
        in subjects["account/owner-a"]["mutationSlots"]
    )


def with_synthetic_build(monkeypatch, artifact_sha256: str) -> dict:
    """Point the lane's shadow record at a synthetic build for a dry run.

    The retained artifact validator pins the retained bytes to the shadow's
    build, which no test can reproduce, so a dry run substitutes a record that
    names the synthetic artifact instead. Everything else in the record is the
    real one.
    """
    real = lane.shadow_record()
    record = json.loads(json.dumps(real))
    record["artifact"]["artifactSha256"] = artifact_sha256
    record["bundle"]["acquisition"]["artifact"]["artifactSha256"] = artifact_sha256
    monkeypatch.setattr(lane, "shadow_record", lambda: record)
    return record


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
    assert descriptor.window_seconds == 600
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
    assert inputs["bounds"]["observationRequests"] == 33
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
        "o5_user_token_remote_transport.py",
        "o5_user_token_https_worker.py",
    }


def test_the_frozen_plan_is_the_lane_compiled_case_for_the_nonce(tmp_path) -> None:
    descriptor = lane.descriptor()
    inputs = synthetic(tmp_path, descriptor)["inputs"]
    assert inputs["plan"]["campaignId"] == CAMPAIGN
    assert inputs["plan"]["nonce"] == NONCE
    assert inputs["plan"] == lane.plan_compiler(NONCE)
    assert o8_admission.campaign_identity(descriptor, inputs) == CAMPAIGN


def test_a_synthetic_approval_passes_the_shared_o7_check_set(
    tmp_path, monkeypatch
) -> None:
    with_synthetic_build(monkeypatch, hashlib.sha256(b"synthetic artifact").hexdigest())
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
    assert permission["campaignManifestDigest"] == admitted_manifest_digest(
        lane.PROJECT, lane.DATABASE, NONCE
    )
    assert permission["wallSeconds"] == 300
    assert permission["recoverySeconds"] == 300
    assert permission["budget"]["accounts"] == 7
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


def test_bound_members_require_closed_o7_inputs() -> None:
    descriptor = lane.descriptor()
    source, source_digest = remote.worker_binding()
    descriptor.binding_verifier(source, source_digest, None)
    with pytest.raises(ValueError, match="closed Rules wire call"):
        descriptor.transport_bound(
            {}, binding=source, binding_digest=source_digest, capability=object()
        )
    assert descriptor.forbidden_transports() == (lane.transport_bound,)


def test_a_retained_artifact_that_is_not_the_shadow_build_is_refused(
    tmp_path,
) -> None:
    """Without the synthetic-build substitution, the real record pins the
    retained bytes to the fireemu build the shadow ran, which a synthetic
    artifact is not."""
    descriptor = lane.descriptor()
    bindings = synthetic(tmp_path, descriptor)
    with pytest.raises(ValueError, match="not the shadow's build"):
        o8_admission.validate_o7_admission(descriptor, **bindings)
    with pytest.raises(ValueError, match="not the shadow's build"):
        descriptor.retained_artifact_validator(
            bindings["artifact_path"],
            bindings["manifest_path"],
            descriptor.artifact_profile,
        )


def test_a_capability_cannot_be_issued_without_a_worker_binding(
    tmp_path, monkeypatch
) -> None:
    with_synthetic_build(monkeypatch, hashlib.sha256(b"synthetic artifact").hexdigest())
    descriptor = lane.descriptor()
    bindings = synthetic(tmp_path, descriptor)
    with pytest.raises(ValueError, match="worker source"):
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
    local = bound_transport(plan, ROLE_PRODUCTION)
    assert o8_admission.reject_production_transport(descriptor, local) is local

    def reaching(request):
        return lane.transport_bound(request)

    with pytest.raises(ValueError, match="must not reach the production wire"):
        o8_admission.reject_production_transport(descriptor, reaching)


def test_the_collector_member_runs_the_lane_collector_bound() -> None:
    descriptor = lane.descriptor()
    plan = lane.plan_compiler(NONCE)
    transport = bound_transport(plan, ROLE_PRODUCTION)
    bundle = descriptor.collector(
        plan,
        transport,
        run_id="dry-run",
        acquisition=acquisition_for(plan, ROLE_PRODUCTION),
    )
    assert bundle["provenance"]["role"] == ROLE_PRODUCTION
    # A bound run without the production Rules management session is held
    # before mutation; this prevents the legacy receipt contract from being
    # mistaken for production lifecycle evidence.
    assert bundle["recordingComplete"] is False
    assert bundle["abort"] == "collector:ValueError"
    assert bundle["budget"]["deadlineSeconds"] == 300.0
    assert bundle["budget"]["recoveryDeadlineSeconds"] == 600.0
    assert bundle["productionReady"] is False
    unbound = Transport(plan)
    refused = descriptor.collector(
        plan,
        unbound,
        run_id="unbound",
        acquisition=acquisition_for(plan, ROLE_PRODUCTION),
    )
    assert refused["abort"] == "collector:ValueError"


def test_the_comparator_member_compares_against_the_published_shadow() -> None:
    """The reference is the checked-in local shadow. A bound production bundle
    of another nonce is refused against it; one of the shadow's own nonce is
    compared row by row, and its statuses agree with what the shadow saw."""
    descriptor = lane.descriptor()
    record = lane.shadow_record()
    plan = lane.plan_compiler(NONCE)
    production = descriptor.collector(
        plan, bound_transport(plan, ROLE_PRODUCTION), run_id="preparation-only",
        acquisition=acquisition_for(plan, ROLE_PRODUCTION),
    )
    result = descriptor.comparator(production, plan)
    assert result["classification"] == REFUSED
    assert "local:campaign-identity-drift" in result["errors"]
    shadow_plan = lane.plan_compiler(record["nonce"])
    production = descriptor.collector(
        shadow_plan,
        bound_transport(shadow_plan, ROLE_PRODUCTION),
        run_id="dry-run",
        acquisition=acquisition_for(shadow_plan, ROLE_PRODUCTION),
    )
    result = descriptor.comparator(production, shadow_plan)
    # No management session means no production authority evidence. Preserve
    # the explicit refusal; this preparation bundle is not a parity result.
    assert result["classification"] == REFUSED
    assert "production:missing-binding:rulesetReleases" in result["errors"]
    assert "production:recording-incomplete" in result["errors"]
    assert "production:recording-aborted" in result["errors"]


def test_rules_session_refuses_foreign_claim_before_any_wire_exchange(
    tmp_path,
) -> None:
    from o5_user_token_collector import open_ownership_journal
    from o5_user_token_production_bridge import management_session

    plan = lane.plan_compiler(NONCE)
    gate_plan = lane.gate_plan(plan, permission_expires_at=time.time() + 3600)
    gate_path = tmp_path / "gate"
    ledger = Ledger.create(tmp_path / "ledger")
    now = time.time()
    permission = {"kind": "o5-test"}
    envelope = {
        "permissionDigest": digest(permission),
        "issuedAt": now - 1,
        "expiresAt": now + 3600,
        "limits": {"requests": 144, "accounts": 7, "resources": 14, "costMicrousd": 144},
        "concurrency": 1,
        "scopes": [{"key": "project/fireemu-35fe6", "mode": "EXCLUSIVE"}],
    }
    claim = {
        "campaignId": CAMPAIGN,
        "manifestDigest": digest(plan),
        "nonceDigest": digest(plan["nonce"]),
        "gatePath": str(gate_path.resolve()),
        "gatePlanDigest": digest(gate_plan),
        "locks": [{"key": "project/fireemu-35fe6", "mode": "EXCLUSIVE"}],
        "budget": dict(envelope["limits"]),
        "durationSeconds": 600,
    }
    ticket = ledger.reserve(envelope, claim, gate_plan)
    shared_gate.create(gate_path, gate_plan)
    gate = shared_gate.Gate(gate_path, CAMPAIGN)

    def execute(*_args, **_kwargs):
        pytest.fail("Foreign claim must be rejected before dispatch")

    wrong_ticket = dict(ticket)
    wrong_ticket["reservation"] = "foreign-reservation"
    wrong_plan = json.loads(json.dumps(plan))
    wrong_plan["nonce"] = "b" * 32
    journal = open_ownership_journal(
        tmp_path / "ownership.jsonl", run_id="claim-negative", plan_digest=plan["planDigest"]
    )
    try:
        for candidate_ticket, candidate_plan in ((wrong_ticket, plan), (ticket, wrong_plan)):
            with pytest.raises(ValueError, match="Ledger claim binding"):
                management_session(
                    gate=gate, ledger=ledger, ticket=candidate_ticket, execute=execute,
                    plan=candidate_plan, journal=journal, ownership={},
                )
    finally:
        journal.close()
    assert gate.snapshot()["managementUsed"] == []


def test_descriptor_collector_runs_complete_rules_lifecycle_with_real_gate_and_ledger(
    tmp_path, monkeypatch
) -> None:
    from test_o5_user_token_production import (
        test_approved_packet_runs_real_loopback_producer_and_records_bounded_counts,
    )

    # Exercise the descriptor through the complete canonical bridge, including
    # setup, every data/action call, typed recovery skips, and Ledger release.
    test_approved_packet_runs_real_loopback_producer_and_records_bounded_counts(
        tmp_path, monkeypatch, None
    )


def test_preserved_local_runner_acquisition_remains_accepted_without_management_session() -> (
    None
):
    configured = os.environ.get("O5_PRESERVED_LOCAL_RUNNER")
    if not configured:
        pytest.skip("O5_PRESERVED_LOCAL_RUNNER is not configured")
    raw_path = Path(configured)
    assert not raw_path.is_symlink(), (
        "configured preserved runner must not be a symlink"
    )
    assert raw_path.is_file(), (
        "configured preserved local runner receipt is unavailable"
    )
    raw = json.loads(raw_path.read_bytes())
    recorded = raw["bundle"]["acquisition"]
    acquisition = {
        key: recorded[key]
        for key in (
            "environment",
            "campaignManifestDigest",
            "nonceReservation",
            "ownerPermission",
            "artifact",
            "principals",
            "window",
        )
    }
    plan = compile_case("fireemu-35fe6", "(default)", raw["nonce"], raw["tenant"])
    fingerprints = {
        ref: value["uidFingerprint"] for ref, value in acquisition["principals"].items()
    }
    transport = Transport(
        plan,
        endpoint="127.0.0.1:52879",
        fingerprints=fingerprints,
    )
    bundle = collect(
        plan,
        transport,
        role=ROLE_LOCAL_SHADOW,
        deadline_seconds=600.0,
        recovery_deadline_seconds=900.0,
        run_id="preserved-local-runner-acquisition",
        acquisition=acquisition,
    )
    assert bundle["recordingComplete"] is True
    assert bundle["abort"] is None
    assert len(bundle["rows"]) == 33
    assert bundle["productionExecuted"] is False


def test_a_local_shadow_bundle_fails_closed_as_production_evidence() -> None:
    """The saved local record cannot be passed off as the production side."""
    descriptor = lane.descriptor()
    record = lane.shadow_record()
    plan = lane.plan_compiler(record["nonce"])
    forged = json.loads(json.dumps(record["bundle"]))
    forged["provenance"]["role"] = ROLE_PRODUCTION
    forged["provenance"]["runId"] = "relabelled"
    forged["productionExecuted"] = True
    result = descriptor.comparator(forged, plan)
    assert result["classification"] == REFUSED
    assert result["rows"] == []
    assert "production:local-mislabelled-as-production" in result["errors"]


def test_a_reference_bundle_of_another_build_is_refused() -> None:
    """The comparator member compares only against the build the record names."""
    descriptor = lane.descriptor()
    record = lane.shadow_record()
    plan = lane.plan_compiler(record["nonce"])
    production = descriptor.collector(
        plan, bound_transport(plan, ROLE_PRODUCTION), run_id="preparation-only",
        acquisition=acquisition_for(plan, ROLE_PRODUCTION),
    )
    other = json.loads(json.dumps(record["bundle"]))
    other["acquisition"]["artifact"]["artifactSha256"] = "0" * 64
    result = descriptor.comparator(production, plan, other)
    assert result["classification"] == REFUSED
    assert result["errors"] == ["local:reference-artifact-mismatch"]
    assert result["rows"] == []
    stripped = json.loads(json.dumps(record["bundle"]))
    stripped["acquisition"]["artifact"] = None
    assert (
        descriptor.comparator(production, plan, stripped)["classification"] == REFUSED
    )


def test_the_descriptor_module_is_bound_by_the_campaign_manifest() -> None:
    assert "o5_user_token_descriptor.py" in _SOURCE_FILES
    assert "o5_user_token_comparator_v2.py" in _SOURCE_FILES
