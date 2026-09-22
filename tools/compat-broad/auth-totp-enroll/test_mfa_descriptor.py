"""The MFA campaign descriptor: complete, budget-bound, wall-clock only."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
for entry in (
    ROOT / "tools/compat-broad",
    ROOT / "tools/compat-broad/production-admission",
    ROOT / "tools/compat-broad/o8-core",
    HERE,
):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

import reservations
from broad_contract import digest
from o8_admission import reject_production_transport
from o8_campaign import CAMPAIGN_APPROVAL_FIELDS, REQUIRED_MEMBERS, CampaignDescriptor

import mfa_admission as admission
import mfa_descriptor as campaign
import mfa_production_transport as transport
from mfa_cases import CAMPAIGN_ID, CASE_IDS, critical_path_seconds, owned_accounts
from mfa_manifest import LIMITS, compile_campaign
from mfa_provenance import BOUND_PATHS, compute_provenance, repository_root
from mfa_timing import VirtualClockSleeper, WallClockSleeper

NONCE = "d" * 32


def test_the_production_descriptor_is_complete_and_wall_clock_bound():
    descriptor = campaign.descriptor(WallClockSleeper())
    assert descriptor.campaign_id == "AUTH-MFA-AGE-TOTP-01"
    assert descriptor.approval_fields == CAMPAIGN_APPROVAL_FIELDS
    assert len(descriptor.approval_fields) == 17
    assert descriptor.binds_campaign_id is True
    assert descriptor.campaign_seconds == LIMITS["maxWallSeconds"] == 2700
    assert descriptor.frozen_bounds["maxWallSeconds"] == 2700
    assert descriptor.recovery_seconds == LIMITS["recoveryReserveSeconds"] == 300
    assert descriptor.window_seconds == 3000
    assert descriptor.frozen_bounds["timingMode"] == "wall-clock"
    assert descriptor.frozen_bounds["caseCount"] == len(CASE_IDS) == 33
    assert descriptor.frozen_bounds["ownedAccounts"] == len(owned_accounts()) == 11
    assert descriptor.frozen_bounds["configurationChange"]["lock"] == {
        "key": "project/fireemu-35fe6/auth/config",
        "mode": "EXCLUSIVE",
    }
    assert set(descriptor.members()) == set(REQUIRED_MEMBERS)


def test_the_selected_plan_reference_binds_the_allowlisted_selector():
    reference = campaign.plan_compiler(
        NONCE, selector="pending-age-300-v1", timing=campaign.WALL_CLOCK
    )
    assert reference["selector"]["caseIds"] == [
        "age-300s-start",
        "age-300s-finalize",
        "age-300s-same-account-fresh-control",
    ]
    assert reference["selectedCaseCount"] == 3
    assert reference["selectedAccountCount"] == 1
    plan = campaign.execution_plan(reference)
    assert plan["selector"]["name"] == "pending-age-300-v1"
    assert plan["limits"]["maxWallSeconds"] == 1200
    assert reference["caseCount"] == reference["selectedCaseCount"] == 3
    assert reference["ownedAccounts"] == reference["selectedAccountCount"] == 1
    selected_descriptor = campaign.descriptor_for_plan(
        reference, WallClockSleeper()
    )
    assert selected_descriptor.campaign_seconds == 1200
    assert selected_descriptor.frozen_bounds["maxWallSeconds"] == 1200
    assert selected_descriptor.frozen_bounds["criticalPathSeconds"] == 301
    assert selected_descriptor.frozen_bounds["recoveryReserveSeconds"] == 300
    assert campaign.lock_scopes(reference)[0]["key"].endswith(
        "auth/accounts/o2-mfa-pending-age-300-" + NONCE
    )


def test_selected_permission_binding_carries_its_canonical_resource_closure():
    reference = campaign.plan_compiler(
        NONCE, selector="pending-age-300-v1", timing=campaign.WALL_CLOCK
    )
    permission = campaign.permission_bindings(
        reference, "a" * 40, "b" * 64, campaign.source_map()
    )
    assert permission["planDigest"] == digest(reference)
    assert permission["manifestDigest"] == reference["manifestDigest"]
    assert permission["selector"] == "pending-age-300-v1"
    assert permission["caseCount"] == 3
    assert permission["ownedAccountRoles"] == ["pending-age-300"]
    assert permission["ownedAccounts"] == 1
    assert permission["wallSeconds"] == permission["campaignSeconds"] == 1200
    assert permission["recoverySeconds"] == 300

    altered = dict(reference, caseCount=33)
    with pytest.raises(ValueError, match="plan reference differs"):
        campaign.permission_bindings(
            altered, "a" * 40, "b" * 64, campaign.source_map()
        )

    unknown = dict(reference, selector={**reference["selector"], "name": "unknown"})
    with pytest.raises(ValueError, match="unsupported MFA selector"):
        campaign.permission_bindings(
            unknown, "a" * 40, "b" * 64, campaign.source_map()
        )


@pytest.mark.parametrize("member", sorted(REQUIRED_MEMBERS))
def test_a_descriptor_missing_any_member_is_refused(member):
    members = campaign.descriptor(WallClockSleeper()).members()
    members[member] = None
    with pytest.raises(ValueError, match="requires every member"):
        CampaignDescriptor(**members)


def test_the_production_descriptor_refuses_a_simulated_sleeper():
    with pytest.raises(ValueError, match="wall-clock sleeper"):
        campaign.descriptor(VirtualClockSleeper())

    class LookAlike:
        mode = "wall-clock"

        def now(self):
            return 0.0

        def sleep_until(self, due, on_tick=None):
            return due

    with pytest.raises(ValueError, match="real wall-clock sleeper"):
        campaign.descriptor(LookAlike())
    with pytest.raises(ValueError, match="virtual-clock sleeper"):
        campaign.rehearsal_descriptor(WallClockSleeper())


def test_a_rehearsal_descriptor_is_visibly_not_production():
    sleeper = VirtualClockSleeper()
    descriptor = campaign.rehearsal_descriptor(sleeper)
    assert descriptor.frozen_bounds["timingMode"] == "virtual-clock"
    assert descriptor.frozen_bounds["rehearsal"] is True
    assert descriptor.window_seconds == 1500
    reference = descriptor.plan_compiler(NONCE)
    assert reference["timingMode"] == "virtual-clock"
    with pytest.raises(ValueError, match="wall-clock plan reference"):
        admission.require_production_timing({"plan": reference})
    admission.require_production_timing(
        {"plan": campaign.descriptor(WallClockSleeper()).plan_compiler(NONCE)}
    )


def test_the_request_budget_is_re_derived_with_management_and_recovery_slots():
    budget = campaign.request_budget()
    assert budget["maxRequests"] == 400
    assert budget["managementRequests"] == 6
    assert budget["managementSlots"]["preflight"] == [
        "oauth-tokeninfo",
        "auth-config-readback",
    ]
    assert budget["managementSlots"]["configurationApply"] == [
        "auth-config-apply",
        "auth-config-apply-readback",
    ]
    assert budget["managementSlots"]["configurationRestore"] == [
        "auth-config-restore",
        "auth-config-restore-readback",
    ]
    # One reconciliation slot is added for each email-bearing account; the
    # anonymous account has no address to reconcile.
    assert budget["recoveryRequests"] == 4 * len(owned_accounts()) - 2 == 42
    assert budget["dataRequests"] == 93
    assert (
        budget["dataRequests"]
        + budget["managementRequests"]
        + budget["recoveryRequests"]
        + budget["headroom"]
        == 400
    )
    wall = campaign.wall_budget()
    assert wall["criticalPathSeconds"] == critical_path_seconds() == 1830
    assert wall["maxWallSeconds"] == 2700 and wall["slackSeconds"] == 120
    assert campaign.ledger_budget() == {
        "requests": 400,
        "accounts": 14,
        "resources": 14,
        "costMicrousd": 100_006,
    }
    cost = campaign.cost_model()
    assert cost["estimatedCostMicrousd"] == 100_000
    assert cost["hardCeilingMicrousd"] == 500_000
    assert cost["configurationChangeMicrousd"] == 4
    assert cost["totalCostMicrousd"] == 100_006


def test_the_lock_scopes_carry_the_exclusive_configuration_lock():
    plan = campaign.plan_compiler(NONCE)
    locks = campaign.lock_scopes(plan)
    assert locks == [
        {
            "key": f"project/fireemu-35fe6/auth/accounts/o2/AUTH-MFA-AGE-TOTP-01/{NONCE}/*",
            "mode": "WRITE",
        },
        {"key": "project/fireemu-35fe6/auth/config", "mode": "EXCLUSIVE"},
        {"key": "project/fireemu-35fe6/identity", "mode": "READ"},
    ]
    reservations._locks(locks)
    # An exclusive lock conflicts even with a reader of the same configuration.
    reader = {"key": "project/fireemu-35fe6/auth/config", "mode": "READ"}
    assert reservations.conflicts(locks[1], reader) is True
    assert reservations.conflicts(locks[0], reader) is False


def test_the_plan_reference_recompiles_to_exactly_one_manifest():
    reference = campaign.plan_compiler(NONCE)
    manifest = campaign.execution_plan(reference)
    assert manifest == compile_campaign(NONCE)
    assert reference["manifestDigest"] == digest(manifest)
    assert reference["caseCount"] == 33 and reference["ownedAccounts"] == 11
    altered = dict(reference, caseCount=32)
    with pytest.raises(ValueError, match="plan reference differs"):
        campaign.execution_plan(altered)
    with pytest.raises(ValueError, match="plan reference"):
        campaign.execution_plan({"nonce": "not-a-nonce"})


def test_the_source_map_binds_the_lane_and_every_provenance_path():
    sources = campaign.source_map()
    for name in BOUND_PATHS:
        assert name in sources
    for name in (
        campaign.COLLECTOR_ENTRY,
        campaign.COMPARATOR_ENTRY,
        campaign.WORKER_ENTRY,
    ):
        assert name in sources
    for name in campaign.ABORT_CLOSURE_SOURCES:
        assert name in sources
    lane = {name for name in sources if name.startswith(campaign.LANE_DIRECTORY)}
    assert {
        f"{campaign.LANE_DIRECTORY}/{module}.py"
        for module in (
            "mfa_o8",
            "mfa_admission",
            "mfa_descriptor",
            "mfa_production",
            "mfa_production_transport",
            "mfa_walk",
            "mfa_config_lock",
            "mfa_timing",
        )
    } <= lane


def test_the_artifact_profile_is_derived_from_the_versioned_shadow():
    record = campaign.shadow_record()
    assert (
        campaign.artifact_profile()
        == "auth-totp-enroll-" + record["worktree"]["commit"][:9]
    )
    basis = campaign.artifact_profile_basis()
    assert basis["ownerAcceptanceRequired"] is True
    assert basis["registry"] == "none"
    assert basis["shadowProvenanceDigest"] == record["provenance"]["digest"]


def test_the_bound_transport_refuses_everything_but_an_admitted_closed_call():
    binding, binding_digest = campaign.worker_binding()
    with pytest.raises(ValueError, match="capability required"):
        campaign.transport_bound(
            {"kind": "auth-public"}, binding=binding, binding_digest=binding_digest
        )
    with pytest.raises(ValueError, match="closed Auth wire call"):
        campaign.transport_bound(
            {"kind": "auth-public"},
            binding=binding,
            binding_digest=binding_digest,
            capability=object(),
        )
    with pytest.raises(ValueError, match="differs from the reviewed transport"):
        campaign.verify_worker_binding(b"other bytes", binding_digest, None)
    with pytest.raises(ValueError, match="differs from the frozen inputs"):
        campaign.verify_worker_binding(
            binding, binding_digest, {campaign.WORKER_ENTRY: "0" * 64}
        )
    campaign.verify_worker_binding(binding, binding_digest, campaign.source_map())


def test_an_injected_transport_that_reaches_the_production_wire_is_refused():
    descriptor = campaign.descriptor(WallClockSleeper())

    def harmless(value):
        return 200, {}

    assert reject_production_transport(descriptor, harmless) is harmless

    def through_the_wire(value):
        return transport.send(value)

    with pytest.raises(ValueError, match="must not reach the production wire"):
        reject_production_transport(descriptor, through_the_wire)

    def through_the_adapter(value):
        return transport.batch_adapter.wire("https://x", "GET", None, {})

    with pytest.raises(ValueError, match="must not reach the production wire"):
        reject_production_transport(descriptor, through_the_adapter)


def _runtime_receipt(side: str, runtime: dict[str, str]) -> dict:
    campaign_manifest = compile_campaign(NONCE)
    return {
        "campaignId": CAMPAIGN_ID,
        "campaign": campaign_manifest,
        "side": side,
        "recordingComplete": True,
        "productionExecuted": side == "production",
        "provenance": compute_provenance(repository_root()),
        "worktree": {
            "commit": runtime["executionCommit"],
            "clean": True,
            "resolved": True,
        },
        "runtimeIdentity": dict(runtime),
        "rows": [
            {"id": identifier, "status": 200, "errorCode": None, "outcome": "observed"}
            for identifier in CASE_IDS
        ],
        "recovery": {
            "cleanupVerified": True,
            "remainingOwnedResources": 0,
            "configurationRestored": True,
            "runId": runtime["runId"],
        },
    }


def _approved(record: dict) -> dict:
    record["ownerApproval"] = {
        "approvedBy": "project owner",
        "manifestDigest": digest(record["campaign"]),
        "nonceDigest": record["campaign"]["owner"]["nonceDigest"],
        "grant": "one-run",
    }
    return record


def test_descriptor_comparator_forwards_independently_constructed_runtime_anchor(
    tmp_path: Path,
):
    binary = tmp_path / "fireemu"
    config = tmp_path / "config.json"
    binary.write_bytes(b"retained executable bytes")
    config.write_bytes(b"exact local configuration bytes")
    runtime = {
        "artifactSha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "executionCommit": "b" * 40,
        "configurationDigest": hashlib.sha256(config.read_bytes()).hexdigest(),
        "runId": "run-1",
    }
    local = _runtime_receipt("local", runtime)
    production = _approved(_runtime_receipt("production", runtime))

    verdict = campaign.comparator(
        production,
        shadow=local,
        root=repository_root(),
        runtime_anchor=dict(runtime),
    )

    assert verdict["comparison"]["classification"] == "MATCH"
    assert "runtimeProblems" not in verdict["comparison"]
    assert verdict["formalCompatibilityClaim"] is False


def test_descriptor_comparator_rejects_a_mismatched_runtime_anchor(tmp_path: Path):
    binary = tmp_path / "fireemu"
    config = tmp_path / "config.json"
    binary.write_bytes(b"retained executable bytes")
    config.write_bytes(b"exact local configuration bytes")
    runtime = {
        "artifactSha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "executionCommit": "b" * 40,
        "configurationDigest": hashlib.sha256(config.read_bytes()).hexdigest(),
        "runId": "run-1",
    }
    local = _runtime_receipt("local", runtime)
    production = _approved(_runtime_receipt("production", runtime))
    wrong = dict(runtime, runId="run-2")

    verdict = campaign.comparator(
        production,
        shadow=local,
        root=repository_root(),
        runtime_anchor=wrong,
    )

    assert verdict["comparison"]["classification"] == "INDETERMINATE"
    assert verdict["comparison"]["runtimeProblems"] == [
        "local runtime identity differs from independent anchor"
    ]


def test_descriptor_comparator_keeps_downgraded_final_record_fail_closed():
    runtime = {
        "artifactSha256": "a" * 64,
        "executionCommit": "b" * 40,
        "configurationDigest": "c" * 64,
        "runId": "run-1",
    }
    local = _runtime_receipt("local", runtime)
    production = _approved(_runtime_receipt("production", runtime))
    local.pop("runtimeIdentity")
    local["recovery"].pop("runId")
    local["productionExecuted"] = True
    local["ownerApproval"] = production["ownerApproval"]

    verdict = campaign.comparator(production, shadow=local, root=repository_root())

    assert verdict["comparison"]["classification"] == "INDETERMINATE"


def test_closed_calls_are_allowlisted_by_endpoint():
    transport.closed_call(
        "auth-public",
        path="/v1/accounts:signUp",
        body={},
        secret="s" * 8,
        key="k" * 8,
        deadline=1.0,
    )
    with pytest.raises(ValueError, match="allowlisted public"):
        transport.closed_call(
            "auth-public",
            path="/v1/accounts:sendOobCode",
            body={},
            secret="s" * 8,
            key="k" * 8,
            deadline=1.0,
        )
    with pytest.raises(ValueError, match="allowlisted admin"):
        transport.closed_call(
            "auth-admin",
            path="/v1/projects/fireemu-35fe6/accounts:batchDelete",
            body={},
            secret="s" * 8,
            deadline=1.0,
        )
    with pytest.raises(ValueError, match="update mask"):
        transport.closed_call(
            "auth-config-patch",
            path="/admin/v2/projects/fireemu-35fe6/config",
            body={},
            secret="s" * 8,
            deadline=1.0,
            mask="mfa; drop",
        )
    with pytest.raises(ValueError, match="nothing but the token"):
        transport.closed_call(
            "oauth-tokeninfo", path="/x", body=None, secret="s" * 8, deadline=1.0
        )
