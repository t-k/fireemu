import copy
import json
import sys
from types import SimpleNamespace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import pytest
from broad_contract import digest
from campaign_auth_list import (
    campaign_cases,
    campaign_manifest,
    compare_rows,
    proposal,
    validate_proposal,
)
from campaign_gate import validate as validate_typed_operation


def test_manifest_has_exact_five_cases_and_fixed_local_entry():
    accepted = [
        case
        for case in campaign_cases()
        if case.get("admission", "accepted") == "accepted"
    ]
    assert [case["id"] for case in accepted] == [
        "auth/refresh/changed-refresh@0",
        "auth/refresh/reference-refresh",
        "firestore/list-collection-ids/root",
        "firestore/list-collection-ids/missing-document-parent",
        "firestore/list-collection-ids/page-size-one",
    ]
    plan = campaign_manifest("a" * 32)
    assert plan["transport"] == "local-only"
    assert plan["maxConcurrency"] == 1
    assert plan["productionExecutable"] is False
    assert plan["costMicrousd"] < 100_000
    assert plan["observationRequests"] == 17
    assert len(plan["jobs"]["auth-list"]["recovery"]) == 19
    assert all(
        "parent" not in operation["body"]
        for operation in plan["jobs"]["auth-list"]["observation"]
        if operation["operationType"] == "firestore-list-collection-ids"
    )


def test_fresh_nonce_and_external_origin_fail_closed():
    with pytest.raises(ValueError, match="fresh hexadecimal"):
        campaign_manifest("old")
    value = proposal()
    drifted = copy.deepcopy(value)
    drifted["planTemplate"]["localOrigins"]["auth"] = (
        "https://identitytoolkit.googleapis.com"
    )
    with pytest.raises(ValueError):
        validate_proposal(drifted)


@pytest.mark.parametrize("kind", ["auth-refresh", "firestore-list-collection-ids"])
def test_typed_gate_requires_principal_resource_and_provenance(kind):
    operation = {
        "operationType": kind,
        "principal": "owner",
        "resource": "r",
        "provenance": {"source": "fixture"},
        "method": "POST",
        "path": "/v1/r:listCollectionIds",
        "body": {},
    }
    if kind == "auth-refresh":
        operation["provenance"]["token"] = "owned-refresh-token"
        operation["body"] = {"grant_type": "refresh_token", "refresh_token": "owned"}
    validate_typed_operation(operation)
    for field in ("principal", "resource", "provenance"):
        broken = copy.deepcopy(operation)
        broken.pop(field)
        with pytest.raises(ValueError):
            validate_typed_operation(broken)


def test_page_token_substitution_reuse_and_wrong_parent_are_rejected():
    plan = campaign_manifest("b" * 32)
    paged = [
        op
        for op in plan["jobs"]["auth-list"]["observation"]
        if op.get("operationType") == "firestore-list-collection-ids"
        and op["body"].get("pageToken")
    ]
    assert len(paged) == 1
    operation = paged[0]
    validate_typed_operation(operation)
    for mutation in ("wrong-parent", "substituted-token", "reused-token"):
        broken = copy.deepcopy(operation)
        if mutation == "wrong-parent":
            broken["path"] = broken["path"].replace("paged-", "wrong-paged-")
            broken["resource"] += "-wrong"
        else:
            broken["body"]["pageToken"] = "other-token"
            broken["provenance"]["pageToken"] = (
                "observed-continuation" if mutation == "reused-token" else "untrusted"
            )
            if mutation == "reused-token":
                broken["provenance"]["tokenValue"] = "other-token"
                broken["provenance"]["consumed"] = True
        with pytest.raises(ValueError):
            validate_typed_operation(broken)


@pytest.mark.parametrize(
    "flags",
    [
        {"recordingComplete": False},
        {"stateValidation": False},
        {"cleanupComplete": False},
    ],
)
def test_comparator_preserves_indeterminate_for_state_recording_cleanup_failures(flags):
    base = {
        "recordingComplete": True,
        "stateValidation": True,
        "cleanupComplete": True,
        "rows": [1],
    }
    other = dict(base)
    other.update(flags)
    assert compare_rows(base, other)["compatibility"] == "indeterminate"


def test_comparator_keeps_mismatch_and_same_wrong_operation_visible():
    left = {
        "recordingComplete": True,
        "stateValidation": True,
        "cleanupComplete": True,
        "rows": [{"operation": "wrong"}],
    }
    right = json.loads(json.dumps(left))
    assert compare_rows(left, right)["compatibility"] == "match"
    right["rows"][0]["status"] = "different"
    assert compare_rows(left, right)["compatibility"] == "mismatch"


@pytest.mark.parametrize(
    "failure", ["auth-refusal", "timeout", "budget", "malformed", "non-json"]
)
def test_transport_and_refusal_failures_are_recorded_as_indeterminate(failure):
    left = {
        "recordingComplete": False,
        "stateValidation": True,
        "cleanupComplete": True,
        "failure": failure,
        "rows": [],
    }
    right = {**left, "recordingComplete": True, "failure": None}
    result = compare_rows(left, right)
    assert result["recording"] is False
    assert result["compatibility"] == "indeterminate"


def test_auth_refresh_source_mismatch_is_refused():
    operation = next(
        operation
        for operation in campaign_manifest("d" * 32)["jobs"]["auth-list"]["observation"]
        if operation["operationType"] == "auth-refresh"
    )
    operation["provenance"]["token"] = "wrong-source"
    with pytest.raises(
        ValueError, match="refresh token provenance|owned refresh token"
    ):
        validate_typed_operation(operation)


def test_checked_in_manifest_matches_proposal():
    path = (
        __import__("pathlib").Path(__file__).parents[3]
        / "spec/compatibility/broad-runs/prod-campaign-auth-list-01.json"
    )
    value = json.loads(path.read_bytes())
    current = proposal()
    assert value["kind"] == current["kind"]
    assert value["sourceCommit"] == current["planTemplate"]["sourceCommit"]
    assert value["cases"] == [
        case["id"]
        for case in campaign_cases()
        if case.get("admission", "accepted") == "accepted"
    ]
    assert value["transport"] == current["planTemplate"]["transport"]
    assert digest(
        {
            "kind": value["kind"],
            "cases": value["cases"],
            "transport": value["transport"],
        }
    )


def test_actual_shadow_uses_fixed_fireemu_artifact_and_closes_transport(tmp_path):
    from campaign_auth_list_shadow import run

    result = run(tmp_path / "shadow")
    assert result["completed"] is True
    assert result["productionExecuted"] is False
    assert result["target"] == "owned-fireemu-artifact"
    assert result["artifactSha256"]
    assert result["runtime"]["ownedProcess"]["listenersClosed"] is True
    assert result["runtime"]["ownedProcess"]["stopped"] is True
    assert result["gate"]["observation"] == 17
    assert result["gate"]["recovery"] == 19
    assert result["gate"]["total"] == 38
    assert result["cleanupComplete"] is True


def test_gate_dispatch_rejects_typed_bypass_before_transport(tmp_path):
    from campaign_gate import CampaignGate, create

    plan = campaign_manifest("e" * 32)
    create(tmp_path / "gate", plan)
    gate = CampaignGate(tmp_path / "gate", "auth-list")
    gate.coordinator_call(0, lambda: (200, {}))
    gate.coordinator_call(1, lambda: (200, {}))
    gate.claim()
    operation = copy.deepcopy(plan["jobs"]["auth-list"]["observation"][0])
    operation["principal"] = "wrong-principal"
    called = False

    def send():
        nonlocal called
        called = True
        return 200, {}

    with pytest.raises(ValueError, match="request outside closed scenario"):
        gate.dispatch(operation, False, send)
    assert called is False


def test_gate_adapter_request_rejects_origin_bypass_before_transport(tmp_path):
    from campaign_gate import CampaignGate, create

    plan = campaign_manifest("f" * 32)
    create(tmp_path / "gate", plan)
    gate = CampaignGate(tmp_path / "gate", "auth-list")
    operation = plan["jobs"]["auth-list"]["observation"][0]
    adapter = SimpleNamespace(
        local={"auth": "https://external.invalid", "firestore": "https://external.invalid"},
        nonce=plan["nonce"],
        budget=SimpleNamespace(recovery=False),
    )
    with pytest.raises(ValueError, match="adapter origin/nonce/observer binding mismatch"):
        gate.adapter_request(adapter, operation, lambda: (200, {}))


def test_gate_finish_rejects_unclosed_recovery(tmp_path):
    from campaign_gate import CampaignGate, create

    plan = campaign_manifest("1" * 32)
    create(tmp_path / "gate", plan)
    gate = CampaignGate(tmp_path / "gate", "auth-list")
    gate.claim()
    with pytest.raises(ValueError, match="cleanup incomplete"):
        gate.finish()
