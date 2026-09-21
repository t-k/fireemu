from __future__ import annotations

import sys
from pathlib import Path

import pytest

LANE = Path(__file__).resolve().parent
sys.path[:0] = [str(LANE), str(LANE.parent), str(LANE.parent / "o8-core"), str(LANE.parent / "production-admission")]

import request_bytes_compiler as compiler
import request_bytes_recovery_campaign as recovery
import shared_gate


def parent_plan():
    return compiler.compile_request_bytes_plan(
        "fireemu-35fe6", "(default)", "0123456789abcdef0123456789abcdef"
    )


def ownership_response(plan, resource, *, nonce=None, name=None, fields=None, update_time="2026-01-01T00:00:00.000000Z"):
    update = next(
        write["update"]
        for probe in plan["probes"]
        for write in probe["body"]["writes"]
        if write["update"]["name"] == resource
    )
    body = {
        "name": name or resource,
        "fields": fields or update["fields"],
        "updateTime": update_time,
    }
    if nonce is not None:
        body["fields"] = {**body["fields"], "_owner": {"stringValue": nonce}}
    return {"complete": True, "status": 200, "body": body}


def fixture_body(operation):
    return {"name": operation["resource"], "fields": {"_owner": {"stringValue": "fixture"}}}


def test_recovery_plan_has_distinct_identity_and_exact_85_slot_shape():
    plan = recovery.compile_recovery_plan(
        parent_plan(), selected_probe="under", recovery_nonce="fedcba9876543210fedcba9876543210"
    )

    assert plan["parentNonce"] == "0123456789abcdef0123456789abcdef"
    assert plan["recoveryNonce"] == "fedcba9876543210fedcba9876543210"
    assert plan["parentNonce"] != plan["recoveryNonce"]
    assert plan["bounds"] == {
        "inspectionReads": 17,
        "conditionalDeletes": 17,
        "absenceReads": 51,
        "maximumRequests": 85,
        "tariffEstimateMicrousd": 45,
    }
    assert len(plan["operations"]) == 85
    assert sum(op["kind"] == "recovery-inspection-read" for op in plan["operations"]) == 17
    assert sum(op["kind"] == "recovery-conditional-delete" for op in plan["operations"]) == 17
    assert sum(op["kind"] == "recovery-absence-read" for op in plan["operations"]) == 51
    assert {op["resource"] for op in plan["operations"][:34]} == set(
        parent_plan()["probes"][0]["resources"]
    )
    assert {op["resource"] for op in plan["operations"][34:]} == {
        resource for probe in parent_plan()["probes"] for resource in probe["resources"]
    }


def test_recovery_plan_rejects_parent_nonce_reuse_and_unknown_probe():
    with pytest.raises(ValueError, match="distinct"):
        recovery.compile_recovery_plan(
            parent_plan(), selected_probe="under", recovery_nonce="0123456789abcdef0123456789abcdef"
        )
    with pytest.raises(ValueError, match="probe"):
        recovery.compile_recovery_plan(
            parent_plan(), selected_probe="unknown", recovery_nonce="fedcba9876543210fedcba9876543210"
        )
    with pytest.raises(ValueError, match="32 characters"):
        recovery.compile_recovery_plan(
            parent_plan(), selected_probe="under", recovery_nonce="not-hex-recovery-nonce-000000"
        )


@pytest.mark.parametrize("mutation", ["resource", "duplicate", "foreign"])
def test_recovery_plan_rejects_mutated_parent_operations(mutation):
    parent = parent_plan()
    if mutation == "resource":
        parent["probes"][0]["resources"][0] += "/foreign"
    elif mutation == "duplicate":
        parent["recovery"].append(dict(parent["recovery"][0]))
    else:
        parent["recovery"][0] = {**parent["recovery"][0], "resource": "projects/foreign"}
    with pytest.raises((ValueError, KeyError)):
        recovery.compile_recovery_plan(
            parent, selected_probe="under", recovery_nonce="fedcba9876543210fedcba9876543210"
        )


def test_gate_plan_is_compiled_from_recovery_operations():
    parent = parent_plan()
    recovery_plan = recovery.compile_recovery_plan(
        parent, selected_probe="under", recovery_nonce="fedcba9876543210fedcba9876543210"
    )
    gate_plan = recovery.compile_gate_plan(
        parent,
        selected_probe="under",
        recovery_nonce="fedcba9876543210fedcba9876543210",
        recovery_plan=recovery_plan,
    )
    assert gate_plan["contract"] == "shared-local-v2"
    assert gate_plan["recoveryRequests"] == 85
    assert gate_plan["costMicrousd"] >= 85
    assert gate_plan["tariffEstimateMicrousd"] == 45
    assert len(gate_plan["jobs"][recovery.RECOVERY_JOB]["recovery"]) == 85
    assert len(gate_plan["jobs"][recovery.RECOVERY_JOB]["schedule"]) == 85


def test_gate_cost_cannot_be_underfunded_by_tariff_estimate():
    parent = parent_plan()
    recovery_plan = recovery.compile_recovery_plan(
        parent, selected_probe="under", recovery_nonce="fedcba9876543210fedcba9876543210"
    )
    gate_plan = recovery.compile_gate_plan(
        parent,
        selected_probe="under",
        recovery_nonce="fedcba9876543210fedcba9876543210",
        recovery_plan=recovery_plan,
    )
    assert gate_plan["costMicrousd"] == 85
    assert gate_plan["tariffEstimateMicrousd"] == 45
    assert gate_plan["costMicrousd"] > gate_plan["tariffEstimateMicrousd"]


def test_ownership_validation_preserves_wrong_nonce_fields_name_version_and_absence():
    plan = parent_plan()
    resource = plan["probes"][0]["resources"][0]
    valid = ownership_response(plan, resource)
    operation = {"method": "GET", "path": "/v1/" + resource, "resource": resource}
    assert recovery.validate_ownership_response(plan, operation, valid)["owned"] is True
    for altered in (
        ownership_response(plan, resource, nonce="wrong"),
        ownership_response(plan, resource, fields={"blob": {"stringValue": "wrong"}}),
        ownership_response(plan, resource, name=resource + "/foreign"),
        ownership_response(plan, resource, update_time="not-a-timestamp"),
    ):
        with pytest.raises(ValueError, match="ownership"):
            recovery.validate_ownership_response(plan, operation, altered)
    absent = {"complete": True, "status": 404, "body": {"error": {"code": 404, "status": "NOT_FOUND"}}}
    assert recovery.validate_ownership_response(plan, operation, absent) == {
        "owned": False,
        "updateTime": None,
    }
    with pytest.raises(ValueError, match="canonical requested resource"):
        recovery.validate_ownership_response(
            plan,
            {"method": "GET", "path": "/v1/projects/foreign", "resource": "projects/foreign"},
            absent,
        )


@pytest.mark.parametrize("mutation", ["operation", "binding", "bounds", "tariff"])
def test_gate_compiler_rejects_mutated_recovery_provenance(mutation):
    parent = parent_plan()
    nonce = "fedcba9876543210fedcba9876543210"
    recovery_plan = recovery.compile_recovery_plan(parent, selected_probe="under", recovery_nonce=nonce)
    if mutation == "operation":
        recovery_plan["operations"][0]["path"] += "/foreign"
    elif mutation == "binding":
        recovery_plan["operations"][1]["versionFrom"] = "foreign"
    elif mutation == "bounds":
        recovery_plan["bounds"]["maximumRequests"] = 84
    else:
        recovery_plan["bounds"]["tariffEstimateMicrousd"] = 44
    with pytest.raises(ValueError, match="canonical recovery provenance"):
        recovery.compile_gate_plan(
            parent,
            selected_probe="under",
            recovery_nonce=nonce,
            recovery_plan=recovery_plan,
        )


def test_real_gate_refuses_delete_without_trusted_creation_proof(tmp_path):
    parent = parent_plan()
    recovery_plan = recovery.compile_recovery_plan(
        parent, selected_probe="under", recovery_nonce="fedcba9876543210fedcba9876543210"
    )
    gate_plan = recovery.compile_gate_plan(
        parent,
        selected_probe="under",
        recovery_nonce="fedcba9876543210fedcba9876543210",
        recovery_plan=recovery_plan,
    )
    gate_path = tmp_path / "gate"
    shared_gate.create(gate_path, gate_plan)
    gate = shared_gate.Gate(gate_path, recovery.RECOVERY_JOB)
    gate.claim()

    inspection = gate_plan["jobs"][recovery.RECOVERY_JOB]["recovery"][0]
    gate.dispatch(inspection, True, lambda: (200, fixture_body(inspection)))
    delete = gate_plan["jobs"][recovery.RECOVERY_JOB]["recovery"][1]
    with pytest.raises(ValueError, match="request outside closed scenario|creation ownership"):
        gate.dispatch(delete, True, lambda: (200, {}))
    with pytest.raises(ValueError, match="cleanup incomplete"):
        gate.finish()
