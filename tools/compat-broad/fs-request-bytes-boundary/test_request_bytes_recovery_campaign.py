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
        "tariffCostMicrousd": 45,
    }
    assert len(plan["operations"]) == 85
    assert sum(op["kind"] == "recovery-inspection-read" for op in plan["operations"]) == 17
    assert sum(op["kind"] == "recovery-conditional-delete" for op in plan["operations"]) == 17
    assert sum(op["kind"] == "recovery-absence-read" for op in plan["operations"]) == 51
    assert {op["resource"] for op in plan["operations"][:34]} == set(
        parent_plan()["probes"][0]["resources"]
    )
    assert {op["resource"] for op in plan["operations"][34:]} == set(
        resource for probe in parent_plan()["probes"] for resource in probe["resources"]
    )


def test_recovery_plan_rejects_parent_nonce_reuse_and_unknown_probe():
    with pytest.raises(ValueError, match="distinct"):
        recovery.compile_recovery_plan(
            parent_plan(), selected_probe="under", recovery_nonce="0123456789abcdef0123456789abcdef"
        )
    with pytest.raises(ValueError, match="probe"):
        recovery.compile_recovery_plan(
            parent_plan(), selected_probe="unknown", recovery_nonce="fedcba9876543210fedcba9876543210"
        )


def test_gate_plan_is_compiled_from_recovery_operations():
    plan = recovery.compile_recovery_plan(
        parent_plan(), selected_probe="under", recovery_nonce="fedcba9876543210fedcba9876543210"
    )
    gate_plan = recovery.compile_gate_plan(plan)
    assert gate_plan["contract"] == "shared-local-v2"
    assert gate_plan["recoveryRequests"] == 85
    assert gate_plan["costMicrousd"] >= 85
    assert len(gate_plan["jobs"][recovery.RECOVERY_JOB]["recovery"]) == 85
    assert len(gate_plan["jobs"][recovery.RECOVERY_JOB]["schedule"]) == 85


def test_ownership_validation_preserves_wrong_nonce_fields_name_version_and_absence():
    plan = parent_plan()
    resource = plan["probes"][0]["resources"][0]
    valid = ownership_response(plan, resource)
    assert recovery.validate_ownership_response(plan, resource, valid)["owned"] is True
    for altered in (
        ownership_response(plan, resource, nonce="wrong"),
        ownership_response(plan, resource, fields={"blob": {"stringValue": "wrong"}}),
        ownership_response(plan, resource, name=resource + "/foreign"),
        ownership_response(plan, resource, update_time="not-a-timestamp"),
    ):
        with pytest.raises(ValueError, match="ownership"):
            recovery.validate_ownership_response(plan, resource, altered)
    absent = {"complete": True, "status": 404, "body": {"error": {"code": 404, "status": "NOT_FOUND"}}}
    assert recovery.validate_ownership_response(plan, resource, absent) == {
        "owned": False,
        "updateTime": None,
    }


def test_real_gate_refuses_delete_without_trusted_creation_proof(tmp_path):
    recovery_plan = recovery.compile_recovery_plan(
        parent_plan(), selected_probe="under", recovery_nonce="fedcba9876543210fedcba9876543210"
    )
    gate_plan = recovery.compile_gate_plan(recovery_plan)
    gate_path = tmp_path / "gate"
    shared_gate.create(gate_path, gate_plan)
    gate = shared_gate.Gate(gate_path, recovery.RECOVERY_JOB)
    gate.claim()

    inspection = gate_plan["jobs"][recovery.RECOVERY_JOB]["recovery"][0]
    gate.dispatch(inspection, True, lambda: (200, recovery.owned_document_body(inspection)))
    delete = gate_plan["jobs"][recovery.RECOVERY_JOB]["recovery"][1]
    with pytest.raises(ValueError, match="request outside closed scenario|creation ownership"):
        gate.dispatch(delete, True, lambda: (200, {}))
    with pytest.raises(ValueError, match="cleanup incomplete"):
        gate.finish()
