"""Contracts for the single exploratory 16 MiB request-byte sentinel."""

from __future__ import annotations

import sys
import base64
import hashlib
import json
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from request_bytes_compiler import (
    DOCUMENT_SAFETY_MARGIN,
    RAW_16MIB_OVER_BYTES,
    RAW_16MIB_OVER_CASE_ID,
    compact_utf8,
    compile_request_bytes_sentinel_plan,
    validate_request_bytes_sentinel_plan,
)
from request_bytes_campaign import (
    compile_request_bytes_sentinel_campaign,
    validate_request_bytes_sentinel_campaign,
)
from request_bytes_collector import collect_local, validate_schedule

NONCE = "a" * 32


def test_sentinel_compiles_one_exactly_sized_twenty_document_commit() -> None:
    plan = compile_request_bytes_sentinel_plan("demo", "(default)", NONCE)

    assert plan["caseId"] == RAW_16MIB_OVER_CASE_ID
    assert plan["catalogId"] == "FS-LIMIT-API-REQUEST-BYTES"
    assert plan["metricStatus"] == "observation hypothesis"
    assert len(plan["probes"]) == 1
    probe = plan["probes"][0]
    assert probe["label"] == "raw-16mib-over"
    assert probe["bodyBytes"] == RAW_16MIB_OVER_BYTES == 16_777_217
    assert len(compact_utf8(probe["body"])) == RAW_16MIB_OVER_BYTES
    assert len(probe["resources"]) == 20
    assert len(plan["ownedResources"]) == 20
    assert len(probe["body"]["writes"]) == 20
    assert all(
        row["currentDocument"] == {"exists": False}
        for row in probe["body"]["writes"]
    )
    assert sum(
        write["update"]["name"].endswith(tuple(f"payload-{i:02d}" for i in range(19)))
        for write in probe["body"]["writes"]
    ) == 19
    assert all(
        doc["logicalBytes"] < DOCUMENT_SAFETY_MARGIN
        for doc in plan["documents"].values()
    )
    assert probe["expected"]["outcome"] == "capture-without-semantic-expectation"
    assert plan["bounds"]["observationRequests"] == 41
    assert plan["bounds"]["recoveryRequests"] == 60
    assert plan["bounds"]["totalRequestBound"] == 101
    validate_request_bytes_sentinel_plan(plan)


def test_sentinel_validator_rejects_body_scope_and_semantic_expectation_drift() -> None:
    plan = compile_request_bytes_sentinel_plan("demo", "(default)", NONCE)
    plan["probes"][0]["body"]["writes"][1]["update"]["fields"]["blob"][
        "stringValue"
    ] += "x"
    with pytest.raises(ValueError, match="byte length"):
        validate_request_bytes_sentinel_plan(plan)

    plan = compile_request_bytes_sentinel_plan("demo", "(default)", NONCE)
    plan["recovery"][0]["resource"] = (
        "projects/foreign/databases/(default)/documents/foreign/victim"
    )
    with pytest.raises(ValueError):
        validate_request_bytes_sentinel_plan(plan)

    plan = compile_request_bytes_sentinel_plan("demo", "(default)", NONCE)
    plan["probes"][0]["expected"]["productionExpectation"] = "refused"
    with pytest.raises(ValueError, match="outcome-neutral"):
        validate_request_bytes_sentinel_plan(plan)


def test_sentinel_validator_rejects_create_precondition_and_schedule_drift() -> None:
    plan = compile_request_bytes_sentinel_plan("demo", "(default)", NONCE)
    plan["probes"][0]["body"]["writes"][0]["currentDocument"] = {"exists": True}
    with pytest.raises(ValueError, match="exists-false"):
        validate_request_bytes_sentinel_plan(plan)

    plan = compile_request_bytes_sentinel_plan("demo", "(default)", NONCE)
    plan["executionSchedule"].reverse()
    with pytest.raises(ValueError):
        validate_request_bytes_sentinel_plan(plan)


def test_transport_rejects_exact_cap_commit_row_with_mutated_owner_nonce() -> None:
    import copy

    import request_bytes_remote_transport as transport

    plan = compile_request_bytes_sentinel_plan("demo", "(default)", NONCE)
    operation = copy.deepcopy(plan["observation"][20])
    operation["body"]["writes"][0]["update"]["fields"]["_owner"][
        "stringValue"
    ] = "b" * 32
    assert len(compact_utf8(operation["body"])) == RAW_16MIB_OVER_BYTES
    plan["observation"][20] = copy.deepcopy(operation)

    with pytest.raises(ValueError, match="request plan validation failed"):
        transport.prepare(plan, "observation", 20, operation, "offline-test-token")


def test_sentinel_campaign_is_finite_costed_and_does_not_predict_outcome() -> None:
    campaign = compile_request_bytes_sentinel_campaign("demo", "(default)", NONCE)

    assert campaign["caseIds"] == [RAW_16MIB_OVER_CASE_ID]
    case = campaign["cases"][0]
    assert case["id"] == RAW_16MIB_OVER_CASE_ID
    assert case["requestBytes"] == RAW_16MIB_OVER_BYTES
    assert case["outcomeExpectation"] == "unknown"
    assert "productionExpectation" not in case
    assert campaign["accounting"] == {
        "documentReads": 80,
        "documentWrites": 20,
        "documentDeletes": 20,
        "dataRequests": 101,
        "managementRequests": 7,
        "httpRequests": 108,
        "uploadedBytes": RAW_16MIB_OVER_BYTES,
    }
    assert campaign["cost"]["estimatedCostMicrousd"] == 88
    assert campaign["budget"]["maxRequestBytes"] == RAW_16MIB_OVER_BYTES
    assert campaign["transportDeadlineSeconds"] == 80
    assert campaign["budget"]["recoveryWindow"]["reserveDeletes"] == 20
    validate_request_bytes_sentinel_campaign(campaign)


def test_sentinel_campaign_validator_rejects_outcome_and_budget_drift() -> None:
    campaign = compile_request_bytes_sentinel_campaign("demo", "(default)", NONCE)
    campaign["cases"][0]["outcomeExpectation"] = "refused"
    with pytest.raises(ValueError, match="outcome-neutral"):
        validate_request_bytes_sentinel_campaign(campaign)

    campaign = compile_request_bytes_sentinel_campaign("demo", "(default)", NONCE)
    campaign["budget"]["maxDeletes"] = 19
    with pytest.raises(ValueError, match="budget"):
        validate_request_bytes_sentinel_campaign(campaign)


def _run_sentinel_collector(tmp_path: Path, outcome: str) -> dict:
    plan = compile_request_bytes_sentinel_plan("demo", "(default)", NONCE)
    fields = {
        write["update"]["name"]: write["update"]["fields"]
        for write in plan["probes"][0]["body"]["writes"]
    }
    live: dict[str, str] = {}
    version = "2026-09-23T01:02:03Z"
    dispatched = []

    def receipt(status: int, body: object, *, content_type: str = "application/json"):
        raw = (
            body.encode("utf-8")
            if isinstance(body, str)
            else json.dumps(body, separators=(",", ":")).encode()
        )
        return {
            "complete": True,
            "failure": None,
            "status": status,
            "headers": {"content-type": content_type},
            "body": body if isinstance(body, str) else body,
            "rawBodyBase64": base64.b64encode(raw).decode("ascii"),
            "rawBodyBytes": len(raw),
            "rawBodySha256": hashlib.sha256(raw).hexdigest(),
            "bodyBytes": len(raw),
        }

    def absent():
        return receipt(404, {"error": {"code": 404, "status": "NOT_FOUND"}})

    def execute(operation: dict) -> dict:
        dispatched.append(operation)
        kind, resource = operation["kind"], operation.get("resource")
        if kind == "conditional-create-commit":
            resources = plan["probes"][0]["resources"]
            if outcome == "accepted":
                live.update({name: version for name in resources})
                return receipt(
                    200,
                    {
                        "writeResults": [
                            {"name": name, "updateTime": version} for name in resources
                        ]
                    },
                )
            if outcome == "typed-refused":
                return receipt(
                    429,
                    {"error": {"code": 429, "status": "RESOURCE_EXHAUSTED"}},
                )
            if outcome == "untyped-refused":
                return receipt(413, "<html>proxy response</html>", content_type="text/html")
            return {
                "complete": False,
                "failure": "response-timeout",
                "status": None,
            }
        if kind == "cleanup-version-bound-delete":
            assert resource in live
            assert operation["path"].endswith("currentDocument.updateTime=2026-09-23T01%3A02%3A03Z")
            del live[resource]
            return receipt(200, {})
        if resource in live:
            return receipt(
                200,
                {
                    "name": resource,
                    "fields": fields[resource],
                    "updateTime": live[resource],
                },
            )
        return absent()

    result = collect_local(plan, execute, tmp_path / outcome)
    result["testDispatched"] = dispatched
    return result


def test_sentinel_collector_acceptance_is_complete_and_cleans_all_owned_documents(
    tmp_path: Path,
) -> None:
    plan = compile_request_bytes_sentinel_plan("demo", "(default)", NONCE)
    validate_schedule(plan)

    result = _run_sentinel_collector(tmp_path, "accepted")

    assert result["completed"] is True
    assert result["resourceAbsence"] is True
    assert result["requestCount"] == 101
    assert result["semanticOutcome"] == "sentinel-accepted"
    assert len([op for op in result["testDispatched"] if op["method"] == "DELETE"]) == 20
    assert result["sentinelResponse"]["httpStatus"] == 200
    assert result["sentinelResponse"]["requestBytes"] == RAW_16MIB_OVER_BYTES


def test_sentinel_collector_typed_refusal_is_outcome_neutral_and_proves_absence(
    tmp_path: Path,
) -> None:
    result = _run_sentinel_collector(tmp_path, "typed-refused")

    assert result["completed"] is True
    assert result["resourceAbsence"] is True
    assert result["semanticOutcome"] == "sentinel-typed-refusal"
    assert {
        key: result["sentinelResponse"]["typedError"][key]
        for key in ("code", "status")
    } == {"code": 429, "status": "RESOURCE_EXHAUSTED"}
    assert not any(op["method"] == "DELETE" for op in result["testDispatched"])


def test_sentinel_collector_records_an_intermediary_response_without_calling_it_firestore(
    tmp_path: Path,
) -> None:
    result = _run_sentinel_collector(tmp_path, "untyped-refused")

    assert result["completed"] is False
    assert result["resourceAbsence"] is True
    assert result["semanticOutcome"] == "sentinel-inconclusive"
    capture = result["sentinelResponse"]
    assert capture["classification"] == "sentinel-untyped-refusal"
    assert capture["httpStatus"] == 413
    assert capture["contentType"] == "text/html"
    assert capture["responseBytes"] == len(b"<html>proxy response</html>")
    assert capture["responseSha256"] == hashlib.sha256(
        b"<html>proxy response</html>"
    ).hexdigest()
    assert capture["typedError"] is None
    assert capture["requestBytes"] == RAW_16MIB_OVER_BYTES
    assert not any(op["method"] == "DELETE" for op in result["testDispatched"])


def test_sentinel_collector_incomplete_commit_is_inconclusive_and_cannot_delete(
    tmp_path: Path,
) -> None:
    result = _run_sentinel_collector(tmp_path, "incomplete")

    assert result["completed"] is False
    assert result["semanticOutcome"] == "sentinel-inconclusive"
    assert not any(op["method"] == "DELETE" for op in result["testDispatched"])


def test_sentinel_collector_reserves_its_case_specific_commit_deadline(
    tmp_path: Path,
) -> None:
    import time

    plan = compile_request_bytes_sentinel_plan("demo", "(default)", NONCE)
    started = time.monotonic()
    seen = {}

    class ProbeGate:
        def snapshot(self):
            return {
                "started": started,
                "plan": {"wallSeconds": 1200, "recoverySeconds": 600},
            }

        def dispatch(self, operation, recovery, send_wire):
            return send_wire()

        def skip_scheduled_slot(self, *args):
            pass

        def abandon_observation(self, *args):
            pass

    class Gate(dict):
        def values(self):
            return [self["raw-16mib-over"]]

    def execute(operation, *, deadline):
        if operation["kind"] == "conditional-create-commit":
            seen["remaining"] = deadline - time.monotonic()
        body = {"error": {"code": 404, "status": "NOT_FOUND"}}
        raw = json.dumps(body, separators=(",", ":")).encode()
        return {
            "complete": True,
            "failure": None,
            "status": 404,
            "body": body,
            "rawBodyBase64": base64.b64encode(raw).decode("ascii"),
            "bodyBytes": len(raw),
        }

    collect_local(
        plan, execute, tmp_path / "run", gate=Gate({"raw-16mib-over": ProbeGate()})
    )

    assert 75 < seen["remaining"] <= 80


def test_descriptor_freezes_one_case_and_projects_one_reserved_gate_job() -> None:
    import request_bytes_descriptor as descriptor

    reference = descriptor.plan_compiler(NONCE, case_id=RAW_16MIB_OVER_CASE_ID)
    plan = descriptor.execution_plan(reference)
    gate = descriptor.gate_plan(
        plan,
        upload_seconds=80,
        observation_slot_seconds=3,
        recovery_slot_seconds=3,
    )

    assert reference["caseId"] == RAW_16MIB_OVER_CASE_ID
    assert reference["bounds"]["requestBytes"] == RAW_16MIB_OVER_BYTES
    assert len(plan["probes"]) == 1
    assert list(gate["jobs"]) == ["request-bytes-raw-16mib-over"]
    job = gate["jobs"]["request-bytes-raw-16mib-over"]
    assert len(job["resources"]) == 20
    assert len(job["observation"]) == 41
    assert len(job["recovery"]) == 60
    assert sum(slot["seconds"] == 80 for slot in job["schedule"]) == 1
    assert gate["jobSlots"] == 1
    assert gate["dataRequests"] == 101
    assert descriptor.lock_scopes(reference)[0]["key"].endswith(
        f"/oracle/{NONCE}/request-bytes-02/probe-r16m1/*"
    )


def test_gate_reservation_admission_is_case_bound() -> None:
    import request_bytes_admission as admission

    permission = {
        "caseId": RAW_16MIB_OVER_CASE_ID,
        "gateReservationSeconds": {
            "upload": 80.0,
            "observationSlot": 3.0,
            "recoverySlot": 3.0,
            "slotBasis": admission.PLANNING_ASSUMPTION,
        },
    }
    assert admission.gate_reservations(permission)["upload"] == 80.0
    permission["gateReservationSeconds"]["upload"] = 60.0
    with pytest.raises(ValueError, match="enforced ceiling"):
        admission.gate_reservations(permission)


def test_sentinel_recovery_child_is_separate_and_covers_only_20_case_resources():
    import request_bytes_compiler as compiler
    import request_bytes_recovery_campaign as recovery

    parent = compiler.compile_request_bytes_sentinel_plan(
        "fireemu-35fe6", "(default)", "d" * 32
    )
    child = recovery.compile_recovery_plan(
        parent,
        selected_probe=compiler.RAW_16MIB_OVER_LABEL,
        recovery_nonce="e" * 32,
    )
    gate = recovery.compile_gate_plan(
        parent,
        selected_probe=compiler.RAW_16MIB_OVER_LABEL,
        recovery_nonce="e" * 32,
        recovery_plan=child,
    )
    assert child["bounds"] == {
        "inspectionReads": 20,
        "conditionalDeletes": 20,
        "absenceReads": 20,
        "maximumRequests": 60,
        "tariffEstimateMicrousd": 28,
    }
    assert len(gate["jobs"][recovery.RECOVERY_JOB]["recovery"]) == 60
    assert len(gate["jobs"][recovery.RECOVERY_JOB]["resources"]) == 20


def test_sentinel_recovery_admission_recompiles_only_its_case_and_60_slot_budget():
    import request_bytes_compiler as compiler
    import request_bytes_recovery_admission as recovery_admission

    parent = compiler.compile_request_bytes_sentinel_plan(
        "fireemu-35fe6", "(default)", "d" * 32
    )
    _, recovery_plan, gate = recovery_admission._canonical_plans(
        parent,
        selected_probe=compiler.RAW_16MIB_OVER_LABEL,
        recovery_nonce="e" * 32,
    )
    descriptor = recovery_admission.descriptor(compiler.RAW_16MIB_OVER_CASE_ID)
    assert recovery_plan["caseId"] == compiler.RAW_16MIB_OVER_CASE_ID
    assert descriptor.budget == recovery_admission.SENTINEL_CHILD_BUDGET
    assert gate["recoveryRequests"] == 60
    with pytest.raises(ValueError, match="unsupported closed recovery case"):
        recovery_admission.descriptor("other-case")
