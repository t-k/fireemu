from __future__ import annotations

import pytest
from o5_user_token_case import compile_case
from o5_user_token_collector import (
    COLLECTOR_CONTRACT,
    ROLE_LOCAL_SHADOW,
    ROLE_PRODUCTION,
    collect,
)

PROJECT = "fireemu-35fe6"
NONCE = "b" * 32


def case() -> dict:
    return compile_case(PROJECT, "(default)", NONCE)


class Transport:
    """A scripted transport. It never opens a socket and holds no credential."""

    def __init__(
        self, plan: dict, *, leak: bool = False, incomplete_at: int | None = None
    ):
        self.plan = plan
        self.leak = leak
        self.incomplete_at = incomplete_at
        self.requests: list[dict] = []
        self.present = {resource: True for resource in plan["ownedResources"]}

    def __call__(self, request: dict) -> dict:
        self.requests.append(request)
        if request.get("phase") == "recovery":
            return self._recovery(request)
        index = request["index"]
        if self.incomplete_at == index:
            return {"complete": False, "failure": "transport-timeout"}
        if self.leak and index == 0:
            return {"complete": True, "status": "OK", "idToken": "secret-value"}
        expected = self.plan["observation"][index]["expect"]["status"]
        return {
            "complete": True,
            "status": expected,
            "code": expected,
            "documentPresent": expected == "OK",
            "fields": {"caseId": request["caseId"]},
        }

    def _recovery(self, request: dict) -> dict:
        resource = request["resource"]
        if request["kind"] == "readback":
            present = self.present.get(resource, False)
            return {
                "complete": True,
                "documentPresent": present,
                "version": "2026-09-18T00:00:00Z" if present else None,
                "status": "OK",
            }
        if request["kind"] == "delete":
            assert request["precondition"]["updateTime"]
            self.present[resource] = False
            return {"complete": True, "status": "OK", "documentPresent": False}
        return {"complete": True, "documentPresent": self.present.get(resource, False)}


def test_a_complete_run_records_every_row_and_recovers_every_resource() -> None:
    plan = case()
    transport = Transport(plan)
    bundle = collect(plan, transport, role=ROLE_PRODUCTION, run_id="run-1")
    assert bundle["contract"] == COLLECTOR_CONTRACT
    assert bundle["recordingComplete"] is True
    assert bundle["abort"] is None
    assert len(bundle["rows"]) == len(plan["observation"])
    assert bundle["cleanup"]["cleanupComplete"] is True
    assert bundle["cleanup"]["outstandingResources"] == []


def test_a_bundle_never_claims_production_authority() -> None:
    plan = case()
    bundle = collect(plan, Transport(plan), role=ROLE_PRODUCTION, run_id="run-1")
    assert bundle["status"] == "PREPARATION_ONLY"
    assert bundle["productionExecuted"] is False
    assert bundle["productionReady"] is False


def test_the_collector_never_receives_or_stores_a_token() -> None:
    plan = case()
    transport = Transport(plan)
    bundle = collect(plan, transport, role=ROLE_PRODUCTION, run_id="run-1")
    for request in transport.requests:
        assert "idToken" not in request
        assert "authorization" not in request
        assert "apiKey" not in request
        assert request.get("credentialRef") is not None
    serialized = repr(bundle)
    assert "idToken" not in serialized
    assert "Bearer" not in serialized


def test_rows_bind_their_principal_without_a_secret() -> None:
    plan = case()
    bundle = collect(plan, Transport(plan), role=ROLE_PRODUCTION, run_id="run-1")
    for row, operation in zip(bundle["rows"], plan["observation"], strict=True):
        assert row["credentialRef"] == operation["credential"]["ref"]
        assert len(row["credentialFingerprint"]) == 16
    fingerprints = {
        row["credentialRef"]: row["credentialFingerprint"] for row in bundle["rows"]
    }
    assert len(set(fingerprints.values())) == len(fingerprints)


def test_a_leaked_credential_aborts_the_run() -> None:
    plan = case()
    bundle = collect(
        plan, Transport(plan, leak=True), role=ROLE_PRODUCTION, run_id="run-1"
    )
    assert bundle["abort"].startswith("credential-leak")
    assert len(bundle["rows"]) == 1
    assert bundle["rows"][0]["observed"] is None
    assert bundle["recordingComplete"] is False


def test_an_incomplete_receipt_stops_later_rows_but_still_recovers() -> None:
    plan = case()
    transport = Transport(plan, incomplete_at=3)
    bundle = collect(plan, transport, role=ROLE_PRODUCTION, run_id="run-1")
    assert bundle["abort"] == "incomplete-receipt"
    assert len(bundle["rows"]) == 4
    assert bundle["recordingComplete"] is False
    assert bundle["cleanup"]["cleanupComplete"] is True


def test_an_exhausted_deadline_stops_observation_before_the_request() -> None:
    plan = case()
    ticks = iter([0.0] + [100.0] * 200)
    transport = Transport(plan)
    bundle = collect(
        plan,
        transport,
        role=ROLE_PRODUCTION,
        run_id="run-1",
        deadline_seconds=10.0,
        clock=lambda: next(ticks),
    )
    assert bundle["abort"] == "deadline-exhausted"
    assert bundle["rows"] == []
    assert bundle["budget"]["observationSpent"] == 0
    assert bundle["cleanup"]["cleanupComplete"] is True


def test_recovery_still_runs_after_a_transport_exception() -> None:
    plan = case()
    transport = Transport(plan)

    def flaky(request: dict) -> dict:
        if request.get("phase") != "recovery" and request["index"] == 2:
            raise TimeoutError("network detail that must not be recorded")
        return transport(request)

    bundle = collect(plan, flaky, role=ROLE_PRODUCTION, run_id="run-1")
    assert bundle["rows"][2]["failure"] == "transport:TimeoutError"
    assert "network detail" not in repr(bundle)
    assert bundle["cleanup"]["cleanupComplete"] is True


def test_deletion_requires_a_proven_version() -> None:
    plan = case()
    transport = Transport(plan)

    def unversioned(request: dict) -> dict:
        receipt = transport(request)
        if request.get("kind") == "readback":
            receipt["version"] = None
        return receipt

    bundle = collect(plan, unversioned, role=ROLE_PRODUCTION, run_id="run-1")
    kinds = [step["kind"] for step in bundle["cleanup"]["steps"]]
    assert "delete" not in kinds
    assert bundle["cleanup"]["cleanupComplete"] is False
    assert bundle["recordingComplete"] is False


def test_an_already_absent_resource_is_not_deleted() -> None:
    plan = case()
    transport = Transport(plan)
    transport.present = {resource: False for resource in plan["ownedResources"]}
    bundle = collect(plan, transport, role=ROLE_LOCAL_SHADOW, run_id="run-2")
    assert [step["kind"] for step in bundle["cleanup"]["steps"]] == [
        "readback" for _ in plan["ownedResources"]
    ]
    assert bundle["cleanup"]["cleanupComplete"] is True


def test_attempted_creates_are_owned_even_when_the_response_is_lost() -> None:
    plan = case()
    transport = Transport(plan)
    creating = next(row for row in plan["observation"] if row["createdDocuments"])

    def lost(request: dict) -> dict:
        if request.get("phase") != "recovery" and request["index"] == creating["index"]:
            raise ConnectionError("lost")
        return transport(request)

    bundle = collect(plan, lost, role=ROLE_PRODUCTION, run_id="run-1")
    assert bundle["attemptedResources"]
    for document in creating["createdDocuments"]:
        assert any(
            resource.endswith(document) for resource in bundle["attemptedResources"]
        )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"role": "administrator", "run_id": "run-1"},
        {"role": ROLE_PRODUCTION, "run_id": ""},
        {"role": ROLE_PRODUCTION, "run_id": "run-1", "deadline_seconds": 0},
        {"role": ROLE_PRODUCTION, "run_id": "run-1", "deadline_seconds": 100000},
    ],
)
def test_invalid_collection_parameters_rejected(kwargs) -> None:
    plan = case()
    with pytest.raises(ValueError):
        collect(plan, Transport(plan), **kwargs)


def test_a_malformed_case_is_rejected_before_any_request() -> None:
    plan = case()
    plan["observation"][1]["expect"]["status"] = "OK"
    transport = Transport(plan)
    with pytest.raises(ValueError):
        collect(plan, transport, role=ROLE_PRODUCTION, run_id="run-1")
    assert transport.requests == []
