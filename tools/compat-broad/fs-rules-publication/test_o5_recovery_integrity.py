"""An injected failure or malformed recovery cannot become release evidence."""

from __future__ import annotations

import pytest
from o5_user_token_collector import ROLE_LOCAL_SHADOW, collect
from test_o5_user_token_collector import Transport, case


def run(override):
    plan = case()
    transport = Transport(plan)

    def execute(request):
        receipt = transport(request)
        return override(request, receipt)

    return (
        plan,
        transport,
        collect(plan, execute, role=ROLE_LOCAL_SHADOW, run_id="integrity"),
    )


@pytest.mark.parametrize(
    "kind", ["readback", "absence", "account-readback", "account-absence"]
)
@pytest.mark.parametrize(
    "bad",
    [
        {"status": "PERMISSION_DENIED"},
        {"code": "UNAVAILABLE"},
        {"httpStatus": 500},
        {"httpStatus": True},
        {"status": "OK", "failure": "transport-interrupted"},
    ],
)
def test_recovery_failure_cannot_be_proven_absence(kind, bad):
    def override(request, receipt):
        if request.get("kind") == kind:
            present = (
                "accountPresent" if kind.startswith("account-") else "documentPresent"
            )
            receipt = {"complete": True, present: False, **bad}
        return receipt

    plan, transport, bundle = run(override)
    assert bundle["cleanup"]["cleanupComplete"] is False
    assert bundle["recordingComplete"] is False
    if kind.endswith("readback") or kind == "readback":
        delete_kind = "account-delete" if kind.startswith("account-") else "delete"
        assert not any(r.get("kind") == delete_kind for r in transport.requests)


@pytest.mark.parametrize("kind", ["readback", "account-readback"])
@pytest.mark.parametrize("presence", [None, 1, "true", [], {}])
def test_version_or_uid_without_typed_presence_never_authorizes_delete(kind, presence):
    def override(request, receipt):
        if request.get("kind") == kind:
            receipt[
                "accountPresent" if kind.startswith("account-") else "documentPresent"
            ] = presence
        return receipt

    _, transport, bundle = run(override)
    assert bundle["cleanup"]["cleanupComplete"] is False
    delete_kind = "account-delete" if kind.startswith("account-") else "delete"
    assert not any(r.get("kind") == delete_kind for r in transport.requests)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf")])
def test_nonfinite_receipt_field_aborts_observation_and_still_recovers(value):
    def override(request, receipt):
        if request.get("phase") != "recovery":
            receipt["fields"] = {"value": value}
        return receipt

    _, transport, bundle = run(override)
    assert bundle["recordingComplete"] is False
    assert len(bundle["rows"]) == 1
    assert bundle["rows"][0]["observed"] is None
    assert bundle["cleanup"]["cleanupComplete"] is True


def test_complete_true_with_explicit_failure_is_not_an_observation():
    def override(request, receipt):
        if request.get("phase") != "recovery":
            receipt["failure"] = "truncated-response"
        return receipt

    _, _, bundle = run(override)
    assert bundle["recordingComplete"] is False
    assert bundle["cleanup"]["cleanupComplete"] is True


@pytest.mark.parametrize("field", ["deadline_seconds", "recovery_deadline_seconds"])
def test_boolean_deadline_is_not_a_duration(field):
    plan = case()
    args = {"deadline_seconds": 1, "recovery_deadline_seconds": 2, field: True}
    transport = Transport(plan)
    with pytest.raises(ValueError):
        collect(plan, transport, role=ROLE_LOCAL_SHADOW, run_id="invalid", **args)
    assert transport.requests == []
