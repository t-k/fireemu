from __future__ import annotations

import compiler_03
import limits_03_descriptor as campaign
import limits_03_preflight as preflight
import pytest
import batch_adapter
import o8_admission


def test_one_poll_lifecycle_is_compiled_as_seven_charged_slots() -> None:
    contract = campaign.lifecycle_contract()
    assert contract["pollLimit"] == 1
    assert contract["observationSlots"] == 4
    assert contract["recoverySlots"] == 3
    assert compiler_03.management_contract()["totalRequests"] == 16
    assert campaign.budget_figures()["requestUpperBound"] == 192
    assert campaign.budget_figures()["envelopeCostMicrousd"] == 59_200


def test_lifecycle_management_ids_are_closed_and_ordered() -> None:
    contract = compiler_03.management_contract()
    assert [slot["id"] for slot in contract["observation"]][-4:] == [
        "index-lifecycle-before",
        "index-lifecycle-apply",
        "index-lifecycle-poll",
        "index-lifecycle-after",
    ]
    assert [slot["id"] for slot in contract["recovery"]][-3:] == [
        "index-lifecycle-restore",
        "index-lifecycle-poll-restore",
        "index-lifecycle-restored",
    ]


def test_hosted_baseline_rejects_wrong_ancestor_before_data() -> None:
    session = preflight.ManagementSession.__new__(preflight.ManagementSession)
    session._lifecycle = {}
    session.lifecycle_failed = False
    wrong = {
        "name": preflight.LIFECYCLE_FIELD,
        "indexConfig": {
            "indexes": [{"queryScope": "BAD"}],
            "usesAncestorConfig": True,
            "ancestorField": "projects/attacker/databases/(default)/collectionGroups/__default__/fields/*",
        },
        "ttlConfig": {"state": "ENABLED"},
    }
    response = {"status": 200, "complete": True, "workerReaped": True, "bodyKind": "json", "body": wrong}
    with pytest.raises(ValueError, match="inherited field"):
        session._accept_lifecycle_response("index-lifecycle-before", response)


def test_lifecycle_transport_reaches_real_wire_boundary(monkeypatch) -> None:
    seen = {}

    def wire(route, method, body, headers, *, timeout, receipt):
        seen.update(route=route, method=method, body=body, headers=headers, timeout=timeout, receipt=receipt)
        return {"http": {"complete": True, "bodyKind": "json", "status": 200}, "body": {"name": "projects/fireemu-35fe6/databases/(default)/operations/op-1"}}

    monkeypatch.setattr(batch_adapter, "wire", wire)
    monkeypatch.setattr(o8_admission, "authorize_transport", lambda *_args, **_kwargs: None)
    response = preflight.management_transport(
        "index-lifecycle-apply",
        "test-token",
        deadline=10**9,
        capability=object(),
        binding=b"worker",
        binding_digest="0" * 64,
        operation={
            "method": "PATCH",
            "route": preflight.LIFECYCLE_ROUTE + "?updateMask=indexConfig",
            "body": {"name": preflight.LIFECYCLE_FIELD, "indexConfig": {"indexes": []}},
        },
    )
    assert response["complete"] is True
    assert seen["method"] == "PATCH"
    assert seen["route"].endswith("?updateMask=indexConfig")
    assert seen["body"]["name"] == preflight.LIFECYCLE_FIELD
    assert seen["headers"]["Authorization"] == "Bearer test-token"
    assert seen["receipt"] is True
