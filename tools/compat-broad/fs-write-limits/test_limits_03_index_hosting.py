from __future__ import annotations

import compiler_03
import limits_03_descriptor as campaign


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
