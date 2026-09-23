"""Closed wall-window contract for the AUTH revision-3 Gate plan."""

import pytest
from shared_gate import create
from test_shared_gate import scheduled_plan

CAMPAIGN = "AUTH-MFA-AGE-TOTP-01"
SELECTOR = "pending-lifetime-rev3-v1"


def rev3_plan():
    value = scheduled_plan(slots=1, probes=("auth",))
    value.update(
        campaignId=CAMPAIGN,
        selector=SELECTOR,
        nonce="a" * 32,
        wallSeconds=1500,
        recoverySeconds=300,
    )
    return value


def test_rev3_selector_admits_1500_second_wall_with_300_second_recovery(tmp_path):
    create(tmp_path / "gate", rev3_plan())


@pytest.mark.parametrize(
    "change",
    [
        {"campaignId": "AUTH-MFA-TOTP-ENROLL-RETRY-01"},
        {"selector": "pending-age-300-v1"},
        {"selector": "unknown-selector"},
        {"wallSeconds": 1501},
        {"recoverySeconds": 299},
    ],
)
def test_rev3_wall_rejects_values_outside_closed_exception(tmp_path, change):
    value = rev3_plan()
    value.update(change)
    with pytest.raises(ValueError):
        create(tmp_path / "gate", value)
    assert not (tmp_path / "gate").exists()


def test_management_request_cap_remains_1200_seconds():
    from shared_gate import WALL_CAP_SECONDS

    assert WALL_CAP_SECONDS == 1200


def test_existing_pending_age_selector_keeps_its_1200_second_wall(tmp_path):
    value = rev3_plan()
    value.update(selector="pending-age-300-v1", wallSeconds=1200)
    create(tmp_path / "gate", value)
