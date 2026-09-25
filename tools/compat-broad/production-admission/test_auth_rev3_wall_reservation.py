# ruff: noqa: I001 -- reservations bootstraps the shared module path.
"""Ledger contract for the bounded AUTH revision-3 wall exception."""

import pytest
from reservations import Ledger, _claim
from broad_contract import digest
from test_reservations import envelope
from test_reservations import plan as base_plan

CAMPAIGN = "AUTH-MFA-AGE-TOTP-01"
SELECTOR = "pending-lifetime-rev3-v1"


def rev3_plan(label="rev3"):
    value = base_plan(label)
    value.update(
        campaignId=CAMPAIGN,
        selector=SELECTOR,
        wallSeconds=1500,
        recoverySeconds=300,
    )
    return value


def rev3_claim(tmp_path, value, *, campaign=CAMPAIGN, duration=1500):
    resource = value["jobs"]["limits"]["resources"][0].rsplit("/", 1)[-1]
    return {
        "campaignId": campaign,
        "manifestDigest": digest("auth-rev3"),
        "nonceDigest": digest(value["nonce"]),
        "gatePath": str((tmp_path / "rev3-gate").resolve()),
        "gatePlanDigest": digest(value),
        "locks": [
            {
                "key": f"project/p/firestore/(default)/documents/owned/{resource}",
                "mode": "WRITE",
            }
        ],
        "budget": {
            "requests": 2,
            "accounts": 0,
            "resources": 1,
            "costMicrousd": value["costMicrousd"],
        },
        "durationSeconds": duration,
    }


def test_claim_accepts_1500_seconds_only_for_stable_campaign(tmp_path):
    value = rev3_plan()
    claim = rev3_claim(tmp_path, value)
    _claim(claim)
    ledger = Ledger.create(tmp_path / "ledger")
    ticket = ledger.reserve(envelope(), claim, value, now=1100)
    row = ledger.snapshot()["reservations"][ticket["reservation"]]
    assert row["claim"]["campaignId"] == CAMPAIGN


@pytest.mark.parametrize(
    "campaign,duration,selector",
    [
        ("AUTH-MFA-TOTP-ENROLL-RETRY-01", 1500, SELECTOR),
        (CAMPAIGN, 1501, SELECTOR),
        (CAMPAIGN, 1500, "pending-age-300-v1"),
        (CAMPAIGN, 1500, "unknown-selector"),
        (CAMPAIGN, 1499, SELECTOR),
    ],
)
def test_claim_rejects_invalid_1500_second_exception(
    tmp_path, campaign, duration, selector
):
    value = rev3_plan()
    value["selector"] = selector
    claim = rev3_claim(tmp_path, value, campaign=campaign, duration=duration)
    if duration == 1501 or campaign != CAMPAIGN:
        with pytest.raises(ValueError):
            _claim(claim)
        return
    _claim(claim)
    ledger = Ledger.create(tmp_path / "ledger")
    with pytest.raises(ValueError):
        ledger.reserve(envelope(), claim, value, now=1100)
    assert ledger.snapshot()["reservations"] == {}


def test_claim_and_gate_campaign_ids_must_match_at_reservation(tmp_path):
    value = rev3_plan()
    claim = rev3_claim(tmp_path, value, campaign="AUTH-MFA-TOTP-ENROLL-RETRY-01")
    claim["durationSeconds"] = 1200
    claim["gatePlanDigest"] = digest(value)
    ledger = Ledger.create(tmp_path / "ledger")
    with pytest.raises(ValueError):
        ledger.reserve(envelope(), claim, value, now=1100)


def test_long_claim_cannot_extend_shorter_rev3_gate_wall(tmp_path):
    value = rev3_plan()
    value["wallSeconds"] = 1200
    claim = rev3_claim(tmp_path, value, duration=1500)
    ledger = Ledger.create(tmp_path / "ledger")

    with pytest.raises(ValueError):
        ledger.reserve(envelope(), claim, value, now=1100)

    assert ledger.snapshot()["reservations"] == {}


def test_tampered_gate_plan_digest_is_rejected(tmp_path):
    value = rev3_plan()
    claim = rev3_claim(tmp_path, value)
    claim["gatePlanDigest"] = digest("tampered")
    ledger = Ledger.create(tmp_path / "ledger")
    with pytest.raises(ValueError):
        ledger.reserve(envelope(), claim, value, now=1100)


def test_old_and_rev3_reservations_share_the_stable_task_budget(tmp_path):
    ledger = Ledger.create(tmp_path / "ledger")
    permission = envelope()
    permission["limits"]["costMicrousd"] = 10_000_000
    old_cost = 5_500_000
    value = rev3_plan("old")
    value["costMicrousd"] = old_cost
    value.update(selector="pending-age-300-v1", wallSeconds=1200)
    claim = rev3_claim(tmp_path, value, duration=1200)
    claim["gatePath"] = str((tmp_path / "old-gate").resolve())
    claim["budget"]["costMicrousd"] = old_cost
    ledger.reserve(permission, claim, value, now=1100)

    rev3_cost = 5_000_000
    value = rev3_plan("rev3")
    value["costMicrousd"] = rev3_cost
    claim = rev3_claim(tmp_path, value)
    claim["gatePath"] = str((tmp_path / "rev3-gate").resolve())
    claim["budget"]["costMicrousd"] = rev3_cost
    with pytest.raises(ValueError, match=f"task-budget-exceeded:{CAMPAIGN}"):
        ledger.reserve(permission, claim, value, now=1100)
    assert len(ledger.snapshot()["reservations"]) == 1
