import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))

import shared_gate
from rev3_gate import JOB, compile_gate_plan
from rev3_projection import CAMPAIGN_ID, CASES_SHA256, SELECTOR
from window_contract import CASES

NONCE = "0123456789abcdef0123456789abcdef"
ROLES = ("baseline", "age-300", "age-450", "age-600", "final")
AGES = (300, 450, 600)


def expected_observation_slots():
    result = [
        f"setup:{role}:{step}"
        for role in ROLES
        for step in (
            "email-absence",
            "sign-up",
            "email-readback",
            "enable-mfa",
            "state-readback",
        )
    ]
    result += [
        f"baseline:{step}"
        for step in ("pending", "start", "finalize", "derived-lookup")
    ]
    result += [f"age-{age}:held-pending" for age in AGES]
    result += [
        f"age-{age}:{step}"
        for age in AGES
        for step in (
            "start",
            "finalize",
            "derived-lookup",
            "post-refusal-state",
            "post-refusal-fresh-pending",
            "post-refusal-fresh-start",
            "post-refusal-fresh-finalize",
            "post-refusal-fresh-derived-lookup",
        )
    ]
    result += [
        f"final:{step}" for step in ("pending", "start", "finalize", "derived-lookup")
    ]
    return result


def expected_recovery_slots():
    return [
        f"recovery:{role}:{step}"
        for role in ROLES
        for step in (
            "address-reconcile",
            "uid-reconcile",
            "delete",
            "address-absence",
            "uid-absence",
        )
    ]


def test_revision_three_gate_plan_freezes_rows_accounts_and_every_slot(tmp_path):
    plan = compile_gate_plan(NONCE)
    job = plan["jobs"][JOB]

    assert plan["campaignId"] == CAMPAIGN_ID
    assert plan["selector"] == SELECTOR
    assert plan["caseIds"] == list(CASES)
    assert plan["caseDigest"] == CASES_SHA256
    assert plan["wallSeconds"] == 1500
    assert plan["recoverySeconds"] == 300
    assert plan["maxObservationSeconds"] == 1200
    assert plan["maxAccounts"] == 5
    assert len(job["observation"]) == 60
    assert len(job["recovery"]) == 25
    assert [
        slot["slotId"] for slot in job["observation"]
    ] == expected_observation_slots()
    assert [slot["slotId"] for slot in job["recovery"]] == expected_recovery_slots()
    observation = {slot["slotId"]: slot for slot in job["observation"]}
    assert observation["age-300:finalize"]["skipWhen"] == (
        "aged-start-refused-or-session-missing"
    )
    assert observation["age-300:derived-lookup"]["skipWhen"] == (
        "aged-finalize-not-accepted"
    )
    assert observation["age-300:post-refusal-state"]["skipWhen"] == (
        "aged-attempt-not-refused"
    )
    for slot_id in (
        "age-300:post-refusal-state",
        "age-300:post-refusal-fresh-pending",
        "age-300:post-refusal-fresh-start",
        "age-300:post-refusal-fresh-finalize",
        "age-300:post-refusal-fresh-derived-lookup",
    ):
        assert "aged-attempt-not-refused" in observation[slot_id]["skipWhen"]
    assert observation["age-300:post-refusal-fresh-pending"]["skipWhen"] == (
        "aged-attempt-not-refused-or-state-readback-failed"
    )
    assert observation["age-300:post-refusal-fresh-start"]["skipWhen"] == (
        "aged-attempt-not-refused-or-state-readback-failed"
    )
    assert observation["age-300:post-refusal-fresh-finalize"]["skipWhen"] == (
        "aged-attempt-not-refused-or-state-readback-failed-or-"
        "fresh-start-refused-or-session-missing"
    )
    assert observation["age-300:post-refusal-fresh-derived-lookup"]["skipWhen"] == (
        "aged-attempt-not-refused-or-state-readback-failed-or-"
        "fresh-start-refused-or-session-missing-or-fresh-finalize-not-accepted"
    )
    assert plan["observationRequests"] == 66
    assert plan["dataRequests"] == 85
    assert plan["managementRequests"] == 8
    assert len(plan["plannedAccounts"]) == len(job["accountBindings"]) == 5
    assert all(NONCE in resource for resource in job["resources"])

    gate_path = tmp_path / "gate"
    shared_gate.create(gate_path, plan)
    assert json.loads((gate_path / "state.json").read_bytes())["plan"] == plan


@pytest.mark.parametrize(
    "changes",
    [
        {"selector": "pending-age-300-v1"},
        {"selector": "unknown"},
        {"campaign_id": "OTHER-TASK"},
        {"wall_seconds": 1501},
        {"recovery_seconds": 299},
        {"max_observation_seconds": 1201},
    ],
)
def test_revision_three_gate_plan_rejects_scope_or_window_drift(changes):
    with pytest.raises(ValueError):
        compile_gate_plan(NONCE, **changes)


@pytest.mark.parametrize("cases", [CASES[:-1], tuple(reversed(CASES))])
def test_revision_three_gate_plan_rejects_case_drift(cases):
    with pytest.raises(ValueError):
        compile_gate_plan(NONCE, cases=cases)
