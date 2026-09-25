"""The checked-in campaign package and its local shadow evidence stay honest."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from action_codes_plan import (
    CAMPAIGN_ID,
    CONTRACT,
    STAGE_IDS,
    proposal,
    validate_proposal,
)

ROOT = Path(__file__).resolve().parents[3]
MANIFEST = ROOT / "spec/compatibility/broad-runs/auth-action-codes-oob-boundary-01.json"
SHADOW = (
    ROOT
    / "spec/compatibility/broad-runs/auth-action-codes-oob-boundary-01-local-shadow.json"
)
REHEARSAL = ROOT / (
    "spec/compatibility/broad-runs/"
    "auth-action-codes-oob-boundary-01-local-shadow-rehearsal.json"
)


def test_the_checked_in_manifest_is_retained_old_proposal_and_rejected_as_stale() -> None:
    value = json.loads(MANIFEST.read_bytes())
    assert value["planTemplate"]["budget"]["recoveryRequests"] == 4
    with pytest.raises(ValueError, match="drift"):
        validate_proposal(value)
    assert MANIFEST.read_text().endswith("}\n")


def test_the_local_shadow_evidence_claims_no_production_observation() -> None:
    evidence = json.loads(SHADOW.read_bytes())
    assert evidence["campaignId"] == CAMPAIGN_ID
    assert evidence["contract"] == CONTRACT
    assert evidence["productionExecuted"] is False
    assert evidence["productionObserved"] == "none"
    assert evidence["boundary"]["promotion"] == "AUTH-ACTION remains WAITING_ORACLE"
    assert evidence["artifact"]["builtFromSourceCommit"] is None
    assert evidence["artifact"]["binding"] == "unbound"
    assert evidence["artifact"]["provenance"] == "retained-external"


def test_the_local_shadow_recorded_every_stage_and_recovered() -> None:
    evidence = json.loads(SHADOW.read_bytes())
    observation = evidence["observation"]
    assert observation["recordingComplete"] is True
    assert observation["cleanupComplete"] is True
    assert observation["remainingAccounts"] == 0
    assert observation["stagesRecorded"] == len(STAGE_IDS)
    assert observation["observationRequests"] == len(STAGE_IDS)
    # A skipped delete costs no request, so recovery stays inside its reserve.
    assert observation["recoveryRequests"] == 3
    assert observation["absenceProven"] is True
    # A clean run collects no delete failure, so a verdict stays reachable.
    assert observation["deleteFailures"] == 0
    assert observation["deliveredMessages"] == 0
    assert evidence["recovery"][0]["id"] == "recover-discover"
    # Account B is deleted by a stage, so recovery never asks for it again.
    deleted_b = next(
        row for row in evidence["recovery"] if row["id"] == "recover-delete-accountB"
    )
    assert deleted_b["skipped"] == "absent at discovery"
    assert evidence["recovery"][-1]["presentAddresses"] == 0
    assert [row["id"] for row in evidence["localStages"]] == list(STAGE_IDS)
    assert evidence["ownedProcess"] == {
        "exitCode": 0,
        "stopped": True,
        "listenersClosed": True,
    }


def test_the_committed_rehearsal_shows_recovery_after_an_injected_failure() -> None:
    evidence = json.loads(REHEARSAL.read_bytes())
    observation = evidence["observation"]
    assert evidence["rehearsal"].startswith("transport failure injected")
    assert observation["stopReason"] == "stage-failed:email-link-signin"
    assert observation["recordingComplete"] is False
    assert observation["stagesRecorded"] == 18
    # The point of the rehearsal: an interrupted run still owns nothing after it.
    assert observation["cleanupComplete"] is True
    assert observation["absenceProven"] is True
    assert observation["remainingAccounts"] == 0
    assert evidence["recovery"][-1]["presentAddresses"] == 0
    assert evidence["ownedProcess"] == {
        "exitCode": 0,
        "stopped": True,
        "listenersClosed": True,
    }


def test_neither_committed_receipt_claims_provenance_it_lacks() -> None:
    for path in (SHADOW, REHEARSAL):
        evidence = json.loads(path.read_bytes())
        assert evidence["receiptSourceBinding"]["binding"] == "unbound"
        assert evidence["receiptSourceBinding"]["builtFromSourceCommit"] is None
        assert evidence["artifact"]["binding"] == "unbound"
        assert evidence["artifact"]["provenance"] == "retained-external"
        assert evidence["productionExecuted"] is False


def test_no_evidence_file_carries_a_secret_value() -> None:
    # A secret name may only introduce a `$binding:` placeholder or a plan
    # expectation, never a value a run produced.
    for path in (MANIFEST, SHADOW, REHEARSAL):
        value = json.loads(path.read_bytes())
        for field, holder in _secret_slots(value):
            assert isinstance(holder, str) and holder.startswith("$binding:"), field


def _secret_slots(value, path="$"):
    fields = (
        "oobCode",
        "oobLink",
        "idToken",
        "refreshToken",
        "passwordHash",
        "password",
    )
    if isinstance(value, dict):
        for key, item in value.items():
            if key in fields:
                yield path + "." + key, item
            else:
                yield from _secret_slots(item, path + "." + key)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _secret_slots(item, f"{path}[{index}]")
