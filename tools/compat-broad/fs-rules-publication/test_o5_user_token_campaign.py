from __future__ import annotations

import copy

import pytest
from o5_user_token_campaign import (
    CAMPAIGN_CONTRACT,
    admission,
    manifest,
    validate_manifest,
)

PROJECT = "fireemu-35fe6"
NONCE = "c" * 32


def value() -> dict:
    return manifest(PROJECT, "(default)", NONCE)


def test_manifest_is_preparation_only() -> None:
    entry = value()
    validate_manifest(entry)
    assert entry["contract"] == CAMPAIGN_CONTRACT
    assert entry["status"] == "PREPARATION_ONLY"
    assert entry["productionExecuted"] is False
    assert entry["productionReady"] is False


def test_frozen_inputs_bind_the_case_and_the_lane_sources() -> None:
    entry = value()
    frozen = entry["frozenInputs"]
    assert frozen["caseDigest"] == entry["observationCase"]["planDigest"]
    assert set(frozen["rulesetDigests"]) == {"A", "B"}
    assert frozen["rulesetDigests"]["A"] != frozen["rulesetDigests"]["B"]
    for name, value_digest in frozen["sources"].items():
        assert name.startswith("o5_user_token_")
        assert len(value_digest) == 64


def test_budget_is_bounded_and_well_under_the_cost_ceiling() -> None:
    entry = value()
    budget = entry["budget"]
    assert budget["concurrencyUpperBound"] == 1
    assert budget["observationRequests"] == len(entry["observationCase"]["observation"])
    assert budget["requestUpperBound"] < 200
    assert budget["estimatedCostUsd"] < 0.01
    assert budget["costCeilingUsd"] == 1.0
    assert budget["wallClockDeadlineSeconds"] == 600.0


def test_permission_envelope_names_its_scope_and_its_refusals() -> None:
    envelope = value()["permissionEnvelope"]
    assert envelope["concurrency"] == 1
    assert "firestore.googleapis.com" in envelope["services"]
    assert "identitytoolkit.googleapis.com" in envelope["services"]
    assert any("outside the nonce subtree" in entry for entry in envelope["forbidden"])
    assert any("preexisting Auth account" in entry for entry in envelope["forbidden"])


def test_owner_preconditions_include_the_ruleset_and_recovery_owner() -> None:
    entry = value()
    joined = " ".join(entry["ownerPreconditions"])
    assert "Ruleset" in joined
    assert "recovery owner" in joined
    assert "tenant" in joined
    assert "nonce" in joined


def test_admission_is_closed() -> None:
    entry = value()
    gate = admission(entry)
    assert gate["productionReady"] is False
    assert "owner-permission" in gate["blockers"]
    with pytest.raises(PermissionError):
        gate["admit"]()


@pytest.mark.parametrize(
    "mutation",
    ["status", "ready", "budget", "contract", "case", "digest"],
)
def test_manifest_drift_rejected(mutation) -> None:
    entry = copy.deepcopy(value())
    if mutation == "status":
        entry["status"] = "READY"
    elif mutation == "ready":
        entry["productionReady"] = True
    elif mutation == "budget":
        entry["budget"]["costCeilingUsd"] = 1000.0
    elif mutation == "contract":
        entry["contract"] = "other"
    elif mutation == "case":
        entry["observationCase"] = None
    else:
        entry["manifestDigest"] = "0" * 64
    with pytest.raises((TypeError, ValueError)):
        validate_manifest(entry)


def test_admission_refuses_a_drifted_manifest() -> None:
    entry = copy.deepcopy(value())
    entry["productionReady"] = True
    with pytest.raises(ValueError):
        admission(entry)
