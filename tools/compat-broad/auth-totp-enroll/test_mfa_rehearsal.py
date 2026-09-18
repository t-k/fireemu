"""Cleanup and failure rehearsals for the collector and the local shadow.

These drive the real cleanup contract through the same code the campaign would use,
without starting an emulator or touching a network.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from mfa_cases import CASE_IDS, observation_cases
from mfa_collector import (
    checkpoint_bytes,
    cleanup_complete,
    initial_state,
    load_checkpoint,
    mark_deleted,
    next_action,
    record_step,
    register_owned,
    run_complete,
)
from mfa_comparator import compare
from mfa_local_shadow import CONFIG, PHONE_SIGN_IN_INFO, Instance, _code_of
from mfa_manifest import compile_campaign
from mfa_provenance import compute_provenance, repository_root

NONCE = "fedcba9876543210fedcba9876543210"
ORIGIN = 1_700_000_000.0


def test_a_run_that_dies_mid_flight_resumes_from_its_checkpoint(tmp_path: Path) -> None:
    state = initial_state(compile_campaign(NONCE), ORIGIN)
    register_owned(state, "account", "uid-aged", ORIGIN)
    record_step(
        state, CASE_IDS[0], {"status": 200}, ORIGIN, schedule={CASE_IDS[1]: ORIGIN + 600.0}
    )
    checkpoint = tmp_path / "checkpoint.json"
    checkpoint.write_bytes(checkpoint_bytes(state))
    del state

    # A fresh process, minutes later, reads only the file.
    resumed = load_checkpoint(checkpoint.read_bytes())
    waiting = next_action(resumed, ORIGIN + 120)
    assert waiting["action"] == "WAIT" and waiting["stepId"] == CASE_IDS[1]
    assert next_action(resumed, ORIGIN + 600.0)["action"] == "RUN"
    assert resumed["ownedResources"][0]["id"] == "uid-aged"


def test_an_abandoned_run_still_names_every_resource_it_must_delete(tmp_path: Path) -> None:
    state = initial_state(compile_campaign(NONCE), ORIGIN)
    for index in range(3):
        register_owned(state, "account", f"uid-{index}", ORIGIN)
    checkpoint = tmp_path / "checkpoint.json"
    checkpoint.write_bytes(checkpoint_bytes(state))
    recovered = load_checkpoint(checkpoint.read_bytes())
    action = next_action(recovered, recovered["deadline"] + 1)
    assert action["action"] == "CLEANUP"
    assert action["outstanding"] == ["uid-0", "uid-1", "uid-2"]
    for index in range(3):
        mark_deleted(recovered, f"uid-{index}", absence_verified=True)
    assert cleanup_complete(recovered) is True
    # Cleanup completing does not turn an aborted run into a complete one.
    assert run_complete(recovered) is False


def test_a_half_deleted_run_cannot_report_a_clean_recovery() -> None:
    state = initial_state(compile_campaign(NONCE), ORIGIN)
    register_owned(state, "account", "uid-kept", ORIGIN)
    register_owned(state, "account", "uid-gone", ORIGIN)
    mark_deleted(state, "uid-gone", absence_verified=True)
    assert cleanup_complete(state) is False
    receipt = {
        "campaignId": compile_campaign(NONCE)["campaignId"],
        "side": "local",
        "recordingComplete": True,
        "productionExecuted": False,
        "provenance": compute_provenance(repository_root()),
        "worktree": {"commit": "a" * 40, "clean": True, "resolved": True},
        "rows": [
            {"id": identifier, "status": 200, "errorCode": None, "outcome": "observed"}
            for identifier in CASE_IDS
        ],
        "recovery": {
            "cleanupVerified": False,
            "remainingOwnedResources": len(
                [item for item in state["ownedResources"] if not item["deleted"]]
            ),
            "configurationRestored": True,
        },
    }
    result = compare(receipt, json.loads(json.dumps(receipt)) | {"side": "production"})
    assert result["classification"] == "INDETERMINATE"
    assert "cleanup was not verified" in result["localProblems"]
    assert "owned resources remain" in result["localProblems"]


def test_the_shadow_configuration_enables_totp_and_stays_strict() -> None:
    assert CONFIG["profile"] == "strict"
    assert CONFIG["auth"]["totp"] == {}
    assert "recaptchaToken" in PHONE_SIGN_IN_INFO


def test_the_shadow_only_addresses_loopback() -> None:
    instance = Instance("http://127.0.0.1:9099", "http://127.0.0.1:9099/v1/", "token")
    assert instance.control == "http://127.0.0.1:9099"
    assert instance.identity.startswith("http://127.0.0.1:9099/")
    with pytest.raises(ValueError, match="loopback"):
        Instance("https://identitytoolkit.googleapis.com", "http://127.0.0.1:9099/v1/", "t").public(
            "/v1/accounts:signUp", {}
        )


def test_the_error_code_projection_keeps_only_the_canonical_prefix() -> None:
    assert _code_of({"error": {"message": "INVALID_CODE : verification code already used"}}) == (
        "INVALID_CODE"
    )
    assert _code_of({"error": {"message": "SESSION_EXPIRED"}}) == "SESSION_EXPIRED"
    assert _code_of({}) is None


def test_a_ledger_missing_a_case_is_refused_rather_than_published() -> None:
    from mfa_local_shadow import build_report

    state = initial_state(compile_campaign(NONCE), ORIGIN)
    rows = {
        case["id"]: {"id": case["id"], "status": 200, "errorCode": None, "outcome": "observed"}
        for case in observation_cases()
    }
    report = build_report(rows, state)
    assert report["side"] == "local" and report["productionExecuted"] is False
    assert [row["id"] for row in report["rows"]] == list(CASE_IDS)
    assert report["recordingComplete"] is False
    rows.pop(CASE_IDS[5])
    with pytest.raises(RuntimeError, match=CASE_IDS[5]):
        build_report(rows, state)
