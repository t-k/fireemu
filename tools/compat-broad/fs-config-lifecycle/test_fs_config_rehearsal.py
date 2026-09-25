from __future__ import annotations

import pytest
from fs_config_lifecycle.rehearsal import (
    ABORTED_RESTORED,
    ABORTED_UNRECOVERED,
    CLEAN,
    FAILURES,
    rehearse,
)

NONCE = "a1b2c3d4e5f60718293a4b5c6d7e8f90"


def test_an_unknown_failure_injection_is_refused() -> None:
    with pytest.raises(ValueError):
        rehearse(NONCE, "disk-full")


def test_no_rehearsal_issues_a_request_or_claims_an_execution() -> None:
    for failure in FAILURES:
        result = rehearse(NONCE, failure)
        assert result["requestsIssued"] == 0
        assert result["productionExecuted"] is False
        assert result["status"] == "PREPARATION_ONLY"


def test_the_happy_path_restores_every_owned_field_and_exits_zero() -> None:
    result = rehearse(NONCE)
    assert result["outcome"] == CLEAN
    assert result["exitCode"] == 0
    assert result["unrecovered"] == []
    assert len(result["ledger"]) == 2
    assert all(entry["recovered"] for entry in result["ledger"])
    assert result["steps"][-1] == "write-final-ledger"
    assert result["ledgerReservation"] == "release-eligible"


def test_projection_drift_aborts_before_any_mutation() -> None:
    result = rehearse(NONCE, "precondition-projection-drift")
    assert result["outcome"] == ABORTED_RESTORED
    assert result["exitCode"] == 1
    assert result["ledger"] == []
    assert "abort-before-any-mutation" in result["steps"]
    assert "patch-ttl" not in result["steps"]


def test_no_rehearsal_creates_or_deletes_a_database() -> None:
    for failure in FAILURES:
        text = " ".join(rehearse(NONCE, failure)["steps"])
        assert "create" not in text
        assert "delete" not in text


def test_an_operation_deadline_runs_recovery_instead_of_continuing() -> None:
    result = rehearse(NONCE, "operation-deadline")
    assert result["outcome"] == ABORTED_RESTORED
    assert result["exitCode"] == 1
    assert "abort-and-run-recovery" in result["steps"]
    assert "revert-ttl" in result["steps"]
    assert "patch-exemption" not in result["steps"]
    assert result["unrecovered"] == []
    assert result["ledgerReservation"] == "held-restored"


def test_a_stop_after_the_ttl_patch_reverts_only_the_ttl_field() -> None:
    result = rehearse(NONCE, "stop-after-ttl-patch")
    assert result["resumedFromCheckpoint"] is True
    assert "resume-from-checkpoint" in result["steps"]
    assert "revert-ttl" in result["steps"]
    assert "revert-exemption" not in result["steps"]
    assert [entry["createdBy"] for entry in result["ledger"]] == ["OC-14"]
    assert result["unrecovered"] == []
    assert result["exitCode"] == 1


def test_an_exhausted_observation_wall_leaves_the_recovery_reserve_for_the_revert() -> (
    None
):
    result = rehearse(NONCE, "wall-exhausted")
    assert result["outcome"] == ABORTED_RESTORED
    steps = result["steps"]
    assert steps.index("observation-wall-exhausted") < steps.index("revert-ttl")
    assert result["unrecovered"] == []


def test_a_refused_revert_is_reported_as_unrecovered_and_holds_the_reservation() -> (
    None
):
    result = rehearse(NONCE, "revert-refused")
    assert result["outcome"] == ABORTED_UNRECOVERED
    assert result["exitCode"] == 1
    assert len(result["unrecovered"]) == 1
    assert result["unrecovered"][0]["kind"] == "fieldConfig"
    assert result["unrecovered"][0]["createdBy"] == "OC-14"
    assert "report-unrecovered-resource" in result["steps"]
    assert result["ledgerReservation"] == "held-unrecovered"


def test_a_credential_refusal_still_attempts_the_revert_and_reports_it() -> None:
    result = rehearse(NONCE, "credential-refused")
    assert result["outcome"] == ABORTED_UNRECOVERED
    assert "attempt-revert-ttl" in result["steps"]
    assert "revert-refused" in result["steps"]
    assert result["ledgerReservation"] == "held-unrecovered"


def test_a_refused_patch_needs_no_revert_and_the_run_continues() -> None:
    result = rehearse(NONCE, "patch-refused")
    assert result["outcome"] == CLEAN
    assert result["refusedApplies"] == ["patch-exemption"]
    assert [entry["createdBy"] for entry in result["ledger"]] == ["OC-14"]
    assert "revert-exemption" not in result["steps"]
    assert result["steps"][-1] == "write-final-ledger"


def test_only_the_clean_outcome_ever_exits_zero() -> None:
    for failure in FAILURES:
        result = rehearse(NONCE, failure)
        assert (result["exitCode"] == 0) == (result["outcome"] == CLEAN)
        if result["unrecovered"]:
            assert result["outcome"] == ABORTED_UNRECOVERED
            assert result["ledgerReservation"] == "held-unrecovered"


def test_the_rehearsal_never_leaks_the_nonce_itself() -> None:
    for failure in FAILURES:
        result = rehearse(NONCE, failure)
        assert result["nonceLength"] == 32
        assert NONCE not in str(result["steps"])


def test_a_reconciliation_mismatch_is_reported_as_an_unrecovered_resource() -> None:
    result = rehearse(NONCE, "reconciliation-mismatch")
    assert result["outcome"] == ABORTED_UNRECOVERED
    assert result["exitCode"] == 1
    assert result["unrecovered"]
    assert result["unrecovered"][0]["foundBy"] == "reconcile-field-listings"


def test_every_clean_run_reconciles_before_writing_the_final_ledger() -> None:
    result = rehearse(NONCE)
    steps = result["steps"]
    assert steps.index("reconcile-field-listings") < steps.index("write-final-ledger")
    assert steps.index("reconcile-database-enumeration") == len(steps) - 2
