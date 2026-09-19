from __future__ import annotations

import pytest
from fs_config_lifecycle.rehearsal import (
    ABORTED_RECOVERED,
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


def test_the_happy_path_recovers_every_owned_resource_and_exits_zero() -> None:
    result = rehearse(NONCE)
    assert result["outcome"] == CLEAN
    assert result["exitCode"] == 0
    assert result["unrecovered"] == []
    assert all(entry["recovered"] for entry in result["ledger"])
    assert result["steps"][-1] == "write-final-ledger"


def test_a_failed_precondition_aborts_before_any_resource_exists() -> None:
    result = rehearse(NONCE, "precondition-unexpected-database")
    assert result["outcome"] == ABORTED_RECOVERED
    assert result["exitCode"] == 1
    assert result["ledger"] == []
    assert "abort-before-any-mutation" in result["steps"]
    assert "create-owned-database" not in result["steps"]


def test_a_refused_create_is_recorded_and_never_retried() -> None:
    result = rehearse(NONCE, "create-refused")
    assert result["outcome"] == ABORTED_RECOVERED
    assert "abort-without-retry" in result["steps"]
    assert result["steps"].count("attempt-create") == 1


def test_an_operation_deadline_runs_cleanup_instead_of_continuing() -> None:
    result = rehearse(NONCE, "operation-deadline")
    assert result["outcome"] == ABORTED_RECOVERED
    assert result["exitCode"] == 1
    assert "abort-and-run-cleanup" in result["steps"]
    assert "verify-database-absence" in result["steps"]
    assert "patch-field-configurations" not in result["steps"]
    assert result["unrecovered"] == []


def test_an_interrupted_run_resumes_from_the_checkpoint_and_still_deletes() -> None:
    result = rehearse(NONCE, "interrupt-after-create")
    assert result["resumedFromCheckpoint"] is True
    assert "resume-from-checkpoint" in result["steps"]
    assert "delete-created-database" in result["steps"]
    assert result["unrecovered"] == []
    assert result["exitCode"] == 1


def test_a_refused_revert_is_reported_as_unrecovered_and_fails_the_run() -> None:
    result = rehearse(NONCE, "revert-refused")
    assert result["outcome"] == ABORTED_UNRECOVERED
    assert result["exitCode"] == 1
    assert len(result["unrecovered"]) == 1
    assert result["unrecovered"][0]["kind"] == "fieldConfig"
    assert "report-unrecovered-resource" in result["steps"]
    database = next(e for e in result["ledger"] if e["kind"] == "database")
    assert database["recovered"] is True


def test_only_the_clean_outcome_ever_exits_zero() -> None:
    for failure in FAILURES:
        result = rehearse(NONCE, failure)
        assert (result["exitCode"] == 0) == (result["outcome"] == CLEAN)
        if result["unrecovered"]:
            assert result["outcome"] == ABORTED_UNRECOVERED


def test_the_rehearsal_never_leaks_the_nonce_itself() -> None:
    for failure in FAILURES:
        result = rehearse(NONCE, failure)
        assert result["nonceLength"] == 32
        assert NONCE not in str(result["steps"])


def test_an_unexpectedly_accepted_negative_create_is_recovered_not_ignored() -> None:
    result = rehearse(NONCE, "negative-create-accepted")
    assert result["outcome"] == ABORTED_RECOVERED
    assert result["exitCode"] == 1
    assert "delete-unexpectedly-created-database" in result["steps"]
    assert "reconcile-database-enumeration" in result["steps"]
    assert result["unrecovered"] == []
    conditional = [entry for entry in result["ledger"] if entry["conditional"]]
    assert len(conditional) == 1
    assert conditional[0]["recovered"] is True


def test_a_reconciliation_mismatch_is_reported_as_an_unrecovered_resource() -> None:
    result = rehearse(NONCE, "reconciliation-mismatch")
    assert result["outcome"] == ABORTED_UNRECOVERED
    assert result["exitCode"] == 1
    assert result["unrecovered"]
    assert "reconcile-database-enumeration" in result["steps"]


def test_every_clean_run_reconciles_the_enumeration_before_finishing() -> None:
    result = rehearse(NONCE)
    assert "reconcile-database-enumeration" in result["steps"]
    assert result["steps"].index("reconcile-database-enumeration") == (
        len(result["steps"]) - 2
    )
