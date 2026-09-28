"""Bounded photoUrl response predicates and secret-free projections."""

import importlib.util
import sys
from pathlib import Path

import pytest


def contract():
    path = Path(__file__).with_name("profile_contract.py")
    assert path.exists(), "Profile observation contract is required"
    spec = importlib.util.spec_from_file_location("profile_contract", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_photo_projection_has_closed_secret_free_partitions():
    c = contract()
    for value, expected in [
        ({}, "absent"),
        ({"photoUrl": None}, "null"),
        ({"photoUrl": ""}, "empty"),
        ({"photoUrl": c.FIRST}, "first"),
        ({"photoUrl": c.SECOND}, "second"),
        ({"photoUrl": "SECRET"}, "other"),
        ({"photoUrl": True}, "invalid-type"),
    ]:
        assert c.photo(value) == expected
        assert "SECRET" not in c.photo(value)


def test_wrong_photo_and_empty_are_mismatches_not_absence():
    c = contract()
    for observed in [
        "absent",
        "null",
        "empty",
        "first",
        "second",
        "other",
        "invalid-type",
    ]:
        row = c.photo_row("set-photo-lookup", 200, observed, True)
        assert row["passed"] is (observed == "first")
        c.validate_case(row, "set-photo-lookup")
        row["passed"] = not row["passed"]
        with pytest.raises(ValueError):
            c.validate_case(row, "set-photo-lookup")
    assert not c.photo_row("deleted-photo-lookup", 200, "empty", True)["passed"]


def test_public_case_rejects_secret_keys_and_status_inconsistency():
    c = contract()
    row = c.photo_row("set-photo", 200, "first", True)
    c.validate_case(row, "set-photo")
    for key in ["idToken", "photoUrl", "rawResponse"]:
        with pytest.raises(ValueError):
            c.validate_case({**row, key: "SECRET"}, "set-photo")
    with pytest.raises(ValueError):
        c.validate_case({**row, "httpStatus": 400}, "set-photo")


def test_complete_rejects_cleanup_or_exit_failures_but_keeps_mismatches():
    c = contract()
    report = {
        "status": "failed",
        "cases": [{"id": name, "passed": False} for name in c.CASES],
        "cleanup": {"uidAbsent": True, "emailAbsent": True},
    }
    assert c.complete(report)
    for key in ["failure", "cleanupFailure", "childCleanupFailure"]:
        assert not c.complete({**report, key: "failure"})
    assert not c.complete({**report, "cleanup": {"emailAbsent": True}})


def test_recovery_preserves_verified_uid_without_trusting_unrelated_record(tmp_path):
    sys.path.insert(0, str(Path(__file__).parent))
    import profile_recorder as recorder

    assert hasattr(recorder, "recovery_identity"), (
        "Recovery must retain ownership-verified UID"
    )
    journal = {
        "project": recorder.PROJECT,
        "email": "fireemu-basic-" + "a" * 32 + "@example.test",
        "marker": "fireemu-owned-" + "b" * 48,
        "creationAttempted": True,
    }
    path = tmp_path / "recovery.json"
    recorder.save(path, journal)
    assert recorder.recovery_identity(path) == (journal, None)
    verified = {**journal, "uid": "owned-uid"}
    recorder.save(tmp_path / "verified-account.json", verified)
    assert recorder.recovery_identity(path) == (journal, "owned-uid")
    # A real second private file must agree with the original journal.
    other = tmp_path / "other"
    other.mkdir()
    recorder.save(other / "recovery.json", journal)
    recorder.save(other / "verified-account.json", {**verified, "marker": "different"})
    with pytest.raises(ValueError):
        recorder.recovery_identity(other / "recovery.json")
