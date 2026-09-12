"""Offline readiness contracts; fixtures never constitute production observations."""

import copy

import pytest


def database():
    return {
        "name": "projects/fireemu-35fe6/databases/(default)",
        "uid": "fixture-database-uid",
        "databaseEdition": "STANDARD",
        "type": "FIRESTORE_NATIVE",
        "locationId": "us-central1",
        "concurrencyMode": "PESSIMISTIC",
        "pointInTimeRecoveryEnablement": "POINT_IN_TIME_RECOVERY_DISABLED",
        "versionRetentionPeriod": "3600s",
        "earliestVersionTime": "2026-09-12T00:00:00Z",
        "deleteProtectionState": "DELETE_PROTECTION_ENABLED",
    }


def test_database_acquisition_and_settings_hashes_are_separate():
    import batch_contract as c

    assert hasattr(c, "database_evidence"), "versioned settings projection required"
    before = c.database_evidence(database())
    after = c.database_evidence(
        {**database(), "earliestVersionTime": "2026-09-12T00:01:00Z"}
    )
    assert before["responseDigest"] != after["responseDigest"]
    assert before["projectionDigest"] == after["projectionDigest"]
    assert before["contract"] == after["contract"]
    assert before["contractDigest"] == c.digest(before["contract"])
    assert "earliestVersionTime" not in before["projection"]
    for key in [
        "uid",
        "databaseEdition",
        "locationId",
        "concurrencyMode",
        "pointInTimeRecoveryEnablement",
        "deleteProtectionState",
    ]:
        changed = c.database_evidence({**database(), key: "different"})
        assert changed["projectionDigest"] != before["projectionDigest"]
    for key in ["uid", "databaseEdition", "locationId"]:
        missing = database()
        del missing[key]
        with pytest.raises(ValueError):
            c.database_evidence(missing)


def test_incomplete_mapping_report_cannot_pass():
    import json

    from batch_comparison import compare
    from broad_contract import ROOT

    batch = json.loads(
        (ROOT / "spec/compatibility/broad-runs/0a7a55ce-mapped-batch.json").read_bytes()
    )["batch"]
    baseline = json.loads(
        (ROOT / "spec/compatibility/broad-runs/bf12f631-expanded.json").read_bytes()
    )
    for changes in [
        {"completed": False},
        {"failure": "Timeout"},
        {"unrecovered": [{"kind": "document"}]},
    ]:
        with pytest.raises(ValueError, match="incomplete"):
            compare({**batch, **changes}, baseline)


def test_recording_status_is_independent_of_observed_mismatch():
    import batch_contract as c

    assert hasattr(c, "recording_exit_code"), "explicit recording exit status required"
    complete = {
        "completed": True,
        "failure": None,
        "unrecovered": [],
        "rows": [{"status": "fail"}],
    }
    assert c.recording_exit_code(complete) == 0
    assert c.recording_exit_code({**complete, "completed": False}) != 0
    assert c.recording_exit_code({**complete, "unrecovered": ["owned"]}) != 0


def test_mapping_cli_report_check_and_incomplete_exit_codes(tmp_path):
    import json
    import subprocess
    import sys

    from broad_contract import ROOT

    original = json.loads(
        (ROOT / "spec/compatibility/broad-runs/0a7a55ce-mapped-batch.json").read_bytes()
    )["batch"]
    baseline = ROOT / "spec/compatibility/broad-runs/bf12f631-expanded.json"
    changed = copy.deepcopy(original)
    next(row for row in changed["rows"] if row["id"].startswith("auth:"))["status"] = (
        "fail"
    )
    for name, report, check, expected in [
        ("mismatch-report", changed, False, 0),
        ("mismatch-check", changed, True, 1),
        ("incomplete", {**original, "completed": False}, False, 1),
    ]:
        source = tmp_path / (name + ".json")
        source.write_text(json.dumps(report))
        command = [
            sys.executable,
            str(ROOT / "tools/compat-broad/batch_comparison.py"),
            "--batch",
            str(source),
            "--baseline",
            str(baseline),
            "--output",
            str(tmp_path / (name + "-out.json")),
        ]
        if check:
            command.append("--check")
        run = subprocess.run(
            command, capture_output=True, text=True, timeout=10, check=False
        )
        assert (run.returncode == 0) == (expected == 0), run.stderr


def test_wrapper_failure_propagation_and_successful_mismatch_recording():
    from batch_contract import wrapper_exit_code

    good = {
        "exitCode": 0,
        "ownedProcess": {"stopped": True, "listenersClosed": True},
        "batch": {
            "completed": True,
            "failure": None,
            "unrecovered": [],
            "rows": [{"status": "fail"}],
        },
    }
    assert wrapper_exit_code(good) == 0
    for change in [
        {"exitCode": 1},
        {"ownedProcess": {"stopped": False, "listenersClosed": True}},
        {"cleanupFailure": "error"},
        {"batch": {"completed": False}},
    ]:
        assert wrapper_exit_code({**good, **change}) != 0
