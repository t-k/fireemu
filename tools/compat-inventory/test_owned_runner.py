"""Owned launch boundaries, with an opt-in real fireemu process integration test."""

import os
import subprocess
import sys
from copy import deepcopy
from itertools import product
from pathlib import Path

import pytest
from aggregation_corpus import CONFIG
from owned_runner import (
    child_identity_matches,
    local_addresses,
    observation_complete,
    run_owned,
    sanitized_environment,
    validate_build,
    validate_config,
)


def test_completed_mismatch_is_not_a_failed_launch():
    from aggregation_corpus import corpus

    ids = [case["id"] for case in corpus()["queries"]] + corpus()["stateCases"]
    report = {
        "status": "failed",
        "cases": [{"id": key, "passed": key != "missing-before-limit"} for key in ids],
        "cleanup": [{"confirmedMissing": True}] * 4,
    }
    assert observation_complete(report)
    assert report["status"] == "failed"
    for changed in [
        {"failure": "ValueError"},
        {"status": "inconclusive"},
        {"cases": report["cases"][:-1]},
        {"cleanup": []},
        {"cleanup": [{"confirmedMissing": True}] * 3 + [{"confirmedMissing": False}]},
        {"cases": list(reversed(report["cases"]))},
        {"cases": [{**report["cases"][0], "passed": 1}] + report["cases"][1:]},
        {"status": "passed"},
    ]:
        assert not observation_complete({**report, **changed})


def test_cleanup_only_matches_the_exact_owned_child_command():
    argv = ["/python", "/runner.py", "--owned-child", "/receipt", "--nonce", "abc"]
    assert child_identity_matches(" ".join(argv), argv)
    assert not child_identity_matches(" ".join(argv[:-1] + ["other"]), argv)
    assert not child_identity_matches("/unrelated", argv)


def test_build_receipt_must_bind_the_artifact_and_all_runtime_inputs():
    receipt = {
        "artifactSha256": "a",
        "inputs": {"crates/x.rs": "x"},
        "command": [
            "cargo",
            "build",
            "--locked",
            "-p",
            "fireemu",
            "--message-format=json",
        ],
        "exitCode": 0,
    }
    validate_build(receipt, "a", {"crates/x.rs": "x"})
    for artifact, inputs in [
        ("other", receipt["inputs"]),
        ("a", {"crates/x.rs": "changed"}),
    ]:
        with pytest.raises(ValueError):
            validate_build(receipt, artifact, inputs)


def test_owned_runner_refuses_ambient_configuration_and_remote_endpoints():
    validate_config(CONFIG)
    for extra in [{"profile": "emulator"}, {"firebaseJson": "other.json"}]:
        with pytest.raises(ValueError):
            validate_config({**CONFIG, **extra})
    clean = sanitized_environment(
        {
            "PATH": "/bin",
            "GOOGLE_APPLICATION_CREDENTIALS": "secret",
            "FIREBASE_CONFIG": "wrong",
            "HTTP_PROXY": "proxy",
            "FIREEMU_WORKER_THREADS": "99",
        }
    )
    assert clean == {"PATH": "/bin"}
    assert local_addresses("127.0.0.1:12345", "http://127.0.0.1:23456/v1/") == (
        "http://127.0.0.1:12345",
        "http://127.0.0.1:23456",
    )
    for firestore, control in [
        ("evil.test:123", "http://127.0.0.1:234/v1/"),
        ("127.0.0.1:0", "http://127.0.0.1:234/v1/"),
        ("127.0.0.1:123", "http://127.0.0.1:234/wrong/"),
    ]:
        with pytest.raises(ValueError):
            local_addresses(firestore, control)


@pytest.mark.skipif(
    not os.environ.get("FIREEMU_EVIDENCE_BINARY"),
    reason="requires explicitly built real fireemu artifact",
)
def test_owned_runner_proves_instance_and_stops_the_actual_artifact(tmp_path):
    report = run_owned(Path(os.environ["FIREEMU_EVIDENCE_BINARY"]), tmp_path / "run")
    assert_owned_run_completed(report)


@pytest.mark.skipif(
    not os.environ.get("FIREEMU_EVIDENCE_BINARY"),
    reason="requires explicitly built real fireemu artifact",
)
def test_owned_runner_cli_reports_the_measured_case_count(tmp_path):
    from aggregation_corpus import corpus

    completed = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).with_name("owned_runner.py")),
            "--binary",
            os.environ["FIREEMU_EVIDENCE_BINARY"],
            "--output",
            str(tmp_path / "cli"),
        ],
        text=True,
        capture_output=True,
        check=True,
    )
    count = len(corpus()["queries"]) + len(corpus()["stateCases"])
    assert f"{count} cases" in completed.stdout


def assert_owned_run_completed(report):
    assert report["status"] in {"passed", "failed"}
    assert observation_complete(report)
    assert not any(
        key in report for key in ("failure", "cleanupFailure", "childCleanupFailure")
    )
    assert report["connection"] == "owned-artifact"
    assert report["ownedProcess"]["exitCode"] == 0
    assert report["ownedProcess"]["listenersClosed"] is True
    assert report["ownedProcess"]["stopped"] is True
    assert report["ownedProcess"]["pid"] == report["instance"]["parentPid"]
    assert report["instance"]["wrongTokenStatus"] == 403
    assert report["instance"]["profile"] == "strict"
    assert all(row["confirmedMissing"] for row in report["cleanup"])


@pytest.mark.parametrize("matches", [True, False])
def test_owned_completion_assertions_accept_completed_observations(matches):
    assert_owned_run_completed(completed_report(matches))


def completed_report(matches=True):
    from aggregation_corpus import corpus

    ids = [case["id"] for case in corpus()["queries"]] + corpus()["stateCases"]
    return {
        "connection": "owned-artifact",
        "status": "passed" if matches else "failed",
        "ownedProcess": {
            "pid": 123,
            "exitCode": 0,
            "stopped": True,
            "listenersClosed": True,
        },
        "instance": {"parentPid": 123, "wrongTokenStatus": 403, "profile": "strict"},
        "cases": [{"id": key, "passed": matches} for key in ids],
        "cleanup": [{"confirmedMissing": True} for _ in range(4)],
    }


@pytest.mark.parametrize(
    "section,key,value",
    [
        (None, "status", "owned-run-failed"),
        (None, "failure", ""),
        (None, "cleanupFailure", ""),
        (None, "childCleanupFailure", ""),
        (None, "cleanup", []),
        ("ownedProcess", "exitCode", 2),
        ("ownedProcess", "listenersClosed", False),
        ("ownedProcess", "stopped", False),
        ("ownedProcess", "pid", 456),
        ("instance", "wrongTokenStatus", 200),
        ("instance", "profile", "emulator"),
    ],
)
def test_owned_completion_assertions_reject_lifecycle_failures(section, key, value):
    report = deepcopy(completed_report())
    (report if section is None else report[section])[key] = value
    with pytest.raises(AssertionError):
        assert_owned_run_completed(report)


def test_bounded_lifecycle_state_space_keeps_semantic_mismatch_separate():
    for matches, exited, stopped, closed, cleaned, failure in product(
        [False, True],
        [False, True],
        [False, True],
        [False, True],
        [False, True],
        [None, "failure", "cleanupFailure", "childCleanupFailure"],
    ):
        report = completed_report(matches)
        report["ownedProcess"].update(
            exitCode=0 if exited else 2, stopped=stopped, listenersClosed=closed
        )
        if not cleaned:
            report["cleanup"] = []
        if failure is not None:
            report[failure] = ""
        expected = exited and stopped and closed and cleaned and failure is None
        if expected:
            assert_owned_run_completed(report)
        else:
            with pytest.raises(AssertionError):
                assert_owned_run_completed(report)
