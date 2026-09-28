"""Owned launch boundaries, with an opt-in real fireemu process integration test."""

import os
import shutil
import subprocess
import sys
import time
import uuid
from copy import deepcopy
from itertools import product
from pathlib import Path

import pytest
import owned_runner
from aggregation_corpus import CONFIG
from owned_runner import (
    BUILD_TIMEOUT_VARIABLE,
    DEFAULT_BUILD_TIMEOUT_SECONDS,
    artifact_binding,
    build_timeout,
    child_identity_matches,
    copy_verified_artifact,
    local_addresses,
    open_verified_artifact,
    observation_complete,
    run_build,
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


def test_artifact_binding_rejects_launch_copy_substitution(tmp_path):
    source = tmp_path / "source-fireemu"
    launch = tmp_path / "launch-fireemu"
    source.write_bytes(b"source")
    launch.write_bytes(b"different")
    receipt = {
        "artifactSha256": __import__("hashlib").sha256(b"source").hexdigest(),
        "inputs": {"crates/x.rs": "x"},
        "command": ["cargo", "build", "--locked", "-p", "fireemu", "--message-format=json"],
        "exitCode": 0,
    }
    with pytest.raises(ValueError, match="launch copy mismatch"):
        artifact_binding(source, launch, receipt, {"crates/x.rs": "x"})


def test_artifact_binding_rejects_hardlinked_launch_copy(tmp_path):
    source = tmp_path / "source-fireemu"
    launch = tmp_path / "launch-fireemu"
    source.write_bytes(b"source")
    launch.hardlink_to(source)
    receipt = {
        "artifactSha256": __import__("hashlib").sha256(b"source").hexdigest(),
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
    with pytest.raises(ValueError, match="hardlink"):
        artifact_binding(source, launch, receipt, {"crates/x.rs": "x"})


def test_artifact_binding_rejects_parent_directory_symlink_alias(tmp_path):
    source = tmp_path / "source-fireemu"
    real_directory = tmp_path / "launch-real"
    alias_directory = tmp_path / "launch"
    source.write_bytes(b"source")
    real_directory.mkdir()
    launch = real_directory / "fireemu"
    launch.write_bytes(b"source")
    alias_directory.symlink_to(real_directory, target_is_directory=True)
    aliased_launch = alias_directory / "fireemu"
    receipt = {
        "artifactSha256": __import__("hashlib").sha256(b"source").hexdigest(),
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
    with pytest.raises(ValueError, match="symlink parent"):
        artifact_binding(source, aliased_launch, receipt, {"crates/x.rs": "x"})


def test_verified_fd_copy_survives_launch_path_replacement(tmp_path):
    source = tmp_path / "source-fireemu"
    launch = tmp_path / "launch-fireemu"
    destination = tmp_path / "destination-fireemu"
    source.write_bytes(b"source")
    launch.write_bytes(b"independent-launch")
    descriptor = os.open(launch, os.O_RDONLY)
    try:
        preserved = launch.with_name("preserved-launch-fireemu")
        launch.rename(preserved)
        launch.hardlink_to(source)
        copy_verified_artifact(launch, destination, descriptor)
    finally:
        os.close(descriptor)
    assert destination.read_bytes() == b"independent-launch"


def test_artifact_binding_returns_fd_capability_for_path_replacement(
    tmp_path,
):
    source = tmp_path / "source-fireemu"
    launch = tmp_path / "launch-fireemu"
    destination = tmp_path / "destination-fireemu"
    source.write_bytes(b"source")
    launch.write_bytes(b"source")
    receipt = {
        "artifactSha256": __import__("hashlib").sha256(b"source").hexdigest(),
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
    binding = artifact_binding(source, launch, receipt, receipt["inputs"])
    verified_fd = binding.pop("_launchFd")
    try:
        preserved = launch.with_name("preserved-launch-fireemu")
        launch.rename(preserved)
        launch.hardlink_to(source)
        copy_verified_artifact(launch, destination, verified_fd)
        assert os.fstat(verified_fd).st_ino != source.stat().st_ino
    finally:
        os.close(verified_fd)
    assert destination.read_bytes() == b"source"


def test_verified_fd_copy_rejects_preexisting_hardlink(tmp_path):
    source = tmp_path / "source-fireemu"
    launch = tmp_path / "launch-fireemu"
    destination = tmp_path / "destination-fireemu"
    source.write_bytes(b"source")
    launch.hardlink_to(source)
    verified_fd = os.open(launch, os.O_RDONLY)
    try:
        with pytest.raises(ValueError, match="independent file"):
            copy_verified_artifact(launch, destination, verified_fd)
    finally:
        os.close(verified_fd)


def test_open_verified_artifact_anchors_parent_before_path_swap(tmp_path, monkeypatch):
    parent = tmp_path / "validated-parent"
    attacker = tmp_path / "attacker-parent"
    artifact = parent / "fireemu"
    parent.mkdir()
    attacker.mkdir()
    artifact.write_bytes(b"wanted")
    (attacker / artifact.name).write_bytes(b"wrong")
    original_open = owned_runner.os.open
    swapped = False

    def swap_parent_before_file_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if not swapped and Path(path).name == artifact.name:
            parent.rename(tmp_path / "preserved-parent")
            parent.symlink_to(attacker, target_is_directory=True)
            swapped = True
        if dir_fd is None:
            return original_open(path, flags, mode)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(owned_runner.os, "open", swap_parent_before_file_open)
    try:
        descriptor = open_verified_artifact(artifact)
    except ValueError:
        descriptor = None
    try:
        assert swapped
        if descriptor is not None:
            assert os.pread(descriptor, 1024, 0) == b"wanted"
    finally:
        if descriptor is not None:
            os.close(descriptor)
        parent.unlink(missing_ok=True)
        if parent.is_symlink():
            parent.unlink()
        (tmp_path / "preserved-parent").rename(parent)


def test_artifact_binding_rejects_launch_replacement_during_descriptor_read(
    tmp_path, monkeypatch
):
    source = tmp_path / "source-fireemu"
    launch = tmp_path / "launch-fireemu"
    source.write_bytes(b"source")
    launch.write_bytes(b"source")
    receipt = {
        "artifactSha256": __import__("hashlib").sha256(b"source").hexdigest(),
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
    original_read = owned_runner.os.read
    replaced = False

    def replace_after_source_read(fd, size):
        nonlocal replaced
        chunk = original_read(fd, size)
        if not replaced and chunk:
            launch.unlink()
            launch.hardlink_to(source)
            replaced = True
        return chunk

    monkeypatch.setattr(owned_runner.os, "read", replace_after_source_read)
    with pytest.raises(ValueError, match="hardlink|changed"):
        artifact_binding(source, launch, receipt, {"crates/x.rs": "x"})


def test_artifact_binding_rejects_independent_launch_replacement_during_read(
    tmp_path, monkeypatch
):
    source = tmp_path / "source-fireemu"
    launch = tmp_path / "launch-fireemu"
    source.write_bytes(b"source")
    launch.write_bytes(b"source")
    original_inode = launch.stat().st_ino
    receipt = {
        "artifactSha256": __import__("hashlib").sha256(b"source").hexdigest(),
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
    original_read = owned_runner.os.read
    replaced = False

    def replace_after_launch_read(fd, size):
        nonlocal replaced
        before = owned_runner.os.fstat(fd)
        chunk = original_read(fd, size)
        if not replaced and chunk and before.st_ino == original_inode:
            replacement = launch.with_name("replacement-fireemu")
            shutil.copyfile(source, replacement)
            launch.unlink()
            replacement.rename(launch)
            replaced = True
        return chunk

    monkeypatch.setattr(owned_runner.os, "read", replace_after_launch_read)
    with pytest.raises(ValueError, match="changed"):
        artifact_binding(source, launch, receipt, {"crates/x.rs": "x"})


def test_artifact_binding_rejects_launch_replacement_after_path_recheck(
    tmp_path, monkeypatch
):
    source = tmp_path / "source-fireemu"
    launch = tmp_path / "launch-fireemu"
    source.write_bytes(b"source")
    launch.write_bytes(b"source")
    receipt = {
        "artifactSha256": __import__("hashlib").sha256(b"source").hexdigest(),
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
    original_stat = owned_runner.os.stat
    replaced = False

    def replace_after_launch_stat(path, *args, **kwargs):
        nonlocal replaced
        result = original_stat(path, *args, **kwargs)
        if not replaced and Path(path) == launch:
            launch.unlink()
            launch.hardlink_to(source)
            replaced = True
        return result

    monkeypatch.setattr(owned_runner.os, "stat", replace_after_launch_stat)
    with pytest.raises(ValueError, match="hardlink|after verification|before opening"):
        artifact_binding(source, launch, receipt, {"crates/x.rs": "x"})


def test_artifact_binding_rejects_launch_replacement_after_final_stat(
    tmp_path, monkeypatch
):
    source = tmp_path / "source-fireemu"
    launch = tmp_path / "launch-fireemu"
    source.write_bytes(b"source")
    launch.write_bytes(b"source")
    receipt = {
        "artifactSha256": __import__("hashlib").sha256(b"source").hexdigest(),
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
    original_stat = owned_runner.os.stat
    launch_stats = 0

    def replace_after_final_stat(path, *args, **kwargs):
        nonlocal launch_stats
        result = original_stat(path, *args, **kwargs)
        if Path(path) == launch:
            launch_stats += 1
            if launch_stats == 2:
                launch.unlink()
                launch.hardlink_to(source)
        return result

    monkeypatch.setattr(owned_runner.os, "stat", replace_after_final_stat)
    with pytest.raises(ValueError, match="hardlink|while reading|before use|after verification"):
        artifact_binding(source, launch, receipt, {"crates/x.rs": "x"})


def test_artifact_binding_rejects_launch_replacement_after_bound_descriptor_stat(
    tmp_path, monkeypatch
):
    source = tmp_path / "source-fireemu"
    launch = tmp_path / "launch-fireemu"
    source.write_bytes(b"source")
    launch.write_bytes(b"source")
    receipt = {
        "artifactSha256": __import__("hashlib").sha256(b"source").hexdigest(),
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
    original_fstat = owned_runner.os.fstat
    fstats = 0

    def replace_after_bound_fstat(fd):
        nonlocal fstats
        result = original_fstat(fd)
        fstats += 1
        if fstats == 5:
            launch.unlink()
            launch.hardlink_to(source)
        return result

    monkeypatch.setattr(owned_runner.os, "fstat", replace_after_bound_fstat)
    with pytest.raises(ValueError, match="hardlink|while reading|before use|before opening"):
        artifact_binding(source, launch, receipt, {"crates/x.rs": "x"})


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


def test_build_timeout_defaults_to_a_cold_build_safe_limit():
    assert DEFAULT_BUILD_TIMEOUT_SECONDS == 1800
    assert build_timeout({}) == DEFAULT_BUILD_TIMEOUT_SECONDS


@pytest.mark.parametrize("raw,seconds", [("60", 60), (" 900 ", 900), ("3600", 3600)])
def test_build_timeout_honours_a_positive_integer_override(raw, seconds):
    assert build_timeout({BUILD_TIMEOUT_VARIABLE: raw}) == seconds


@pytest.mark.parametrize("raw", ["", "0", "-1", "abc", "1.5", "60s", "1e3", "０"])
def test_build_timeout_rejects_invalid_values_instead_of_falling_back(raw):
    with pytest.raises(ValueError, match=BUILD_TIMEOUT_VARIABLE):
        build_timeout({BUILD_TIMEOUT_VARIABLE: raw})


def test_build_timeout_variable_never_reaches_the_build_child_environment():
    assert BUILD_TIMEOUT_VARIABLE not in sanitized_environment(
        {"PATH": "/bin", BUILD_TIMEOUT_VARIABLE: "60"}
    )


def test_run_build_reports_a_hung_build_and_reaps_the_child():
    marker = "fireemu-build-timeout-probe-" + uuid.uuid4().hex
    started = time.monotonic()
    with pytest.raises(TimeoutError) as raised:
        run_build(
            ["sh", "-c", f"sleep 120 # {marker}"], {"PATH": os.environ["PATH"]}, 1
        )
    assert time.monotonic() - started < 30
    assert "1 seconds" in str(raised.value)
    assert "cargo build -p fireemu" in str(raised.value)
    assert BUILD_TIMEOUT_VARIABLE in str(raised.value)
    listing = subprocess.run(
        ["ps", "-A", "-o", "args="], text=True, stdout=subprocess.PIPE, check=True
    )
    assert marker not in listing.stdout


def test_run_build_returns_the_completed_process_when_it_finishes():
    completed = run_build(["sh", "-c", "printf ok"], {"PATH": os.environ["PATH"]}, 60)
    assert completed.returncode == 0
    assert completed.stdout == "ok"
