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
        state,
        CASE_IDS[0],
        {"status": 200},
        ORIGIN,
        schedule={CASE_IDS[1]: ORIGIN + 600.0},
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


def test_an_abandoned_run_still_names_every_resource_it_must_delete(
    tmp_path: Path,
) -> None:
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
        Instance(
            "https://identitytoolkit.googleapis.com", "http://127.0.0.1:9099/v1/", "t"
        ).public("/v1/accounts:signUp", {})


def test_the_error_code_projection_keeps_only_the_canonical_prefix() -> None:
    assert _code_of(
        {"error": {"message": "INVALID_CODE : verification code already used"}}
    ) == ("INVALID_CODE")
    assert _code_of({"error": {"message": "SESSION_EXPIRED"}}) == "SESSION_EXPIRED"
    assert _code_of({}) is None


def test_a_ledger_missing_a_case_is_refused_rather_than_published() -> None:
    from mfa_local_shadow import build_report

    state = initial_state(compile_campaign(NONCE), ORIGIN)
    rows = {
        case["id"]: {
            "id": case["id"],
            "status": 200,
            "errorCode": None,
            "outcome": "observed",
        }
        for case in observation_cases()
    }
    report = build_report(rows, state, compile_campaign(NONCE))
    assert report["side"] == "local" and report["productionExecuted"] is False
    assert report["campaign"]["owner"]["namespace"].endswith(NONCE)
    assert [row["id"] for row in report["rows"]] == list(CASE_IDS)
    assert report["recordingComplete"] is False
    rows.pop(CASE_IDS[5])
    with pytest.raises(RuntimeError, match=CASE_IDS[5]):
        build_report(rows, state, compile_campaign(NONCE))


def test_a_published_row_carrying_secret_material_is_refused() -> None:
    from mfa_collector import SensitiveMaterialError
    from mfa_local_shadow import _row

    assert (
        _row("baseline-fresh-finalize", 200, None, pendingAgeSeconds=1.0)["status"]
        == 200
    )
    for extra in (
        {"sharedSecretKey": "ABC"},
        {"verificationCode": "123456"},
        {"idToken": "x"},
        {"mfaPendingCredential": "x"},
        {"sessionInfo": "x"},
        {"detail": {"nested": [{"refreshToken": "x"}]}},
    ):
        with pytest.raises(SensitiveMaterialError, match="published row"):
            _row("baseline-fresh-finalize", 200, None, **extra)


def test_a_child_that_outlives_its_deadline_is_reaped_and_confirmed_gone() -> None:
    import subprocess
    import sys

    from mfa_local_shadow import (
        capture_child_identity,
        process_identity,
        reap_owned_child,
    )

    argv = [sys.executable, "-c", "import time; time.sleep(120)"]
    process = subprocess.Popen(argv)
    try:
        identity = capture_child_identity(process)
        with pytest.raises(subprocess.TimeoutExpired):
            process.wait(timeout=0.2)
        assert process_identity(process.pid) is not None
        assert identity == process_identity(process.pid)
        assert reap_owned_child(process, identity) == "stopped"
        assert process_identity(process.pid) is None
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)


def test_a_child_whose_identity_is_not_the_one_that_was_started_is_never_signalled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A live child's wrong identity never grants permission to signal its PID."""
    import subprocess
    import sys

    from mfa_local_shadow import capture_child_identity, reap_owned_child

    argv = [sys.executable, "-I", "-S", "-B", "-c", "import time; time.sleep(120)"]
    process = subprocess.Popen(argv)
    try:
        # procfs may transiently report no command line during exec. Establish
        # the fixture using the production capture operation, not one immediate
        # procfs read after Popen. Signal refusal itself is checked directly.
        assert capture_child_identity(process) is not None
        stranger = ("some-other-command", "some other command --with args")

        def forbidden_signal(*_args):
            pytest.fail("an unconfirmed identity must never be signalled")

        with monkeypatch.context() as patch:
            patch.setattr("mfa_local_shadow.os.kill", forbidden_signal)
            assert reap_owned_child(process, stranger) == "pid-reused-refusing-to-signal"
            assert process.poll() is None
            assert reap_owned_child(process, None) == "pid-reused-refusing-to-signal"
            assert process.poll() is None
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)


def test_a_command_name_the_kernel_truncates_does_not_block_the_reaper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Linux cuts `comm` to 15 characters and drops the path; macOS keeps the full path.

    The reaper must stop its own child under either reporting, so this drives it with the
    Linux rendering of a long executable path that macOS would report in full.
    """
    import subprocess
    import sys

    import mfa_local_shadow
    from mfa_local_shadow import capture_child_identity, reap_owned_child

    executable = "/opt/hostedtoolcache/python/3.12.11/x64/bin/python3.12-long-name"
    reported = mfa_local_shadow.process_identity
    # TASK_COMM_LEN is 16 bytes, so Linux reports at most 15 characters of the base name.
    truncated = executable.rsplit("/", 1)[1][:15]

    def linux_identity(pid: int) -> tuple[str, str] | None:
        real = reported(pid)
        return None if real is None else (truncated, real[1])

    argv = [sys.executable, "-c", "import time; time.sleep(120)"]
    process = subprocess.Popen(argv)
    monkeypatch.setattr(mfa_local_shadow, "process_identity", linux_identity)
    try:
        identity = capture_child_identity(process)
        assert identity is not None
        assert identity[0] == truncated and "/" not in identity[0]
        assert not identity[1].startswith(identity[0])
        assert reap_owned_child(process, identity) == "stopped"
        assert process.poll() is not None
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)


def test_reaping_an_already_finished_child_is_a_no_op() -> None:
    import subprocess
    import sys

    from mfa_local_shadow import capture_child_identity, reap_owned_child

    argv = [sys.executable, "-c", "pass"]
    process = subprocess.Popen(argv)
    identity = capture_child_identity(process)
    process.wait(timeout=30)
    assert reap_owned_child(process, identity) == "stopped"


def test_a_child_that_exits_before_it_is_waited_for_is_reported_stopped() -> None:
    """A child nothing has waited for holds its PID and reports no argument vector."""
    import subprocess
    import sys
    import time

    from mfa_local_shadow import capture_child_identity, reap_owned_child

    argv = [sys.executable, "-c", "pass"]
    process = subprocess.Popen(argv)
    identity = capture_child_identity(process)
    time.sleep(0.5)
    # Nothing has waited for the child, so on Linux this reaps a zombie rather than
    # mistaking an empty argument vector for a process that survived its signals.
    assert reap_owned_child(process, identity) == "stopped"
    assert process.poll() is not None


def test_the_recorder_walks_the_cases_in_their_declared_order() -> None:
    """The ledger's rows are the recorder's own sequence, so this pins the two together."""
    ledger = json.loads(
        (
            repository_root() / "spec/compatibility/broad-runs/o2-mfa-local-shadow.json"
        ).read_text(encoding="utf-8")
    )
    assert [row["id"] for row in ledger["rows"]] == list(CASE_IDS)
    observed = {row["id"]: row for row in ledger["rows"]}
    assert observed["second-factor-limit"]["errorCode"] == "SECOND_FACTOR_EXISTS"
    assert observed["totp-withdraw"]["status"] == 200
