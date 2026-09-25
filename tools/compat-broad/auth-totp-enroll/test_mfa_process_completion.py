"""A missing OS identity must not become proof of process cleanup."""

from types import SimpleNamespace

import pytest

import mfa_local_shadow as shadow


OWN = ("parent", "parent --controller")
CHILD = ("child", "child --owned")


@pytest.mark.parametrize("spawn", [None, CHILD, ("stranger", "stranger")])
def test_missing_identity_of_a_live_child_never_reports_stopped(monkeypatch, spawn):
    process = SimpleNamespace(pid=12345)
    monkeypatch.setattr(shadow, "_has_exited", lambda _process: False)
    monkeypatch.setattr(shadow, "process_identity", lambda _pid: None)
    monkeypatch.setattr(shadow.os, "kill", lambda *_: pytest.fail("unbound signal"))

    assert shadow.reap_owned_child(process, spawn) == "pid-reused-refusing-to-signal"


def test_exit_during_identity_read_is_confirmed_by_waiting(monkeypatch):
    process = SimpleNamespace(pid=12345)
    waits = iter([False, True])
    monkeypatch.setattr(shadow, "_has_exited", lambda _process: next(waits))
    monkeypatch.setattr(shadow, "process_identity", lambda _pid: None)
    monkeypatch.setattr(shadow.os, "kill", lambda *_: pytest.fail("exited child signal"))

    assert shadow.reap_owned_child(process, CHILD) == "stopped"


@pytest.mark.parametrize("first_read", [None, OWN])
def test_capture_waits_for_a_confirmed_post_exec_identity(monkeypatch, first_read):
    process = SimpleNamespace(pid=12345)
    reads = iter([first_read, CHILD])
    clock = [0.0]
    monkeypatch.setattr(shadow, "_has_exited", lambda _process: False)
    monkeypatch.setattr(
        shadow, "process_identity",
        lambda pid: next(reads) if pid == process.pid else OWN,
    )
    monkeypatch.setattr(shadow, "time", SimpleNamespace(
        monotonic=lambda: clock[0],
        sleep=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
    ))

    assert shadow.capture_child_identity(process) == CHILD
    assert clock[0] > 0


@pytest.mark.parametrize("identity", [None, OWN])
def test_capture_deadline_does_not_bind_missing_or_parent_identity(monkeypatch, identity):
    process = SimpleNamespace(pid=12345)
    monkeypatch.setattr(shadow, "_has_exited", lambda _process: False)
    monkeypatch.setattr(
        shadow, "process_identity",
        lambda pid: identity if pid == process.pid else OWN,
    )
    monkeypatch.setattr(shadow, "time", SimpleNamespace(monotonic=lambda: 0.0))

    assert shadow.capture_child_identity(process, settle_seconds=0) is None


def test_capture_returns_no_identity_after_confirmed_exit(monkeypatch):
    process = SimpleNamespace(pid=12345)
    monkeypatch.setattr(shadow, "_has_exited", lambda _process: True)
    monkeypatch.setattr(shadow, "process_identity", lambda _pid: OWN)

    assert shadow.capture_child_identity(process) is None


def test_missing_identity_after_attempted_signals_is_not_a_cleanup_proof(monkeypatch):
    import subprocess

    def wait(*, timeout):
        raise subprocess.TimeoutExpired("child", timeout)

    process = SimpleNamespace(pid=12345, wait=wait)
    signals = []
    identities = iter([CHILD, CHILD, None])
    monkeypatch.setattr(shadow, "_has_exited", lambda _process: False)
    monkeypatch.setattr(shadow, "process_identity", lambda _pid: next(identities))
    monkeypatch.setattr(shadow.os, "kill", lambda _pid, sig: signals.append(sig))

    assert shadow.reap_owned_child(process, CHILD) == "survived"
    assert signals == [shadow.signal.SIGTERM, shadow.signal.SIGKILL]


def test_existing_output_is_rejected_before_build_or_child_start(tmp_path, monkeypatch):
    output = tmp_path / "old-output"
    output.mkdir()
    receipt = output / "shadow.json"
    receipt.write_text('{"recordingComplete":true}')
    monkeypatch.setattr(shadow.subprocess, "run", lambda *_a, **_kw: pytest.fail("build"))
    monkeypatch.setattr(shadow.subprocess, "Popen", lambda *_a, **_kw: pytest.fail("child"))

    with pytest.raises(FileExistsError):
        shadow.parent(output)
    assert receipt.read_text() == '{"recordingComplete":true}'


@pytest.mark.parametrize("failure", [
    "none", "exit", "timeout", "recording", "disagreements", "cleanup",
    "remaining", "boolean-count", "configuration", "missing-recovery",
    "missing-budget", "excess-budget", "budget-refilled", "budget-count-mismatch",
    "budget-open", "budget-observation-limit", "budget-plan",
])
def test_parent_requires_successful_child_and_complete_current_receipt(
    tmp_path, monkeypatch, failure
):
    import json
    import subprocess

    binary = tmp_path / "target/debug/fireemu"
    binary.parent.mkdir(parents=True)
    binary.write_text("inert test fixture; never executed")
    output = tmp_path / "new-output"
    (tmp_path / ".gitignore").write_text("new-output/\n")
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.email", "fixture@example.test"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.name", "MFA fixture"],
        check=True,
    )
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "commit", "--quiet", "-m", "fixture"],
        check=True,
    )
    from mfa_manifest import compile_campaign
    from mfa_request_budget import RequestBudget
    plan = compile_campaign("f" * 32)
    budget = RequestBudget()
    budget.bind(plan)
    with budget.attempt():
        pass
    budget.begin_recovery(())
    budget.close()
    report = {
        "campaign": plan, "requestBudget": budget.snapshot(),
        "recordingComplete": True, "disagreements": [], "requestsCharged": 1,
        "recovery": {"cleanupVerified": True, "remainingOwnedResources": 0,
                     "configurationRestored": True},
    }
    if failure == "recording":
        report["recordingComplete"] = False
    elif failure == "disagreements":
        report["disagreements"] = ["unvalidated local state"]
    elif failure == "cleanup":
        report["recovery"]["cleanupVerified"] = False
    elif failure == "remaining":
        report["recovery"]["remainingOwnedResources"] = 1
    elif failure == "boolean-count":
        report["recovery"]["remainingOwnedResources"] = False
    elif failure == "configuration":
        report["recovery"]["configurationRestored"] = False
    elif failure == "missing-recovery":
        report.pop("recovery")

    if failure == "missing-budget":
        report.pop("requestBudget")
    elif failure == "excess-budget":
        report["requestBudget"]["maxRequests"] = 401
    elif failure == "budget-refilled":
        report["requestBudget"]["requestsCharged"] = 0
    elif failure == "budget-count-mismatch":
        report["requestsCharged"] = True
    elif failure == "budget-open":
        report["requestBudget"]["phase"] = "observation"
    elif failure == "budget-observation-limit":
        report["requestBudget"]["observationLimitHit"] = True
    elif failure == "budget-plan":
        report["requestBudget"]["planDigest"] = "0" * 64

    def start(_argv, **_kwargs):
        (output / "shadow.json").write_text(json.dumps(report))

        def wait(*, timeout):
            if failure == "timeout":
                raise subprocess.TimeoutExpired("inert child fixture", timeout)
            return 2 if failure == "exit" else 0

        return SimpleNamespace(pid=12345, wait=wait, poll=lambda: 0)

    child_subprocess = SimpleNamespace(
        Popen=start,
        PIPE=subprocess.PIPE,
        TimeoutExpired=subprocess.TimeoutExpired,
    )
    monkeypatch.setattr(shadow, "repository_root", lambda: tmp_path)
    monkeypatch.setattr(shadow, "subprocess", child_subprocess)
    monkeypatch.setattr(shadow, "capture_child_identity", lambda _process: CHILD)
    monkeypatch.setattr(shadow, "reap_owned_child", lambda *_: "stopped")

    assert shadow.parent(output) == (0 if failure == "none" else 1)
    assert json.loads((output / "shadow.json").read_text()) == report
