"""Owned executable fixtures: bounded readiness, pipe drain and conservative shutdown."""
from __future__ import annotations

import json
import os
import shlex
import signal
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import credential_process as runtime
import credential_shadow as shadow


SETUP_SECONDS = 20.0


def executable(tmp_path, program, *, setup_seconds=0, setup="", observation="output", minimum_bytes=1):
    source = tmp_path / "fixture.py"
    marker = tmp_path / "artifact.ready.json"
    temporary = marker.with_suffix(".tmp")
    source.write_text(
        "import os, sys, time, signal, json\n"
        + f"time.sleep({setup_seconds!r})\n" + setup + "\n"
        + f"marker = {str(marker)!r}; temporary = {str(temporary)!r}\n"
        + "with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as out:\n"
        + f"    json.dump(dict(pid=os.getpid(), ignoreTerm=signal.getsignal(signal.SIGTERM)==signal.SIG_IGN, observation={observation!r}, minimumBytes={minimum_bytes!r}), out)\n"
        + "os.replace(temporary, marker)\n" + program
    )
    wrapper = tmp_path / "artifact"
    wrapper.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + " -I -S -B " + shlex.quote(str(source)) + ' "$@"\n')
    wrapper.chmod(0o700)
    return wrapper


def await_fixture(condition, process, phase):
    deadline = time.monotonic() + SETUP_SECONDS
    while not condition():
        exit_code = process.poll()
        if exit_code is not None:
            raise AssertionError({"phase": phase, "exitCode": exit_code})
        assert time.monotonic() < deadline, {"phase": phase, "pid": process.pid}
        time.sleep(.01)


def private_work(tmp_path):
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    return work


@pytest.fixture
def owned(monkeypatch):
    import copy

    original_launch = runtime.subprocess.Popen
    original_monitor = runtime._OutputMonitor
    original_stop = runtime.stop_daemon
    original_signal = runtime.os.killpg
    processes = []

    def launch(*args, **kwargs):
        forwarded = copy.deepcopy((args, kwargs))
        process = original_launch(*args, **kwargs)
        assert (args, kwargs) == forwarded
        if kwargs.get("start_new_session"):
            processes.append(process)
            process._fixture_signals = []
            process._fixture_launch = forwarded
            marker = Path(args[0][0]).with_suffix(".ready.json")
            await_fixture(marker.is_file, process, "interpreter-setup")
            plan = json.loads(marker.read_text())
            assert plan["pid"] == process.pid
            assert marker.stat().st_mode & 0o777 == 0o600
            if plan["observation"] != "exit":
                assert process.poll() is None, plan
            process._fixture_plan = plan
        return process

    def monitor(stream, capture):
        process = next(value for value in processes if value.stdout is stream)
        observer = original_monitor(stream, capture)
        start = observer.thread.start

        def prepared_start():
            start()
            plan = process._fixture_plan
            def prepared():
                if plan["observation"] in {"silent", "exit"}:
                    return True
                if plan["observation"] == "failure":
                    return observer.failure is not None and observer.ready.is_set()
                if plan["observation"] == "origin":
                    return observer.origin is not None
                return observer.captured >= plan["minimumBytes"] or observer.failure is not None
            await_fixture(prepared, process, "output-monitor-setup")
            if plan["observation"] != "exit":
                assert process.poll() is None, plan
            process._fixture_readiness_started = time.monotonic()

        observer.thread.start = prepared_start
        return observer

    def signal_group(pid, value):
        process = next(process for process in processes if process.pid == pid)
        assert process._fixture_plan["pid"] == pid
        process._fixture_signals.append((pid, value))
        return original_signal(pid, value)

    def stop(process):
        entered = time.monotonic()
        receipt = original_stop(process)
        ended = time.monotonic()
        readiness = getattr(process, "_fixture_readiness_started", None)
        process._fixture_shutdown = receipt
        process._fixture_timings = {"readinessSeconds": None if readiness is None else entered - readiness,
                                   "stopSeconds": ended - entered}
        if readiness is not None:
            assert entered - readiness < runtime.STARTUP_SECONDS + 10, process._fixture_timings
        assert ended - entered < 2 * runtime.STOP_SECONDS + 10, process._fixture_timings
        return receipt

    monkeypatch.setattr(runtime.subprocess, "Popen", launch)
    monkeypatch.setattr(runtime, "_OutputMonitor", monitor)
    monkeypatch.setattr(runtime.os, "killpg", signal_group)
    monkeypatch.setattr(runtime, "stop_daemon", stop)
    monkeypatch.setattr(runtime, "STARTUP_SECONDS", .35)
    assert runtime.STOP_SECONDS == 20
    yield processes
    for process in processes:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=SETUP_SECONDS)
        observer = getattr(process, "_credential_output_monitor", None)
        if observer is not None:
            observer.stop()
        if process.stdout is not None and not process.stdout.closed:
            process.stdout.close()


@pytest.mark.parametrize("setup_seconds", [0, .6], ids=["prepared", "delayed"])
@pytest.mark.parametrize("payload,ignore_term,diagnostic_type,observation", [
    pytest.param(b"", False, "DaemonStartupDeadlineExceeded", "silent", id="silent"),
    pytest.param(b"partial no newline", False, "DaemonStartupDeadlineExceeded", "output", id="partial"),
    pytest.param(b"", True, "DaemonStartupDeadlineExceeded", "silent", id="ignore-term"),
    pytest.param(b"x" * 9000, False, "StartupLineLimit", "failure", id="long-line"),
    pytest.param(b"auth (REST): external.invalid:8123\n", False,
                 "DaemonReadinessOutputInvalid", "failure", id="external"),
    pytest.param(b"auth (REST): 127.0.0.1:8123/private\n", False,
                 "DaemonReadinessOutputInvalid", "failure", id="path"),
    pytest.param(b"auth (REST): localhost:8123\n", False,
                 "DaemonReadinessOutputInvalid", "failure", id="localhost"),
])
def test_unready_daemon_cannot_block_readline_or_escape_caller_ownership(
    tmp_path, owned, payload, ignore_term, diagnostic_type, observation, setup_seconds, record_property
):
    program = (f"os.write(1, {payload!r}); " if payload else "") + "time.sleep(60)"
    binary = executable(
        tmp_path, program, setup_seconds=setup_seconds,
        setup="signal.signal(signal.SIGTERM, signal.SIG_IGN)" if ignore_term else "",
        observation=observation, minimum_bytes=len(payload),
    )
    work = private_work(tmp_path)
    with pytest.raises(runtime.StartupError) as caught:
        runtime.start_daemon(binary, work)
    assert len(owned) == 1
    process = owned[0]
    diagnostic, receipt = caught.value.diagnostics, caught.value.shutdown
    evidence = {"diagnostic": diagnostic, "shutdown": receipt,
                "setup": process._fixture_plan, "timings": process._fixture_timings,
                "signals": process._fixture_signals}
    record_property("readinessObservation", json.dumps(evidence))
    assert process._fixture_plan["ignoreTerm"] is ignore_term, evidence
    assert diagnostic["type"] == diagnostic_type, evidence
    saved = (work / "startup-output.bin").read_bytes()
    if diagnostic_type == "StartupLineLimit":
        assert runtime.MAX_STARTUP_LINE_BYTES < len(saved) <= len(payload), evidence
        assert saved == payload[:len(saved)], evidence
    else:
        assert saved == payload, evidence
    assert diagnostic["bytes"] == len(saved), evidence
    assert diagnostic["sha256"] == __import__("hashlib").sha256(saved).hexdigest(), evidence
    expected_signals = [signal.SIGTERM, signal.SIGKILL] if ignore_term else [signal.SIGTERM]
    assert process._fixture_signals == [(process.pid, value) for value in expected_signals], evidence
    assert receipt["exitCode"] == -expected_signals[-1] == process.poll(), evidence
    assert receipt["processStopped"] is True and receipt["childrenBeforeStop"] == 0, evidence
    assert receipt["remainingChildren"] == 0 and receipt["outputDrainerStopped"] is True, evidence
    if observation == "failure":
        assert receipt["failures"] == ["daemon-output-unconfirmed"], evidence
    else:
        assert receipt["failures"] in ([], ["daemon-output-unconfirmed"]), evidence
    assert not process._credential_output_monitor.thread.is_alive(), evidence
    assert process.stdout.closed, evidence
    assert process._fixture_timings["readinessSeconds"] < runtime.STARTUP_SECONDS + 10, evidence
    assert process._fixture_timings["stopSeconds"] < 2 * runtime.STOP_SECONDS + 10, evidence


@pytest.mark.parametrize("phase", ["interpreter-setup", "output-monitor-setup"])
def test_fixture_setup_detects_early_death_before_its_guard_expires(tmp_path, owned, phase):
    """Actual fixture death must fail the preparation wait without using its full budget."""
    binary = executable(
        tmp_path, "time.sleep(.1); sys.exit(3)", observation="origin",
        setup="sys.exit(3)" if phase == "interpreter-setup" else "",
    )
    started = time.monotonic()
    with pytest.raises(AssertionError) as caught:
        runtime.start_daemon(binary, private_work(tmp_path))
    assert caught.value.args[0] == {"phase": phase, "exitCode": 3}
    assert time.monotonic() - started < SETUP_SECONDS / 2
    assert len(owned) == 1 and owned[0].poll() == 3


@pytest.mark.parametrize("reaped", [True, False])
def test_short_stop_policy_is_inert_and_keeps_unconfirmed_reap(monkeypatch, reaped):
    import subprocess
    import threading
    from unittest.mock import Mock

    assert threading.enumerate() == [threading.main_thread()]
    probe = subprocess.run(["ps", "-axo", "pid="], capture_output=True, text=True, check=True)
    existing = {int(value) for value in probe.stdout.split()}
    pid = next(value for value in range(99999, 90000, -1)
               if value not in existing and value - 1 not in existing)
    child = pid - 1
    assert pid not in existing and child not in existing
    operations = []
    timeout_error = subprocess.TimeoutExpired
    completed_process = subprocess.CompletedProcess
    real_os, real_subprocess = runtime.os, runtime.subprocess

    class Output:
        closed = False

        def close(self):
            operations.append(("stdout-close",))
            self.closed = True

    def stop_monitor():
        operations.append(("monitor-stop",))
        return True

    class Process:
        _credential_owned_group = True
        returncode = None
        waits = 0

        def __init__(self):
            self.pid = pid
            self.stdout = Output()
            self._credential_output_monitor = SimpleNamespace(failure=None, stop=stop_monitor)

        def poll(self):
            return self.returncode

        def wait(self, *, timeout):
            self.waits += 1
            operations.append(("wait", timeout))
            if self.waits == 1 or not reaped:
                raise timeout_error("inert-daemon", timeout)
            self.returncode = -signal.SIGKILL
            return self.returncode

    def census(args, **kwargs):
        assert args == ["/usr/bin/pgrep", "-P", str(pid)]
        assert kwargs == {"capture_output": True, "text": True,
                          "timeout": runtime.CENSUS_SECONDS, "check": False}
        operations.append(("census",))
        return completed_process(args, 0, str(child) + "\n", "")

    def signal_group(target, value):
        assert target == pid
        operations.append(("signal", value))

    def check_child(target, value):
        assert target == child and value == 0
        operations.append(("alive", target, value))
        raise ProcessLookupError

    # The runtime routes to inert fakes; independent guards reject any bypass through the real modules.
    monkeypatch.setattr(runtime, "os", SimpleNamespace(killpg=signal_group, kill=check_child))
    monkeypatch.setattr(runtime, "subprocess", SimpleNamespace(run=census, TimeoutExpired=timeout_error))
    guards = [Mock(side_effect=lambda *_args, **_kwargs: pytest.fail("real process operation reached"))
              for _ in range(3)]
    monkeypatch.setattr(real_os, "killpg", guards[0])
    monkeypatch.setattr(real_os, "kill", guards[1])
    monkeypatch.setattr(real_subprocess, "run", guards[2])
    monkeypatch.setattr(runtime, "STOP_SECONDS", .15)
    process = Process()
    receipt = runtime.stop_daemon(process)
    assert operations == [("census",), ("signal", signal.SIGTERM), ("wait", .15),
                          ("signal", signal.SIGKILL), ("wait", .15), ("alive", child, 0),
                          ("monitor-stop",), ("stdout-close",)]
    assert receipt == {"exitCode": -signal.SIGKILL if reaped else None,
                       "processStopped": reaped, "childrenBeforeStop": 1, "remainingChildren": 0,
                       "outputDrainerStopped": True,
                       "failures": [] if reaped else ["process-stop-TimeoutExpired"]}
    assert process.stdout.closed is True
    for guard in guards:
        guard.assert_not_called()


def test_startup_failure_retains_bounded_private_output_and_verified_shutdown(tmp_path, owned):
    secret = b"PRIVATE-STARTUP-DETAIL"
    binary = executable(tmp_path, "os.write(1, b'PRIVATE-STARTUP-DETAIL'); time.sleep(60)")
    work = private_work(tmp_path)
    with pytest.raises(runtime.StartupError) as caught:
        runtime.start_daemon(binary, work)
    error = caught.value
    diagnostic = error.diagnostics
    saved = work / "startup-output.bin"
    assert saved.read_bytes() == secret
    assert saved.stat().st_mode & 0o777 == 0o600
    assert diagnostic == {"phase": "readiness", "type": "DaemonStartupDeadlineExceeded",
                          "bytes": len(secret), "sha256": __import__("hashlib").sha256(secret).hexdigest()}
    assert error.shutdown["processStopped"] is True
    assert error.shutdown["remainingChildren"] == 0
    assert secret.decode() not in json.dumps(diagnostic)


def test_startup_output_is_capped_at_the_private_capture_limit(tmp_path, owned):
    binary = executable(tmp_path, "os.write(1,b'x'*(runtime_limit+1)); time.sleep(60)".replace(
        "runtime_limit", str(runtime.MAX_STARTUP_BYTES)))
    work = private_work(tmp_path)
    with pytest.raises(runtime.StartupError) as caught:
        runtime.start_daemon(binary, work)
    assert (work / "startup-output.bin").stat().st_size <= runtime.MAX_STARTUP_BYTES
    assert caught.value.diagnostics["bytes"] <= runtime.MAX_STARTUP_BYTES


def test_unconfirmed_leader_stop_survives_startup_error_replacement(tmp_path, owned, monkeypatch):
    binary = executable(tmp_path, "os.write(1,b'private diagnostic'); time.sleep(60)")
    work = private_work(tmp_path)
    shutdown = {"exitCode": None, "processStopped": False, "remainingChildren": None,
                "outputDrainerStopped": False, "failures": ["process-stop-unconfirmed"]}
    monkeypatch.setattr(runtime, "stop_daemon", lambda _process: shutdown)
    with pytest.raises(runtime.StartupError, match="leader stop unconfirmed") as caught:
        runtime.start_daemon(binary, work)
    assert caught.value.shutdown == shutdown
    assert caught.value.diagnostics["phase"] == "readiness"
    assert caught.value.diagnostics["bytes"] > 0


@pytest.mark.parametrize("unsafe", ["symlink", "permissions"])
def test_startup_refuses_unverified_workdir_before_launch(tmp_path, owned, unsafe):
    binary = executable(tmp_path, "time.sleep(60)")
    real_work = tmp_path / "real-work"; real_work.mkdir()
    work = tmp_path / "work"
    if unsafe == "symlink":
        work.symlink_to(real_work, target_is_directory=True)
    else:
        work.mkdir(mode=0o755)
        work.chmod(0o755)
    with pytest.raises(runtime.StartupError) as caught:
        runtime.start_daemon(binary, work)
    assert not owned
    assert caught.value.shutdown["processStarted"] is False
    assert caught.value.diagnostics["phase"] == "launch"


def test_popen_failure_has_safe_launch_diagnostic_and_no_process_status(tmp_path, monkeypatch):
    binary = executable(tmp_path, "time.sleep(60)")
    work = private_work(tmp_path)
    def fail_launch(*_args, **_kwargs):
        raise OSError("PRIVATE-LAUNCH-DETAIL")
    monkeypatch.setattr(runtime.subprocess, "Popen", fail_launch)
    with pytest.raises(OSError) as caught:
        runtime.start_daemon(binary, work)
    assert caught.value.diagnostics == {"phase": "launch", "type": "OSError", "bytes": 0,
                                        "sha256": __import__("hashlib").sha256(b"").hexdigest()}
    assert caught.value.shutdown == {"processStarted": False, "processStopped": True,
        "exitCode": None, "remainingChildren": 0, "outputDrainerStopped": True, "failures": []}
    assert "PRIVATE-LAUNCH-DETAIL" not in json.dumps(caught.value.diagnostics)


def test_capture_write_failure_keeps_stop_status_and_publishes_no_raw_output(
    tmp_path, owned, monkeypatch
):
    binary = executable(tmp_path, "os.write(1,b'PRIVATE-CAPTURE-FAILURE'); time.sleep(60)")
    work = private_work(tmp_path)
    original = runtime._OutputMonitor

    class BrokenCapture:
        def write(self, _data):
            raise OSError("PRIVATE-CAPTURE-IO-DETAIL")

    def broken_monitor(stream, capture):
        return original(stream, BrokenCapture())

    monkeypatch.setattr(runtime, "_OutputMonitor", broken_monitor)
    with pytest.raises(runtime.StartupError) as caught:
        runtime.start_daemon(binary, work)
    assert (work / "startup-output.bin").read_bytes() == b""
    assert caught.value.shutdown["processStopped"] is True
    assert "daemon-output-unconfirmed" in caught.value.shutdown["failures"]
    assert caught.value.diagnostics["type"] == "OutputMonitorOSError"
    assert "PRIVATE-CAPTURE" not in json.dumps(caught.value.diagnostics)


@pytest.mark.parametrize("address", ["127.0.0.1:8123", "[::1]:8123"])
def test_readiness_accepts_numeric_endpoints_and_output_is_drained_after_ready(tmp_path, owned, address):
    binary = executable(tmp_path, f"os.write(1,b'auth (REST): {address}\\n'); time.sleep(.1)\n"
        "for _ in range(200): os.write(1,b'x'*65536)\n"
        "open('drained','w').write('yes'); time.sleep(60)", observation="origin")
    work = private_work(tmp_path)
    proc, base = runtime.start_daemon(binary, work)
    assert base == "http://" + address
    deadline = time.monotonic() + 3
    while not (work / "drained").exists() and time.monotonic() < deadline:
        time.sleep(.01)
    assert (work / "drained").exists(), "daemon blocked writing logs after readiness"
    result = runtime.stop_daemon(proc)
    assert result["processStopped"] is True and result["remainingChildren"] == 0
    assert result["outputDrainerStopped"] is True and result["failures"] == []


def test_monitor_initialization_failure_still_reaps_started_daemon(tmp_path, owned, monkeypatch):
    binary = executable(tmp_path, "time.sleep(60)")
    work = private_work(tmp_path)
    def broken(*_args):
        raise OSError("private startup details")
    monkeypatch.setattr(runtime, "_OutputMonitor", broken)
    with pytest.raises(OSError):
        runtime.start_daemon(binary, work)
    assert len(owned) == 1 and owned[0].poll() is not None


def test_census_error_does_not_prevent_leader_shutdown(tmp_path, owned, monkeypatch):
    binary = executable(tmp_path, "os.write(1,b'auth (REST): 127.0.0.1:8123\\n'); time.sleep(60)", observation="origin")
    work = private_work(tmp_path)
    proc, _ = runtime.start_daemon(binary, work)
    def broken(_pid):
        raise OSError("private census error")
    monkeypatch.setattr(runtime, "_children_of", broken)
    result = runtime.stop_daemon(proc)
    assert proc.poll() is not None and result["processStopped"] is True
    assert result["remainingChildren"] is None and result["failures"] == ["child-census-OSError"]
    assert "private census" not in json.dumps(result)


def test_stdout_close_error_is_not_lost_and_leader_is_reaped(tmp_path, owned):
    binary = executable(tmp_path, "os.write(1,b'auth (REST): 127.0.0.1:8123\\n'); time.sleep(60)", observation="origin")
    work = private_work(tmp_path)
    proc, _ = runtime.start_daemon(binary, work)
    original = proc.stdout
    def broken():
        original.close()
        raise OSError("private pipe detail")
    proc.stdout = SimpleNamespace(close=broken)
    try:
        result = runtime.stop_daemon(proc)
        assert proc.poll() is not None
        assert result["outputDrainerStopped"] is False
        assert "stdout-close-OSError" in result["failures"]
        assert "private pipe detail" not in json.dumps(result)
    finally:
        proc.stdout = original


def test_startup_does_not_inherit_cloud_or_injection_environment(tmp_path, owned, monkeypatch):
    for key in ("GOOGLE_APPLICATION_CREDENTIALS", "NODE_OPTIONS", "PYTHONPATH", "HTTP_PROXY"):
        monkeypatch.setenv(key, "secret-injection")
    binary = executable(tmp_path, "import json\nopen('env.json','w').write(json.dumps(dict(os.environ)))\n"
        "os.write(1,b'auth (REST): 127.0.0.1:8123\\n'); time.sleep(60)", observation="origin")
    work = private_work(tmp_path)
    proc, _ = runtime.start_daemon(binary, work)
    try:
        env = json.loads((work / "env.json").read_text())
        assert not {"GOOGLE_APPLICATION_CREDENTIALS", "NODE_OPTIONS", "PYTHONPATH", "HTTP_PROXY"} & set(env)
    finally:
        runtime.stop_daemon(proc)


def test_config_is_not_overwritten_or_reused(tmp_path, owned):
    binary = executable(tmp_path, "time.sleep(60)")
    work = private_work(tmp_path)
    config = work / "fireemu.shadow.json"; config.write_text("keep")
    with pytest.raises(FileExistsError):
        runtime.start_daemon(binary, work)
    assert not owned and config.read_text() == "keep"


@pytest.mark.parametrize("setup_seconds", [0, .6])
def test_real_exit_three_is_observed_before_shutdown(tmp_path, owned, monkeypatch, setup_seconds):
    # Slow fixture setup must not masquerade as an exit(3) observation.
    binary = executable(tmp_path, f"time.sleep({setup_seconds}); sys.exit(3)", observation="exit")
    work = private_work(tmp_path)
    operations = []
    stop = runtime.stop_daemon
    launch = runtime.subprocess.Popen

    def await_fixture_exit(*args, **kwargs):
        process = launch(*args, **kwargs)
        if kwargs.get("start_new_session"):
            # Exit preparation is bounded independently of the .35 readiness and production stop fixture.
            assert process.wait(timeout=20) == 3
            operations.append(("exit", process.returncode))
        return process

    monkeypatch.setattr(runtime.subprocess, "Popen", await_fixture_exit)

    def capture_stop(process):
        # A silent exited child has real EOF, not validated readiness output.
        monitor = process._credential_output_monitor
        monitor.thread.join(timeout=20)
        assert not monitor.thread.is_alive()
        assert monitor.failure == "startup-output-ended"
        operations.append(("output-ended", monitor.failure))
        operations.append(("shutdown", process.poll()))
        return stop(process)

    monkeypatch.setattr(runtime, "stop_daemon", capture_stop)
    with pytest.raises(runtime.StartupError) as caught:
        runtime.start_daemon(binary, work)
    receipt = caught.value.shutdown
    diagnostic = caught.value.diagnostics
    assert diagnostic["type"] in {"DaemonExitedBeforeReadiness", "StartupOutputEnded"}, diagnostic
    assert diagnostic["bytes"] == 0, diagnostic
    assert diagnostic["sha256"] == __import__("hashlib").sha256(b"").hexdigest(), diagnostic
    assert operations == [("exit", 3), ("output-ended", "startup-output-ended"), ("shutdown", 3)]
    assert receipt["exitCode"] == 3 and receipt["processStopped"] is True
    assert receipt["remainingChildren"] == 0
    assert receipt["outputDrainerStopped"] is True
    assert receipt["failures"] == ["daemon-output-unconfirmed"]
    assert owned[0].poll() == 3
    assert not owned[0]._credential_output_monitor.thread.is_alive()
