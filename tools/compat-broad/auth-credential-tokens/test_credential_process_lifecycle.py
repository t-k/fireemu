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


def executable(tmp_path, program):
    source = tmp_path / "fixture.py"
    source.write_text("import os, sys, time, signal\n" + program)
    wrapper = tmp_path / "artifact"
    wrapper.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + " -I -S -B " + shlex.quote(str(source)) + ' "$@"\n')
    wrapper.chmod(0o700)
    return wrapper


@pytest.fixture
def owned(monkeypatch):
    original = runtime.subprocess.Popen
    processes = []
    def launch(*args, **kwargs):
        proc = original(*args, **kwargs)
        if kwargs.get("start_new_session"):
            processes.append(proc)
        return proc
    monkeypatch.setattr(runtime.subprocess, "Popen", launch)
    monkeypatch.setattr(runtime, "STARTUP_SECONDS", .35)
    monkeypatch.setattr(runtime, "STOP_SECONDS", .15)
    yield processes
    for proc in processes:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=2)
        monitor = getattr(proc, "_credential_output_monitor", None)
        if monitor is not None:
            monitor.stop()
        if proc.stdout is not None and not proc.stdout.closed:
            proc.stdout.close()


@pytest.mark.parametrize("program", [
    "time.sleep(60)",
    "os.write(1,b'partial no newline'); time.sleep(60)",
    "signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(60)",
    "os.write(1,b'x'*9000); time.sleep(60)",
    "os.write(1,b'auth (REST): external.invalid:8123\\n'); time.sleep(60)",
    "os.write(1,b'auth (REST): 127.0.0.1:8123/private\\n'); time.sleep(60)",
    "os.write(1,b'auth (REST): localhost:8123\\n'); time.sleep(60)",
    "sys.exit(3)",
])
def test_unready_daemon_cannot_block_readline_or_escape_caller_ownership(tmp_path, owned, program):
    binary = executable(tmp_path, program)
    work = tmp_path / "work"; work.mkdir()
    started = time.monotonic()
    with pytest.raises(runtime.StartupError):
        runtime.start_daemon(binary, work)
    assert time.monotonic() - started < 3
    assert len(owned) == 1 and owned[0].poll() is not None
    monitor = getattr(owned[0], "_credential_output_monitor", None)
    if monitor is not None:
        assert not monitor.thread.is_alive()


@pytest.mark.parametrize("address", ["127.0.0.1:8123", "[::1]:8123"])
def test_readiness_accepts_numeric_endpoints_and_output_is_drained_after_ready(tmp_path, owned, address):
    binary = executable(tmp_path, f"os.write(1,b'auth (REST): {address}\\n'); time.sleep(.1)\n"
        "for _ in range(200): os.write(1,b'x'*65536)\n"
        "open('drained','w').write('yes'); time.sleep(60)")
    work = tmp_path / "work"; work.mkdir()
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
    work = tmp_path / "work"; work.mkdir()
    def broken(_stream):
        raise OSError("private startup details")
    monkeypatch.setattr(runtime, "_OutputMonitor", broken)
    with pytest.raises(OSError):
        runtime.start_daemon(binary, work)
    assert len(owned) == 1 and owned[0].poll() is not None


def test_census_error_does_not_prevent_leader_shutdown(tmp_path, owned, monkeypatch):
    binary = executable(tmp_path, "os.write(1,b'auth (REST): 127.0.0.1:8123\\n'); time.sleep(60)")
    work = tmp_path / "work"; work.mkdir()
    proc, _ = runtime.start_daemon(binary, work)
    def broken(_pid):
        raise OSError("private census error")
    monkeypatch.setattr(runtime, "_children_of", broken)
    result = runtime.stop_daemon(proc)
    assert proc.poll() is not None and result["processStopped"] is True
    assert result["remainingChildren"] is None and result["failures"] == ["child-census-OSError"]
    assert "private census" not in json.dumps(result)


def test_stdout_close_error_is_not_lost_and_leader_is_reaped(tmp_path, owned):
    binary = executable(tmp_path, "os.write(1,b'auth (REST): 127.0.0.1:8123\\n'); time.sleep(60)")
    work = tmp_path / "work"; work.mkdir()
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
        "os.write(1,b'auth (REST): 127.0.0.1:8123\\n'); time.sleep(60)")
    work = tmp_path / "work"; work.mkdir()
    proc, _ = runtime.start_daemon(binary, work)
    try:
        env = json.loads((work / "env.json").read_text())
        assert not {"GOOGLE_APPLICATION_CREDENTIALS", "NODE_OPTIONS", "PYTHONPATH", "HTTP_PROXY"} & set(env)
    finally:
        runtime.stop_daemon(proc)


def test_config_is_not_overwritten_or_reused(tmp_path, owned):
    binary = executable(tmp_path, "time.sleep(60)")
    work = tmp_path / "work"; work.mkdir()
    config = work / "fireemu.shadow.json"; config.write_text("keep")
    with pytest.raises(FileExistsError):
        runtime.start_daemon(binary, work)
    assert not owned and config.read_text() == "keep"
