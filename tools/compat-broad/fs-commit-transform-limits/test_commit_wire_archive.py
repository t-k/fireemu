"""Real-process tests for the archive-descriptor bound Commit wire worker.

Every request in this module targets an owned loopback server or a closed
loopback port. No production origin, credential or network is used.
"""

import hashlib
import importlib.util
import json
import os
import socket
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import ClassVar
from unittest.mock import patch

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import commit_remote_transport as transport
from test_commit_remote_transport import payload

_SPEC = importlib.util.spec_from_file_location("o8_bundle", HERE / "o8_bundle.py")
assert _SPEC is not None and _SPEC.loader is not None
o8_bundle = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(o8_bundle)

TOKEN = "loopback-only-token"


def frozen_worker_sources() -> dict[str, str]:
    return {
        name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        for name in o8_bundle.WORKER_SOURCES
    }


class Handler(BaseHTTPRequestHandler):
    received: ClassVar[list] = []
    slow: ClassVar[bool] = False

    def do_POST(self):
        self.received.append((self.path, self.headers.get("Authorization")))
        if self.slow:
            time.sleep(3)
        body = json.dumps(
            {"error": {"code": 400, "status": "INVALID_ARGUMENT"}}
        ).encode()
        self.send_response(400)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class Loopback:
    def __init__(self, *, slow: bool = False) -> None:
        Handler.received = []
        Handler.slow = slow
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    def close(self) -> None:
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()
        Handler.slow = False


def closed_loopback_origin() -> str:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    return f"http://127.0.0.1:{port}"


def unchecked_bound(value, **kwargs):
    """Exercise worker mechanics while keeping the public gate under test."""
    with patch("o8_admission.authorize_transport"):
        return transport._request_bound_unchecked(value, **kwargs)


def test_production_request_refuses_the_pathname_worker_entirely():
    """Only an archive-bound capability may reach the fixed production origin."""
    with pytest.raises(TypeError):
        transport.request(payload(local=False, token=TOKEN))
    with pytest.raises(ValueError, match="archive"):
        transport.request(payload(local=False, token=TOKEN), local_origin=None)


def test_bound_wire_completes_against_an_owned_loopback_server():
    archive, sha = o8_bundle.build_worker_archive_from_source(
        ROOT, frozen_worker_sources()
    )
    server = Loopback()
    try:
        with o8_bundle.unlinked_archive_fd(archive, sha) as fd:
            with pytest.raises(ValueError, match="capability"):
                transport.request_bound(
                    payload(token=TOKEN),
                    archive_fd=fd,
                    archive_sha256=sha,
                    local_origin=server.origin,
                )
            result = unchecked_bound(
                payload(token=TOKEN),
                archive_fd=fd,
                archive_sha256=sha,
                local_origin=server.origin,
            )
    finally:
        server.close()
    assert result["complete"] is True
    assert result["status"] == 400
    assert Handler.received[-1][1] == f"Bearer {TOKEN}"


def test_bound_wire_executes_archive_bytes_not_a_replaced_pathname(tmp_path: Path):
    """A worker source replaced after the archive is built cannot be executed."""
    archive, sha = o8_bundle.build_worker_archive_from_source(
        ROOT, frozen_worker_sources()
    )
    marker = tmp_path / "shadow-ran"
    for member in o8_bundle.WORKER_SOURCES.values():
        (tmp_path / member).write_text(
            f"raise RuntimeError('replaced {member} executed')\n"
        )
    (tmp_path / "commit_remote_transport.py").write_text(
        f"open({str(marker)!r}, 'w').close()\nraise RuntimeError('replaced worker')\n"
    )
    server = Loopback()
    try:
        with o8_bundle.unlinked_archive_fd(archive, sha) as fd:
            child = subprocess.run(
                [sys.executable, "-I", "-S", "-B", f"/dev/fd/{fd}", "--worker", sha],
                input=json.dumps(
                    {
                        "value": payload(token=TOKEN),
                        "localOrigin": server.origin,
                        "timeout": 5,
                    }
                ),
                text=True,
                capture_output=True,
                pass_fds=(fd,),
                cwd=tmp_path,
                env={"PYTHONPATH": str(tmp_path)},
                timeout=30,
                check=False,
            )
    finally:
        server.close()
    assert child.returncode == 0, child.stderr
    assert json.loads(child.stdout)["status"] == 400
    assert not marker.exists()


@pytest.mark.parametrize("invalid", ["closed", "linked", "writable", "directory"])
def test_bound_wire_refuses_an_unowned_descriptor_before_any_request(
    tmp_path: Path, invalid: str
):
    archive, sha = o8_bundle.build_worker_archive_from_source(
        ROOT, frozen_worker_sources()
    )
    server = Loopback()
    handle = None
    try:
        if invalid == "closed":
            with o8_bundle.unlinked_archive_fd(archive, sha) as opened:
                handle = opened
        elif invalid == "linked":
            linked = tmp_path / "linked.pyz"
            linked.write_bytes(archive)
            handle = os.open(linked, os.O_RDONLY)
        elif invalid == "writable":
            writable = tmp_path / "writable.pyz"
            writable.write_bytes(archive)
            handle = os.open(writable, os.O_RDWR)
        else:
            handle = os.open(tmp_path, os.O_RDONLY)
        with pytest.raises(ValueError):
            unchecked_bound(
                payload(token=TOKEN),
                archive_fd=handle,
                archive_sha256=sha,
                local_origin=server.origin,
            )
    finally:
        if handle is not None and invalid != "closed":
            os.close(handle)
        server.close()
    assert Handler.received == []


def test_bound_wire_refuses_archive_digest_drift_before_any_request():
    archive, sha = o8_bundle.build_worker_archive_from_source(
        ROOT, frozen_worker_sources()
    )
    server = Loopback()
    try:
        with (
            o8_bundle.unlinked_archive_fd(archive, sha) as fd,
            pytest.raises(ValueError),
        ):
            unchecked_bound(
                payload(token=TOKEN),
                archive_fd=fd,
                archive_sha256="0" * 64,
                local_origin=server.origin,
            )
    finally:
        server.close()
    assert Handler.received == []


def test_child_refuses_a_digest_it_cannot_confirm_before_reading_stdin(tmp_path: Path):
    """The child re-verifies the archive before it reads the credential envelope."""
    archive, sha = o8_bundle.build_worker_archive_from_source(
        ROOT, frozen_worker_sources()
    )
    server = Loopback()
    try:
        with o8_bundle.unlinked_archive_fd(archive, sha) as fd:
            child = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    f"/dev/fd/{fd}",
                    "--worker",
                    "0" * 64,
                ],
                input=json.dumps(
                    {
                        "value": payload(token=TOKEN),
                        "localOrigin": server.origin,
                        "timeout": 5,
                    }
                ),
                text=True,
                capture_output=True,
                pass_fds=(fd,),
                cwd=tmp_path,
                env={},
                timeout=30,
                check=False,
            )
    finally:
        server.close()
    assert child.returncode == 2
    assert child.stdout == ""
    assert TOKEN not in child.stdout + child.stderr
    assert Handler.received == []


def test_bound_wire_deadline_terminates_and_reaps_the_worker():
    archive, sha = o8_bundle.build_worker_archive_from_source(
        ROOT, frozen_worker_sources()
    )
    server = Loopback(slow=True)
    try:
        with o8_bundle.unlinked_archive_fd(archive, sha) as fd:
            result = unchecked_bound(
                payload(token=TOKEN),
                archive_fd=fd,
                archive_sha256=sha,
                local_origin=server.origin,
                timeout=0.4,
            )
    finally:
        server.close()
    assert result["complete"] is False
    assert result["kind"] == "deadline-exceeded"
    assert result["workerReaped"] is True


def test_bound_worker_keeps_the_token_out_of_argv_environment_and_stderr(
    tmp_path: Path,
):
    archive, sha = o8_bundle.build_worker_archive_from_source(
        ROOT, frozen_worker_sources()
    )
    command = [sys.executable, "-I", "-S", "-B", "/dev/fd/0", "--worker", sha]
    assert all(TOKEN not in part for part in command)
    origin = closed_loopback_origin()
    with o8_bundle.unlinked_archive_fd(archive, sha) as fd:
        child = subprocess.run(
            [sys.executable, "-I", "-S", "-B", f"/dev/fd/{fd}", "--worker", sha],
            input=json.dumps(
                {
                    "value": payload(token=TOKEN),
                    "localOrigin": origin,
                    "timeout": 5,
                }
            ),
            text=True,
            capture_output=True,
            pass_fds=(fd,),
            cwd=tmp_path,
            env={},
            timeout=30,
            check=False,
        )
    assert TOKEN not in child.stdout + child.stderr
    assert child.stderr == ""


def test_parent_descriptor_is_not_inherited_by_an_unrelated_child(tmp_path: Path):
    archive, sha = o8_bundle.build_worker_archive_from_source(
        ROOT, frozen_worker_sources()
    )
    with o8_bundle.unlinked_archive_fd(archive, sha) as fd:
        assert os.get_inheritable(fd) is False
        probe = subprocess.run(
            [
                sys.executable,
                "-I",
                "-c",
                f"import os,sys\ntry:\n os.fstat({fd})\nexcept OSError:\n sys.exit(0)\nsys.exit(3)\n",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    assert probe.returncode == 0, probe.stdout + probe.stderr


def _sleeper(tmp_path: Path, *, trap: bool) -> tuple[list[str], Path]:
    """A real child that reports readiness, optionally ignoring SIGTERM."""
    ready = tmp_path / f"ready-{'trap' if trap else 'plain'}"
    script = "import signal, sys, time\n"
    if trap:
        script += "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
    script += (
        f"open({str(ready)!r}, 'w').close()\n"
        "sys.stdout.flush()\n"
        "time.sleep(30)\n"
    )
    return [sys.executable, "-I", "-c", script], ready


def _await(path: Path) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.01)
    raise AssertionError(f"child never reported readiness at {path}")


def test_reap_ends_a_running_worker(tmp_path: Path):
    command, ready = _sleeper(tmp_path, trap=False)
    child = subprocess.Popen(command, stdout=subprocess.DEVNULL)
    try:
        _await(ready)
        transport._reap(child)
    finally:
        if child.poll() is None:  # pragma: no cover -- only on a failed reap
            child.kill()
            child.wait()
    assert child.poll() is not None


def test_reap_escalates_to_kill_when_terminate_is_ignored(tmp_path: Path):
    command, ready = _sleeper(tmp_path, trap=True)
    child = subprocess.Popen(command, stdout=subprocess.DEVNULL)
    try:
        _await(ready)
        transport._reap(child)
    finally:
        if child.poll() is None:  # pragma: no cover -- only on a failed reap
            child.kill()
            child.wait()
    assert child.returncode is not None
    assert child.returncode < 0


def test_spawn_reaps_the_worker_when_the_parent_raises(tmp_path: Path, monkeypatch):
    """A failure that is not a deadline must still leave no unreaped child."""
    command, _ready = _sleeper(tmp_path, trap=False)
    started: list[subprocess.Popen] = []
    original = transport.subprocess.Popen

    def record(*args, **kwargs):
        # A recording wrapper around the real Popen, not a substitute for it:
        # the worker must be identified by pid, because unrelated children of
        # this test process would answer a wait on any child.
        child = original(*args, **kwargs)
        started.append(child)
        return child

    monkeypatch.setattr(transport.subprocess, "Popen", record)
    with pytest.raises((TypeError, AttributeError)):
        # A non-text payload fails inside communicate, after the child started.
        transport._spawn(command, 17, 5.0, ())
    assert len(started) == 1
    assert started[0].returncode is not None
    with pytest.raises(ChildProcessError):
        os.waitpid(started[0].pid, os.WNOHANG)
