"""Parent evidence and real local process boundaries; no fireemu or cloud traffic."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import socket
import subprocess
import sys

import o5_user_token_local_run as module
import pytest


def successful(nonce):
    return {
        "contract": "fs-rules-user-token-local-shadow-run-v1",
        "status": "LOCAL_SHADOW_ONLY",
        "productionExecuted": False,
        "productionReady": False,
        "completed": True,
        "nonce": nonce,
        "childPid": 111,
        "recordingComplete": True,
        "stateValidation": True,
        "resourceCleanupComplete": True,
        "tenantDeleted": True,
        "firestoreOrigin": "http://127.0.0.1:18081",
        "authOrigin": "http://127.0.0.1:18082",
    }


def parent_fixture(
    tmp_path, monkeypatch, change=lambda value: value, *, code=0, stopped=True
):
    binary = tmp_path / "fake-binary"
    binary.write_text("not executed")
    calls = []
    monkeypatch.setattr(module, "build", lambda: (binary, {"artifactSha256": "b" * 64}))
    output = tmp_path / "new-run"

    class Child:
        pid = 222

        def wait(self, timeout):
            calls.append(("wait", timeout))
            if code == "timeout":
                raise subprocess.TimeoutExpired("owned", timeout)
            return code

        def poll(self):
            return code

    def launch(argv, **kwargs):
        calls.append(("launch", kwargs))
        assert kwargs["start_new_session"] is True
        assert "GOOGLE_APPLICATION_CREDENTIALS" not in kwargs["env"]
        nonce = argv[argv.index("--nonce") + 1]
        value = change(successful(nonce))
        if value is not None:
            path = output / "local-shadow.json"
            if value == "symlink":
                path.symlink_to(binary)
            elif value == "fifo":
                os.mkfifo(path)
            elif isinstance(value, str):
                path.write_text(value)
            else:
                path.write_text(json.dumps(value))
        return Child()

    monkeypatch.setattr(module.subprocess, "Popen", launch)
    monkeypatch.setattr(
        module, "_stop_owned_process", lambda _child: calls.append(("stop",)) or stopped
    )
    monkeypatch.setattr(
        module,
        "_socket_closed",
        lambda origin: (
            origin
            in {
                "http://127.0.0.1:18081",
                "http://127.0.0.1:18082",
            }
        ),
    )
    return output, calls


@pytest.mark.parametrize(
    "field",
    [
        "completed",
        "recordingComplete",
        "stateValidation",
        "resourceCleanupComplete",
        "tenantDeleted",
    ],
)
@pytest.mark.parametrize("value", [False, 1, None, "true"])
def test_zero_child_exit_does_not_replace_typed_acceptance(
    tmp_path, monkeypatch, field, value
):
    output, calls = parent_fixture(tmp_path, monkeypatch, lambda v: {**v, field: value})
    assert module.run_parent(output) == 2
    receipt = json.loads((output / "parent-result.json").read_text())
    assert receipt["completed"] is False
    assert receipt["childReceiptValid"] is False
    assert ("stop",) in calls


@pytest.mark.parametrize(
    "change",
    [
        lambda v: None,
        lambda v: "{invalid",
        lambda v: "[]",
        lambda v: "symlink",
        lambda v: "fifo",
        lambda v: {**v, "nonce": "other"},
        lambda v: {**v, "contract": "other"},
        lambda v: {**v, "productionExecuted": True},
        lambda v: {**v, "productionReady": 0},
        lambda v: {**v, "childPid": True},
        lambda v: {**v, "failure": "failure"},
        lambda v: {k: val for k, val in v.items() if k != "authOrigin"},
        lambda v: {**v, "authOrigin": "http://remote.invalid:1"},
    ],
)
def test_missing_wrong_or_unsafe_receipt_never_succeeds(tmp_path, monkeypatch, change):
    output, _ = parent_fixture(tmp_path, monkeypatch, change)
    assert module.run_parent(output) == 2
    assert json.loads((output / "parent-result.json").read_text())["completed"] is False


def test_parent_preserves_child_bytes_and_binds_their_digest(tmp_path, monkeypatch):
    output, _ = parent_fixture(tmp_path, monkeypatch)
    assert module.run_parent(output) == 0
    raw = (output / "local-shadow.json").read_bytes()
    parent = json.loads((output / "parent-result.json").read_text())
    assert parent["completed"] is True
    assert parent["returnCode"] == 0
    assert parent["childReceiptSha256"] == hashlib.sha256(raw).hexdigest()
    assert "artifact" not in json.loads(raw)
    assert "originsClosed" not in json.loads(raw)
    assert (output / "parent-result.json").stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("code,stopped", [(1, True), ("timeout", True), (0, False)])
def test_exit_timeout_or_unconfirmed_stop_keeps_failure(
    tmp_path, monkeypatch, code, stopped
):
    output, calls = parent_fixture(tmp_path, monkeypatch, code=code, stopped=stopped)
    assert module.run_parent(output) == 2
    assert ("stop",) in calls


@pytest.mark.parametrize("kind", ["directory", "file", "symlink", "dangling"])
def test_existing_output_refused_before_build(tmp_path, monkeypatch, kind):
    output = tmp_path / "old"
    if kind == "directory":
        output.mkdir()
    elif kind == "file":
        output.write_text("original")
    else:
        target = tmp_path / "target"
        if kind == "symlink":
            target.mkdir()
        output.symlink_to(target)
    monkeypatch.setattr(module, "build", lambda: pytest.fail("build must not start"))
    with pytest.raises(module.Refused):
        module.run_parent(output)


def test_build_failure_is_recorded_without_fabricated_child_success(
    tmp_path, monkeypatch
):
    def fail():
        raise FileNotFoundError("private-path")

    monkeypatch.setattr(module, "build", fail)
    output = tmp_path / "failed"
    assert module.run_parent(output) == 2
    record = (output / "parent-result.json").read_text()
    assert "private-path" not in record
    assert json.loads(record)["childReceiptValid"] is False


def test_publication_failure_cannot_return_zero(tmp_path, monkeypatch):
    output, _ = parent_fixture(tmp_path, monkeypatch)
    real = module._publish_new

    def publish(path, value):
        if path.name == "parent-result.json":
            raise OSError("disk-full")
        return real(path, value)

    monkeypatch.setattr(module, "_publish_new", publish)
    with pytest.raises(OSError):
        module.run_parent(output)


@pytest.mark.parametrize(
    "raw", ['{"completed": false, "completed": true}', '{"a":NaN}', '{"a":Infinity}']
)
def test_child_json_rejects_duplicate_keys_and_nonfinite_values(tmp_path, raw):
    file = tmp_path / "child"
    file.write_text(raw)
    with pytest.raises(module.Refused):
        module._read_child_receipt(file)


def test_publisher_never_overwrites_and_removes_temporary_file(tmp_path):
    file = tmp_path / "receipt.json"
    file.write_text("original")
    with pytest.raises(FileExistsError):
        module._publish_new(file, {"ok": True})
    assert file.read_text() == "original"
    assert list(tmp_path.glob(".receipt-*")) == []


@pytest.mark.parametrize(
    "err,expected",
    [
        (errno.ECONNREFUSED, True),
        (errno.ETIMEDOUT, False),
        (errno.EHOSTUNREACH, False),
        (errno.EACCES, False),
    ],
)
def test_only_connection_refusal_proves_closed(monkeypatch, err, expected):
    def connect(*_a, **_k):
        raise OSError(err, "test")

    monkeypatch.setattr(module.socket, "create_connection", connect)
    assert module._socket_closed("http://127.0.0.1:4321") is expected


@pytest.mark.parametrize(
    "origin",
    [
        "http://remote.invalid:9",
        "http://127.0.0.1",
        "http://u@127.0.0.1:9",
        "http://127.0.0.1:9/path",
        "http://127.0.0.1:9#x",
    ],
)
def test_unknown_origin_does_not_become_vacuous_closure(monkeypatch, origin):
    monkeypatch.setattr(
        module.socket,
        "create_connection",
        lambda *_a, **_k: pytest.fail("network reached"),
    )
    assert module._socket_closed(origin) is False


def test_real_open_loopback_listener_is_not_reported_closed():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        origin = f"http://127.0.0.1:{sock.getsockname()[1]}"
        assert module._socket_closed(origin) is False
    assert module._socket_closed(origin) is True


def test_real_owned_process_group_is_stopped_and_reaped():
    child = subprocess.Popen(
        [sys.executable, "-I", "-S", "-c", "import time; time.sleep(60)"],
        start_new_session=True,
    )
    try:
        assert module._stop_owned_process(child) is True
        assert child.poll() is not None
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=2)


def test_reaped_leader_with_unconfirmed_group_is_never_signalled(monkeypatch):
    class Child:
        pid = 54321

        def poll(self):
            return 0

    sent = []
    monkeypatch.setattr(module.os, "killpg", lambda pid, sig: sent.append(sig))
    assert module._stop_owned_process(Child()) is False
    assert sent == [0]


def test_foreign_process_group_is_not_signalled(monkeypatch):
    class Child:
        pid = 54321

        def poll(self):
            return None

    monkeypatch.setattr(module.os, "getpgid", lambda pid: pid + 1)
    monkeypatch.setattr(
        module.os, "killpg", lambda *_: pytest.fail("foreign group signalled")
    )
    assert module._stop_owned_process(Child()) is False
