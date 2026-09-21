"""Production mode of the lane wire, without a spawn and without a socket.

Each test names the review mutant it kills (W01..W04). The child's exchange is
driven in-process with a fake opener so the header composition is observable;
nothing here reaches the fixed production origin or any other host.
"""

import email.message
import subprocess
import sys
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import partition_cursor_wire as wire

PATH = "/v1/projects/fireemu-35fe6/databases/(default)/documents/a/b"
REQUEST = {"method": "GET", "path": PATH, "body": None}
TOKEN = "ya29.offline-fixture-token"
ORIGINAL_SPAWN = wire._spawn


@pytest.fixture(autouse=True)
def no_spawn_no_socket(monkeypatch):
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: pytest.fail("must not spawn")
    )
    monkeypatch.setattr(wire, "_spawn", lambda *a, **k: pytest.fail("must not spawn"))


def production_payload(**overrides):
    value = {
        "origin": wire.PRODUCTION_ORIGIN,
        "method": "GET",
        "path": PATH,
        "body": None,
        "seconds": 4.0,
        "mode": "production",
        "bearer": TOKEN,
        "userProject": wire.PRODUCTION_USER_PROJECT,
    }
    value.update(overrides)
    return value


@pytest.mark.parametrize(
    "origin",
    [
        "http://127.0.0.1:8080",
        "http://[::1]:8080",
        "https://127.0.0.1",
        "https://firestore.googleapis.com/",
        "https://firestore.googleapis.com:443",
        "http://firestore.googleapis.com",
        "https://firestore.googleapis.com.evil.example",
        "https://www.googleapis.com",
        None,
    ],
)
def test_the_parent_refuses_every_origin_but_the_fixed_one_in_production_mode(origin):
    """W01 (parent side): `production_request` and `_input` refuse before any
    file or process exists."""
    with pytest.raises(PermissionError, match="fixed production origin"):
        wire.production_request(REQUEST, TOKEN, origin=origin)
    with pytest.raises(PermissionError, match="fixed production origin"):
        wire._input(
            origin,
            REQUEST,
            4.0,
            mode="production",
            bearer=TOKEN,
            user_project=wire.PRODUCTION_USER_PROJECT,
        )


@pytest.mark.parametrize(
    "origin", ["http://127.0.0.1:8080", "http://[::1]:8080", "https://example.invalid"]
)
def test_the_child_refuses_a_production_payload_aimed_at_another_origin(
    monkeypatch, origin
):
    """W01 (child side): `_exchange` re-validates the origin itself, so a
    forged stdin payload cannot steer the child at a loopback or any other
    host."""
    monkeypatch.setattr(
        urllib.request, "build_opener", lambda *a, **k: pytest.fail("must not open")
    )
    with pytest.raises(PermissionError, match="fixed production origin"):
        wire._exchange(production_payload(origin=origin))


def test_the_child_refuses_a_local_payload_carrying_a_credential(monkeypatch):
    monkeypatch.setattr(
        urllib.request, "build_opener", lambda *a, **k: pytest.fail("must not open")
    )
    payload = production_payload(origin="http://127.0.0.1:8080")
    del payload["mode"]
    with pytest.raises(ValueError, match="invalid worker input"):
        wire._exchange(payload)
    with pytest.raises(ValueError, match="carries no credential"):
        wire._input("http://127.0.0.1:8080", REQUEST, 4.0, mode="local", bearer=TOKEN)


@pytest.mark.parametrize(
    "bearer",
    ["", "a" * 8193, "tok en", "tok\nen", "tok\x00en", "tok\x7fen", "töken", 42, None],
)
def test_the_bearer_bounds_are_enforced_on_both_sides(monkeypatch, bearer):
    """W02: a bearer must be non-empty printable ASCII of at most 8192 bytes."""
    monkeypatch.setattr(
        urllib.request, "build_opener", lambda *a, **k: pytest.fail("must not open")
    )
    with pytest.raises(ValueError, match="bounded bearer token"):
        wire.production_request(REQUEST, bearer)
    with pytest.raises(ValueError, match="bounded bearer token"):
        wire._exchange(production_payload(bearer=bearer))


def test_the_quota_project_is_fixed(monkeypatch):
    monkeypatch.setattr(
        urllib.request, "build_opener", lambda *a, **k: pytest.fail("must not open")
    )
    with pytest.raises(ValueError, match="fixed quota project"):
        wire._exchange(production_payload(userProject="another-project"))
    with pytest.raises(ValueError, match="fixed quota project"):
        wire._input(
            wire.PRODUCTION_ORIGIN,
            REQUEST,
            4.0,
            mode="production",
            bearer=TOKEN,
            user_project=None,
        )


@pytest.mark.parametrize(
    "timeout", [5.01, 6, 20, 21, 0, -1, float("nan"), float("inf"), True]
)
def test_the_production_request_ceiling_and_bounds_are_enforced_before_a_spawn(timeout):
    """W03: the whole-worker ceiling is 5 s; a larger or invalid timeout is
    refused before the child exists."""
    with pytest.raises(ValueError):
        wire.production_request(REQUEST, TOKEN, timeout=timeout)


def test_a_deadline_already_passed_is_refused_before_a_spawn():
    import time

    with pytest.raises(ValueError, match="production request deadline"):
        wire.production_request(REQUEST, TOKEN, deadline=time.monotonic() - 1)
    with pytest.raises(ValueError, match="finite absolute deadline"):
        wire.production_request(REQUEST, TOKEN, deadline=float("nan"))


class FakeResponse:
    def __init__(self, raw=b"{}"):
        self.status = 200
        self.headers = email.message.Message()
        self.headers["Content-Type"] = "application/json"
        self.headers["Content-Length"] = str(len(raw))
        self._raw = raw

    def read(self, _limit):
        raw, self._raw = self._raw, b""
        return raw

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


def capture_opener(monkeypatch):
    seen = []

    class Opener:
        def open(self, request, timeout):
            seen.append((request, timeout))
            return FakeResponse()

    monkeypatch.setattr(urllib.request, "build_opener", lambda *handlers: Opener())
    return seen


def test_the_production_child_sends_the_handoff_bearer_and_the_quota_project(
    monkeypatch,
):
    """W04: the child's Authorization header carries the handoff token, never
    the local placeholder, and names the fixed quota project."""
    seen = capture_opener(monkeypatch)
    result = wire._exchange(production_payload())
    assert result["status"] == 200
    ((request, timeout),) = seen
    assert request.full_url == wire.PRODUCTION_ORIGIN + PATH
    assert request.get_header("Authorization") == "Bearer " + TOKEN
    assert request.get_header("X-goog-user-project") == wire.PRODUCTION_USER_PROJECT
    assert request.get_header("Accept") == "application/json"
    assert timeout == 4.0


def test_the_local_child_keeps_the_placeholder_bearer_and_no_quota_project(monkeypatch):
    seen = capture_opener(monkeypatch)
    wire._exchange(
        {
            "origin": "http://127.0.0.1:8080",
            "method": "GET",
            "path": PATH,
            "body": None,
            "seconds": 4.0,
        }
    )
    ((request, _timeout),) = seen
    assert request.get_header("Authorization") == "Bearer owner"
    assert request.get_header("X-goog-user-project") is None
    assert request.full_url == "http://127.0.0.1:8080" + PATH


def test_the_production_payload_never_carries_the_bearer_on_the_command_line(
    monkeypatch,
):
    """The token travels on stdin: the spawned argv is the interpreter, its
    isolation flags and this file, nothing else."""
    captured = {}

    def fake_run(argv, *, input, capture_output, timeout, env, check):
        captured.update(argv=argv, payload=input, env=env, timeout=timeout)
        raise subprocess.TimeoutExpired(argv, timeout)

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(wire, "_spawn", ORIGINAL_SPAWN)
    with pytest.raises(ValueError, match="deadline exceeded"):
        wire.production_request(REQUEST, TOKEN, timeout=3.0)
    assert captured["argv"][1:4] == ["-I", "-S", "-B"]
    assert captured["argv"][4].endswith("partition_cursor_wire.py")
    assert TOKEN not in " ".join(captured["argv"])
    assert TOKEN.encode() in captured["payload"]
    assert set(captured["env"]) <= {"PATH", "LANG", "SYSTEMROOT"}
    assert captured["timeout"] == 3.0
