import copy
import json
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import ClassVar

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from commit_remote_transport import prepare, request
from transform_compiler import compile_plan


def payload(index=6, phase="observation", *, token="synthetic-token", local=True):
    nonce = "a" * 32
    plan = compile_plan("demo" if local else "fireemu-35fe6", "(default)", nonce)
    operation = copy.deepcopy(plan[phase][index])
    if phase == "recovery" and operation.get("versionFrom") is not None:
        operation.pop("versionFrom")
        operation["path"] += "?currentDocument.updateTime=2026-01-01T00%3A00%3A00Z"
    value = {"nonce": nonce, "phase": phase, "index": index, "operation": operation, "token": token}
    if local:
        value["localMode"] = True
    return value


def test_prepare_binds_canonical_commit_targets_and_local_namespace():
    value = payload()
    prepared = prepare(value, local_origin="http://127.0.0.1:1234")
    assert prepared["url"].startswith("http://127.0.0.1:1234/v1/projects/demo/")
    assert prepared["method"] == "POST"
    assert prepared["response_cap"] > 0


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["operation"]["body"]["writes"][0]["transform"].update(
            document="projects/foreign/databases/(default)/documents/x/y"
        ),
        lambda value: value["operation"].update(path="https://attacker.invalid/v1/x"),
        lambda value: value["operation"]["body"]["writes"].append({}),
        lambda value: value.update(token="secret\r\nInjected: yes"),
    ],
)
def test_binding_mutations_are_rejected_before_io(mutation):
    value = payload()
    mutation(value)
    with pytest.raises(ValueError):
        prepare(value, local_origin="http://127.0.0.1:1234")


def test_cleanup_requires_exact_resolved_version():
    value = payload(1, "recovery")
    value["operation"]["path"] += "&extra=1"
    with pytest.raises(ValueError):
        prepare(value, local_origin="http://127.0.0.1:1234")


@pytest.mark.parametrize(
    "origin",
    [
        "http://:secret@127.0.0.1:1234",
        "http://user@127.0.0.1:1234",
        "http://user:secret@127.0.0.1:1234",
    ],
)
def test_local_origin_rejects_userinfo_before_io(origin):
    with pytest.raises(ValueError):
        prepare(payload(), local_origin=origin)


class Handler(BaseHTTPRequestHandler):
    received: ClassVar[list] = []
    slow = False

    def do_POST(self):
        self.received.append((self.path, self.headers.get("Authorization")))
        if self.slow:
            time.sleep(2)
        body = json.dumps({"error": {"code": 400, "status": "INVALID_ARGUMENT"}}).encode()
        self.send_response(400)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def test_loopback_complete_four_x_is_retained_and_secret_stays_outside_argv(tmp_path):
    Handler.received = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        value = payload()
        result = request(value, local_origin=f"http://127.0.0.1:{server.server_port}")
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
    assert result["complete"] is True
    assert result["status"] == 400
    assert result["body"]["error"]["status"] == "INVALID_ARGUMENT"
    assert Handler.received[-1][1] == "Bearer synthetic-token"


def test_worker_rejects_foreign_binding_without_echoing_secret():
    value = payload()
    value["operation"]["path"] = "https://attacker.invalid/v1/foreign"
    completed = subprocess.run(
        [sys.executable, "-I", str(Path(__file__).with_name("commit_remote_transport.py")), "--worker"],
        input=json.dumps({"value": value, "localOrigin": "http://127.0.0.1:1", "timeout": 1}),
        text=True,
        capture_output=True,
        env={},
        timeout=5,
        check=False,
    )
    assert completed.returncode != 0
    assert "synthetic-token" not in completed.stdout + completed.stderr
    assert completed.stdout == completed.stderr == ""


def test_loopback_trickle_is_hard_deadline_bounded():
    Handler.slow = True
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = request(payload(), local_origin=f"http://127.0.0.1:{server.server_port}", timeout=0.2)
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
        Handler.slow = False
    assert result["complete"] is False
    assert result["kind"] == "deadline-exceeded"
