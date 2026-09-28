from __future__ import annotations

import copy
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest
from local_collector import collect_local
from local_store_fixture import LocalTransformStore
from local_transport import local_executor, verify_wire_journal
from transform_compiler import compile_plan


@pytest.fixture
def local_wire():
    plan = compile_plan("demo-local", "(default)", "a" * 32)
    store = LocalTransformStore()
    requests = plan["observation"] + plan["recovery"]
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            operation = copy.deepcopy(requests[len(received)])
            operation["path"] = self.path
            data = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            if data:
                operation["body"] = json.loads(data)
            received.append(
                (self.command, self.path, len(data), self.headers.get("Authorization"))
            )
            receipt = store.execute(operation)
            payload = json.dumps(receipt["body"]).encode()
            self.send_response(receipt["status"])
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        do_PATCH = do_POST = do_DELETE = do_GET

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield plan, f"http://127.0.0.1:{server.server_port}", received
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()


def test_closed_loopback_adapter_records_all_17_real_http_receipts(
    local_wire, tmp_path
):
    plan, origin, received = local_wire
    execute = local_executor(plan, origin, tmp_path / "wire", "a" * 64)
    result = collect_local(plan, execute)
    assert result["recordingComplete"] is result["cleanupComplete"] is True
    assert len(received) == 17
    assert max(size for _, _, size, _ in received) > 16 * 1024
    assert all(auth == "Bearer owner" for _, _, _, auth in received)
    assert verify_wire_journal(plan, result, tmp_path / "wire", "a" * 64) == 17
    receipt = tmp_path / "wire/000-receipt.json"
    value = json.loads(receipt.read_text())
    value["receipt"]["status"] = 200
    receipt.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="receipt"):
        verify_wire_journal(plan, result, tmp_path / "wire", "a" * 64)


@pytest.mark.parametrize(
    "origin",
    [
        "https://firestore.googleapis.com",
        "http://example.com:9999",
        "http://localhost:9999",
        "http://127.0.0.1:9999/path",
    ],
)
def test_remote_or_ambiguous_origins_are_rejected_before_output(origin, tmp_path):
    plan = compile_plan("demo", "(default)", "b" * 32)
    with pytest.raises(ValueError):
        local_executor(plan, origin, tmp_path / "wire", "a" * 64)
    assert not (tmp_path / "wire").exists()


def test_unbound_request_is_rejected_before_wire(local_wire, tmp_path):
    plan, origin, received = local_wire
    execute = local_executor(plan, origin, tmp_path / "wire", "a" * 64)
    request = copy.deepcopy(plan["observation"][0])
    request["privileged"] = 1
    with pytest.raises(ValueError, match="binding"):
        execute(request)
    assert received == []


def test_existing_evidence_directory_is_never_reused(local_wire, tmp_path):
    plan, origin, _ = local_wire
    local_executor(plan, origin, tmp_path / "wire", "a" * 64)
    with pytest.raises(FileExistsError):
        local_executor(plan, origin, tmp_path / "wire", "a" * 64)
