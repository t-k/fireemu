"""Real Gate/Ledger recovery executor coverage with a bounded loopback server."""

from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "o8-core"))
sys.path.insert(0, str(HERE.parent / "production-admission"))

import o8_admission
import request_bytes_descriptor
import request_bytes_recovery_admission as issuer
import request_bytes_recovery_executor as executor
from test_request_bytes_recovery_admission import _actual_child, _o7_files


class LoopbackHandler(BaseHTTPRequestHandler):
    owned: ClassVar[set[str]] = set()
    versions: ClassVar[dict[str, str]] = {}
    fields: ClassVar[dict[str, dict]] = {}

    def do_GET(self):
        resource = self.path.split("?", 1)[0].removeprefix("/v1/")
        if resource in self.owned:
            payload = {"name": resource, "fields": self.fields[resource], "updateTime": self.versions[resource]}
            self.send_response(200)
        else:
            payload = {"error": {"code": 404, "status": "NOT_FOUND"}}
            self.send_response(404)
        self.send_header("Content-Type", "application/json")
        encoded = json.dumps(payload).encode()
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_DELETE(self):
        resource = self.path.split("?", 1)[0].removeprefix("/v1/")
        self.owned.discard(resource)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *_args):
        return


def _server(owned, versions, fields):
    LoopbackHandler.owned = owned
    LoopbackHandler.versions = versions
    LoopbackHandler.fields = fields
    server = ThreadingHTTPServer(("127.0.0.1", 0), LoopbackHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_port}"


def _redirect_server(target, status):
    class RedirectHandler(BaseHTTPRequestHandler):
        requests = 0

        def do_GET(self):
            type(self).requests += 1
            self.send_response(status)
            self.send_header("Location", target + "/v1/redirected")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_DELETE(self):
            self.do_GET()

        def log_message(self, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_port}", RedirectHandler


def _counting_server():
    class CountingHandler(BaseHTTPRequestHandler):
        requests = 0

        def do_GET(self):
            type(self).requests += 1
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        def do_DELETE(self):
            self.do_GET()

        def log_message(self, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), CountingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_port}", CountingHandler


def _issued_fixture(tmp_path):
    o7, ledger, child_ticket, parent_plan, child_gate_plan, permission = _actual_child(tmp_path)
    inputs = issuer.freeze_inputs(
        ledger,
        child_ticket,
        parent_plan,
        permission,
        selected_probe="under",
        source_commit=o7.commit,
        artifact_sha256=o7.inputs["artifactSha256"],
    )
    files = _o7_files(tmp_path, o7, inputs)
    capability = issuer.issue_production_capability(
        ledger=ledger,
        child_ticket=child_ticket,
        parent_plan=parent_plan,
        child_gate_plan=child_gate_plan,
        selected_probe="under",
        inputs=inputs,
        permission=permission,
        ledger_root=o7.ledger,
        **files,
    )
    return o7, ledger, child_ticket, parent_plan, child_gate_plan, permission, inputs, capability


@pytest.mark.parametrize("owned_count", [0, 3])
def test_real_executor_runs_85_slots_and_settles_child(tmp_path, owned_count):
    _o7, ledger, child_ticket, parent_plan, child_gate_plan, permission, inputs, capability = _issued_fixture(tmp_path)
    operations = child_gate_plan["jobs"][executor.RECOVERY_JOB]["recovery"]
    candidates = [
        operation["resource"]
        for operation in operations
        if operation["kind"] == "recovery-inspection-read"
    ][:3]
    owned = set(candidates[:owned_count])
    versions = {resource: "2026-09-22T00:00:00Z" for resource in owned}
    fields = {
        write["update"]["name"]: write["update"]["fields"]
        for operation in parent_plan["observation"]
        if isinstance(operation.get("body"), dict)
        for write in operation["body"].get("writes", [])
        if isinstance(write.get("update"), dict)
        and write["update"].get("name") in owned
    }
    server, base_url = _server(owned, versions, fields)
    try:
        result = executor.execute_recovery(ledger=ledger, child_ticket=child_ticket, canonical_parent_plan=parent_plan, child_gate_plan=child_gate_plan, capability=capability, inputs=inputs, permission=permission, gate_path=tmp_path / "child-gate", base_url=base_url)
    finally:
        server.shutdown()
        server.server_close()
    assert result["ticket"]["claimDigest"] == child_ticket["claimDigest"]
    state = ledger.snapshot()
    child = state["reservations"][child_ticket["parentReservation"]]["recoveryChildren"][0]
    assert child["state"] == "settled"
    assert capability.consumed is True
    gate_state = json.loads((tmp_path / "child-gate" / "state.json").read_text())
    job = gate_state["jobs"][executor.RECOVERY_JOB]
    events = [event for event in gate_state["events"] if event["phase"] == "recovery"]
    skips = [skip for skip in gate_state["skips"] if skip["job"] == executor.RECOVERY_JOB]
    assert job["recovery"] == 85
    assert len(job["absent"]) == 51
    assert len(events) == 68 + owned_count
    assert len(skips) == 17 - owned_count
    assert all(skip["reason"] == "absent-or-unavailable-cleanup-read" for skip in skips)
    operations_by_index = {
        index: operation
        for index, operation in enumerate(operations)
    }
    assert sum(operations_by_index[event["index"]]["kind"] == "recovery-inspection-read" and event["status"] == 200 for event in events) == owned_count
    assert sum(operations_by_index[event["index"]]["kind"] == "recovery-inspection-read" and event["status"] == 404 for event in events) == 17 - owned_count
    assert sum(operations_by_index[event["index"]]["kind"] == "recovery-conditional-delete" and event["status"] == 200 for event in events) == owned_count
    assert sum(operations_by_index[event["index"]]["kind"] == "recovery-absence-read" and event["status"] == 404 for event in events) == 51


@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_redirect_response_is_rejected_without_following_destination(tmp_path, status):
    _o7, ledger, child_ticket, parent_plan, child_gate_plan, permission, inputs, capability = _issued_fixture(tmp_path)
    target_server, target_url, target_handler = _counting_server()
    redirect_server, redirect_url, redirect_handler = _redirect_server(target_url, status)
    try:
        with pytest.raises(ValueError):
            executor.execute_recovery(
                ledger=ledger,
                child_ticket=child_ticket,
                canonical_parent_plan=parent_plan,
                child_gate_plan=child_gate_plan,
                capability=capability,
                inputs=inputs,
                permission=permission,
                gate_path=tmp_path / "child-gate",
                base_url=redirect_url,
            )
    finally:
        redirect_server.shutdown()
        redirect_server.server_close()
        target_server.shutdown()
        target_server.server_close()
    assert redirect_handler.requests == 1
    assert target_handler.requests == 0


@pytest.mark.parametrize(
    "base_url",
    [
        "https://example.invalid:1234",
        "http://127.0.0.1:1234@remote.invalid",
        "http://127.0.0.1%401234@remote.invalid:80",
        "http://127.0.0.2:1234",
        "http://127.0.0.1:not-a-port",
        "http://127.0.0.1:1234/unexpected",
        "http://127.0.0.1:1234/?foreign=1",
        "http://127.0.0.1:1234/#foreign",
    ],
)
def test_executor_rejects_non_loopback_without_ledger_change(tmp_path, base_url):
    _o7, ledger, child_ticket, parent_plan, child_gate_plan, _permission = _actual_child(tmp_path)
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="loopback"):
        executor.execute_recovery(ledger=ledger, child_ticket=child_ticket, canonical_parent_plan=parent_plan, child_gate_plan=child_gate_plan, capability=None, inputs={}, permission={}, gate_path=tmp_path / "child-gate", base_url=base_url)
    assert ledger.snapshot() == before


def test_executor_rejects_missing_capability_before_gate_write(tmp_path):
    _o7, ledger, child_ticket, parent_plan, child_gate_plan, _permission = _actual_child(tmp_path)
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="active O7 production capability"):
        executor.execute_recovery(ledger=ledger, child_ticket=child_ticket, canonical_parent_plan=parent_plan, child_gate_plan=child_gate_plan, capability=None, inputs={}, permission={}, gate_path=tmp_path / "child-gate", base_url="http://127.0.0.1:1")
    assert ledger.snapshot() == before


@pytest.mark.parametrize("mutation", ["expired", "source", "permission", "host", "bytechange", "consumed"])
def test_post_issue_binding_refusal_has_no_gate_or_ledger_side_effects(tmp_path, monkeypatch, mutation):
    _o7, ledger, child_ticket, parent_plan, child_gate_plan, permission, inputs, capability = _issued_fixture(tmp_path)
    if mutation == "expired":
        import time

        expired = time.time() + 10_000
        monkeypatch.setattr(executor.time, "time", lambda: expired)
    elif mutation == "source":
        source_name = next(iter(inputs["sourceInputs"]))
        inputs["sourceInputs"][source_name] = "0" * 64
    elif mutation == "permission":
        permission["budget"] = {"requests": 1}
    elif mutation == "host":
        monkeypatch.setattr(o8_admission, "execution_host", lambda: {"platform": "foreign", "machine": "foreign"})
    elif mutation == "bytechange":
        monkeypatch.setattr(request_bytes_descriptor.request_bytes_remote_transport, "_WORKER_SHA256", "0" * 64)
    else:
        capability._consume(
            campaign_id=issuer.CAMPAIGN,
            inputs_digest=inputs["inputsDigest"],
            ledger_root=ledger.path,
        )
    before = ledger.snapshot()
    with pytest.raises(ValueError):
        executor.execute_recovery(
            ledger=ledger,
            child_ticket=child_ticket,
            canonical_parent_plan=parent_plan,
            child_gate_plan=child_gate_plan,
            capability=capability,
            inputs=inputs,
            permission=permission,
            gate_path=tmp_path / "child-gate",
            base_url="http://127.0.0.1:1",
        )
    assert ledger.snapshot() == before
    assert not (tmp_path / "child-gate").exists()


def test_foreign_issued_capability_refuses_before_gate_write(tmp_path):
    _o7, ledger, child_ticket, parent_plan, child_gate_plan, permission, inputs, _capability = _issued_fixture(tmp_path / "local")
    _foreign_o7, _foreign_ledger, _foreign_ticket, _foreign_parent, _foreign_gate, _foreign_permission, _foreign_inputs, foreign_capability = _issued_fixture(tmp_path / "foreign")
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="other frozen inputs|shared Ledger"):
        executor.execute_recovery(
            ledger=ledger,
            child_ticket=child_ticket,
            canonical_parent_plan=parent_plan,
            child_gate_plan=child_gate_plan,
            capability=foreign_capability,
            inputs=inputs,
            permission=permission,
            gate_path=tmp_path / "local" / "child-gate",
            base_url="http://127.0.0.1:1",
        )
    assert ledger.snapshot() == before
    assert not (tmp_path / "local" / "child-gate").exists()
