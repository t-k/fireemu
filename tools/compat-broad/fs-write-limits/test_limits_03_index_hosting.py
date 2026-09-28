from __future__ import annotations

import http.client
import ipaddress
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "fs-write-txn"))

import batch_adapter
import compiler_03
import credential_prep
import limits_03_descriptor as campaign
import limits_03_o8 as launcher
import limits_03_preflight as preflight
import limits_03_remote_transport as remote
import pytest
import test_limits_03_o8 as o8_fixture


def test_one_poll_lifecycle_is_compiled_as_seven_charged_slots() -> None:
    contract = campaign.lifecycle_contract()
    assert contract["pollLimit"] == 1
    assert contract["observationSlots"] == 4
    assert contract["recoverySlots"] == 3
    assert compiler_03.management_contract()["totalRequests"] == 16
    assert campaign.budget_figures()["requestUpperBound"] == 192
    assert campaign.budget_figures()["envelopeCostMicrousd"] == 59_200


def test_lifecycle_management_ids_are_closed_and_ordered() -> None:
    contract = compiler_03.management_contract()
    observation = [slot["id"] for slot in contract["observation"]]
    assert observation[3:7] == [
        "index-lifecycle-before",
        "index-lifecycle-apply",
        "index-lifecycle-poll",
        "index-lifecycle-after",
    ]
    assert observation[7:] == ["index-exemption", "auth"]
    assert [slot["id"] for slot in contract["recovery"]][-3:] == [
        "index-lifecycle-restore",
        "index-lifecycle-poll-restore",
        "index-lifecycle-restored",
    ]


def test_hosted_baseline_rejects_wrong_ancestor_before_data() -> None:
    session = preflight.ManagementSession.__new__(preflight.ManagementSession)
    session._lifecycle = {}
    session.lifecycle_failed = False
    wrong = {
        "name": preflight.LIFECYCLE_FIELD,
        "indexConfig": {
            "indexes": [{"queryScope": "BAD"}],
            "usesAncestorConfig": True,
            "ancestorField": "projects/attacker/databases/(default)/collectionGroups/__default__/fields/*",
        },
        "ttlConfig": {"state": "ENABLED"},
    }
    response = {
        "status": 200,
        "complete": True,
        "workerReaped": True,
        "bodyKind": "json",
        "body": wrong,
    }
    with pytest.raises(ValueError, match="inherited field"):
        session._accept_lifecycle_response("index-lifecycle-before", response)


def test_lifecycle_transport_reaches_real_loopback_batch_wire() -> None:
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            return

        def _respond(self, body):
            encoded = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def _record(self):
            length = int(self.headers.get("Content-Length", "0"))
            payload = self.rfile.read(length)
            seen.append(
                (
                    self.command,
                    self.path,
                    self.headers.get("Authorization"),
                    None if not payload else json.loads(payload),
                )
            )

        def do_GET(self):
            self._record()
            if "/operations/" in self.path:
                self._respond({"name": self.path.removeprefix("/v1/"), "done": True})
                return
            field_reads = len(
                [
                    entry
                    for entry in seen
                    if entry[0] == "GET" and "/operations/" not in entry[1]
                ]
            )
            if field_reads == 1:
                self._respond(
                    {
                        "name": preflight.LIFECYCLE_FIELD,
                        "indexConfig": {
                            "indexes": [{"queryScope": "COLLECTION"}],
                            "usesAncestorConfig": True,
                            "ancestorField": preflight.DEFAULT_ANCESTOR_FIELD,
                        },
                        "ttlConfig": {"state": "ENABLED"},
                    }
                )
                return
            self._respond(
                {
                    "name": preflight.LIFECYCLE_FIELD,
                    "indexConfig": {
                        "indexes": []
                        if field_reads == 2
                        else [{"queryScope": "COLLECTION"}],
                        "usesAncestorConfig": field_reads != 2,
                        "ancestorField": preflight.DEFAULT_ANCESTOR_FIELD,
                    },
                    "ttlConfig": {"state": "ENABLED"},
                }
            )

        def do_PATCH(self):
            self._record()
            operation = (
                "op-apply"
                if len([entry for entry in seen if entry[0] == "PATCH"]) == 1
                else "op-restore"
            )
            self._respond(
                {"name": f"projects/fireemu-35fe6/databases/(default)/operations/{operation}"}
            )

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        origin = f"http://127.0.0.1:{server.server_port}"
        field_url = (
            origin
            + "/v1/projects/fireemu-35fe6/databases/(default)/collectionGroups/nx/fields/*"
        )
        operation_url = (
            origin + "/v1/projects/fireemu-35fe6/databases/(default)/operations/"
        )
        headers = {
            "Authorization": "Bearer test-token",
            "Content-Type": "application/json",
        }

        responses = [
            batch_adapter.wire(
                field_url, "GET", None, headers, local=True, timeout=3, receipt=True
            ),
            batch_adapter.wire(
                field_url + "?updateMask=indexConfig",
                "PATCH",
                {"name": preflight.LIFECYCLE_FIELD, "indexConfig": {"indexes": []}},
                headers,
                local=True,
                timeout=3,
                receipt=True,
            ),
            batch_adapter.wire(
                operation_url + "op-apply",
                "GET",
                None,
                headers,
                local=True,
                timeout=3,
                receipt=True,
            ),
            batch_adapter.wire(
                field_url, "GET", None, headers, local=True, timeout=3, receipt=True
            ),
            batch_adapter.wire(
                field_url + "?updateMask=indexConfig",
                "PATCH",
                {
                    "name": preflight.LIFECYCLE_FIELD,
                    "indexConfig": {
                        "indexes": [{"queryScope": "COLLECTION"}],
                        "usesAncestorConfig": True,
                        "ancestorField": preflight.DEFAULT_ANCESTOR_FIELD,
                    },
                },
                headers,
                local=True,
                timeout=3,
                receipt=True,
            ),
            batch_adapter.wire(
                operation_url + "op-restore",
                "GET",
                None,
                headers,
                local=True,
                timeout=3,
                receipt=True,
            ),
            batch_adapter.wire(
                field_url, "GET", None, headers, local=True, timeout=3, receipt=True
            ),
        ]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert all(response["http"]["complete"] is True for response in responses)
    assert responses[1]["body"]["name"].endswith("/operations/op-apply")
    assert responses[5]["body"]["name"].endswith("/operations/op-restore")
    assert [entry[0] for entry in seen] == [
        "GET",
        "PATCH",
        "GET",
        "GET",
        "PATCH",
        "GET",
        "GET",
    ]
    assert all(entry[2] == "Bearer test-token" for entry in seen)
    assert seen[2][1].endswith("/operations/op-apply")
    assert seen[5][1].endswith("/operations/op-restore")


@pytest.mark.parametrize(
    "fault", ["normal", "lost-apply", "after-mismatch", "poll-invalid", "foreign-operation"]
)
def test_management_session_runs_real_gate_lifecycle_over_loopback(
    tmp_path, monkeypatch, fault
):
    """The real Gate and temporary Ledger charge all lifecycle calls through batch_wire."""
    built = o8_fixture.Admission(tmp_path)
    seen = []
    state = {"field": "before"}
    responder = o8_fixture.ExemptResponder()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *_args):
            return

        def _body(self):
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            return None if not raw else json.loads(raw)

        def _respond(self, body, status=200):
            encoded = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(encoded)

        def _record(self):
            self.request_body = self._body()
            seen.append(
                (
                    self.command,
                    self.path,
                    self.headers.get("Authorization"),
                    self.request_body,
                )
            )

        def do_GET(self):
            self._record()
            if "/operations/" in self.path:
                body = {"name": self.path.removeprefix("/v1/"), "done": True}
                if fault == "poll-invalid" and "op-apply" in self.path:
                    body["error"] = {"status": "FAILED_PRECONDITION"}
                self._respond(body)
            elif "/collectionGroups/nx/fields/" in self.path:
                field_reads = len(
                    [
                        entry
                        for entry in seen
                        if entry[0] == "GET"
                        and "/collectionGroups/nx/fields/" in entry[1]
                    ]
                )
                if state["field"] == "before":
                    inherited = True
                elif fault in ("normal", "after-mismatch") and field_reads == 2:
                    inherited = False
                else:
                    self._respond(
                        {
                            "name": preflight.INDEX_FIELD,
                            "indexConfig": {
                                "indexes": [],
                                "usesAncestorConfig": False,
                                "ancestorField": preflight.DEFAULT_ANCESTOR_FIELD,
                            },
                        }
                    )
                    return
                self._respond(
                    {
                        "name": preflight.LIFECYCLE_FIELD,
                        "indexConfig": {
                            "indexes": (
                                [{"queryScope": "COLLECTION"}]
                                if inherited or fault == "after-mismatch"
                                else []
                            ),
                            "usesAncestorConfig": inherited,
                            "ancestorField": preflight.DEFAULT_ANCESTOR_FIELD,
                        },
                        "ttlConfig": {"state": "ENABLED"},
                    }
                )
            elif "/collectionGroups/pk/fields/" in self.path:
                self._respond(
                    {
                        "name": preflight.INDEX_FIELD,
                        "indexConfig": {
                            "indexes": [],
                            "usesAncestorConfig": False,
                            "ancestorField": preflight.DEFAULT_ANCESTOR_FIELD,
                        },
                    }
                )
            elif self.path.rstrip("/").endswith("/databases/(default)"):
                self._respond(o8_fixture.DATABASE_BODY)
            elif "/admin/v2/" in self.path:
                self._respond(o8_fixture.AUTH_BODY)
            elif self.path == "/v1/projects/fireemu-35fe6":
                self._respond(o8_fixture.PROJECT_BODY)
            else:
                result = responder(
                    {"method": "GET", "path": self.path, "body": None},
                    state["field"] == "before",
                    0,
                    0,
                )
                self._respond(result["body"], result["status"])

        def do_PATCH(self):
            self._record()
            if "/collectionGroups/nx/fields/" in self.path:
                if state["field"] == "before":
                    state["field"] = "after"
                    operation = "op-foreign" if fault == "foreign-operation" else "op-apply"
                else:
                    state["field"] = "before"
                    operation = "op-restore"
                project = "foreign" if operation == "op-foreign" else "fireemu-35fe6"
                self._respond(
                    {
                        "name": f"projects/{project}/databases/(default)/operations/{operation}"
                    }
                )
                return
            result = responder(
                {"method": "PATCH", "path": self.path, "body": self.request_body},
                state["field"] == "before",
                0,
                0,
            )
            self._respond(result["body"], result["status"])

        def do_POST(self):
            self._record()
            if "/oauth2/" in self.path:
                self._respond(
                    {
                        "issued_to": "offline-client",
                        "user_id": "offline-subject",
                        "scope": preflight.SCOPE,
                        "expires_in": 3600,
                    }
                )
                return
            result = responder(
                {"method": "POST", "path": self.path, "body": self.request_body},
                state["field"] == "before",
                0,
                0,
            )
            self._respond(result["body"], result["status"])

        def do_DELETE(self):
            self._record()
            result = responder(
                {"method": "DELETE", "path": self.path, "body": None},
                state["field"] == "before",
                0,
                0,
            )
            self._respond(result["body"], result["status"])

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    loopback_host = server.server_address[0]
    assert ipaddress.ip_address(loopback_host).is_loopback
    origin = f"http://{loopback_host}:{server.server_port}"
    real_wire = batch_adapter.wire

    def loopback_wire(url, method, body, headers, *, timeout=12, receipt=False):
        nonlocal lost_apply_response
        parsed = urlsplit(url)
        assert parsed.scheme == "https"
        assert parsed.hostname in {
            "cloudresourcemanager.googleapis.com",
            "firestore.googleapis.com",
            "identitytoolkit.googleapis.com",
        }
        path = parsed.path + ("?" + parsed.query if parsed.query else "")
        result = real_wire(
            origin + path,
            method,
            body,
            headers,
            local=True,
            timeout=timeout,
            receipt=receipt,
        )
        if (
            fault == "lost-apply"
            and not lost_apply_response
            and method == "PATCH"
            and path.endswith("?updateMask=indexConfig")
        ):
            lost_apply_response = True
            return {
                "http": {"complete": False, "bodyKind": None, "status": None},
                "body": None,
            }
        return result

    original_private_request = credential_prep._private_request

    def loopback_private_request(slot, secret, *, deadline):
        return original_private_request(
            slot, secret, fixture_origin=origin, deadline=deadline
        )

    wire_observations = []

    lost_apply_response = False

    def loopback_exchange(url, method, body, headers, deadline, response_cap):
        nonlocal lost_apply_response
        parsed = urlsplit(url)
        assert parsed.hostname == "firestore.googleapis.com"
        loopback_host = server.server_address[0]
        assert ipaddress.ip_address(loopback_host).is_loopback
        path = parsed.path + ("?" + parsed.query if parsed.query else "")
        wire_observations.append((method, path, deadline, response_cap))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError("loopback data deadline exceeded")
        connection = http.client.HTTPConnection(
            loopback_host,
            server.server_port,
            timeout=remaining,
        )
        try:
            connection.request(
                method,
                path,
                body=body,
                headers=headers,
            )
            response = connection.getresponse()
            if 300 <= response.status < 400 or not response.will_close:
                raise ValueError(
                    "loopback response must be non-redirecting and closing"
                )
            raw = response.read(response_cap + 1)
            if len(raw) > response_cap:
                raise ValueError("loopback response cap exceeded")
            return response.status, response.getheader("Content-Type", ""), raw, None
        finally:
            connection.close()

    monkeypatch.setattr(batch_adapter, "wire", loopback_wire)
    monkeypatch.setattr(credential_prep, "_private_request", loopback_private_request)
    monkeypatch.setattr(remote, "_exchange", loopback_exchange)
    try:
        result = launcher.execute(
            launcher.build_parser().parse_args(built.argv(tmp_path))
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    output = tmp_path / "output"
    receipt = json.loads((output / "receipt.json").read_bytes())
    gate = json.loads((output / "gate-snapshot.json").read_bytes())
    lifecycle_paths = [
        path
        for _, path, _, _ in seen
        if "/collectionGroups/nx/fields/" in path or "/operations/" in path
    ]
    if fault == "lost-apply":
        assert result["failure"] == "management-observation-aborted"
        assert result["reservationReleased"] is False
        assert receipt["releaseEligible"] is False
        assert gate["managementAbort"]["applyOutcome"] == "may-have-landed"
        assert len(wire_observations) == 0
        assert len(lifecycle_paths) == 6
        assert lifecycle_paths[0].endswith("/collectionGroups/nx/fields/*")
        assert lifecycle_paths[1].endswith("?updateMask=indexConfig")
        assert lifecycle_paths[2].endswith("/collectionGroups/nx/fields/*")
        assert lifecycle_paths[3].endswith("?updateMask=indexConfig")
        assert lifecycle_paths[4].endswith("/operations/op-restore")
        assert lifecycle_paths[5].endswith("/collectionGroups/nx/fields/*")
        assert state["field"] == "before"
    elif fault == "normal":
        assert result["failure"] is None
        assert result["reservationReleased"] is True
        assert len(gate["managementEvents"]) == 16
        assert len(lifecycle_paths) == 9
        assert lifecycle_paths[1].endswith("?updateMask=indexConfig")
        assert lifecycle_paths[2].endswith("/operations/op-apply")
        assert lifecycle_paths[6].endswith("?updateMask=indexConfig")
        assert lifecycle_paths[7].endswith("/operations/op-restore")
    else:
        assert result["failure"] == "management-observation-aborted"
        assert result["reservationReleased"] is False
        assert receipt["releaseEligible"] is False
        assert gate["managementAbort"]["applyOutcome"] == "coordinator-cancelled"
        assert wire_observations == []
        assert state["field"] == "before"
    firestore_requests = [entry for entry in seen if entry[1].startswith("/v1/")]
    assert firestore_requests
    assert all(
        entry[2] == "Bearer " + o8_fixture.TOKEN for entry in firestore_requests
    ), [(entry[1], entry[2]) for entry in firestore_requests]
    assert all(deadline > 0 for _, _, deadline, _ in wire_observations)
    if fault == "normal":
        assert wire_observations
        assert receipt["collection"]["cleanupComplete"] is True
    assert responder.documents == {}
