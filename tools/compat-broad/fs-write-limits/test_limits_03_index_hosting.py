from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import batch_adapter
import compiler_03
import limits_03_descriptor as campaign
import limits_03_preflight as preflight
import pytest


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
    assert [slot["id"] for slot in contract["observation"]][-4:] == [
        "index-lifecycle-before",
        "index-lifecycle-apply",
        "index-lifecycle-poll",
        "index-lifecycle-after",
    ]
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
    response = {"status": 200, "complete": True, "workerReaped": True, "bodyKind": "json", "body": wrong}
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
            if len([entry for entry in seen if entry[0] == "GET"]) == 1:
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
                        "indexes": [],
                        "usesAncestorConfig": True,
                        "ancestorField": preflight.DEFAULT_ANCESTOR_FIELD,
                    },
                    "ttlConfig": {"state": "ENABLED"},
                }
            )

        def do_PATCH(self):
            self._record()
            operation = "op-apply" if len([entry for entry in seen if entry[0] == "PATCH"]) == 1 else "op-restore"
            self._respond({"name": f"projects/fireemu-35fe6/databases/(default)/operations/{operation}"})

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        origin = f"http://127.0.0.1:{server.server_port}"
        field_url = origin + "/v1/projects/fireemu-35fe6/databases/(default)/collectionGroups/nx/fields/*"
        operation_url = origin + "/v1/projects/fireemu-35fe6/databases/(default)/operations/"
        headers = {"Authorization": "Bearer test-token", "Content-Type": "application/json"}

        responses = [
            batch_adapter.wire(field_url, "GET", None, headers, local=True, timeout=3, receipt=True),
            batch_adapter.wire(
                field_url + "?updateMask=indexConfig",
                "PATCH",
                {"name": preflight.LIFECYCLE_FIELD, "indexConfig": {"indexes": []}},
                headers,
                local=True,
                timeout=3,
                receipt=True,
            ),
            batch_adapter.wire(operation_url + "op-apply", "GET", None, headers, local=True, timeout=3, receipt=True),
            batch_adapter.wire(field_url, "GET", None, headers, local=True, timeout=3, receipt=True),
            batch_adapter.wire(
                field_url + "?updateMask=indexConfig",
                "PATCH",
                {"name": preflight.LIFECYCLE_FIELD, "indexConfig": {"indexes": {"usesAncestorConfig": True}}},
                headers,
                local=True,
                timeout=3,
                receipt=True,
            ),
            batch_adapter.wire(operation_url + "op-restore", "GET", None, headers, local=True, timeout=3, receipt=True),
            batch_adapter.wire(field_url, "GET", None, headers, local=True, timeout=3, receipt=True),
        ]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert all(response["http"]["complete"] is True for response in responses)
    assert responses[1]["body"]["name"].endswith("/operations/op-apply")
    assert responses[5]["body"]["name"].endswith("/operations/op-restore")
    assert [entry[0] for entry in seen] == ["GET", "PATCH", "GET", "GET", "PATCH", "GET", "GET"]
    assert all(entry[2] == "Bearer test-token" for entry in seen)
    assert seen[2][1].endswith("/operations/op-apply")
    assert seen[5][1].endswith("/operations/op-restore")
