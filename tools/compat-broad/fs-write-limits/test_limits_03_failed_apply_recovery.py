from __future__ import annotations

import ipaddress
import json
import math
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad/fs-write-txn"))

import batch_adapter
import credential_prep
import limits_03_o8 as launcher
import limits_03_preflight as preflight
import limits_03_remote_transport as remote
import pytest
import shadow_03
import test_limits_03_o8 as o8_fixture


@pytest.mark.parametrize(
    "apply_mode", ["rejected", "possibly-landed", "incomplete-response"]
)
@pytest.mark.parametrize(
    "final_readback", ["exact", "changed", "malformed", "unavailable"]
)
def test_semantic_invalid_apply_runs_gate_bound_restore_and_stays_held(
    tmp_path, monkeypatch, apply_mode, final_readback
):
    """A fully received semantic rejection proves no apply but cannot release."""
    built = o8_fixture.Admission(tmp_path)
    seen = []
    before = {
        "name": preflight.LIFECYCLE_FIELD,
        "indexConfig": {
            "indexes": [{"queryScope": "COLLECTION"}],
            "usesAncestorConfig": True,
            "ancestorField": preflight.DEFAULT_ANCESTOR_FIELD,
        },
        "ttlConfig": {"state": "ENABLED"},
    }
    restored = {"complete": False}
    state = {"field": "before"}

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *_args):
            return

        def _record(self):
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            body = None if not raw else json.loads(raw)
            seen.append((self.command, self.path, body))
            return body

        def _respond(self, body, status=200):
            encoded = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self):
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
            elif self.path == "/v1/projects/fireemu-35fe6":
                self._respond(o8_fixture.PROJECT_BODY)
            elif self.path.rstrip("/").endswith("/databases/(default)"):
                self._respond(o8_fixture.DATABASE_BODY)
            elif "/admin/v2/" in self.path:
                self._respond(o8_fixture.AUTH_BODY)
            elif "/operations/" in self.path:
                self._respond({"name": self.path.removeprefix("/v1/"), "done": True})
            elif "/collectionGroups/nx/fields/" in self.path:
                field_reads = sum(
                    1
                    for method, path, _body in seen
                    if method == "GET" and "/collectionGroups/nx/fields/" in path
                )
                if field_reads == 2:
                    # A rejected apply leaves the real pre-state in place.
                    # Returning the requested exemption here falsely hid the
                    # recovery path's early exit on this semantic failure.
                    self._respond(
                        o8_fixture.EXEMPT_FIELD_BODY
                        if state["field"] == "after"
                        else before
                    )
                elif field_reads >= 3 and final_readback == "unavailable":
                    self._respond({"error": {"status": "UNAVAILABLE"}}, status=503)
                elif field_reads >= 3 and final_readback == "malformed":
                    self._respond({"name": "malformed-resource"})
                elif field_reads >= 3 and final_readback == "changed":
                    changed = json.loads(json.dumps(before))
                    changed["indexConfig"]["usesAncestorConfig"] = False
                    self._respond(changed)
                else:
                    self._respond(before)
            elif "/collectionGroups/pk/fields/" in self.path:
                self._respond(o8_fixture.EXEMPT_FIELD_BODY)
            else:
                pytest.fail(f"unexpected local GET {self.path}")

        def do_PATCH(self):
            body = self._record()
            if "/collectionGroups/nx/fields/" not in self.path:
                pytest.fail(f"unexpected local PATCH {self.path}")
            if "indexConfig" in body:
                if apply_mode == "rejected":
                    # Complete Firestore JSON 400, with no field mutation.
                    self._respond(
                        {"error": {"code": 400, "status": "INVALID_ARGUMENT"}},
                        status=400,
                    )
                elif apply_mode == "incomplete-response":
                    encoded = b'{"error":{"code":400'
                    self.send_response(400)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(encoded) + 16))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(encoded)
                    self.wfile.flush()
                else:
                    # The response is unusable although the exemption landed.
                    state["field"] = "after"
                    self._respond(
                        {
                            "name": (
                                "projects/foreign/databases/(default)/operations/"
                                "op-apply"
                            )
                        }
                    )
                return
            state["field"] = "before"
            restored["complete"] = True
            self._respond(
                {
                    "name": (
                        "projects/fireemu-35fe6/databases/(default)/operations/"
                        "op-restore"
                    )
                }
            )

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
            pytest.fail(f"unexpected local POST {self.path}")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    assert ipaddress.ip_address(host).is_loopback
    origin = f"http://{host}:{port}"
    real_wire = batch_adapter.wire

    def loopback_wire(url, method, body, headers, *, timeout=12, receipt=False):
        parsed = urlsplit(url)
        assert parsed.hostname in {
            "cloudresourcemanager.googleapis.com",
            "firestore.googleapis.com",
            "identitytoolkit.googleapis.com",
        }
        path = parsed.path + ("?" + parsed.query if parsed.query else "")
        return real_wire(
            origin + path,
            method,
            body,
            headers,
            local=True,
            timeout=timeout,
            receipt=receipt,
        )

    real_private_request = credential_prep._private_request

    def loopback_private_request(slot, secret, *, deadline):
        return real_private_request(
            slot, secret, fixture_origin=origin, deadline=deadline
        )

    def forbidden_data_exchange(*_args, **_kwargs):
        raise AssertionError("data transport must not run after rejected apply")

    monkeypatch.setattr(batch_adapter, "wire", loopback_wire)
    monkeypatch.setattr(credential_prep, "_private_request", loopback_private_request)
    monkeypatch.setattr(remote, "_exchange", forbidden_data_exchange)
    try:
        result = launcher.execute(
            launcher.build_parser().parse_args(built.argv(tmp_path))
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    receipt = json.loads((tmp_path / "output/receipt.json").read_bytes())
    gate = json.loads((tmp_path / "output/gate-snapshot.json").read_bytes())
    lifecycle_calls = [
        (method, path, body)
        for method, path, body in seen
        if "/collectionGroups/nx/fields/" in path or "/operations/" in path
    ]
    assert result["failure"] is not None
    assert result["reservationReleased"] is False
    assert result["productionExecuted"] is False
    assert receipt["releaseEligible"] is False
    assert receipt["recoveryAttempted"] is True
    assert restored["complete"] is True
    assert [method for method, _path, _body in lifecycle_calls] == [
        "GET",
        "PATCH",
        "GET",
        "PATCH",
        "GET",
        "GET",
    ]
    assert lifecycle_calls[1][2] == {
        "name": preflight.LIFECYCLE_FIELD,
        "indexConfig": {"indexes": []},
    }
    assert lifecycle_calls[1][1].endswith("?updateMask=indexConfig")
    assert lifecycle_calls[2][1].endswith("/collectionGroups/nx/fields/*")
    assert lifecycle_calls[3][2] == {"name": preflight.LIFECYCLE_FIELD}
    assert lifecycle_calls[3][1].endswith("?updateMask=indexConfig")
    assert lifecycle_calls[4][1].endswith("/operations/op-restore")
    assert lifecycle_calls[5][2] is None
    events = {event["id"]: event for event in gate["managementEvents"]}
    apply = events["observation:index-lifecycle-apply"]
    assert apply["status"] == (200 if apply_mode == "possibly-landed" else 400)
    assert apply["completed"] is (apply_mode != "incomplete-response")
    assert apply["workerReaped"] is True
    assert [
        events["recovery:" + slot]["id"] for slot in preflight.LIFECYCLE_RECOVERY_SLOTS
    ] == ["recovery:" + slot for slot in preflight.LIFECYCLE_RECOVERY_SLOTS]
    assert gate["managementAbort"]["applyOutcome"] == (
        "may-have-landed"
        if apply_mode == "incomplete-response"
        else "coordinator-cancelled"
    )
    evidence = {row["id"]: row["response"] for row in receipt["managementEvidence"]}
    assert state["field"] == "before"
    if apply_mode == "rejected":
        assert evidence["observation:index-lifecycle-apply"]["body"] == {
            "error": {"code": 400, "status": "INVALID_ARGUMENT"}
        }
    if apply_mode in ("rejected", "incomplete-response"):
        exemption = evidence["recovery:index-exemption"]
        assert exemption["body"]["baselineVerified"] is False
        assert exemption["complete"] is True
        assert events["recovery:index-exemption"]["completed"] is True
        assert receipt["indexExemption"]["verifiedAtPostflight"] is False
    if apply_mode in ("rejected", "incomplete-response"):
        assert receipt["postflightComplete"] is False
    restored_evidence = evidence["recovery:index-lifecycle-restored"]["body"]
    if final_readback == "exact":
        assert {
            key: value
            for key, value in restored_evidence.items()
            if key != "_lifecycleApplyDisposition"
        } == before
        expected = (
            "rejected-no-op-restored"
            if apply_mode == "rejected"
            else "uncertain-apply-restored"
        )
    else:
        expected = "restore-unproven"
    assert restored_evidence["_lifecycleApplyDisposition"] == expected
    assert receipt["failure"] is not None


@pytest.mark.parametrize(
    ("operation", "poll", "accepted"),
    [
        (
            {"name": "projects/fireemu-35fe6/databases/(default)/operations/op-apply"},
            {
                "name": "projects/fireemu-35fe6/databases/(default)/operations/op-apply",
                "done": True,
            },
            True,
        ),
        (
            {"name": "projects/fireemu-35fe6/databases/(default)/operations/op-apply"},
            {
                "name": "projects/fireemu-35fe6/databases/(default)/operations/op-other",
                "done": True,
            },
            False,
        ),
        (
            {"name": "projects/other/databases/(default)/operations/op-apply"},
            {
                "name": "projects/other/databases/(default)/operations/op-apply",
                "done": True,
            },
            False,
        ),
    ],
)
def test_saved_lifecycle_poll_is_bound_to_its_apply_operation(
    operation, poll, accepted
):
    if accepted:
        preflight.validate_saved_lifecycle_operation_poll(operation, poll)
    else:
        with pytest.raises(ValueError, match="operation/poll identity"):
            preflight.validate_saved_lifecycle_operation_poll(operation, poll)


@pytest.mark.parametrize("part", ["A", "B", "ALL"])
def test_shadow_supervisor_timeout_covers_the_compiled_gate_window(part):
    from compiler_03 import compile_limits_plan

    plan = compile_limits_plan("demo-firestore-probe", "(default)", "0" * 32, part)
    wall = plan["localGatePlan"]["wallSeconds"]
    assert shadow_03.shadow_execution_timeout(part) == (
        math.ceil(wall) + shadow_03.SHADOW_STARTUP_HEADROOM_SECONDS
    )


def test_shadow_supervisor_rejects_an_undeclared_part():
    with pytest.raises(ValueError, match="closed shadow part"):
        shadow_03.shadow_execution_timeout("C")
