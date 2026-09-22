"""A fresh-session control must return tokens for the intended account.

These tests drive the complete runner with the existing 032 in-memory service.
Only service replies and time are substituted. They do not contact production,
verify JWT signatures, exercise the Gate, or establish production compatibility.
"""
from __future__ import annotations

import copy
import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import credential_shadow as shadow
from credential_cases import observation_cases
from credential_collector import (
    _jwt_objects,
    cleanup_report,
    enter_recovery,
    new_budget,
    new_tracker,
)
from credential_comparator import compare
from test_credential_boundary_readback import BASE, NONCE, MemoryPoster

RESET = "refresh-after-password-reset-rejected"
VALID_SINCE = "refresh-after-explicit-valid-since-rejected"
CASES = (RESET, VALID_SINCE)


class FreshControlPoster(MemoryPoster):
    """Change only a received response at the named control, never a live call."""

    def __init__(self, case_id=None, point="refresh", fault=None):
        super().__init__()
        self.case_id, self.point, self.fault = case_id, point, fault
        self.active = self.stage = None
        self.reset_completed = False
        self.injections = 0

    def _change(self, status, body, point):
        body = copy.deepcopy(body)
        token_key = "idToken" if point == "signin" else "id_token"
        refresh_key = "refreshToken" if point == "signin" else "refresh_token"
        if self.fault == "empty-body":
            return 200, {}
        if self.fault == "missing-id-token":
            body.pop(token_key)
        elif self.fault == "malformed-id-token":
            body[token_key] = "DO-NOT-LOG-INVALID-TOKEN"
        elif self.fault == "empty-refresh-token":
            body[refresh_key] = ""
        elif self.fault == "typed-refresh-token":
            body[refresh_key] = {"secret": "DO-NOT-LOG"}
        elif self.fault == "missing-refresh-token":
            body.pop(refresh_key)
        elif self.fault == "refusal":
            return 403, {"error": {"code": 403, "message": "PERMISSION_DENIED"}}
        elif self.fault in {"wrong-subject", "missing-subject", "wrong-project", "wrong-issuer", "tenant", "no-firebase"}:
            _, claims = _jwt_objects(body[token_key])
            if self.fault == "wrong-subject":
                claims.update(sub="DO-NOT-LOG-OTHER-USER", user_id="DO-NOT-LOG-OTHER-USER")
            elif self.fault == "missing-subject":
                claims.pop("sub")
            elif self.fault == "wrong-project":
                claims["aud"] = "DO-NOT-LOG-OTHER-PROJECT"
            elif self.fault == "wrong-issuer":
                claims["iss"] = "https://DO-NOT-LOG.invalid"
            elif self.fault == "tenant":
                claims["firebase"]["tenant"] = "DO-NOT-LOG-OTHER-TENANT"
            elif self.fault == "no-firebase":
                claims.pop("firebase")
            body[token_key] = shadow.unsigned_jwt(claims)
            self.secret_samples.append(body[token_key])
        else:
            raise AssertionError("undeclared test fault")
        return status, body

    def __call__(self, budget, base, path, body, *, owner=False):
        route = path.split("?")[0]
        stage = self.stage
        result = super().__call__(budget, base, path, body, owner=owner)
        if self.recovery:
            return result
        if stage in ("signin", "refresh"):
            assert route == ("/accounts:signInWithPassword" if stage == "signin" else "")
            self.stage = "refresh" if stage == "signin" else None
            if self.active == self.case_id and stage == self.point and self.fault:
                self.injections += 1
                assert self.injections == 1, "a failed control must not be retried"
                return self._change(*result, stage)
        elif stage == "subject":
            assert route == ""
            self.stage = "signin"
        elif route == "/accounts:resetPassword":
            self.active, self.stage, self.reset_completed = RESET, "subject", True
        elif route == "/accounts:update" and self.reset_completed and "validSince" in body:
            self.active, self.stage = VALID_SINCE, "subject"
        return result


def execute(monkeypatch, case_id=None, point="refresh", fault=None):
    poster = FreshControlPoster(case_id, point, fault)
    monkeypatch.setattr(shadow, "_rest", poster.wait)
    tracker = new_tracker(NONCE)
    budget = new_budget(60, 600, 0.0, started_monotonic=time.monotonic(),
                        recovery_requests=12, recovery_wall_seconds=60)
    def runner(base, b, t, rows):
        return shadow.run_cases(base, b, t, rows, poster=poster)
    rows, failure = shadow.collect(BASE, budget, tracker, runner=runner)
    return rows, failure, tracker, budget, poster


def finish(rows, failure, tracker, budget, poster):
    poster.recovery = True
    enter_recovery(budget, time.monotonic())
    assert shadow.cleanup(BASE, budget, tracker, poster=poster) == []
    assert cleanup_report(tracker)["cleanupComplete"] is True
    assert len(poster.deleted) == 3 and not poster.users
    record, code = shadow.finish_record(
        rows=rows, tracker=tracker, budget=budget, failure=failure,
        shutdown={"processStopped": True, "remainingChildren": 0, "exitCode": 0,
                  "outputDrainerStopped": True, "failures": []},
        source_binding={"commit": "SYNTHETIC-FRESH-CONTROL-TEST", "artifactSha256": None},
    )
    return record, code


def synthetic_pair(record):
    """Comparator unit inputs only; no build, production or acquisition claim."""
    receipts = []
    for side in ("local", "production"):
        item = copy.deepcopy(record["receipt"])
        item.update(side=side, productionExecuted=side == "production",
                    collectorBinding={"syntheticComparatorFixture": "035"})
        receipts.append(item)
    return receipts


BAD_SUCCESS = (
    "empty-body", "missing-id-token", "malformed-id-token", "empty-refresh-token",
    "typed-refresh-token", "missing-refresh-token", "wrong-subject", "missing-subject",
    "wrong-project", "wrong-issuer", "tenant", "no-firebase",
)


@pytest.mark.parametrize("case_id", CASES)
@pytest.mark.parametrize("point", ("signin", "refresh"))
@pytest.mark.parametrize("fault", BAD_SUCCESS)
def test_bad_success_is_not_a_fresh_session_control(monkeypatch, case_id, point, fault):
    rows, failure, tracker, budget, poster = execute(monkeypatch, case_id, point, fault)
    assert poster.injections == 1
    assert failure == "ShadowError: local collection failed", "invalid control passed as a successful refresh"
    assert case_id in rows, "retain the primary observation before validating its control (034)"
    assert rows[case_id]["status"] == 400
    assert rows[case_id]["errorCode"] == "INVALID_REFRESH_TOKEN"
    assert "freshSessionRefresh" not in rows[case_id]
    assert len(rows) == (18 if case_id == RESET else 19)
    record, code = finish(rows, failure, tracker, budget, poster)
    assert code == 1 and record["failure"] is not None
    assert sum(r["errorCode"] == "NOT_RUN" for r in record["receipt"]["rows"]) == (1 if case_id == RESET else 0)
    serialized = json.dumps(record)
    assert "DO-NOT-LOG" not in serialized
    for secret in poster.secret_samples:
        assert secret not in serialized
    report = compare(*synthetic_pair(record))
    classes = {r["caseId"]: r["classification"] for r in report["rows"]}
    assert classes[case_id] == "INDETERMINATE"


def test_genuine_fixture_control_preserves_shape_and_request_budget(monkeypatch):
    rows, failure, tracker, budget, poster = execute(monkeypatch)
    assert failure is None and poster.injections == 0
    for case_id in CASES:
        assert rows[case_id]["freshSessionRefresh"] == {"status": 200, "errorCode": None}
    assert set(rows) == {c["id"] for c in observation_cases()}
    record, code = finish(rows, failure, tracker, budget, poster)
    assert code == 0 and budget["requests"] == 42
    assert compare(*synthetic_pair(record))["summary"] == {
        "match": 19, "different": 0, "expectedNondeterminism": 0, "indeterminate": 0,
    }


@pytest.mark.parametrize("case_id", CASES)
def test_real_control_refusal_remains_observed_data(monkeypatch, case_id):
    rows, failure, tracker, budget, poster = execute(monkeypatch, case_id, "refresh", "refusal")
    assert failure is None
    assert rows[case_id]["freshSessionRefresh"] == {"status": 403, "errorCode": "PERMISSION_DENIED"}
    assert len(rows) == 19
    record, code = finish(rows, failure, tracker, budget, poster)
    assert code == 1
    report = compare(*synthetic_pair(record))
    assert next(r for r in report["rows"] if r["caseId"] == case_id)["classification"] == "INDETERMINATE"


@pytest.mark.parametrize("fault", (None, "wrong-subject"), ids=("complete", "wrong-user-refresh"))
def test_real_http_worker_keeps_control_identity_and_cleanup(monkeypatch, fault):
    """Actual HTTP and Python workers; the server, clock and daemon are test-only."""
    import http.server
    import socket
    import threading

    poster = FreshControlPoster(VALID_SINCE if fault else None, "refresh", fault)
    monkeypatch.setattr(shadow, "_rest", poster.wait)
    server_budget = new_budget(60, 600, 0.0, started_monotonic=time.monotonic(),
                               recovery_requests=12, recovery_wall_seconds=60)
    errors = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            try:
                length = int(self.headers.get("Content-Length", "0"))
                assert 0 < length <= 65536
                request = json.loads(self.rfile.read(length))
                owner = self.headers.get("Authorization") == "Bearer owner"
                admin = f"/identitytoolkit.googleapis.com/v1/projects/{shadow.PROJECT}"
                identity = "/identitytoolkit.googleapis.com/v1"
                if self.path.startswith(admin):
                    path = self.path[len(admin):]
                elif self.path.startswith(identity):
                    path = self.path[len(identity):]
                else:
                    assert self.path.startswith("/securetoken.googleapis.com/v1/token?")
                    path = ""
                status, response = poster(server_budget, origin, path, request, owner=owner)
                raw = json.dumps(response).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            except Exception as error:  # noqa: BLE001
                errors.append(type(error).__name__)  # Never retain a token-bearing message.
                self.send_error(500)

        def log_message(self, *_):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    address = server.server_address
    origin = f"http://127.0.0.1:{address[1]}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    calls = []
    real_run = shadow.credential_wire.subprocess.run

    def counted_run(args, **kwargs):
        # Observe, do not replace, the subprocess. Retain no stdin/response secrets.
        calls.append(tuple(args[1:4]))
        return real_run(args, **kwargs)

    monkeypatch.setattr(shadow.credential_wire.subprocess, "run", counted_run)
    tracker = new_tracker(NONCE)
    budget = new_budget(60, 600, 0.0, started_monotonic=time.monotonic(),
                        recovery_requests=12, recovery_wall_seconds=60)
    try:
        # No injected poster: the real post -> credential_wire -> subprocess -> HTTP path.
        rows, failure = shadow.collect(origin, budget, tracker)
        poster.recovery = True
        enter_recovery(budget, time.monotonic())
        enter_recovery(server_budget, time.monotonic())
        assert shadow.cleanup(origin, budget, tracker) == []
        assert cleanup_report(tracker)["cleanupComplete"] is True
        assert not errors and not poster.users and len(poster.deleted) == 3
        assert len(rows) == 19
        assert len(calls) == len(poster.calls) == budget["requests"] == 42
        assert all(args == ("-I", "-S", "-B") for args in calls)
        if fault:
            assert failure == "ShadowError: local collection failed"
            assert rows[VALID_SINCE]["status"] == 400
            assert "freshSessionRefresh" not in rows[VALID_SINCE]
        else:
            assert failure is None
            assert rows[VALID_SINCE]["freshSessionRefresh"] == {"status": 200, "errorCode": None}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()
    with socket.socket() as client:
        client.settimeout(1)
        assert client.connect_ex(address) != 0, "fixture listener was not closed"
