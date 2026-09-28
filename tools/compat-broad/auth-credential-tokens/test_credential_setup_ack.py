"""Setup ACK failures must not become credential compatibility observations.

The full real runner/collector/comparator are used. The API service, JWTs and
clock are explicit test doubles; no production, Gate, or native-runtime claim.
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
    cleanup_report,
    enter_recovery,
    new_budget,
    new_tracker,
    reserve_request,
)
from credential_comparator import compare
from test_credential_boundary_readback import BASE, NONCE, MemoryPoster

STAGES = ("older-session", "same-second", "claim-precedence", "explicit-revocation")
PRIMARY = {
    "older-session": "revocation-older-session-rejected",
    "same-second": "revocation-same-second-session",
    "claim-precedence": "claim-precedence-session-over-account",
    "explicit-revocation": "refresh-after-explicit-valid-since-rejected",
}
KEPT = dict(zip(STAGES, (3, 4, 16, 18), strict=True))
FAULTS = (
    "refused-400", "refused-403", "refused-429", "refused-503",
    "error-at-200", "wrong-uid", "null-uid", "numeric-uid", "float-status",
)


class SetupPoster(MemoryPoster):
    """Script the four existing admin updates, without adding any wire operation."""

    def __init__(self, stage=None, fault=None):
        super().__init__()
        self.stage, self.fault = stage, fault
        self.updates = 0
        self.injections = 0
        self.injected_at = None
        self.unapplied = None

    def __call__(self, budget, base, path, body, *, owner=False):
        route = path.split("?")[0]
        selected = False
        if not self.recovery and route == "/accounts:update":
            assert owner is True
            stage = STAGES[self.updates]
            self.updates += 1
            selected = stage == self.stage and self.fault is not None
        if selected and self.fault.startswith("refused-"):
            # A genuine refusal: the fake backend does not apply the setup.
            reserve_request(budget, time.monotonic())
            self.calls.append((route, copy.deepcopy(body), owner))
            self.unapplied = copy.deepcopy(self.users[body["localId"]])
            status = int(self.fault.removeprefix("refused-"))
            reply = (status, {"error": {"code": status, "message": "SETUP_REFUSED_DO_NOT_LOG"}})
        else:
            reply = super().__call__(budget, base, path, body, owner=owner)
        if selected:
            self.injections += 1
            assert self.injections == 1, "setup failure must not cause a retry"
            self.injected_at = len(self.calls)
            status, result = reply
            if self.fault == "error-at-200":
                reply = (200, {**result, "error": {"message": "SETUP_DO_NOT_LOG"}})
            elif self.fault == "wrong-uid":
                reply = (200, {"localId": "OTHER-ACCOUNT-DO-NOT-LOG"})
            elif self.fault == "null-uid":
                reply = (200, {"localId": None})
            elif self.fault == "numeric-uid":
                reply = (200, {"localId": 7})
            elif self.fault == "float-status":
                reply = (200.0, result)
            elif self.fault == "omitted-uid":
                reply = (200, {})
            elif self.fault == "additional-fields":
                reply = (200, {**result, "kind": "identitytoolkit#SetAccountInfoResponse", "displayName": "fixture"})
        return reply


def execute(monkeypatch, stage=None, fault=None, poster=None):
    poster = poster or SetupPoster(stage, fault)
    monkeypatch.setattr(shadow, "_rest", poster.wait)
    tracker = new_tracker(NONCE)
    budget = new_budget(60, 600, 0.0, started_monotonic=time.monotonic(),
                        recovery_requests=12, recovery_wall_seconds=60)
    def runner(base, b, t, rows):
        return shadow.run_cases(base, b, t, rows, poster=poster)
    rows, failure = shadow.collect(BASE, budget, tracker, runner=runner)
    return rows, failure, tracker, budget, poster


def finish(rows, failure, tracker, budget, poster):
    count = len(tracker["accounts"])
    poster.recovery = True
    enter_recovery(budget, time.monotonic())
    assert shadow.cleanup(BASE, budget, tracker, poster=poster) == []
    assert len(poster.deleted) == count and not poster.users
    assert cleanup_report(tracker)["cleanupComplete"] is True
    return shadow.finish_record(
        rows=rows, tracker=tracker, budget=budget, failure=failure,
        shutdown={"processStopped": True, "remainingChildren": 0, "exitCode": 0,
                  "outputDrainerStopped": True, "failures": []},
        source_binding={"commit": "SYNTHETIC-SETUP-ACK-036", "artifactSha256": None},
    )


def comparison(record):
    """Only a comparator unit input; fabricated provenance is labelled explicitly."""
    pair = []
    for side in ("local", "production"):
        receipt = copy.deepcopy(record["receipt"])
        receipt.update(side=side, productionExecuted=side == "production",
                       collectorBinding={"syntheticComparatorFixture": "036"})
        pair.append(receipt)
    return compare(*pair)


@pytest.mark.parametrize("stage", STAGES)
@pytest.mark.parametrize("fault", FAULTS)
def test_invalid_setup_ack_stops_before_its_dependent_observation(monkeypatch, stage, fault):
    rows, failure, tracker, budget, poster = execute(monkeypatch, stage, fault)
    assert poster.injections == 1
    assert failure == "ShadowError: local collection failed"
    assert len(rows) == KEPT[stage]
    assert PRIMARY[stage] not in rows
    assert len(poster.calls) == poster.injected_at, "no downstream operation after failed setup"
    record, code = finish(rows, failure, tracker, budget, poster)
    assert code == 1
    assert record["receipt"]["recordingComplete"] is False
    assert record["receipt"]["cleanup"]["cleanupComplete"] is True
    assert record["productionExecuted"] is False
    ordered = record["receipt"]["rows"]
    assert sum(r["errorCode"] == "NOT_RUN" for r in ordered) == 19 - KEPT[stage]
    serialized = json.dumps(record)
    assert "DO_NOT_LOG" not in serialized and "DO-NOT-LOG" not in serialized
    assert all(secret not in serialized for secret in poster.secret_samples)
    report = comparison(record)
    assert report["parityEstablished"] is False
    assert all(r["classification"] != "MATCH" for r in report["rows"] if r["caseId"] == PRIMARY[stage])


def test_successful_campaign_still_runs_nineteen_rows_and_forty_two_requests(monkeypatch):
    rows, failure, tracker, budget, poster = execute(monkeypatch)
    assert failure is None
    assert set(rows) == {case["id"] for case in observation_cases()}
    assert poster.updates == 4
    record, code = finish(rows, failure, tracker, budget, poster)
    assert code == 0 and budget["requests"] == 42
    assert comparison(record)["summary"] == {
        "match": 19, "different": 0, "expectedNondeterminism": 0, "indeterminate": 0,
    }


@pytest.mark.parametrize("stage", STAGES)
@pytest.mark.parametrize("shape", ("omitted-uid", "additional-fields"))
def test_ack_guard_does_not_invent_required_optional_response_fields(monkeypatch, stage, shape):
    rows, failure, tracker, budget, poster = execute(monkeypatch, stage, shape)
    assert failure is None
    _record, code = finish(rows, failure, tracker, budget, poster)
    assert code == 0 and len(rows) == 19 and budget["requests"] == 42


def test_successful_ack_is_not_claimed_to_prove_silent_backend_application(monkeypatch):
    class SilentNoApply(SetupPoster):
        def __call__(self, budget, base, path, body, *, owner=False):
            # An honest-looking 200 is not a readback. Retain the subsequent
            # service behaviour; don't force the hypothesis's expected result.
            if not self.recovery and path == "/accounts:update" and "customAttributes" in body:
                reserve_request(budget, time.monotonic())
                self.calls.append((path, copy.deepcopy(body), owner))
                self.updates += 1
                return 200, {"localId": body["localId"]}
            return super().__call__(budget, base, path, body, owner=owner)
    rows, failure, tracker, budget, poster = execute(monkeypatch, poster=SilentNoApply())
    assert failure is None
    assert rows[PRIMARY["claim-precedence"]]["assertions"]["accountOnlyClaimPresent"] is False
    record, code = finish(rows, failure, tracker, budget, poster)
    assert code == 1  # Local expectation remains unexpected, never filled as true.
    assert record["expectedLocalAgreement"]["unexpected"]


@pytest.mark.parametrize("fault", (None, "refused-400", "wrong-uid"), ids=("complete", "setup-refused", "setup-wrong-user"))
def test_real_http_worker_stops_after_failed_setup_and_cleans_up(monkeypatch, fault):
    """Actual HTTP and Python workers; the server, clock and daemon are test-only."""
    import http.server
    import socket
    import threading

    poster = SetupPoster("claim-precedence" if fault else None, fault)
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
        assert len(calls) == len(poster.calls) == budget["requests"]
        assert all(args == ("-I", "-S", "-B") for args in calls)
        if fault:
            assert failure == "ShadowError: local collection failed"
            assert len(rows) == 16
            assert PRIMARY["claim-precedence"] not in rows
            assert poster.calls[poster.injected_at][0] == "/accounts:delete"
            assert len(calls) == poster.injected_at + 8  # Existing three-account cleanup.
        else:
            assert failure is None and len(rows) == 19
            assert len(calls) == 42
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()
    with socket.socket() as client:
        client.settimeout(1)
        assert client.connect_ex(address) != 0, "fixture listener was not closed"
