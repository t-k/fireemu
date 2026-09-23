"""Finite account-lookup evidence regression (no production or native server).

The full runner/collector/comparator are real. API replies, time and JWTs are
explicit in-memory test data; only the two HTTP tests use real loopback transport.
"""

from __future__ import annotations

import copy
import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import credential_collector as collector
import credential_comparator as comparator
import credential_shadow as shadow
from credential_cases import SAME_SECOND_CASE_ID, observation_cases
from test_credential_boundary_readback import BASE, NONCE, MemoryPoster

NEWER = "revocation-newer-session-accepted"
MEASUREMENT = "lookupMatchesAccount"
CASES = (SAME_SECOND_CASE_ID, NEWER)
FAULTS = (
    "empty-body",
    "empty-users",
    "wrong-uid",
    "wrong-tenant",
    "extra-user",
    "missing-uid",
)


class LookupPoster(MemoryPoster):
    """Alter the reply only; the request still carries the correct account token."""

    def __init__(self, case_id=None, fault=None, *, unpinned=False):
        def drift(status, body):
            body["users"][0]["validSince"] = str(
                int(body["users"][0]["validSince"]) + 1
            )
            return status, body

        super().__init__(readback=drift if unpinned else None)
        self.case_id, self.fault = case_id, fault
        self.client_lookups = 0
        self.injected = 0

    def __call__(self, budget, base, path, body, *, owner=False):
        status, result = super().__call__(budget, base, path, body, owner=owner)
        if self.recovery or owner or path.split("?")[0] != "/accounts:lookup":
            return status, result
        self.client_lookups += 1
        case = {2: SAME_SECOND_CASE_ID, 3: NEWER}.get(self.client_lookups)
        if case != self.case_id or self.fault is None:
            return status, result
        self.injected += 1
        assert self.injected == 1, "the measured request must not be retried"
        result = copy.deepcopy(result)
        if self.fault == "empty-body":
            return 200, {}
        if self.fault == "empty-users":
            return 200, {"users": []}
        if self.fault == "wrong-uid":
            result["users"][0]["localId"] = "fixture-uid-0"
        elif self.fault == "wrong-tenant":
            result["users"][0]["tenantId"] = "DO-NOT-LOG-OTHER-TENANT"
        elif self.fault == "extra-user":
            result["users"].append({"localId": "DO-NOT-LOG-OTHER-UID"})
        elif self.fault == "missing-uid":
            result["users"][0].pop("localId")
        elif self.fault == "refused":
            return 400, {"error": {"code": 400, "message": "TOKEN_EXPIRED"}}
        else:
            raise AssertionError("unknown fixture fault")
        return status, result


def execute(monkeypatch, case_id=None, fault=None, *, unpinned=False, signing=True):
    poster = LookupPoster(case_id, fault, unpinned=unpinned)
    monkeypatch.setattr(shadow, "_rest", poster.wait)
    tracker = collector.new_tracker(NONCE)
    budget = collector.new_budget(
        60,
        600,
        0.0,
        started_monotonic=time.monotonic(),
        recovery_requests=12,
        recovery_wall_seconds=60,
    )
    env = shadow.local_environment()
    env["signing"] = signing

    def runner(base, b, t, rows):
        return shadow.run_cases(base, b, t, rows, poster=poster, environment=env)

    rows, failure = shadow.collect(BASE, budget, tracker, runner=runner)
    poster.recovery = True
    collector.enter_recovery(budget, time.monotonic())
    assert shadow.cleanup(BASE, budget, tracker, poster=poster) == []
    assert not poster.users
    assert collector.cleanup_report(tracker)["cleanupComplete"] is True
    record, code = shadow.finish_record(
        rows=rows,
        tracker=tracker,
        budget=budget,
        failure=failure,
        shutdown={
            "processStopped": True,
            "remainingChildren": 0,
            "exitCode": 0,
            "outputDrainerStopped": True,
            "failures": [],
        },
        source_binding={"commit": "SYNTHETIC-LOOKUP-040", "artifactSha256": None},
    )
    return rows, record, code, poster


def compare_records(left, right=None):
    """Synthetic comparator envelopes only; not production or acquisition evidence."""
    receipts = []
    for side, record in (("local", left), ("production", right or left)):
        receipt = copy.deepcopy(record["receipt"])
        receipt.update(
            side=side,
            productionExecuted=side == "production",
            collectorBinding={"syntheticComparatorFixture": "040"},
        )
        receipts.append(receipt)
    return comparator.compare(*receipts)


def classes(report):
    return {row["caseId"]: row["classification"] for row in report["rows"]}


@pytest.mark.parametrize("case_id", CASES)
@pytest.mark.parametrize("fault", FAULTS)
def test_lookup_response_difference_is_not_erased(monkeypatch, case_id, fault):
    _, good, good_code, _ = execute(monkeypatch)
    rows, bad, code, poster = execute(monkeypatch, case_id, fault)
    assert good_code == 0 and code == 1
    assert poster.injected == 1 and len(poster.calls) == 42
    assert len(rows) == 19 and bad["failure"] is None
    assert rows[case_id]["status"] == 200 and rows[case_id]["errorCode"] is None
    assert rows[case_id]["assertions"][MEASUREMENT] is False
    report = compare_records(bad, good)
    classified = classes(report)
    assert classified[case_id] == "DIFFERENT"
    if case_id == NEWER:
        assert classified[SAME_SECOND_CASE_ID] == "INDETERMINATE"
    assert report["parityEstablished"] is False
    encoded = json.dumps(bad)
    assert "DO-NOT-LOG" not in encoded
    for secret in poster.secret_samples:
        assert secret not in encoded


@pytest.mark.parametrize("fault", FAULTS)
def test_two_identical_invalid_positive_controls_do_not_place_a_boundary(
    monkeypatch, fault
):
    rows, record, code, _ = execute(monkeypatch, NEWER, fault)
    assert code == 1 and rows[NEWER]["assertions"][MEASUREMENT] is False
    result = classes(compare_records(record))
    # Agreement as data does not establish a valid positive control.
    assert result[NEWER] == "MATCH"
    assert result[SAME_SECOND_CASE_ID] == "INDETERMINATE"


@pytest.mark.parametrize("fault", ("empty-body", "wrong-uid"))
def test_invalid_lookup_is_not_hidden_as_timing_nondeterminism(monkeypatch, fault):
    _, good, _, _ = execute(monkeypatch, unpinned=True)
    _, bad, code, _ = execute(monkeypatch, SAME_SECOND_CASE_ID, fault, unpinned=True)
    assert code == 1
    assert classes(compare_records(bad, good))[SAME_SECOND_CASE_ID] == "DIFFERENT"
    assert classes(compare_records(bad))[SAME_SECOND_CASE_ID] == "INDETERMINATE"


def test_normal_campaign_keeps_all_cases_and_request_count(monkeypatch):
    rows, record, code, poster = execute(monkeypatch)
    assert code == 0 and record["failure"] is None
    assert len(rows) == len(observation_cases()) == 19
    assert len(poster.calls) == 42 and len(poster.deleted) == 3
    assert all(rows[c]["assertions"][MEASUREMENT] is True for c in CASES)
    assert compare_records(record)["summary"] == {
        "match": 19,
        "different": 0,
        "expectedNondeterminism": 0,
        "indeterminate": 0,
    }


def test_real_timing_difference_with_valid_lookup_keeps_old_classification(monkeypatch):
    rows, record, _code, _ = execute(monkeypatch, unpinned=True)
    assert rows[SAME_SECOND_CASE_ID]["boundaryPinned"] is False
    assert rows[SAME_SECOND_CASE_ID]["assertions"][MEASUREMENT] is True
    assert (
        classes(compare_records(record))[SAME_SECOND_CASE_ID]
        == "EXPECTED_NONDETERMINISM"
    )


@pytest.mark.parametrize("case_id", CASES)
def test_genuine_lookup_refusal_is_recorded_without_synthesizing_a_user(
    monkeypatch, case_id
):
    rows, record, code, _ = execute(monkeypatch, case_id, "refused")
    assert code == 1 and record["failure"] is None
    assert len(rows) == 19
    assert rows[case_id]["status"] == 400
    assert rows[case_id]["errorCode"] == "TOKEN_EXPIRED"
    assert rows[case_id]["assertions"][MEASUREMENT] is False
    result = classes(compare_records(record))
    assert result[case_id] == "MATCH"
    if case_id == NEWER:
        assert result[SAME_SECOND_CASE_ID] == "INDETERMINATE"


@pytest.mark.parametrize("case_id", CASES)
def test_legacy_missing_measurement_is_not_filled_in(monkeypatch, case_id):
    _, record, _, _ = execute(monkeypatch)
    stale = copy.deepcopy(record)
    next(r for r in stale["receipt"]["rows"] if r["caseId"] == case_id)[
        "assertions"
    ].pop(MEASUREMENT)
    before = copy.deepcopy(stale)
    result = classes(compare_records(stale))
    assert stale == before and result[case_id] == "INDETERMINATE"
    assert result[SAME_SECOND_CASE_ID] == "INDETERMINATE"


@pytest.mark.parametrize(
    "status,body,uid",
    [
        (True, {"users": [{"localId": "u"}]}, "u"),
        (200.0, {"users": [{"localId": "u"}]}, "u"),
        ("200", {"users": [{"localId": "u"}]}, "u"),
        (403, {"users": [{"localId": "u"}]}, "u"),
        (200, None, "u"),
        (200, [], "u"),
        (200, {"users": None}, "u"),
        (200, {"users": {"localId": "u"}}, "u"),
        (200, {"users": ["u"]}, "u"),
        (200, {"users": [{"localId": True}]}, "u"),
        (200, {"users": [{"localId": "u", "error": {}}]}, "u"),
        (200, {"users": [{"localId": "u"}], "error": {}}, "u"),
        (200, {"users": [{"localId": "u", "tenantId": False}]}, "u"),
        (200, {"users": [{"localId": "u", "tenantId": []}]}, "u"),
        (200, {"users": [{"localId": "u"}]}, ""),
        (200, {"users": [{"localId": "u"}]}, None),
        (200, {"users": [{"localId": "u"}]}, True),
    ],
)
def test_helper_never_conflates_malformed_reply_with_account_success(status, body, uid):
    before = copy.deepcopy(body)
    assert collector.lookup_matches_account(status, body, uid=uid) is False
    assert body == before


@pytest.mark.parametrize(
    "extra",
    [
        {},
        {"tenantId": None},
        {"tenantId": ""},
        {
            "email": "fixture@example.invalid",
            "emailVerified": True,
            "providerUserInfo": [],
            "validSince": "1800000000",
            "displayName": "fixture",
        },
    ],
)
def test_optional_fields_are_neither_required_nor_copied(extra):
    body = {
        "users": [{"localId": "u", **extra}],
        "kind": "identitytoolkit#GetAccountInfoResponse",
    }
    before = copy.deepcopy(body)
    assert collector.lookup_matches_account(200, body, uid="u") is True
    assert body == before


def test_each_run_uses_its_own_uid_not_a_cross_environment_literal():
    for uid in ("local-fixture", "production-fixture"):
        assert collector.lookup_matches_account(
            200, {"users": [{"localId": uid}]}, uid=uid
        )
    assert not collector.lookup_matches_account(
        200, {"users": [{"localId": "local-fixture"}]}, uid="production-fixture"
    )


def test_no_signing_path_keeps_lookup_measurement_and_recovers(monkeypatch):
    rows, record, code, poster = execute(
        monkeypatch, NEWER, "empty-body", signing=False
    )
    assert len(rows) == 8 and len(poster.deleted) == 2
    assert rows[NEWER]["assertions"][MEASUREMENT] is False
    assert code == 1 and record["failure"] is None


@pytest.mark.parametrize(
    "fault", (None, "wrong-uid"), ids=("complete", "wrong-returned-account")
)
def test_real_http_lookup_records_identity_and_reaps_workers(monkeypatch, fault):
    """Full local HTTP/worker path with synthetic API replies, not native fireemu."""
    import http.server
    import socket
    import threading

    poster = LookupPoster(NEWER if fault else None, fault)
    monkeypatch.setattr(shadow, "_rest", poster.wait)
    server_budget = collector.new_budget(
        60,
        600,
        0.0,
        started_monotonic=time.monotonic(),
        recovery_requests=12,
        recovery_wall_seconds=60,
    )
    errors = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            try:
                length = int(self.headers["Content-Length"])
                assert 0 < length <= 65536
                body = json.loads(self.rfile.read(length))
                admin = f"/identitytoolkit.googleapis.com/v1/projects/{shadow.PROJECT}"
                client = "/identitytoolkit.googleapis.com/v1"
                if self.path.startswith(admin):
                    route = self.path[len(admin) :]
                elif self.path.startswith(client):
                    route = self.path[len(client) :]
                else:
                    assert self.path.startswith("/securetoken.googleapis.com/v1/token?")
                    route = ""
                status, response = poster(
                    server_budget,
                    origin,
                    route,
                    body,
                    owner=self.headers.get("Authorization") == "Bearer owner",
                )
                raw = json.dumps(response).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            except (AssertionError, KeyError, OSError, TypeError, ValueError) as error:
                errors.append(type(error).__name__)
                self.send_error(500)

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    address = server.server_address
    origin = f"http://127.0.0.1:{address[1]}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    spawned = []
    real_popen = shadow.credential_wire.subprocess.Popen

    def tracked_popen(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        spawned.append(process)
        return process

    monkeypatch.setattr(shadow.credential_wire.subprocess, "Popen", tracked_popen)
    try:
        tracker = collector.new_tracker(NONCE)
        budget = collector.new_budget(
            60,
            600,
            0.0,
            started_monotonic=time.monotonic(),
            recovery_requests=12,
            recovery_wall_seconds=60,
        )
        rows, failure = shadow.collect(origin, budget, tracker)
        poster.recovery = True
        collector.enter_recovery(budget, time.monotonic())
        collector.enter_recovery(server_budget, time.monotonic())
        assert shadow.cleanup(origin, budget, tracker) == []
        record, code = shadow.finish_record(
            rows=rows,
            tracker=tracker,
            budget=budget,
            failure=failure,
            shutdown={
                "processStopped": True,
                "remainingChildren": 0,
                "exitCode": 0,
                "outputDrainerStopped": True,
                "failures": [],
            },
            source_binding={
                "commit": "SYNTHETIC-HTTP-LOOKUP-040",
                "artifactSha256": None,
            },
        )
        assert errors == [] and failure is None and len(rows) == 19
        assert len(poster.calls) == budget["requests"] == len(spawned) == 42
        assert all(process.poll() == 0 for process in spawned)
        assert not poster.users and len(poster.deleted) == 3
        assert rows[NEWER]["assertions"][MEASUREMENT] is (fault is None)
        assert code == (1 if fault else 0)
        result = classes(compare_records(record))
        assert result[SAME_SECOND_CASE_ID] == ("INDETERMINATE" if fault else "MATCH")
        encoded = json.dumps(record)
        for secret in poster.secret_samples:
            assert secret not in encoded
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert not thread.is_alive()
    with socket.socket() as sock:
        sock.settimeout(1)
        assert sock.connect_ex(address) != 0
