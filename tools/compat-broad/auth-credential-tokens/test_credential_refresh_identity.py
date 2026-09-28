"""A refresh must be compared to its own account, not just claim names/types.

Full collector/runner/comparator modules are exercised. The service and clock are
explicit doubles from 032; all comparator envelopes are synthetic test fixtures,
not production or source-bound acceptance evidence. No JWT signature is verified.
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
import credential_shadow as shadow
from credential_cases import ASSERTION_NAMES, observation_cases
from credential_comparator import compare
from test_credential_boundary_readback import BASE, NONCE, MemoryPoster
from test_credential_fresh_control import finish, synthetic_pair

MEASUREMENT = "idTokenMatchesAccount"
REFRESH_CASES = {
    "refresh-preserves-auth-time": 1,
    "refresh-repeat-preserves-auth-time": 2,
    # Third exchange is the unknown-token negative; fourth is the custom refresh.
    "claim-precedence-session-over-account": 4,
}


class IdentityPoster(MemoryPoster):
    """Substitute values in ONE received ID token; retain its keys, types and times."""

    def __init__(self, case_id=None, fault=None, *, uid_prefix=""):
        super().__init__()
        self.case_id, self.fault = case_id, fault
        self.refresh_ordinal = 0
        self.injections = 0
        self.uid_prefix = uid_prefix

    def issue(self, uid, *args, **kwargs):
        if self.uid_prefix and uid.startswith("fixture-uid-"):
            # A different legitimate run can allocate different opaque account IDs.
            # Rename the account in the synthetic service before issuing credentials.
            self.users[self.uid_prefix + uid] = self.users.pop(uid)
            uid = self.uid_prefix + uid
        return super().issue(uid, *args, **kwargs)

    def __call__(self, budget, base, path, body, *, owner=False):
        status, response = super().__call__(budget, base, path, body, owner=owner)
        if self.recovery or path != "":
            return status, response
        self.refresh_ordinal += 1
        if self.case_id is None or self.refresh_ordinal != REFRESH_CASES[self.case_id]:
            return status, response
        assert status == 200 and "id_token" in response
        response = copy.deepcopy(response)
        _, claims = collector._jwt_objects(response["id_token"])
        if self.fault == "subject":
            claims.update(sub="DO-NOT-LOG-OTHER-USER", user_id="DO-NOT-LOG-OTHER-USER")
        elif self.fault == "audience":
            claims["aud"] = "DO-NOT-LOG-OTHER-PROJECT"
        elif self.fault == "issuer":
            claims["iss"] = "https://securetoken.google.com/DO-NOT-LOG-OTHER-PROJECT"
        elif self.fault == "user-id":
            claims["user_id"] = "DO-NOT-LOG-OTHER-USER"
        else:
            raise AssertionError("undeclared identity substitution")
        response["id_token"] = shadow.unsigned_jwt(claims)
        self.secret_samples.append(response["id_token"])
        self.injections += 1
        return status, response


def execute(monkeypatch, case_id=None, fault=None, *, uid_prefix=""):
    poster = IdentityPoster(case_id, fault, uid_prefix=uid_prefix)
    monkeypatch.setattr(shadow, "_rest", poster.wait)
    tracker = collector.new_tracker(NONCE)
    budget = collector.new_budget(
        60, 600, 0.0, started_monotonic=time.monotonic(),
        recovery_requests=12, recovery_wall_seconds=60,
    )
    def runner(base, b, t, rows):
        return shadow.run_cases(base, b, t, rows, poster=poster)
    rows, failure = shadow.collect(BASE, budget, tracker, runner=runner)
    assert failure is None, "a measured identity mismatch is not a missing observation"
    assert set(rows) == {case["id"] for case in observation_cases()}
    record, code = finish(rows, failure, tracker, budget, poster)
    assert len(poster.calls) == 42 and budget["requests"] == 42
    return record, code, poster


def pair_of(left_record, right_record):
    """Use actual collected rows inside explicitly synthetic comparison envelopes."""
    pair = synthetic_pair(right_record)
    pair[0]["rows"] = copy.deepcopy(left_record["receipt"]["rows"])
    return pair


def classifications(pair):
    report = compare(*pair)
    assert report["reason"] == "classified"
    assert report["parityEstablished"] is False
    return {row["caseId"]: row["classification"] for row in report["rows"]}


def row(record, case_id):
    return next(item for item in record["receipt"]["rows"] if item["caseId"] == case_id)


@pytest.mark.parametrize("case_id", REFRESH_CASES)
@pytest.mark.parametrize("fault", ("subject", "audience", "issuer", "user-id"))
def test_one_sided_same_shape_identity_substitution_is_a_difference(monkeypatch, case_id, fault):
    good, good_code, _ = execute(monkeypatch)
    bad, bad_code, poster = execute(monkeypatch, case_id, fault)
    assert poster.injections == 1
    # The old names/types-only projection cannot distinguish any of these inputs.
    assert row(good, case_id)["claims"] == row(bad, case_id)["claims"]
    assert classifications(pair_of(bad, good))[case_id] == "DIFFERENT"
    assert classifications(pair_of(good, bad))[case_id] == "DIFFERENT"
    assert good_code == 0 and bad_code == 1
    assert row(bad, case_id)["assertions"][MEASUREMENT] is False
    assert row(good, case_id)["assertions"][MEASUREMENT] is True
    assert bad["receipt"]["recordingComplete"] is True
    assert bad["receipt"]["cleanup"]["cleanupComplete"] is True
    serialized = json.dumps(bad)
    assert "DO-NOT-LOG" not in serialized
    for secret in poster.secret_samples:
        assert secret not in serialized


def test_new_measurement_is_declared_for_only_the_three_refresh_conditions():
    assert MEASUREMENT in ASSERTION_NAMES
    selected = {
        case["id"] for case in observation_cases()
        if MEASUREMENT in case["expectedLocal"]["assertions"]
    }
    assert selected == set(REFRESH_CASES)
    assert len(observation_cases()) == 19


@pytest.mark.parametrize("case_id", REFRESH_CASES)
def test_historical_rows_without_identity_measurement_are_not_promoted(monkeypatch, case_id):
    good, _, _ = execute(monkeypatch)
    pair = pair_of(good, good)
    for receipt in pair:
        next(item for item in receipt["rows"] if item["caseId"] == case_id)["assertions"].pop(MEASUREMENT, None)
    before = copy.deepcopy(pair)
    assert classifications(pair)[case_id] == "INDETERMINATE"
    assert pair == before


@pytest.mark.parametrize("case_id", REFRESH_CASES)
def test_two_measured_false_results_remain_comparable_data(monkeypatch, case_id):
    bad, code, _ = execute(monkeypatch, case_id, "subject")
    assert row(bad, case_id)["assertions"].get(MEASUREMENT) is False
    assert classifications(pair_of(bad, bad))[case_id] == "MATCH"
    # A comparator match does not override the run's failed semantic check or review.
    assert code == 1


def test_different_legitimate_account_ids_between_runs_do_not_create_a_difference(monkeypatch):
    left, code1, _ = execute(monkeypatch)
    right, code2, _ = execute(monkeypatch, uid_prefix="second-run-")
    assert code1 == code2 == 0
    assert set(classifications(pair_of(left, right)).values()) == {"MATCH"}
    assert all(row(right, case_id)["assertions"].get(MEASUREMENT) is True for case_id in REFRESH_CASES)


def payload():
    return {
        "sub": "known-test-account", "user_id": "known-test-account",
        "aud": "known-test-project",
        "iss": "https://securetoken.google.com/known-test-project",
        "firebase": {"sign_in_provider": "password", "identities": {}},
    }


@pytest.mark.parametrize("change", (
    {"sub": "other"}, {"sub": None}, {"aud": "other"}, {"aud": ["known-test-project"]},
    {"iss": "other"}, {"user_id": "other"}, {"firebase": {"tenant": "other"}},
    {"firebase": {"tenant": ""}}, {"firebase": None},
))
def test_helper_rejects_a_measurable_wrong_identity_without_publishing_it(change):
    claims = {**payload(), **change}
    original = copy.deepcopy(claims)
    assert collector.id_token_matches_account(
        shadow.unsigned_jwt(claims), uid="known-test-account", project="known-test-project"
    ) is False
    assert claims == original


def test_helper_accepts_default_namespace_without_optional_user_id():
    claims = payload()
    claims.pop("user_id")
    assert collector.id_token_matches_account(
        shadow.unsigned_jwt(claims), uid="known-test-account", project="known-test-project"
    ) is True


@pytest.mark.parametrize("token", (None, "", "bad.token", 123))
def test_helper_malformed_token_never_proves_identity(token):
    assert collector.id_token_matches_account(
        token, uid="known-test-account", project="known-test-project"
    ) is False


def test_helper_compares_identity_not_the_local_or_signed_trust_root():
    import base64
    claims = payload()
    unsigned = shadow.unsigned_jwt(claims)
    header = base64.urlsafe_b64encode(b'{"alg":"RS256","typ":"JWT"}').rstrip(b"=").decode()
    # Deliberately NOT a valid signature; this helper is not an authentication API.
    synthetic_signed = header + "." + unsigned.split(".")[1] + ".Zml4dHVyZQ"
    for token in (unsigned, synthetic_signed):
        assert collector.id_token_matches_account(
            token, uid="known-test-account", project="known-test-project"
        ) is True


@pytest.mark.parametrize("uid,project", (("", "p"), ("x" * 129, "p"), (True, "p"), ("u", "")))
def test_helper_requires_an_explicit_valid_reference_account(uid, project):
    with pytest.raises(ValueError, match="known account and project required"):
        collector.id_token_matches_account(shadow.unsigned_jwt(payload()), uid=uid, project=project)


@pytest.mark.parametrize("fault", (None, "subject"), ids=("complete", "wrong-subject"))
def test_real_http_worker_records_the_identity_result_and_reclaims_accounts(monkeypatch, fault):
    """Real HTTP/client/child workers, with a synthetic loopback service only."""
    import http.server
    import socket
    import threading

    case_id = "refresh-preserves-auth-time"
    poster = IdentityPoster(case_id if fault else None, fault)
    monkeypatch.setattr(shadow, "_rest", poster.wait)
    server_budget = collector.new_budget(
        60, 600, 0.0, started_monotonic=time.monotonic(),
        recovery_requests=12, recovery_wall_seconds=60,
    )
    failures = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            try:
                length = int(self.headers["Content-Length"])
                assert 0 < length <= 65536
                body = json.loads(self.rfile.read(length))
                admin = f"/identitytoolkit.googleapis.com/v1/projects/{shadow.PROJECT}"
                client = "/identitytoolkit.googleapis.com/v1"
                if self.path.startswith(admin):
                    path = self.path[len(admin):]
                elif self.path.startswith(client):
                    path = self.path[len(client):]
                else:
                    assert self.path.startswith("/securetoken.googleapis.com/v1/token?")
                    path = ""
                status, response = poster(
                    server_budget, origin, path, body,
                    owner=self.headers.get("Authorization") == "Bearer owner",
                )
                raw = json.dumps(response).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            except Exception as error:  # noqa: BLE001
                failures.append(type(error).__name__)  # Never log credential material.
                self.send_error(500)

        def log_message(self, *_):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    address = server.server_address
    origin = f"http://127.0.0.1:{address[1]}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    child_exits = []
    real_run = shadow.credential_wire.subprocess.run

    def counted_run(args, **kwargs):
        result = real_run(args, **kwargs)
        child_exits.append((tuple(args[1:4]), result.returncode))
        return result

    monkeypatch.setattr(shadow.credential_wire.subprocess, "run", counted_run)
    tracker = collector.new_tracker(NONCE)
    budget = collector.new_budget(
        60, 600, 0.0, started_monotonic=time.monotonic(),
        recovery_requests=12, recovery_wall_seconds=60,
    )
    try:
        # No poster injection here: post -> fixed child worker -> actual HTTP.
        rows, failure = shadow.collect(origin, budget, tracker)
        poster.recovery = True
        collector.enter_recovery(budget, time.monotonic())
        collector.enter_recovery(server_budget, time.monotonic())
        assert shadow.cleanup(origin, budget, tracker) == []
        assert collector.cleanup_report(tracker)["cleanupComplete"] is True
        assert failure is None and len(rows) == 19
        assert not failures and not poster.users and len(poster.deleted) == 3
        assert len(child_exits) == len(poster.calls) == budget["requests"] == 42
        assert all(args == ("-I", "-S", "-B") and code == 0 for args, code in child_exits)
        assert rows[case_id]["assertions"][MEASUREMENT] is (fault is None)
        ordered = [rows[case["id"]] for case in observation_cases()]
        unexpected = shadow._agreement(ordered)["unexpected"]
        assert [item["caseId"] for item in unexpected] == ([case_id] if fault else [])
        assert all(secret not in json.dumps(rows) for secret in poster.secret_samples)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()
    with socket.socket() as client:
        client.settimeout(1)
        assert client.connect_ex(address) != 0, "fixture listener was not closed"
