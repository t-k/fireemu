"""Retain paid refresh observations if their later fresh-session control fails.

MemoryPoster is an explicit, deterministic service double, adapted from the
032 boundary-readback regression fixture. These are not production receipts.
The complete runner, collector and comparator are imported without import stubs.
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
    reserve_request,
    unobserved_reason,
)
from credential_comparator import compare

BASE = "http://127.0.0.1:19099"
NONCE = "a1" * 16
RESET = "refresh-after-password-reset-rejected"
VALID_SINCE = "refresh-after-explicit-valid-since-rejected"
CASES = [RESET, VALID_SINCE]

class MemoryPoster:
    """Script the existing operation sequence; never perform HTTP."""
    def __init__(self, readback=None, boundary_refused=False):
        self.now = 1_800_000_000
        self.users = {}
        self.sessions = {}
        self.counter = 0
        self.calls = []
        self.deleted = []
        self.readback = readback
        self.boundary_refused = boundary_refused
        self.boundary_uid = None
        self.boundary_token_lookup = False
        self.recovery = False
        self.secret_samples = []

    def wait(self, _budget, seconds):
        self.now += max(1, int(seconds + 0.999))

    def token(self, uid, auth_time, session_claims=None, cookie_duration=None):
        claims = dict(self.users[uid].get('claims', {}))
        claims.update(session_claims or {})
        payload = {
            'sub': uid, 'user_id': uid, 'aud': shadow.PROJECT,
            'iss': f'https://securetoken.google.com/{shadow.PROJECT}',
            'auth_time': auth_time, 'iat': self.now, 'exp': self.now + 3600,
            'firebase': {'identities': {}, 'sign_in_provider': self.users[uid]['provider']},
            **claims,
        }
        if cookie_duration is not None:
            payload.update(iss=f'https://session.firebase.google.com/{shadow.PROJECT}',
                           exp=self.now + cookie_duration)
        token = shadow.unsigned_jwt(payload)
        self.secret_samples.append(token)
        return token

    def issue(self, uid, auth_time=None, session_claims=None, refresh=False):
        if auth_time is None:
            auth_time = self.now
        self.counter += 1
        rt = f'FIXTURE-REFRESH-{self.counter}'
        self.sessions[rt] = (uid, auth_time, dict(session_claims or {}))
        self.secret_samples.append(rt)
        token = self.token(uid, auth_time, session_claims)
        if refresh:
            return {'id_token': token, 'refresh_token': rt, 'expires_in': '3600'}
        return {'localId': uid, 'idToken': token, 'refreshToken': rt, 'expiresIn': '3600'}

    @staticmethod
    def refusal(code):
        return 400, {'error': {'code': 400, 'message': code}}

    def __call__(self, budget, base, path, body, *, owner=False):
        reserve_request(budget, time.monotonic())
        self.calls.append((path.split('?')[0], copy.deepcopy(body), owner))
        path = path.split('?')[0]
        if path == '/accounts:signUp':
            uid = f'fixture-uid-{len(self.users)}'
            self.users[uid] = {'email': body['email'], 'password': body['password'],
                               'validSince': 0, 'provider': 'password', 'claims': {}}
            return 200, {**self.issue(uid), 'email': body['email']}
        if path == '/accounts:signInWithPassword':
            uid = next(uid for uid, u in self.users.items() if u.get('email') == body['email'])
            assert self.users[uid]['password'] == body['password']
            return 200, self.issue(uid)
        if path == '':
            if body['refresh_token'] not in self.sessions:
                return self.refusal('INVALID_REFRESH_TOKEN')
            uid, auth_time, claims = self.sessions[body['refresh_token']]
            if auth_time < self.users[uid]['validSince']:
                return self.refusal('INVALID_REFRESH_TOKEN')
            return 200, self.issue(uid, auth_time, claims, refresh=True)
        if path == '/accounts:update':
            user = self.users[body['localId']]
            if 'validSince' in body:
                user['validSince'] = int(body['validSince'])
            if 'customAttributes' in body:
                user['claims'] = json.loads(body['customAttributes'])
            return 200, {'localId': body['localId']}
        if path == '/accounts:lookup' and owner:
            if 'email' in body:
                users = [{'localId': uid} for uid, u in self.users.items() if u.get('email') in body['email']]
            else:
                users = [{'localId': uid, 'validSince': str(self.users[uid]['validSince'])}
                         for uid in body['localId'] if uid in self.users]
            response = {'users': users}
            if not self.recovery:
                assert self.boundary_uid is None, 'only one observation admin lookup is planned'
                self.boundary_uid = body['localId'][0]
                if self.readback:
                    return self.readback(200, copy.deepcopy(response))
            return 200, response
        if path == '/accounts:lookup':
            _, claims = _jwt_objects(body['idToken'])
            uid = claims['sub']
            if self.boundary_uid == uid and not self.boundary_token_lookup:
                self.boundary_token_lookup = True
                if self.boundary_refused:
                    return self.refusal('TOKEN_EXPIRED')
            if claims['auth_time'] < self.users[uid]['validSince']:
                return self.refusal('TOKEN_EXPIRED')
            return 200, {'users': [{'localId': uid}]}
        if path == '/accounts:signInWithCustomToken':
            _, claims = _jwt_objects(body['token'])
            if 'sub' in claims['claims']:
                return self.refusal('INVALID_CUSTOM_TOKEN')
            if claims['exp'] < time.time():
                return self.refusal('TOKEN_EXPIRED')
            uid = claims['uid']
            assert uid not in self.users
            self.users[uid] = {'validSince': 0, 'provider': 'custom', 'claims': {}}
            issued = self.issue(uid, session_claims=claims['claims'])
            issued.pop('localId')  # Official custom sign-in need not return localId.
            return 200, {**issued, 'isNewUser': True}
        if path == ':createSessionCookie':
            _, claims = _jwt_objects(body['idToken'])
            if claims['auth_time'] < self.users[claims['sub']]['validSince']:
                return self.refusal('TOKEN_EXPIRED')
            duration = int(body.get('validDuration', 1209600))
            if not 300 <= duration <= 1209600:
                return self.refusal('INVALID_DURATION')
            return 200, {'sessionCookie': self.token(claims['sub'], claims['auth_time'],
                         {'role': claims['role']}, cookie_duration=duration)}
        if path == '/accounts:sendOobCode':
            self.reset_email = body['email']
            return 200, {'oobCode': 'FIXTURE-OOB-CODE'}
        if path == '/accounts:resetPassword':
            assert body['oobCode'] == 'FIXTURE-OOB-CODE'
            uid = next(uid for uid, u in self.users.items() if u.get('email') == self.reset_email)
            self.users[uid].update(password=body['newPassword'], validSince=self.now)
            return 200, {'email': self.reset_email}
        if path == '/accounts:delete':
            assert self.recovery
            uid = body['localId']
            self.deleted.append(uid)
            self.users.pop(uid)
            return 200, {}
        raise AssertionError(f'unplanned fixture operation: {path}')



class ControlPoster(MemoryPoster):
    """Inject only at the declared fresh-session control, after its subject row.

    Faults are deterministic exceptions/HTTP replies, never an external request.
    The original request budget is still charged by MemoryPoster/reserve_request.
    """
    def __init__(self, target=None, point="signin", fault="timeout", observed_status=400):
        super().__init__()
        self.target = target
        self.point = point
        self.fault = fault
        self.observed_status = observed_status
        self.active = None
        self.stage = None
        self.after_reset = False
        self.rows = None
        self.control_publication_checks = []
        self.subject_responses = {}
        self.faults = 0

    def __call__(self, budget, base, path, body, *, owner=False):
        route = path.split("?")[0]
        if not self.recovery and self.stage == "subject" and self.active == self.target and self.point == "subject":
            assert route == ""
            reserve_request(budget, time.monotonic())
            self.calls.append((route, copy.deepcopy(body), owner))
            self.faults += 1
            raise TimeoutError("DO-NOT-LOG-FIXTURE-TOKEN")
        if not self.recovery and self.stage in ("signin", "refresh"):
            expected = "/accounts:signInWithPassword" if self.stage == "signin" else ""
            assert route == expected, "fixture must fail at the declared control slot"
            self.control_publication_checks.append((self.active, self.stage, self.active in self.rows))
            if self.active == self.target and self.stage == self.point:
                self.faults += 1
                assert self.faults == 1, "an interrupted control must never be retried"
                if self.fault == "budget":
                    # Exhaust only the observation budget; keep the real recovery reserve.
                    budget["requests"] = budget["maxRequests"] - budget["recoveryRequests"]
                    reserve_request(budget, time.monotonic())
                    raise AssertionError("the real budget limiter did not refuse")
                reserve_request(budget, time.monotonic())
                self.calls.append((route, copy.deepcopy(body), owner))
                if self.fault == "timeout":
                    raise TimeoutError("DO-NOT-LOG-FIXTURE-TOKEN")
                if self.fault == "invalid-response":
                    raise ValueError("DO-NOT-LOG-FIXTURE-TOKEN")
                if self.fault == "http-refusal":
                    self.stage = None
                    return 403, {"error": {"code": 403, "message": "PERMISSION_DENIED: DO-NOT-LOG-FIXTURE-TOKEN"}}
                raise AssertionError("unknown fixture fault")
            result = super().__call__(budget, base, path, body, owner=owner)
            self.stage = "refresh" if self.stage == "signin" else None
            return result

        result = super().__call__(budget, base, path, body, owner=owner)
        if self.recovery:
            return result
        if self.stage == "subject":
            assert route == "", "subject must be a stale-session refresh"
            if self.observed_status == 200:
                result = 200, {"id_token": "DO-NOT-LOG-FIXTURE-TOKEN"}
            elif self.observed_status == 429:
                result = 429, {"error": {"code": 429, "message": "TOO_MANY_ATTEMPTS_TRY_LATER"}}
            self.subject_responses[self.active] = copy.deepcopy(result)
            self.stage = "signin"
        elif route == "/accounts:resetPassword":
            self.active, self.stage, self.after_reset = RESET, "subject", True
        elif route == "/accounts:update" and self.after_reset and "validSince" in body:
            self.active, self.stage = VALID_SINCE, "subject"
        return result


def execute(monkeypatch, target=None, point="signin", fault="timeout", observed_status=400):
    poster = ControlPoster(target, point, fault, observed_status)
    monkeypatch.setattr(shadow, "_rest", poster.wait)
    tracker = new_tracker(NONCE)
    budget = new_budget(60, 600, 0.0, started_monotonic=time.monotonic(),
                        recovery_requests=12, recovery_wall_seconds=60)
    def runner(base, budget, tracker, rows):
        poster.rows = rows
        return shadow.run_cases(base, budget, tracker, rows, poster=poster)
    rows, failure = shadow.collect(BASE, budget, tracker, runner=runner)
    return rows, failure, tracker, budget, poster


def finish(rows, failure, tracker, budget, poster):
    poster.recovery = True
    enter_recovery(budget, time.monotonic())
    assert shadow.cleanup(BASE, budget, tracker, poster=poster) == []
    assert cleanup_report(tracker)["cleanupComplete"] is True
    assert not poster.users
    record, exit_code = shadow.finish_record(
        rows=rows, tracker=tracker, budget=budget, failure=failure,
        shutdown={"processStopped": True, "remainingChildren": 0, "exitCode": 0,
                  "outputDrainerStopped": True, "failures": []},
        source_binding={"commit": "SYNTHETIC-CONTROL-TEST", "artifactSha256": None},
    )
    return record, exit_code


@pytest.mark.parametrize("case_id", CASES)
@pytest.mark.parametrize("point", ["signin", "refresh"])
@pytest.mark.parametrize("fault", ["timeout", "invalid-response", "budget"])
def test_received_subject_survives_a_later_control_exception(monkeypatch, case_id, point, fault):
    rows, failure, tracker, budget, poster = execute(monkeypatch, case_id, point, fault)
    assert poster.faults == 1
    assert failure is not None and "DO-NOT-LOG" not in failure
    assert case_id in rows, "received stale-refresh response was discarded by its later control"
    assert rows[case_id]["status"] == 400
    assert rows[case_id]["errorCode"] == "INVALID_REFRESH_TOKEN"
    assert "freshSessionRefresh" not in rows[case_id]
    assert unobserved_reason(rows[case_id]) is None
    assert all(check[2] for check in poster.control_publication_checks)
    assert len(rows) == (18 if case_id == RESET else 19)
    if case_id == RESET:
        assert VALID_SINCE not in rows
    else:
        assert rows[VALID_SINCE]["diagnostics"]["validSince"] == rows[VALID_SINCE]["diagnostics"]["authTime"] + 2
    record, exit_code = finish(rows, failure, tracker, budget, poster)
    assert exit_code == 1, "retaining a response must not turn failed collection into success"
    assert record["failure"] == failure
    assert record["receipt"]["cleanup"]["remainingAccounts"] == 0
    assert record["productionExecuted"] is False
    ordered = record["receipt"]["rows"]
    assert sum(r["errorCode"] == "NOT_RUN" for r in ordered) == (1 if case_id == RESET else 0)
    assert any(r["caseId"] == case_id for r in record["expectedLocalAgreement"]["unexpected"])
    serialized = json.dumps(record)
    assert "DO-NOT-LOG" not in serialized
    for secret in poster.secret_samples:
        assert secret not in serialized


@pytest.mark.parametrize("case_id", CASES)
def test_control_signin_refusal_keeps_the_subject_row(monkeypatch, case_id):
    rows, failure, tracker, budget, poster = execute(monkeypatch, case_id, "signin", "http-refusal")
    assert failure == "ShadowError: local collection failed"
    assert case_id in rows, "observed subject was lost on sign-in refusal"
    assert rows[case_id]["errorCode"] == "INVALID_REFRESH_TOKEN"
    assert "freshSessionRefresh" not in rows[case_id]
    assert len(rows) == (18 if case_id == RESET else 19)
    assert finish(rows, failure, tracker, budget, poster)[1] == 1


@pytest.mark.parametrize("case_id", CASES)
def test_observed_control_refusal_is_recorded_not_changed_to_success(monkeypatch, case_id):
    rows, failure, tracker, budget, poster = execute(monkeypatch, case_id, "refresh", "http-refusal")
    assert failure is None
    assert rows[case_id]["freshSessionRefresh"] == {"status": 403, "errorCode": "PERMISSION_DENIED"}
    assert rows[case_id]["errorCode"] == "INVALID_REFRESH_TOKEN"
    assert len(rows) == 19
    record, exit_code = finish(rows, failure, tracker, budget, poster)
    assert exit_code == 1
    assert "DO-NOT-LOG" not in json.dumps(record)


@pytest.mark.parametrize("case_id", CASES)
@pytest.mark.parametrize("observed_status", [200, 429])
def test_actual_subject_outcome_is_preserved_without_forcing_expected_refusal(monkeypatch, case_id, observed_status):
    rows, failure, tracker, budget, poster = execute(monkeypatch, case_id, "refresh", "timeout", observed_status)
    assert failure is not None
    assert case_id in rows, "actual subject response was lost on control failure"
    assert rows[case_id]["status"] == observed_status
    assert rows[case_id]["errorCode"] == (None if observed_status == 200 else "TOO_MANY_ATTEMPTS_TRY_LATER")
    record, exit_code = finish(rows, failure, tracker, budget, poster)
    assert exit_code == 1
    assert "DO-NOT-LOG" not in json.dumps(record)


def test_successful_campaign_preserves_nineteen_rows_and_forty_two_calls(monkeypatch):
    rows, failure, tracker, budget, poster = execute(monkeypatch)
    assert failure is None and poster.faults == 0
    assert set(rows) == {c["id"] for c in observation_cases()}
    assert len(poster.control_publication_checks) == 4
    assert all(check[2] for check in poster.control_publication_checks)
    for case_id in CASES:
        assert rows[case_id]["freshSessionRefresh"] == {"status": 200, "errorCode": None}
    record, exit_code = finish(rows, failure, tracker, budget, poster)
    assert exit_code == 0
    assert record["receipt"]["recordingComplete"] is True
    assert budget["requests"] == 42


def synthetic_pair_from_rows(rows):
    # Explicit unit-test pair. This intentionally supplies a synthetic binding,
    # not a forged real build/production receipt and not a provenance validation.
    base = {
        "recordingComplete": True,
        "cleanup": {"cleanupComplete": True, "remainingAccounts": 0,
                    "ownedAccounts": 3, "addressReadbacks": 2},
        "collectorBinding": {"unitTestFixture": "control-failure-only"},
        "rows": [copy.deepcopy(rows[c["id"]]) for c in observation_cases()],
    }
    return [dict(copy.deepcopy(base), side=side, productionExecuted=side == "production")
            for side in ("local", "production")]


@pytest.mark.parametrize("case_id", CASES)
@pytest.mark.parametrize("missing_on", ["local", "production", "both"])
def test_comparator_never_promotes_a_retained_row_with_missing_control(monkeypatch, case_id, missing_on):
    rows, failure, _tracker, _budget, _poster = execute(monkeypatch)
    assert failure is None
    pair = synthetic_pair_from_rows(rows)
    receipts = pair if missing_on == "both" else [pair[0 if missing_on == "local" else 1]]
    for receipt in receipts:
        next(r for r in receipt["rows"] if r["caseId"] == case_id).pop("freshSessionRefresh")
    report = compare(*pair)
    assert report["productionCompared"] is True
    classes = {r["caseId"]: r["classification"] for r in report["rows"]}
    assert classes[case_id] == "INDETERMINATE"
    assert all(value == "MATCH" for key, value in classes.items() if key != case_id)


def test_last_control_interruption_remains_indeterminate_through_comparator(monkeypatch):
    rows, failure, _tracker, _budget, _poster = execute(monkeypatch, VALID_SINCE, "refresh", "timeout")
    assert failure is not None and len(rows) == 19
    report = compare(*synthetic_pair_from_rows(rows))
    assert report["productionCompared"] is True
    classes = {r["caseId"]: r["classification"] for r in report["rows"]}
    assert classes[VALID_SINCE] == "INDETERMINATE"
    assert all(value == "MATCH" for key, value in classes.items() if key != VALID_SINCE)


@pytest.mark.parametrize("case_id", CASES)
def test_subject_without_a_received_response_stays_not_run(monkeypatch, case_id):
    rows, failure, tracker, budget, poster = execute(monkeypatch, case_id, "subject", "timeout")
    assert failure == "TimeoutError: local collection failed"
    assert case_id not in rows
    assert case_id not in poster.subject_responses
    record, exit_code = finish(rows, failure, tracker, budget, poster)
    assert exit_code == 1
    row = next(r for r in record["receipt"]["rows"] if r["caseId"] == case_id)
    assert row["status"] == 0 and row["errorCode"] == "NOT_RUN"
