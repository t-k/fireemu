"""Same-second observation must use the requested account's typed readback.

The API is an explicit in-memory test double. Tokens are synthetic unsigned JWTs;
this exercises the real runner/collector, not native fireemu or production.
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
from credential_cases import SAME_SECOND_CASE_ID, observation_cases
from credential_collector import (
    _jwt_objects,
    cleanup_report,
    enter_recovery,
    new_budget,
    new_tracker,
    reserve_request,
)

BASE = 'http://127.0.0.1:19099'
NONCE = 'a1' * 16


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


def execute(monkeypatch, readback=None, *, boundary_refused=False):
    poster = MemoryPoster(readback, boundary_refused)
    monkeypatch.setattr(shadow, '_rest', poster.wait)
    tracker = new_tracker(NONCE)
    budget = new_budget(60, 600, 0.0, started_monotonic=time.monotonic(),
                        recovery_requests=12, recovery_wall_seconds=60)
    def runner(base, budget, tracker, rows):
        return shadow.run_cases(base, budget, tracker, rows, poster=poster)
    rows, failure = shadow.collect(BASE, budget, tracker, runner=runner)
    return rows, failure, tracker, budget, poster


def changed_user(**changes):
    def apply(status, body):
        body['users'][0].update(changes)
        return status, body
    return apply


def test_complete_valid_campaign_keeps_all_nineteen_rows(monkeypatch):
    rows, failure, tracker, budget, poster = execute(monkeypatch)
    assert failure is None
    assert set(rows) == {c['id'] for c in observation_cases()}
    ordered = [rows[c['id']] for c in observation_cases()]
    assert shadow._agreement(ordered)['unexpected'] == []
    assert rows[SAME_SECOND_CASE_ID]['boundaryPinned'] is True
    assert len(tracker['accounts']) == 3
    poster.recovery = True
    enter_recovery(budget, time.monotonic())
    assert shadow.cleanup(BASE, budget, tracker, poster=poster) == []
    assert cleanup_report(tracker)['cleanupComplete'] is True
    assert not poster.users
    assert budget['requests'] == 42  # Existing sequence; no added network requests.


BAD_READBACKS = [
    ('wrong-uid', changed_user(localId='OTHER-ACCOUNT-DO-NOT-LOG')),
    ('wrong-tenant', changed_user(tenantId='OTHER-TENANT-DO-NOT-LOG')),
    ('missing-uid', lambda s, b: (s, {'users': [{'validSince': b['users'][0]['validSince']}]})),
    ('extra-user', lambda s, b: (s, {'users': [b['users'][0], copy.deepcopy(b['users'][0])]})),
    ('empty-users', lambda s, b: (s, {'users': []})),
    ('missing-users', lambda s, b: (s, {})),
    ('null-users', lambda s, b: (s, {'users': None})),
    ('non-object-user', lambda s, b: (s, {'users': ['not-an-account']})),
    ('error-envelope', lambda s, b: (s, {**b, 'error': {'message': 'DO-NOT-LOG'}})),
    ('wrong-status', lambda s, b: (403, b)),
    ('string-status', lambda s, b: ('200', b)),
    ('float-status', lambda s, b: (200.0, b)),
    ('boolean-second', changed_user(validSince=True)),
    ('float-second', changed_user(validSince=1800000000.0)),
    ('missing-second', lambda s, b: (s, {'users': [{'localId': b['users'][0]['localId']}]})),
    ('null-second', changed_user(validSince=None)),
    ('bad-second', changed_user(validSince='not-a-second-DO-NOT-LOG')),
    ('oversized-second', changed_user(validSince='9' * 33)),
    ('int64-overflow', changed_user(validSince=str(1 << 63))),
    ('int64-underflow', changed_user(validSince=-(1 << 63) - 1)),
]


@pytest.mark.parametrize('name,readback', BAD_READBACKS, ids=[x[0] for x in BAD_READBACKS])
def test_invalid_readback_is_not_a_pinned_or_nondeterministic_observation(monkeypatch, name, readback):
    rows, failure, tracker, _budget, poster = execute(monkeypatch, readback)
    assert failure == 'ShadowError: local collection failed'
    assert SAME_SECOND_CASE_ID not in rows
    assert len(rows) == 4  # Preserve the first three refresh rows and older-session control.
    assert poster.boundary_token_lookup is False
    assert len(tracker['accounts']) == 2
    assert 'DO-NOT-LOG' not in json.dumps([rows, failure])


@pytest.mark.parametrize('form', ['int', 'string', 'leading-zero-string'])
def test_matching_server_second_is_compared_numerically_but_recorded_verbatim(monkeypatch, form):
    received = []
    def readback(status, body):
        old = body['users'][0]['validSince']
        new = int(old) if form == 'int' else ('00' + old if form == 'leading-zero-string' else old)
        body['users'][0]['validSince'] = new
        received.append(new)
        return status, body
    rows, failure, *_ = execute(monkeypatch, readback)
    assert failure is None
    row = rows[SAME_SECOND_CASE_ID]
    assert row['boundaryPinned'] is True
    assert row['boundarySeconds']['validSince'] == received[0]
    assert type(row['boundarySeconds']['validSince']) is type(received[0])


@pytest.mark.parametrize('difference', [-1, 1, 2])
def test_valid_but_different_second_remains_an_unpinned_observation(monkeypatch, difference):
    def readback(status, body):
        body['users'][0]['validSince'] = str(int(body['users'][0]['validSince']) + difference)
        return status, body
    rows, failure, *_ = execute(monkeypatch, readback)
    assert failure is None
    row = rows[SAME_SECOND_CASE_ID]
    assert row['boundaryPinned'] is False
    assert row['boundarySeconds']['authTime'] + difference == int(row['boundarySeconds']['validSince'])


def test_observed_boundary_refusal_is_preserved_not_forced_to_local_success(monkeypatch):
    rows, failure, *_ = execute(monkeypatch, boundary_refused=True)
    assert failure is None
    row = rows[SAME_SECOND_CASE_ID]
    assert row['boundaryPinned'] is True
    assert row['status'] == 400
    assert row['errorCode'] == 'TOKEN_EXPIRED'
    assert row['assertions']['acceptedResponse'] is False


def test_invalid_readback_still_cleans_up_owned_accounts_and_records_not_run(monkeypatch):
    rows, failure, tracker, budget, poster = execute(monkeypatch, BAD_READBACKS[0][1])
    assert failure == 'ShadowError: local collection failed'
    poster.recovery = True
    enter_recovery(budget, time.monotonic())
    assert shadow.cleanup(BASE, budget, tracker, poster=poster) == []
    assert set(poster.deleted) == {'fixture-uid-0', 'fixture-uid-1'}
    record, code = shadow.finish_record(
        rows=rows, tracker=tracker, budget=budget, failure=failure,
        shutdown={'processStopped': True, 'remainingChildren': 0, 'exitCode': 0,
                  'outputDrainerStopped': True, 'failures': []},
        source_binding={'commit': 'SYNTHETIC-UNIT-TEST', 'artifactSha256': None},
    )
    assert code == 1
    assert record['receipt']['cleanup']['cleanupComplete'] is True
    assert record['receipt']['recordingComplete'] is False
    assert record['productionExecuted'] is False
    ordered = record['receipt']['rows']
    assert sum(r['errorCode'] == 'NOT_RUN' for r in ordered) == 15
    serialized = json.dumps(record)
    assert 'OTHER-ACCOUNT-DO-NOT-LOG' not in serialized
    for secret in poster.secret_samples:
        assert secret not in serialized


@pytest.mark.parametrize('value', [-(1 << 63), '-9223372036854775808', 0, '0', (1 << 63) - 1, '9223372036854775807'])
def test_int64_domain_is_not_replaced_with_current_wall_clock_expectations(value):
    body = {'users': [{'localId': 'fixture-user', 'validSince': value}]}
    before = copy.deepcopy(body)
    actual = shadow._boundary_readback_second(200, body, 'fixture-user')
    assert actual == value and type(actual) is type(value)
    assert body == before
