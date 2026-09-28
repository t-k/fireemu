"""Revocation cutoffs must be probed with a token for the same account/project.

The complete runner/collector/comparator are real; API replies, clock and JWTs are
explicitly synthetic. This never establishes native or production compatibility.
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
from credential_cases import observation_cases
from credential_comparator import compare
from test_credential_boundary_readback import BASE, NONCE, MemoryPoster

STAGES = ('older', 'boundary', 'newer')
KEPT = {'older': 3, 'boundary': 4, 'newer': 5}
SENT = {'older': 5, 'boundary': 8, 'newer': 12}


class SpecimenPoster(MemoryPoster):
    """Change one setup response, not the account this run actually creates/updates."""
    def __init__(self, stage=None, fault=None):
        super().__init__()
        self.stage, self.fault = stage, fault
        self.signins = 0
        self.injected = 0

    def __call__(self, budget, base, path, body, *, owner=False):
        status, response = super().__call__(budget, base, path, body, owner=owner)
        route = path.split('?')[0]
        if self.recovery:
            return status, response
        stage = None
        if route == '/accounts:signUp' and len(self.users) == 2:
            stage = 'older'
        if route == '/accounts:signInWithPassword':
            self.signins += 1
            stage = {1: 'boundary', 2: 'newer'}.get(self.signins)
        if self.stage is None or stage != self.stage or self.fault is None:
            return status, response
        self.injected += 1
        assert self.injected == 1, 'the specimen must never be retried'
        response = copy.deepcopy(response)
        _, payload = collector._jwt_objects(response['idToken'])
        if self.fault == 'subject':
            # This account really exists in the synthetic service: the pre-fix
            # lookup can succeed for it, rather than dying on a nonexistent key.
            payload.update(sub='fixture-uid-0', user_id='fixture-uid-0')
        elif self.fault == 'audience':
            payload['aud'] = 'DO-NOT-LOG-OTHER-PROJECT'
        elif self.fault == 'issuer':
            payload['iss'] = 'https://securetoken.google.com/DO-NOT-LOG-OTHER-PROJECT'
        elif self.fault == 'user-id':
            payload['user_id'] = 'DO-NOT-LOG-OTHER-USER'
        elif self.fault == 'tenant':
            payload['firebase']['tenant'] = 'DO-NOT-LOG-TENANT'
        elif self.fault == 'auth-time-missing':
            payload.pop('auth_time')
        elif self.fault == 'auth-time-bool':
            payload['auth_time'] = True
        elif self.fault == 'auth-time-string':
            payload['auth_time'] = str(payload['auth_time'])
        elif self.fault == 'optional-identity-absent':
            response.pop('localId')
            payload.pop('user_id')
        elif self.fault == 'conflicting-echo':
            response['localId'] = 'DO-NOT-LOG-OTHER-USER'
        else:
            raise AssertionError('unknown synthetic fault')
        response['idToken'] = shadow.unsigned_jwt(payload)
        self.secret_samples.append(response['idToken'])
        return status, response


def execute(monkeypatch, stage=None, fault=None, *, signing=True):
    poster = SpecimenPoster(stage, fault)
    monkeypatch.setattr(shadow, '_rest', poster.wait)
    tracker = collector.new_tracker(NONCE)
    budget = collector.new_budget(60, 600, 0.0, started_monotonic=time.monotonic(),
        recovery_requests=12, recovery_wall_seconds=60)
    environment = shadow.local_environment()
    environment['signing'] = signing
    def runner(base, b, t, rows):
        return shadow.run_cases(base, b, t, rows, poster=poster, environment=environment)
    rows, failure = shadow.collect(BASE, budget, tracker, runner=runner)
    sent_before_cleanup = len(poster.calls)
    poster.recovery = True
    collector.enter_recovery(budget, time.monotonic())
    assert shadow.cleanup(BASE, budget, tracker, poster=poster) == []
    assert collector.cleanup_report(tracker)['cleanupComplete'] is True
    assert not poster.users
    record, code = shadow.finish_record(
        rows=rows, tracker=tracker, budget=budget, failure=failure,
        shutdown={'processStopped': True, 'remainingChildren': 0, 'exitCode': 0,
                  'outputDrainerStopped': True, 'failures': []},
        source_binding={'commit':'SYNTHETIC-SPECIMEN-TEST', 'artifactSha256':None})
    return rows, failure, record, code, poster, sent_before_cleanup


def synthetic_comparison(record):
    """Synthetic envelopes only: not a valid production receipt or admission."""
    pair = []
    for side in ('local', 'production'):
        receipt=copy.deepcopy(record['receipt'])
        receipt.update(side=side, productionExecuted=side=='production',
                       collectorBinding={'syntheticComparatorFixture':'038'})
        pair.append(receipt)
    return compare(*pair)


@pytest.mark.parametrize('stage', STAGES)
@pytest.mark.parametrize('fault', ('subject', 'audience', 'issuer', 'user-id', 'tenant'))
def test_wrong_specimen_stops_before_followup_and_keeps_owned_accounts(monkeypatch, stage, fault):
    rows, failure, record, code, poster, sent = execute(monkeypatch, stage, fault)
    assert poster.injected == 1
    assert failure == 'ShadowError: local collection failed'
    assert sent == SENT[stage], 'do not issue the cutoff update or lookup after the bad setup'
    assert len(rows) == KEPT[stage]
    assert set(poster.deleted) == {'fixture-uid-0','fixture-uid-1'}
    assert code == 1 and record['receipt']['recordingComplete'] is False
    assert sum(row['errorCode']=='NOT_RUN' for row in record['receipt']['rows']) == 19-KEPT[stage]
    report=synthetic_comparison(record)
    assert report['summary']['indeterminate'] == 19
    assert report['parityEstablished'] is False
    encoded=json.dumps(record)
    assert 'DO-NOT-LOG' not in encoded
    for token in poster.secret_samples:
        assert token not in encoded


@pytest.mark.parametrize('stage', STAGES)
@pytest.mark.parametrize('fault', ('auth-time-missing','auth-time-bool','auth-time-string'))
def test_missing_integer_auth_time_is_a_setup_failure_not_keyerror(monkeypatch, stage, fault):
    rows, failure, _record, code, poster, sent = execute(monkeypatch, stage, fault)
    assert failure == 'ShadowError: local collection failed'
    assert sent == SENT[stage] and len(rows) == KEPT[stage]
    assert code == 1 and len(poster.deleted)==2


@pytest.mark.parametrize('stage', ('boundary','newer'))
def test_optional_identity_echoes_are_not_new_requirements(monkeypatch, stage):
    rows, failure, record, code, poster, sent = execute(monkeypatch, stage, 'optional-identity-absent')
    assert failure is None and code==0 and len(rows)==19
    assert sent==34 and len(poster.calls)==42
    assert synthetic_comparison(record)['summary']['match']==19


@pytest.mark.parametrize('stage', ('boundary','newer'))
def test_explicit_identity_echo_cannot_contradict_the_token(monkeypatch, stage):
    rows, failure, _record, code, _poster, sent = execute(monkeypatch, stage, 'conflicting-echo')
    assert failure=='ShadowError: local collection failed' and code==1
    assert sent==SENT[stage] and len(rows)==KEPT[stage]


def test_normal_campaign_retains_nineteen_cases_and_forty_two_requests(monkeypatch):
    rows, failure, record, code, poster, sent=execute(monkeypatch)
    assert failure is None and code==0
    assert len(rows)==len(observation_cases())==19
    assert sent==34 and len(poster.calls)==42
    assert len(poster.deleted)==3
    assert synthetic_comparison(record)['summary']['match']==19


def test_wrong_boundary_specimen_is_rejected_even_without_custom_signing(monkeypatch):
    rows, failure, _record, code, poster, sent=execute(monkeypatch,'boundary','subject',signing=False)
    assert failure=='ShadowError: local collection failed' and code==1
    assert sent==8 and len(rows)==4 and len(poster.deleted)==2


@pytest.mark.parametrize('fault', (None, 'subject'), ids=('complete', 'wrong-boundary-user'))
def test_real_http_worker_stops_before_using_another_users_specimen(monkeypatch, fault):
    """Real local HTTP and worker processes, never native fireemu or production."""
    import http.server
    import socket
    import threading

    poster=SpecimenPoster('boundary' if fault else None, fault)
    monkeypatch.setattr(shadow,'_rest',poster.wait)
    server_budget=collector.new_budget(60,600,0.0,started_monotonic=time.monotonic(),
        recovery_requests=12,recovery_wall_seconds=60)
    errors=[]
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            try:
                length=int(self.headers['Content-Length'])
                assert 0 < length <= 65536
                body=json.loads(self.rfile.read(length))
                admin=f'/identitytoolkit.googleapis.com/v1/projects/{shadow.PROJECT}'
                client='/identitytoolkit.googleapis.com/v1'
                if self.path.startswith(admin):
                    route=self.path[len(admin):]
                elif self.path.startswith(client):
                    route=self.path[len(client):]
                else:
                    assert self.path.startswith('/securetoken.googleapis.com/v1/token?')
                    route=''
                status,response=poster(server_budget,origin,route,body,
                    owner=self.headers.get('Authorization')=='Bearer owner')
                raw=json.dumps(response).encode()
                self.send_response(status)
                self.send_header('Content-Type','application/json')
                self.send_header('Content-Length',str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            except Exception as error:  # noqa: BLE001
                errors.append(type(error).__name__)
                self.send_error(500)
        def log_message(self,*_):
            pass
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
    server.daemon_threads=True
    address=server.server_address
    origin=f'http://127.0.0.1:{address[1]}'
    thread=threading.Thread(target=server.serve_forever,daemon=True)
    thread.start()
    children=[]
    real_run=shadow.credential_wire.subprocess.run
    def tracked_run(args,**kwargs):
        result=real_run(args,**kwargs)
        children.append((tuple(args[1:4]),result.returncode))
        return result
    monkeypatch.setattr(shadow.credential_wire.subprocess,'run',tracked_run)
    tracker=collector.new_tracker(NONCE)
    budget=collector.new_budget(60,600,0.0,started_monotonic=time.monotonic(),
        recovery_requests=12,recovery_wall_seconds=60)
    try:
        rows,failure=shadow.collect(origin,budget,tracker)  # actual HTTP post path
        assert len(poster.calls)==(8 if fault else 34)
        assert len(rows)==(4 if fault else 19)
        assert failure==('ShadowError: local collection failed' if fault else None)
        poster.recovery=True
        collector.enter_recovery(budget,time.monotonic())
        collector.enter_recovery(server_budget,time.monotonic())
        assert shadow.cleanup(origin,budget,tracker)==[]
        assert collector.cleanup_report(tracker)['cleanupComplete'] is True
        assert len(poster.deleted)==(2 if fault else 3) and not poster.users
        assert len(children)==len(poster.calls)==budget['requests']==(14 if fault else 42)
        assert all(args==('-I','-S','-B') and code==0 for args,code in children)
        assert not errors
        for token in poster.secret_samples:
            assert token not in json.dumps(rows)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()
    with socket.socket() as client:
        client.settimeout(1)
        assert client.connect_ex(address)!=0
