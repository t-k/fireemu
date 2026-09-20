"""Actual loopback sockets + fixed worker; no native or production execution."""
from __future__ import annotations

import contextlib
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess
import sys
import threading
import time

import pytest

sys.path[:0] = [str(Path(__file__).parent), str(Path(__file__).parents[1])]
import txn_wire as wire
import txn_expiry_shadow as shadow
import test_txn_expiry_collector as cf


def get_request(**overrides):
    return {"rpc": "GetDocument", "database": "(default)", "projectId": "fireemu-test",
            "name": "projects/fireemu-test/databases/(default)/documents/items/a",
            "body": None, "query": None, "maxRequestBytes": 8192,
            "maxResponseBytes": 65536, "timeoutSeconds": 1.0, **overrides}


@contextlib.contextmanager
def server(*, status=200, raw=b'{}', mode="normal", media="application/json", extras=()):
    calls, stopped = [], threading.Event()
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass
        def reply(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            calls.append((self.command, self.path, body, dict(self.headers)))
            selected = mode
            response = raw
            if mode == "clock-post-drip" and self.command == "GET":
                selected = "normal"
                response = json.dumps({"session": "default", "clock": {
                    "clock": "2026-09-18T00:00:00Z", "backwardsSets": 0}}).encode()
            elif mode == "clock-post-drip":
                selected = "drip"
            if selected == "no-headers":
                stopped.wait(4)
                return
            self.send_response(status)
            if media is not None:
                self.send_header("Content-Type", media)
            length = len(response) if selected != "drip" else 200
            if selected == "truncated":
                length += 30
            self.send_header("Content-Length", str(length))
            for key, value in extras:
                self.send_header(key, value)
            self.end_headers()
            try:
                if selected == "drip":
                    for _ in range(198):
                        if stopped.wait(.015):
                            return
                        self.wfile.write(b' '); self.wfile.flush()
                    self.wfile.write(b'{}')
                else:
                    self.wfile.write(response)
            except (BrokenPipeError, ConnectionResetError):
                pass
        do_GET = do_POST = reply
    service = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=lambda: service.serve_forever(poll_interval=.01), daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{service.server_port}', calls
    finally:
        stopped.set(); service.shutdown(); service.server_close(); thread.join(timeout=2)
        assert not thread.is_alive()


@pytest.mark.parametrize('mode', ['drip', 'no-headers'])
def test_deadline_bounds_entire_response_and_reaps_fixed_child(mode, monkeypatch):
    children, original = [], subprocess.Popen
    def spawn(*args, **kw):
        child = original(*args, **kw); children.append(child); return child
    monkeypatch.setattr(wire.subprocess, 'Popen', spawn)
    with server(mode=mode) as (origin, calls):
        started = time.monotonic()
        result = shadow.rest_transport(origin)(get_request())
        elapsed = time.monotonic() - started
        assert result['complete'] is False
        assert result['message'] == 'request-deadline-exceeded'
        assert elapsed < 2.5
        assert len(calls) == 1
    assert len(children) == 1 and children[0].poll() is not None


@pytest.mark.parametrize('status', [401, 403])
def test_headers_survive_timeout_and_stop_collector_authority(status):
    with server(status=status, mode='drip') as (origin, calls):
        send = shadow.rest_transport(origin)
        receipt = cf.collection_with(lambda req: send({**req, 'timeoutSeconds': 1.0})).run()
        assert receipt['complete'] is False
        assert receipt['authorityRefusal']
        assert len(calls) == 1


@pytest.mark.parametrize('mode,expected_count', [('drip', 1), ('clock-post-drip', 2)])
def test_control_get_and_post_have_total_deadlines_and_no_retry(mode, expected_count):
    with server(mode=mode) as (origin, calls):
        advance = shadow.clock_advance(origin, 'control-private', timeout=1.0)
        started = time.monotonic()
        with pytest.raises(ValueError, match='incomplete'):
            advance(20)
        assert time.monotonic() - started < 2.5
        assert len(calls) == expected_count == advance.requests


def test_initial_instance_identity_probe_is_also_bounded():
    with server(mode='drip') as (origin, calls):
        started = time.monotonic()
        with pytest.raises(ValueError, match='incomplete'):
            shadow._control_get(origin, '/v1/sessions/default/resources', 'private', timeout=1.0)
        assert time.monotonic() - started < 2.5 and len(calls) == 1


@pytest.mark.parametrize('status,raw', [
    (200, b'{}'),
    (404, b'{"error":{"code":404,"status":"NOT_FOUND"}}'),
    (403, b'{"error":{"code":403,"status":"PERMISSION_DENIED"}}'),
])
def test_worker_preserves_exact_bytes_and_status(status, raw):
    with server(status=status, raw=raw) as (origin, calls):
        result = wire.request(origin + '/v1/projects/p/databases/(default)/documents/a/b',
                              method='GET', seconds=5)
    assert result == {'httpStatus': status, 'complete': True, 'rawBody': raw, 'failure': None}
    assert len(calls) == 1


@pytest.mark.parametrize('kwargs', [
    {'mode': 'truncated'}, {'raw': b'x' * 65537}, {'media': 'text/plain'},
    {'media': None}, {'status': 302, 'extras': [('Location', 'http://external.invalid/path')]},
    {'extras': [('Content-Length', '2')]},
    {'extras': [('Transfer-Encoding', 'chunked')]},
    {'extras': [('Content-Type', 'application/json')]},
])
def test_bounded_worker_refuses_bad_http_without_following(kwargs):
    with server(**kwargs) as (origin, calls):
        result = shadow.rest_transport(origin)(get_request(timeoutSeconds=5))
    assert result['complete'] is False and len(calls) == 1


@pytest.mark.parametrize('raw', [b'', b'[]', b'{"x":1,"x":2}', b'{"x":NaN}',
    b'{"x":1e999}', '{}'.encode('utf-16')])
def test_complete_http_is_not_automatically_usable_json(raw):
    with server(raw=raw) as (origin, calls):
        result = shadow.rest_transport(origin)(get_request(timeoutSeconds=5))
    assert result['complete'] is False and result['httpStatus'] == 200 and len(calls) == 1


@pytest.mark.parametrize('seconds', [0, -1, True, '1', float('nan'), float('inf'), 121, 10**1000])
def test_bad_duration_never_launches_worker(seconds, monkeypatch):
    monkeypatch.setattr(wire.subprocess, 'run', lambda *_a, **_k: pytest.fail('spawned'))
    with pytest.raises(ValueError):
        wire.request('http://127.0.0.1:8000/v1/sessions/default', method='GET', seconds=seconds)


@pytest.mark.parametrize('url', [
    'http://localhost:8000/v1/sessions/default', 'https://127.0.0.1:8000/v1/sessions/default',
    'http://127.0.0.1/v1/sessions/default', 'http://user@127.0.0.1:8000/v1/sessions/default',
    'http://127.0.0.1:8000/v1/sessions/default#x',
    'http://127.0.0.1:8000/v1/sessions/default?x=1',
    'http://127.0.0.1:8000/unknown', 'http://127.0.0.1:8000//v1/sessions/default',
])
def test_target_rejection_occurs_before_worker_launch(url, monkeypatch):
    monkeypatch.setattr(wire.subprocess, 'run', lambda *_a, **_k: pytest.fail('spawned'))
    with pytest.raises(ValueError):
        wire.request(url, method='GET')


@pytest.mark.parametrize('field,value', [('response_limit', True), ('response_limit', 65537),
    ('request_limit', 8193), ('token', 'x\r\ny'), ('token', ''), ('method', 'DELETE')])
def test_malformed_worker_parameters_do_not_spawn(field, value, monkeypatch):
    monkeypatch.setattr(wire.subprocess, 'run', lambda *_a, **_k: pytest.fail('spawned'))
    options = {'method': 'GET', field: value}
    with pytest.raises(ValueError):
        wire.request('http://127.0.0.1:8000/v1/sessions/default', **options)


def test_environment_is_minimal_and_secrets_only_go_to_stdin(monkeypatch):
    seen = []
    for name in ('GOOGLE_APPLICATION_CREDENTIALS', 'AWS_ACCESS_KEY_ID', 'PYTHONPATH',
                 'PYTHONSTARTUP', 'HTTPS_PROXY', 'FIREEMU_CONTROL_TOKEN'):
        monkeypatch.setenv(name, 'ambient-secret')
    def run(command, **kw):
        seen.append((command, kw))
        return subprocess.CompletedProcess(command, 2, b'', b'private-debug')
    monkeypatch.setattr(wire.subprocess, 'run', run)
    result = wire.request('http://127.0.0.1:8000/v1/sessions/default', method='GET', token='sensitive-token')
    command, args = seen[0]
    assert command[1:4] == ['-I', '-S', '-B']
    assert 'sensitive-token' not in repr(command) and 'sensitive-token' not in repr(args['env'])
    assert b'sensitive-token' in args['input'] and 'ambient-secret' not in repr(args['env'])
    assert isinstance(args['env'], dict)
    assert args['timeout'] == 10 and result['failure'] == 'worker-result-invalid'
    assert 'private-debug' not in repr(result)


def test_worker_receives_requested_transaction_query_and_payload_unchanged():
    with server(raw=b'{"transaction":"AA=="}') as (origin, calls):
        request = get_request(rpc='BeginTransaction', body={'options': {'readWrite': {}}}, timeoutSeconds=5)
        result = shadow.rest_transport(origin)(request)
    assert result['code'] == 0 and result['complete'] is True
    assert calls[0][0:2] == ('POST', '/v1/projects/fireemu-test/databases/(default)/documents:beginTransaction')
    assert json.loads(calls[0][2]) == request['body']
    with server(status=404, raw=b'{"error":{"code":404,"status":"NOT_FOUND"}}') as (origin, calls):
        shadow.rest_transport(origin)(get_request(query={'transaction': 'a/b+='}, timeoutSeconds=5))
    assert calls[0][1].endswith('?transaction=a%2Fb%2B%3D')


def test_explicit_response_limit_is_enforced():
    with server(raw=b'{"value":"1234567890"}') as (origin, calls):
        result = shadow.rest_transport(origin)(get_request(maxResponseBytes=8, timeoutSeconds=5))
    assert result['complete'] is False and len(calls) == 1


def test_worker_partial_header_does_not_fabricate_observed_status(monkeypatch):
    def timeout(*args, **kw):
        raise subprocess.TimeoutExpired(args[0], kw['timeout'], output=b'{"kind":"headers","status":403}')
    monkeypatch.setattr(wire.subprocess, 'run', timeout)
    result = wire.request('http://127.0.0.1:8000/v1/sessions/default', method='GET')
    assert result['httpStatus'] is None and result['complete'] is False


@pytest.mark.parametrize('raw', [
    b'{"kind":"headers","status":403}\n',
    b'{"kind":"headers","status":403}\nnot-json\n',
    b'{"kind":"headers","status":403}\n{"kind":"headers","status":200}\n',
])
def test_invalid_final_frame_does_not_erase_auth_refusal(raw):
    result = wire._result(raw, 0)
    assert result['complete'] is False and result['httpStatus'] == 403


def test_entire_collector_and_virtual_clock_use_real_worker_http_and_recover():
    """Expected semantics are fixture-supplied; the network/collector are real."""
    import datetime
    import urllib.parse
    import test_txn_expiry_comparison as cases_fixture
    import txn_expiry_collector as collector
    import txn_expiry_comparison as comparison

    endpoint = cases_fixture.CaseAwareEndpoint()
    data_calls, control_calls = [], []
    current = [datetime.datetime(2026, 9, 18, tzinfo=datetime.timezone.utc)]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args): pass
        def reply(self):
            parsed = urllib.parse.urlsplit(self.path)
            payload = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            body = json.loads(payload) if payload else None
            if parsed.path.startswith('/v1/sessions/default'):
                control_calls.append((self.command, parsed.path))
                if self.command == 'POST': current[0] += datetime.timedelta(seconds=body['seconds'])
                clock = {'clock': current[0].isoformat().replace('+00:00', 'Z'), 'backwardsSets': 0}
                value = {'session': 'default', 'clock': clock} if self.command == 'GET' else clock
                status = 200
            else:
                if self.command == 'GET':
                    request = {'rpc': 'GetDocument', 'name': parsed.path.removeprefix('/v1/'), 'body': None}
                else:
                    rpc = {':commit': 'Commit', ':rollback': 'Rollback', ':beginTransaction': 'BeginTransaction'}
                    request = {'rpc': rpc[next(s for s in rpc if parsed.path.endswith(s))], 'body': body}
                data_calls.append(request)
                result = endpoint(request)
                status = collector.HTTP_STATUS[result['code']]
                value = result['body'] if result['code'] == 0 else {'error': {
                    'code': status, 'status': result['status'], 'message': result.get('message')}}
            raw = json.dumps(value).encode()
            self.send_response(status);self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw)));self.end_headers();self.wfile.write(raw)
        do_GET = do_POST = reply
    service = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=lambda: service.serve_forever(poll_interval=.01), daemon=True)
    thread.start()
    try:
        origin = f'http://127.0.0.1:{service.server_port}'
        advance = shadow.clock_advance(origin, 'local-control', timeout=5)
        col = cf.collection_with(shadow.rest_transport(origin))
        col.advance = advance
        endpoint.attach(col)
        receipt = col.run()
        assert receipt['complete'] is True
        assert comparison.local_self_contract(receipt)['classification'] == comparison.MATCH
        assert receipt['unrecovered'] == [] and receipt['openTransactions'] == []
        assert receipt['unconfirmedTransactionStarts'] == [] and endpoint.documents == {}
        assert len(data_calls) == receipt['requestCount']
        assert len(control_calls) == advance.requests == 4
        deletes = [w for r in data_calls for w in (r.get('body') or {}).get('writes', []) if 'delete' in w]
        assert len(deletes) == 5 and all('updateTime' in w['currentDocument'] for w in deletes)
        print(json.dumps({'actualLocalDataHttpRequests': len(data_calls), 'actualLocalControlHttpRequests': len(control_calls),
                          'nativeExecuted': False, 'productionExecuted': False}))
    finally:
        service.shutdown(); service.server_close(); thread.join(timeout=2)
        assert not thread.is_alive()
