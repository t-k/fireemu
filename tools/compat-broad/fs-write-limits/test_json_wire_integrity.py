"""Ambiguous JSON is diagnostic data, never typed creation/absence evidence.

Exercise both standalone worker dependency closures and their Gate/Ledger use.
The limits worker is also embedded in the admitted O8 worker archive.
"""
from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from urllib.parse import quote

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import batch_wire
from test_batch_wire_completion import (
    ABSENT, VERSION, _gate_and_ledger, exchange, frame, raw_server,
)
import shared_gate
from broad_contract import digest

_spec = importlib.util.spec_from_file_location("json_test_limits_transport", HERE / "transport.py")
assert _spec is not None and _spec.loader is not None
limits_transport = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(limits_transport)

BAD = [
    b'{"error":{"code":403,"code":404,"status":"NOT_FOUND"}}',
    b'{"error":{"status":"PERMISSION_DENIED"},"error":{"code":404,"status":"NOT_FOUND"}}',
    b'{"error":{"code":404,"status":"NOT_FOUND","status":"NOT_FOUND"}}',
    b'{"error":{"code":404,"\\u0063ode":404,"status":"NOT_FOUND"}}',
    b'{"nested":[{"key":1,"key":2}]}',
    b'{"error":{"code":404,"status":"NOT_FOUND"},"diagnostic":NaN}',
    b'{"error":{"code":404,"status":"NOT_FOUND"},"diagnostic":Infinity}',
    b'{"nested":[-Infinity]}', b'{"nested":[1e9999]}', b'{"nested":[-1e9999]}',
    '{"error":{"code":404,"status":"NOT_FOUND"}}'.encode('utf-16'),
    '{"error":{"code":404,"status":"NOT_FOUND"}}'.encode('utf-32'),
    b'{"invalid":"\xff"}', b'\xef\xbb\xbf{}',
]
GOOD = [
    b'{"error":{"code":404,"status":"NOT_FOUND"}}',
    b'{"left":{"same":1},"right":{"same":2}}',
    b'[{"same":1},{"same":2}]',
    b'{"integer":404,"float":404.0,"bool":true,"negativeZero":-0.0}',
    '{"unicode":"東京","emoji":"🦀","escaped":"\\u0061"}'.encode(),
    b'{"finite":1e300}', b'[]', b'null', b'"text"',
]

class Response(io.BytesIO):
    status = 404
    def __init__(self, payload):
        from email.message import Message
        super().__init__(payload)
        self.headers = Message()
        self.headers['Content-Length'] = str(len(payload))
        self.headers['Content-Type'] = 'application/json'


def captured_decode(monkeypatch, flavor, payload):
    """Use the actual main/_exchange decoder, replacing HTTP I/O only."""
    response = Response(payload)
    monkeypatch.setattr(batch_wire.urllib.request, 'build_opener',
                        lambda *_a: SimpleNamespace(open=lambda *_a, **_k: response))
    if flavor == 'limits':
        result = limits_transport._exchange('http://127.0.0.1:19099/v1/test', 'GET', None, {}, 65536, 2)
    else:
        request = {'url':'http://127.0.0.1:19099/v1/test', 'method':'GET', 'body':None,
                   'headers':{}, 'receipt':flavor == 'batch-receipt'}
        monkeypatch.setattr(sys, 'stdin', io.StringIO(json.dumps(request)))
        with contextlib.redirect_stdout(io.StringIO()) as out:
            batch_wire.main()
        result = json.loads(out.getvalue(), parse_constant=lambda _s: (_ for _ in ()).throw(ValueError()))
    assert response.closed
    return result


@pytest.mark.parametrize('flavor', ['limits', 'batch', 'batch-receipt'])
@pytest.mark.parametrize('payload', BAD)
def test_ambiguous_or_non_utf8_json_is_not_typed_evidence(monkeypatch, flavor, payload):
    result = captured_decode(monkeypatch, flavor, payload)
    if flavor == 'limits':
        assert result['complete'] is True  # HTTP reception and JSON validity differ.
        assert result['kind'] == 'non-json'
        assert isinstance(result['body'], str)
    elif flavor == 'batch-receipt':
        assert result['http']['complete'] is True
        assert result['http']['bodyKind'] == 'non-json'
        assert result['body'] is None
    else:
        assert result[0] == 404
        assert set(result[1]) == {'nonJson'}


@pytest.mark.parametrize('flavor', ['limits', 'batch', 'batch-receipt'])
@pytest.mark.parametrize('payload', GOOD)
def test_unique_finite_utf8_values_preserve_shape_and_types(monkeypatch, flavor, payload):
    result = captured_decode(monkeypatch, flavor, payload)
    actual = result['body'] if flavor != 'batch' else result[1]
    expected = json.loads(payload.decode('utf-8'))
    assert digest(actual) == digest(expected)
    if flavor == 'limits': assert result['kind'] == 'api-error'
    if flavor == 'batch-receipt': assert result['http']['bodyKind'] == 'json'


def worker_result(flavor, payload, status, operation):
    if flavor == 'batch':
        response = exchange(frame(payload, status=status), operation=operation)
        assert response.returncode == 0, response.stderr
        code, body, _ = json.loads(response.stdout)
        return code, body
    with raw_server(frame(payload, status=status)) as (origin, requests):
        receipt = limits_transport.request(origin, operation, request_byte_limit=10000,
                                          response_byte_limit=65536, timeout=5)
    assert len(requests) == 1
    assert receipt['complete'] is True
    return receipt['status'], receipt['body']


@pytest.mark.parametrize('flavor', ['limits', 'batch'])
@pytest.mark.parametrize('scheduled', [False, True])
@pytest.mark.parametrize('corrupted', ['none', 'create', 'absence'])
def test_actual_workers_cannot_release_ledger_from_ambiguous_json(tmp_path, flavor, scheduled, corrupted):
    gate, ledger, ticket, job, doc, envelope, claim = _gate_and_ledger(tmp_path, scheduled)
    setup = job['observation'][0]
    encoded = json.dumps(doc).encode()
    if corrupted == 'create': encoded = b'{"name":"foreign",' + encoded[1:]
    if corrupted == 'create':
        with pytest.raises(ValueError, match='conditional creation identity mismatch'):
            gate.dispatch(setup, False, lambda: worker_result(flavor, encoded, 200, setup))
    else:
        gate.dispatch(setup, False, lambda: worker_result(flavor, encoded, 200, setup))
    read, declared, final = job['recovery']
    if corrupted == 'create':
        assert shared_gate.unconfirmed_creates(gate.snapshot(), 'wire') == 1
        for operation in job['recovery']:
            operation = copy.deepcopy(operation); operation.pop('versionFrom', None)
            gate.dispatch(operation, True, lambda: (404, ABSENT))
    else:
        gate.dispatch(read, True, lambda: (200, doc))
        deletion = {key: value for key, value in declared.items() if key != 'versionFrom'}
        deletion['path'] += '?currentDocument.updateTime=' + quote(VERSION, safe='')
        gate.dispatch(deletion, True, lambda: (200, {}))
        encoded = json.dumps(ABSENT).encode()
        if corrupted == 'absence':
            encoded = b'{"error":{"code":403,"status":"PERMISSION_DENIED"},' + encoded[1:]
        if corrupted == 'absence':
            with pytest.raises(ValueError, match='typed Firestore absence required'):
                gate.dispatch(final, True, lambda: worker_result(flavor, encoded, 404, final))
        else:
            gate.dispatch(final, True, lambda: worker_result(flavor, encoded, 404, final))
    if corrupted == 'none':
        gate.finish(); ledger.finish(ticket)
        assert ledger.snapshot()['reservations'][ticket['reservation']]['state'] == 'released'
    else:
        with pytest.raises(ValueError): gate.finish()
        with pytest.raises(ValueError): ledger.finish(ticket)
        assert ledger.snapshot()['reservations'][ticket['reservation']]['state'] == 'held'
    assert ledger.snapshot()['envelopes'][digest(envelope)]['allocated'] == claim['budget']
