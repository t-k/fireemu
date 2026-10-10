"""Offline boundaries for the selected S5b metadata-only API key read."""
import unittest
from unittest.mock import patch
import txn_program_http as worker
import pytest

KEY = 'projects/123456789012/locations/global/keys/644789b7-ac0a-47ff-a740-8836448a0633'


def test_selected_key_metadata_is_one_exact_get_without_key_string():
    calls = []
    class Response:
        status = 200
        def read(self, limit):
            assert limit == 65537
            return b'{"name":"selected","restrictions":{}}'
        def getheader(self, name):
            return 'application/json'
    class Connection:
        def __init__(self, host, timeout): calls.append((host, timeout))
        def request(self, method, path, **kwargs): calls.append((method, path, kwargs))
        def getresponse(self): return Response()
        def close(self): calls.append('closed')
    with patch.object(worker.http.client, 'HTTPSConnection', Connection):
        result = worker.worker_call({'slot': 's5b-key-metadata', 'secret': 'fixture-bearer', 'resource': KEY, 'project': 'fireemu-oracle-query', 'projectNumber': '123456789012'})
    assert result['complete'] is True
    assert calls[0] == ('apikeys.googleapis.com', 11)
    assert calls[1][:2] == ('GET', '/v2/' + KEY)
    assert 'getKeyString' not in calls[1][1]
    assert calls[-1] == 'closed'


def test_selected_key_refuses_every_resource_override_before_connection():
    variants = [
        ('fireemu-oracle-sbx', KEY),
        ('fireemu-oracle-query', KEY + ':getKeyString'),
        ('fireemu-oracle-query', KEY.replace('644789b7', '744789b7')),
        ('fireemu-oracle-query', None),
        ('fireemu-oracle-query', KEY + '?alt=json'),
    ]
    for project, resource in variants:
        with patch.object(worker.http.client, 'HTTPSConnection', side_effect=AssertionError('connection before validation')):
            with unittest.TestCase().assertRaises(ValueError):
                worker.worker_call({'slot': 's5b-key-metadata', 'secret': 'fixture-bearer', 'resource': resource, 'project': project, 'projectNumber': '123456789012'})


@pytest.mark.parametrize('number', [None, 123456789012, True, 1.5, '', '0123456789012', '123456789013', '123456789012?alt=json', '\uFF11' * 12])
def test_selected_key_refuses_missing_wrong_or_noncanonical_project_number(number):
    call = {'slot': 's5b-key-metadata', 'secret': 'fixture-bearer', 'resource': KEY, 'project': 'fireemu-oracle-query'}
    if number is not None: call['projectNumber'] = number
    with patch.object(worker.http.client, 'HTTPSConnection', side_effect=AssertionError('connection before validation')):
        with pytest.raises(ValueError): worker.worker_call(call)


@pytest.mark.parametrize('slot', ['oauth-tokeninfo', 'project', 'database', 'rules-release', 'refresh'])
def test_project_number_ipc_field_is_refused_for_other_slots(slot):
    with patch.object(worker.http.client, 'HTTPSConnection', side_effect=AssertionError('connection before validation')):
        with pytest.raises(ValueError):
            worker.worker_call({'slot': slot, 'secret': 'fixture-bearer', 'resource': None, 'project': 'fireemu-oracle-query', 'projectNumber': '123456789012'})


def test_request_once_passes_project_number_only_to_selected_key_worker():
    import json
    payloads = []
    class Child:
        returncode = 0
        stdin = stdout = None
        def communicate(self, payload, timeout):
            assert timeout == 13
            payloads.append(json.loads(payload))
            return b'{"complete":true,"status":200,"body":{}}', None
        def poll(self): return 0
    with patch.object(worker.subprocess, 'Popen', return_value=Child()):
        worker.request_once('s5b-key-metadata', 'fixture-bearer', KEY, project='fireemu-oracle-query', project_number='123456789012')
        worker.request_once('project', 'fixture-bearer', project='fireemu-oracle-query', project_number='123456789012')
    assert payloads[0]['projectNumber'] == '123456789012'
    assert payloads[0]['resource'] == KEY
    assert 'projectNumber' not in payloads[1]


@pytest.mark.parametrize('digits', range(6, 21))
def test_selected_key_project_number_length_round_trips_to_the_exact_resource(digits):
    number = '1' + '0' * (digits - 1)
    key = f'projects/{number}/locations/global/keys/644789b7-ac0a-47ff-a740-8836448a0633'
    paths = []
    class Connection:
        def __init__(self, _host, timeout): assert timeout == 11
        def request(self, method, path, **_kwargs): paths.append((method, path))
        def getresponse(self): return self
        status = 200
        def read(self, _limit): return b'{}'
        def getheader(self, _name): return 'application/json'
        def close(self): pass
    with patch.object(worker.http.client, 'HTTPSConnection', Connection):
        assert worker.worker_call({'slot': 's5b-key-metadata', 'secret': 'fixture-bearer', 'resource': key, 'project': 'fireemu-oracle-query', 'projectNumber': number})['complete'] is True
    assert paths == [('GET', '/v2/' + key)]


if __name__ == '__main__':
    suite = unittest.TestSuite(unittest.FunctionTestCase(fn) for fn in [
        test_selected_key_metadata_is_one_exact_get_without_key_string,
        test_selected_key_refuses_every_resource_override_before_connection,
    ])
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
