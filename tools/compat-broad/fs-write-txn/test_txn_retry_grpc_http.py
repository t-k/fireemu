"""Fixed REST metadata/OAuth slots, no redirects or automatic retries."""

import pytest

import txn_retry_grpc_http as http


class Response:
    status = 200
    def read(self, _cap): return b'{"name":"fixed"}'
    def getheader(self, _name): return 'application/json; charset=utf-8'


class Connection:
    requests = []
    def __init__(self, host, timeout): self.host = host; self.closed = False
    def request(self, method, path, body=None, headers=None): self.requests.append((self.host, method, path, body, headers))
    def getresponse(self): return Response()
    def close(self): self.closed = True


def test_seven_management_slots_and_refresh_have_one_fixed_request(monkeypatch):
    monkeypatch.setattr(http.http.client, 'HTTPSConnection', Connection)
    Connection.requests = []
    for slot in ['oauth-tokeninfo', 'project', 'database', 'rules-release', 'ruleset-source']:
        resource = 'projects/fireemu-oracle-sbx/rulesets/fixed' if slot == 'ruleset-source' else None
        result = http.worker_call({'slot': slot, 'secret': 'private-bearer', 'resource': resource})
        assert result['complete'] is True
    result = http.worker_call({'slot': 'refresh', 'secret': {'type': 'authorized_user', 'client_id': 'client', 'client_secret': 'private', 'refresh_token': 'private'}, 'resource': None})
    assert result['complete'] is True
    assert len(Connection.requests) == 6
    assert Connection.requests[-1][:3] == ('oauth2.googleapis.com', 'POST', '/token')
    assert all('gcloud' not in path for _host, _method, path, _body, _headers in Connection.requests)


@pytest.mark.parametrize('spec', [
    {'slot': 'unknown', 'secret': 'token', 'resource': None},
    {'slot': 'ruleset-source', 'secret': 'token', 'resource': 'projects/fireemu-oracle-idp/rulesets/foreign'},
    {'slot': 'project', 'secret': 'token\nInjected: bad', 'resource': None},
    {'slot': 'project', 'secret': 'token', 'resource': None, 'url': 'https://foreign.example/'},
])
def test_no_origin_path_or_header_override_is_admitted(spec, monkeypatch):
    monkeypatch.setattr(http.http.client, 'HTTPSConnection', Connection)
    Connection.requests = []
    with pytest.raises(ValueError): http.worker_call(spec)
    assert Connection.requests == []


def test_redirect_is_incomplete_and_not_followed(monkeypatch):
    monkeypatch.setattr(http.http.client, 'HTTPSConnection', Connection)
    monkeypatch.setattr(Response, 'status', 302)
    Connection.requests = []
    result = http.worker_call({'slot': 'project', 'secret': 'token', 'resource': None})
    assert result['complete'] is False
    assert len(Connection.requests) == 1
