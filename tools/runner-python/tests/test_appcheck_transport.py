"""SECURITY-SENSITIVE: how the runner fetches the App Check emulator's keys, and which claims it requires (Codex r2 on
slice 2b). The runner fetches the keys itself, so no dependency default (redirects, proxies, name resolution) decides
where a request goes; the claim checks add what the stock SDK leaves optional (`exp`, the exact issuer).

Every transport test proves the negative the same way: a second local server stands in for "the outside", and the
test asserts it was never contacted. Name lookups and connections are recorded as well, so a request that would have
left the machine fails the test even though no network is available to it.
"""

import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler

import jwt
import pytest
from jwt.algorithms import RSAAlgorithm

from fireemu_runner import appcheck
from test_appcheck import EMULATOR_KEY, KID, OTHER_KEY, PROJECT, JwksServer, LoopbackServer, token

KEYS_BODY = json.dumps({"keys": [{**json.loads(RSAAlgorithm.to_jwk(EMULATOR_KEY.public_key())), "kid": KID, "alg": "RS256", "use": "sig"}]}).encode()
ATTACKER_BODY = json.dumps({"keys": [{**json.loads(RSAAlgorithm.to_jwk(OTHER_KEY.public_key())), "kid": KID, "alg": "RS256", "use": "sig"}]}).encode()


class Scripted:
    """A loopback server that answers every GET with `reply(handler)` and counts them."""

    def __init__(self, reply):
        self.requests = 0
        self.paths = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                outer.requests += 1
                outer.paths.append(self.path)
                reply(self)

            def log_message(self, *args):
                pass

        self.server = LoopbackServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.port = self.server.server_port
        self.url = f"http://127.0.0.1:{self.port}/v1/jwks"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def answer(handler, status=200, body=b"", headers=()):
    handler.send_response(status)
    for name, value in headers:
        handler.send_header(name, value)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


@pytest.fixture
def client_for():
    """A key client for a URL, plus a way to close what the test opened."""
    opened = []

    def make(url, **options):
        client = appcheck.LoopbackKeyClient(url, **options)
        opened.append(client)
        return client

    yield make


def verifies(client, value):
    """Whether the client yields a key under which `value` verifies."""
    try:
        key = client.get_signing_key_from_jwt(value).key
        jwt.decode(value, key, algorithms=["RS256"], audience=f"projects/{PROJECT}")
        return True
    except Exception:
        return False


@pytest.fixture
def traffic(monkeypatch):
    """Records every name lookup and connection attempt the process makes."""
    seen = {"lookups": [], "connects": []}
    real_getaddrinfo = socket.getaddrinfo
    real_create = socket.create_connection

    def getaddrinfo(host, *args, **kwargs):
        seen["lookups"].append(host)
        return real_getaddrinfo(host, *args, **kwargs)

    def create_connection(address, *args, **kwargs):
        seen["connects"].append(address)
        return real_create(address, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(socket, "create_connection", create_connection)
    return seen


# --- the happy path and its bounds -------------------------------------------------------------------------


def test_the_client_fetches_the_key_set_once_and_serves_later_tokens_from_its_cache(client_for):
    server = JwksServer({KID: EMULATOR_KEY})
    try:
        client = client_for(server.url)
        assert verifies(client, token()) and verifies(client, token()) and verifies(client, token())
        assert server.requests == 1
    finally:
        server.close()


def test_the_request_says_where_it_goes_and_carries_the_sdks_metrics_header(client_for):
    seen = {}

    def reply(handler):
        seen.update(host=handler.headers["Host"], metrics=handler.headers.get("x-goog-api-client"), connection=handler.headers.get("Connection"))
        answer(handler, body=KEYS_BODY)

    server = Scripted(reply)
    try:
        assert verifies(client_for(server.url, headers={"x-goog-api-client": "gl-python/test"}), token())
        assert seen["host"] == f"127.0.0.1:{server.port}" and seen["metrics"]
    finally:
        server.close()


def test_an_unknown_kid_refetches_once_per_interval_and_never_in_a_flood(client_for):
    server = JwksServer({KID: EMULATOR_KEY})
    try:
        client = client_for(server.url, refresh_interval=0.3)
        assert verifies(client, token())
        assert server.requests == 1
        for _ in range(5):
            assert not verifies(client, token(kid="who-is-this"))
        assert server.requests == 1, "inside the interval a flood of unknown kids fetches nothing"
        time.sleep(0.35)
        for _ in range(5):
            assert not verifies(client, token(kid="who-is-this"))
        assert server.requests == 2, "one fetch per interval, not one per token"
    finally:
        server.close()


def test_a_key_that_appears_after_the_first_fetch_is_picked_up_after_the_interval(client_for):
    keys = {"empty": True}

    def reply(handler):
        answer(handler, body=json.dumps({"keys": []}).encode() if keys["empty"] else KEYS_BODY)

    server = Scripted(reply)
    try:
        client = client_for(server.url, refresh_interval=0.2)
        assert not verifies(client, token())
        keys["empty"] = False
        assert not verifies(client, token()), "inside the interval nothing is fetched"
        time.sleep(0.25)
        assert verifies(client, token())
    finally:
        server.close()


@pytest.mark.parametrize(
    "label, reply",
    [
        ("a server error", lambda h: answer(h, 500, b"{}")),
        ("not found", lambda h: answer(h, 404, b"{}")),
        ("not json", lambda h: answer(h, body=b"<html>")),
        ("a json array", lambda h: answer(h, body=b"[]")),
        ("keys that are not a list", lambda h: answer(h, body=json.dumps({"keys": {}}).encode())),
        ("a key without material", lambda h: answer(h, body=json.dumps({"keys": [{"kid": KID, "kty": "RSA"}]}).encode())),
        ("an empty key set", lambda h: answer(h, body=json.dumps({"keys": []}).encode())),
        ("no body at all", lambda h: answer(h, 200, b"")),
    ],
)
def test_every_bad_answer_leaves_a_valid_looking_token_unverified(client_for, label, reply):
    server = Scripted(reply)
    try:
        assert not verifies(client_for(server.url), token()), label
    finally:
        server.close()


def test_an_answer_over_the_size_bound_is_refused_without_reading_it_all(client_for):
    server = Scripted(lambda h: answer(h, body=b" " * (300 * 1024) + KEYS_BODY))
    try:
        assert not verifies(client_for(server.url), token())
        small = Scripted(lambda h: answer(h, body=KEYS_BODY))
        try:
            assert verifies(client_for(small.url, max_bytes=len(KEYS_BODY)), token())
            assert not verifies(client_for(small.url, max_bytes=len(KEYS_BODY) - 1), token())
        finally:
            small.close()
    finally:
        server.close()


def test_a_server_that_never_answers_is_given_up_on_within_the_timeout(client_for):
    release = threading.Event()
    server = Scripted(lambda h: release.wait(5))
    try:
        started = time.monotonic()
        assert not verifies(client_for(server.url, timeout=0.3), token())
        assert time.monotonic() - started < 3
    finally:
        release.set()
        server.close()


def test_a_closed_port_is_a_failure_not_a_hang(client_for):
    started = time.monotonic()
    assert not verifies(client_for("http://127.0.0.1:1/v1/jwks", timeout=1), token())
    assert time.monotonic() - started < 3


# --- redirects, proxies and name resolution never take a request off the machine ------------------------------


def test_a_redirect_to_another_loopback_server_is_not_followed(client_for):
    elsewhere = Scripted(lambda h: answer(h, body=ATTACKER_BODY))
    redirecting = Scripted(lambda h: answer(h, 302, b"", [("Location", elsewhere.url)]))
    try:
        client = client_for(redirecting.url)
        # The attacker's key set would verify a token the attacker signed, if the redirect were followed.
        assert not verifies(client, token(key=OTHER_KEY))
        assert not verifies(client, token())
        assert redirecting.requests >= 1 and elsewhere.requests == 0
    finally:
        redirecting.close()
        elsewhere.close()


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_every_redirect_status_is_a_failure(client_for, status):
    elsewhere = Scripted(lambda h: answer(h, body=KEYS_BODY))
    redirecting = Scripted(lambda h: answer(h, status, KEYS_BODY, [("Location", elsewhere.url)]))
    try:
        assert not verifies(client_for(redirecting.url), token())
        assert elsewhere.requests == 0
    finally:
        redirecting.close()
        elsewhere.close()


def test_a_redirect_to_an_outside_host_triggers_no_lookup_and_no_connection(client_for, traffic):
    redirecting = Scripted(lambda h: answer(h, 302, b"", [("Location", "http://attacker.invalid/keys")]))
    try:
        assert not verifies(client_for(redirecting.url), token(key=OTHER_KEY))
        assert "attacker.invalid" not in traffic["lookups"]
        assert all(address[0] in ("127.0.0.1", "::1") for address in traffic["connects"])
    finally:
        redirecting.close()


@pytest.mark.parametrize("variable", ["http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"])
def test_a_proxy_in_the_environment_is_never_used(client_for, monkeypatch, variable):
    proxy = Scripted(lambda h: answer(h, body=ATTACKER_BODY))
    keys = JwksServer({KID: EMULATOR_KEY})
    try:
        monkeypatch.setenv(variable, f"http://127.0.0.1:{proxy.port}")
        monkeypatch.delenv("no_proxy", raising=False)
        monkeypatch.delenv("NO_PROXY", raising=False)
        client = client_for(keys.url)
        assert verifies(client, token())
        assert not verifies(client_for(keys.url), token(key=OTHER_KEY))
        assert proxy.requests == 0 and keys.requests == 2
    finally:
        proxy.close()
        keys.close()


def test_a_name_that_resolves_off_the_machine_is_refused_before_any_connection(client_for, monkeypatch):
    connects = []
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))])
    monkeypatch.setattr(socket, "create_connection", lambda address, *a, **k: connects.append(address) or (_ for _ in ()).throw(AssertionError("connected")))
    client = client_for("http://localhost:9/v1/jwks")
    assert not verifies(client, token())
    assert connects == []


def test_one_off_machine_address_among_loopback_ones_refuses_the_whole_name(client_for, monkeypatch):
    connects = []
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda host, port, *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port)), (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))],
    )
    monkeypatch.setattr(socket, "create_connection", lambda address, *a, **k: connects.append(address) or (_ for _ in ()).throw(AssertionError("connected")))
    assert not verifies(client_for("http://localhost:9/v1/jwks"), token())
    assert connects == []


def test_localhost_resolving_to_loopback_is_connected_to_by_address_not_by_name(client_for, monkeypatch):
    server = JwksServer({KID: EMULATOR_KEY})
    connects = []
    real = socket.create_connection
    monkeypatch.setattr(socket, "create_connection", lambda address, *a, **k: connects.append(address) or real(address, *a, **k))
    try:
        port = server.server.server_port
        assert verifies(client_for(f"http://localhost:{port}/v1/jwks"), token())
        assert connects and all(address[0] in ("127.0.0.1", "::1") for address in connects)
    finally:
        server.close()


@pytest.mark.parametrize("url", ["http://10.1.2.3:9/v1/jwks", "http://example.invalid/v1/jwks", "https://127.0.0.1:9/v1/jwks", "http://[2001:db8::1]:9/v1/jwks"])
def test_the_client_itself_refuses_a_url_that_is_not_loopback_http(client_for, traffic, url):
    assert not verifies(client_for(url), token())
    assert traffic["connects"] == []


# --- the dependency this relies on --------------------------------------------------------------------------


@pytest.mark.parametrize("version, expected", [("2.15.1", True), ("2.16.0", True), ("3.0.0", True), ("2.10.1", True), ("2.9.0", False), ("1.7.1", False), ("2.10", False), ("junk", False), ("", False)])
def test_the_hook_is_installed_only_with_a_pyjwt_at_or_above_the_tested_floor(monkeypatch, version, expected):
    from firebase_admin import app_check

    monkeypatch.setattr(app_check, "_AppCheckService", app_check._AppCheckService)
    monkeypatch.setattr(jwt, "__version__", version)
    assert appcheck.install_jwks_hook("http://127.0.0.1:1/v1/jwks") is expected


# --- survivors of the scoped mutation run on the key client ---------------------------------------------------------

from jwt.exceptions import PyJWKClientError  # noqa: E402


def key_error(client, value):
    with pytest.raises(PyJWKClientError) as error:
        client.get_signing_key_from_jwt(value)
    return str(error.value)


def test_the_defaults_are_the_bounds_the_design_states():
    client = appcheck.LoopbackKeyClient("http://127.0.0.1:1/v1/jwks")
    assert (client._timeout, client._max_bytes, client._lifespan, client._refresh_interval) == (5.0, 256 * 1024, 21600, 1.0)


def test_the_exact_messages_of_the_key_client(client_for):
    assert key_error(client_for("http://127.0.0.1:1/v1/jwks", timeout=1), token()) == "the App Check keys could not be fetched"
    server = JwksServer({KID: EMULATOR_KEY})
    try:
        client = client_for(server.url)
        assert key_error(client, token(kid="nope")) == "unable to find a signing key that matches 'nope'"
        no_kid = jwt.encode({"exp": int(time.time()) + 60}, EMULATOR_KEY, algorithm="RS256")
        assert key_error(client, no_kid) == "the token has no key id"
        empty_kid = jwt.encode({"exp": int(time.time()) + 60}, EMULATOR_KEY, algorithm="RS256", headers={"kid": ""})
        assert key_error(client, empty_kid) == "the token has no key id"
    finally:
        server.close()


@pytest.mark.parametrize(
    "url, message",
    [
        ("https://127.0.0.1:9/v1/jwks", "the key URL is not a loopback http URL"),
        ("http:///v1/jwks", "the key URL is not a loopback http URL"),
        ("http://127.0.0.1/v1/jwks", "the key URL is not a loopback http URL"),
        ("http://10.1.2.3:9/v1/jwks", "10.1.2.3 is not a loopback address"),
    ],
)
def test_the_fetch_refuses_a_bad_url_with_its_reason(url, message):
    with pytest.raises(OSError) as error:
        appcheck.LoopbackKeyClient(url)._fetch()
    assert str(error.value) == message


def test_loopback_addresses_are_read_from_literals_and_from_names(monkeypatch):
    assert appcheck._loopback_addresses("127.0.0.1", 9) == ["127.0.0.1"]
    assert appcheck._loopback_addresses("[::1]", 9) == ["::1"]
    seen = {}

    def getaddrinfo(host, port, **kwargs):
        seen.update(host=host, port=port, kwargs=kwargs)
        return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1%lo0", port, 0, 1)), (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    assert appcheck._loopback_addresses("localhost", 4242) == ["::1", "127.0.0.1"]
    assert seen == {"host": "localhost", "port": 4242, "kwargs": {"type": socket.SOCK_STREAM}}


def test_the_messages_of_a_name_that_cannot_be_used(monkeypatch):
    def fail(*args, **kwargs):
        raise socket.gaierror("no such name")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    with pytest.raises(OSError) as error:
        appcheck._loopback_addresses("nowhere.invalid", 9)
    assert str(error.value) == "cannot resolve nowhere.invalid"
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [])
    with pytest.raises(OSError) as error:
        appcheck._loopback_addresses("empty.invalid", 9)
    assert str(error.value) == "empty.invalid is not a loopback address"


def test_connecting_tries_each_checked_address_and_reports_the_last_failure(monkeypatch):
    client = appcheck.LoopbackKeyClient("http://127.0.0.1:1/v1/jwks")
    attempts = []

    def create(address, timeout=None):
        attempts.append((address, timeout))
        raise OSError(f"refused by {address[0]}")

    monkeypatch.setattr(socket, "create_connection", create)
    with pytest.raises(OSError) as error:
        client._connect(["::1", "127.0.0.1"], 7)
    assert str(error.value) == "refused by 127.0.0.1"
    assert attempts == [(("::1", 7), 5.0), (("127.0.0.1", 7), 5.0)]
    with pytest.raises(OSError) as error:
        client._connect([], 7)
    assert str(error.value) == "no address"


def test_the_request_is_a_get_of_the_path_and_query_asking_for_json_and_closing_the_connection(client_for):
    seen = {}

    def reply(handler):
        seen.update(path=handler.path, accept=handler.headers.get("Accept"), connection=handler.headers.get("Connection"))
        answer(handler, body=KEYS_BODY)

    server = Scripted(reply)
    try:
        assert verifies(client_for(f"http://127.0.0.1:{server.port}/v1/jwks?format=jwk&x=1"), token())
        assert seen == {"path": "/v1/jwks?format=jwk&x=1", "accept": "application/json", "connection": "close"}
        assert verifies(client_for(f"http://127.0.0.1:{server.port}"), token())
        assert seen["path"] == "/"
    finally:
        server.close()


def test_a_body_that_never_ends_is_cut_at_the_bound_and_not_read_to_the_end(client_for):
    def endless(handler):
        handler.send_response(200)
        handler.send_header("Connection", "close")
        handler.end_headers()
        try:
            while True:
                handler.wfile.write(b" " * 65536)
        except OSError:
            return

    server = Scripted(endless)
    try:
        started = time.monotonic()
        assert not verifies(client_for(server.url, timeout=5, max_bytes=100000), token())
        assert time.monotonic() - started < 4, "the client read on instead of stopping at the bound"
    finally:
        server.close()


def test_a_key_set_may_hold_junk_around_the_one_key_that_counts(client_for):
    odd = [
        "junk",
        5,
        None,
        {"kty": "oct", "kid": "symmetric", "k": "c2VjcmV0"},
        {"kty": "RSA", "kid": "broken", "n": "!!", "e": "AQAB"},
        {"kty": "RSA", "n": "x", "e": "AQAB"},
        {**json.loads(RSAAlgorithm.to_jwk(EMULATOR_KEY.public_key())), "kid": KID},
    ]
    server = Scripted(lambda h: answer(h, body=json.dumps({"keys": odd}).encode()))
    try:
        client = client_for(server.url)
        assert verifies(client, token())
        assert key_error(client_for(server.url), token(kid="symmetric")).startswith("unable to find a signing key")
    finally:
        server.close()


def test_keys_are_refetched_when_their_lifespan_is_over_and_not_before(client_for):
    server = JwksServer({KID: EMULATOR_KEY})
    try:
        client = client_for(server.url, lifespan=0.3, refresh_interval=0)
        assert verifies(client, token()) and verifies(client, token())
        assert server.requests == 1
        time.sleep(0.35)
        assert verifies(client, token())
        assert server.requests == 2
    finally:
        server.close()


def test_a_failed_fetch_forgets_the_old_keys_and_tries_again_after_the_interval(client_for):
    state = {"up": True}

    def reply(handler):
        answer(handler, body=KEYS_BODY) if state["up"] else answer(handler, 503, b"{}")

    server = Scripted(reply)
    try:
        client = client_for(server.url, lifespan=0.2, refresh_interval=0.1)
        assert verifies(client, token())
        state["up"] = False
        time.sleep(0.25)
        assert key_error(client, token()) == "the App Check keys could not be fetched"
        state["up"] = True
        time.sleep(0.15)
        assert verifies(client, token())
    finally:
        server.close()


def test_a_cyclic_wrapper_chain_is_not_an_async_handler():
    from fireemu_runner.diagnostics import is_async_handler

    def loops(event):
        pass

    loops.__wrapped__ = loops
    assert is_async_handler(loops) is False


def test_the_body_is_read_with_a_bound_one_byte_past_the_limit(client_for, monkeypatch):
    import http.client

    amounts = []
    real = http.client.HTTPResponse.read

    def read(self, amt=None):
        amounts.append(amt)
        return real(self, amt)

    monkeypatch.setattr(http.client.HTTPResponse, "read", read)
    server = Scripted(lambda h: answer(h, body=KEYS_BODY))
    try:
        assert verifies(client_for(server.url, max_bytes=5000), token())
        assert amounts == [5001]
    finally:
        server.close()


def test_the_name_lookup_for_a_named_host_gets_the_servers_port(client_for, monkeypatch):
    server = JwksServer({KID: EMULATOR_KEY})
    seen = []
    real = socket.getaddrinfo
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, *a, **k: seen.append((host, port)) or real(host, port, *a, **k))
    try:
        port = server.server.server_port
        assert verifies(client_for(f"http://localhost:{port}/v1/jwks"), token())
        assert seen[0] == ("localhost", port)
    finally:
        server.close()


def fetch_error(reply):
    server = Scripted(reply)
    try:
        with pytest.raises((OSError, ValueError)) as error:
            appcheck.LoopbackKeyClient(server.url, max_bytes=1000)._fetch()
        return type(error.value).__name__, str(error.value)
    finally:
        server.close()


def test_the_exact_reasons_a_fetch_gives_up(client_for):
    assert fetch_error(lambda h: answer(h, 500, b"{}")) == ("OSError", "the key server answered 500")
    assert fetch_error(lambda h: answer(h, 302, b"", [("Location", "http://127.0.0.1:1/")])) == ("OSError", "the key server answered 302")
    assert fetch_error(lambda h: answer(h, body=b" " * 1001)) == ("OSError", "the key set is larger than the bound")
    assert fetch_error(lambda h: answer(h, body=b"[]")) == ("ValueError", "the key set has no keys list")
    assert fetch_error(lambda h: answer(h, body=b'{"keys": 3}')) == ("ValueError", "the key set has no keys list")
