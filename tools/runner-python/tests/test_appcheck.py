"""Callable App Check for Python functions. SECURITY-SENSITIVE: read with the design in the slice 2b plan, point 4.

The Python SDK verifies the `X-Firebase-AppCheck` token of a callable itself, with the Admin SDK, against
Google's JWKS. The runner points the Admin SDK at the App Check emulator's JWKS when the daemon says there is
one (`FIREEMU_APP_CHECK_JWKS_URL`), and only then tells the daemon to forward the header. These tests use the real
SDK and a real local JWKS server and show:

- the hook: a token the emulator's key signed verifies; a forged token, a token another key signed (also under the
  emulator's `kid`), an unknown `kid`, an expired token, a wrong audience, `alg: none` and an HS256 token keyed with
  the public key are all refused (nothing reaches `request.app`, and an enforcing callable answers 401);
- the announcement: `consumeAppCheckToken` is `disabled` only when the hook is installed. Without an emulator the
  value stays undetermined, so the daemon removes the header before the function and no JWKS is ever fetched.
"""

import base64
import json
import socketserver
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from werkzeug.test import Client

from fireemu_runner import appcheck
from fireemu_runner.manifest import build_manifest
from fireemu_runner.serve import RunnerRouter

PROJECT = "demo-proj"
SECRET = "s3cret"


class LoopbackServer(HTTPServer):
    """`HTTPServer.server_bind` asks DNS for the host's name (`socket.getfqdn`), which takes tens of seconds on some CI
    runners; these servers only ever listen on the loopback address."""

    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = "127.0.0.1", self.socket.getsockname()[1]


def make_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


EMULATOR_KEY = make_key()
OTHER_KEY = make_key()
KID = "emulator-kid-1"


class JwksServer:
    """Serves one JWKS and counts the requests."""

    def __init__(self, keys):
        self.requests = 0
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                outer.requests += 1
                body = json.dumps({"keys": [{**json.loads(RSAAlgorithm.to_jwk(key.public_key())), "kid": kid, "alg": "RS256", "use": "sig"} for kid, key in keys.items()]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = LoopbackServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}/v1/jwks"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def token(key=EMULATOR_KEY, kid=KID, audience=None, expires_in=3600, algorithm="RS256", extra_headers=None, claims=None, drop=()):
    now = int(time.time())
    payload = {
        "iss": "https://firebaseappcheck.googleapis.com/1234567890",
        "aud": audience if audience is not None else ["projects/1234567890", f"projects/{PROJECT}"],
        "sub": "1:1234567890:web:app",
        "iat": now,
        "exp": now + expires_in,
        **(claims or {}),
    }
    for name in drop:
        payload.pop(name, None)
    headers = {"kid": kid, "typ": "JWT", **(extra_headers or {})}
    return jwt.encode(payload, key, algorithm=algorithm, headers=headers)


@pytest.fixture
def hooked(monkeypatch, discovered):
    """The Admin SDK pointed at a local JWKS server, with a fresh App Check service."""
    import firebase_admin
    from firebase_admin import app_check

    server = JwksServer({KID: EMULATOR_KEY})
    # The runner has no Google credentials (the daemon points them at a file that does not exist); the stock service
    # needs them to build its HTTP client, which only limited-use consumption would use.
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/nonexistent/no-credentials.json")
    monkeypatch.setattr(app_check, "_AppCheckService", app_check._AppCheckService)
    assert appcheck.install_jwks_hook(server.url) is True
    # `discovered` created the default app; its App Check service (and its key cache) is built on first use.
    with firebase_admin.get_app()._lock:
        firebase_admin.get_app()._services.pop(app_check._APP_CHECK_ATTRIBUTE, None)
    yield server
    server.close()


def verify(value):
    from firebase_admin import app_check

    return app_check.verify_token(value)


# --- the hook ----------------------------------------------------------------------------------------


def test_a_token_the_emulators_key_signed_verifies(hooked):
    claims = verify(token())
    assert claims["sub"] == "1:1234567890:web:app" and claims["app_id"] == "1:1234567890:web:app"
    assert hooked.requests >= 1


@pytest.mark.parametrize(
    "label, make",
    [
        ("another key under the emulator's kid", lambda: token(key=OTHER_KEY)),
        ("an unknown kid", lambda: token(kid="no-such-kid")),
        ("an expired token", lambda: token(expires_in=-60)),
        ("another project's audience", lambda: token(audience=["projects/1", "projects/other-project"])),
        ("no audience claim at all", lambda: token(audience=[])),
        ("alg none", lambda: jwt.encode({"aud": [f"projects/{PROJECT}"], "sub": "x", "exp": int(time.time()) + 600}, key=None, algorithm="none", headers={"kid": KID, "typ": "JWT"})),
        ("a bare string", lambda: "not.a.token"),
        ("an empty token", lambda: ""),
        ("a token without a typ header", lambda: jwt.encode({"aud": [f"projects/{PROJECT}"], "sub": "x", "exp": int(time.time()) + 600}, EMULATOR_KEY, algorithm="RS256", headers={"kid": KID, "typ": "other"})),
    ],
)
def test_every_token_the_emulators_key_did_not_sign_for_this_project_is_refused(hooked, label, make):
    with pytest.raises(Exception):
        verify(make())


def test_an_hs256_token_keyed_with_the_public_key_is_refused(hooked):
    # The classic algorithm-confusion forgery: the public JWK as an HMAC secret.
    public_pem = EMULATOR_KEY.public_key().public_bytes(
        encoding=__import__("cryptography").hazmat.primitives.serialization.Encoding.PEM,
        format=__import__("cryptography").hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    now = int(time.time())
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT", "kid": KID}).encode()).rstrip(b"=")
    payload = base64.urlsafe_b64encode(json.dumps({"aud": [f"projects/{PROJECT}"], "sub": "x", "exp": now + 600}).encode()).rstrip(b"=")
    import hashlib
    import hmac

    signature = base64.urlsafe_b64encode(hmac.new(public_pem, header + b"." + payload, hashlib.sha256).digest()).rstrip(b"=")
    with pytest.raises(Exception):
        verify((header + b"." + payload + b"." + signature).decode())


def test_a_tampered_payload_is_refused(hooked):
    header, payload, signature = token().split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    claims["sub"] = "forged-app"
    forged = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    with pytest.raises(Exception):
        verify(f"{header}.{forged}.{signature}")


def test_the_hook_never_touches_the_production_url_when_it_is_installed(hooked):
    from firebase_admin import app_check

    assert app_check._AppCheckService._JWKS_URL == hooked.url
    assert "googleapis.com" not in app_check._AppCheckService._JWKS_URL


def test_limited_use_consumption_is_refused_without_a_request_to_google(hooked):
    from firebase_admin import app_check, exceptions

    with pytest.raises(exceptions.FailedPreconditionError, match="APP_CHECK_REPLAY_UNSUPPORTED"):
        app_check.verify_token(token(), consume=True)


def test_a_project_without_an_id_is_refused_like_the_stock_service(hooked, monkeypatch):
    import firebase_admin
    from firebase_admin import app_check

    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    monkeypatch.delenv("GCLOUD_PROJECT", raising=False)
    app = firebase_admin.initialize_app(name="no-project", options={})
    try:
        with pytest.raises(ValueError, match="project ID must be specified"):
            app_check.verify_token(token(), app=app)
    finally:
        firebase_admin.delete_app(app)


# --- reading the daemon's variable ---------------------------------------------------------------------


@pytest.mark.parametrize("value", ["http://127.0.0.1:41234/v1/jwks", "http://localhost:9/v1/jwks", "http://[::1]:5000/v1/jwks"])
def test_a_loopback_http_url_is_accepted(value):
    assert appcheck.jwks_url({"FIREEMU_APP_CHECK_JWKS_URL": value}) == value


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "https://firebaseappcheck.googleapis.com/v1/jwks",
        "http://firebaseappcheck.googleapis.com/v1/jwks",
        "http://example.com/v1/jwks",
        "http://127.0.0.1.evil.example/v1/jwks",
        "http://127.0.0.1@evil.example/v1/jwks",
        "http://evil.example#@127.0.0.1/v1/jwks",
        "http://10.0.0.5:80/v1/jwks",
        "file:///etc/passwd",
        "ftp://127.0.0.1/v1/jwks",
        "http://127.0.0.1",
        "http://127.0.0.1:99999/v1/jwks",
        "javascript:alert(1)",
        "127.0.0.1:80/v1/jwks",
    ],
)
def test_anything_but_a_loopback_http_url_is_refused_so_nothing_leaves_the_machine(value):
    environ = {} if value is None else {"FIREEMU_APP_CHECK_JWKS_URL": value}
    assert appcheck.jwks_url(environ) is None


def test_the_hook_is_not_installed_without_a_url_or_when_the_sdk_is_not_the_one_it_was_written_for(monkeypatch):
    from firebase_admin import app_check

    monkeypatch.setattr(app_check, "_AppCheckService", app_check._AppCheckService)
    stock = app_check._AppCheckService
    assert appcheck.install_from_environment({}) is False
    assert app_check._AppCheckService is stock
    for missing in ("_JWKS_URL", "_decode_and_verify", "_has_valid_token_headers", "_APP_CHECK_HEADERS"):
        monkeypatch.delattr(stock, missing)
        assert appcheck.install_jwks_hook("http://127.0.0.1:1/v1/jwks") is False, missing
        assert app_check._AppCheckService is stock, missing
        monkeypatch.undo()
        monkeypatch.setattr(app_check, "_AppCheckService", stock)


def test_install_from_environment_installs_a_valid_url_and_reports_it(monkeypatch):
    from firebase_admin import app_check

    monkeypatch.setattr(app_check, "_AppCheckService", app_check._AppCheckService)
    assert appcheck.install_from_environment({"FIREEMU_APP_CHECK_JWKS_URL": "http://127.0.0.1:7/v1/jwks"}) is True
    assert app_check._AppCheckService._JWKS_URL == "http://127.0.0.1:7/v1/jwks"


# --- the announcement ------------------------------------------------------------------------------------


def callable_entry(manifest, name):
    (entry,) = [e for e in manifest["functions"] if e["name"] == name]
    return entry["trigger"]


def test_callables_say_consumeAppCheckToken_disabled_only_when_the_hook_is_installed(discovered):
    off = build_manifest(discovered)
    on = build_manifest(discovered, app_check_verified=True)
    for name in ("add", "refuse", "add_enforced"):
        assert "consumeAppCheckToken" not in callable_entry(off, name)
        assert callable_entry(on, name)["consumeAppCheckToken"] == "disabled"
    # An onRequest function and the non-HTTP triggers say nothing about App Check.
    assert callable_entry(on, "hello") == {"type": "http", "callable": False}


# --- through the router with the real SDK wrapper --------------------------------------------------------


@pytest.fixture
def client(discovered, hooked):
    return Client(RunnerRouter(discovered, build_manifest(discovered, app_check_verified=True), PROJECT, SECRET))


def call(client, name, app_check=None, *, headers=None):
    request_headers = {"x-fireemu-runner-secret": SECRET, "content-type": "application/json", **(headers or {})}
    if app_check is not None:
        request_headers["X-Firebase-AppCheck"] = app_check
    response = client.open(f"/{PROJECT}/us-central1/{name}", method="POST", data=json.dumps({"data": {"a": 1, "b": 2}}), headers=request_headers, buffered=True)
    return response.status_code, json.loads(response.get_data())


def test_an_enforcing_callable_refuses_a_call_without_a_token(client):
    status, body = call(client, "add_enforced")
    assert status == 401 and body["error"]["status"] == "UNAUTHENTICATED"


@pytest.mark.parametrize(
    "make",
    [lambda: token(key=OTHER_KEY), lambda: token(kid="nope"), lambda: token(expires_in=-5), lambda: "junk", lambda: token(audience=["projects/x"])],
)
def test_an_enforcing_callable_refuses_every_token_that_does_not_verify(client, make):
    status, body = call(client, "add_enforced", make())
    assert status == 401 and body["error"]["status"] == "UNAUTHENTICATED" and "result" not in body


def test_an_enforcing_callable_runs_for_a_token_that_verifies_and_sees_the_app(client):
    status, body = call(client, "add_enforced", token())
    assert status == 200 and body["result"]["app"] == "1:1234567890:web:app" and body["result"]["sum"] == 3


def test_a_non_enforcing_callable_gets_no_app_for_a_token_that_does_not_verify(client):
    for bad in (token(key=OTHER_KEY), "junk", token(expires_in=-5)):
        status, body = call(client, "add_enforced_off", bad)
        assert status == 200 and body["result"]["app"] is None


def test_a_non_enforcing_callable_gets_the_app_for_a_token_that_verifies(client):
    status, body = call(client, "add_enforced_off", token())
    assert status == 200 and body["result"]["app"] == "1:1234567890:web:app"


def test_two_app_check_headers_never_let_a_forged_one_through(client):
    # The Werkzeug server joins repeated fields with a comma, which is not a token.
    status, body = call(client, "add_enforced", token() + ", " + token(key=OTHER_KEY))
    assert status == 401 and "result" not in body
    status, body = call(client, "add_enforced", token(key=OTHER_KEY) + ", " + token())
    assert status == 401 and "result" not in body


def test_an_auth_token_does_not_stand_in_for_an_app_check_token(client):
    status, body = call(client, "add_enforced", headers={"Authorization": "Bearer something"})
    assert status == 401


def test_the_runner_never_fetches_keys_for_a_call_that_presents_no_token(client, hooked):
    before = hooked.requests
    call(client, "add_enforced")
    call(client, "add_enforced_off")
    assert hooked.requests == before


# --- the keys cannot be had: refuse, never accept ---------------------------------------------------------


class BrokenJwks:
    """A key server that answers badly."""

    def __init__(self, status, body):
        outer_status, outer_body = status, body

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(outer_status)
                self.send_header("Content-Length", str(len(outer_body)))
                self.end_headers()
                self.wfile.write(outer_body)

            def log_message(self, *args):
                pass

        self.server = LoopbackServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_port}/v1/jwks"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.mark.parametrize("failure", ["closed port", "empty key set", "server error", "not json", "key without material"])
def test_an_enforcing_callable_refuses_a_valid_looking_token_when_the_keys_cannot_be_had(discovered, monkeypatch, failure):
    import firebase_admin
    from firebase_admin import app_check

    broken = None
    if failure == "closed port":
        url = "http://127.0.0.1:1/v1/jwks"
    else:
        body = {
            "empty key set": json.dumps({"keys": []}).encode(),
            "server error": b"{}",
            "not json": b"<html>",
            "key without material": json.dumps({"keys": [{"kid": KID, "kty": "RSA"}]}).encode(),
        }[failure]
        broken = BrokenJwks(500 if failure == "server error" else 200, body)
        url = broken.url
    monkeypatch.setattr(app_check, "_AppCheckService", app_check._AppCheckService)
    assert appcheck.install_jwks_hook(url) is True
    with firebase_admin.get_app()._lock:
        firebase_admin.get_app()._services.pop(app_check._APP_CHECK_ATTRIBUTE, None)
    try:
        client = Client(RunnerRouter(discovered, build_manifest(discovered, app_check_verified=True), PROJECT, SECRET))
        status, body = call(client, "add_enforced", token())
        assert status == 401 and "result" not in body
        status, body = call(client, "add_enforced_off", token())
        assert status == 200 and body["result"]["app"] is None
    finally:
        if broken is not None:
            broken.close()
        with firebase_admin.get_app()._lock:
            firebase_admin.get_app()._services.pop(app_check._APP_CHECK_ATTRIBUTE, None)


# --- a pairwise matrix: function x token x key server --------------------------------------------------------
#
# The rows were generated with PICT from a model of those three factors (pairwise, with the seed rows forced in:
# a valid token for both functions, a foreign key, a tampered payload, a doubled header and a down key server for the
# enforcing one). The oracle is independent of the SDK: a call is authenticated as the app if and only if the token is
# the emulator's own, the key server is up, and nothing else is wrong with the call.

MATRIX = [
    ("add_enforced", "valid", "up"),
    ("add_enforced_off", "valid", "up"),
    ("add_enforced", "none", "up"),
    ("add_enforced", "foreign_key", "up"),
    ("add_enforced", "tampered", "up"),
    ("add_enforced", "valid", "down"),
    ("add_enforced_off", "foreign_key", "up"),
    ("add_enforced", "doubled", "up"),
    ("add_enforced", "unknown_kid", "up"),
    ("add_enforced_off", "unknown_kid", "down"),
    ("add_enforced", "expired", "up"),
    ("add_enforced", "junk", "empty"),
    ("add_enforced_off", "foreign_key", "empty"),
    ("add_enforced_off", "doubled", "down"),
    ("add_enforced_off", "foreign_key", "down"),
    ("add_enforced", "doubled", "empty"),
    ("add_enforced_off", "none", "down"),
    ("add_enforced_off", "expired", "empty"),
    ("add_enforced_off", "junk", "up"),
    ("add_enforced_off", "expired", "down"),
    ("add_enforced", "none", "empty"),
    ("add_enforced", "wrong_audience", "empty"),
    ("add_enforced_off", "wrong_audience", "down"),
    ("add_enforced_off", "tampered", "down"),
    ("add_enforced_off", "valid", "empty"),
    ("add_enforced_off", "unknown_kid", "empty"),
    ("add_enforced_off", "junk", "down"),
    ("add_enforced_off", "wrong_audience", "up"),
    ("add_enforced_off", "tampered", "empty"),
]

TOKENS = {
    "none": lambda: None,
    "valid": lambda: token(),
    "tampered": lambda: _tampered(),
    "foreign_key": lambda: token(key=OTHER_KEY),
    "unknown_kid": lambda: token(kid="unknown"),
    "expired": lambda: token(expires_in=-30),
    "wrong_audience": lambda: token(audience=["projects/9", "projects/elsewhere"]),
    "doubled": lambda: token() + ", " + token(),
    "junk": lambda: "x.y.z",
}


def _tampered():
    header, payload, signature = token().split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    claims["sub"] = "forged"
    return f"{header}.{base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b'=').decode()}.{signature}"


@pytest.mark.parametrize("function, kind, keys", MATRIX)
def test_each_row_authenticates_the_app_only_for_the_emulators_own_token(discovered, monkeypatch, function, kind, keys):
    import firebase_admin
    from firebase_admin import app_check

    servers = []
    if keys == "up":
        server = JwksServer({KID: EMULATOR_KEY})
        servers.append(server)
        url = server.url
    elif keys == "empty":
        server = BrokenJwks(200, json.dumps({"keys": []}).encode())
        servers.append(server)
        url = server.url
    else:
        url = "http://127.0.0.1:1/v1/jwks"
    monkeypatch.setattr(app_check, "_AppCheckService", app_check._AppCheckService)
    assert appcheck.install_jwks_hook(url) is True
    with firebase_admin.get_app()._lock:
        firebase_admin.get_app()._services.pop(app_check._APP_CHECK_ATTRIBUTE, None)
    try:
        client = Client(RunnerRouter(discovered, build_manifest(discovered, app_check_verified=True), PROJECT, SECRET))
        status, body = call(client, function, TOKENS[kind]())
    finally:
        for server in servers:
            server.close()
        with firebase_admin.get_app()._lock:
            firebase_admin.get_app()._services.pop(app_check._APP_CHECK_ATTRIBUTE, None)
    authenticated = kind == "valid" and keys == "up"
    if authenticated:
        assert status == 200 and body["result"]["app"] == "1:1234567890:web:app"
    elif function == "add_enforced":
        assert status == 401 and "result" not in body
    else:
        assert status == 200 and body["result"]["app"] is None


# --- survivors of the mutation run on the App Check module ----------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        5,
        True,
        ["http://127.0.0.1:9/v1/jwks"],
        "https://127.0.0.1:9/v1/jwks",  # a loopback host over TLS is still not what the daemon names
        "http://user@127.0.0.1:9/v1/jwks",
        "http://:password@127.0.0.1:9/v1/jwks",
        "http://user:password@127.0.0.1:9/v1/jwks",
        "http:///v1/jwks",
        "http://127.0.0.1:9/v1/jwks#fragment",
        "http://127.0.0.1:9/",
        "http://127.0.0.1:9",
        "http://127.0.0.1:9?x=/v1/jwks",
        "http://127.0.0.1/v1/jwks",
        "http://localhost/v1/jwks",
    ],
)
def test_each_condition_of_the_url_check_refuses_on_its_own(value):
    assert appcheck.jwks_url({"FIREEMU_APP_CHECK_JWKS_URL": value}) is None


@pytest.mark.parametrize("value", ["http://127.0.0.1:9/a", "http://127.0.0.1:9/v1/jwks?x=1", "http://127.0.0.1:65535/k"])
def test_the_shortest_path_and_a_query_are_fine(value):
    assert appcheck.jwks_url({"FIREEMU_APP_CHECK_JWKS_URL": value}) == value


def test_an_sdk_without_the_service_at_all_gets_no_hook(monkeypatch):
    from firebase_admin import app_check

    monkeypatch.delattr(app_check, "_AppCheckService")
    assert appcheck.install_jwks_hook("http://127.0.0.1:1/v1/jwks") is False


def test_the_service_keeps_the_stock_key_client_settings_and_has_no_way_to_reach_google(hooked):
    import firebase_admin
    from firebase_admin import app_check

    service = app_check._get_app_check_service(firebase_admin.get_app())
    assert isinstance(service._jwks_client, appcheck.LoopbackKeyClient)
    assert service._jwks_client._lifespan == 21600
    assert service._jwks_client._headers == app_check._AppCheckService._APP_CHECK_HEADERS
    assert service._jwks_client._headers.get("x-goog-api-client")
    assert service._http_client is None
    assert service._scoped_project_id == "projects/" + service._project_id and service._project_id == PROJECT


def test_the_exact_messages_of_the_replacement_service(hooked, monkeypatch):
    import firebase_admin
    from firebase_admin import app_check, exceptions

    with pytest.raises(exceptions.FailedPreconditionError) as error:
        app_check.verify_token(token(), consume=True)
    assert str(error.value) == "limited-use App Check token consumption is not available in fireemu (APP_CHECK_REPLAY_UNSUPPORTED)"
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    monkeypatch.delenv("GCLOUD_PROJECT", raising=False)
    app = firebase_admin.initialize_app(name="no-project-2", options={})
    try:
        with pytest.raises(ValueError) as error:
            app_check.verify_token(token(), app=app)
        assert str(error.value) == (
            "A project ID must be specified to access the App Check service. Either set the projectId option, "
            "use service account credentials, or set the GOOGLE_CLOUD_PROJECT environment variable."
        )
    finally:
        firebase_admin.delete_app(app)
