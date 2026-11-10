"""Production Auth blocking verification uses the SDK with the daemon's public keys."""

import base64
import importlib.metadata
import hashlib
import hmac
import io
import json
import random
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from werkzeug.test import Client

from fireemu_runner import blocking, main
from fireemu_runner.framing import FrameWriter
from fireemu_runner.manifest import build_manifest
from fireemu_runner.serve import RunnerRouter
from firebase_functions.private import token_verifier

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER = rsa.generate_private_key(public_exponent=65537, key_size=2048)
KID = "daemon-key"
AUD = "https://pcblock-abc123-uc.a.run.app"
PRODUCTION_AUD = "https://us-central1-demo-proj.cloudfunctions.net/fn"
NOTE = '[functions] note: firebase-functions (Python) 0.6.0 accepts only a "run.app" audience in an Auth blocking token, while firebase-tools 15.28.2 registers the function\'s cloudfunctions.net address, so in production every Auth blocking function written with it fails with 503 "Error code: 47"; fireemu skips that check by default and runs it, so this function passes here (functions.authBlockingToken: "production", set by productionExact, reproduces the production failure)'


def jwk(key=KEY, kid=KID):
    return {**json.loads(RSAAlgorithm.to_jwk(key.public_key())), "kid": kid, "alg": "RS256", "use": "sig"}


def token(aud=AUD, key=KEY, kid=KID, claims=None, drop=(), algorithm="RS256"):
    now = int(time.time())
    payload = {"aud": aud, "iss": "https://securetoken.google.com/demo-proj", "sub": "user-1", "iat": now, "exp": now + 300, **(claims or {})}
    for name in drop:
        payload.pop(name, None)
    headers = {"typ": "JWT"}
    if kid is not None:
        headers["kid"] = kid
    return jwt.encode(payload, key, algorithm=algorithm, headers=headers)


@pytest.fixture
def hooked(monkeypatch, discovered):
    monkeypatch.setenv("FIREBASE_AUTH_EMULATOR_HOST", "127.0.0.1:9")
    monkeypatch.setattr(token_verifier, "_JWTVerifier", token_verifier._JWTVerifier)
    monkeypatch.setattr(token_verifier, "_auth_utils", token_verifier._auth_utils)
    env = {blocking.ENVIRONMENT_VARIABLE: json.dumps({"keys": [jwk()]})}
    assert blocking.install_from_environment(env)
    assert not env


def test_default_mode_is_unchanged(monkeypatch, discovered):
    monkeypatch.setenv("FIREBASE_AUTH_EMULATOR_HOST", "127.0.0.1:9")
    old = token_verifier._JWTVerifier, token_verifier._auth_utils
    assert not blocking.install_from_environment({})
    assert (token_verifier._JWTVerifier, token_verifier._auth_utils) == old
    assert token_verifier.verify_auth_blocking_token(token(key=None, algorithm="none"))["uid"] == "user-1"


def test_production_audience_refused_by_sdk_and_handler(hooked, discovered):
    value = token(aud=PRODUCTION_AUD)
    with pytest.raises(token_verifier.InvalidAuthBlockingTokenError, match='incorrect "aud"'):
        token_verifier.verify_auth_blocking_token(value)
    seen = discovered["bc_user"].__wrapped__.__globals__["SEEN"]
    before = len(seen)
    client = Client(RunnerRouter(discovered, build_manifest(discovered), "demo-proj", "s"))
    response = client.post("/demo-proj/us-central1/bc_user", data=json.dumps({"data": {"jwt": value}}), headers={"x-fireemu-runner-secret": "s", "content-type": "application/json"})
    assert response.status_code == 500
    assert json.loads(response.get_data()) == {"error": {"message": "INTERNAL", "status": "INTERNAL"}}
    assert len(seen) == before


def test_valid_token(hooked):
    assert token_verifier.verify_auth_blocking_token(token())["uid"] == "user-1"


def confused():
    pem = KEY.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "kid": KID, "typ": "JWT"}).encode()).rstrip(b"=")
    now = int(time.time())
    claims = {"aud": AUD, "iss": "https://securetoken.google.com/demo-proj", "sub": "user-1", "iat": now, "exp": now + 300}
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=")
    data = header + b"." + payload
    signature = base64.urlsafe_b64encode(hmac.new(pem, data, hashlib.sha256).digest()).rstrip(b"=")
    return (data + b"." + signature).decode()



def tampered():
    parts = token().split(".")
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    payload["sub"] = "attacker"
    parts[1] = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return ".".join(parts)


@pytest.mark.parametrize("label,make,error", [
    ("other key", lambda: token(key=OTHER), token_verifier.InvalidAuthBlockingTokenError),
    ("unknown kid", lambda: token(kid="unknown"), token_verifier.InvalidAuthBlockingTokenError),
    ("missing kid", lambda: token(kid=None), token_verifier.InvalidAuthBlockingTokenError),
    ("unsigned", lambda: token(key=None, algorithm="none"), token_verifier.InvalidAuthBlockingTokenError),
    ("algorithm confusion", confused, token_verifier.InvalidAuthBlockingTokenError),
    ("expired", lambda: token(claims={"exp": int(time.time()) - 300}), token_verifier.ExpiredAuthBlockingTokenError),
    ("future iat", lambda: token(claims={"iat": int(time.time()) + 300}), token_verifier.InvalidAuthBlockingTokenError),
    ("wrong issuer", lambda: token(claims={"iss": "wrong"}), token_verifier.InvalidAuthBlockingTokenError),
    ("missing subject", lambda: token(drop=("sub",)), token_verifier.InvalidAuthBlockingTokenError),
    ("tampered payload", tampered, token_verifier.InvalidAuthBlockingTokenError),
    ("audience list", lambda: token(aud=["run.app"]), token_verifier.InvalidAuthBlockingTokenError),
    ("long audience", lambda: token(aud="x" * 5000), token_verifier.InvalidAuthBlockingTokenError),
])
def test_refusals(hooked, label, make, error):
    with pytest.raises(error):
        token_verifier.verify_auth_blocking_token(make())

def test_empty_token_refused_by_sdk(hooked):
    with pytest.raises(ValueError):
        token_verifier.verify_auth_blocking_token("")


@pytest.mark.parametrize("value", ["{", "[]", '{"keys":[]}', '{"keys":[{"kty":"EC"}]}', json.dumps({"keys": [{**jwk(), "kid": ""}]}), json.dumps({"keys": [{**jwk(), "n": "!"}]})])
def test_invalid_keys(value):
    assert blocking.parse_keys(value) is None


def test_two_keys_and_skipped_entry():
    result = blocking.parse_keys(json.dumps({"keys": [jwk(), {"kty": "EC"}, jwk(OTHER, "other")]}))
    assert set(result) == {KID, "other"}
    assert all(value.startswith("-----BEGIN PUBLIC KEY-----") for value in result.values())


@pytest.mark.parametrize("value", ["", "{", "[]", '{"keys":[]}', '{"keys":[{"kty":"EC"}]}', json.dumps({"keys": [{k: v for k, v in jwk().items() if k != "kid"}]})])
def test_invalid_install_fails_closed(value):
    old = token_verifier._JWTVerifier, token_verifier._auth_utils
    env = {blocking.ENVIRONMENT_VARIABLE: value}
    with pytest.raises(blocking.VerificationUnavailable):
        blocking.install_from_environment(env)
    assert not env
    assert (token_verifier._JWTVerifier, token_verifier._auth_utils) == old


def test_failed_install_leaves_stock_emulated_verifier(monkeypatch, discovered):
    monkeypatch.setenv("FIREBASE_AUTH_EMULATOR_HOST", "127.0.0.1:9")
    with pytest.raises(blocking.VerificationUnavailable):
        blocking.install_from_environment({blocking.ENVIRONMENT_VARIABLE: '{"keys":[]}'})
    assert token_verifier.verify_auth_blocking_token(token(key=None, algorithm="none"))["uid"] == "user-1"


def test_a_run_app_audience_signed_by_the_key_verifies_end_to_end(monkeypatch, discovered):
    monkeypatch.setenv("FIREBASE_AUTH_EMULATOR_HOST", "127.0.0.1:9")
    monkeypatch.setattr(token_verifier, "_JWTVerifier", token_verifier._JWTVerifier)
    monkeypatch.setattr(token_verifier, "_auth_utils", token_verifier._auth_utils)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert blocking.install_from_environment({blocking.ENVIRONMENT_VARIABLE: json.dumps({"keys": [jwk(key)]})})
    value = token(key=key, claims={"event_id": "event-1", "event_type": "beforeCreate", "ip_address": "127.0.0.1", "user_agent": "Google-Firebase", "locale": "und", "sign_in_method": "password", "user_record": {"uid": "user-1"}})
    claims = token_verifier.verify_auth_blocking_token(value)
    assert claims["uid"] == claims["sub"] == "user-1"
    parts = value.split(".")
    payload = bytearray(base64.urlsafe_b64decode(parts[1] + "=="))
    payload[payload.index(b"user-1")] ^= 1
    parts[1] = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    with pytest.raises(token_verifier.InvalidAuthBlockingTokenError):
        token_verifier.verify_auth_blocking_token(".".join(parts))


def test_seeded_audiences(hooked):
    rng = random.Random(1234)
    audiences = ["", "x" * 5000, "run.app" + "x" * 5000]
    for _ in range(197):
        audiences.append("".join(rng.choice(["a", "b", ".", "run.app"]) for _ in range(rng.randrange(30))))
    for audience in audiences:
        value = token(aud=audience)
        if "run.app" in audience:
            assert token_verifier.verify_auth_blocking_token(value)["uid"] == "user-1"
        else:
            with pytest.raises(token_verifier.InvalidAuthBlockingTokenError):
                token_verifier.verify_auth_blocking_token(value)


def test_default_note():
    assert blocking.default_note("0.6.0") == NOTE
    assert blocking.default_note("0.7.0") is None
    assert blocking.default_note(None) is None


@pytest.mark.parametrize("verified,has_blocking,version", [(False, True, "0.6.0"), (False, False, "0.6.0"), (True, True, "0.6.0"), (False, True, "0.7.0"), (True, False, "0.7.0")])
def test_serve_diagnostic_combinations(discovered, monkeypatch, capsys, verified, has_blocking, version):
    monkeypatch.setattr(blocking.importlib.metadata, "version", lambda _: version)
    monkeypatch.setattr(main, "start_server", lambda *args: (type("Server", (), {"shutdown": lambda self: None})(), 1))
    functions = {"bc_user": discovered["bc_user"]} if has_blocking else {}
    assert main.serve(functions, "cb", "s", io.BytesIO(), FrameWriter(io.BytesIO()), blocking_verified=verified) == 0
    assert capsys.readouterr().err == (NOTE + "\n" if has_blocking and not verified and version == "0.6.0" else "")


def test_serve_diagnostic_installed_version(discovered, monkeypatch, capsys):
    version = importlib.metadata.version("firebase-functions")
    monkeypatch.setattr(main, "start_server", lambda *args: (type("Server", (), {"shutdown": lambda self: None})(), 1))
    main.serve({"bc_user": discovered["bc_user"]}, "cb", "s", io.BytesIO(), FrameWriter(io.BytesIO()))
    note = blocking.default_note(version)
    assert capsys.readouterr().err == (note + "\n" if note else "")


@pytest.mark.parametrize("attribute", ["_JWTVerifier", "_auth_utils", "_token_gen"])
def test_unsupported_sdk_refuses_install(monkeypatch, attribute):
    monkeypatch.delattr(token_verifier, attribute, raising=True)
    old = {name: getattr(token_verifier, name, None) for name in ("_JWTVerifier", "_auth_utils", "_token_gen")}
    env = {blocking.ENVIRONMENT_VARIABLE: json.dumps({"keys": [jwk()]})}
    with pytest.raises(blocking.VerificationUnavailable):
        blocking.install_from_environment(env)
    assert not env
    assert {name: getattr(token_verifier, name, None) for name in old} == old


def test_emulation_view_restored_after_verification_and_refusal(hooked):
    assert token_verifier._auth_utils.is_emulated()
    token_verifier.verify_auth_blocking_token(token())
    assert token_verifier._auth_utils.is_emulated()
    with pytest.raises(token_verifier.InvalidAuthBlockingTokenError):
        token_verifier.verify_auth_blocking_token(token(aud=PRODUCTION_AUD))
    assert token_verifier._auth_utils.is_emulated()


def test_runner_fails_before_loading_user_code_or_hello(tmp_path):
    from harness import Runner

    marker = tmp_path / "loaded"
    (tmp_path / "main.py").write_text("from pathlib import Path\nPath(__file__).with_name('loaded').touch()\n")
    process = Runner(source=tmp_path, extra_env={blocking.ENVIRONMENT_VARIABLE: '{"keys":[]}'})
    try:
        assert process.process.wait(timeout=10) != 0
        for reader in process._readers:
            reader.join(timeout=5)
        assert "not serving" in process.stderr
        assert not process.frames
        assert not marker.exists()
    finally:
        process.kill()


def test_run_fails_before_loading_user_code(monkeypatch, tmp_path, capsys):
    from test_run import Wiring

    wiring = Wiring(monkeypatch)
    monkeypatch.setenv(blocking.ENVIRONMENT_VARIABLE, '{"keys":[]}')
    monkeypatch.setattr(main, "load_codebase", lambda source: pytest.fail("user code loaded"))
    assert main.run(["--source", str(tmp_path)]) == 1
    assert "not serving" in capsys.readouterr().err
    assert wiring.frames() == []


def test_runner_rejects_production_audience_with_jwks():
    from harness import Runner

    process = Runner(extra_env={blocking.ENVIRONMENT_VARIABLE: json.dumps({"keys": [jwk()]})})
    try:
        value = token(aud="https://us-central1-demo-proj.cloudfunctions.net/bc_user", claims={"event_id": "event-1", "event_type": "beforeCreate", "ip_address": "127.0.0.1", "user_agent": "test", "locale": "und", "user_record": {"uid": "user-1", "email": "plain@example.com", "metadata": {"creation_time": 0}, "provider_data": []}})
        status, _, _ = process.request("/demo-proj/us-central1/bc_user", method="POST", body={"data": {"jwt": value}})
        assert status == 500
        assert process.close() == 0
        assert 'incorrect "aud"' in process.stderr
        assert "functions.authBlockingToken" not in process.stderr
    finally:
        process.kill()


def test_runner_accepts_emulated_token_and_announces_default():
    from harness import Runner

    process = Runner()
    try:
        value = token(aud="http://127.0.0.1:1/demo-proj/us-central1/bc_user", key=None, algorithm="none", claims={"event_id": "event-1", "event_type": "beforeCreate", "ip_address": "127.0.0.1", "user_agent": "test", "user_record": {"uid": "user-1", "email": "plain@example.com", "metadata": {"creation_time": 0}, "provider_data": []}})
        status, _, _ = process.request("/demo-proj/us-central1/bc_user", method="POST", body={"data": {"jwt": value}})
        assert status == 200
        assert any(entry["function"] == "bc_user" for entry in process.seen())
        assert process.close() == 0
        note = blocking.default_note(importlib.metadata.version("firebase-functions"))
        assert note is not None
        assert process.stderr.count(note) == 1
    finally:
        process.kill()


@pytest.mark.parametrize("attribute, value", [
    ("_JWTVerifier", None),
    ("_auth_utils", type("NoEmulationCheck", (), {"is_emulated": None})()),
])
def test_an_sdk_whose_internals_differ_is_refused_not_ignored(monkeypatch, attribute, value):
    monkeypatch.setattr(token_verifier, attribute, value)
    env = {blocking.ENVIRONMENT_VARIABLE: json.dumps({"keys": [jwk()]})}
    with pytest.raises(blocking.VerificationUnavailable, match="unsupported SDK"):
        blocking.install_from_environment(env)
    assert not env


def test_an_sdk_without_a_certificate_url_is_refused_not_ignored(monkeypatch):
    monkeypatch.setattr(token_verifier._token_gen, "ID_TOKEN_CERT_URI", "")
    env = {blocking.ENVIRONMENT_VARIABLE: json.dumps({"keys": [jwk()]})}
    with pytest.raises(blocking.VerificationUnavailable, match="unsupported SDK"):
        blocking.install_from_environment(env)
    assert not env
