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


@pytest.mark.parametrize("label,make", [
    ("other key", lambda: token(key=OTHER)),
    ("unknown kid", lambda: token(kid="unknown")),
    ("missing kid", lambda: token(kid=None)),
    ("unsigned", lambda: token(key=None, algorithm="none")),
    ("algorithm confusion", confused),
    ("expired", lambda: token(claims={"exp": int(time.time()) - 300})),
    ("future iat", lambda: token(claims={"iat": int(time.time()) + 300})),
    ("wrong issuer", lambda: token(claims={"iss": "wrong"})),
    ("missing subject", lambda: token(drop=("sub",))),
    ("tampered payload", tampered),
    ("empty", lambda: ""),
    ("audience list", lambda: token(aud=["run.app"])),
    ("long audience", lambda: token(aud="x" * 5000)),
])
def test_refusals(hooked, label, make):
    with pytest.raises(Exception):
        token_verifier.verify_auth_blocking_token(make())


@pytest.mark.parametrize("value", ["{", "[]", '{"keys":[]}', '{"keys":[{"kty":"EC"}]}', json.dumps({"keys": [{**jwk(), "kid": ""}]}), json.dumps({"keys": [{**jwk(), "n": "!"}]})])
def test_invalid_keys(value):
    assert blocking.parse_keys(value) is None


def test_two_keys_and_skipped_entry():
    result = blocking.parse_keys(json.dumps({"keys": [jwk(), {"kty": "EC"}, jwk(OTHER, "other")]}))
    assert set(result) == {KID, "other"}
    assert all(value.startswith("-----BEGIN PUBLIC KEY-----") for value in result.values())


def test_invalid_install_removes_value_and_announces(monkeypatch, capsys):
    old = token_verifier._JWTVerifier, token_verifier._auth_utils
    env = {blocking.ENVIRONMENT_VARIABLE: "invalid"}
    assert not blocking.install_from_environment(env)
    assert not env
    assert (token_verifier._JWTVerifier, token_verifier._auth_utils) == old
    lines = capsys.readouterr().err.splitlines()
    assert len(lines) == 1 and lines[0].startswith("[functions] note: ")


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
            with pytest.raises(Exception):
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
def test_unsupported_sdk_refuses_install(monkeypatch, capsys, attribute):
    monkeypatch.delattr(token_verifier, attribute)
    env = {blocking.ENVIRONMENT_VARIABLE: json.dumps({"keys": [jwk()]})}
    assert not blocking.install_from_environment(env)
    assert not env
    lines = capsys.readouterr().err.splitlines()
    assert len(lines) == 1 and lines[0].startswith("[functions] note: ")


def test_emulation_view_restored_after_verification_and_refusal(hooked):
    assert token_verifier._auth_utils.is_emulated()
    token_verifier.verify_auth_blocking_token(token())
    assert token_verifier._auth_utils.is_emulated()
    with pytest.raises(Exception):
        token_verifier.verify_auth_blocking_token(token(aud=PRODUCTION_AUD))
    assert token_verifier._auth_utils.is_emulated()
