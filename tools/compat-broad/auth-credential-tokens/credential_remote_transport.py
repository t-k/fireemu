"""Fixed-origin, bounded HTTPS transport for the AUTH-CREDENTIAL production run.

Every call here carries one frozen Gate slot: the declared path names the route,
the run-time body carries the values the slot binds, and the secrets (the owner's
bearer token and the Web API key) are attached here and nowhere else. They travel to
the isolated worker on stdin, never on argv, and never enter a journal.

The worker is a single reviewed source file whose bytes this module pins by digest
before spawning it. The pinned digest is the integrity binding the campaign's O8
capability carries, so a capability issued against other bytes cannot reach the wire
through this path. It is an integrity binding, not a secret and not an authority.

A loopback fixture origin exists for the transport's own tests; the production
adapter never supplies one, and the worker refuses a loopback target unless it was
started as a fixture worker.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import os
import subprocess
import sys
import time
from dataclasses import dataclass
import urllib.parse
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "o8-core"))
sys.path.insert(0, str(HERE))

from credential_gate import IDENTITY, SECURE
from credential_wire import response_body
from o8_admission import authorize_transport

WORKER_ENTRY = "credential_https_worker.py"
WORKER_SHA256 = "4941cc4c5838f16cd6368b82af8d93c2c8c3064b1f9cd279daedeee0abb39953"
MAX_SECONDS = 12.0
MAX_ENVELOPE_BYTES = 65536
MAX_OUTPUT_BYTES = 90000
PROJECT = "fireemu-35fe6"
SIGN_BLOB_HOST = "iamcredentials.googleapis.com"
CUSTOM_TOKEN_HEADER = {"alg": "RS256", "typ": "JWT"}


@dataclass(frozen=True)
class WorkerExchange:
    status: int
    body: dict[str, Any]
    worker_reaped: bool


class WorkerFailure(ValueError):
    """A secret-free worker failure with an observed child lifecycle result."""

    def __init__(self, message: str, *, worker_reaped: bool):
        super().__init__(message)
        self.worker_reaped = worker_reaped


def worker_binding() -> tuple[bytes, str]:
    """The reviewed worker source and its digest, read from the lane."""
    source = (HERE / WORKER_ENTRY).read_bytes()
    return source, hashlib.sha256(source).hexdigest()


def verify_worker_binding(binding: Any, binding_digest: Any, frozen: Any) -> None:
    """Three independent statements of the worker bytes must agree.

    The binding must hash to the digest the capability carries, that digest must be
    the one this module pins, and, when a frozen source map is supplied, it must
    equal the digest the O7 inputs froze for the worker file.
    """
    if not isinstance(binding, bytes) or not binding:
        raise ValueError("reviewed worker source required")
    observed = hashlib.sha256(binding).hexdigest()
    if observed != binding_digest or observed != WORKER_SHA256:
        raise ValueError("worker source digest differs from the reviewed transport")
    if frozen is not None and frozen.get(f"tools/compat-broad/auth-credential-tokens/{WORKER_ENTRY}") != observed:
        raise ValueError("worker source digest differs from the frozen inputs")


def _private_string(value: Any, maximum: int) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= maximum
        and value.isascii()
        and not any(char.isspace() or ord(char) < 33 or ord(char) == 127 for char in value)
    )


def _seconds(deadline: float) -> float:
    if type(deadline) not in (int, float) or not math.isfinite(deadline):
        raise ValueError("finite absolute deadline required")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError("request deadline already passed")
    return min(MAX_SECONDS, remaining)


def request_with_lifecycle(
    url: str,
    body: dict[str, Any] | None,
    *,
    headers: dict[str, str],
    seconds: float,
    form: bool = False,
    fixture_origin: str | None = None,
) -> WorkerExchange:
    """Exactly one isolated worker for one request; the deadline kills and reaps it."""
    _source, observed = worker_binding()
    if observed != WORKER_SHA256:
        raise ValueError("worker source digest differs from the reviewed transport")
    if type(seconds) not in (int, float) or not 0 < seconds <= MAX_SECONDS:
        raise ValueError("bounded request duration required")
    encoded = None
    if body is not None:
        encoded = urllib.parse.urlencode(body) if form else json.dumps(body, allow_nan=False)
        headers = {
            **headers,
            "Content-Type": "application/x-www-form-urlencoded" if form else "application/json",
        }
    envelope = json.dumps(
        {"url": url, "body": encoded, "headers": headers, "seconds": float(seconds)},
        allow_nan=False,
    ).encode("utf-8")
    if len(envelope) > MAX_ENVELOPE_BYTES:
        raise ValueError("request envelope exceeds bound")
    argv = [sys.executable, "-I", "-S", "-B", str(HERE / WORKER_ENTRY)]
    if fixture_origin is not None:
        argv.append("--fixture-worker")
    env = {key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "LANG") if key in os.environ}
    process = None
    try:
        process = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env
        )
        stdout, _stderr = process.communicate(input=envelope, timeout=seconds)
    except subprocess.TimeoutExpired:
        if process is not None:
            try:
                process.kill()
                process.communicate(timeout=1)
            except (OSError, subprocess.TimeoutExpired):
                raise WorkerFailure("credential worker was not reaped", worker_reaped=False) from None
            if process.poll() is None:
                raise WorkerFailure("credential worker was not reaped", worker_reaped=False) from None
        raise WorkerFailure("credential request deadline exceeded", worker_reaped=True) from None
    except OSError:
        raise WorkerFailure("credential worker could not start", worker_reaped=process is None) from None
    if process is None or process.poll() is None:
        raise WorkerFailure("credential worker was not reaped", worker_reaped=False) from None
    try:
        if process.returncode != 0 or not 0 < len(stdout) <= MAX_OUTPUT_BYTES:
            raise WorkerFailure("invalid worker result", worker_reaped=True)
        value = json.loads(stdout)
        if (
            not isinstance(value, list)
            or len(value) != 3
            or type(value[0]) is not int
            or not 200 <= value[0] <= 599
            or not isinstance(value[1], str)
        ):
            raise WorkerFailure("invalid worker result", worker_reaped=True)
        body_value = response_body(base64.b64decode(value[1], validate=True))
        if not isinstance(body_value, dict):
            raise WorkerFailure("credential HTTP response was not usable", worker_reaped=True)
        return WorkerExchange(status=value[0], body=body_value, worker_reaped=True)
    except WorkerFailure:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError, binascii.Error):
        raise WorkerFailure("credential HTTP response was not usable", worker_reaped=True) from None


def request(
    url: str,
    body: dict[str, Any] | None,
    *,
    headers: dict[str, str],
    seconds: float,
    form: bool = False,
    fixture_origin: str | None = None,
) -> tuple[int, dict[str, Any]]:
    result = request_with_lifecycle(
        url, body, headers=headers, seconds=seconds, form=form, fixture_origin=fixture_origin
    )
    return result.status, result.body


def _origin(fixture_origin: str | None) -> str:
    if fixture_origin is None:
        return "https://"
    parsed = urllib.parse.urlsplit(fixture_origin)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in ("127.0.0.1", "::1")
        or not parsed.port
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("loopback fixture origin required")
    return fixture_origin + "/"


def _headers(*, owner: bool, token: str) -> dict[str, str]:
    if not owner:
        return {}
    return {"Authorization": "Bearer " + token, "x-goog-user-project": PROJECT}


def transmit(
    declared: dict[str, Any],
    body: dict[str, Any],
    *,
    token: str,
    api_key: str,
    deadline: float,
    capability: Any,
    binding: Any,
    binding_digest: Any,
    fixture_origin: str | None = None,
) -> tuple[int, dict[str, Any]]:
    """Send one frozen Gate slot with its run-time body over the bound wire."""
    authorize_transport(capability, binding=binding, binding_digest=binding_digest)
    verify_worker_binding(binding, binding_digest, None)
    if not isinstance(declared, dict) or not isinstance(body, dict):
        raise ValueError("closed credential slot required")  # noqa: TRY004 -- refusal class, not a type report
    path = declared.get("path")
    if not isinstance(path, str) or not path.startswith((IDENTITY + "/", SECURE)):
        raise ValueError("closed credential route required")
    if not _private_string(token, 8192) or not _private_string(api_key, 256):
        raise ValueError("bounded credential required")
    owner = declared.get("owner") is True
    url = _origin(fixture_origin) + path
    if not owner:
        url += "?key=" + urllib.parse.quote(api_key, safe="")
    return request(
        url,
        body,
        headers=_headers(owner=owner, token=token),
        seconds=_seconds(deadline),
        form=declared.get("form") is True,
        fixture_origin=fixture_origin,
    )


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def sign_custom_token(
    payload: dict[str, Any],
    *,
    service_account: str,
    token: str,
    deadline: float,
    capability: Any,
    binding: Any,
    binding_digest: Any,
    fixture_origin: str | None = None,
) -> tuple[str, dict[str, Any]]:
    """Mint one RS256 custom token through the IAM Credentials signBlob call.

    The bearer needs `iam.serviceAccounts.signBlob` on the service account
    (`roles/iam.serviceAccountTokenCreator`). No key is fetched or stored; the
    signature comes back from the API and only its public projection is returned
    beside the token.
    """
    authorize_transport(capability, binding=binding, binding_digest=binding_digest)
    verify_worker_binding(binding, binding_digest, None)
    if not _private_string(token, 8192) or not _private_string(service_account, 256) or "@" not in service_account:
        raise ValueError("bounded signing credential required")
    if not isinstance(payload, dict) or payload.get("iss") != service_account or payload.get("sub") != service_account:
        raise ValueError("custom token payload must name the signing account")
    signing_input = (
        _b64url(json.dumps(CUSTOM_TOKEN_HEADER, separators=(",", ":")).encode())
        + "."
        + _b64url(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    )
    url = (
        _origin(fixture_origin)
        + f"{SIGN_BLOB_HOST}/v1/projects/-/serviceAccounts/{service_account}:signBlob"
    )
    status, response = request(
        url,
        {"payload": base64.b64encode(signing_input.encode()).decode("ascii")},
        headers={"Authorization": "Bearer " + token, "x-goog-user-project": PROJECT},
        seconds=_seconds(deadline),
        fixture_origin=fixture_origin,
    )
    signed = response.get("signedBlob")
    key_id = response.get("keyId")
    if status != 200 or not isinstance(signed, str) or not signed:
        raise ValueError(f"signBlob refused: {status}")
    try:
        signature = base64.b64decode(signed, validate=True)
    except ValueError:
        raise ValueError("signBlob answered with an invalid signature encoding") from None
    public = {
        "kind": "custom-token-signature-v1",
        "status": status,
        "keyIdPresent": isinstance(key_id, str) and bool(key_id),
        "algorithm": CUSTOM_TOKEN_HEADER["alg"],
        "signatureBytes": len(signature),
        "payloadDigest": hashlib.sha256(signing_input.encode()).hexdigest(),
    }
    return signing_input + "." + _b64url(signature), public


__all__ = [
    "WORKER_ENTRY",
    "WORKER_SHA256",
    "request",
    "sign_custom_token",
    "transmit",
    "verify_worker_binding",
    "worker_binding",
]
