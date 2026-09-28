"""Closed Firebase Auth issuance exchange for private O5 identity proofs.

This module does not verify JWT signatures. Its trust boundary is the bounded
HTTPS Auth issuance response from the allowlisted endpoint; JWT decoding is
only a consistency check on that response. Proofs cannot be constructed from
JSON by callers.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from broad_contract import digest

PROJECT = "fireemu-35fe6"
SERVICE = "identitytoolkit.googleapis.com"
ORIGIN = "https://" + SERVICE
MAX_BYTES = 64 * 1024
MAX_SECONDS = 12.0
_SEAL = object()
_STANDARD_TOKEN_CLAIMS = frozenset(
    {
        "iss",
        "aud",
        "sub",
        "user_id",
        "iat",
        "auth_time",
        "exp",
        "firebase",
        "email",
        "email_verified",
    }
)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any):
        raise ValueError("redirect refused")


@dataclass(frozen=True, slots=True, init=False)
class IdentityProof:
    principal_ref: str
    token: str
    token_hash: str
    uid: str
    provider: str
    tenant: str | None
    claims_digest: str
    issuer: str
    audience: str
    issued_at: int
    auth_time: int
    expires_at: int
    request_digest: str
    issuance_origin: str
    issuance_mode: str
    _seal: object

    def __init__(self, *_args: Any, **_kwargs: Any):
        raise TypeError("identity proofs are issued only by the Auth exchange")

    def trusted(self, now: float | None = None) -> bool:
        capture = time.time() if now is None else now
        return (
            self._seal is _SEAL
            and hashlib.sha256(self.token.encode()).hexdigest() == self.token_hash
            and type(capture) in (int, float)
            and self.issued_at <= capture < self.expires_at
        )


def _proof(values: tuple[Any, ...]) -> IdentityProof:
    result = object.__new__(IdentityProof)
    for field, value in zip(IdentityProof.__dataclass_fields__, values):
        object.__setattr__(result, field, value)
    return result


def _compact(value: Any) -> bytes:
    return json.dumps(
        value, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()


def _b64json(segment: str) -> dict[str, Any]:
    if not isinstance(segment, str) or len(segment) > MAX_BYTES or not segment:
        raise ValueError("bounded token payload required")
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        value = json.loads(raw)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("token payload malformed") from None
    if not isinstance(value, dict):
        raise ValueError("token payload object required")  # noqa: TRY004
    return value


def _payload(token: Any) -> dict[str, Any]:
    if not isinstance(token, str) or len(token) > MAX_BYTES or token.count(".") != 2:
        raise ValueError("issued ID token shape refused")
    return _b64json(token.split(".")[1])


def build_request(
    kind: str,
    *,
    api_key: str,
    email: str | None,
    password: str | None,
    tenant: str | None,
) -> dict[str, Any]:
    if (
        kind not in {"signup", "signin"}
        or not isinstance(api_key, str)
        or not api_key
        or len(api_key) > 256
    ):
        raise ValueError("closed Auth issuance kind required")
    body: dict[str, Any] = {"returnSecureToken": True}
    if kind == "signup":
        if email is None:
            pass
        else:
            body.update(email=email, password=password)
    else:
        if not isinstance(email, str) or not isinstance(password, str):
            raise ValueError("password sign-in fields required")
        body.update(email=email, password=password)
    if tenant is not None:
        body["tenantId"] = tenant
    path = (
        "/v1/accounts:"
        + ("signUp" if kind == "signup" else "signInWithPassword")
        + "?"
        + urllib.parse.urlencode({"key": api_key})
    )
    if len(_compact(body)) > MAX_BYTES:
        raise ValueError("Auth issuance body exceeds bound")
    return {
        "method": "POST",
        "path": path,
        "body": body,
        "requestDigest": digest({"method": "POST", "path": path, "body": body}),
    }


def _origin(fixture_origin: str | None) -> str:
    if fixture_origin is None:
        return ORIGIN
    parsed = urllib.parse.urlsplit(fixture_origin)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "::1"}
        or not parsed.port
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("fixture origin refused")
    return fixture_origin.rstrip("/")


def _exchange(
    request: dict[str, Any], *, fixture_origin: str | None = None
) -> dict[str, Any]:
    if (
        set(request) != {"method", "path", "body", "requestDigest"}
        or request.get("method") != "POST"
        or not isinstance(request.get("path"), str)
        or not request["path"].startswith("/v1/accounts:")
        or not isinstance(request.get("body"), dict)
        or request["requestDigest"]
        != digest({"method": "POST", "path": request["path"], "body": request["body"]})
    ):
        raise ValueError("closed Auth issuance request required")
    request_path = urllib.parse.urlsplit(request["path"])
    query = urllib.parse.parse_qs(request_path.query, keep_blank_values=True)
    if (
        request_path.path
        not in {"/v1/accounts:signUp", "/v1/accounts:signInWithPassword"}
        or set(query) != {"key"}
        or len(query["key"]) != 1
        or not query["key"][0]
    ):
        raise ValueError("closed Auth issuance route required")
    body_keys = set(request["body"])
    if (
        body_keys - {"returnSecureToken", "email", "password", "tenantId"}
        or request["body"].get("returnSecureToken") is not True
    ):
        raise ValueError("closed Auth issuance body required")
    if request_path.path.endswith("signInWithPassword") and body_keys - {
        "returnSecureToken",
        "email",
        "password",
        "tenantId",
    }:
        raise ValueError("closed password issuance body required")
    if request_path.path.endswith("signInWithPassword") and not all(
        isinstance(request["body"].get(key), str) and request["body"].get(key)
        for key in ("email", "password")
    ):
        raise ValueError("closed password issuance fields required")
    if (
        request_path.path.endswith("accounts:signUp")
        and ("email" in body_keys or "password" in body_keys)
        and not all(
            isinstance(request["body"].get(key), str) and request["body"].get(key)
            for key in ("email", "password")
        )
    ):
        raise ValueError("closed signup fields required")
    payload = _compact(request["body"])
    if len(payload) > MAX_BYTES:
        raise ValueError("Auth issuance body exceeds bound")
    target = _origin(fixture_origin)
    parsed = urllib.parse.urlsplit(target)
    connection = (
        http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=MAX_SECONDS)
        if fixture_origin
        else http.client.HTTPSConnection(SERVICE, timeout=MAX_SECONDS)
    )
    try:
        connection.request(
            "POST",
            request["path"],
            body=payload,
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        raw = response.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("Auth issuance response exceeds bound")
        body = json.loads(raw) if raw else {}
        if not isinstance(body, dict):
            raise ValueError("Auth issuance response object required")  # noqa: TRY004
        return {"status": response.status, "body": body}
    except (
        OSError,
        TimeoutError,
        http.client.HTTPException,
        json.JSONDecodeError,
    ) as error:
        raise ValueError("Auth issuance exchange failed") from error
    finally:
        connection.close()


def issue_proof(
    principal_ref: str,
    request: dict[str, Any],
    *,
    expected_provider: str,
    expected_tenant: str | None,
    expected_claims: dict[str, Any],
    fixture_origin: str | None = None,
    now: int | None = None,
) -> IdentityProof:
    if (
        not isinstance(principal_ref, str)
        or not principal_ref
        or expected_provider not in {"password", "anonymous"}
    ):
        raise ValueError("closed principal proof binding required")
    response = _exchange(request, fixture_origin=fixture_origin)
    if response["status"] != 200:
        raise ValueError("Auth issuance refused")
    body = response["body"]
    if (
        set(body)
        - {"localId", "idToken", "refreshToken", "expiresIn", "email", "registered"}
        or not isinstance(body.get("localId"), str)
        or not isinstance(body.get("idToken"), str)
        or not body["idToken"]
    ):
        raise ValueError("typed Auth issuance response required")
    token = body["idToken"]
    claims = _payload(token)
    firebase = claims.get("firebase")
    if not isinstance(firebase, dict):
        raise ValueError("Firebase token claims required")  # noqa: TRY004
    issuer = f"https://securetoken.google.com/{PROJECT}"
    capture = int(time.time()) if now is None else now
    if (
        claims.get("iss") != issuer
        or claims.get("aud") != PROJECT
        or claims.get("sub") != body["localId"]
        or claims.get("user_id") != body["localId"]
    ):
        raise ValueError("issued token identity differs")
    if (
        firebase.get("sign_in_provider") != expected_provider
        or firebase.get("tenant") != expected_tenant
    ):
        raise ValueError("issued token provider or tenant differs")
    if (
        any(type(claims.get(key)) is not int for key in ("iat", "auth_time", "exp"))
        or claims["exp"] <= capture
        or claims["iat"] > capture
        or claims["auth_time"] > capture
    ):
        raise ValueError("issued token time claims differ")
    custom = {
        key: value
        for key, value in claims.items()
        if key not in _STANDARD_TOKEN_CLAIMS
    }
    if custom != expected_claims:
        raise ValueError("issued token claims differ")
    return _proof(
        (
            principal_ref,
            token,
            hashlib.sha256(token.encode()).hexdigest(),
            body["localId"],
            expected_provider,
            expected_tenant,
            digest(custom),
            issuer,
            PROJECT,
            claims["iat"],
            claims["auth_time"],
            claims["exp"],
            request["requestDigest"],
            _origin(fixture_origin),
            "fixture" if fixture_origin is not None else "production",
            _SEAL,
        )
    )


def mint_acknowledged_setup_proof(
    principal_ref: str,
    *,
    private_handoff: Any,
    setup_receipt: Any,
    gate_authority: Any,
    gate_acknowledgment: dict[str, Any],
    expected_provider: str,
    expected_tenant: str | None,
    expected_claims: dict[str, Any],
    request_digest: str,
    fixture_origin: str | None = None,
    now: int | None = None,
) -> IdentityProof:
    """Mint a proof from a durably acknowledged setup exchange without network I/O."""
    from o5_user_token_campaign import setup_plan
    from o5_user_token_remote_transport import SetupPrivateHandoff, SetupPublicReceipt
    from shared_gate import Gate, _validate_rules_management_plan

    if not isinstance(gate_authority, Gate):
        raise ValueError("durable Gate authority required")  # noqa: TRY004 -- Admission refuses invalid authority uniformly.
    if (
        not isinstance(principal_ref, str)
        or not principal_ref
        or expected_provider not in {"password", "anonymous"}
    ):
        raise ValueError("closed principal proof binding required")
    if not isinstance(request_digest, str) or not re.fullmatch(
        r"[0-9a-f]{64}", request_digest
    ):
        raise ValueError("setup request digest required")
    required = {
        "kind",
        "principalRef",
        "uid",
        "tenant",
        "tokenHash",
        "requestDigest",
        "responseDigest",
        "eventDigest",
        "planDigest",
        "nonce",
        "slotId",
    }
    if (
        not isinstance(gate_acknowledgment, dict)
        or set(gate_acknowledgment) != required
        or gate_acknowledgment.get("kind") != "setup-ack"
    ):
        raise ValueError("typed setup Gate acknowledgment required")
    if (
        gate_acknowledgment["principalRef"] != principal_ref
        or gate_acknowledgment["requestDigest"] != request_digest
    ):
        raise ValueError("setup acknowledgment binding differs")
    if gate_acknowledgment["tenant"] != expected_tenant:
        raise ValueError("setup acknowledgment tenant differs")
    for key in ("responseDigest", "eventDigest", "planDigest", "tokenHash"):
        if not isinstance(gate_acknowledgment[key], str) or not re.fullmatch(
            r"[0-9a-f]{64}", gate_acknowledgment[key]
        ):
            raise ValueError("setup acknowledgment digest required")
    if not isinstance(gate_acknowledgment["nonce"], str) or not re.fullmatch(
        r"[0-9a-f]{32}", gate_acknowledgment["nonce"]
    ):
        raise ValueError("setup acknowledgment nonce required")
    if (
        not isinstance(gate_acknowledgment["slotId"], str)
        or not gate_acknowledgment["slotId"]
    ):
        raise ValueError("setup acknowledgment slot required")
    state = gate_authority.snapshot()
    if state.get("planDigest") != gate_acknowledgment["planDigest"]:
        raise ValueError("setup Gate plan binding differs")
    canonical = _validate_rules_management_plan(state["plan"])
    item = next(
        (
            candidate
            for candidate in setup_plan(canonical)["operations"]
            if "observation:setup/" + candidate["id"] == gate_acknowledgment["slotId"]
            and candidate["route"] in {"accounts:signUp", "accounts:signInWithPassword"}
        ),
        None,
    )
    if item is None:
        raise ValueError("canonical setup issuance slot required")
    account = next(
        account
        for account in canonical["ownedAccounts"]
        if account["ref"] == item["accountRef"]
    )
    provider = "anonymous" if account["kind"] == "anonymous" else "password"
    issued_claims = (
        account["claims"] if item["route"] == "accounts:signInWithPassword" else {}
    )
    if (
        principal_ref != account["ref"]
        or gate_acknowledgment["nonce"] != canonical["nonce"]
        or expected_tenant != account["tenant"]
        or expected_provider != provider
        or expected_claims != issued_claims
    ):
        raise ValueError("canonical setup subject binding differs")
    event = next(
        (
            candidate
            for candidate in state.get("managementEvents", [])
            if isinstance(candidate, dict)
            and candidate.get("id") == gate_acknowledgment["slotId"]
        ),
        None,
    )
    if (
        not isinstance(event, dict)
        or event.get("completed") is not True
        or event.get("workerReaped") is not True
    ):
        raise ValueError("setup Gate event is not durably completed")
    receipt = event.get("rulesReceipt")
    if (
        not isinstance(receipt, dict)
        or not isinstance(receipt.get("body"), dict)
        or event.get("status") != 200
        or receipt.get("status") != 200
        or receipt.get("complete") is not True
        or receipt.get("workerReaped") is not True
        or event.get("responseDigest") != digest(receipt)
        or event.get("bodyDigest") != digest(receipt["body"])
        or event.get("responseDigest") != gate_acknowledgment["responseDigest"]
        or digest(event) != gate_acknowledgment["eventDigest"]
    ):
        raise ValueError("setup Gate event binding differs")
    if not isinstance(private_handoff, SetupPrivateHandoff) or not isinstance(
        setup_receipt, SetupPublicReceipt
    ):
        raise ValueError("typed setup handoff and receipt required")  # noqa: TRY004 -- Preserve the admission refusal contract.
    token, response_digest, handoff_request_digest = private_handoff.proof_material()
    uid = setup_receipt.local_id
    if (
        not isinstance(token, str)
        or not token
        or not isinstance(uid, str)
        or uid != gate_acknowledgment["uid"]
    ):
        raise ValueError("acknowledged setup handoff required")
    if (
        setup_receipt.item_id != item["id"]
        or setup_receipt.http_status != 200
        or receipt["body"].get("effects")
        != [
            {
                "subject": "account/" + account["ref"],
                "proof": {
                    "kind": "account",
                    "accountRef": account["ref"],
                    "tenantId": account["tenant"],
                    "uid": uid,
                },
            }
        ]
    ):
        raise ValueError("setup Gate subject binding differs")
    # The event digests the sanitized wrapper; only its nested digest binds
    # the actual REST body retained by the transport-issued private handoff.
    if (
        response_digest != receipt["body"].get("responseDigest")
        or handoff_request_digest != request_digest
    ):
        raise ValueError("setup handoff provenance differs")
    if hashlib.sha256(token.encode()).hexdigest() != gate_acknowledgment["tokenHash"]:
        raise ValueError("setup token acknowledgment differs")
    claims = _payload(token)
    firebase = claims.get("firebase")
    capture = int(time.time()) if now is None else now
    issuer = f"https://securetoken.google.com/{PROJECT}"
    if (
        not isinstance(firebase, dict)
        or claims.get("iss") != issuer
        or claims.get("aud") != PROJECT
        or claims.get("sub") != uid
        or claims.get("user_id") != uid
    ):
        raise ValueError("setup token identity differs")
    if (
        firebase.get("sign_in_provider") != expected_provider
        or firebase.get("tenant") != expected_tenant
    ):
        raise ValueError("setup token provider or tenant differs")
    if (
        any(type(claims.get(key)) is not int for key in ("iat", "auth_time", "exp"))
        or claims["exp"] <= capture
        or claims["iat"] > capture
        or claims["auth_time"] > capture
    ):
        raise ValueError("setup token time claims differ")
    custom = {
        key: value
        for key, value in claims.items()
        if key not in _STANDARD_TOKEN_CLAIMS
    }
    if custom != expected_claims:
        raise ValueError("setup token claims differ")
    return _proof(
        (
            principal_ref,
            token,
            gate_acknowledgment["tokenHash"],
            uid,
            expected_provider,
            expected_tenant,
            digest(custom),
            issuer,
            PROJECT,
            claims["iat"],
            claims["auth_time"],
            claims["exp"],
            request_digest,
            _origin(fixture_origin),
            "fixture" if fixture_origin is not None else "production",
            _SEAL,
        )
    )


__all__ = [
    "IdentityProof",
    "build_request",
    "issue_proof",
    "mint_acknowledged_setup_proof",
]
