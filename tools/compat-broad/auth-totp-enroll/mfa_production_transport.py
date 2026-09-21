"""The production Identity Platform session for AUTH-MFA-AGE-TOTP-01.

Every request the campaign sends to the service goes through one closed value, one
allowlisted endpoint, one reviewed wire worker and one admitted capability. The
worker is the shared `batch_wire.py` spawned through `batch_adapter.wire`, which
refuses every host but the fixed Google API hosts, bounds the body and the response,
and reaps itself on the deadline. The bearer token and the Web API key live only in
this process and the worker's stdin; they are never written, never put in a row and
never returned in an error.

This module adapts what `tools/auth-session-v2/session_v2_recorder.py` and the
earlier pending-revocation recorder established for production: the admin routes
carry `X-Goog-User-Project`, the configuration is patched with an explicit update
mask, and the test phone number's code is a fixed value rather than an SMS.
"""

from __future__ import annotations

import hashlib
import importlib.util
import math
import re
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]

from mfa_config_lock import CONFIG_PATH, TEST_CODE
from mfa_walk import code_of


def _load(name: str, path: Path):
    """Load one reviewed shared module by exact path, without touching sys.path."""
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"reviewed module unavailable: {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, module)
    spec.loader.exec_module(module)
    return module


if str(ROOT / "tools/compat-broad") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools/compat-broad"))
batch_adapter = _load(
    "_mfa_batch_adapter", ROOT / "tools/compat-broad/batch_adapter.py"
)
credential_prep = _load(
    "_mfa_credential_prep", ROOT / "tools/compat-broad/fs-write-txn/credential_prep.py"
)

PROJECT = "fireemu-35fe6"
IDENTITY_HOST = "https://identitytoolkit.googleapis.com"
SCOPE = "https://www.googleapis.com/auth/cloud-platform"
# The wire worker's own ceiling; a slot reserves at most this much.
REQUEST_SECONDS = 12.0
# The only endpoints the permission envelope allows, keyed by the path the walk uses.
PUBLIC_PATHS = frozenset(
    {
        "/v1/accounts:signUp",
        "/v1/accounts:signInWithPassword",
        "/v1/accounts:lookup",
        "/v2/accounts/mfaEnrollment:start",
        "/v2/accounts/mfaEnrollment:finalize",
        "/v2/accounts/mfaEnrollment:withdraw",
        "/v2/accounts/mfaSignIn:start",
        "/v2/accounts/mfaSignIn:finalize",
    }
)
ADMIN_PATHS = frozenset(
    {
        f"/v1/projects/{PROJECT}/accounts:lookup",
        f"/v1/projects/{PROJECT}/accounts:update",
        f"/v1/projects/{PROJECT}/accounts:delete",
        CONFIG_PATH,
    }
)
# `GET /v1/projects?key=` is the same public, key-only endpoint the client SDKs call
# on startup; it answers with the project the key was minted for. Every other public
# path is selected by the key alone with no project binding at all (the admin paths
# above are pinned to PROJECT by their literal path instead), so this is the one
# read-only call that can prove the key belongs to the approved project before it is
# ever used for a signUp or handed to a configuration patch.
PROJECT_CONFIG_PATH = "/v1/projects"
CALL_KINDS = (
    "auth-public",
    "auth-admin",
    "auth-config-patch",
    "oauth-tokeninfo",
    "auth-key-project",
)
_MASK = re.compile(r"^[A-Za-z0-9_.,]{1,128}$")


def private_string(value: Any, maximum: int) -> bool:
    return credential_prep.private_string(value, maximum)


def closed_call(
    kind: str,
    *,
    path: str | None,
    body: Any,
    secret: str,
    deadline: float,
    key: str | None = None,
    mask: str | None = None,
) -> dict:
    """The closed value one wire call carries. Validated again by `send`."""
    value = {
        "kind": kind,
        "path": path,
        "body": body,
        "secret": secret,
        "key": key,
        "mask": mask,
        "deadline": deadline,
    }
    validate_call(value)
    return value


def validate_call(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != {
        "kind",
        "path",
        "body",
        "secret",
        "key",
        "mask",
        "deadline",
    }:
        raise ValueError("closed Auth wire call required")
    kind = value["kind"]
    if kind not in CALL_KINDS:
        raise ValueError("closed Auth wire call kind required")
    if not private_string(value["secret"], 8192):
        raise ValueError("bounded private secret required")
    deadline = value["deadline"]
    if (
        type(deadline) not in (int, float)
        or isinstance(deadline, bool)
        or not math.isfinite(deadline)
    ):
        raise ValueError("finite absolute deadline required")
    if kind == "oauth-tokeninfo":
        if (
            value["path"] is not None
            or value["body"] is not None
            or value["key"] is not None
        ):
            raise ValueError("tokeninfo call carries nothing but the token")
        return
    if kind == "auth-public":
        if value["path"] not in PUBLIC_PATHS or not private_string(value["key"], 512):
            raise ValueError("allowlisted public Auth endpoint and API key required")
        if not isinstance(value["body"], dict):
            raise ValueError("public Auth call carries a JSON object")
    elif kind == "auth-key-project":
        if value["path"] != PROJECT_CONFIG_PATH or not private_string(
            value["key"], 512
        ):
            raise ValueError("project-config endpoint and API key required")
        if value["body"] is not None:
            raise ValueError("project-config call carries no body")
    elif kind == "auth-admin":
        if value["path"] not in ADMIN_PATHS or value["key"] is not None:
            raise ValueError("allowlisted admin Auth endpoint required")
        if value["body"] is not None and not isinstance(value["body"], dict):
            raise ValueError("admin Auth call carries a JSON object or nothing")
    elif kind == "auth-config-patch":
        if value["path"] != CONFIG_PATH or value["key"] is not None:
            raise ValueError("configuration patch targets the project configuration")
        if not isinstance(value["body"], dict) or not isinstance(value["mask"], str):
            raise ValueError("configuration patch requires a body and an update mask")
        if _MASK.fullmatch(value["mask"]) is None:
            raise ValueError("bounded update mask required")
    if kind != "auth-config-patch" and value["mask"] is not None:
        raise ValueError("only a configuration patch carries an update mask")


def _remaining(deadline: float) -> float:
    duration = min(REQUEST_SECONDS, deadline - time.monotonic())
    if duration <= 0:
        raise ValueError("Auth request deadline already passed")
    return duration


def send(value: dict) -> tuple[int, dict]:
    """The fixed production wire. Reachable only through an admitted capability.

    Returns the HTTP status and the JSON object body. An incomplete or non-JSON
    response is a transport failure and raises; it is charged by the caller either
    way, because the request was sent.
    """
    validate_call(value)
    kind = value["kind"]
    duration = _remaining(value["deadline"])
    if kind == "oauth-tokeninfo":
        result = credential_prep._private_request(
            "tokeninfo",
            value["secret"],
            deadline=min(duration, credential_prep.REQUEST_SECONDS),
        )
        if result.get("complete") is not True or result.get("workerReaped") is not True:
            raise ValueError("tokeninfo exchange incomplete")
        status, body = result.get("status"), result.get("body")
        if type(status) is not int or not isinstance(body, dict):
            raise ValueError("tokeninfo response malformed")
        return status, body
    headers = {"Accept": "application/json"}
    if kind in ("auth-public", "auth-key-project"):
        url = (
            IDENTITY_HOST
            + value["path"]
            + "?key="
            + urllib.parse.quote(value["key"], safe="")
        )
        method = "POST" if kind == "auth-public" else "GET"
    else:
        headers["Authorization"] = "Bearer " + value["secret"]
        headers["X-Goog-User-Project"] = PROJECT
        url = IDENTITY_HOST + value["path"]
        if kind == "auth-config-patch":
            url += "?updateMask=" + urllib.parse.quote(value["mask"], safe=",")
            method = "PATCH"
        else:
            method = "GET" if value["body"] is None else "POST"
    if value["body"] is not None:
        headers["Content-Type"] = "application/json"
    response = batch_adapter.wire(
        url, method, value["body"], headers, timeout=duration, receipt=True
    )
    http = response.get("http", {}) if isinstance(response, dict) else {}
    body = response.get("body") if isinstance(response, dict) else None
    if (
        http.get("complete") is not True
        or http.get("bodyKind") != "json"
        or not isinstance(body, dict)
    ):
        raise ValueError("Auth response incomplete or not a JSON object")
    status = http.get("status")
    if type(status) is not int or not 100 <= status <= 599:
        raise ValueError("Auth response status malformed")
    return status, body


def verify_tokeninfo(body: Any, principal: dict, *, required_seconds: float) -> dict:
    """The bearer belongs to the frozen principal, carries the scope and outlives the run.

    Returns a secret-free attestation in the shape the shared Gate's management
    receipt validator accepts for the `oauth-tokeninfo` slot. The identity comes from
    the owner-frozen permission and is compared against tokeninfo; it is never read
    out of tokeninfo and written into the permission.
    """
    if not isinstance(body, dict):
        raise ValueError("tokeninfo body required")  # noqa: TRY004 -- refusal class
    clients = [body[key] for key in ("issued_to", "audience") if key in body]
    seconds = body.get("expires_in")
    if "subject" in principal:
        identity_ok = body.get("user_id") == principal["subject"]
        mode = "subject"
    else:
        identity_ok = (
            body.get("email") == principal["verifiedEmail"]
            and body.get("verified_email") is True
        )
        mode = "verified-email"
    if (
        not clients
        or any(value != principal["clientId"] for value in clients)
        or not identity_ok
        or not isinstance(body.get("scope"), str)
        or SCOPE not in body["scope"].split()
        or type(seconds) is not int
        or not 1 < seconds <= 3600
    ):
        raise ValueError(
            "credential identity or scope differs from the frozen principal"
        )
    if seconds < required_seconds:
        raise ValueError("credential lifetime cannot cover the campaign")
    identity = principal.get("subject", principal.get("verifiedEmail", ""))
    return {
        "kind": "request-byte-token-attestation-v1",
        "principalDigest": hashlib.sha256(
            (principal["clientId"] + "\n" + identity).encode()
        ).hexdigest(),
        "requiredScopeVerified": True,
        "identityMode": mode,
        "identityVerified": True,
        "oauthClientVerified": True,
        "expiresInSeconds": seconds,
        "remainingSecondsAtVerification": float(seconds),
        "requiredSeconds": float(required_seconds),
        "complete": True,
        "workerReaped": True,
    }


def verify_key_project(body: Any, expected_project: str) -> dict:
    """The Web API key belongs to the approved project, or the run refuses.

    The public routes (`signUp` first of all) select the project by the key
    alone; nothing else binds them to `expected_project` the way the admin
    routes are pinned by their literal `/v1/projects/{PROJECT}/...` path. This
    read-only, key-only call is the one place that binding is checked, and it
    must be checked before the key is ever used for a signUp or a configuration
    patch.
    """
    if not isinstance(body, dict):
        raise ValueError("project-config body required")  # noqa: TRY004 -- refusal class
    project_id = body.get("projectId")
    if (
        not isinstance(project_id, str)
        or not project_id
        or project_id != expected_project
    ):
        raise ValueError("Web API key does not belong to the approved project")
    return {
        "kind": "auth-key-project-attestation-v1",
        "projectId": project_id,
        "verified": True,
    }


class ProductionSession:
    """The walk's session over the admitted capability. Charges every attempt."""

    def __init__(self, *, capability, token: str, api_key: str, deadline_for) -> None:
        if not private_string(token, 8192) or not private_string(api_key, 512):
            raise ValueError("bounded bearer token and API key required")
        self._capability = capability
        self._token = token
        self._key = api_key
        self._deadline_for = deadline_for
        self._requests = 0
        self.last_status: int | None = None
        self.credential_rejected = False

    @property
    def requests(self) -> int:
        return self._requests

    def _transmit(self, value: dict) -> tuple[int, dict]:
        # Charged before the send, so a request that never answers is still counted.
        self._requests += 1
        status, body = self._capability._transmit(value)
        self.last_status = status
        if status in (401, 403) and value["kind"] not in (
            "auth-public",
            "auth-key-project",
        ):
            self.credential_rejected = True
        return status, body

    def _deadline(self, deadline: float | None) -> float:
        return self._deadline_for() if deadline is None else deadline

    def public(
        self, path: str, body: Any, *, deadline: float | None = None
    ) -> tuple[int, dict]:
        return self._transmit(
            closed_call(
                "auth-public",
                path=path,
                body=body,
                secret=self._token,
                key=self._key,
                deadline=self._deadline(deadline),
            )
        )

    def admin(
        self, path: str, body: Any, *, deadline: float | None = None
    ) -> tuple[int, dict]:
        return self._transmit(
            closed_call(
                "auth-admin",
                path=path,
                body=body,
                secret=self._token,
                deadline=self._deadline(deadline),
            )
        )

    def patch_config(
        self, body: dict, mask: str, *, deadline: float | None = None
    ) -> tuple[int, dict]:
        return self._transmit(
            closed_call(
                "auth-config-patch",
                path=CONFIG_PATH,
                body=body,
                secret=self._token,
                mask=mask,
                deadline=self._deadline(deadline),
            )
        )

    def read_config(self, *, deadline: float | None = None) -> tuple[int, dict]:
        return self.admin(CONFIG_PATH, None, deadline=deadline)

    def project_config(self, *, deadline: float | None = None) -> tuple[int, dict]:
        """The read-only `GET /v1/projects?key=` the key-project preflight sends."""
        return self._transmit(
            closed_call(
                "auth-key-project",
                path=PROJECT_CONFIG_PATH,
                body=None,
                secret=self._token,
                key=self._key,
                deadline=self._deadline(deadline),
            )
        )

    def tokeninfo(self, *, deadline: float | None = None) -> tuple[int, dict]:
        return self._transmit(
            closed_call(
                "oauth-tokeninfo",
                path=None,
                body=None,
                secret=self._token,
                deadline=self._deadline(deadline),
            )
        )

    def sms_code(self) -> str:
        return TEST_CODE


def transport_source() -> tuple[bytes, str]:
    """This module's own bytes and digest: the worker binding the capability pins."""
    source = Path(__file__).resolve().read_bytes()
    return source, hashlib.sha256(source).hexdigest()


__all__ = [
    "ADMIN_PATHS",
    "CALL_KINDS",
    "PROJECT_CONFIG_PATH",
    "PUBLIC_PATHS",
    "ProductionSession",
    "closed_call",
    "code_of",
    "send",
    "transport_source",
    "validate_call",
    "verify_key_project",
    "verify_tokeninfo",
]
