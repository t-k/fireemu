"""Bounded HTTPS worker with a closed service/route allowlist."""

from __future__ import annotations

import argparse
import http.client
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

MAX_REQUEST_BYTES = 1_048_576
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_SECONDS = 12.0
DEFAULT_SECONDS = 8.0
FIXED_ORIGINS = {
    "firestore": "https://firestore.googleapis.com",
    "identity": "https://identitytoolkit.googleapis.com",
    "rules": "https://firebaserules.googleapis.com",
}
ALLOWED_HEADERS = {"authorization", "content-type", "x-goog-user-project"}
PROJECT = "fireemu-35fe6"
_DOCUMENT = re.compile(
    r"^/v1/projects/fireemu-35fe6/databases/\(default\)/documents/o5-user-token/n[0-9a-f]{32}/cases/[A-Za-z0-9_-]{1,128}$"
)
_COMMIT = "/v1/projects/fireemu-35fe6/databases/(default)/documents:commit"
_RULESET = "/v1/projects/fireemu-35fe6/rulesets"
_RULESET_ITEM = re.compile(r"^/v1/projects/fireemu-35fe6/rulesets/[A-Za-z0-9_-]{1,128}$")
_RELEASE = re.compile(r"^/v1/projects/fireemu-35fe6/releases/[A-Za-z0-9_.-]{1,128}$")
_EXECUTABLE = re.compile(r"^/v1/projects/fireemu-35fe6/releases/[A-Za-z0-9_.-]{1,128}:getExecutable$")
_ACCOUNT = re.compile(
    r"^/v1/projects/fireemu-35fe6(?:/tenants/[A-Za-z0-9][A-Za-z0-9_-]{3,35})?/accounts:(lookup|update|delete)$"
)
_SETUP_DOCUMENT = re.compile(
    r"^/v1/projects/fireemu-35fe6/databases/\(default\)/documents/o5-user-token/n[0-9a-f]{32}/cases/[A-Za-z0-9_-]{1,128}\?currentDocument\.exists=false$"
)
_SETUP_ACCOUNT = re.compile(
    r"^/v1/accounts:(signUp|signInWithPassword)\?key=[A-Za-z0-9._~-]{1,256}$"
)
_SETUP_ADMIN_ACCOUNT = re.compile(
    r"^/v1/projects/fireemu-35fe6(?:/tenants/[A-Za-z0-9][A-Za-z0-9_-]{3,35})?/accounts:update$"
)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any):
        raise ValueError("redirect refused")


def _json(value: Any, *, error: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(error)  # noqa: TRY004
    return value


def _fixture(fixture_origin: str | None) -> str | None:
    if fixture_origin is None:
        return None
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


def _route(service: Any, route: Any, method: Any, path: Any) -> None:
    if not all(isinstance(value, str) for value in (service, route, method, path)):
        raise ValueError("closed worker request required")
    if (
        service == "firestore"
        and route == "observation-get"
        and method == "GET"
        and _DOCUMENT.fullmatch(path)
    ):
        return
    if (
        service == "firestore"
        and route == "observation-commit"
        and method == "POST"
        and path == _COMMIT
    ):
        return
    if (
        service == "firestore"
        and route == "document-recovery-get"
        and method == "GET"
        and _DOCUMENT.fullmatch(path)
    ):
        return
    if (
        service == "firestore"
        and route == "document-recovery-delete"
        and method == "DELETE"
        and _DOCUMENT.fullmatch(path.split("?", 1)[0])
        and path.count("?") == 1
        and "currentDocument.updateTime=" in path
    ):
        return
    if (
        service == "firestore"
        and route == "document-create"
        and method == "PATCH"
        and _SETUP_DOCUMENT.fullmatch(path)
    ):
        return
    if (
        service == "identity"
        and route in {"account-recovery", "principal-action", "principal-action-readback"}
        and method == "POST"
        and _ACCOUNT.fullmatch(path)
    ):
        return
    if (
        service == "identity"
        and route in {"accounts:signUp", "accounts:update", "accounts:signInWithPassword"}
        and method == "POST"
        and ((route == "accounts:update" and _SETUP_ADMIN_ACCOUNT.fullmatch(path)) or (route != "accounts:update" and _SETUP_ACCOUNT.fullmatch(path)))
    ):
        return
    if (
        service == "rules"
        and route == "ruleset-create"
        and method == "POST"
        and path == _RULESET
    ):
        return
    if (
        service == "rules"
        and route in {"ruleset-get", "ruleset-delete"}
        and method in {"GET", "DELETE"}
        and _RULESET_ITEM.fullmatch(path)
    ):
        return
    if (
        service == "rules"
        and route in {"release-get", "release-patch"}
        and method in {"GET", "PATCH"}
        and _RELEASE.fullmatch(path)
    ):
        return
    if (
        service == "rules"
        and route == "release-get-executable"
        and method == "GET"
        and _EXECUTABLE.fullmatch(path)
    ):
        return
    raise ValueError("closed service route required")


def _bounded_body(value: Any) -> bytes | None:
    if value is None:
        return None
    encoded = json.dumps(
        value, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()
    if len(encoded) > MAX_REQUEST_BYTES:
        raise ValueError("request body exceeds bound")
    return encoded


def _rules_body(route: str, body: Any) -> None:
    """Validate the exact JSON shapes used by the Rules REST methods."""
    if route == "ruleset-create":
        if not isinstance(body, dict) or set(body) not in ({"source"}, {"source", "attachmentPoint"}):
            raise ValueError("ruleset create body shape refused")
        source = body.get("source")
        files = source.get("files") if isinstance(source, dict) else None
        if not isinstance(files, list) or len(files) != 1 or not isinstance(files[0], dict) or set(files[0]) != {"name", "content"} or files[0]["name"] != "firestore.rules" or not isinstance(files[0]["content"], str):
            raise ValueError("ruleset source body shape refused")
        if "attachmentPoint" in body and body["attachmentPoint"] != "projects/fireemu-35fe6/databases/(default)":
            raise ValueError("ruleset attachment body shape refused")
    elif route == "release-patch":
        if not isinstance(body, dict) or set(body) != {"release", "updateMask"} or body["updateMask"] != "rulesetName":
            raise ValueError("release patch body shape refused")
        release = body["release"]
        if not isinstance(release, dict) or set(release) != {"name", "rulesetName"} or not _RELEASE.fullmatch("/v1/" + str(release.get("name", ""))) or not _RULESET_ITEM.fullmatch("/v1/" + str(release.get("rulesetName", ""))):
            raise ValueError("release patch resource shape refused")


def _setup_body(route: str, body: Any) -> None:
    if route == "document-create":
        if not isinstance(body, dict) or set(body) != {"name", "fields"}:
            raise ValueError("setup document body shape refused")
        if not isinstance(body["name"], str) or not body["name"].startswith("projects/fireemu-35fe6/databases/(default)/documents/o5-user-token/") or not isinstance(body["fields"], dict):
            raise ValueError("setup document body binding refused")
    elif route == "accounts:signUp":
        if not isinstance(body, dict) or set(body) not in ({"returnSecureToken"}, {"email", "password", "returnSecureToken"}, {"returnSecureToken", "tenantId"}, {"email", "password", "returnSecureToken", "tenantId"}) or body.get("returnSecureToken") is not True:
            raise ValueError("setup signup body shape refused")
        if "tenantId" in body and (not isinstance(body["tenantId"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{3,35}", body["tenantId"])):
            raise ValueError("setup signup tenant binding refused")
    elif route == "accounts:update":
        if not isinstance(body, dict) or set(body) != {"localId", "customAttributes"} or not isinstance(body["localId"], str) or not isinstance(body["customAttributes"], str):
            raise ValueError("setup claims body shape refused")
    elif route == "accounts:signInWithPassword":
        if not isinstance(body, dict) or set(body) not in ({"email", "password", "returnSecureToken"}, {"email", "password", "returnSecureToken", "tenantId"}) or body.get("returnSecureToken") is not True:
            raise ValueError("setup signin body shape refused")
        if "tenantId" in body and (not isinstance(body["tenantId"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{3,35}", body["tenantId"])):
            raise ValueError("setup signin tenant binding refused")


def exchange(
    envelope: dict[str, Any], *, fixture_origin: str | None = None
) -> dict[str, Any]:
    if set(envelope) != {
        "service",
        "route",
        "method",
        "path",
        "headers",
        "body",
        "seconds",
    }:
        raise ValueError("closed worker envelope required")
    service, route, method, path = (
        envelope[key] for key in ("service", "route", "method", "path")
    )
    _route(service, route, method, path)
    headers = envelope["headers"]
    if (
        not isinstance(headers, dict)
        or not headers
        or {str(key).lower() for key in headers} - ALLOWED_HEADERS
        or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in headers.items()
        )
    ):
        raise ValueError("closed worker headers required")
    lowered = {key.lower() for key in headers}
    client_setup = service == "identity" and route in {"accounts:signUp", "accounts:signInWithPassword"}
    if service in {"identity", "rules"} and not client_setup and "authorization" not in lowered:
        raise ValueError("authorization header required")
    seconds = envelope["seconds"]
    maximum_seconds = MAX_SECONDS if service == "rules" else DEFAULT_SECONDS
    if type(seconds) not in (int, float) or not 0 < seconds <= maximum_seconds:
        raise ValueError("bounded worker deadline required")
    body = _bounded_body(envelope["body"])
    if route in {"ruleset-create", "release-patch"}:
        _rules_body(route, envelope["body"])
    if route in {"document-create", "accounts:signUp", "accounts:update", "accounts:signInWithPassword"}:
        _setup_body(route, envelope["body"])
    if client_setup and "authorization" in lowered:
        raise ValueError("client setup must not use authorization header")
    if route == "document-create" and envelope["body"]["name"] != path.split("?", 1)[0].removeprefix("/v1/"):
        raise ValueError("setup document name binding refused")
    if (
        method == "GET"
        and body is not None
        or method != "GET"
        and route in {"observation-commit", "ruleset-create", "release-patch", "document-create", "accounts:signUp", "accounts:update", "accounts:signInWithPassword"}
        and body is None
    ):
        raise ValueError("request body shape refused")
    fixture = _fixture(fixture_origin)
    origin = fixture or FIXED_ORIGINS[service]
    request_headers = dict(headers)
    if body is not None:
        request_headers.setdefault("Content-Type", "application/json")
    request = urllib.request.Request(
        origin + path, data=body, headers=request_headers, method=method
    )
    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.ProxyHandler({}))
    started = time.monotonic()
    deadline = started + float(seconds)
    try:
        with opener.open(request, timeout=float(seconds)) as response:
            if time.monotonic() > deadline:
                raise TimeoutError
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            if time.monotonic() > deadline:
                raise TimeoutError
            if len(raw) > MAX_RESPONSE_BYTES:
                raise ValueError("response body exceeds bound")
            return {
                "status": int(response.status),
                "body": _json(
                    json.loads(raw) if raw else {}, error="object response required"
                ),
            }
    except urllib.error.HTTPError as error:
        raw = error.read(MAX_RESPONSE_BYTES + 1)
        if time.monotonic() > deadline:
            raise TimeoutError
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ValueError("response body exceeds bound") from None
        return {
            "status": int(error.code),
            "body": _json(
                json.loads(raw) if raw else {}, error="object response required"
            ),
        }
    except TimeoutError:
        raise ValueError("worker deadline exceeded") from None
    except (
        OSError,
        http.client.HTTPException,
        json.JSONDecodeError,
    ) as error:
        raise ValueError("bounded worker exchange failed") from error
    finally:
        if time.monotonic() > deadline:
            raise ValueError("worker walltime exceeded")


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--fixture-origin")
    args = parser.parse_args()
    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if len(raw) > MAX_REQUEST_BYTES:
            raise ValueError("worker envelope exceeds bound")
        result = exchange(
            _json(json.loads(raw), error="worker envelope required"),
            fixture_origin=args.fixture_origin,
        )
        sys.stdout.write(json.dumps(result, separators=(",", ":"), allow_nan=False))
        return 0
    except Exception as error:  # noqa: BLE001 - only sanitized type crosses process boundary
        sys.stderr.write(type(error).__name__)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
