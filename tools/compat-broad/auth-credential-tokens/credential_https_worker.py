"""Isolated HTTPS worker for the AUTH-CREDENTIAL production transport.

One process, one request, stdlib only. The parent starts it with `-I -S -B`, hands it
a JSON envelope on stdin and kills it at the deadline. It answers on stdout with
`[status, base64(body), contentType]` and exits 2 on any failure without printing a
byte of the response, the request or an exception: those may carry credentials.

Only the three Google hosts this campaign talks to are reachable over HTTPS. A
loopback HTTP origin is reachable only when the parent starts the worker as a
fixture worker, which the production transport never does.
"""

from __future__ import annotations

import base64
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

HOSTS = frozenset(
    {
        "identitytoolkit.googleapis.com",
        "securetoken.googleapis.com",
        "iamcredentials.googleapis.com",
        "oauth2.googleapis.com",
        "cloudresourcemanager.googleapis.com",
    }
)
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1"})
MAX_INPUT_BYTES = 65536
MAX_BODY_BYTES = 65536
MAX_SECONDS = 12.0
ENVELOPE_FIELDS = frozenset({"url", "body", "headers", "seconds"})
PROJECT = "fireemu-35fe6"
AUTH_CONFIG_PATH = f"/admin/v2/projects/{PROJECT}/config"
CLIENT_AUTH_PATHS = frozenset(
    "/v1/accounts:" + rpc
    for rpc in (
        "signUp",
        "signInWithPassword",
        "signInWithCustomToken",
        "lookup",
        "resetPassword",
        "update",
        "delete",
        "signInWithEmailLink",
    )
)
OWNER_AUTH_PATHS = frozenset(
    f"/v1/projects/{PROJECT}/accounts:" + rpc
    for rpc in ("lookup", "update", "delete", "sendOobCode")
) | {f"/v1/projects/{PROJECT}:createSessionCookie"}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("redirect forbidden")


def validate_target(url, *, fixture):
    parsed = urllib.parse.urlsplit(url)
    if (
        not isinstance(url, str)
        or len(url) > 2048
        or any(ord(c) <= 32 or ord(c) == 127 for c in url)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or not parsed.path.startswith("/")
    ):
        raise ValueError("malformed target")
    if fixture:
        if (
            parsed.scheme != "http"
            or parsed.hostname not in LOOPBACK_HOSTS
            or not parsed.port
        ):
            raise ValueError("loopback fixture target required")
        return parsed
    if (
        parsed.scheme != "https"
        or parsed.hostname not in HOSTS
        or parsed.port is not None
    ):
        raise ValueError("production host outside the allowlist")
    if parsed.hostname == "oauth2.googleapis.com" and parsed.path == "/tokeninfo":
        query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if len(query) != 1 or query[0][0] != "access_token" or not query[0][1]:
            raise ValueError("token-info route must be exact")
    elif parsed.hostname == "oauth2.googleapis.com":
        if parsed.path != "/token" or parsed.query:
            raise ValueError("OAuth refresh route must be exact")
    elif parsed.hostname == "cloudresourcemanager.googleapis.com":
        if parsed.path != "/v1/projects/fireemu-35fe6" or parsed.query:
            raise ValueError("project route must be exact")
    elif parsed.hostname == "identitytoolkit.googleapis.com" and parsed.path.startswith(
        "/admin/v2/"
    ):
        if parsed.path != "/admin/v2/projects/fireemu-35fe6/config" or parsed.query:
            raise ValueError("Auth config route must be exact")
    return parsed


def _read_bounded(response):
    lengths = response.headers.get_all("Content-Length", [])
    if len(lengths) > 1:
        raise ValueError("ambiguous response length")
    raw = response.read(MAX_BODY_BYTES + 1)
    if len(raw) > MAX_BODY_BYTES:
        raise ValueError("oversized response")
    if lengths and (not lengths[0].strip().isdigit() or int(lengths[0]) != len(raw)):
        raise ValueError("incomplete response")
    return raw


def _owner_headers(headers, *, post):
    expected = {"Authorization", "x-goog-user-project"}
    if post:
        expected.add("Content-Type")
    bearer = headers.get("Authorization", "")
    return (
        set(headers) == expected
        and headers.get("x-goog-user-project") == PROJECT
        and bearer.startswith("Bearer ")
        and bool(bearer[7:])
        and not any(char.isspace() for char in bearer[7:])
        and (not post or headers.get("Content-Type") == "application/json")
    )


def _validate_auth_post(parsed, body, headers):
    if body is None or not isinstance(json.loads(body), dict):
        raise ValueError("Auth JSON POST required")
    if parsed.path in OWNER_AUTH_PATHS:
        if parsed.query or not _owner_headers(headers, post=True):
            raise ValueError("Auth owner POST authority required")
    elif parsed.path in CLIENT_AUTH_PATHS:
        query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if (
            len(query) != 1
            or query[0][0] != "key"
            or not query[0][1]
            or headers != {"Content-Type": "application/json"}
        ):
            raise ValueError("Auth client POST key required")
    else:
        raise ValueError("Auth POST route outside the finite allowlist")


def prepare_request(value, *, fixture):
    """Validate the complete envelope before constructing a request; no I/O."""
    if not isinstance(value, dict) or set(value) != ENVELOPE_FIELDS:
        raise ValueError("invalid worker input")
    seconds = value["seconds"]
    if type(seconds) not in (int, float) or not 0 < seconds <= MAX_SECONDS:
        raise ValueError("bounded request duration required")
    headers = value["headers"]
    if not isinstance(headers, dict) or any(
        not isinstance(k, str)
        or not isinstance(v, str)
        or any(ord(char) < 32 or ord(char) == 127 for char in k + v)
        for k, v in headers.items()
    ):
        raise ValueError("typed headers required")
    body = value["body"]
    if body is not None and (
        not isinstance(body, str) or len(body.encode()) > MAX_INPUT_BYTES
    ):
        raise ValueError("bounded body required")
    parsed = validate_target(value["url"], fixture=fixture)
    if not fixture:
        if parsed.hostname == "oauth2.googleapis.com" and parsed.path == "/tokeninfo":
            if value["body"] is not None:
                raise ValueError("token-info route must be GET")
        elif parsed.hostname == "oauth2.googleapis.com":
            fields = urllib.parse.parse_qsl(value["body"] or "", keep_blank_values=True)
            if (
                value["body"] is None
                or value["headers"].get("Content-Type")
                != "application/x-www-form-urlencoded"
            ):
                raise ValueError("OAuth refresh form required")
            if {key for key, _value in fields} != {
                "grant_type",
                "client_id",
                "client_secret",
                "refresh_token",
            }:
                raise ValueError("OAuth refresh fields required")
            values = dict(fields)
            if values.get("grant_type") != "refresh_token" or any(
                not values[key]
                for key in ("client_id", "client_secret", "refresh_token")
            ):
                raise ValueError("OAuth refresh fields required")
        elif parsed.hostname == "cloudresourcemanager.googleapis.com" or (
            parsed.hostname == "identitytoolkit.googleapis.com"
            and parsed.path == AUTH_CONFIG_PATH
        ):
            if body is not None or not _owner_headers(headers, post=False):
                raise ValueError("project authority headers required")
        elif parsed.hostname == "identitytoolkit.googleapis.com":
            _validate_auth_post(parsed, body, headers)
    return urllib.request.Request(
        value["url"],
        data=None if body is None else body.encode("utf-8"),
        headers={"Accept": "application/json", **headers},
        method="POST" if body is not None else "GET",
    )


def exchange(value, *, fixture):
    request = prepare_request(value, fixture=fixture)
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler({}))
    try:
        response = opener.open(request, timeout=value["seconds"])
    except urllib.error.HTTPError as error:
        response = error
    with response:
        status = response.status
        if type(status) is not int or not 200 <= status <= 599 or 300 <= status < 400:
            raise ValueError("invalid response envelope")
        raw = _read_bounded(response)
        content_type = response.headers.get("Content-Type", "")[:256]
        return status, raw, content_type


def main():
    fixture = sys.argv[1:] == ["--fixture-worker"]
    if sys.argv[1:] not in ([], ["--fixture-worker"]):
        return 2
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        return 2
    status, body, content_type = exchange(json.loads(raw), fixture=fixture)
    sys.stdout.buffer.write(
        json.dumps(
            [status, base64.b64encode(body).decode("ascii"), content_type]
        ).encode()
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:  # noqa: BLE001 -- never serialize a response, a request or an exception text.
        sys.exit(2)
