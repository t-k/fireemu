"""Two closed OAuth requests after reservation; never discover or read credentials."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from broad_contract import digest

MODE = "authorized-user-refresh-v1"
VERIFIED_MODE = "verified-token-v1"
MAX_BYTES = 16384
REQUEST_SECONDS = 12
PREPARATION_SECONDS = 100
INNER_SECONDS = 1100
OUTER_SECONDS = 1200
OUTER_COST_MICROUSD = 1_303_500
SCOPE = "https://www.googleapis.com/auth/cloud-platform"
ADC_FIELDS = {"type", "client_id", "client_secret", "refresh_token"}


def contract():
    return {
        "mode": MODE,
        "kind": "stream-bounded-credential-preparation-v1",
        "slots": [
            {
                "id": "refresh",
                "method": "POST",
                "host": "oauth2.googleapis.com",
                "path": "/token",
            },
            {
                "id": "tokeninfo",
                "method": "POST",
                "host": "www.googleapis.com",
                "path": "/oauth2/v1/tokeninfo",
            },
        ],
        "requestSeconds": REQUEST_SECONDS,
        "preparationSeconds": PREPARATION_SECONDS,
        "maxRequestBytes": MAX_BYTES,
        "maxResponseBytes": MAX_BYTES,
        "outer": {
            "requests": 35,
            "seconds": OUTER_SECONDS,
            "costMicrousd": OUTER_COST_MICROUSD,
        },
        "inner": {"requests": 33, "seconds": INNER_SECONDS, "costMicrousd": 1_303_300},
        "discoverySource": "https://www.googleapis.com/discovery/v1/apis/oauth2/v1/rest",
        "discoveryRevision": "20200213",
        "additionalNetworkAllowanceMiB": 16,
        "networkMicrousdIncludingPreparation": ((5483 + 16) * 230000 + 1023) // 1024,
    }


def decode_json(raw):
    def unique(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate private input key")
            result[key] = value
        return result

    return json.loads(
        raw,
        object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(
            ValueError("finite private JSON required")
        ),
    )


def private_string(value, maximum):
    return (
        isinstance(value, str)
        and 0 < len(value) <= maximum
        and value.isascii()
        and not any(
            char.isspace() or ord(char) < 33 or ord(char) == 127 for char in value
        )
    )


def validate_principal(value):
    if (
        not isinstance(value, dict)
        or set(value) != {"clientId", "requiredScopes"}
        or not private_string(value["clientId"], 512)
        or value["requiredScopes"] != [SCOPE]
    ):
        raise ValueError("explicit OAuth client and cloud-platform scope required")


def validate_handoff(value, permission):
    if (
        not isinstance(value, dict)
        or set(value) != {"kind", "permissionDigest", "apiKey", "adc"}
        or value["kind"] != "stream-o8-authorized-user-v1"
        or value["permissionDigest"] != digest(permission)
    ):
        raise ValueError("bound authorized-user handoff required")
    adc = value["adc"]
    if (
        not isinstance(adc, dict)
        or set(adc) != ADC_FIELDS
        or adc["type"] != "authorized_user"
        or any(
            not private_string(adc[key], maximum)
            for key, maximum in (
                ("client_id", 512),
                ("client_secret", 4096),
                ("refresh_token", 8192),
            )
        )
        or not private_string(value["apiKey"], 256)
    ):
        raise ValueError("closed authorized-user credential fields required")
    validate_principal(permission.get("credentialPrincipal"))
    if (
        digest(adc) != permission.get("authorizedUserDigest")
        or adc["client_id"] != permission["credentialPrincipal"]["clientId"]
    ):
        raise ValueError("authorized-user binding differs")
    return value


def build_request(slot, secret):
    from urllib.parse import urlencode

    if slot == "refresh":
        if (
            not isinstance(secret, dict)
            or set(secret) != ADC_FIELDS
            or secret["type"] != "authorized_user"
        ):
            raise ValueError("closed refresh fields required")
        values = {
            key: secret[key] for key in ("client_id", "client_secret", "refresh_token")
        }
        if any(not private_string(value, 8192) for value in values.values()):
            raise ValueError("bounded refresh values required")
        body = urlencode({"grant_type": "refresh_token", **values}).encode()
        host, path = "oauth2.googleapis.com", "/token"
    elif slot == "tokeninfo" and private_string(secret, 8192):
        body = b""
        host = "www.googleapis.com"
        path = "/oauth2/v1/tokeninfo?" + urlencode({"access_token": secret})
    else:
        raise ValueError("closed credential operation required")
    if len(body) > MAX_BYTES or len(path.encode()) > MAX_BYTES:
        raise ValueError("credential request byte limit")
    return {"method": "POST", "host": host, "path": path, "body": body}


def _http_request(slot, secret, fixture_origin=None):
    import http.client
    import ssl
    from urllib.parse import urlsplit

    from broad_contract import local_origin

    request = build_request(slot, secret)
    if fixture_origin is None:
        connection = http.client.HTTPSConnection(
            request["host"],
            timeout=REQUEST_SECONDS,
            context=ssl.create_default_context(),
        )
    else:
        local_origin(fixture_origin)
        target = urlsplit(fixture_origin)
        connection = http.client.HTTPConnection(
            target.hostname, target.port, timeout=REQUEST_SECONDS
        )
    summary = {
        "complete": False,
        "status": None,
        "receivedBytes": 0,
        "requestBytes": len(request["body"]) + len(request["path"].encode()),
    }
    try:
        connection.request(
            "POST",
            request["path"],
            body=request["body"],
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
        )
        response = connection.getresponse()
        summary["status"] = response.status
        if response.status != 200:
            return {**summary, "failure": "http-status"}
        length = response.getheader("Content-Length")
        if length is not None and (not length.isdigit() or int(length) > MAX_BYTES):
            return {**summary, "failure": "response-limit"}
        raw = response.read(MAX_BYTES + 1)
        summary["receivedBytes"] = len(raw)
        if len(raw) > MAX_BYTES or (length is not None and len(raw) != int(length)):
            return {**summary, "failure": "response-limit"}
        body = decode_json(raw)
        if not isinstance(body, dict):
            raise TypeError("credential response object required")
        return {**summary, "complete": True, "body": body}
    except Exception:  # noqa: BLE001 -- Never return credential-bearing exception text.
        return {**summary, "failure": "transport-or-json"}
    finally:
        connection.close()


def private_request(slot, secret, *, fixture_origin=None, deadline=REQUEST_SECONDS):
    import os
    import subprocess

    from broad_contract import local_origin

    build_request(slot, secret)
    if not 0 < deadline <= REQUEST_SECONDS:
        raise ValueError("bounded credential deadline required")
    payload = {"slot": slot, "secret": secret}
    flag = "--worker"
    if fixture_origin is not None:
        local_origin(fixture_origin)
        payload["fixtureOrigin"] = fixture_origin
        flag = "--fixture-worker"
    raw = json.dumps(payload, allow_nan=False).encode()
    if len(raw) > 65536:
        raise ValueError("bounded private credential request required")
    worker = subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), flag],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={"PATH": os.defpath, "LANG": "C"},
    )
    try:
        stdout, _ = worker.communicate(raw, timeout=deadline)
        if worker.returncode != 0 or len(stdout) > 65536:
            return {
                "complete": False,
                "failure": "private-worker",
                "workerReaped": True,
            }
        result = decode_json(stdout)
        if not isinstance(result, dict):
            raise TypeError("private credential response required")
        return {**result, "workerReaped": True}
    except subprocess.TimeoutExpired:
        worker.kill()
        worker.communicate(timeout=5)
        return {"complete": False, "failure": "deadline", "workerReaped": True}
    finally:
        if worker.poll() is None:
            worker.kill()
            worker.wait(timeout=5)


def _worker():
    if sys.argv[1:] not in (["--worker"], ["--fixture-worker"]):
        return 2
    raw = sys.stdin.buffer.read(65537)
    if len(raw) > 65536:
        return 2
    value = decode_json(raw)
    fields = {"slot", "secret"} | (
        {"fixtureOrigin"} if sys.argv[1] == "--fixture-worker" else set()
    )
    if not isinstance(value, dict) or set(value) != fields:
        return 2
    result = _http_request(value["slot"], value["secret"], value.get("fixtureOrigin"))
    sys.stdout.write(json.dumps(result, allow_nan=False))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(_worker())
    except Exception:  # noqa: BLE001 -- Private worker errors never expose secrets.
        raise SystemExit(2) from None
