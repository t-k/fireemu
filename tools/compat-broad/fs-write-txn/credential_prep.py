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


def _private_request(slot, secret, *, fixture_origin=None, deadline=REQUEST_SECONDS):
    import os
    import subprocess
    import time

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
    deadline_at = time.monotonic() + deadline
    cleanup_margin = min(0.25, deadline / 4)
    worker = subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), flag],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={"PATH": os.defpath, "LANG": "C"},
    )
    try:
        stdout, _ = worker.communicate(
            raw, timeout=max(0, deadline_at - time.monotonic() - cleanup_margin)
        )
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
        try:
            worker.communicate(timeout=max(0, deadline_at - time.monotonic()))
        except subprocess.TimeoutExpired:
            return {
                "complete": False,
                "failure": "deadline",
                "workerReaped": False,
                "workerPid": worker.pid,
            }
        return {"complete": False, "failure": "deadline", "workerReaped": True}
    finally:
        if worker.poll() is None:
            worker.kill()
            worker.poll()  # Nonblocking; an unreaped child remains explicit uncertainty.


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


def lifetime(value):
    if (
        type(value) not in (int, str)
        or not str(value).isdigit()
        or not 1 < int(value) <= 3600
    ):
        raise ValueError("bounded credential lifetime required")
    return int(value)


def refresh_result(body, sent):
    if (
        not isinstance(body, dict)
        or body.get("token_type") != "Bearer"
        or not private_string(body.get("access_token"), 8192)
    ):
        raise ValueError("typed OAuth refresh response required")
    return body["access_token"], sent + lifetime(body.get("expires_in")) - 1


def verified_credential(token, refresh_expiry, body, principal, sent):
    import time

    from batch_contract import Credential

    validate_principal(principal)
    if not isinstance(body, dict):
        raise TypeError("typed tokeninfo response required")
    clients = [body[key] for key in ("issued_to", "audience") if key in body]
    if not clients or any(value != principal["clientId"] for value in clients):
        raise ValueError("verified OAuth client differs")
    scope = body.get("scope")
    if (
        not isinstance(scope, str)
        or len(scope) > MAX_BYTES
        or not set(principal["requiredScopes"]).issubset(scope.split())
    ):
        raise ValueError("verified credential scope insufficient")
    expiry = min(refresh_expiry, sent + lifetime(body.get("expires_in")) - 1)
    now = time.monotonic()
    credential = Credential()
    credential.accept(token, {"expires_in": int(expiry - now)}, now)
    if not credential.usable(now, INNER_SECONDS + 2):
        raise ValueError("credential does not cover complete inner session")
    return credential, {
        "clientVerified": True,
        "principalDigest": digest(principal),
        "scopeDigest": digest(sorted(set(scope.split()))),
        "expiresAt": time.time() + credential.expiry - now,
    }


JOURNAL_FILES = (
    "binding",
    "refresh-charge",
    "refresh-receipt",
    "tokeninfo-charge",
    "tokeninfo-receipt",
    "complete",
)


def prepare_credentials(
    output,
    ledger,
    ticket,
    permission,
    plan,
    handoff,
    *,
    fixture_origin=None,
    binding_check=None,
):
    """Acquire only after two ordered, durably charged and validated responses."""
    import time

    from stream_bridge import source_digest
    from stream_production import write_atomic_receipt

    validate_handoff(handoff, permission)
    if digest(handoff["apiKey"]) != permission.get("apiKeyDigest"):
        raise ValueError("API key binding differs")
    if (
        fixture_origin is not None
        and permission.get("kind") != "local-stream-shadow-only"
    ):
        raise ValueError("local fixture permission required")
    if (
        fixture_origin is None
        and permission.get("kind") != "stream-prepared-refresh-owner-permission-v1"
    ):
        raise ValueError("refresh owner permission required")
    if permission.get("credentialMode") != MODE or permission.get(
        "credentialPreparationDigest"
    ) != digest(contract()):
        raise ValueError("frozen preparation contract required")
    claim = ledger.bound_claim(ticket)
    if (
        claim["budget"]
        != {
            "requests": 35,
            "accounts": 0,
            "resources": 3,
            "costMicrousd": OUTER_COST_MICROUSD,
        }
        or claim["durationSeconds"] != OUTER_SECONDS
        or claim["gatePlanDigest"] != digest(plan)
    ):
        raise ValueError("complete outer reservation required")
    reservation = ledger.snapshot()["reservations"][ticket["reservation"]]
    reservation_start = reservation["deadline"] - OUTER_SECONDS
    monotonic_end = time.monotonic() + reservation["deadline"] - time.time()
    frozen_permission = digest(permission)

    def current():
        ledger.validate(ticket, duration=INNER_SECONDS + REQUEST_SECONDS + 2)
        if (
            digest(permission) != frozen_permission
            or plan.get("permissionDigest") != frozen_permission
            or plan.get("observerSha256") != source_digest()
            or time.time() - reservation_start >= PREPARATION_SECONDS
            or time.monotonic() + INNER_SECONDS + REQUEST_SECONDS + 2 > monotonic_end
            or time.time() + INNER_SECONDS + REQUEST_SECONDS + 2
            > permission["expiresAt"]
        ):
            raise ValueError("preparation binding or lease changed")
        if binding_check is not None:
            binding_check()

    current()
    directory = Path(output) / "credential-preparation"
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError:
        raise ValueError("preparation cannot be resumed or repeated") from None
    binding = {
        "kind": contract()["kind"],
        "contractDigest": digest(contract()),
        "permissionDigest": frozen_permission,
        "ticketDigest": digest(ticket),
        "planDigest": digest(plan),
        "claimDigest": digest(claim),
        "reservationStartedAt": reservation_start,
        "observerSha256": source_digest(),
    }
    write_atomic_receipt(directory / "binding.json", binding)
    token = None
    refresh_expiry = None
    credential = None
    facts = None
    for ordinal, slot in enumerate(("refresh", "tokeninfo"), 1):
        current()
        charge = {
            "slot": slot,
            "ordinal": ordinal,
            "costMicrousd": 100,
            "bindingDigest": digest(binding),
            "chargedAt": time.time(),
        }
        write_atomic_receipt(directory / f"{slot}-charge.json", charge)
        current()  # The durable charge is not authorization to send after drift.
        sent = time.monotonic()
        result = _private_request(
            slot,
            handoff["adc"] if slot == "refresh" else token,
            fixture_origin=fixture_origin,
        )
        receipt = {
            "slot": slot,
            "chargeDigest": digest(charge),
            "verified": False,
            "complete": result.get("complete") is True,
            "workerReaped": result.get("workerReaped") is True,
            "status": result.get("status"),
            "receivedBytes": result.get("receivedBytes", 0),
        }
        try:
            if not receipt["complete"] or not receipt["workerReaped"]:
                raise ValueError("bounded private request incomplete")
            if slot == "refresh":
                token, refresh_expiry = refresh_result(result.get("body"), sent)
            else:
                credential, facts = verified_credential(
                    token,
                    refresh_expiry,
                    result.get("body"),
                    permission["credentialPrincipal"],
                    sent,
                )
                receipt["claims"] = facts
            receipt["verified"] = True
        except (ValueError, TypeError, KeyError):
            receipt["failure"] = "response-or-claims-invalid"
            write_atomic_receipt(directory / f"{slot}-receipt.json", receipt)
            raise ValueError(
                "credential preparation failed; reservation retained"
            ) from None
        write_atomic_receipt(directory / f"{slot}-receipt.json", receipt)
    current()
    write_atomic_receipt(
        directory / "complete.json",
        {
            "attempts": 2,
            "verified": True,
            "bindingDigest": digest(binding),
            "finishedAt": time.time(),
        },
    )
    records = {
        name: decode_json((directory / f"{name}.json").read_bytes())
        for name in JOURNAL_FILES
    }
    proof = {
        "attempts": 2,
        "journalDigest": digest(records),
        "monotonicDeadline": monotonic_end,
        "reservationStartedAt": reservation_start,
    }
    return credential, proof


def validate_preparation(output, ledger, ticket, permission, proof, state):
    """Require the original sealed two-slot acquisition before inner release."""
    import time

    from stream_bridge import source_digest

    directory = Path(output) / "credential-preparation"
    records = {
        name: decode_json((directory / f"{name}.json").read_bytes())
        for name in JOURNAL_FILES
    }
    binding = records["binding"]
    ledger.validate(ticket, duration=1)
    if (
        proof.get("attempts") != 2
        or proof.get("journalDigest") != digest(records)
        or binding["ticketDigest"] != digest(ticket)
        or binding["permissionDigest"] != digest(permission)
        or binding["claimDigest"] != digest(ledger.bound_claim(ticket))
        or binding["observerSha256"] != source_digest()
        or binding["contractDigest"] != digest(contract())
        or records["complete"].get("verified") is not True
        or time.monotonic() >= proof["monotonicDeadline"]
        or time.time() - binding["reservationStartedAt"] >= OUTER_SECONDS
        or state["total"] + 2 > 35
        or state["costMicrousd"] + 200 > OUTER_COST_MICROUSD
    ):
        raise ValueError("preparation proof or combined bound differs")
    for ordinal, slot in enumerate(("refresh", "tokeninfo"), 1):
        charge = records[f"{slot}-charge"]
        receipt = records[f"{slot}-receipt"]
        if (
            charge["ordinal"] != ordinal
            or charge["slot"] != slot
            or charge["bindingDigest"] != digest(binding)
            or receipt["chargeDigest"] != digest(charge)
            or receipt.get("verified") is not True
            or receipt.get("workerReaped") is not True
        ):
            raise ValueError("ordered preparation proof required")
    return {"requests": state["total"] + 2, "costMicrousd": state["costMicrousd"] + 200}


if __name__ == "__main__":
    try:
        raise SystemExit(_worker())
    except Exception:  # noqa: BLE001 -- Private worker errors never expose secrets.
        raise SystemExit(2) from None
