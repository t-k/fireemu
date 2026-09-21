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

# The read-only HTTP layer's own socket timeout is kept below the deadline
# the coordinator (`_private_request`) will use to SIGKILL the worker, so a
# stalled connection surfaces as a labeled "read-timeout" failure carrying
# diagnostics instead of an opaque kill with no signal at all. See
# `_bounded_socket_timeout`.
SOCKET_TIMEOUT_FLOOR_SECONDS = 1.0
WORKER_STARTUP_MARGIN_SECONDS = 0.5

# `_http_request` treats its `timeout` argument as a single absolute
# deadline for the whole exchange (connect, headers, every body read), not a
# fixed per-operation socket timeout. Each phase gets whatever remains of
# that deadline, less this small safety margin, so a slow earlier phase
# (e.g. delayed headers) narrows the budget left for the next one instead of
# each phase getting a fresh full-length timeout. The floor keeps a socket
# call from ever being handed a zero or negative timeout (which would put
# the socket in non-blocking mode) when the remaining budget is already
# below the margin; in that case the phase is reported as timed out
# immediately instead of attempting the call.
PHASE_MARGIN_SECONDS = 0.01
PHASE_TIMEOUT_FLOOR_SECONDS = 0.001
BODY_READ_CHUNK_BYTES = 8192


def _bounded_socket_timeout(deadline, cleanup_margin):
    """HTTP-layer timeout for one private-worker call, strictly below the
    coordinator's own kill deadline (`deadline - cleanup_margin`) by a fixed
    margin that covers interpreter startup and result serialization, and
    never below a small floor so a very short deadline still gets a usable
    (if short) socket timeout rather than zero."""
    return max(
        SOCKET_TIMEOUT_FLOOR_SECONDS,
        deadline - cleanup_margin - WORKER_STARTUP_MARGIN_SECONDS,
    )


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


def _http_request(slot, secret, fixture_origin=None, *, timeout=REQUEST_SECONDS):
    """Bounded HTTP call against a single absolute deadline (`timeout`
    seconds from now), not a fixed per-operation socket timeout. The
    deadline is recomputed before connecting, before reading headers and
    before every body read, so a slow earlier phase (delayed headers, a
    slow-trickling body) narrows what is left for the next phase instead of
    each phase getting a fresh full-length timeout that could add up past
    the caller's own kill deadline. See `_private_request` and
    `_bounded_socket_timeout` for how that outer deadline is derived.

    Failures are a diagnosable, non-credential-bearing taxonomy:
    connect-timeout, connect-failed, headers-timeout, body-truncated,
    body-oversize, read-timeout, transport-error (other OSError/http
    exceptions, tagged with the exception class name) and json-invalid.
    Every failure carries receivedBytes, declaredLength (when known),
    elapsedSeconds and the phase it failed in; timeouts also carry the
    requested socketTimeoutSeconds budget. None of these fields can contain
    response or credential bytes -- they are counts, a header value already
    bounded to MAX_BYTES, and exception type names."""
    import http.client
    import socket
    import ssl
    import threading
    import time
    from urllib.parse import urlsplit

    from broad_contract import local_origin

    request = build_request(slot, secret)
    started = time.monotonic()
    deadline = started + timeout
    summary = {
        "complete": False,
        "status": None,
        "receivedBytes": 0,
        "requestBytes": len(request["body"]) + len(request["path"].encode()),
        "declaredLength": None,
        "elapsedSeconds": 0.0,
        "socketTimeoutSeconds": timeout,
    }

    def stamped(**fields):
        summary["elapsedSeconds"] = time.monotonic() - started
        return {**summary, **fields}

    def phase_budget():
        """Timeout for the next blocking socket call, strictly below the
        remaining time to `deadline`, or None once that margin is gone."""
        remaining = deadline - time.monotonic()
        if remaining <= PHASE_MARGIN_SECONDS:
            return None
        return max(remaining - PHASE_MARGIN_SECONDS, PHASE_TIMEOUT_FLOOR_SECONDS)

    connect_budget = phase_budget()
    if connect_budget is None:
        return stamped(failure="connect-timeout", phase="connect")
    if fixture_origin is None:
        connection = http.client.HTTPSConnection(
            request["host"],
            timeout=connect_budget,
            context=ssl.create_default_context(),
        )
    else:
        local_origin(fixture_origin)
        target = urlsplit(fixture_origin)
        connection = http.client.HTTPConnection(
            target.hostname, target.port, timeout=connect_budget
        )
    try:
        try:
            connection.connect()
        except TimeoutError as error:
            return stamped(
                failure="connect-timeout",
                exceptionClass=type(error).__name__,
                phase="connect",
            )
        except OSError as error:
            return stamped(
                failure="connect-failed",
                exceptionClass=type(error).__name__,
                phase="connect",
            )

        # Captured once, not re-read from `connection.sock`: once the
        # response headers say the connection will close (as every fixed
        # request here does), `HTTPConnection.getresponse()` immediately
        # calls `self.close()`, which sets `connection.sock` to None even
        # though the response body is still readable through this same
        # socket object (the response's own buffered reader holds a
        # separate reference to it via `sock.makefile()`).
        sock = connection.sock
        headers_budget = phase_budget()
        if headers_budget is None:
            return stamped(failure="headers-timeout", phase="headers")
        sock.settimeout(headers_budget)
        header_expired = threading.Event()
        header_finished = threading.Event()

        def interrupt_headers():
            if header_finished.wait(headers_budget):
                return
            header_expired.set()
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        header_interrupt = threading.Thread(target=interrupt_headers, daemon=True)
        header_interrupt.start()
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
            if header_expired.is_set():
                return stamped(failure="headers-timeout", phase="headers")
        except TimeoutError as error:
            return stamped(
                failure="headers-timeout",
                exceptionClass=type(error).__name__,
                phase="headers",
            )
        except OSError as error:
            if header_expired.is_set():
                return stamped(
                    failure="headers-timeout",
                    exceptionClass=type(error).__name__,
                    phase="headers",
                )
            return stamped(
                failure="connect-failed",
                exceptionClass=type(error).__name__,
                phase="headers",
            )
        finally:
            header_finished.set()
            header_interrupt.join(timeout=0.1)
        summary["status"] = response.status
        if response.status != 200:
            return stamped(failure="http-status", phase="headers")
        transfer_encoding = response.getheader("Transfer-Encoding")
        if (
            transfer_encoding is not None
            and response.getheader("Content-Length") is not None
        ):
            return stamped(
                failure="transport-error",
                exceptionClass="ConflictingMessageFraming",
                phase="headers",
            )
        length = response.getheader("Content-Length")
        declared = None
        if length is not None:
            if not length.isdigit():
                return stamped(
                    failure="transport-error",
                    exceptionClass="InvalidContentLength",
                    phase="headers",
                )
            declared = int(length)
            summary["declaredLength"] = declared
            if declared > MAX_BYTES:
                return stamped(failure="body-oversize", phase="headers")

        # Read the body in bounded pieces rather than one call for the whole
        # (possibly MAX_BYTES-sized) response: `receivedBytes` is updated
        # after every piece, so a timeout or a truncated chunked stream
        # partway through still reports the bytes already received instead
        # of losing them inside one large, all-or-nothing read.
        received = 0
        buffer = bytearray()
        while received <= MAX_BYTES:
            body_budget = phase_budget()
            if body_budget is None:
                return stamped(
                    failure="read-timeout", receivedBytes=received, phase="body"
                )
            sock.settimeout(body_budget)
            want = min(BODY_READ_CHUNK_BYTES, MAX_BYTES + 1 - received)
            try:
                piece = response.read1(want)
            except http.client.IncompleteRead as error:
                # `.partial` is only the bytes read within this one call;
                # `received` already carries the bytes from earlier pieces.
                received += len(error.partial)
                return stamped(
                    failure="body-truncated", receivedBytes=received, phase="body"
                )
            except TimeoutError as error:
                return stamped(
                    failure="read-timeout",
                    exceptionClass=type(error).__name__,
                    receivedBytes=received,
                    phase="body",
                )
            except Exception as error:  # noqa: BLE001 -- exception class name only.
                return stamped(
                    failure="transport-error",
                    exceptionClass=type(error).__name__,
                    receivedBytes=received,
                    phase="body",
                )
            if not piece:
                break
            buffer += piece
            received += len(piece)
            summary["receivedBytes"] = received
            if declared is not None and received >= declared:
                break

        raw = bytes(buffer)
        if len(raw) > MAX_BYTES:
            return stamped(
                failure="body-oversize", receivedBytes=len(raw), phase="body"
            )
        if declared is not None and len(raw) != declared:
            return stamped(
                failure="body-truncated", receivedBytes=len(raw), phase="body"
            )
        try:
            body = decode_json(raw)
            if not isinstance(body, dict):
                raise TypeError("credential response object required")
        except Exception:  # noqa: BLE001 -- Never return credential-bearing text.
            return stamped(failure="json-invalid", receivedBytes=len(raw), phase="body")
        return stamped(complete=True, body=body, phase="body")
    except Exception as error:  # noqa: BLE001 -- Never return credential-bearing text.
        return stamped(failure="transport-error", exceptionClass=type(error).__name__)
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
    cleanup_margin = min(0.25, deadline / 4)
    payload = {
        "slot": slot,
        "secret": secret,
        # The worker's own HTTP-layer timeout, kept below this call's kill
        # deadline so a stall is diagnosed as "read-timeout" by the worker
        # instead of only ever observed as an opaque SIGKILL. See
        # `_bounded_socket_timeout`.
        "socketTimeoutSeconds": _bounded_socket_timeout(deadline, cleanup_margin),
    }
    flag = "--worker"
    if fixture_origin is not None:
        local_origin(fixture_origin)
        payload["fixtureOrigin"] = fixture_origin
        flag = "--fixture-worker"
    raw = json.dumps(payload, allow_nan=False).encode()
    if len(raw) > 65536:
        raise ValueError("bounded private credential request required")
    deadline_at = time.monotonic() + deadline
    worker = subprocess.Popen(
        # This worker uses only stdlib and explicit repository imports. Do not
        # run site hooks or inherit interpreter search-path configuration.
        [sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()), flag],
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
    fields = {"slot", "secret", "socketTimeoutSeconds"} | (
        {"fixtureOrigin"} if sys.argv[1] == "--fixture-worker" else set()
    )
    if not isinstance(value, dict) or set(value) != fields:
        return 2
    timeout = value["socketTimeoutSeconds"]
    if (
        type(timeout) not in (int, float)
        or isinstance(timeout, bool)
        or not 0 < timeout <= REQUEST_SECONDS
    ):
        return 2
    result = _http_request(
        value["slot"], value["secret"], value.get("fixtureOrigin"), timeout=timeout
    )
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
