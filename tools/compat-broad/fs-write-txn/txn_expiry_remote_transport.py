"""Fixed-origin, bounded REST transport for the transaction expiry campaign.

The collector speaks a small RPC vocabulary (`BeginTransaction`, `Commit`,
`Rollback`, `GetDocument`) over an injected transport. This module is the
production side of that transport: it turns one collector request into exactly
one Firestore REST exchange against the fixed host, runs it in a digest-pinned
worker process with an absolute deadline, and normalizes the answer into the
response contract the collector already validates.

It acquires no credential, admits no campaign, retries nothing and reaches no
host but `firestore.googleapis.com`. Every call must carry an admitted O7
capability; tests inject a low-level exchange instead of the worker and never
reach the network.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import sys
import time
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(HERE))

import txn_expiry_cases as cases
import txn_expiry_collector as collector
import txn_expiry_plan as plan_module
from batch_contract import PROJECT
from batch_wire import _decode_json_response
from o8_admission import authorize_transport

ORIGIN = "https://firestore.googleapis.com"
WORKER_ENTRY = "tools/compat-broad/fs-write-txn/txn_expiry_https_worker.py"
#: The reviewed worker bytes this transport spawns. A worker that does not hash
#: to this value is never started; the O7 frozen inputs bind the same digest.
WORKER_SHA256 = "2ee15b1a97a3b952d3c3429590a196ba129b88f083c42acfd6532ab863c424e4"
MAX_REQUEST_BYTES = plan_module.MAX_REQUEST_BYTES
MAX_RESPONSE_BYTES = plan_module.MAX_RESPONSE_BYTES
#: The longest any single exchange may take: the contended out-of-band commit,
#: which production does not refuse immediately but holds until the lock goes.
MAX_SECONDS = plan_module.CONTENDED_REQUEST_TIMEOUT_SECONDS
RPC_SUFFIX = {
    "BeginTransaction": ":beginTransaction",
    "Commit": ":commit",
    "Rollback": ":rollback",
}
#: REST status names mapped to the gRPC codes the case table speaks. Kept
#: identical to the rehearsal transport's table so a production row and a
#: rehearsal row are normalized by the same rule.
STATUS_TO_CODE = {
    "OK": 0,
    "CANCELLED": 1,
    "UNKNOWN": 2,
    "INVALID_ARGUMENT": 3,
    "DEADLINE_EXCEEDED": 4,
    "NOT_FOUND": 5,
    "ALREADY_EXISTS": 6,
    "PERMISSION_DENIED": 7,
    "RESOURCE_EXHAUSTED": 8,
    "FAILED_PRECONDITION": 9,
    "ABORTED": 10,
    "OUT_OF_RANGE": 11,
    "UNIMPLEMENTED": 12,
    "INTERNAL": 13,
    "UNAVAILABLE": 14,
    "UNAUTHENTICATED": 16,
}


def _load(name, path):
    """Load one reviewed module by exact path, without touching sys.path."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"reviewed module unavailable: {name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# The bounded, cancellable worker exchange is the request-byte lane's reviewed
# implementation, reached by path rather than by prepending that lane's
# directory to sys.path. It selects no worker: the bytes and digest come from
# here.
_exchange_module = _load(
    "_txn_expiry_process_exchange",
    ROOT
    / "tools/compat-broad/fs-request-bytes-boundary/request_bytes_process_exchange.py",
)
_run_process_exchange = _exchange_module._run_process_exchange


def worker_source() -> bytes:
    return (ROOT / WORKER_ENTRY).read_bytes()


def _text(value, *, limit):
    return isinstance(value, str) and 0 < len(value) <= limit


def _identity(value):
    return (
        _text(value, limit=128)
        and not any(c in value for c in "/?#%\\")
        and not any(ord(c) <= 32 for c in value)
    )


def build(request, *, project=PROJECT, database=plan_module.DATABASE):
    """One exact REST exchange for one collector request, or a refusal.

    The request has to name the fixed production project and database, and a
    document request has to name a document below the plan's own owned
    collection. Anything else is refused here, before a worker exists.
    """
    if not isinstance(request, dict):
        raise ValueError("collector request required")  # noqa: TRY004 -- admission boundary collapses malformed input to one refusal class
    rpc = request.get("rpc")
    if rpc not in cases.RPCS:
        raise ValueError("request outside the campaign rpc vocabulary")
    if (
        request.get("projectId") != project
        or request.get("database") != database
        or not _identity(project)
        or not _identity(database)
    ):
        raise ValueError("fixed production project and database required")
    timeout = request.get("timeoutSeconds")
    if not collector.finite_seconds(timeout) or not 0 < timeout <= MAX_SECONDS:
        raise ValueError("request timeout outside envelope")
    limit = request.get("maxResponseBytes")
    request_limit = request.get("maxRequestBytes")
    if (
        type(limit) is not int
        or not 1 <= limit <= MAX_RESPONSE_BYTES
        or type(request_limit) is not int
        or not 1 <= request_limit <= MAX_REQUEST_BYTES
    ):
        raise ValueError("request bounds invalid")
    base = f"/v1/projects/{project}/databases/{database}/documents"
    if rpc == "GetDocument":
        name = request.get("name")
        prefix = f"projects/{project}/databases/{database}/documents/"
        if (
            not _text(name, limit=1024)
            or not name.startswith(prefix)
            or any(c in name for c in "?#%\\")
            or any(ord(c) <= 32 for c in name)
        ):
            raise ValueError("document resource mismatch")
        path = name[len(prefix) :]
        segments = path.split("/")
        if (
            len(segments) != 4
            or segments[0] != "oracle"
            or segments[2] != plan_module.CAMPAIGN_SEGMENT
            or segments[3] not in cases.RESOURCE_ROLES
            or plan_module.NONCE_PATTERN.match(segments[1]) is None
        ):
            raise ValueError("document outside the owned campaign collection")
        if request.get("body") is not None:
            raise ValueError("a document read carries no body")
        query = request.get("query") or {}
        if not isinstance(query, dict) or set(query) - {"transaction"}:
            raise ValueError("invalid document query")
        url = f"/v1/{name}"
        if "transaction" in query:
            token = query["transaction"]
            if not _text(token, limit=4096):
                raise ValueError("invalid transaction query")
            url += "?transaction=" + urllib.parse.quote(token, safe="")
        return "GET", url, None
    body = request.get("body")
    if not isinstance(body, dict) or request.get("query") is not None:
        raise ValueError("request object required")
    if request.get("name") is not None:
        raise ValueError("an rpc request names no document")
    payload = json.dumps(body, allow_nan=False, separators=(",", ":")).encode()
    if len(payload) > request_limit:
        raise ValueError("request exceeds bound")
    return "POST", base + RPC_SUFFIX[rpc], payload


def normalize(status, raw, request):
    """The collector's response contract, from one complete HTTP answer."""
    try:
        body = _decode_json_response(raw)
    except (ValueError, TypeError, RecursionError, UnicodeError):
        return _incomplete(status, "response-not-json")
    if not isinstance(body, dict):
        return _incomplete(status, "response-object-required")
    if status == 200:
        normalized = {
            "complete": True,
            "code": 0,
            "status": "OK",
            "message": None,
            "body": body,
        }
    else:
        detail = body.get("error") if set(body) == {"error"} else None
        if not isinstance(detail, dict):
            return _incomplete(status, "error-envelope-required")
        code = STATUS_TO_CODE.get(detail.get("status"))
        if (
            type(code) is not int
            or type(detail.get("code")) is not int
            or detail["code"] != status
        ):
            return _incomplete(status, "error-status-not-confirmed")
        message = detail.get("message")
        normalized = {
            "complete": True,
            "code": code,
            "status": detail["status"],
            "message": message if isinstance(message, str) else None,
            "body": body,
        }
    normalized["httpStatus"] = status
    return collector._checked_response(normalized, request)


def _incomplete(status, failure):
    return {
        "complete": False,
        "code": None,
        "status": None,
        "httpStatus": status,
        "message": failure,
        "body": None,
    }


def _bounded_deadline(request, *, deadline, clock):
    """The absolute instant this exchange must be over by.

    The collector's own per-request timeout is a ceiling; the caller's absolute
    deadline, derived from the Gate slot it reserved, is another. The exchange
    stops at whichever comes first, and never later than the campaign's
    contended-request maximum.
    """
    if type(deadline) not in (int, float) or not math.isfinite(deadline):
        raise ValueError("finite absolute deadline required")
    local = clock() + min(float(request["timeoutSeconds"]), float(MAX_SECONDS))
    return min(local, deadline)


def request(
    value,
    *,
    deadline,
    capability=None,
    binding=None,
    binding_digest=None,
    exchange=None,
    clock=time.monotonic,
):
    """Send one collector request through the fixed production wire.

    Returns the collector's response contract plus a private `wire` record
    (raw bytes, digests, elapsed seconds) the coordinator journals. The token
    is read from `value["token"]`, used for one exchange and never stored.
    """
    if not isinstance(value, dict) or set(value) != {"request", "token"}:
        raise ValueError("closed transaction wire call required")
    inner = value["request"]
    token = value["token"]
    if not _text(token, limit=8192) or not all(33 <= ord(c) <= 126 for c in token):
        raise ValueError("invalid credential shape")
    method, path, payload = build(inner)
    if exchange is None:
        if capability is None:
            raise ValueError("active O7 production capability required")
        authorize_transport(capability, binding=binding, binding_digest=binding_digest)
        if (
            not isinstance(binding, bytes)
            or hashlib.sha256(binding).hexdigest() != WORKER_SHA256
            or binding_digest != WORKER_SHA256
        ):
            raise ValueError("worker source digest differs from the reviewed transport")
    absolute = _bounded_deadline(inner, deadline=deadline, clock=clock)
    started = clock()
    if clock() >= absolute:
        return _wire_failure(None, "timeout", started, clock, payload)
    message = {
        "method": method,
        "path": path,
        "authorization": "Bearer " + token,
        "project": inner["projectId"],
        "bodyBytes": len(payload or b""),
        "deadline": absolute,
    }
    encoded = (
        json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode()
        + b"\n"
        + (payload or b"")
    )
    try:
        if exchange is not None:
            status, content_type, raw, failure = exchange(
                method, path, payload, absolute, MAX_RESPONSE_BYTES
            )
        else:
            status, content_type, raw, failure = _run_process_exchange(
                worker_source=binding,
                worker_sha256=WORKER_SHA256,
                request_payload=encoded,
                deadline=absolute,
                response_cap=MAX_RESPONSE_BYTES,
            )
    except Exception as error:  # noqa: BLE001 -- a transport fault is a bounded receipt, never a secret.
        return _wire_failure(None, type(error).__name__, started, clock, payload)
    elapsed = clock() - started
    wire = {
        "status": status,
        "contentType": content_type if isinstance(content_type, str) else "",
        "failure": failure,
        "rawBodyBytes": len(raw),
        "rawBodySha256": hashlib.sha256(raw).hexdigest(),
        "rawBodyBase64": base64.b64encode(raw).decode("ascii"),
        "requestBytes": len(payload or b""),
        "requestSha256": hashlib.sha256(payload or b"").hexdigest(),
        "elapsedSeconds": elapsed,
    }
    if failure is not None or type(status) is not int or not 100 <= status <= 599:
        result = _incomplete(
            status if type(status) is int else None, failure or "status-missing"
        )
    elif 300 <= status < 400:
        result = _incomplete(status, "redirect")
    elif wire["contentType"].split(";", 1)[0].strip().lower() != "application/json":
        result = _incomplete(status, "invalid-media-type")
    else:
        result = normalize(status, raw, inner)
    result["wire"] = wire
    return result


def _wire_failure(status, failure, started, clock, payload):
    result = _incomplete(status, failure)
    result["wire"] = {
        "status": status,
        "contentType": "",
        "failure": failure,
        "rawBodyBytes": 0,
        "rawBodySha256": hashlib.sha256(b"").hexdigest(),
        "rawBodyBase64": "",
        "requestBytes": len(payload or b""),
        "requestSha256": hashlib.sha256(payload or b"").hexdigest(),
        "elapsedSeconds": clock() - started,
    }
    return result
