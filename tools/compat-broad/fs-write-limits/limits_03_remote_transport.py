"""Fixed-origin, bounded REST transport for FS-WRITE-LIMITS-03.

Every call is bound to one slot of a plan the reviewed compiler produced from
the frozen nonce: the operation handed in must equal that slot's operation, a
cleanup delete must carry the version the Gate resolved, and the body bytes sent
are the canonical encoding of the frozen body. The worker that performs the
HTTPS exchange is a single reviewed source file pinned here by digest and run
in an isolated interpreter through the request-byte lane's process exchange.

This module acquires no credential, admits no campaign, persists nothing and
never retries. It is unreachable without an admitted O7 capability.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import math
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(HERE))

from compiler_03 import (
    CAMPAIGN,
    READBACK_SECONDS,
    SMALL_REQUEST_SECONDS,
    TRANSPORT_CEILING_SECONDS,
    compile_limits_plan,
    resolve_body,
    slot_seconds,
)
from o8_admission import authorize_transport

ORIGIN = "https://firestore.googleapis.com"
PROJECT = "fireemu-35fe6"
DATABASE = "(default)"
# The largest compiled body is the field-value refusal at 1,048,818 bytes; the
# worker refuses anything above this ceiling before it opens a connection.
MAX_REQUEST_BYTES = 4 * 1024 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
# The per-request wire deadline is the slot's own reservation: the transport
# ceiling for a body-carrying slot, the readback bound for a large read and the
# small bound for everything else. `compiler_03.slot_seconds` is the one place
# that decides which, so the transport cannot outrun what the Gate reserved.
TIMEOUT = TRANSPORT_CEILING_SECONDS
WORKER_ENTRY = "tools/compat-broad/fs-write-limits/limits_03_https_worker.py"
_WORKER_SHA256 = "cca47769c29929485eb0decb3e27f6fbef5b8f95ebf6bfaa76de4abc35d80499"
_TOKEN = re.compile(r"[A-Za-z0-9._~+/-]{1,8192}=*")
_VERSION = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z")
_DIAGNOSTIC_LIMIT = 512
_PLAN_CACHE: dict[tuple[str, str], dict[str, Any]] = {}


def _load(name: str, path: Path):
    """Load one reviewed module by exact path, without touching sys.path."""
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"reviewed module unavailable: {name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# The bounded, cancellable process exchange is the request-byte lane's reviewed
# implementation, reused rather than copied: it selects no worker and knows no
# origin, so the only lane-specific parts are the worker bytes and the message.
_process_exchange = _load(
    "_limits_03_process_exchange",
    ROOT
    / "tools/compat-broad/fs-request-bytes-boundary/request_bytes_process_exchange.py",
)


def _compact(value: Any) -> bytes:
    return json.dumps(
        value, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _token(value: Any) -> str:
    if not isinstance(value, str) or _TOKEN.fullmatch(value) is None:
        raise ValueError("invalid credential shape")
    return value


def worker_source() -> bytes:
    source = (ROOT / WORKER_ENTRY).read_bytes()
    if hashlib.sha256(source).hexdigest() != _WORKER_SHA256:
        raise ValueError("fixed worker digest mismatch")
    return source


def compiled_plan(nonce: str, part: str = "ALL") -> dict[str, Any]:
    """The reviewed compiler's plan for one nonce, recompiled and cached."""
    key = (nonce, part)
    if key not in _PLAN_CACHE:
        _PLAN_CACHE[key] = compile_limits_plan(PROJECT, DATABASE, nonce, part)
    return _PLAN_CACHE[key]


def operation_for_slot(
    plan: dict[str, Any], phase: str, index: int, operation: dict[str, Any]
) -> tuple[dict[str, Any], int]:
    """The frozen operation one slot names, and the row's response ceiling.

    A cleanup delete is frozen without its version and gains it only from the
    Gate-resolved read, so that one path suffix is the only part of an
    operation that may differ from the compiled plan.
    """
    if phase not in ("observation", "recovery") or type(index) is not int:
        raise ValueError("invalid request operation position")
    if not isinstance(operation, dict):
        raise TypeError("request operation required")
    # The authority is the reviewed compiler's own plan for the frozen nonce,
    # recompiled here, not the object handed in: a caller cannot move a request
    # to another slot or another body by reshaping the plan it passes.
    plan = compiled_plan(plan["nonce"], plan.get("part", "ALL"))
    job = plan["localGatePlan"]["jobs"]["limits"]
    operations = job[phase]
    if not 0 <= index < len(operations):
        raise ValueError("request operation outside plan")
    offset = 0 if phase == "observation" else len(job["observation"])
    row = plan["requests"][offset + index]
    # A large body is carried in the plan by reference; the frozen bytes are
    # the request row's, and the operation handed in must carry exactly those.
    expected = resolve_body(copy.deepcopy(operations[index]), row["body"])
    version_from = expected.pop("versionFrom", None)
    if version_from is not None:
        prefix = expected["path"] + "?currentDocument.updateTime="
        path = operation.get("path")
        if not isinstance(path, str) or not path.startswith(prefix):
            raise ValueError("resolved cleanup version required")
        version = unquote(path[len(prefix) :])
        try:
            datetime.fromisoformat(version.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("invalid cleanup version binding") from None
        if _VERSION.fullmatch(version) is None or path != prefix + quote(
            version, safe=""
        ):
            raise ValueError("invalid cleanup version binding")
        expected["path"] = path
    if _compact(operation) != _compact(expected):
        raise ValueError("request operation differs from frozen plan slot")
    return expected, row["responseByteLimit"]


def prepare(
    plan: dict[str, Any],
    phase: str,
    index: int,
    operation: dict[str, Any],
    token: str,
) -> tuple[str, str, bytes | None, dict[str, str], int]:
    """Validate and prepare one exact frozen REST operation without I/O."""
    if (
        not isinstance(plan, dict)
        or not isinstance(plan.get("nonce"), str)
        or not re.fullmatch(r"[0-9a-f]{32}", plan["nonce"])
        or plan.get("part", "ALL") not in ("ALL", "A", "B")
        or not str(plan.get("campaignId", "")).startswith(CAMPAIGN)
    ):
        raise ValueError("compiled limits-03 plan required")
    expected, response_cap = operation_for_slot(plan, phase, index, operation)
    credential = _token(token)
    body = None if expected["body"] is None else _compact(expected["body"])
    if body is not None and len(body) > MAX_REQUEST_BYTES:
        raise ValueError("request exceeds bounded byte ceiling")
    if not 0 < response_cap <= MAX_RESPONSE_BYTES:
        raise ValueError("compiled response ceiling outside the worker's bound")
    headers = {"Authorization": "Bearer " + credential, "x-goog-user-project": PROJECT}
    if body is not None:
        headers["Content-Type"] = "application/json"
    return ORIGIN + expected["path"], expected["method"], body, headers, response_cap


def slot_timeout(operation: dict[str, Any], response_cap: int) -> float:
    """The wire deadline one slot may spend, equal to its Gate reservation."""
    return slot_seconds(
        {"body": operation.get("body"), "responseByteLimit": response_cap}
    )


def _diagnostic(raw: bytes) -> str:
    return raw[:_DIAGNOSTIC_LIMIT].decode("utf-8", errors="replace")


# Reuse the lane's strict UTF-8/unique-key/finite-number response decoder by
# exact path. Ambient modules named "transport" must not select the contract.
_response_json = _load("_limits_03_response_json", HERE / "transport.py")


def _parse_body(body: bytes) -> Any:
    try:
        return _response_json._decode_json_response(body)
    except (UnicodeDecodeError, ValueError, RecursionError):
        return _diagnostic(body)


def _receipt(
    status: int | None,
    content_type: str,
    raw: bytes,
    failure: str | None,
    request_body: bytes | None,
) -> dict[str, Any]:
    if status is not None and 300 <= status < 400 and failure is None:
        failure = "redirect"
    if status is None:
        failure = failure or "transport-error"
    return {
        "kind": "typed-receipt" if status is not None else "transport-failure",
        "complete": failure is None,
        "failure": failure,
        "status": status,
        "contentType": content_type[:128],
        "bodyBytes": len(raw),
        "rawBodyBytes": len(raw),
        "rawBodySha256": hashlib.sha256(raw).hexdigest(),
        "rawBodyBase64": base64.b64encode(raw).decode("ascii"),
        "body": _parse_body(raw) if raw else None,
        "diagnostic": _diagnostic(raw),
        "requestBytes": len(request_body or b""),
        "requestSha256": hashlib.sha256(request_body or b"").hexdigest(),
    }


def _exchange(
    url: str,
    method: str,
    body: bytes | None,
    headers: dict[str, str],
    deadline: float,
    response_cap: int,
) -> tuple[int | None, str, bytes, str | None]:
    if not url.startswith(ORIGIN + "/") or url.count(ORIGIN) != 1:
        raise ValueError("invalid fixed origin")
    path = url[len(ORIGIN) :]
    if not path.startswith("/v1/projects/" + PROJECT + "/"):
        raise ValueError("invalid project path")
    source = worker_source()
    message = {
        "method": method,
        "path": path,
        "authorization": headers["Authorization"],
        "project": PROJECT,
        "bodyBytes": len(body or b""),
        "deadline": deadline,
    }
    payload = _compact(message) + b"\n" + (body or b"")
    if time.monotonic() >= deadline:
        return None, "", b"", "timeout"
    return _process_exchange._run_process_exchange(
        worker_source=source,
        worker_sha256=_WORKER_SHA256,
        request_payload=payload,
        deadline=deadline,
        response_cap=response_cap,
    )


def request(
    plan: dict[str, Any],
    phase: str,
    index: int,
    operation: dict[str, Any],
    token: str,
    *,
    deadline: float,
    capability=None,
    binding=None,
    binding_digest=None,
) -> dict[str, Any]:
    """Send one fixed-origin operation, or return a typed transport failure.

    The wire deadline is the slot's reservation from `compiler_03.slot_seconds`,
    capped by the absolute deadline the Gate handed the collector, so a request
    can neither outrun its own reservation nor the phase window.
    """
    if capability is None:
        raise ValueError("active O7 production capability required")
    authorize_transport(capability, binding=binding, binding_digest=binding_digest)
    if type(deadline) not in (int, float) or not math.isfinite(deadline):
        raise ValueError("finite absolute deadline required")
    started = time.monotonic()
    url, method, body, headers, response_cap = prepare(
        plan, phase, index, operation, token
    )
    timeout = slot_timeout(operation, response_cap)
    if timeout not in (SMALL_REQUEST_SECONDS, READBACK_SECONDS, TIMEOUT):
        raise ValueError("slot reservation outside the declared bounds")
    local_deadline = min(started + timeout, deadline)
    if time.monotonic() >= local_deadline:
        receipt = _receipt(None, "", b"", "timeout", body)
    else:
        status, content_type, raw, failure = _exchange(
            url, method, body, headers, local_deadline, response_cap
        )
        receipt = _receipt(status, content_type, raw, failure, body)
    receipt["elapsedSeconds"] = time.monotonic() - started
    return receipt
