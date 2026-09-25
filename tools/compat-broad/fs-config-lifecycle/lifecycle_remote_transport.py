"""Fixed-origin HTTPS transport for the FS-CONFIG-LIFECYCLE production run.

One request at a time, through the reviewed worker bytes pinned below, spawned in an
isolated interpreter by the request-byte lane's bounded process exchange. The token
is written to the worker's stdin and never to a file, an environment variable or an
argument. The transport is reachable only through the descriptor's `transport_bound`
member on a consumed capability; a preparation run cannot name it.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(HERE))

from o8_admission import authorize_transport

ORIGIN = "https://firestore.googleapis.com"
TIMEOUT = 6.0
RESPONSE_BYTES = 256 * 1024
MAX_REQUEST_BYTES = 4096
WORKER_ENTRY = "tools/compat-broad/fs-config-lifecycle/lifecycle_https_worker.py"
EXCHANGE_MODULE = (
    "tools/compat-broad/fs-request-bytes-boundary/request_bytes_process_exchange.py"
)
_TOKEN = re.compile(r"[A-Za-z0-9._~+/-]{1,8192}=*")
# The digest of the worker bytes above. A worker edit that is not accompanied by a
# new digest here cannot run: the transport refuses before spawning it.
_WORKER_SHA256 = "37bed7bc3df888df15429c0600e790ae2f7c35e1209cb792d80a1cf0d5d67eb0"


def _load_exchange():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "_lifecycle_process_exchange", ROOT / EXCHANGE_MODULE
    )
    if spec is None or spec.loader is None:
        raise ValueError("reviewed process exchange unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def worker_source() -> bytes:
    source = (ROOT / WORKER_ENTRY).read_bytes()
    if hashlib.sha256(source).hexdigest() != _WORKER_SHA256:
        raise ValueError("fixed worker digest mismatch")
    return source


def _compact(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _parse(raw: bytes) -> Any:
    try:
        return json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None


def request(
    value: dict,
    token: str,
    *,
    deadline: float,
    capability,
    binding: bytes,
    binding_digest: str,
) -> dict[str, Any]:
    """Send one bounded Admin API request; return a gate receipt, never raise on wire."""
    import _lane

    _lane.ensure_package()
    from fs_config_lifecycle.lifecycle_collector import request_url_path

    authorize_transport(capability, binding=binding, binding_digest=binding_digest)
    if not isinstance(token, str) or _TOKEN.fullmatch(token) is None:
        raise ValueError("bounded bearer token required")
    if type(deadline) not in (int, float) or not math.isfinite(deadline):
        raise ValueError("finite absolute deadline required")
    if not isinstance(value, dict) or value.get("method") not in ("GET", "PATCH"):
        raise ValueError("closed configuration request required")
    source = worker_source()
    if binding != source or binding_digest != _WORKER_SHA256:
        raise ValueError("worker binding differs from the reviewed transport")
    body = b"" if value.get("body") is None else _compact(value["body"])
    if len(body) > MAX_REQUEST_BYTES:
        raise ValueError("configuration request exceeds the byte bound")
    message = {
        "method": value["method"],
        "path": request_url_path(value),
        "authorization": "Bearer " + token,
        "bodyBytes": len(body),
        "deadline": deadline,
    }
    exchange = _load_exchange()
    status, _content_type, raw, failure = exchange._run_process_exchange(
        worker_source=source,
        worker_sha256=_WORKER_SHA256,
        request_payload=_compact(message) + b"\n" + body,
        deadline=deadline,
        response_cap=RESPONSE_BYTES,
    )
    parsed = _parse(raw) if raw else None
    complete = (
        failure is None and status is not None and (parsed is not None or not raw)
    )
    return {
        "status": status,
        "body": parsed,
        "complete": complete,
        "failure": failure
        if failure is not None
        else (None if complete else "non-json"),
        "raw": bytes(raw),
    }
