"""Fixed-origin, fixed-plan bounded wire adapter for the Commit campaign."""

from __future__ import annotations

import copy
import fcntl
import hashlib
import importlib.util
import json
import math
import os
import re
import stat
import subprocess
import sys
import time
import types
import zipimport
from pathlib import Path
from urllib.parse import unquote, urlsplit

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))

def _archive_origin() -> tuple[str, str] | None:
    match = re.fullmatch(r"(/dev/fd/([0-9]+))/commit_remote_transport\.py", __file__)
    if match is None:
        return None
    archive, number = match.group(1), int(match.group(2))
    info = os.fstat(number)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 0
        or fcntl.fcntl(number, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
        or archive not in sys.path
    ):
        raise ImportError("untrusted archive descriptor")
    return archive, hashlib.sha256(os.pread(number, info.st_size, 0)).hexdigest()


_ARCHIVE = _archive_origin()
if _ARCHIVE is None:
    _transport_spec = importlib.util.spec_from_file_location(
        "_commit_fixed_bounded_transport", ROOT / "tools/compat-broad/fs-write-limits/transport.py"
    )
    if _transport_spec is None or _transport_spec.loader is None:
        raise ImportError("bounded transport unavailable")
    _transport = importlib.util.module_from_spec(_transport_spec)
    _transport_spec.loader.exec_module(_transport)
else:
    _archive, _ = _ARCHIVE
    _importer = zipimport.zipimporter(_archive)
    _code = _importer.get_code("transport")
    _origin = f"{_archive}/transport.py"
    if _code is None or _code.co_filename != _origin or _archive_origin() != _ARCHIVE:
        raise ImportError("bounded transport archive member unavailable")
    _transport = types.ModuleType("_commit_fixed_bounded_transport")
    _transport.__file__ = _origin
    _transport.__loader__ = _importer
    exec(_code, _transport.__dict__)  # noqa: S102 -- exact member of the verified inherited archive
    if _archive_origin() != _ARCHIVE:
        raise ImportError("bounded transport archive digest changed")
_exchange = _transport._exchange
MAX_CAP = _transport.MAX_CAP

sys.path.insert(0, str(HERE))
from transform_compiler import compile_plan

ORIGIN = "https://firestore.googleapis.com"
PROJECT = "fireemu-35fe6"
DATABASE = "(default)"
TIMEOUT = 12.0
INPUT_CAP = 4 * 1024 * 1024
_TOKEN = re.compile(r"[A-Za-z0-9._~+/-]{1,8192}=*")
_VERSION = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z")


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _local_origin(value: str) -> str:
    parts = urlsplit(value)
    if (
        parts.scheme != "http"
        or parts.hostname not in {"127.0.0.1", "localhost"}
        or parts.username is not None
        or parts.password is not None
        or parts.path not in {"", "/"}
        or parts.query
        or parts.fragment
    ):
        raise ValueError("local origin must be an unqualified loopback HTTP origin")
    return value.rstrip("/")


def _binding(value: dict) -> tuple[dict, str]:
    if not isinstance(value, dict) or set(value) not in (
        {"nonce", "phase", "index", "operation", "token"},
        {"nonce", "phase", "index", "operation", "token", "localMode"},
    ):
        raise ValueError("closed Commit wire input required")
    local = value.get("localMode", False)
    if type(local) is not bool:
        raise ValueError("localMode must be boolean")
    if not isinstance(value["nonce"], str) or re.fullmatch(r"[0-9a-f]{32}", value["nonce"]) is None:
        raise ValueError("invalid nonce")
    phase, index, operation = value["phase"], value["index"], value["operation"]
    if phase not in {"observation", "recovery"} or type(index) is not int or not isinstance(operation, dict):
        raise ValueError("invalid Commit operation position")
    project, database = ("demo", DATABASE) if local else (PROJECT, DATABASE)
    plan = compile_plan(project, database, value["nonce"])
    operations = plan[phase]
    if not 0 <= index < len(operations):
        raise ValueError("operation outside canonical Commit plan")
    expected = copy.deepcopy(operations[index])
    version_from = expected.pop("versionFrom", None)
    if version_from is not None:
        path = operation.get("path")
        prefix = expected["path"] + "?currentDocument.updateTime="
        if not isinstance(path, str) or not path.startswith(prefix):
            raise ValueError("resolved cleanup version required")
        version = unquote(path[len(prefix) :])
        if _VERSION.fullmatch(version) is None or path != prefix + quote_version(version):
            raise ValueError("invalid cleanup version binding")
        expected["path"] = prefix + quote_version(version)
    if _json(operation) != _json(expected):
        raise ValueError("operation differs from canonical Commit plan")
    token = value["token"]
    if not isinstance(token, str) or _TOKEN.fullmatch(token) is None:
        raise ValueError("invalid credential shape")
    return expected, project


def quote_version(value: str) -> str:
    return value.replace(":", "%3A").replace("+", "%2B")


def prepare(value: dict, *, local_origin: str | None = None) -> dict:
    operation, project = _binding(value)
    local = value.get("localMode", False)
    origin = _local_origin(local_origin) if local else ORIGIN
    if local and local_origin is None:
        raise ValueError("local mode requires explicit loopback origin")
    if not local and local_origin is not None:
        raise ValueError("production mode cannot override fixed origin")
    data = None if operation.get("body") is None else _json(operation["body"]).encode()
    if data is not None and len(data) > MAX_CAP:
        raise ValueError("request exceeds bounded cap")
    return {
        "url": origin + operation["path"],
        "method": operation["method"],
        "data": data,
        "headers": {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + value["token"],
            "x-goog-user-project": project,
        },
        "response_cap": MAX_CAP,
    }


def request(value: dict, *, local_origin: str | None = None, timeout: float = TIMEOUT) -> dict:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 < timeout <= TIMEOUT:
        raise ValueError("timeout must be positive and at most 12 seconds")
    prepare(value, local_origin=local_origin)
    envelope = {"value": value, "localOrigin": local_origin, "timeout": timeout}
    encoded = _json(envelope)
    if len(encoded.encode()) > INPUT_CAP:
        raise ValueError("wire input limit")
    try:
        child = subprocess.run(
            [sys.executable, "-I", str(HERE / "commit_remote_transport.py"), "--worker"],
            input=encoded,
            text=True,
            capture_output=True,
            env={},
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"kind": "deadline-exceeded", "complete": False}
    if child.returncode != 0:
        return {"kind": "worker-error", "complete": False}
    try:
        return json.loads(child.stdout)
    except (ValueError, UnicodeDecodeError):
        return {"kind": "worker-error", "complete": False}


def _worker(raw: bytes) -> None:
    if len(raw) > INPUT_CAP:
        raise ValueError("wire input limit")
    envelope = json.loads(raw)
    value = envelope["value"]
    args = prepare(value, local_origin=envelope.get("localOrigin"))
    deadline = time.monotonic() + float(envelope["timeout"])
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("deadline exceeded before I/O")
    result = _exchange(
        args["url"], args["method"], args["data"], args["headers"], args["response_cap"], remaining
    )
    print(json.dumps(result, allow_nan=False), end="")


if __name__ == "__main__":
    try:
        if sys.argv[1:] != ["--worker"]:
            raise ValueError("worker entrypoint only")
        _worker(sys.stdin.buffer.read(INPUT_CAP + 1))
    except Exception:  # noqa: BLE001 -- never echo worker input or diagnostics
        # Never echo input, credentials, or child diagnostics.
        sys.exit(2)
