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
    HERE = Path(__file__).resolve().parent
    ROOT = HERE.parents[2]
    sys.path.insert(0, str(ROOT / "tools/compat-broad"))
else:
    # The archive is the only application import root in worker mode.  Retain
    # interpreter-owned stdlib locations, but never derive a checkout path
    # from the /dev/fd path and add it ahead of the archive.
    HERE = Path(__file__).parent
    ROOT = None
    archive_path = _ARCHIVE[0]
    prefixes = tuple(
        Path(prefix).resolve()
        for prefix in {sys.base_prefix, sys.exec_prefix}
    )
    stdlib_paths = []
    for entry in sys.path:
        if not entry or entry == archive_path:
            continue
        try:
            resolved = Path(entry).resolve()
        except OSError:
            continue
        if any(resolved == prefix or prefix in resolved.parents for prefix in prefixes):
            stdlib_paths.append(entry)
    sys.path[:] = [archive_path, *stdlib_paths]

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

if _ARCHIVE is None:
    sys.path.insert(0, str(HERE))
from transform_compiler import compile_plan

ORIGIN = "https://firestore.googleapis.com"
PROJECT = "fireemu-35fe6"
DATABASE = "(default)"
TIMEOUT = 12.0
INPUT_CAP = 4 * 1024 * 1024
ARCHIVE_CAP = 32 * 1024 * 1024
REAP_GRACE = 2.0
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


def _timeout(value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 < value <= TIMEOUT:
        raise ValueError("timeout must be positive and at most 12 seconds")
    return float(value)


def _envelope(value: dict, local_origin: str | None, timeout: float) -> str:
    encoded = _json({"value": value, "localOrigin": local_origin, "timeout": timeout})
    if len(encoded.encode()) > INPUT_CAP:
        raise ValueError("wire input limit")
    return encoded


def _reap(child) -> None:
    """End and collect a worker, escalating if it ignores termination."""
    if child.poll() is not None:
        child.wait()
        return
    try:
        child.terminate()
    except OSError:
        pass
    try:
        child.wait(timeout=REAP_GRACE)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        child.kill()
    except OSError:
        pass
    child.wait()


def _spawn(command: list[str], encoded: str, timeout: float, pass_fds: tuple[int, ...]) -> dict:
    """Run one bounded worker; always terminate and reap it before returning.

    Every exit from this function reaps the child: a normal exchange, a deadline,
    a malformed payload the parent cannot write, and an interruption alike.
    """
    child = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={},
        close_fds=True,
        pass_fds=pass_fds,
    )
    collected = False
    try:
        try:
            out, _ = child.communicate(encoded, timeout=timeout)
            collected = True
        except subprocess.TimeoutExpired:
            _reap(child)
            collected = True
            return {"kind": "deadline-exceeded", "complete": False, "workerReaped": True}
        if child.returncode != 0 or len(out.encode()) > MAX_CAP:
            return {"kind": "worker-error", "complete": False, "workerReaped": True}
        try:
            return json.loads(out)
        except (ValueError, UnicodeDecodeError):
            return {"kind": "worker-error", "complete": False, "workerReaped": True}
    finally:
        if not collected:
            _reap(child)


def _verify_archive_fd(fd: int, expected_sha256: str) -> None:
    """Require an unlinked, read-only, regular descriptor holding exactly those bytes."""
    if type(fd) is not int or fd < 0:
        raise ValueError("archive descriptor required")
    if not isinstance(expected_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
        raise ValueError("archive digest required")
    try:
        info = os.fstat(fd)
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    except OSError as error:
        raise ValueError("archive descriptor is not open") from error
    if flags & os.O_ACCMODE != os.O_RDONLY:
        raise ValueError("archive descriptor is writable")
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 0:
        raise ValueError("archive descriptor is not an unlinked regular file")
    if info.st_size > ARCHIVE_CAP:
        raise ValueError("archive descriptor too large")
    data = os.pread(fd, info.st_size + 1, 0)
    if len(data) != info.st_size or hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError("archive descriptor digest differs")
    later = os.fstat(fd)
    if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink) != (
        later.st_dev,
        later.st_ino,
        later.st_size,
        later.st_mtime_ns,
        later.st_ctime_ns,
        later.st_nlink,
    ):
        raise ValueError("archive descriptor changed during verification")


def request(value: dict, *, local_origin: str, timeout: float = TIMEOUT) -> dict:
    """Run one local/preparation request through the pathname worker.

    This entry point can never reach the fixed production origin: it requires an
    explicit loopback origin. Production requires `request_bound`, whose worker
    bytes are pinned to an O7-issued archive descriptor.
    """
    if local_origin is None:
        raise ValueError("production wire requires an O7 archive descriptor binding")
    timeout = _timeout(timeout)
    prepare(value, local_origin=local_origin)
    encoded = _envelope(value, local_origin, timeout)
    return _spawn(
        [sys.executable, "-I", "-S", "-B", str(HERE / "commit_remote_transport.py"), "--worker"],
        encoded,
        timeout,
        (),
    )


def _request_bound_unchecked(
    value: dict,
    *,
    archive_fd: int,
    archive_sha256: str,
    capability=None,
    local_origin: str | None = None,
    timeout: float = TIMEOUT,
) -> dict:
    """Run one bounded request in a worker loaded only from the bound archive.

    The descriptor is re-verified immediately before every spawn, and the child
    re-verifies it again before it reads the credential envelope or performs I/O.
    """
    try:
        from o8_admission import authorize_transport
    except ImportError as error:
        raise ValueError("O7 transport admission unavailable") from error
    authorize_transport(
        capability, binding=archive_fd, binding_digest=archive_sha256
    )
    timeout = _timeout(timeout)
    prepare(value, local_origin=local_origin)
    _verify_archive_fd(archive_fd, archive_sha256)
    encoded = _envelope(value, local_origin, timeout)
    _verify_archive_fd(archive_fd, archive_sha256)
    return _spawn(
        [sys.executable, "-I", "-S", "-B", f"/dev/fd/{archive_fd}", "--worker", archive_sha256],
        encoded,
        timeout,
        (archive_fd,),
    )


def request_bound(
    value: dict,
    *,
    archive_fd: int,
    archive_sha256: str,
    capability=None,
    local_origin: str | None = None,
    timeout: float = TIMEOUT,
) -> dict:
    """Run the production worker only through an admitted O7 capability."""
    try:
        from o8_admission import authorize_transport
    except ImportError as error:
        raise ValueError("O7 transport admission unavailable") from error
    authorize_transport(
        capability, binding=archive_fd, binding_digest=archive_sha256
    )
    return _request_bound_unchecked(
        value,
        archive_fd=archive_fd,
        archive_sha256=archive_sha256,
        capability=capability,
        local_origin=local_origin,
        timeout=timeout,
    )


def _worker(raw: bytes, *, allow_production: bool = False, verify=None) -> None:
    if len(raw) > INPUT_CAP:
        raise ValueError("wire input limit")
    envelope = json.loads(raw)
    value = envelope["value"]
    local_origin = envelope.get("localOrigin")
    if local_origin is None and not allow_production:
        raise ValueError("pathname worker is local only")
    args = prepare(value, local_origin=local_origin)
    deadline = time.monotonic() + _timeout(envelope["timeout"])
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("deadline exceeded before I/O")
    if verify is not None:
        verify()
    result = _exchange(
        args["url"], args["method"], args["data"], args["headers"], args["response_cap"], remaining
    )
    print(json.dumps(result, allow_nan=False), end="")


def _worker_main(expected_sha256: str) -> int:
    """Archive dispatcher entry: prove the loaded archive before any secret or I/O."""
    try:
        def verify():
            observed = _archive_origin()
            if observed is None or observed != _ARCHIVE or observed[1] != expected_sha256:
                raise ImportError("archive origin or digest differs")

        verify()
        raw = sys.stdin.buffer.read(INPUT_CAP + 1)
        verify()
        _worker(raw, allow_production=True, verify=verify)
    except Exception:  # noqa: BLE001 -- never echo worker input or diagnostics
        return 2
    return 0


if __name__ == "__main__":
    try:
        if sys.argv[1:] != ["--worker"]:
            raise ValueError("worker entrypoint only")
        _worker(sys.stdin.buffer.read(INPUT_CAP + 1))
    except Exception:  # noqa: BLE001 -- never echo worker input or diagnostics
        # Never echo input, credentials, or child diagnostics.
        sys.exit(2)
