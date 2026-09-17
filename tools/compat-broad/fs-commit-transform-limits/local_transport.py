"""Closed O3 loopback adapter over the existing bounded HTTP worker."""

from __future__ import annotations

import copy
import fcntl
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
import types
import zipimport
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import quote

from local_collector import normalize_receipt, owned, typed_not_found
from transform_comparator import _exact, _validate_plan

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from broad_contract import local_origin

TRANSPORT = HERE.parent / "fs-write-limits/transport.py"


def _archive_origin() -> tuple[str, str] | None:
    match = re.fullmatch(r"(/dev/fd/([0-9]+))/local_transport\.py", __file__)
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
    _spec = importlib.util.spec_from_file_location("o3_shared_bounded_transport", TRANSPORT)
    if _spec is None or _spec.loader is None:
        raise ImportError("bounded transport unavailable")
    _transport = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_transport)
else:
    _archive, _ = _ARCHIVE
    _importer = zipimport.zipimporter(_archive)
    _code = _importer.get_code("transport")
    _origin = f"{_archive}/transport.py"
    if _code is None or _code.co_filename != _origin or _archive_origin() != _ARCHIVE:
        raise ImportError("bounded transport archive member unavailable")
    TRANSPORT = Path(_origin)
    _transport = types.ModuleType("o3_shared_bounded_transport")
    _transport.__file__ = _origin
    _transport.__loader__ = _importer
    exec(_code, _transport.__dict__)  # noqa: S102 -- exact member of the verified inherited archive
    if _archive_origin() != _ARCHIVE:
        raise ImportError("bounded transport archive digest changed")
REQUEST_CAP = 64 * 1024
RESPONSE_CAP = 256 * 1024


def save_new(path: Path, value: Any) -> None:
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def local_executor(plan: dict, origin: str, output: Path, binding: str) -> Callable:
    """Only this compiled campaign, once, in order, on numeric loopback."""
    _validate_plan(plan)
    local_origin(origin)
    if not isinstance(binding, str) or re.fullmatch(r"[0-9a-f]{64}", binding) is None:
        raise ValueError("invalid execution binding")
    plan = copy.deepcopy(plan)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    observation_index = 0
    recovery_index = 0
    recovery_started = False
    sent = 0
    attempted: set[str] = set()
    preflight: set[str] = set()
    ownership: set[str] = set()
    prior: dict[str, Any] = {}

    def execute(operation: dict[str, Any]) -> dict[str, Any]:
        nonlocal observation_index, recovery_index, recovery_started, sent, prior
        operation = copy.deepcopy(operation)
        is_recovery = operation.get("kind", "").startswith("cleanup-")
        if sent >= 17 or recovery_started and not is_recovery:
            raise ValueError("closed campaign budget or phase binding")
        if is_recovery:
            recovery_started = True
            if recovery_index >= 6:
                raise ValueError("closed recovery budget")
            expected = copy.deepcopy(plan["recovery"][recovery_index])
            resource = expected["resource"]
            if expected["kind"] == "cleanup-conditional-delete":
                eligible = resource in attempted and owned(prior, resource)
                if operation.get("kind") == "cleanup-verify-absence" and not eligible:
                    recovery_index += 1
                    expected = copy.deepcopy(plan["recovery"][recovery_index])
                elif eligible:
                    expected["path"] += "?currentDocument.updateTime=" + quote(
                        prior["body"]["updateTime"], safe=""
                    )
                else:
                    raise ValueError("cleanup ownership binding")
            phase, index = "cleanup", recovery_index
        else:
            if observation_index >= 11:
                raise ValueError("closed observation budget")
            expected = plan["observation"][observation_index]
            phase, index = "rows", observation_index
        if not _exact(operation, expected):
            raise ValueError("raw compiled request binding")
        if operation["kind"] == "create-only-patch":
            if preflight != set(plan["ownedResources"]):
                raise ValueError("both preflight absences required")
            attempted.add(operation["resource"])
        if (
            operation["kind"] == "commit-transform"
            and operation["resources"][0] not in ownership
        ):
            raise ValueError("commit ownership binding")
        context = {
            "sequence": sent,
            "phase": phase,
            "index": index,
            "binding": binding,
            "planDigest": plan["planDigest"],
        }
        save_new(output / f"{sent:03d}-request.json", {**context, "request": operation})
        # Count before I/O: an interrupted request cannot be retried by this adapter.
        sent += 1
        if is_recovery:
            recovery_index += 1
        else:
            observation_index += 1
        try:
            receipt = _transport.request(
                origin,
                operation,
                request_byte_limit=REQUEST_CAP,
                response_byte_limit=RESPONSE_CAP,
                timeout=12,
            )
        except Exception as error:  # noqa: BLE001 -- persist an ambiguous wire failure for recovery.
            receipt = {"complete": False, "failure": f"wire:{type(error).__name__}"}
        save_new(
            output / f"{sent - 1:03d}-receipt.json", {**context, "receipt": receipt}
        )
        prior = normalize_receipt(receipt)
        kind = operation["kind"]
        if kind == "preflight-typed-absence" and typed_not_found(prior):
            preflight.add(operation["resource"])
        if kind in {"create-only-patch", "baseline-readback"}:
            resource = operation["resource"]
            if owned(prior, resource):
                ownership.add(resource)
            else:
                ownership.discard(resource)
        return receipt

    return execute


def verify_wire_journal(plan: dict, result: dict, output: Path, binding: str) -> int:
    """Bind each actually dispatched row to its immutable raw wire receipt."""
    _validate_plan(plan)
    sequence = 0
    for phase in ("rows", "cleanup"):
        for row in result[phase]:
            if row.get("skipped"):
                continue
            context = {
                "sequence": sequence,
                "phase": phase,
                "index": row["index"],
                "binding": binding,
                "planDigest": plan["planDigest"],
            }
            request = json.loads((output / f"{sequence:03d}-request.json").read_bytes())
            receipt = json.loads((output / f"{sequence:03d}-receipt.json").read_bytes())
            if not _exact(request, {**context, "request": row["request"]}):
                raise ValueError("wire request binding differs")
            if not _exact(
                {key: value for key, value in receipt.items() if key != "receipt"},
                context,
            ):
                raise ValueError("wire receipt provenance differs")
            observed = {
                key: value
                for key, value in row.items()
                if key not in {"index", "request", "absent"}
            }
            if not _exact(observed, normalize_receipt(receipt["receipt"])):
                raise ValueError("wire receipt differs from collected row")
            sequence += 1
    if sequence > 17 or len(list(output.iterdir())) != sequence * 2:
        raise ValueError("wire journal count differs")
    return sequence
