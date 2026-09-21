"""Offline comparator for two retained partition/cursor bundles.

Each side is validated against a plan recompiled from its own recorded identity,
so a production run and a local run with different nonces can still be compared.
Only the compiled owned identities, opaque pagination tokens and server-assigned
timestamps are canonicalized; Firestore Value types, query shapes, document order
and typed error objects stay exact. The result is semantic only and never marks
acquisition validated or a promotion ready.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import stat
from pathlib import Path
from typing import Any

from partition_cursor_case import CAMPAIGN, compile_plan
from partition_cursor_wire import MAX_RAW_BYTES, decode_response, same_json

TIMESTAMP_KEYS = frozenset({"createTime", "updateTime", "readTime", "commitTime"})
TOKEN_KEYS = frozenset({"pageToken", "nextPageToken"})
RESPONSE_DERIVED_SKIPS = frozenset(
    {
        "no-page-token",
        "range-not-required",
        "reconstruction-slots-exceeded",
        "no-partition-response",
        "malformed-partition-cursor",
    }
)
_DISPATCHED = frozenset({"pass", "mismatch"})


def _json_tree(value: Any, active: set[int] | None = None, depth: int = 0) -> bool:
    """Reject non-JSON and cyclic caller input before canonicalization."""
    kind = type(value)
    if depth > 128:
        return False
    if kind is int:
        return value.bit_length() <= 4096
    if kind in (str, bool) or value is None:
        return True
    if kind is float:
        return math.isfinite(value)
    if kind not in (dict, list):
        return False
    active = set() if active is None else active
    if id(value) in active:
        return False
    active.add(id(value))
    try:
        if kind is dict and any(type(key) is not str for key in value):
            return False
        return all(_json_tree(item, active, depth + 1)
                   for item in (value.values() if kind is dict else value))
    finally:
        active.remove(id(value))


def _retention_fault(bundle: dict[str, Any]) -> str | None:
    """Refuse a side whose rows are not covered by retained wire bytes."""
    raw = bundle.get("raw")
    dispatched = [
        row
        for row in bundle["rows"] + bundle["cleanup"]["rows"]
        if isinstance(row, dict) and row.get("status") != "skipped"
    ]
    if not isinstance(raw, dict) or not dispatched:
        return "unbound-retention"
    if (raw.get("complete") is not True or type(raw.get("bindings")) is not int
            or raw.get("bindings") != len(dispatched)):
        return "raw-bindings-below-dispatched-rows"
    if any(type(row.get("raw")) is not dict or row["raw"].get("present") is not True for row in dispatched):
        return "unretained-dispatched-row"
    return None


def _production_claim_fault(bundle: dict[str, Any]) -> str | None:
    """A bundle collected from the local artifact can never claim production."""
    if type(bundle.get("productionExecuted")) is not bool:
        return "invalid-production-flag"
    if (
        bundle.get("productionExecuted") is True
        and bundle.get("target") == "owned-local-artifact"
    ):
        return "local-artifact-claims-production"
    return None


def _private_directory(path: str | Path, *, dir_fd: int | None = None) -> int:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)
    info = os.fstat(fd)
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        os.close(fd)
        raise ValueError("private evidence directory required")
    return fd


def _signature(info: os.stat_result) -> tuple:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_nlink, info.st_mode, info.st_uid)


def _read_sidecar(raw_fd: int, name: str, count: int) -> bytes:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=raw_fd)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or before.st_nlink != 1 or before.st_mode & 0o077
                or not 0 < count <= MAX_RAW_BYTES or before.st_size != count):
            raise ValueError("invalid evidence file")
        data = bytearray()
        while len(data) <= MAX_RAW_BYTES:
            chunk = os.read(fd, min(8192, MAX_RAW_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(fd)
        named = os.stat(name, dir_fd=raw_fd, follow_symlinks=False)
        if (_signature(before) != _signature(after)
                or _signature(after) != _signature(named) or len(data) != count):
            raise ValueError("evidence changed while reading")
        return bytes(data)
    finally:
        os.close(fd)


def verify_retained_bytes(bundle: dict[str, Any], directory: str | Path) -> list[str]:
    """Rebind bounded, private regular sidecars to exact slots and typed JSON.

    No absolute paths, parent traversal, links, FIFO reads or lenient JSON.
    Holding directory descriptors prevents a later pathname swap redirecting reads.
    This is a read-only integrity check, never cleanup authority.
    """
    plan = _plan_for(bundle)
    if plan is None:
        return ["invalid-bundle"]
    faults: list[str] = []
    root_fd = raw_fd = None
    try:
        root_fd = _private_directory(directory)
        raw_fd = _private_directory("raw", dir_fd=root_fd)
        for row in bundle["rows"] + bundle["cleanup"]["rows"]:
            binding = row.get("raw")
            if row.get("status") == "skipped":
                continue
            label = f"{row['phase']}-{row['index']}"
            expected_name = f"{row['phase']}-{row['index']:02d}.raw"
            receipt = row.get("receipt")
            if (type(binding) is not dict or binding.get("present") is not True
                    or binding.get("path") != expected_name
                    or type(binding.get("byteCount")) is not int
                    or type(receipt) is not dict
                    or type(receipt.get("byteCount")) is not int
                    or binding["byteCount"] != receipt["byteCount"]):
                faults.append(label + ":invalid-binding")
                continue
            try:
                payload = _read_sidecar(raw_fd, expected_name, binding["byteCount"])
                if hashlib.sha256(payload).hexdigest() != binding.get("sha256"):
                    faults.append(label + ":digest")
                    continue
                decoded = decode_response(payload)
                if not same_json(decoded, receipt.get("body")):
                    faults.append(label + ":body-differs-from-bytes")
            except OSError:
                faults.append(label + ":unreadable")
            except (ValueError, TypeError, UnicodeError, RecursionError):
                faults.append(label + ":unusable-sidecar")
        if _signature(os.fstat(raw_fd)) != _signature(os.stat("raw", dir_fd=root_fd, follow_symlinks=False)):
            faults.append("raw-directory-replaced")
    except (OSError, ValueError, TypeError):
        faults.append("unavailable-private-evidence-directory")
    finally:
        if raw_fd is not None:
            os.close(raw_fd)
        if root_fd is not None:
            os.close(root_fd)
    return faults


def _plan_for(bundle: Any) -> dict[str, Any] | None:
    if type(bundle) is not dict or not _json_tree(bundle) or bundle.get("campaignId") != CAMPAIGN:
        return None
    try:
        plan = compile_plan(
            bundle.get("project"), bundle.get("database"), bundle.get("nonce")
        )
    except (TypeError, ValueError):
        return None
    if (
        plan["planDigest"] != bundle.get("planDigest")
        or plan["ownedScope"] != bundle.get("ownedScope")
        or plan["groupCollection"] != bundle.get("groupCollection")
    ):
        return None
    cleanup = bundle.get("cleanup")
    if (
        not isinstance(bundle.get("rows"), list)
        or len(bundle["rows"]) != len(plan["observation"])
        or not isinstance(cleanup, dict)
        or not isinstance(cleanup.get("rows"), list)
        or len(cleanup["rows"]) != len(plan["recovery"])
    ):
        return None
    for phase, rows in (("observation", bundle["rows"]), ("recovery", cleanup["rows"])):
        for index, (row, slot) in enumerate(zip(rows, plan[phase])):
            if (type(row) is not dict or row.get("phase") != phase
                    or type(row.get("index")) is not int or row["index"] != index
                    or row.get("kind") != slot["kind"]
                    or type(row.get("status")) is not str
                    or ("skipReason" in row and row["skipReason"] is not None
                        and type(row["skipReason"]) is not str)):
                return None
    return plan


def _canonical(value: Any, plan: dict[str, Any], key: str = "") -> Any:
    if isinstance(value, dict):
        return {
            name: _canonical(item, plan, name) for name, item in sorted(value.items())
        }
    if isinstance(value, list):
        return [_canonical(item, plan) for item in value]
    if isinstance(value, str):
        if key in TIMESTAMP_KEYS:
            # No compiled case in this set asserts a time relation. A future case
            # that does must compare these values exactly instead.
            return "<timestamp>"
        if key in TOKEN_KEYS:
            return "<token>"
        return (
            value.replace(plan["ownedScope"], "<scope>")
            .replace(plan["groupCollection"], "<group>")
            .replace(plan["databaseRoot"], "<database>")
        )
    return value


def _comparable(row: dict[str, Any]) -> dict[str, Any]:
    """Keep the semantic receipt members; byte counts and content-type parameters
    differ between a production endpoint and a local artifact by construction."""
    receipt = row.get("receipt")
    if not isinstance(receipt, dict):
        return {"request": row.get("request"), "receipt": receipt}
    media = receipt.get("contentType")
    return {
        "request": row.get("request"),
        "receipt": {
            "status": receipt.get("status"),
            "complete": receipt.get("complete"),
            "contentType": media.split(";")[0].strip().lower()
            if isinstance(media, str)
            else media,
            "body": receipt.get("body"),
        },
    }


def _row_pair(
    left: Any, right: Any, left_plan: dict[str, Any], right_plan: dict[str, Any]
) -> tuple[str, bool]:
    """Classify one slot as equivalent, mismatching or indeterminate."""
    if not isinstance(left, dict) or not isinstance(right, dict):
        return "INDETERMINATE", False
    if left.get("kind") != right.get("kind"):
        return "INDETERMINATE", False
    states = (left.get("status"), right.get("status"))
    if any(state not in _DISPATCHED and state != "skipped" for state in states):
        return "INDETERMINATE", False
    if states == ("skipped", "skipped"):
        if left.get("skipReason") == right.get("skipReason"):
            return "EQUIVALENT", False
        reasons = {left.get("skipReason"), right.get("skipReason")}
        return (
            "SEMANTIC_MISMATCH"
            if reasons <= RESPONSE_DERIVED_SKIPS
            else "INDETERMINATE"
        ), False
    if "skipped" in states:
        reason = left.get("skipReason") or right.get("skipReason")
        return (
            "SEMANTIC_MISMATCH" if reason in RESPONSE_DERIVED_SKIPS else "INDETERMINATE"
        ), False
    comparable_left, comparable_right = _comparable(left), _comparable(right)
    if not same_json(_canonical(comparable_left, left_plan), _canonical(
        comparable_right, right_plan
    )):
        return "SEMANTIC_MISMATCH", False
    return "EQUIVALENT", not same_json(comparable_left, comparable_right)


def _indeterminate(reason: str) -> dict[str, Any]:
    return {
        "kind": "fs-query-partition-cursor-comparison-v1",
        "campaignId": CAMPAIGN,
        "classification": "INDETERMINATE",
        "reason": reason,
        "rows": 0,
        "nondeterministic": 0,
        "differences": [],
        "acquisitionValidated": False,
        "promotionReady": False,
        "productionExecuted": False,
        "retainedBytesVerified": False,
    }


def compare_evidence(
    production: Any,
    local: Any,
    *,
    production_directory: str | Path | None = None,
    local_directory: str | Path | None = None,
) -> dict[str, Any]:
    """Compare two retained bundles; the result is semantic evidence only.

    When a retained directory is supplied for a side, every dispatched row is
    re-bound to its sidecar bytes before any row is compared.
    """
    production_plan, local_plan = _plan_for(production), _plan_for(local)
    if production_plan is None or local_plan is None:
        return _indeterminate("unbound-bundle")
    for side in (production, local):
        fault = _retention_fault(side) or _production_claim_fault(side)
        if fault:
            return _indeterminate(fault)
    for side, directory in (
        (production, production_directory),
        (local, local_directory),
    ):
        if directory is not None and verify_retained_bytes(side, directory):
            return _indeterminate("retained-bytes-disagree-with-receipt")
    executed = any(
        side.get("productionExecuted") is True for side in (production, local)
    )
    differences: list[dict[str, Any]] = []
    nondeterministic = 0
    indeterminate = False
    compared = 0
    pairs = list(zip(production["rows"], local["rows"])) + list(
        zip(production["cleanup"]["rows"], local["cleanup"]["rows"])
    )
    for left, right in pairs:
        verdict, verbatim = _row_pair(left, right, production_plan, local_plan)
        compared += 1
        nondeterministic += int(verbatim)
        if verdict == "EQUIVALENT":
            continue
        indeterminate = indeterminate or verdict == "INDETERMINATE"
        differences.append(
            {
                "phase": left.get("phase") if isinstance(left, dict) else None,
                "index": left.get("index") if isinstance(left, dict) else None,
                "kind": left.get("kind") if isinstance(left, dict) else None,
                "classification": verdict,
            }
        )
    if indeterminate:
        classification = "INDETERMINATE"
    elif differences:
        classification = "SEMANTIC_MISMATCH"
    else:
        classification = "EQUIVALENT"
    return {
        "kind": "fs-query-partition-cursor-comparison-v1",
        "campaignId": CAMPAIGN,
        "classification": classification,
        "reason": None,
        "rows": compared,
        "nondeterministic": nondeterministic,
        "differences": copy.deepcopy(differences),
        "acquisitionValidated": False,
        "promotionReady": False,
        "productionExecuted": executed,
        "retainedBytesVerified": production_directory is not None and local_directory is not None,
    }
