"""Offline preparation and evidence primitives for O4; production admission is closed."""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
from pathlib import Path
from typing import Any

from query_in_compiler import validate_plan

_ROOT = Path(__file__).resolve().parents[3]
_PHASES = (
    ("oauth", 2),
    ("preflight", 4),
    ("observation", 6),
    ("recovery", 3),
    ("postflight", 4),
)
_RAW_LIMIT = 65536
_ROW_LIMIT = 8192
_ENVELOPE_LIMIT = 32768


def source_inputs() -> dict[str, str]:
    """Bind all case code and the compiler's imported policy inputs by source bytes."""
    files = [
        Path(__file__),
        Path(__file__).with_name("query_in_compiler.py"),
        Path(__file__).with_name("query_in_collector.py"),
        _ROOT / "tools/compat-broad/broad_contract.py",
        _ROOT / "spec/limits/firestore-standard-query-2026-08-25.json",
    ]
    return {
        str(path.relative_to(_ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in files
    }


def admission_status(plan: dict[str, Any]) -> dict[str, Any]:
    validate_plan(plan)

    def closed() -> None:
        raise PermissionError("O4 production admission is unavailable")

    return {
        "productionReady": False,
        "attemptCeiling": 19,
        "observationCeiling": 12,
        "recoveryReserve": 7,
        "blockers": [
            "gate-contract",
            "index-policy",
            "namespace-ownership",
            "cost-and-retention",
            "owner-permission",
        ],
        "admit": closed,
    }


def validate_permission(permission: Any) -> None:
    """No permission can presently satisfy the unimplemented live bindings."""
    if not isinstance(permission, dict):
        raise ValueError("O4 permission must be an object")  # noqa: TRY004 -- one closed admission error type.
    expiry = permission.get("expiresAt")
    if type(expiry) not in (int, float) or not math.isfinite(expiry):
        raise ValueError("finite expiry required")
    raise ValueError("O4 cost, index, scope and recovery bindings are unavailable")


class AttemptLedger:
    """An offline one-way reservation model for the exact nineteen attempt order."""

    def __init__(self) -> None:
        self._cursor = [0] * len(_PHASES)
        self._actual = 0
        self._pending: tuple[int, int] | None = None
        self._skips: list[dict[str, Any]] = []

    def reserve(self, phase: str, index: int) -> None:
        if self._pending is not None:
            raise ValueError("attempt already reserved")
        names = [name for name, _ in _PHASES]
        if phase not in names or type(index) is not int:
            raise ValueError("unknown attempt")
        slot = names.index(phase)
        if any(self._cursor[earlier] != _PHASES[earlier][1] for earlier in range(slot)):
            raise ValueError("earlier phase incomplete")
        if any(self._cursor[later] != 0 for later in range(slot + 1, len(_PHASES))):
            raise ValueError("phase already passed")
        if index != self._cursor[slot] or index >= _PHASES[slot][1]:
            raise ValueError("attempt cursor mismatch")
        self._pending = (slot, index)

    def commit(self) -> None:
        if self._pending is None:
            raise ValueError("no attempt reserved")
        slot, _ = self._pending
        self._cursor[slot] += 1
        self._actual += 1
        self._pending = None

    def skip(self, reason: str) -> None:
        if self._pending != (3, 1) or reason not in {
            "already-absent",
            "create-not-proven",
            "create-version-mismatch",
            "unsafe-delete",
        }:
            raise ValueError("only the conditional recovery delete may be skipped")
        self._skips.append({"phase": "recovery", "index": 1, "reason": reason})
        self._cursor[3] += 1
        self._pending = None

    def snapshot(self) -> dict[str, Any]:
        return {
            "cursor": self._cursor.copy(),
            "actualSends": self._actual,
            "reserved": self._pending is not None,
            "skips": copy.deepcopy(self._skips),
        }


class CompactJournal:
    """Bound the final publication independently of raw response sidecars."""

    def __init__(self) -> None:
        self._rows: list[dict[str, Any]] = []
        self._envelope: dict[str, Any] = {}

    @staticmethod
    def _encoded(value: Any) -> bytes:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")

    @property
    def rows(self) -> list[dict[str, Any]]:
        return copy.deepcopy(self._rows)

    @property
    def envelope(self) -> dict[str, Any]:
        return copy.deepcopy(self._envelope)

    def append(self, row: dict[str, Any]) -> None:
        if (
            len(self._rows) >= 9
            or not isinstance(row, dict)
            or len(self._encoded(row)) > _ROW_LIMIT
        ):
            raise ValueError("compact row capacity")
        self._rows.append(copy.deepcopy(row))

    def set_envelope(self, envelope: dict[str, Any]) -> None:
        if (
            not isinstance(envelope, dict)
            or len(self._encoded(envelope)) > _ENVELOPE_LIMIT
        ):
            raise ValueError("compact envelope capacity")
        self._envelope = copy.deepcopy(envelope)

    def encoded(self) -> bytes:
        result = self._encoded({"envelope": self._envelope, "rows": self._rows}) + b"\n"
        if len(result) > 131072:
            raise ValueError("final publication capacity")
        return result


class RawJournal:
    """Publish bounded immutable raw bytes and derive a hash-checked view."""

    def __init__(self, directory: Path) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=False, exist_ok=False)
        self._fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self._bindings: dict[str, dict[str, Any]] = {}

    def add(
        self,
        phase: str,
        index: int,
        status: int | None,
        body: bytes,
        *,
        complete: bool,
        content_type: str,
    ) -> dict[str, Any]:
        if (
            phase not in {"observation", "recovery"}
            or type(index) is not int
            or not 0 <= index < (6 if phase == "observation" else 3)
        ):
            raise ValueError("invalid raw sidecar slot")
        if (
            not isinstance(body, bytes)
            or len(body) > _RAW_LIMIT
            or type(complete) is not bool
            or not isinstance(content_type, str)
            or len(content_type) > 128
        ):
            raise ValueError("invalid bounded raw receipt")
        name = f"{phase}-{index:02d}.raw"
        fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=self._fd,
        )
        with os.fdopen(fd, "wb") as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(self._fd)
        binding = {
            "path": name,
            "byteCount": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
            "status": status,
            "complete": complete,
            "contentType": content_type,
        }
        self._bindings[name] = copy.deepcopy(binding)
        return binding

    def semantic_view(self, binding: dict[str, Any]) -> dict[str, Any]:
        path = binding.get("path")
        if not isinstance(path, str) or not any(
            path == f"{phase}-{index:02d}.raw"
            for phase, count in (("observation", 6), ("recovery", 3))
            for index in range(count)
        ):
            raise ValueError("unknown raw sidecar")
        if binding != self._bindings.get(path):
            raise ValueError("raw receipt metadata binding differs")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self._fd)
        with os.fdopen(fd, "rb") as stream:
            body = stream.read(_RAW_LIMIT + 1)
        actual = hashlib.sha256(body).hexdigest()
        if len(body) != binding.get("byteCount") or actual != binding.get("sha256"):
            raise ValueError("raw sidecar binding differs")
        if binding.get("complete") is not True:
            raise ValueError("incomplete raw response has no semantic view")
        result: dict[str, Any] = {
            "projectionVersion": 1,
            "sourceRawSha256": actual,
        }
        if path != "observation-02.raw":
            result["difference"] = "not-positive-query-slot"
            return result
        if binding.get("status") != 200:
            result["difference"] = "unexpected-query-status"
            return result
        if (
            binding.get("contentType", "").split(";", 1)[0].strip().lower()
            != "application/json"
        ):
            result["difference"] = "unexpected-query-content-type"
            return result
        try:
            parsed = json.loads(body)
        except (UnicodeError, json.JSONDecodeError):
            result["difference"] = "malformed-query-json"
            return result
        if not isinstance(parsed, list):
            result["difference"] = "unexpected-query-shape"
            return result
        documents = []
        for row in parsed:
            if (
                not isinstance(row, dict)
                or (
                    set(row) - {"document", "readTime", "skippedResults", "transaction"}
                )
                or not isinstance(row.get("document"), dict)
            ):
                result["difference"] = "unexpected-query-row"
                return result
            document = row["document"]
            if not isinstance(document.get("name"), str) or not isinstance(
                document.get("fields"), dict
            ):
                result["difference"] = "unexpected-query-row"
                return result
            documents.append({"name": document["name"], "fields": document["fields"]})
        result["documents"] = documents
        return result

    def close(self) -> None:
        os.close(self._fd)
