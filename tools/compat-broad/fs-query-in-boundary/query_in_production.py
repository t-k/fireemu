"""Offline preparation and evidence primitives for O4; production admission is closed."""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import math
import os
import re
from datetime import datetime
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
_TIMESTAMP = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$")
_INTEGER = re.compile(r"^(?:0|-?[1-9][0-9]*)$")
_PROJECT = re.compile(r"^[A-Za-z0-9_-]+$")
_RESERVED_FIELD = re.compile(r"^__.*__$")
_MAX_VALUE_DEPTH = 20
_MAX_VALUE_NODES = 1024


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant: {value}")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _typed_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def _utf8_length(value: Any) -> int | None:
    if not isinstance(value, str):
        return None
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError:
        return None


def _field_name(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and (length := _utf8_length(value)) is not None
        and length <= 1500
        and _RESERVED_FIELD.fullmatch(value) is None
    )


def _document_name(value: Any) -> bool:
    if _utf8_length(value) is None:
        return False
    parts = value.split("/")
    return (
        len(parts) >= 7
        and len(parts) % 2 == 1
        and parts[0] == "projects"
        and _PROJECT.fullmatch(parts[1]) is not None
        and parts[2] == "databases"
        and (parts[3] == "(default)" or _PROJECT.fullmatch(parts[3]) is not None)
        and parts[4] == "documents"
        and all(
            part not in {"", ".", ".."}
            and (length := _utf8_length(part)) is not None
            and length <= 1500
            for part in parts[5:]
        )
    )


def _fields(value: Any, depth: int, budget: list[int]) -> bool:
    return isinstance(value, dict) and all(
        _field_name(name) and _firestore_value(item, depth + 1, budget)
        for name, item in value.items()
    )


def _finite_number(value: Any) -> bool:
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(float(value))
    except OverflowError:
        return False


def _firestore_value(value: Any, depth: int, budget: list[int]) -> bool:
    budget[0] -= 1
    if (
        depth > _MAX_VALUE_DEPTH
        or budget[0] < 0
        or not isinstance(value, dict)
        or len(value) != 1
    ):
        return False
    kind, item = next(iter(value.items()))
    if kind == "nullValue":
        return item == "NULL_VALUE"
    if kind == "booleanValue":
        return type(item) is bool
    if kind == "integerValue":
        return (
            isinstance(item, str)
            and len(item) <= 20
            and _INTEGER.fullmatch(item) is not None
            and -(2**63) <= int(item) < 2**63
        )
    if kind == "doubleValue":
        return _finite_number(item) or (
            isinstance(item, str) and item in {"NaN", "Infinity", "-Infinity"}
        )
    if kind == "timestampValue":
        return _typed_timestamp(item)
    if kind == "stringValue":
        return _utf8_length(item) is not None
    if kind == "bytesValue":
        if not isinstance(item, str):
            return False
        try:
            return (
                base64.b64encode(base64.b64decode(item, validate=True)).decode("ascii")
                == item
            )
        except (ValueError, binascii.Error):
            return False
    if kind == "referenceValue":
        return _document_name(item)
    if kind == "geoPointValue":
        return (
            isinstance(item, dict)
            and set(item) == {"latitude", "longitude"}
            and all(_finite_number(item[key]) for key in ("latitude", "longitude"))
            and -90 <= item["latitude"] <= 90
            and -180 <= item["longitude"] <= 180
        )
    if kind == "arrayValue":
        return (
            isinstance(item, dict)
            and set(item) <= {"values"}
            and isinstance(item.get("values", []), list)
            and all(
                isinstance(child, dict)
                and "arrayValue" not in child
                and _firestore_value(child, depth + 1, budget)
                for child in item.get("values", [])
            )
        )
    if kind == "mapValue":
        return (
            isinstance(item, dict)
            and set(item) <= {"fields"}
            and _fields(item.get("fields", {}), depth + 1, budget)
        )
    return False


def _typed_query_row(row: Any) -> bool:
    # The compiled query requests neither a transaction nor result skipping.
    # RunQuery may still emit a typed terminal row, or a readTime-only row for
    # an empty result.  Preserve those protocol markers instead of treating
    # them as malformed documents.
    if not isinstance(row, dict) or set(row) - {"document", "readTime", "done"}:
        return False
    if "done" in row and row["done"] is not True:
        return False
    if "readTime" in row and not _typed_timestamp(row["readTime"]):
        return False
    if "document" not in row:
        # A readTime-only response is the valid empty-result representation;
        # a terminal row may also contain no document.
        return "readTime" in row or "done" in row
    document = row["document"]
    if not isinstance(document, dict) or set(document) - {
        "name",
        "fields",
        "createTime",
        "updateTime",
    }:
        return False
    if not _document_name(document.get("name")) or not _fields(
        document.get("fields"), 0, [_MAX_VALUE_NODES]
    ):
        return False
    return not any(
        key in document and not _typed_timestamp(document[key])
        for key in ("createTime", "updateTime")
    )


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
        self._closed = False
        self._manifest_loaded = False

    @classmethod
    def reload(cls, directory: Path) -> RawJournal:
        """Reload an already published journal without trusting its directory listing."""
        self = cls.__new__(cls)
        self.directory = Path(directory)
        self._fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self._closed = False
        self._manifest_loaded = True
        try:
            manifest_fd = os.open("manifest.json", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self._fd)
        except BaseException:
            os.close(self._fd)
            raise
        try:
            with os.fdopen(manifest_fd, "rb") as stream:
                encoded = stream.read(_ENVELOPE_LIMIT + 1)
                if len(encoded) > _ENVELOPE_LIMIT:
                    raise ValueError("raw journal manifest capacity")
                manifest = json.loads(encoded, object_pairs_hook=_unique_json_object)
        except BaseException:
            os.close(self._fd)
            raise
        if not isinstance(manifest, dict) or type(manifest.get("version")) is not int or manifest["version"] != 1:
            os.close(self._fd)
            raise ValueError("invalid raw journal manifest")
        bindings = manifest.get("bindings")
        if not isinstance(bindings, list) or len(bindings) > 9:
            os.close(self._fd)
            raise ValueError("invalid raw journal manifest")
        self._bindings = {}
        for binding in bindings:
            if not isinstance(binding, dict):
                os.close(self._fd)
                raise TypeError("invalid raw journal binding")
            phase = binding.get("phase")
            index = binding.get("index")
            path = binding.get("path")
            expected_path = (
                f"{phase}-{index:02d}.raw"
                if phase in {"observation", "recovery"} and type(index) is int
                else None
            )
            limit = 6 if phase == "observation" else 3
            if (
                expected_path is None
                or index < 0
                or index >= limit
                or path != expected_path
                or path in self._bindings
                or set(binding) != {"phase", "index", "path", "byteCount", "sha256", "status", "complete", "contentType"}
                or type(binding.get("byteCount")) is not int
                or not 0 <= binding["byteCount"] <= _RAW_LIMIT
                or not isinstance(binding.get("sha256"), str)
                or re.fullmatch(r"[0-9a-f]{64}", binding["sha256"]) is None
                or (binding.get("status") is not None and (type(binding["status"]) is not int or not 100 <= binding["status"] <= 599))
                or type(binding.get("complete")) is not bool
                or (binding["complete"] and binding["status"] is None)
                or not isinstance(binding.get("contentType"), str)
                or len(binding["contentType"]) > 128
            ):
                os.close(self._fd)
                raise ValueError("invalid raw journal binding")
            self._bindings[path] = copy.deepcopy(binding)
        return self

    def _write_manifest(self) -> None:
        manifest = {"version": 1, "bindings": list(self._bindings.values())}
        encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        if len(encoded) > _ENVELOPE_LIMIT:
            raise ValueError("raw journal manifest capacity")
        fd = os.open("manifest.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self._fd)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(encoded)
                stream.write(b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(self._fd)
        except BaseException:
            try:
                os.unlink("manifest.json", dir_fd=self._fd)
            except FileNotFoundError:
                pass
            raise

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
        if self._manifest_loaded:
            raise ValueError("reloaded raw journal is immutable")
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
        if (
            status is not None and (type(status) is not int or not 100 <= status <= 599)
        ) or (complete and status is None):
            raise ValueError("typed HTTP status required")
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
            "phase": phase,
            "index": index,
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
        if type(binding.get("status")) is not int or binding["status"] != 200:
            result["difference"] = "unexpected-query-status"
            return result
        if (
            binding.get("contentType", "").split(";", 1)[0].strip().lower()
            != "application/json"
        ):
            result["difference"] = "unexpected-query-content-type"
            return result
        try:
            parsed = json.loads(
                body,
                parse_constant=_reject_json_constant,
                object_pairs_hook=_unique_json_object,
            )
        except (UnicodeError, ValueError, RecursionError):
            result["difference"] = "malformed-query-json"
            return result
        if not isinstance(parsed, list):
            result["difference"] = "unexpected-query-shape"
            return result
        if not parsed:
            # RunQuery represents an empty result with a typed readTime row.
            # An empty JSON array has no protocol-bound response evidence.
            result["difference"] = "unexpected-query-row"
            return result
        documents = []
        terminal_seen = False
        for index, row in enumerate(parsed):
            if not _typed_query_row(row):
                result["difference"] = "unexpected-query-row"
                return result
            if terminal_seen:
                result["difference"] = "unexpected-query-row"
                return result
            if row.get("done") is True:
                if index != len(parsed) - 1:
                    result["difference"] = "unexpected-query-row"
                    return result
                terminal_seen = True
            document = row.get("document")
            if document is not None:
                documents.append({"name": document["name"], "fields": document["fields"]})
        result["documents"] = documents
        return result

    def close(self) -> None:
        if not self._closed:
            try:
                if not self._manifest_loaded:
                    self._write_manifest()
            finally:
                os.close(self._fd)
                self._closed = True
