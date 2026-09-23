"""Unobserved production inputs for one bounded FS-DATA-WRITE sandbox run."""

from __future__ import annotations

import json
from typing import Any

PROJECT = "fireemu-oracle-sbx"
DOCS = f"projects/{PROJECT}/databases/(default)/documents"
COMMIT = f"/v1/{DOCS}:commit"
BATCH_WRITE = f"/v1/{DOCS}:batchWrite"
BATCH_GET = f"/v1/{DOCS}:batchGet"


def name_of_length(target: int, tag: str) -> str:
    """Build an even-segment relative document name of exact UTF-8 length."""
    for pairs in range(1, 12):
        slash_bytes = 2 * pairs - 1
        fixed_collection_bytes = pairs
        document_bytes = target - slash_bytes - fixed_collection_bytes
        if not pairs <= document_bytes <= pairs * 1500:
            continue
        lengths = [document_bytes // pairs + (index < document_bytes % pairs) for index in range(pairs)]
        segments: list[str] = []
        for index, length in enumerate(lengths):
            segments.extend(("c", (tag if index == 0 else "d")[:length].ljust(length, "d")))
        name = "/".join(segments)
        if len(name.encode()) == target:
            return name
    raise ValueError(f"cannot form document name of {target} bytes")


def index_sum_name_of_length(target: int, tag: str) -> str:
    """Reproduce the exact two-segment names used by the exploratory sum probe."""
    layout = {1000: (998, 1), 2000: (1400, 599)}
    if target not in layout:
        raise ValueError(f"unsupported index-sum name length: {target}")
    collection_bytes, document_bytes = layout[target]
    return f"{tag[:collection_bytes].ljust(collection_bytes, 'c')}/{'d' * document_bytes}"


def _readback(names: list[str]) -> dict[str, Any]:
    return {"id": "readback", "method": "POST", "path": BATCH_GET, "body": {"documents": names}}


def _commit_program(program_id: str, writes: list[dict[str, Any]], names: list[str], body: str | None = None) -> dict[str, Any]:
    return {
        "id": program_id,
        "area": "writes",
        "steps": [
            {"id": "write", "method": "POST", "path": COMMIT, "body": body if body is not None else {"writes": writes}},
            _readback(names),
        ],
    }


def _update(name: str, value: str = "1") -> dict[str, Any]:
    return {"update": {"name": name, "fields": {"v": {"integerValue": value}}}}


def _field_update(name: str, fields: dict[str, Any]) -> dict[str, Any]:
    return {"update": {"name": name, "fields": fields}}


def _raw_request_program(size: int) -> dict[str, Any]:
    name = f"{DOCS}/raw11/{size}"
    payload = json.dumps({"writes": [_update(name)]}, separators=(",", ":"))
    if len(payload) > size:
        raise ValueError("raw request target smaller than JSON body")
    payload = payload[:-1] + " " * (size - len(payload)) + "}"
    return _commit_program(f"writes/limits/raw-11mib/{size}", [_update(name)], [name], payload)


def _batch_variant(variant: str) -> dict[str, Any]:
    prefix = f"{DOCS}/batchInvalid"
    names = [f"{prefix}/{variant}-{suffix}" for suffix in ("first", "middle", "last")]
    middle = _update(names[1])
    if variant == "no-operation":
        middle = {"currentDocument": {"exists": False}}
    elif variant == "collection-name":
        middle["update"]["name"] = f"{DOCS}/batchInvalid"
    elif variant == "empty-field-name":
        middle["update"]["fields"] = {"": {"integerValue": "1"}}
    elif variant == "reserved-field-name":
        middle["update"]["fields"] = {"__bad__": {"integerValue": "1"}}
    elif variant == "bad-mask-path":
        middle["updateMask"] = {"fieldPaths": ["a..b"]}
    elif variant == "bad-integer":
        middle["update"]["fields"] = {"v": {"integerValue": "not-a-number"}}
    elif variant == "unknown-value-kind":
        middle["update"]["fields"] = {"v": {"fooValue": 1}}
    elif variant == "bad-timestamp":
        middle["update"]["fields"] = {"v": {"timestampValue": "yesterday"}}
    elif variant == "exists-precondition-fails":
        middle["currentDocument"] = {"exists": True}
    else:
        raise ValueError(f"unknown batch variant: {variant}")
    return {
        "id": f"writes/batch-write-malformed/{variant}",
        "area": "writes",
        "steps": [
            {"id": "batch-write", "method": "POST", "path": BATCH_WRITE, "body": {"writes": [_update(names[0]), middle, _update(names[2])]}},
            _readback(names),
        ],
    }


def build_programs() -> list[dict[str, Any]]:
    programs = [_raw_request_program(size) for size in (11_534_336, 11_534_337)]
    programs.extend(
        _batch_variant(variant)
        for variant in (
            "no-operation", "collection-name", "empty-field-name", "reserved-field-name",
            "bad-mask-path", "bad-integer", "unknown-value-kind", "bad-timestamp",
            "exists-precondition-fails",
        )
    )
    for length in (2642, 2643):
        name = f"{DOCS}/{name_of_length(length, f'n{length}')}"
        write = _field_update(name, {"s": {"stringValue": "x" * 1500}})
        programs.append(_commit_program(f"writes/limits/index-entry-string-name/{length}", [write], [name]))
    for length in (4621, 4622, 6127, 6128):
        name = f"{DOCS}/{name_of_length(length, f'n{length}')}"
        programs.append(_commit_program(f"writes/limits/empty-document-name/{length}", [_field_update(name, {})], [name]))
    for length, count in ((2000, 9549), (2000, 9550), (1000, 19998), (1000, 19999)):
        name = f"{DOCS}/{index_sum_name_of_length(length, f'g{length}')}"
        values = [{"integerValue": str(index)} for index in range(count)]
        write = _field_update(name, {"a": {"arrayValue": {"values": values}}})
        programs.append(_commit_program(f"writes/limits/index-entry-sum/{length}-{count}", [write], [name]))
    names = [f"{DOCS}/decoded11/item{index}" for index in range(11)]
    writes = [_field_update(name, {"s": {"stringValue": "x" * 1_040_000}}) for name in names]
    programs.append(_commit_program("writes/limits/decoded-11x1040000", writes, names))
    return programs
