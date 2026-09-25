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
        lengths = [
            document_bytes // pairs + (index < document_bytes % pairs)
            for index in range(pairs)
        ]
        segments: list[str] = []
        for index, length in enumerate(lengths):
            segments.extend(
                ("c", (tag if index == 0 else "d")[:length].ljust(length, "d"))
            )
        name = "/".join(segments)
        if len(name.encode()) == target:
            return name
    raise ValueError(f"cannot form document name of {target} bytes")


def index_sum_name_of_length(target: int, tag: str) -> str:
    """Reproduce the exact two-segment names used by the exploratory sum probe."""
    layout = {500: (498, 1), 1000: (998, 1), 2000: (1400, 599)}
    if target not in layout:
        raise ValueError(f"unsupported index-sum name length: {target}")
    collection_bytes, document_bytes = layout[target]
    return (
        f"{tag[:collection_bytes].ljust(collection_bytes, 'c')}/{'d' * document_bytes}"
    )


def _readback(names: list[str]) -> dict[str, Any]:
    return {
        "id": "readback",
        "method": "POST",
        "path": BATCH_GET,
        "body": {"documents": names},
    }


def _commit_program(
    program_id: str,
    writes: list[dict[str, Any]],
    names: list[str],
    body: str | None = None,
) -> dict[str, Any]:
    return {
        "id": program_id,
        "area": "writes",
        "steps": [
            {
                "id": "write",
                "method": "POST",
                "path": COMMIT,
                "body": body if body is not None else {"writes": writes},
            },
            _readback(names),
        ],
    }


def _update(name: str, value: str = "1") -> dict[str, Any]:
    return {"update": {"name": name, "fields": {"v": {"integerValue": value}}}}


def _field_update(name: str, fields: dict[str, Any]) -> dict[str, Any]:
    return {"update": {"name": name, "fields": fields}}


def _near_limit_delete_program(route: str, count: int) -> dict[str, Any]:
    run_marker = "DELETE_RUN_ID"
    prefix = f"del{route.replace('-', '')}{count}{run_marker}"
    runtime_collection_bytes = 998
    marker_growth = 32 - len(run_marker)
    collection = prefix.ljust(runtime_collection_bytes - marker_growth, "c")
    name = f"{DOCS}/{collection}/d"
    values = [{"integerValue": str(index)} for index in range(count)]
    if route == "rest":
        delete = {"id": "delete", "method": "DELETE", "path": f"/v1/{name}"}
    elif route == "commit":
        delete = {
            "id": "delete",
            "method": "POST",
            "path": COMMIT,
            "body": {"writes": [{"delete": name}]},
        }
    elif route == "batch-write":
        delete = {
            "id": "delete",
            "method": "POST",
            "path": BATCH_WRITE,
            "body": {"writes": [{"delete": name}]},
        }
    else:
        raise ValueError(f"unsupported near-limit DELETE route: {route}")
    return {
        "id": f"writes/limits/near-limit-delete-refusal/{route}/{count}",
        "area": "writes",
        "steps": [
            {
                "id": "seed",
                "method": "POST",
                "path": COMMIT,
                "body": {
                    "writes": [
                        _field_update(name, {"a": {"arrayValue": {"values": values}}})
                    ]
                },
            },
            {"id": "before-delete", "method": "GET", "path": f"/v1/{name}"},
            delete,
            {
                "id": "after-delete",
                "method": "POST",
                "path": f"/v1/{DOCS}:batchGet",
                "body": {"documents": [name]},
            },
            {
                "id": "group-after-delete",
                "method": "POST",
                "path": f"/v1/{DOCS}:runQuery",
                "body": {
                    "structuredQuery": {
                        "from": [{"collectionId": collection, "allDescendants": True}],
                        "select": {"fields": [{"fieldPath": "__name__"}]},
                        "limit": 2,
                    }
                },
            },
        ],
    }


def _raw_request_program(size: int) -> dict[str, Any]:
    name = f"{DOCS}/raw11/{size}"
    payload = json.dumps({"writes": [_update(name)]}, separators=(",", ":"))
    if len(payload) > size:
        raise ValueError("raw request target smaller than JSON body")
    payload = payload[:-1] + " " * (size - len(payload)) + "}"
    return _commit_program(
        f"writes/limits/raw-11mib/{size}", [_update(name)], [name], payload
    )


def _non_commit_batchwrite_request_program(size: int) -> dict[str, Any]:
    name = f"{DOCS}/rawBatch/{size}"
    payload = json.dumps({"writes": [_update(name)]}, separators=(",", ":"))
    if len(payload) > size:
        raise ValueError("raw BatchWrite target smaller than JSON body")
    payload = payload[:-1] + " " * (size - len(payload)) + "}"
    return {
        "id": f"writes/limits/non-commit-rest-request-bytes/batch-write/{size}",
        "area": "writes",
        "steps": [
            {"id": "write", "method": "POST", "path": BATCH_WRITE, "body": payload},
            _readback([name]),
        ],
    }


def _non_commit_read_request_program(family: str, size: int) -> dict[str, Any]:
    collection = "rawBatchGet" if family == "batch-get" else "rawQuery"
    name = f"{DOCS}/{collection}/{size}"
    if family == "batch-get":
        path = BATCH_GET
        body = {"documents": [name]}
    elif family == "run-query":
        path = f"/v1/{DOCS}:runQuery"
        body = {"structuredQuery": {"from": [{"collectionId": collection}]}}
    else:
        raise ValueError(f"unsupported non-Commit REST family: {family}")
    payload = json.dumps(body, separators=(",", ":"))
    if len(payload) > size:
        raise ValueError("raw read target smaller than JSON body")
    payload = payload[:-1] + " " * (size - len(payload)) + "}"
    return {
        "id": f"writes/limits/non-commit-rest-request-bytes/{family}/{size}",
        "area": "writes",
        "steps": [
            {
                "id": "seed",
                "method": "POST",
                "path": COMMIT,
                "body": {"writes": [_update(name)]},
            },
            {"id": "probe", "method": "POST", "path": path, "body": payload},
        ],
    }


def _non_commit_document_write_program(family: str, size: int) -> dict[str, Any]:
    collection = "rawCreate" if family == "create" else "rawPatch"
    name = f"{DOCS}/{collection}/{size}"
    if family == "create":
        method = "POST"
        path = f"/v1/{DOCS}/{collection}?documentId={size}"
        steps: list[dict[str, Any]] = []
    elif family == "patch":
        method = "PATCH"
        path = f"/v1/{name}"
        steps = [
            {
                "id": "seed",
                "method": "POST",
                "path": COMMIT,
                "body": {"writes": [_update(name, "1")]},
            }
        ]
    else:
        raise ValueError(f"unsupported non-Commit REST document write: {family}")
    payload = json.dumps(
        {"fields": {"v": {"integerValue": "2"}}}, separators=(",", ":")
    )
    if len(payload) > size:
        raise ValueError("raw document write target smaller than JSON body")
    payload = payload[:-1] + " " * (size - len(payload)) + "}"
    steps.extend(
        [
            {"id": "probe", "method": method, "path": path, "body": payload},
            {"id": "readback", "method": "GET", "path": f"/v1/{name}"},
        ]
    )
    return {
        "id": f"writes/limits/non-commit-rest-request-bytes/{family}/{size}",
        "area": "writes",
        "steps": steps,
    }


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
    elif variant == "two-fields-bad-integer":
        middle["update"]["fields"] = {
            "z": {"integerValue": "1"},
            "a": {"integerValue": "not-a-number"},
        }
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
            {
                "id": "batch-write",
                "method": "POST",
                "path": BATCH_WRITE,
                "body": {"writes": [_update(names[0]), middle, _update(names[2])]},
            },
            _readback(names),
        ],
    }


def _field_path_mask_program(length: int) -> dict[str, Any]:
    name = f"{DOCS}/fieldPathMask/{length}"
    field = "f" * length
    write = _field_update(name, {field: {"integerValue": "1"}})
    write["updateMask"] = {"fieldPaths": [field]}
    return _commit_program(f"writes/limits/field-path-mask/{length}", [write], [name])


def _implied_array_key_program(length: int) -> dict[str, Any]:
    name = f"{DOCS}/impliedArrayKey/{length}"
    value = {
        "arrayValue": {
            "values": [{"mapValue": {"fields": {"k" * length: {"integerValue": "1"}}}}]
        }
    }
    return _commit_program(
        f"writes/limits/implied-array-key/{length}",
        [_field_update(name, {"a": value})],
        [name],
    )


def _map_key_programs(
    label: str, key: str, *, write: bool = True
) -> list[dict[str, Any]]:
    value = {"mapValue": {"fields": {key: {"integerValue": "1"}}}}
    query = {
        "id": f"writes/map-key-validation/{label}/query",
        "area": "writes",
        "steps": [
            {
                "id": "query",
                "method": "POST",
                "path": f"/v1/{DOCS}:runQuery",
                "body": {
                    "structuredQuery": {
                        "from": [{"collectionId": "mapValidation"}],
                        "where": {
                            "fieldFilter": {
                                "field": {"fieldPath": "m"},
                                "op": "EQUAL",
                                "value": value,
                            }
                        },
                    }
                },
            }
        ],
    }
    if not write:
        return [query]
    name = f"{DOCS}/mapValidation/{label}"
    return [
        _commit_program(
            f"writes/map-key-validation/{label}/write",
            [_field_update(name, {"m": value})],
            [name],
        ),
        query,
    ]


def build_programs() -> list[dict[str, Any]]:
    programs = [_raw_request_program(size) for size in (11_534_336, 11_534_337)]
    programs.extend(
        _non_commit_batchwrite_request_program(size)
        for size in (10_485_760, 10_485_761)
    )
    programs.extend(
        _non_commit_read_request_program(family, size)
        for family in ("batch-get", "run-query")
        for size in (10_485_760, 10_485_761)
    )
    programs.extend(
        _non_commit_document_write_program(family, size)
        for family in ("create", "patch")
        for size in (10_485_760, 10_485_761)
    )
    programs.extend(
        _batch_variant(variant)
        for variant in (
            "no-operation",
            "collection-name",
            "empty-field-name",
            "reserved-field-name",
            "bad-mask-path",
            "bad-integer",
            "two-fields-bad-integer",
            "unknown-value-kind",
            "bad-timestamp",
            "exists-precondition-fails",
        )
    )
    programs.extend(_field_path_mask_program(length) for length in (1499, 1500))
    programs.extend(_implied_array_key_program(length) for length in (1494, 1495))
    for label, key in (
        ("reserved", "__bad__"),
        ("empty", ""),
        ("overlong", "k" * 1_501),
    ):
        programs.extend(_map_key_programs(label, key))
    programs.extend(_map_key_programs("type-tag", "__type__", write=False))
    map_name = f"{DOCS}/m/x"
    programs.append(
        _commit_program(
            "writes/limits/aggregate-map/strict-only",
            [
                _field_update(
                    map_name,
                    {
                        "m": {
                            "mapValue": {
                                "fields": {"s": {"stringValue": "x" * 1_048_500}}
                            }
                        }
                    },
                )
            ],
            [map_name],
        )
    )
    for length in (2641, 2642):
        name = f"{DOCS}/{name_of_length(length, f'n{length}')}"
        write = _field_update(name, {"s": {"stringValue": "x" * 1500}})
        programs.append(
            _commit_program(
                f"writes/limits/index-entry-string-name/{length}", [write], [name]
            )
        )
    for length in (4627, 4628, 6127, 6128):
        name = f"{DOCS}/{name_of_length(length, f'n{length}')}"
        programs.append(
            _commit_program(
                f"writes/limits/empty-document-name/{length}",
                [_field_update(name, {})],
                [name],
            )
        )
    index_sum_steps: list[dict[str, Any]] = []
    for index, (length, count) in enumerate(
        (
            (500, 19999),
            (500, 20000),
            (2000, 7184),
            (2000, 7185),
            (1000, 12123),
            (1000, 12124),
        )
    ):
        tag = f"g{length}{'a' if index % 2 == 0 else 'b'}"
        name = f"{DOCS}/{index_sum_name_of_length(length, tag)}"
        values = [{"integerValue": str(index)} for index in range(count)]
        write = _field_update(name, {"a": {"arrayValue": {"values": values}}})
        pair = _commit_program(
            f"writes/limits/index-entry-sum/{length}-{count}", [write], [name]
        )
        pair["steps"][0]["id"] = f"write-{length}-{count}"
        pair["steps"][1]["id"] = f"readback-{length}-{count}"
        index_sum_steps.extend(pair["steps"])
    programs.append(
        {
            "id": "writes/limits/index-entry-sum/adjacent",
            "area": "writes",
            "steps": index_sum_steps,
        }
    )
    names = [f"{DOCS}/decoded11/item{index}" for index in range(11)]
    writes = [
        _field_update(name, {"s": {"stringValue": "x" * 1_040_000}}) for name in names
    ]
    programs.append(_commit_program("writes/limits/decoded-11x1040000", writes, names))
    programs.extend(
        _near_limit_delete_program(route, count)
        for route in ("rest", "commit", "batch-write")
        for count in (12_112, 12_113)
    )
    return programs
