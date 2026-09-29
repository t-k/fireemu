"""Unobserved production inputs for one bounded FS-DATA-WRITE sandbox run."""

from __future__ import annotations

import json
from typing import Any

PROJECT = "fireemu-oracle-sbx"
DOCS = f"projects/{PROJECT}/databases/(default)/documents"
COMMIT = f"/v1/{DOCS}:commit"
BATCH_WRITE = f"/v1/{DOCS}:batchWrite"
BATCH_GET = f"/v1/{DOCS}:batchGet"


# (string bytes, relative document-name bytes, last document-ID bytes or None for the even
# split of `name_of_length`) for the indexed-string follow-up.
INDEXED_STRING_NAME_POINTS = (
    (2999, 1142, None),
    (2999, 1143, None),
    (2999, 1500, None),
    (2999, 1800, None),
    (2999, 2100, None),
    (2999, 2400, None),
    (2999, 2606, None),
    (2999, 2607, None),
    (2000, 2141, None),
    (2000, 2142, None),
    # Own name alone refuses this write; own plus parent name would not.
    (1500, 2642, 1500),
)


def name_with_last_id(target: int, tag: str, last_id_bytes: int) -> str:
    """`c/<tag padded>/c/<last>`: a two-pair name of exact length with a fixed last ID."""
    first = target - last_id_bytes - 5
    if not 1 <= first <= 1500 or not 1 <= last_id_bytes <= 1500:
        raise ValueError(
            f"cannot form a {target}-byte name with a {last_id_bytes}-byte last ID"
        )
    name = f"c/{tag[:first].ljust(first, 'd')}/c/{'d' * last_id_bytes}"
    if len(name.encode()) != target:
        raise ValueError("name fixture length")
    return name


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
    return {
        "id": f"writes/limits/non-commit-rest-request-bytes/batch-write/{size}",
        "area": "writes",
        "steps": [
            {
                "id": "write",
                "method": "POST",
                "path": BATCH_WRITE,
                **_padded_body(payload, size),
            },
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
            {
                "id": "probe",
                "method": "POST",
                "path": path,
                **_padded_body(payload, size),
            },
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
    steps.extend(
        [
            {
                "id": "probe",
                "method": method,
                "path": path,
                **_padded_body(payload, size),
            },
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


# Bodies of at least this size are stored compact with `padToBytes`; the harness pads them
# before sending. Stored whole, eleven-mebibyte bodies push the exported corpus past what a
# caller can buffer.
COMPACT_PADDING_FROM = 11_534_336


def _padded_body(payload: str, size: int) -> dict[str, Any]:
    """The step fields that send `payload` padded with spaces before its last `}` to `size`."""
    if len(payload) > size:
        raise ValueError("request target smaller than JSON body")
    if size >= COMPACT_PADDING_FROM:
        return {"body": payload, "padToBytes": size}
    return {"body": payload[:-1] + " " * (size - len(payload)) + "}"}


# Production accepted 10,485,761 bytes on every non-Commit REST route; the 11 MiB pair
# brackets each route against the REST Commit maximum (owner decision D4, 2026-09-27 split).
NON_COMMIT_REQUEST_SIZES = (10_485_760, 10_485_761, 11_534_336, 11_534_337)


def _aggregate_map_pair_program(size: int) -> dict[str, Any]:
    """A map whose logical size is `size`: field `s` (2 bytes) plus a string of size - 3."""
    name = f"{DOCS}/aggregatePair/m{size}"
    value = "x" * (size - 3)
    write = _field_update(
        name, {"m": {"mapValue": {"fields": {"s": {"stringValue": value}}}}}
    )
    return _commit_program(f"writes/limits/aggregate-map/{size}", [write], [name])


def _indexed_value_pair_program(name_sum: int) -> dict[str, Any]:
    """A 2,999-byte indexed string under a name whose own and parent sizes sum to `name_sum`.

    The capped index entry is `name_sum` + 21 (field) + 32 + 1,500 (truncated value): 6,753
    under 5,200 and 7,681, one byte over the 7,680 entry limit, under 6,128.
    """
    fixed = ["ifvpair", "r", "p", "z" * 800, "p", "z" * 800, "p"]
    parent_storage = (name_sum - (len("ifvtest") + 1) - (len("d") + 1)) // 2
    pad = parent_storage - 16 - sum(len(segment) + 1 for segment in fixed) - 1
    segments = [*fixed, "z" * pad, "ifvtest", "d"]
    name = f"{DOCS}/{'/'.join(segments)}"
    write = _field_update(name, {"s" * 20: {"stringValue": "x" * 2_999}})
    return _commit_program(
        f"writes/limits/indexed-field-value-bytes/{name_sum}", [write], [name]
    )


def build_programs() -> list[dict[str, Any]]:
    programs = [_raw_request_program(size) for size in (11_534_336, 11_534_337)]
    programs.extend(
        _non_commit_batchwrite_request_program(size)
        for size in NON_COMMIT_REQUEST_SIZES
    )
    programs.extend(
        _non_commit_read_request_program(family, size)
        for family in ("batch-get", "run-query")
        for size in NON_COMMIT_REQUEST_SIZES
    )
    programs.extend(
        _non_commit_document_write_program(family, size)
        for family in ("create", "patch")
        for size in NON_COMMIT_REQUEST_SIZES
    )
    programs.extend(
        _aggregate_map_pair_program(size) for size in (1_048_487, 1_048_488)
    )
    programs.extend(_indexed_value_pair_program(total) for total in (5_200, 6_128))
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
    # The follow-up to the bracket recording: accepted-side observations for an indexed
    # string longer than 1,500 bytes, in the same shape as the pair above.
    for string_bytes, name_bytes, last_id_bytes in INDEXED_STRING_NAME_POINTS:
        tag = f"s{string_bytes}n{name_bytes}"
        relative = (
            name_of_length(name_bytes, tag)
            if last_id_bytes is None
            else name_with_last_id(name_bytes, tag, last_id_bytes)
        )
        name = f"{DOCS}/{relative}"
        write = _field_update(name, {"s": {"stringValue": "x" * string_bytes}})
        programs.append(
            _commit_program(
                f"writes/limits/indexed-string-name/{string_bytes}/{name_bytes}",
                [write],
                [name],
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
