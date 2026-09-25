"""Compile local FS-DATA-WRITE boundary inputs; never execute a request.

Each case needs a separate, empty, owned local backend. Index configurations
belong to those backends only. Expectations are hypotheses, not observations.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Any

PROJECT = "demo-fs-data-write"
DATABASE = "(default)"
ROOT = Path(__file__).resolve().parents[3]
CATALOG = ROOT / "spec/limits/firestore-standard-2026-08-25.json"
PREFIX = f"projects/{PROJECT}/databases/{DATABASE}/documents/"
FAMILIES = {
    "collection-id": ("FS-LIMIT-COLLECTION-ID", 1500),
    "document-id": ("FS-LIMIT-DOCUMENT-ID", 1500),
    "subcollection-depth": ("FS-LIMIT-SUBCOLLECTION-DEPTH", 100),
    "document-name": ("FS-LIMIT-DOCUMENT-NAME-BYTES", 6144),
    "field-name": ("FS-LIMIT-FIELD-NAME", 1500),
    "field-path": ("FS-LIMIT-FIELD-PATH-BYTES", 1500),
    "field-string": ("FS-LIMIT-FIELD-VALUE-BYTES", 1048487),
    "field-bytes": ("FS-LIMIT-FIELD-VALUE-BYTES", 1048487),
    "field-map": ("FS-LIMIT-FIELD-VALUE-BYTES", 1048487),
    "field-array": ("FS-LIMIT-FIELD-VALUE-BYTES", 1048487),
    "indexed-value": ("FS-LIMIT-INDEXED-FIELD-VALUE-BYTES", 1500),
    "index-count": ("FS-LIMIT-INDEX-ENTRIES-PER-DOCUMENT", 40000),
    "index-entry": ("FS-LIMIT-INDEX-ENTRY-BYTES", 7680),
    "index-sum": ("FS-LIMIT-INDEX-ENTRY-SUM-PER-DOCUMENT", 8388608),
}
POSITIONS = {"below": -1, "exact": 0, "over": 1}


def _bytes(n: int) -> dict[str, str]:
    if n < 0:
        raise ValueError("negative payload size")
    return {"bytesValue": base64.b64encode(b"x" * n).decode("ascii")}


def _string(n: int) -> dict[str, str]:
    if n < 0:
        raise ValueError("negative payload size")
    return {"stringValue": "x" * n}


def _integer(n: int) -> dict[str, str]:
    return {"integerValue": str(n)}


def _disabled_indexes(collection: str) -> dict[str, Any]:
    return {
        "indexes": [],
        "fieldOverrides": [{"collectionGroup": collection, "fieldPath": "*", "indexes": []}],
    }


def _composite(collection: str, modes: list[tuple[str, str]]) -> dict[str, Any]:
    config = _disabled_indexes(collection)
    fields = []
    for name, mode in modes:
        setting = {"arrayConfig": "CONTAINS"} if mode == "contains" else {"order": "ASCENDING"}
        fields.append({"fieldPath": name, **setting})
    config["indexes"] = [{
        "collectionGroup": collection, "queryScope": "COLLECTION", "fields": fields,
    }]
    return config


def _name_size(relative: str) -> int:
    return 16 + sum(len(part.encode("utf-8")) + 1 for part in relative.split("/"))


def _long_resource(size: int, nonce: str) -> str:
    # Three collection/document pairs, each segment within its own 1,500-byte limit.
    # Firestore charges the relative path's segments plus a fixed 16 bytes, not the
    # project-qualified REST resource prefix. Five separators add five bytes here.
    remaining = size - 17 - len(nonce) - 5
    segments = []
    for index in range(5):
        length = min(1500, remaining - (4 - index))
        if length < 1:
            raise ValueError("document-name fixture cannot fit")
        segments.append(chr(ord("a") + index) * length)
        remaining -= length
    if remaining:
        raise ValueError("document-name fixture exceeds segment capacity")
    return "/".join([*segments, nonce])


def _selection(family: str | None, position: str | None) -> tuple[list[str], list[str]]:
    if family is not None and (not isinstance(family, str) or family not in FAMILIES):
        raise ValueError("unknown closed boundary family")
    if position is not None and (not isinstance(position, str) or position not in POSITIONS):
        raise ValueError("unknown closed boundary position")
    return ([family] if family is not None else list(FAMILIES),
            [position] if position is not None else list(POSITIONS))


def compile_case(family: str, position: str, nonce: str) -> dict[str, Any]:
    if family is None or position is None:
        raise ValueError("one closed boundary case required")
    _selection(family, position)
    if not isinstance(nonce, str) or re.fullmatch(r"[0-9a-f]{32}", nonce) is None:
        raise ValueError("32 lowercase hexadecimal characters required")
    limit_id, maximum = FAMILIES[family]
    point = maximum + POSITIONS[position]
    relative = "c/" + nonce
    fields: dict[str, Any] = {"v": _integer(1)}
    config: dict[str, Any] = {"indexes": [], "fieldOverrides": []}
    metric: dict[str, Any] = {"target": point, "unit": "bytes"}
    overlaps: list[str] = []

    if family == "collection-id":
        relative = "c" * point + "/" + nonce
    elif family == "document-id":
        relative = "c/" + nonce + "d" * (point - len(nonce))
    elif family == "subcollection-depth":
        relative = "/".join(["c", "d"] * (point - 1) + ["c", nonce])
        metric["unit"] = "collection-levels"
    elif family == "document-name":
        relative = _long_resource(point, nonce)
        config = _disabled_indexes(relative.split("/")[-2])
        overlaps = ["FS-LIMIT-INDEX-ENTRY-BYTES"]
    elif family == "field-name":
        fields = {"f" * point: _integer(1)}
        config = _disabled_indexes("c")
        overlaps = ["FS-LIMIT-FIELD-PATH-BYTES"]
    elif family == "field-path":
        names = ["a" * 500, "b" * 500, "c" * (point - 1002)]
        value: dict[str, Any] = _integer(1)
        for name in names[1:][::-1]:
            value = {"mapValue": {"fields": {name: value}}}
        fields = {names[0]: value}
        config = _disabled_indexes("c")
    elif family in {"field-string", "field-bytes", "field-map", "field-array"}:
        config = _disabled_indexes("c")
        metric["unit"] = "payload-bytes" if family in {"field-string", "field-bytes"} else "logical-bytes"
        if family == "field-string":
            fields = {"v": _string(point)}
        elif family == "field-bytes":
            fields = {"v": _bytes(point)}
        elif family == "field-map":
            # string_size("s") + string_size(payload); maps have no extra 32-byte charge.
            fields = {"v": {"mapValue": {"fields": {"s": _string(point - 3)}}}}
        else:
            fields = {"v": {"arrayValue": {"values": [_bytes(point // 2), _bytes(point - point // 2)]}}}
    elif family == "indexed-value":
        fields = {"v": _string(point - 1), "k": _integer(0)}
        config = _composite("c", [("v", "ascending"), ("k", "ascending")])
        metric.update(indexedValueBytes=min(point, 1500), storedStringBytes=point - 1)
    elif family == "index-count":
        fields = {"v": {"arrayValue": {"values": [_integer(n) for n in range(point)]}}, "k": _integer(0)}
        config = _composite("c", [("v", "contains"), ("k", "ascending")])
        size = _name_size(relative) + 8 + 8 + 32
        metric.update(unit="entries", entries=point, maximumEntryBytes=size, indexBytes=point * size)
    elif family == "index-entry":
        # A single composite, without automatic indexes. No value needs truncation.
        fields = {name: _string(1499) for name in "abcde"}
        fields["f"] = _bytes(point - _name_size(relative) - 32 - 5 * 1500)
        config = _composite("c", [(name, "ascending") for name in "abcdef"])
        metric.update(entries=1, maximumEntryBytes=point, indexBytes=point)
    elif family == "index-sum":
        base = _name_size(relative) + 32 + 256
        count = (point - base - 1) // (base + 8)
        tail = point - count * (base + 8) - base
        if not 1 <= tail <= 1500:
            raise ValueError("index-sum remainder exceeds indexed-value budget")
        # Distinct integers plus a bytes value: no array-element deduplication.
        values = [*(_integer(n) for n in range(count)), _bytes(tail)]
        fields = {"v": {"arrayValue": {"values": values}}, "k": _string(255)}
        config = _composite("c", [("v", "contains"), ("k", "ascending")])
        metric.update(entries=count + 1, maximumEntryBytes=base + max(8, tail), indexBytes=point)

    resource = PREFIX + relative
    document = {"name": resource, "fields": fields}
    return {
        "id": family + "/" + position, "family": family, "position": position,
        "limitId": limit_id, "maximum": maximum, "metric": metric,
        "overlappingLimits": overlaps, "resource": resource, "document": document,
        "write": {"update": document, "currentDocument": {"exists": False}},
        "indexConfiguration": config,
        "expect": {
            "accepted": (
                (position != "over" and family != "document-name")
                or family == "indexed-value"
            ),
            "basis": "local-test-hypothesis-not-production-observation",
            "rejectedCommitPreservesSiblings": True,
            "batchWriteSiblingsRemainIndependent": True,
            "readbackPreservesUntruncatedFields": True,
        },
    }


def compile_suite(nonce: str, *, family: str | None = None, position: str | None = None) -> dict[str, Any]:
    families, positions = _selection(family, position)
    entries = {row["id"]: row for row in json.loads(CATALOG.read_bytes())["limits"]}
    for limit_id, maximum in FAMILIES.values():
        if entries[limit_id]["maximum"] != maximum or entries[limit_id]["implemented"] != "implemented":
            raise ValueError("write-path catalog drift: " + limit_id)
    return {
        "kind": "fs-data-write-local-boundaries-v1",
        "target": "isolated-local-backend-per-case", "project": PROJECT, "database": DATABASE,
        "nonce": nonce, "productionExecuted": False, "authorizesProduction": False,
        "nativeExecuted": False, "compatibility": "not-observed",
        "catalogSha256": hashlib.sha256(CATALOG.read_bytes()).hexdigest(),
        "compilerSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "selection": {"families": families, "positions": positions},
        "cases": [compile_case(f, p, nonce) for f in families for p in positions],
        "separateExistingCoverage": [
            {"limitId": "FS-LIMIT-DOCUMENT-BYTES", "source": "tools/compat-broad/fs-write-limits/compiler.py"},
            {"limitId": "FS-LIMIT-NESTED-MAP-ARRAY-DEPTH", "source": "tools/compat-broad/fs-write-limits/compiler.py"},
            {"limitId": "FS-LIMIT-API-REQUEST-BYTES", "source": "crates/fireemu-adapter-grpc/tests/request_bytes.rs"},
            {"limitId": "FS-LIMIT-FIELD-TRANSFORMS-PER-DOCUMENT", "source": "tools/compat-broad/fs-commit-transform-limits/transform_compiler.py"},
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--family", choices=list(FAMILIES))
    parser.add_argument("--position", choices=list(POSITIONS))
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--stdout", action="store_true")
    mode.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    value = compile_suite(args.nonce, family=args.family, position=args.position)
    if args.stdout:
        print(json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False))
    else:
        with args.output.open("x", encoding="utf-8") as stream:
            json.dump(value, stream, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
            stream.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
