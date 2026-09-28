"""FS-REQUEST-BYTES-METRIC-033: offline, bounded metric audit, NOT admission.

The existing campaign measures raw REST bytes. This companion also computes the
protobuf CommitRequest size for its create-only/string-value subset. That size is
NOT an assertion about Google's quota implementation. No network, credentials,
Gate/Ledger writes, expectation changes or historical receipt edits occur here.

Wire fields: CommitRequest.database=1, writes=2; Write.update=1,
current_document=4; Document.name=1, fields=2 (map entry key=1/value=2);
Value.string_value=17 (oneof); Precondition.exists=1 (oneof). The database is
bound from the REST route, not present in the campaign's JSON body. Explicit
exists=false still serializes as 08 00. See the companion test for an independent
Google protobuf serializer check of this deliberately limited wire schema.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any

from request_bytes_catalog_samples import compile_catalog_sample_plan
from request_bytes_compiler import (
    CATALOG_MAXIMUM,
    DOCUMENT_SAFETY_MARGIN,
    compact_utf8,
    document_size_bytes,
)

# This audit studies the 10 MiB catalog samples. The strict campaign's 11 MiB
# REQUEST_LIMIT is a different boundary and must not move it.
AUDIT_LIMIT = CATALOG_MAXIMUM
MAX_AUDIT_BYTES = 32 * 1024 * 1024  # local analysis bound, NOT a service quota
MAX_AUDIT_WRITES = 64  # this companion is intentionally not a general converter
_DATABASE = re.compile(r"projects/[A-Za-z0-9_-]+/databases/(?:\(default\)|[A-Za-z0-9_-]+)")
_HASH = re.compile(r"[0-9a-f]{64}")


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def _varint_bytes(value: int) -> int:
    _require(type(value) is int and value >= 0, "nonnegative-integer-required")
    return max(1, (value.bit_length() + 6) // 7)


def _length_delimited(field: int, length: int) -> int:
    return _varint_bytes((field << 3) | 2) + _varint_bytes(length) + length


def _string_bytes(value: Any) -> int:
    _require(type(value) is str, "string-value-required")
    try:
        return len(value.encode("utf-8"))
    except UnicodeError:
        raise ValueError("invalid-unicode") from None


def _keys(value: Any, names: set[str]) -> None:
    _require(type(value) is dict and set(value) == names, "unsupported-request-shape")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        _require(name not in result, "duplicate-json-key")
        result[name] = value
    return result


def _bad_constant(_: str) -> None:
    raise ValueError("nonfinite-json")


def _decode(raw: bytes) -> dict[str, Any]:
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_AUDIT_BYTES, "body-size-out-of-audit-scope")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                          parse_constant=_bad_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ValueError("invalid-json-body") from None


def measure_body(raw: bytes, database_resource: str) -> dict[str, Any]:
    """Measure exact raw bytes and compute size for the supported semantic subset.

    Reject unknown fields instead of silently dropping them and under-counting.
    Does not infer responses, backend limits or whether any request was ever sent.
    """
    _require(type(database_resource) is str and _DATABASE.fullmatch(database_resource) is not None,
             "database-resource-required")
    body = _decode(raw)
    _keys(body, {"writes"})
    writes = body["writes"]
    _require(type(writes) is list and 1 <= len(writes) <= MAX_AUDIT_WRITES,
             "write-count-out-of-audit-scope")
    database_bytes = _length_delimited(1, _string_bytes(database_resource))
    writes_bytes = payload_bytes = precondition_bytes = 0
    logical_documents: list[int] = []
    proto_documents: list[int] = []
    seen: set[str] = set()
    for write in writes:
        _keys(write, {"update", "currentDocument"})
        _keys(write["currentDocument"], {"exists"})
        _require(write["currentDocument"]["exists"] is False, "create-only-precondition-required")
        document = write["update"]
        _keys(document, {"name", "fields"})
        name, fields = document["name"], document["fields"]
        _require(type(name) is str and name.startswith(database_resource + "/documents/"),
                 "document-database-mismatch")
        _require(name not in seen, "duplicate-document")
        seen.add(name)
        _require(type(fields) is dict and 0 < len(fields) <= 64, "field-count-out-of-audit-scope")
        doc_size = _length_delimited(1, _string_bytes(name))
        for key, value in fields.items():
            key_size = _string_bytes(key)
            _require(0 < key_size <= 1500, "field-name-out-of-audit-scope")
            _keys(value, {"stringValue"})
            length = _string_bytes(value["stringValue"])
            payload_bytes += length
            # Value.string_value is a oneof: an empty string is still present.
            value_size = _length_delimited(17, length)
            map_entry_size = _length_delimited(1, key_size) + _length_delimited(2, value_size)
            doc_size += _length_delimited(2, map_entry_size)
        logical_documents.append(document_size_bytes(name, fields))
        proto_documents.append(doc_size)
        # Precondition.exists=false is PRESENT in a oneof, not an omitted scalar.
        precondition_size = _varint_bytes(1 << 3) + 1  # tag 08, value 00
        embedded_precondition = _length_delimited(4, precondition_size)
        precondition_bytes += embedded_precondition
        write_size = _length_delimited(1, doc_size) + embedded_precondition
        writes_bytes += _length_delimited(2, write_size)
    proto_size = database_bytes + writes_bytes
    return {
        "rawBodySha256": hashlib.sha256(raw).hexdigest(),
        "rawRestBodyBytes": len(raw),
        "compactRestBodyBytes": len(compact_utf8(body)),
        "protobufCommitRequestBytes": proto_size,
        "protobufDatabaseFieldBytes": database_bytes,
        "protobufWritesFieldsBytes": writes_bytes,
        "protobufEmbeddedPreconditionsBytes": precondition_bytes,
        "stringValueUtf8Bytes": payload_bytes,
        "rawMinusProtobufBytes": len(raw) - proto_size,
        "protobufHeadroomTo10MiB": AUDIT_LIMIT - proto_size,
        "rawExceeds10MiB": len(raw) > AUDIT_LIMIT,
        "protobufExceeds10MiB": proto_size > AUDIT_LIMIT,
        "documentCount": len(writes),
        "maxDocumentLogicalBytes": max(logical_documents),
        "sumDocumentLogicalBytes": sum(logical_documents),
        "maxDocumentProtobufBytes": max(proto_documents),
        "everyDocumentBelowCampaignMargin": max(logical_documents) < DOCUMENT_SAFETY_MARGIN,
    }


def candidate_at_proto_size(body: dict[str, Any], database_resource: str,
                            target: int) -> bytes:
    """A near-boundary research input only; NOT a Gate plan or sendable packet.

    Extend/shrink the final blob within the unchanged document safety margin.
    Demand exact remeasurement; never assume nested varint widths are constant.
    """
    _require(type(target) is int and target in (AUDIT_LIMIT - 1, AUDIT_LIMIT, AUDIT_LIMIT + 1),
             "unsupported-protobuf-target")
    candidate = copy.deepcopy(body)
    original = measure_body(compact_utf8(candidate), database_resource)
    fields = candidate["writes"][-1]["update"]["fields"]
    _require("blob" in fields, "candidate-blob-required")
    value = fields["blob"]["stringValue"]
    _require(value.isascii() and value and set(value) == {"x"}, "candidate-ascii-padding-required")
    delta = target - original["protobufCommitRequestBytes"]
    _require(abs(delta) <= 64 * 1024 and len(value) + delta >= 0, "candidate-resize-out-of-scope")
    fields["blob"]["stringValue"] = "x" * (len(value) + delta)
    raw = compact_utf8(candidate)
    measured = measure_body(raw, database_resource)
    _require(measured["protobufCommitRequestBytes"] == target, "varint-width-transition-needs-new-plan")
    _require(measured["everyDocumentBelowCampaignMargin"], "candidate-document-safety-margin")
    return raw


def audit_compiled(project: str, database: str, nonce: str) -> dict[str, Any]:
    """Reconstruct existing compiler inputs; do not call them actual raw evidence."""
    plan = compile_catalog_sample_plan(project, database, nonce)
    database_resource = f"projects/{project}/databases/{database}"
    rows, candidates = [], []
    for probe, target in zip(plan["probes"], (AUDIT_LIMIT - 1, AUDIT_LIMIT, AUDIT_LIMIT + 1), strict=True):
        raw = compact_utf8(probe["body"])
        rows.append({"label": probe["label"], **measure_body(raw, database_resource)})
        candidate = candidate_at_proto_size(probe["body"], database_resource, target)
        candidates.append({"label": f"protobuf-{target - AUDIT_LIMIT:+d}",
                           "targetProtobufBytes": target,
                           **measure_body(candidate, database_resource)})
    # Exactly the same logical input with two legal leading JSON whitespace bytes.
    original = compact_utf8(plan["probes"][0]["body"])
    whitespace_twin = {"label": "same-under-input-plus-two-spaces",
                       "sameDecodedInputAs": "under",
                       **measure_body(b"  " + original, database_resource)}
    compiler = Path(__file__).with_name("request_bytes_compiler.py").read_bytes()
    return {
        "inputKind": "compiler-regeneration-not-production-evidence",
        "compilerGitBlob": hashlib.sha1(b"blob " + str(len(compiler)).encode() + b"\0" + compiler).hexdigest(),
        "originalMetricStatus": plan["metricStatus"],
        "rows": rows,
        "offlineCandidatesNotAuthorized": candidates + [whitespace_twin],
    }


def measure_saved_file(path: Path, database_resource: str, expected_sha256: str) -> dict[str, Any]:
    """Require the exact caller-selected raw-body hash; never reserialize first."""
    _require(_HASH.fullmatch(expected_sha256) is not None, "raw-body-sha256-required")
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        _require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= MAX_AUDIT_BYTES,
                 "bounded-regular-body-required")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(MAX_AUDIT_BYTES + 1)
    finally:
        os.close(fd)
    _require(len(raw) <= MAX_AUDIT_BYTES, "body-size-out-of-audit-scope")
    _require(hashlib.sha256(raw).hexdigest() == expected_sha256, "raw-body-hash-mismatch")
    return {"inputKind": "operator-supplied-hash-bound-body-not-verified-acquisition",
            "rows": [measure_body(raw, database_resource)]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    compiled = sub.add_parser("compiled", help="regenerate the existing compiler and show offline candidate sizes")
    compiled.add_argument("--project", required=True)
    compiled.add_argument("--database", default="(default)")
    compiled.add_argument("--nonce", required=True)
    body = sub.add_parser("body", help="measure a retained raw JSON body, with its independently recorded hash")
    body.add_argument("--database-resource", required=True)
    body.add_argument("--body-file", required=True, type=Path)
    body.add_argument("--sha256", required=True)
    args = parser.parse_args(argv)
    try:
        result = (audit_compiled(args.project, args.database, args.nonce) if args.mode == "compiled"
                  else measure_saved_file(args.body_file, args.database_resource, args.sha256))
        result.update({"schema": "fireemu-request-bytes-metric-audit-v1",
                       "productionExecuted": False, "authorizesNetwork": False,
                       "compatibility": "NOT_ASSESSED", "backendQuotaMetric": "UNVERIFIED",
                       "wireScope": "create-only string-value CommitRequest; database from REST route; no framing/headers"})
        print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))
        return 0
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        # Do not echo private body values, paths or malformed field names.
        print("request-byte metric audit: input or shape could not be verified", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
