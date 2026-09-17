"""Compile a finite, offline Firestore REST plan for FS-DATA-WRITE-LIMITS-02.

This module only creates typed request descriptions. It never opens a network
connection and intentionally leaves the production Gate and comparator out of
scope.
"""
from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from typing import Any

FIELD_VALUE_MAX = 1_048_487
DOCUMENT_MAX = 1_048_576
DEPTH_MAX = 20
CAMPAIGN = "FS-DATA-WRITE-LIMITS-02"
_NONCE = re.compile(r"^[0-9a-f]{32}$")
_SEGMENT = re.compile(r"^[^/]+$")
_ROOT = Path(__file__).resolve().parents[3]
_CATALOG = _ROOT / "spec/limits/firestore-standard-2026-08-25.json"


def _string_size(value: str) -> int:
    return len(value.encode("utf-8")) + 1


def _value_size(value: dict[str, Any]) -> int:
    if "nullValue" in value or "booleanValue" in value:
        return 1
    if "integerValue" in value or "doubleValue" in value or "timestampValue" in value:
        return 8
    if "stringValue" in value:
        return _string_size(value["stringValue"])
    if "bytesValue" in value:
        return len(base64.b64decode(value["bytesValue"], validate=True))
    if "referenceValue" in value:
        return _reference_size(value["referenceValue"])
    if "arrayValue" in value:
        return sum(_value_size(item) for item in value["arrayValue"].get("values", []))
    if "mapValue" in value:
        return _fields_size(value["mapValue"].get("fields", {})) + 32
    raise ValueError("unsupported Firestore typed value")


def _fields_size(fields: dict[str, dict[str, Any]]) -> int:
    return sum(_string_size(name) + _value_size(value) for name, value in fields.items())


def _reference_size(resource: str) -> int:
    relative = resource.split("/documents/", 1)[-1]
    return 16 + sum(_string_size(segment) for segment in relative.split("/"))


def document_name_size(resource: str) -> int:
    """Return the core ``document_name_size`` for a REST resource name."""
    if "/documents/" not in resource:
        raise ValueError("resource must contain /documents/")
    relative = resource.split("/documents/", 1)[1]
    segments = relative.split("/")
    if not segments or any(not segment for segment in segments):
        raise ValueError("malformed document resource")
    return 16 + sum(_string_size(segment) for segment in segments)


def document_size_bytes(resource: str, fields: dict[str, dict[str, Any]]) -> int:
    return document_name_size(resource) + 32 + _fields_size(fields)


def nested_depth(fields: dict[str, dict[str, Any]]) -> int:
    def value_depth(value: dict[str, Any]) -> int:
        if "mapValue" in value:
            values = value["mapValue"].get("fields", {}).values()
            return 1 + max((value_depth(item) for item in values), default=0)
        if "arrayValue" in value:
            return 1 + max((value_depth(item) for item in value["arrayValue"].get("values", [])), default=0)
        return 0

    return max((value_depth(value) for value in fields.values()), default=0)


def _string(value: str) -> dict[str, str]:
    return {"stringValue": value}


def _bytes(value: bytes) -> dict[str, str]:
    return {"bytesValue": base64.b64encode(value).decode("ascii")}


def _boundary_fields(resource: str, size: int, nonce: str) -> dict[str, dict[str, Any]]:
    fields: dict[str, dict[str, Any]] = {
        "_sharedOwner": {"referenceValue": resource},
    }
    remaining = size - document_name_size(resource) - 32 - _fields_size(fields) - _string_size("blob")
    if remaining < 0:
        raise ValueError("boundary metadata exceeds document budget")
    chunks = []
    while remaining:
        chunk = min(remaining, FIELD_VALUE_MAX)
        chunks.append(chunk)
        remaining -= chunk
    if len(chunks) == 1:
        fields["blob"] = _bytes(b"x" * chunks[0])
    else:
        raise ValueError("boundary payload cannot fit the single legal bytes field")
    return fields


def _nested_fields(depth: int, nonce: str, resource: str) -> dict[str, dict[str, Any]]:
    value: dict[str, Any] = _bytes(b"x")
    for _ in range(depth):
        value = {"mapValue": {"fields": {"level": value}}}
    return {"_sharedOwner": {"referenceValue": resource}, "nested": value}


def _catalog_limits() -> tuple[int, int]:
    catalog = json.loads(_CATALOG.read_bytes())
    entries = {entry["id"]: entry for entry in catalog["limits"]}
    if entries["FS-LIMIT-FIELD-VALUE-BYTES"]["maximum"] != FIELD_VALUE_MAX:
        raise ValueError("field value catalog drift")
    depth_id = "FS-LIMIT-NESTED-MAP-ARRAY-DEPTH"
    if entries[depth_id]["maximum"] != DEPTH_MAX:
        raise ValueError("nested depth catalog drift")
    return entries["FS-LIMIT-DOCUMENT-BYTES"]["maximum"], entries[depth_id]["maximum"]


def compile_limits_plan(project: str, database: str, nonce: str) -> dict[str, Any]:
    """Compile four cases and their bounded ordered offline request plan."""
    if not isinstance(project, str) or not project or not re.fullmatch(r"[A-Za-z0-9_-]+", project):
        raise ValueError("malformed project")
    if not isinstance(database, str) or not database or (database != "(default)" and not re.fullmatch(r"[A-Za-z0-9_-]+", database)):
        raise ValueError("malformed database")
    if not _NONCE.fullmatch(nonce):
        raise ValueError("nonce must be 32 lowercase hexadecimal characters")
    catalog_document_max, catalog_depth_max = _catalog_limits()
    root = f"projects/{project}/databases/{database}/documents/oracle/{nonce}/limits-02"
    cases = (
        ("exact-document-boundary", "exact", DOCUMENT_MAX, _boundary_fields),
        ("over-document-boundary", "over", DOCUMENT_MAX + 1, _boundary_fields),
        ("exact-nested-boundary", "nested-exact", 0, lambda r, _s, n: _nested_fields(catalog_depth_max, n, r)),
        ("over-nested-boundary", "nested-over", 0, lambda r, _s, n: _nested_fields(catalog_depth_max + 1, n, r)),
    )
    documents: dict[str, Any] = {}
    requests: list[dict[str, Any]] = []
    for label, suffix, size, builder in cases:
        resource = f"{root}/{suffix}"
        fields = builder(resource, size, nonce)
        logical = document_size_bytes(resource, fields)
        documents[label] = {
            "resource": resource,
            "fields": fields,
            "fieldValueBytes": {name: _value_size(value) for name, value in fields.items()},
            "logicalBytes": logical,
            "depth": nested_depth(fields),
        }
        requests.append({"kind": "preflight-typed-absence", "service": "firestore", "method": "GET", "path": "/v1/" + resource, "expect": {"status": 404, "typed": "NOT_FOUND"}})
    for label in ("exact-document-boundary", "exact-nested-boundary", "over-document-boundary", "over-nested-boundary"):
        doc = documents[label]
        requests.append({"kind": "create-only-commit", "service": "firestore", "method": "PATCH", "path": "/v1/" + doc["resource"] + "?currentDocument.exists=false", "body": {"name": doc["resource"], "fields": doc["fields"]}, "expect": {"positive": label.startswith("exact-")}})
    for label in ("exact-document-boundary", "over-document-boundary", "exact-nested-boundary", "over-nested-boundary"):
        doc = documents[label]
        requests.append({"kind": "typed-readback", "service": "firestore", "method": "GET", "path": "/v1/" + doc["resource"], "expect": {"status": 200 if label.startswith("exact-") else 404, "typed": "OK" if label.startswith("exact-") else "NOT_FOUND"}})
    exact_controls = ("exact-document-boundary", "exact-nested-boundary")
    for negative in ("over-document-boundary", "over-nested-boundary"):
        for control in exact_controls:
            requests.append({"kind": "unchanged-control-readback", "service": "firestore", "method": "GET", "path": "/v1/" + documents[control]["resource"], "after": negative, "expect": {"status": 200, "unchanged": True}})
    for label, doc in documents.items():
        requests.append({"kind": "cleanup-ownership-read", "service": "firestore", "method": "GET", "path": "/v1/" + doc["resource"], "requires": ["ownership marker"], "expect": {"status": 200}})
        requests.append({"kind": "cleanup-conditional-delete", "service": "firestore", "method": "DELETE", "path": "/v1/" + doc["resource"] + "?currentDocument.updateTime={boundUpdateTime}", "enabled": False, "requires": ["ownership marker", "bound updateTime/version"], "expect": {"status": 200}})
        requests.append({"kind": "cleanup-verify-absence", "service": "firestore", "method": "GET", "path": "/v1/" + doc["resource"], "expect": {"status": 404, "typed": "NOT_FOUND"}})
    request_sizes = [len(json.dumps(item.get("body", {}), separators=(",", ":")).encode()) for item in requests]
    response_sizes = []
    for item in requests:
        if item["kind"] in ("typed-readback", "unchanged-control-readback") and item["expect"]["status"] == 200:
            label = next(name for name, doc in documents.items() if doc["resource"] in item["path"])
            response_sizes.append(len(json.dumps({"name": documents[label]["resource"], "fields": documents[label]["fields"]}, separators=(",", ":")).encode()))
        else:
            response_sizes.append(65536)
    return {"campaignId": CAMPAIGN, "catalog": {"documentMaximum": catalog_document_max, "fieldValueMaximum": FIELD_VALUE_MAX, "nestedDepthId": "FS-LIMIT-NESTED-MAP-ARRAY-DEPTH", "nestedDepthMaximum": catalog_depth_max}, "nonce": nonce, "documents": documents, "requests": requests, "budgetAccounting": {"requestUpperBound": len(requests), "requestBodyUpperBoundBytes": max(request_sizes), "responseUpperBoundBytes": sum(response_sizes), "transportRequestUpperBoundBytes": max(request_sizes), "maxResponseBytes": 8388608, "recoverySeconds": 159, "productionReady": False}}
