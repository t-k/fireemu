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
    return sum(
        _string_size(name) + _value_size(value) for name, value in fields.items()
    )


def _reference_size(resource: str) -> int:
    return document_name_size(resource)


def document_name_size(resource: str) -> int:
    """Charge document segments, not the project/database namespace.

    This checks structure, not byte/depth limits: boundary compilers must still
    be able to measure structurally valid over-limit paths.
    """
    if not isinstance(resource, str):
        raise ValueError("malformed document resource")
    parts = resource.split("/", 5)
    if (
        len(parts) != 6
        or parts[0] != "projects"
        or not parts[1]
        or parts[2] != "databases"
        or not parts[3]
        or parts[4] != "documents"
    ):
        raise ValueError("malformed document resource")
    segments = parts[5].split("/")
    if len(segments) < 2 or len(segments) % 2 or any(not part for part in segments):
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
            return 1 + max(
                (value_depth(item) for item in value["arrayValue"].get("values", [])),
                default=0,
            )
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
    remaining = (
        size
        - document_name_size(resource)
        - 32
        - _fields_size(fields)
        - _string_size("blob")
    )
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
    if (
        not isinstance(project, str)
        or not project
        or not re.fullmatch(r"[A-Za-z0-9_-]+", project)
    ):
        raise ValueError("malformed project")
    if (
        not isinstance(database, str)
        or not database
        or (database != "(default)" and not re.fullmatch(r"[A-Za-z0-9_-]+", database))
    ):
        raise ValueError("malformed database")
    if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
        raise ValueError("nonce must be 32 lowercase hexadecimal characters")
    catalog_document_max, catalog_depth_max = _catalog_limits()
    root = f"projects/{project}/databases/{database}/documents/oracle/{nonce}/limits-02"
    cases = (
        ("exact-document-boundary", "exact", catalog_document_max, _boundary_fields),
        ("over-document-boundary", "over", catalog_document_max + 1, _boundary_fields),
        (
            "exact-nested-boundary",
            "nested-exact",
            0,
            lambda r, _s, n: _nested_fields(catalog_depth_max, n, r),
        ),
        (
            "over-nested-boundary",
            "nested-over",
            0,
            lambda r, _s, n: _nested_fields(catalog_depth_max + 1, n, r),
        ),
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
            "fieldValueBytes": {
                name: _value_size(value) for name, value in fields.items()
            },
            "logicalBytes": logical,
            "depth": nested_depth(fields),
        }
        requests.append(
            {
                "kind": "preflight-typed-absence",
                "service": "firestore",
                "method": "GET",
                "path": "/v1/" + resource,
                "expect": {"status": 404, "typed": "NOT_FOUND"},
            }
        )
    controls = ("exact-document-boundary", "exact-nested-boundary")
    for label in (*controls, "over-document-boundary", "over-nested-boundary"):
        doc = documents[label]
        positive = label in controls
        requests.append(
            {
                "kind": "create-only-patch",
                "service": "firestore",
                "method": "PATCH",
                "path": "/v1/" + doc["resource"] + "?currentDocument.exists=false",
                "body": {"name": doc["resource"], "fields": doc["fields"]},
                "expect": {"positive": positive},
            }
        )
        requests.append(
            {
                "kind": "typed-readback",
                "service": "firestore",
                "method": "GET",
                "path": "/v1/" + doc["resource"],
                "expect": {
                    "status": 200 if positive else 404,
                    "typed": "OK" if positive else "NOT_FOUND",
                },
            }
        )
        if not positive:
            for control in controls:
                requests.append(
                    {
                        "kind": "unchanged-control-readback",
                        "service": "firestore",
                        "method": "GET",
                        "path": "/v1/" + documents[control]["resource"],
                        "after": label,
                        "expect": {"status": 200, "unchanged": True},
                    }
                )
    observation_count = len(requests)
    for doc in documents.values():
        index = len(requests) - observation_count
        requests.append(
            {
                "kind": "cleanup-ownership-read",
                "service": "firestore",
                "method": "GET",
                "path": "/v1/" + doc["resource"],
                "expect": {"statuses": [200, 404]},
            }
        )
        requests.append(
            {
                "kind": "cleanup-conditional-delete",
                "service": "firestore",
                "method": "DELETE",
                "path": "/v1/" + doc["resource"],
                "versionFrom": index,
                "expect": {"status": 200},
            }
        )
        requests.append(
            {
                "kind": "cleanup-verify-absence",
                "service": "firestore",
                "method": "GET",
                "path": "/v1/" + doc["resource"],
                "expect": {"status": 404, "typed": "NOT_FOUND"},
            }
        )
    for row in requests:
        row.setdefault("body", None)
        row.update(privileged=True, form=False)
        resource = row["path"].split("?", 1)[0].removeprefix("/v1/")
        doc = next(d for d in documents.values() if d["resource"] == resource)
        full_bytes = len(
            json.dumps({"name": resource, "fields": doc["fields"]}).encode()
        )
        # Allow document metadata and formatting, even for an unexpected success or existence.
        # The future transport must stop on overflow rather than treating a prefix as complete.
        row["responseByteLimit"] = (
            max(65536, full_bytes + 4096)
            if row["method"] in ("GET", "PATCH")
            else 65536
        )
    keys = ("service", "path", "method", "body", "privileged", "form", "versionFrom")
    operations = [{k: row[k] for k in keys if k in row} for row in requests]
    gate_plan = {
        "contract": "shared-local-v2",
        "nonce": nonce,
        "jobs": {
            "limits": {
                "resources": [d["resource"] for d in documents.values()],
                "observation": operations[:observation_count],
                "recovery": operations[observation_count:],
            }
        },
        "wallSeconds": 420,
        "recoverySeconds": 180,
        "observationRequests": observation_count,
        "intervalSeconds": 0.25,
        "requestCostMicrousd": 100,
        "costMicrousd": len(requests) * 100,
        "fixedCostMicrousd": 0,
        "coordinatorRequests": 0,
        "transport": "local-only",
    }
    request_sizes = [
        len(json.dumps(row["body"]).encode()) if row["body"] is not None else 0
        for row in requests
    ]
    response_total = sum(row["responseByteLimit"] for row in requests)
    return {
        "campaignId": CAMPAIGN,
        "catalog": {
            "documentMaximum": catalog_document_max,
            "fieldValueMaximum": FIELD_VALUE_MAX,
            "nestedDepthId": "FS-LIMIT-NESTED-MAP-ARRAY-DEPTH",
            "nestedDepthMaximum": catalog_depth_max,
        },
        "nonce": nonce,
        "documents": documents,
        "requests": requests,
        "localGatePlan": gate_plan,
        "budgetAccounting": {
            "requestUpperBound": len(requests),
            "requestBodyUpperBoundBytes": max(request_sizes),
            "transportRequestUpperBoundBytes": max(request_sizes),
            "responseUpperBoundBytes": response_total,
            "maxResponseBytes": max(row["responseByteLimit"] for row in requests),
            "recoverySeconds": gate_plan["recoverySeconds"],
            "productionReady": False,
            "legacyTransportCompatible": False,
        },
        "executionBlockers": [
            "large-body transport and per-response cap enforcement",
            "local artifact shadow and failure rehearsal",
            "production collector/comparator and O7 binding",
            "new manifest budgets; old 24-request/90-second plan is insufficient",
        ],
    }
