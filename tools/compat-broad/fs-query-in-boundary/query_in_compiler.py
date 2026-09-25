"""Credential-free compiler for the finite IN 30/31 query boundary case."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any

MAX_DISJUNCTIONS = 30
CAMPAIGN = "FS-DATA-QUERY-IN-BOUNDARY-04"
_NONCE = re.compile(r"^[0-9a-f]{32}$")
_TARGET = re.compile(r"^[A-Za-z0-9_-]+$")
_ROOT = Path(__file__).resolve().parents[3]
_CATALOG = _ROOT / "spec/limits/firestore-standard-query-2026-08-25.json"


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    ).hexdigest()


def _operation(
    kind: str,
    method: str,
    path: str,
    *,
    expect: dict[str, Any],
    body: Any = None,
    **extra: Any,
) -> dict[str, Any]:
    return {
        "kind": kind,
        "service": "firestore",
        "method": method,
        "path": path,
        "body": body,
        "privileged": True,
        "form": False,
        "expect": expect,
        "responseByteLimit": 65536,
        **extra,
    }


def _catalog_maximum() -> int:
    catalog = json.loads(_CATALOG.read_bytes())
    entries = {entry["id"]: entry for entry in catalog["limits"]}
    entry = entries["FS-QUERY-LIMIT-DNF-DISJUNCTIONS"]
    if entry["maximum"] != MAX_DISJUNCTIONS or entry["boundary"] != "inclusive-maximum":
        raise ValueError("query disjunction catalog drift")
    return entry["maximum"]


def _fixture_fields() -> dict[str, dict[str, Any]]:
    # This is the existing second/filters/in-30-31-state fixture. Ownership is
    # established by conditional creation plus exact field readback; no marker
    # field is added so the attached fixture remains unchanged.
    return {
        "n": {"integerValue": "2"},
        "g": {"stringValue": "q"},
        "a": {"mapValue": {"fields": {"b": {"integerValue": "7"}}}},
    }


def _document_path(project: str, database: str, *segments: str) -> str:
    if not segments or any(
        not isinstance(segment, str) or not _TARGET.fullmatch(segment)
        for segment in segments
    ):
        raise ValueError("document path segments must be non-empty target names")
    return f"projects/{project}/databases/{database}/documents/" + "/".join(segments)


def _validate_document_path(path: Any, project: str, database: str, label: str) -> None:
    if not isinstance(path, str):
        raise ValueError(f"{label} must be a document path")  # noqa: TRY004 -- malformed plans use one public validation error.
    prefix = f"projects/{project}/databases/{database}/documents/"
    if not path.startswith(prefix):
        raise ValueError(f"{label} is outside the compiled resource")
    segments = path[len(prefix) :].split("/")
    if (
        len(segments) == 0
        or any(not _TARGET.fullmatch(segment) for segment in segments)
        or len(segments) % 2
    ):
        raise ValueError(f"{label} must be a document path")


def _validate_plan_paths(plan: dict[str, Any]) -> None:
    project, database = plan.get("project"), plan.get("database")
    parent = plan.get("parent")
    document = plan.get("document")
    _validate_document_path(parent, project, database, "document parent")
    _validate_document_path(document, project, database, "document")
    if document != parent + "/cur/c":
        raise ValueError("document must be the compiled relative collection/document")
    if plan.get("ownedScope") != parent or plan.get("ownedResources") != [document]:
        raise ValueError("owned scope drift")
    for phase in ("observation", "recovery"):
        for operation in plan.get(phase, []):
            if operation.get("resource") not in (None, document):
                raise ValueError("operation resource escaped owned document")
            if operation.get("parent") not in (None, parent):
                raise ValueError("query parent escaped owned document")
            for resource in operation.get("targetResources", []):
                _validate_document_path(resource, project, database, "target resource")
                if resource != document:
                    raise ValueError("target resource escaped owned document")


def _query(parent: str, count: int) -> dict[str, Any]:
    return {
        "structuredQuery": {
            "from": [{"collectionId": "cur"}],
            "where": {
                "fieldFilter": {
                    "field": {"fieldPath": "n"},
                    "op": "IN",
                    "value": {
                        "arrayValue": {
                            "values": [{"integerValue": str(i)} for i in range(count)]
                        }
                    },
                }
            },
            "limit": 1,
        }
    }


def compile_plan(project: str, database: str, nonce: str) -> dict[str, Any]:
    """Compile exactly six observation and three recovery operations."""
    if not isinstance(project, str) or not _TARGET.fullmatch(project):
        raise ValueError("malformed project")
    if not isinstance(database, str) or (
        database != "(default)" and not _TARGET.fullmatch(database)
    ):
        raise ValueError("malformed database")
    if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
        raise ValueError("nonce must be 32 lowercase hexadecimal characters")
    catalog_maximum = _catalog_maximum()
    parent = _document_path(
        project, database, "oracle", nonce, "o4-query-in-boundary", "root"
    )
    document = parent + "/cur/c"
    fixture_fields = _fixture_fields()
    expected_document = {"name": document, "fields": copy.deepcopy(fixture_fields)}
    query_path = "/v1/" + parent + ":runQuery"

    observation = [
        _operation(
            "preflight-typed-absence",
            "GET",
            "/v1/" + document,
            expect={"status": 404, "typed": "NOT_FOUND"},
            resource=document,
        ),
        _operation(
            "create-only-patch",
            "PATCH",
            "/v1/" + document + "?currentDocument.exists=false",
            body={"name": document, "fields": copy.deepcopy(fixture_fields)},
            expect={"status": 200, "owned": True},
            resource=document,
        ),
        _operation(
            "positive-query",
            "POST",
            query_path,
            body=_query(parent, catalog_maximum),
            expect={
                "status": 200,
                "outcome": "accepted",
                "documents": [expected_document],
            },
            parent=parent,
            targetResources=[document],
            operandCount=catalog_maximum,
        ),
        _operation(
            "before-readback",
            "GET",
            "/v1/" + document,
            expect={"status": 200, "document": expected_document},
            resource=document,
        ),
        _operation(
            "diagnostic-query",
            "POST",
            query_path,
            body=_query(parent, catalog_maximum + 1),
            expect={
                "status": 400,
                "outcome": "refused",
                "typed": "INVALID_ARGUMENT",
            },
            parent=parent,
            targetResources=[document],
            operandCount=catalog_maximum + 1,
        ),
        _operation(
            "after-readback",
            "GET",
            "/v1/" + document,
            expect={"status": 200, "document": expected_document},
            resource=document,
        ),
    ]
    recovery = [
        _operation(
            "cleanup-ownership-read",
            "GET",
            "/v1/" + document,
            expect={"statuses": [200, 404], "owned": True},
            resource=document,
        ),
        _operation(
            "cleanup-conditional-delete",
            "DELETE",
            "/v1/" + document,
            expect={"status": 200, "owned": True},
            resource=document,
            versionFrom=0,
        ),
        _operation(
            "cleanup-verify-absence",
            "GET",
            "/v1/" + document,
            expect={"status": 404, "typed": "NOT_FOUND"},
            resource=document,
        ),
    ]
    plan = {
        "schemaVersion": 1,
        "campaignId": CAMPAIGN,
        "catalogId": "FS-QUERY-LIMIT-DNF-DISJUNCTIONS",
        "catalogMaximum": catalog_maximum,
        "project": project,
        "database": database,
        "nonce": nonce,
        "ownedScope": parent,
        "parent": parent,
        "document": document,
        "ownedResources": [document],
        "fixtureId": "second/filters/in-30-31-state",
        "fixtureFields": fixture_fields,
        "expectedPositiveDocument": expected_document,
        "ownership": "conditional-create-plus-exact-fields",
        "observation": observation,
        "recovery": recovery,
        "budget": {
            "observationRequests": 6,
            "recoveryRequests": 3,
            "requestUpperBound": 9,
            "resourceUpperBound": 1,
            "concurrencyUpperBound": 1,
        },
        "productionReady": False,
    }
    plan["planDigest"] = _digest(plan)
    return plan


def validate_plan(plan: dict[str, Any]) -> None:
    """Reject any changed request, scope, fixture, budget, or digest input."""
    if not isinstance(plan, dict):
        raise TypeError("plan must be an object")
    _validate_plan_paths(plan)
    try:
        expected = compile_plan(plan["project"], plan["database"], plan["nonce"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("invalid compiled plan inputs") from error
    if plan != expected:
        raise ValueError("compiled plan drift")
    unsigned = {key: value for key, value in plan.items() if key != "planDigest"}
    if plan.get("planDigest") != _digest(unsigned):
        raise ValueError("compiled plan digest drift")
