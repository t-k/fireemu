"""Credential-free, finite compiler for the Commit transform boundary."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from typing import Any

MAX_TRANSFORMS = 500
CAMPAIGN = "FS-DATA-WRITE-COMMIT-TRANSFORMS-03"
_NONCE = re.compile(r"^[0-9a-f]{32}$")
_TARGET = re.compile(r"^[A-Za-z0-9_-]+$")


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
    body: Any = None,
    expect: dict[str, Any],
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
        **extra,
    }


def _fields(resource: str) -> dict[str, dict[str, Any]]:
    return {
        "_sharedOwner": {"referenceValue": resource},
        "seed": {"integerValue": "0"},
    }


def _commit(resource: str, count: int, outcome: str) -> dict[str, Any]:
    first = count // 2
    second = count - first
    writes = []
    start = 0
    for size in (first, second):
        writes.append(
            {
                "transform": {
                    "document": resource,
                    "fieldTransforms": [
                        {"fieldPath": f"t{i}", "increment": {"integerValue": "1"}}
                        for i in range(start, start + size)
                    ],
                },
                "currentDocument": {"exists": True},
            }
        )
        start += size
    return {
        "writes": writes,
        "expect": {"outcome": outcome, "status": 200}
        if outcome == "accepted"
        else {"outcome": outcome, "statusClass": "4xx"},
    }


def compile_plan(project: str, database: str, nonce: str) -> dict[str, Any]:
    """Compile exact 500 and refused 501 transforms over two owned documents."""
    if not isinstance(project, str) or not _TARGET.fullmatch(project):
        raise ValueError("malformed project")
    if not isinstance(database, str) or (
        database != "(default)" and not _TARGET.fullmatch(database)
    ):
        raise ValueError("malformed database")
    if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
        raise ValueError("nonce must be 32 lowercase hexadecimal characters")

    scope = f"projects/{project}/databases/{database}/documents/oracle/{nonce}/commit-limits-03"
    resources = {label: f"{scope}/{label}" for label in ("exact-500", "over-501")}
    documents = {
        label: {
            "resource": resource,
            "fields": _fields(resource),
            "transformCount": count,
            "expectedFields": (
                {
                    **_fields(resource),
                    **{f"t{i}": {"integerValue": "1"} for i in range(count)},
                }
                if label == "exact-500"
                else _fields(resource)
            ),
        }
        for label, resource, count in (
            ("exact-500", resources["exact-500"], MAX_TRANSFORMS),
            ("over-501", resources["over-501"], MAX_TRANSFORMS + 1),
        )
    }

    observation: list[dict[str, Any]] = []
    for label in ("exact-500", "over-501"):
        resource = resources[label]
        observation.append(
            _operation(
                "preflight-typed-absence",
                "GET",
                "/v1/" + resource,
                expect={"status": 404, "typed": "NOT_FOUND"},
                resource=resource,
            )
        )
    for label in ("exact-500", "over-501"):
        resource = resources[label]
        observation.append(
            _operation(
                "create-only-patch",
                "PATCH",
                "/v1/" + resource + "?currentDocument.exists=false",
                body={
                    "name": resource,
                    "fields": copy.deepcopy(documents[label]["fields"]),
                },
                expect={"status": 200, "marker": "owned"},
                resource=resource,
            )
        )
    for label in ("exact-500", "over-501"):
        resource = resources[label]
        observation.append(
            _operation(
                "baseline-readback",
                "GET",
                "/v1/" + resource,
                expect={"status": 200, "postState": "baseline"},
                resource=resource,
            )
        )
    for label, count, outcome in (
        ("exact-500", MAX_TRANSFORMS, "accepted"),
        ("over-501", MAX_TRANSFORMS + 1, "refused"),
    ):
        resource = resources[label]
        body = _commit(resource, count, outcome)
        expectation = body.pop("expect")
        observation.append(
            _operation(
                "commit-transform",
                "POST",
                "/v1/projects/"
                + project
                + "/databases/"
                + database
                + "/documents:commit",
                body=body,
                expect=expectation,
                resources=[resource],
                transformCount=count,
            )
        )
        observation.append(
            _operation(
                "poststate-readback",
                "GET",
                "/v1/" + resource,
                expect={
                    "status": 200,
                    "postState": "transformed"
                    if outcome == "accepted"
                    else "unchanged",
                },
                resource=resource,
            )
        )
    # Preserve an accepted-document control after the refused Commit.
    observation.append(
        _operation(
            "poststate-control-readback",
            "GET",
            "/v1/" + resources["exact-500"],
            expect={"status": 200, "postState": "transformed"},
            resource=resources["exact-500"],
        )
    )

    recovery: list[dict[str, Any]] = []
    for label in ("exact-500", "over-501"):
        resource = resources[label]
        recovery.extend(
            (
                _operation(
                    "cleanup-ownership-read",
                    "GET",
                    "/v1/" + resource,
                    expect={"statuses": [200, 404], "marker": "owned"},
                    resource=resource,
                ),
                _operation(
                    "cleanup-conditional-delete",
                    "DELETE",
                    "/v1/" + resource,
                    expect={"status": 200, "marker": "owned"},
                    resource=resource,
                    versionFrom=len(recovery),
                ),
                _operation(
                    "cleanup-verify-absence",
                    "GET",
                    "/v1/" + resource,
                    expect={"status": 404, "typed": "NOT_FOUND"},
                    resource=resource,
                ),
            )
        )
    plan = {
        "schemaVersion": 1,
        "campaignId": CAMPAIGN,
        "project": project,
        "database": database,
        "nonce": nonce,
        "ownedScope": scope,
        "ownedResources": list(resources.values()),
        "documents": documents,
        "observation": observation,
        "recovery": recovery,
        "budget": {
            "observationRequests": len(observation),
            "recoveryRequests": len(recovery),
            "requestUpperBound": len(observation) + len(recovery),
            "resourceUpperBound": 2,
            "concurrencyUpperBound": 1,
        },
        "productionReady": False,
    }
    plan["planDigest"] = _digest(plan)
    return plan
