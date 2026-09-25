"""Credential-free compiler for the bounded PartitionQuery and cursor case set.

This module compiles a fixed observation plan. It opens no socket, reads no
credential, mutates no index or Rules, and claims no production compatibility.
Every owned document lives in one nonce-scoped tree. Production requires a
database parent for PartitionQuery, so the partition operations and the
collection-group readbacks address the database and are kept owned by a
nonce-unique collection group whose only members are this run's own documents.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from typing import Any

CAMPAIGN = "FS-QUERY-PARTITION-CURSOR-04"
GROUP_PREFIX = "o4pc"
CURSOR_COLLECTION = "cur"
PARTITION_PREFIX = "part"
PARTITION_DOCUMENTS = 12
CURSOR_DOCUMENTS = 8
PARTITION_BUCKETS = 3
OBSERVATION_COUNT = 31
RECOVERY_COUNT = 6
RECONSTRUCTION_SLOTS = 2
RESPONSE_BYTE_LIMIT = 65536

_NONCE = re.compile(r"^[0-9a-f]{32}$")
_TARGET = re.compile(r"^[A-Za-z0-9_-]+$")
_ORDER_NAME_ASC = [{"field": {"fieldPath": "__name__"}, "direction": "ASCENDING"}]


def digest(value: Any) -> str:
    """Digest a plan fragment; non-finite numbers are never accepted."""
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    ).hexdigest()


def _document_path(project: str, database: str, *segments: str) -> str:
    if not segments or any(
        not isinstance(segment, str) or not _TARGET.fullmatch(segment)
        for segment in segments
    ):
        raise ValueError("document path segments must be non-empty target names")
    return _database_root(project, database) + "/" + "/".join(segments)


def _database_root(project: str, database: str) -> str:
    return f"projects/{project}/databases/{database}/documents"


def _validate_document_path(path: Any, project: str, database: str, label: str) -> None:
    if not isinstance(path, str):
        raise ValueError(f"{label} must be a document path")  # noqa: TRY004 -- malformed plans use one public validation error.
    prefix = _database_root(project, database) + "/"
    if not path.startswith(prefix):
        raise ValueError(f"{label} is outside the compiled resource")
    segments = path[len(prefix) :].split("/")
    if any(not _TARGET.fullmatch(segment) for segment in segments) or len(segments) % 2:
        raise ValueError(f"{label} must be a document path")


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
        "responseByteLimit": RESPONSE_BYTE_LIMIT,
        **extra,
    }


def group_collection(nonce: str) -> str:
    """The collection group is nonce-unique so a database-wide PartitionQuery,
    which production requires, still matches only this run's own documents."""
    if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
        raise ValueError("nonce must be 32 lowercase hexadecimal characters")
    return GROUP_PREFIX + nonce


def _fields(ordinal: int) -> dict[str, Any]:
    return {
        "n": {"integerValue": str(ordinal)},
        "g": {"stringValue": "a" if ordinal % 2 == 0 else "b"},
    }


def _partition_documents(scope: str, group: str) -> list[str]:
    return [
        f"{scope}/{PARTITION_PREFIX}/p{index // (PARTITION_DOCUMENTS // PARTITION_BUCKETS)}"
        f"/{group}/d{index:02d}"
        for index in range(PARTITION_DOCUMENTS)
    ]


def _cursor_documents(scope: str) -> list[str]:
    return [
        f"{scope}/{CURSOR_COLLECTION}/c{index}" for index in range(CURSOR_DOCUMENTS)
    ]


def _expected(name: str, ordinal: int) -> dict[str, Any]:
    return {"name": name, "fields": _fields(ordinal)}


def _group_query(group: str) -> dict[str, Any]:
    return {
        "from": [{"collectionId": group, "allDescendants": True}],
        "orderBy": copy.deepcopy(_ORDER_NAME_ASC),
    }


def _cursor_query(
    *, order_field: str = "n", direction: str = "ASCENDING", **extra: Any
) -> dict[str, Any]:
    query: dict[str, Any] = {
        "from": [{"collectionId": CURSOR_COLLECTION}],
        "orderBy": [{"field": {"fieldPath": order_field}, "direction": direction}],
    }
    query.update(extra)
    return query


def _integer(value: int) -> dict[str, Any]:
    return {"integerValue": str(value)}


def _accepted_partition(count: int, **extra: Any) -> dict[str, Any]:
    return {
        "status": 200,
        "outcome": "accepted",
        "maxPartitions": count,
        "cursorsOrdered": True,
        "documentsAsserted": False,
        **extra,
    }


def _refused() -> dict[str, Any]:
    return {"status": 400, "outcome": "refused", "typed": "INVALID_ARGUMENT"}


def _refused_open() -> dict[str, Any]:
    """A typed refusal whose status code is recorded rather than pinned.

    An order on an indexed field can fail index admission before PartitionQuery
    shape admission, and which check answers first is one of the conditions this
    campaign is meant to observe rather than assume.
    """
    return {"status": 400, "outcome": "refused", "typedOpen": True}


def _partition_body(query: dict[str, Any], count: str, **extra: Any) -> dict[str, Any]:
    return {"structuredQuery": query, "partitionCount": count, **extra}


def _setup_operations(
    scope: str, root: str, database_root: str, group: str, seeded: list[str]
) -> list[dict[str, Any]]:
    group_documents = [
        _expected(name, index)
        for index, name in enumerate(seeded[:PARTITION_DOCUMENTS])
    ]
    cursor_documents = [
        _expected(name, index)
        for index, name in enumerate(seeded[PARTITION_DOCUMENTS:])
    ]
    return [
        _operation(
            "preflight-typed-absence",
            "GET",
            "/v1/" + root,
            expect={"status": 404, "typed": "NOT_FOUND"},
            resource=root,
        ),
        _operation(
            "create-only-patch",
            "PATCH",
            "/v1/" + root + "?currentDocument.exists=false",
            body={"name": root, "fields": {"marker": {"stringValue": CAMPAIGN}}},
            expect={"status": 200, "owned": True},
            resource=root,
        ),
        _operation(
            "seed-commit",
            "POST",
            "/v1/" + database_root + ":commit",
            body={
                "writes": [
                    {
                        "update": {
                            "name": name,
                            "fields": _fields(
                                index % PARTITION_DOCUMENTS
                                if index < PARTITION_DOCUMENTS
                                else index - PARTITION_DOCUMENTS
                            ),
                        },
                        "currentDocument": {"exists": False},
                    }
                    for index, name in enumerate(seeded)
                ]
            },
            expect={"status": 200, "owned": True, "writeResults": len(seeded)},
            parent=database_root,
            targetResources=list(seeded),
        ),
        _operation(
            "baseline-group-name-order",
            "POST",
            "/v1/" + database_root + ":runQuery",
            body={"structuredQuery": _group_query(group)},
            expect={"status": 200, "outcome": "accepted", "documents": group_documents},
            parent=database_root,
            targetResources=seeded[:PARTITION_DOCUMENTS],
        ),
        _operation(
            "baseline-collection-order",
            "POST",
            "/v1/" + scope + ":runQuery",
            body={"structuredQuery": _cursor_query()},
            expect={
                "status": 200,
                "outcome": "accepted",
                "documents": cursor_documents,
            },
            parent=scope,
            targetResources=seeded[PARTITION_DOCUMENTS:],
        ),
    ]


def _partition_operations(
    scope: str, database_root: str, group: str, seeded: list[str]
) -> list[dict[str, Any]]:
    # Production requires a database parent for PartitionQuery, so every accepted
    # partition operation is database-wide and isolation comes from the
    # nonce-unique collection group rather than from a document parent.
    path = "/v1/" + database_root + ":partitionQuery"
    owned_group = seeded[:PARTITION_DOCUMENTS]
    filtered = _group_query(group)
    filtered["where"] = {
        "fieldFilter": {
            "field": {"fieldPath": "n"},
            "op": "GREATER_THAN",
            "value": _integer(0),
        }
    }
    limited = _group_query(group)
    limited["limit"] = 10
    ordered = _group_query(group)
    ordered["orderBy"] = [{"field": {"fieldPath": "n"}, "direction": "ASCENDING"}]
    offset_query = _group_query(group)
    offset_query["offset"] = 1
    scoped = _group_query(group)
    scoped["from"] = [{"collectionId": group}]
    return [
        _operation(
            "partition-count-1",
            "POST",
            path,
            body=_partition_body(_group_query(group), "1"),
            expect=_accepted_partition(1),
            parent=database_root,
            targetResources=owned_group,
        ),
        _operation(
            "partition-count-4",
            "POST",
            path,
            body=_partition_body(_group_query(group), "4"),
            expect=_accepted_partition(4),
            parent=database_root,
            targetResources=owned_group,
        ),
        _operation(
            "partition-count-4-page-size-2",
            "POST",
            path,
            body=_partition_body(_group_query(group), "4", pageSize=2),
            expect=_accepted_partition(4),
            parent=database_root,
            targetResources=owned_group,
        ),
        _operation(
            "partition-page-token-continuation",
            "POST",
            path,
            body=_partition_body(_group_query(group), "4", pageSize=2),
            expect=_accepted_partition(4, skippable=True),
            parent=database_root,
            targetResources=owned_group,
            pageTokenFrom=7,
        ),
        _operation(
            "partition-not-collection-group",
            "POST",
            path,
            body=_partition_body(scoped, "2"),
            expect=_refused(),
            parent=database_root,
            targetResources=owned_group,
        ),
        _operation(
            "partition-with-filter",
            "POST",
            path,
            body=_partition_body(filtered, "2"),
            expect=_refused(),
            parent=database_root,
            targetResources=owned_group,
        ),
        _operation(
            "partition-count-zero",
            "POST",
            path,
            body=_partition_body(_group_query(group), "0"),
            expect=_refused(),
            parent=database_root,
            targetResources=owned_group,
        ),
        _operation(
            "partition-with-limit",
            "POST",
            path,
            body=_partition_body(limited, "2"),
            expect=_refused(),
            parent=database_root,
            targetResources=owned_group,
        ),
        _operation(
            "partition-with-offset",
            "POST",
            path,
            body=_partition_body(offset_query, "2"),
            expect=_refused(),
            parent=database_root,
            targetResources=owned_group,
        ),
        _operation(
            "partition-order-non-name",
            "POST",
            path,
            body=_partition_body(ordered, "2"),
            expect=_refused_open(),
            parent=database_root,
            targetResources=owned_group,
        ),
        _operation(
            "partition-document-parent",
            "POST",
            "/v1/" + scope + ":partitionQuery",
            body=_partition_body(_group_query(group), "2"),
            expect=_refused(),
            parent=scope,
            targetResources=owned_group,
        ),
        _operation(
            "partition-reconstruction-range-0",
            "POST",
            "/v1/" + database_root + ":runQuery",
            body={"structuredQuery": _group_query(group)},
            expect={
                "status": 200,
                "outcome": "accepted",
                "documentsAsserted": False,
                "reconstruction": True,
                "skippable": True,
            },
            parent=database_root,
            targetResources=owned_group,
            cursorFrom=5,
            reconstructionSlot=0,
        ),
        _operation(
            "partition-reconstruction-range-1",
            "POST",
            "/v1/" + database_root + ":runQuery",
            body={"structuredQuery": _group_query(group)},
            expect={
                "status": 200,
                "outcome": "accepted",
                "documentsAsserted": False,
                "reconstruction": True,
                "skippable": True,
            },
            parent=database_root,
            targetResources=owned_group,
            cursorFrom=5,
            reconstructionSlot=1,
        ),
    ]


def _cursor_operations(
    scope: str, group: str, seeded: list[str]
) -> list[dict[str, Any]]:
    path = "/v1/" + scope + ":runQuery"
    cursor = seeded[PARTITION_DOCUMENTS:]
    expected = [_expected(name, index) for index, name in enumerate(cursor)]
    reference = {"referenceValue": cursor[3]}
    foreign = {"referenceValue": f"{scope}/{group}/absent"}

    def case(
        kind: str, query: dict[str, Any], documents: list[dict[str, Any]]
    ) -> dict[str, Any]:
        return _operation(
            kind,
            "POST",
            path,
            body={"structuredQuery": query},
            expect={"status": 200, "outcome": "accepted", "documents": documents},
            parent=scope,
            targetResources=[document["name"] for document in documents],
        )

    def refusal(kind: str, query: dict[str, Any]) -> dict[str, Any]:
        return _operation(
            kind,
            "POST",
            path,
            body={"structuredQuery": query},
            expect=_refused(),
            parent=scope,
            targetResources=[],
        )

    descending = case(
        "cursor-descending-limit",
        _cursor_query(direction="DESCENDING", limit=3),
        list(reversed(expected))[:3],
    )
    descending["sdkEquivalent"] = "limitToLast(3) over an ascending order"
    return [
        case(
            "cursor-start-at-value",
            _cursor_query(startAt={"values": [_integer(3)], "before": True}),
            expected[3:],
        ),
        case(
            "cursor-start-after-value",
            _cursor_query(startAt={"values": [_integer(3)], "before": False}),
            expected[4:],
        ),
        case(
            "cursor-end-at-value",
            _cursor_query(endAt={"values": [_integer(3)], "before": False}),
            expected[:4],
        ),
        case(
            "cursor-end-before-value",
            _cursor_query(endAt={"values": [_integer(3)], "before": True}),
            expected[:3],
        ),
        case(
            "cursor-document-reference-start-at",
            _cursor_query(
                order_field="__name__",
                startAt={"values": [reference], "before": True},
            ),
            expected[3:],
        ),
        case(
            "cursor-offset-limit",
            _cursor_query(offset=2, limit=3),
            expected[2:5],
        ),
        case(
            "cursor-start-at-with-offset",
            _cursor_query(
                startAt={"values": [_integer(2)], "before": True}, offset=1, limit=2
            ),
            expected[3:5],
        ),
        descending,
        refusal(
            "cursor-too-many-values",
            # Firestore normalizes a single explicit order into [n, __name__],
            # so two values would still fit. The first two values are type
            # correct for those positions and only the third exceeds the
            # normalized order length, which isolates the cardinality rule from
            # the cursor value-type rule covered by the next case.
            _cursor_query(
                startAt={
                    "values": [_integer(3), reference, _integer(9)],
                    "before": True,
                }
            ),
        ),
        refusal(
            "cursor-reference-type-mismatch",
            _cursor_query(
                order_field="__name__",
                startAt={"values": [{"stringValue": "c3"}], "before": True},
            ),
        ),
        refusal(
            "cursor-foreign-reference",
            _cursor_query(
                order_field="__name__",
                startAt={"values": [foreign], "before": True},
            ),
        ),
        refusal("cursor-negative-offset", _cursor_query(offset=-1)),
    ]


def _recovery_operations(
    scope: str, root: str, database_root: str, group: str, seeded: list[str]
) -> list[dict[str, Any]]:
    return [
        _operation(
            "cleanup-ownership-read",
            "GET",
            "/v1/" + root,
            expect={"statuses": [200, 404], "owned": True},
            resource=root,
        ),
        _operation(
            "cleanup-seed-delete",
            "POST",
            "/v1/" + database_root + ":commit",
            body={
                "writes": [
                    {"delete": name, "currentDocument": {"updateTime": None}}
                    for name in seeded
                ]
            },
            expect={
                "status": 200,
                "owned": True,
                "writeResults": len(seeded),
                "updateTimes": False,
            },
            parent=database_root,
            targetResources=list(seeded),
            versionFrom=2,
        ),
        _operation(
            "cleanup-root-delete",
            "DELETE",
            "/v1/" + root,
            expect={"status": 200, "owned": True},
            resource=root,
            versionFrom=1,
        ),
        _operation(
            "cleanup-verify-group-absence",
            "POST",
            "/v1/" + database_root + ":runQuery",
            body={"structuredQuery": _group_query(group)},
            expect={"status": 200, "outcome": "accepted", "documents": []},
            parent=database_root,
            targetResources=[],
        ),
        _operation(
            "cleanup-verify-collection-absence",
            "POST",
            "/v1/" + scope + ":runQuery",
            body={"structuredQuery": _cursor_query()},
            expect={"status": 200, "outcome": "accepted", "documents": []},
            parent=scope,
            targetResources=[],
        ),
        _operation(
            "cleanup-verify-root-absence",
            "GET",
            "/v1/" + root,
            expect={"status": 404, "typed": "NOT_FOUND"},
            resource=root,
        ),
    ]


def compile_plan(project: str, database: str, nonce: str) -> dict[str, Any]:
    """Compile exactly thirty-one observation and six recovery operations."""
    if not isinstance(project, str) or not _TARGET.fullmatch(project):
        raise ValueError("malformed project")
    if not isinstance(database, str) or (
        database != "(default)" and not _TARGET.fullmatch(database)
    ):
        raise ValueError("malformed database")
    if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
        raise ValueError("nonce must be 32 lowercase hexadecimal characters")
    database_root = _database_root(project, database)
    scope = _document_path(
        project, database, "oracle", nonce, "o4-query-partition-cursor", "root"
    )
    group = group_collection(nonce)
    seeded = _partition_documents(scope, group) + _cursor_documents(scope)
    observation = (
        _setup_operations(scope, scope, database_root, group, seeded)
        + _partition_operations(scope, database_root, group, seeded)
        + _cursor_operations(scope, group, seeded)
        + [
            _operation(
                "post-state-group-readback",
                "POST",
                "/v1/" + database_root + ":runQuery",
                body={"structuredQuery": _group_query(group)},
                expect={
                    "status": 200,
                    "outcome": "accepted",
                    "documents": [
                        _expected(name, index)
                        for index, name in enumerate(seeded[:PARTITION_DOCUMENTS])
                    ],
                },
                parent=database_root,
                targetResources=seeded[:PARTITION_DOCUMENTS],
            )
        ]
    )
    plan = {
        "schemaVersion": 1,
        "campaignId": CAMPAIGN,
        "project": project,
        "database": database,
        "nonce": nonce,
        "ownedScope": scope,
        "databaseRoot": database_root,
        "groupCollection": group,
        "cursorCollection": CURSOR_COLLECTION,
        "ownedResources": [scope, *seeded],
        "ownership": "conditional-create-plus-exact-fields",
        "observation": observation,
        "recovery": _recovery_operations(scope, scope, database_root, group, seeded),
        "budget": {
            "observationRequests": OBSERVATION_COUNT,
            "recoveryRequests": RECOVERY_COUNT,
            "requestUpperBound": OBSERVATION_COUNT + RECOVERY_COUNT,
            "resourceUpperBound": PARTITION_DOCUMENTS + CURSOR_DOCUMENTS + 1,
            "concurrencyUpperBound": 1,
            "reconstructionSlots": RECONSTRUCTION_SLOTS,
        },
        "productionExecuted": False,
        "productionReady": False,
    }
    plan["planDigest"] = digest(plan)
    return plan


def _validate_plan_paths(plan: dict[str, Any]) -> None:
    project, database = plan.get("project"), plan.get("database")
    scope = plan.get("ownedScope")
    _validate_document_path(scope, project, database, "owned scope")
    owned = plan.get("ownedResources")
    if not isinstance(owned, list) or not owned or owned[0] != scope:
        raise ValueError("owned scope drift")
    for resource in owned[1:]:
        _validate_document_path(resource, project, database, "owned resource")
        if not resource.startswith(scope + "/"):
            raise ValueError("owned resource escaped the nonce scope")
    allowed = {scope, plan.get("databaseRoot")}
    for phase in ("observation", "recovery"):
        for operation in plan.get(phase, []):
            if operation.get("resource") not in (None, scope):
                raise ValueError("operation resource escaped the owned scope")
            if operation.get("parent") not in {None, *allowed}:
                raise ValueError("query parent escaped the compiled parents")
            for resource in operation.get("targetResources", []):
                if resource not in owned:
                    raise ValueError("target resource escaped the owned scope")
            for write in (operation.get("body") or {}).get("writes", []):
                name = write.get("delete") or (write.get("update") or {}).get("name")
                if name not in owned:
                    raise ValueError("write target escaped the owned scope")


def validate_plan(plan: Any) -> None:
    """Reject any changed request, scope, fixture, budget or digest input."""
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
    if plan.get("planDigest") != digest(unsigned):
        raise ValueError("compiled plan digest drift")
