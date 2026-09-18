"""Compile the offline Firestore REST plan for FS-WRITE-LIMITS-03.

The campaign covers two residues of the FS-DATA-WRITE closure audit:

* R3, BatchWrite continuation past a malformed or undecodable item. Three cases
  separate the three hypotheses: a per-item failure with a valid prefix and
  suffix, a value the request decoder cannot read at all, and the duplicate
  document that production is already known to answer with a whole-request 400.
* R4, the three configuration-independent write-path catalog limits at their
  exact boundary pairs: collection id bytes, subcollection depth, and document
  name bytes.

The three index-entry limits are deliberately absent: their boundary values
depend on the index configuration in force and that decision belongs to the
owner. The four limits the catalog declares unsupported are absent for the same
reason.

This module only creates typed request descriptions. It never opens a network
connection, holds no credential, and authorizes no production execution.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

CAMPAIGN = "FS-WRITE-LIMITS-03"
COLLECTION_ID_MAX = 1_500
SUBCOLLECTION_DEPTH_MAX = 100
DOCUMENT_NAME_MAX = 6_144
# Not observed by this campaign, but every created document must stay inside it
# or the refusal under test is confounded. See `_check_no_confound`.
INDEX_ENTRY_BYTES_MAX = 7_680
INDEXED_VALUE_TRUNCATION = 1_500
_NONCE = re.compile(r"^[0-9a-f]{32}$")
_ROOT = Path(__file__).resolve().parents[3]
_CATALOG = _ROOT / "spec/limits/firestore-standard-2026-08-25.json"

# Every owned document carries this many prefix pairs: (oracle, nonce) and
# (limits-03, <id>). The lock declared by the manifest is ancestor-aware, so the
# deeper cases stay inside the same owned namespace.
PREFIX_PAIRS = 2


def _catalog_limits() -> dict[str, int]:
    catalog = json.loads(_CATALOG.read_bytes())
    entries = {entry["id"]: entry for entry in catalog["limits"]}
    declared = {
        "FS-LIMIT-COLLECTION-ID": COLLECTION_ID_MAX,
        "FS-LIMIT-SUBCOLLECTION-DEPTH": SUBCOLLECTION_DEPTH_MAX,
        "FS-LIMIT-DOCUMENT-NAME-BYTES": DOCUMENT_NAME_MAX,
    }
    for identifier, expected in declared.items():
        entry = entries[identifier]
        if entry["maximum"] != expected:
            raise ValueError(f"catalog drift on {identifier}")
        if entry["implemented"] != "implemented":
            raise ValueError(f"{identifier} is not declared implemented")
        if entry["enforcementStage"] != "request":
            raise ValueError(f"{identifier} is not a request-stage limit")
    return declared


def resource_name_bytes(resource: str) -> int:
    """UTF-8 bytes of the full protocol resource name.

    This is the quantity `FS-LIMIT-DOCUMENT-NAME-BYTES` is measured on, and it
    depends on the project and database ids, so the local and production plans
    pad by different amounts to reach the same boundary.
    """
    return len(resource.encode("utf-8"))


def storage_name_bytes(resource: str) -> int:
    """`document_name_size` from `crates/fireemu-core-firestore/src/size.rs`.

    This is the quantity index entries are charged, and it is not the same as
    the protocol resource-name byte count that `FS-LIMIT-DOCUMENT-NAME-BYTES`
    is measured on.
    """
    relative = resource.split("/documents/", 1)[1]
    return 16 + sum(len(segment.encode()) + 1 for segment in relative.split("/"))


def _indexed_value_bytes(value: dict[str, Any]) -> int:
    if "referenceValue" in value:
        size = storage_name_bytes(value["referenceValue"])
    elif "integerValue" in value:
        size = 8
    elif "stringValue" in value:
        size = len(value["stringValue"].encode()) + 1
    elif "arrayValue" in value:
        members = value["arrayValue"].get("values")
        # The undecodable case carries a value the server never indexes.
        size = (
            sum(_indexed_value_bytes(member) for member in members)
            if isinstance(members, list)
            else 0
        )
    else:
        raise ValueError("unsupported indexed value")
    return min(size, INDEXED_VALUE_TRUNCATION)


def largest_index_entry_bytes(resource: str, fields: dict[str, Any]) -> int:
    """Largest automatic single-field collection index entry for a document."""
    parent = "/".join(resource.split("/")[:-2])
    parent_bytes = (
        storage_name_bytes(parent) if parent.split("/documents/", 1)[-1] else 0
    )
    base = storage_name_bytes(resource) + parent_bytes + 32
    return base + max(
        len(name.encode()) + 1 + _indexed_value_bytes(value)
        for name, value in fields.items()
    )


def subcollection_depth(resource: str) -> int:
    relative = resource.split("/documents/", 1)[1]
    segments = relative.split("/")
    if len(segments) % 2 != 0 or any(not segment for segment in segments):
        raise ValueError("malformed document resource")
    return len(segments) // 2


def _owner(resource: str) -> dict[str, Any]:
    return {"referenceValue": resource}


def _fields(resource: str, value: int) -> dict[str, Any]:
    return {"_sharedOwner": _owner(resource), "v": {"integerValue": str(value)}}


def _undecodable_fields(resource: str) -> dict[str, Any]:
    # A JSON value that cannot be decoded into the protobuf repeated field. It
    # is well-formed JSON, so the question this asks production is whether the
    # request decoder refuses the whole request or reports one item.
    return {
        "_sharedOwner": _owner(resource),
        "bad": {"arrayValue": {"values": "not-an-array"}},
    }


def _depth_resource(root: str, leaf: str, pairs: int) -> str:
    """Return a document resource with exactly `pairs` collection levels."""
    if pairs < PREFIX_PAIRS:
        raise ValueError("depth case cannot be shallower than the owned prefix")
    # `{root}/{leaf}` is already PREFIX_PAIRS pairs: (oracle, nonce) and
    # (limits-03, leaf).
    return f"{root}/{leaf}" + "/c/d" * (pairs - PREFIX_PAIRS)


def _padded_resource(root: str, leaf: str, target: int) -> str:
    """Return a document resource whose UTF-8 byte length is exactly `target`.

    Padding is spread over whole (collection, document) pairs so that no single
    identifier reaches 1500 bytes and the subcollection depth stays small. Only
    the document identifiers are padded; each padding collection id is one byte.
    """
    base = f"{root}/{leaf}"
    remaining = target - resource_name_bytes(base)
    if remaining <= 0:
        raise ValueError("document name target is below the owned prefix")
    # Each padding pair costs "/p/" plus the padded document id.
    per_pair_overhead = 3
    widest = COLLECTION_ID_MAX - 1
    pairs = -(-remaining // (widest + per_pair_overhead))
    while True:
        payload = remaining - pairs * per_pair_overhead
        if payload >= pairs:
            break
        pairs -= 1
        if pairs < 1:
            raise ValueError("document name target cannot be padded")
    widths = [payload // pairs] * pairs
    for index in range(payload - sum(widths)):
        widths[index] += 1
    if any(not 1 <= width <= widest for width in widths):
        raise ValueError("padding segment outside identifier limits")
    resource = base + "".join(f"/p/{'z' * width}" for width in widths)
    if resource_name_bytes(resource) != target:
        raise ValueError("document name padding did not reach the target")
    return resource


def _preflight(resource: str) -> dict[str, Any]:
    return {
        "kind": "preflight-typed-absence",
        "service": "firestore",
        "method": "GET",
        "path": "/v1/" + resource,
        "body": None,
        "expect": {"status": 404, "typed": "NOT_FOUND"},
    }


def _readback(resource: str, *, present: bool, kind: str) -> dict[str, Any]:
    return {
        "kind": kind,
        "service": "firestore",
        "method": "GET",
        "path": "/v1/" + resource,
        "body": None,
        "expect": {
            "status": 200 if present else 404,
            "typed": "OK" if present else "NOT_FOUND",
        },
    }


def _create_only_patch(document: dict[str, Any], *, positive: bool) -> dict[str, Any]:
    resource = document["resource"]
    return {
        "kind": "create-only-patch",
        "service": "firestore",
        "method": "PATCH",
        "path": "/v1/" + resource + "?currentDocument.exists=false",
        "body": {"name": resource, "fields": document["fields"]},
        "expect": {"positive": positive},
    }


def _conditional_create(resource: str, fields: dict[str, Any]) -> dict[str, Any]:
    return {
        "update": {"name": resource, "fields": fields},
        "currentDocument": {"exists": False},
    }


def compile_limits_plan(project: str, database: str, nonce: str) -> dict[str, Any]:
    """Compile the six cases and their bounded ordered offline request plan."""
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
    catalog = _catalog_limits()
    prefix = f"projects/{project}/databases/{database}/documents"
    root = f"{prefix}/oracle/{nonce}/limits-03"
    batch_path = "/v1/" + prefix + ":batchWrite"

    documents: dict[str, Any] = {}

    def add(
        label: str, resource: str, fields: dict[str, Any] | None, *, owned: bool = True
    ) -> dict[str, Any]:
        document = {
            "resource": resource,
            "fields": fields,
            "nameBytes": resource_name_bytes(resource),
            "depth": subcollection_depth(resource),
            # A name that exceeds a request-stage identifier limit is not a
            # resource the API will read back, so it cannot be an owned Gate
            # resource: typed absence is unprovable for it. It is probed, not
            # owned, and an unexpected acceptance stops the campaign through the
            # Gate's own creation-proof check and is handed to the recovery
            # owner.
            "owned": owned,
        }
        documents[label] = document
        return document

    # R3: BatchWrite continuation.
    malformed = [
        add(f"batch-malformed-{part}", f"{root}/bw-a-{index}", None)
        for index, part in ((0, "prefix"), (2, "suffix"))
    ]
    undecodable = [
        add(f"batch-undecodable-{part}", f"{root}/bw-b-{index}", None)
        for index, part in ((0, "prefix"), (1, "middle"), (2, "suffix"))
    ]
    duplicate = [
        add(f"batch-duplicate-{part}", f"{root}/bw-c-{index}", None)
        for index, part in ((0, "first"), (1, "second"))
    ]
    for index, document in enumerate(malformed + undecodable + duplicate):
        document["fields"] = _fields(document["resource"], index)
    undecodable[1]["fields"] = _undecodable_fields(undecodable[1]["resource"])

    # R4: the three configuration-independent catalog limits.
    limits: list[dict[str, Any]] = [
        {
            "id": "FS-LIMIT-COLLECTION-ID",
            "label": "collection-id",
            "accept": f"{root}/cid-exact/{'i' * COLLECTION_ID_MAX}/x",
            "refuse": f"{root}/cid-over/{'i' * (COLLECTION_ID_MAX + 1)}/x",
            "boundary": [COLLECTION_ID_MAX, COLLECTION_ID_MAX + 1],
            "probe": "create",
        },
        {
            "id": "FS-LIMIT-SUBCOLLECTION-DEPTH",
            "label": "subcollection-depth",
            "accept": _depth_resource(root, "depth-exact", SUBCOLLECTION_DEPTH_MAX),
            "refuse": _depth_resource(root, "depth-over", SUBCOLLECTION_DEPTH_MAX + 1),
            "boundary": [SUBCOLLECTION_DEPTH_MAX, SUBCOLLECTION_DEPTH_MAX + 1],
            "probe": "create",
        },
        {
            "id": "FS-LIMIT-DOCUMENT-NAME-BYTES",
            "label": "document-name",
            "accept": _padded_resource(root, "name-exact", DOCUMENT_NAME_MAX),
            "refuse": _padded_resource(root, "name-over", DOCUMENT_NAME_MAX + 1),
            "boundary": [DOCUMENT_NAME_MAX, DOCUMENT_NAME_MAX + 1],
            # A document named at 6144 bytes cannot be created at all while the
            # automatic single-field indexes are in force: its smallest possible
            # index entry is 11040 bytes against a 7680-byte limit, because the
            # entry charges the document name and its parent's name. So this
            # boundary is probed by requests that carry the name without
            # creating an index entry. Observing it with a create needs the same
            # index configuration decision that gates the index-entry limits.
            "probe": "name-only",
        },
    ]
    for index, limit in enumerate(limits):
        for side in ("accept", "refuse"):
            resource = limit[side]
            document = add(
                f"{limit['label']}-{side}",
                resource,
                None,
                owned=side == "accept" and limit["probe"] == "create",
            )
            document["fields"] = _fields(resource, 100 + index)
            document["limitId"] = limit["id"]

    _check_no_confound(documents, limits)

    owned = [document for document in documents.values() if document["owned"]]
    requests: list[dict[str, Any]] = []
    for document in owned:
        requests.append(_preflight(document["resource"]))

    # R3-1: a write with no operation between two valid create-only writes.
    requests.append(
        {
            "kind": "batch-write",
            "case": "batch-malformed-middle",
            "service": "firestore",
            "method": "POST",
            "path": batch_path,
            "body": {
                "writes": [
                    _conditional_create(
                        malformed[0]["resource"], malformed[0]["fields"]
                    ),
                    {},
                    _conditional_create(
                        malformed[1]["resource"], malformed[1]["fields"]
                    ),
                ]
            },
            "expect": {
                "status": 200,
                "itemCodes": [0, 3, 0],
                "landed": [malformed[0]["resource"], malformed[1]["resource"]],
            },
        }
    )
    for document in malformed:
        requests.append(
            _readback(document["resource"], present=True, kind="typed-readback")
        )

    # R3-2: a value the request decoder cannot read, in the same position.
    requests.append(
        {
            "kind": "batch-write",
            "case": "batch-undecodable-value",
            "service": "firestore",
            "method": "POST",
            "path": batch_path,
            "body": {
                "writes": [
                    _conditional_create(document["resource"], document["fields"])
                    for document in undecodable
                ]
            },
            "expect": {
                "status": 400,
                "typed": "INVALID_ARGUMENT",
                "landed": [],
            },
        }
    )
    for document in undecodable:
        requests.append(
            _readback(document["resource"], present=False, kind="typed-readback")
        )

    # R3-3: the duplicate-document control. Production is already known to
    # answer this with a whole-request 400 and no publication.
    requests.append(
        {
            "kind": "batch-write",
            "case": "batch-duplicate-document",
            "service": "firestore",
            "method": "POST",
            "path": batch_path,
            "body": {
                "writes": [
                    _conditional_create(
                        duplicate[0]["resource"], duplicate[0]["fields"]
                    ),
                    _conditional_create(
                        duplicate[1]["resource"], duplicate[1]["fields"]
                    ),
                    _conditional_create(
                        duplicate[0]["resource"], duplicate[0]["fields"]
                    ),
                ]
            },
            "expect": {
                "status": 400,
                "typed": "INVALID_ARGUMENT",
                "landed": [],
                "diagnosticDivergenceKnown": True,
            },
        }
    )
    for document in duplicate:
        requests.append(
            _readback(document["resource"], present=False, kind="typed-readback")
        )

    # R4: each limit's accept/refuse pair, then the refused resource's typed
    # absence, then the accepted control re-read after the refusal.
    for limit in limits:
        accept = documents[f"{limit['label']}-accept"]
        refuse = documents[f"{limit['label']}-refuse"]
        if limit["probe"] == "create":
            requests.append(_create_only_patch(accept, positive=True))
        else:
            requests.append(
                {
                    "kind": "name-boundary-readback",
                    "service": "firestore",
                    "method": "GET",
                    "path": "/v1/" + accept["resource"],
                    "body": None,
                    # A name at the boundary is a valid resource, so the request
                    # is processed and answers typed absence rather than a
                    # syntax refusal.
                    "expect": {"status": 404, "typed": "NOT_FOUND"},
                }
            )
        requests.append(_create_only_patch(refuse, positive=False))
        requests.append(
            {
                "kind": "refusal-consistency-readback",
                "service": "firestore",
                "method": "GET",
                "path": "/v1/" + refuse["resource"],
                "body": None,
                # The refused name is not a resource, so a read of it must be
                # refused the same way the write was. This is the post-state
                # evidence for a request-stage identifier limit: no document
                # exists because no such document can be named.
                "expect": {"status": 400, "typed": "INVALID_ARGUMENT"},
            }
        )
        if limit["probe"] == "create":
            requests.append(
                _readback(
                    accept["resource"], present=True, kind="unchanged-control-readback"
                )
            )

    observation_count = len(requests)
    for document in owned:
        index = len(requests) - observation_count
        resource = document["resource"]
        requests.append(
            {
                "kind": "cleanup-ownership-read",
                "service": "firestore",
                "method": "GET",
                "path": "/v1/" + resource,
                "body": None,
                "expect": {"statuses": [200, 404]},
            }
        )
        requests.append(
            {
                "kind": "cleanup-conditional-delete",
                "service": "firestore",
                "method": "DELETE",
                "path": "/v1/" + resource,
                "body": None,
                "versionFrom": index,
                "expect": {"status": 200},
            }
        )
        requests.append(
            {
                "kind": "cleanup-verify-absence",
                "service": "firestore",
                "method": "GET",
                "path": "/v1/" + resource,
                "body": None,
                "expect": {"status": 404, "typed": "NOT_FOUND"},
            }
        )

    for row in requests:
        row.update(privileged=True, form=False)
        row["responseByteLimit"] = _response_limit(row, documents)

    keys = ("service", "path", "method", "body", "privileged", "form", "versionFrom")
    operations = [{k: row[k] for k in keys if k in row} for row in requests]
    recovery_operations = operations[observation_count:]
    gate_plan = {
        "contract": "shared-local-v2",
        "nonce": nonce,
        "jobs": {
            "limits": {
                "resources": [d["resource"] for d in owned],
                "observation": operations[:observation_count],
                "recovery": recovery_operations,
            }
        },
        "wallSeconds": 1000,
        "recoverySeconds": 420,
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
    return {
        "campaignId": CAMPAIGN,
        "catalog": catalog,
        "nonce": nonce,
        "documents": documents,
        "cases": _case_index(),
        "requests": requests,
        "localGatePlan": gate_plan,
        "budgetAccounting": {
            "requestUpperBound": len(requests),
            "observationRequests": observation_count,
            "recoveryRequests": len(recovery_operations),
            "ownedDocuments": len(owned),
            "probedNames": len(documents) - len(owned),
            "requestBodyUpperBoundBytes": max(request_sizes),
            "transportRequestUpperBoundBytes": max(request_sizes),
            "responseUpperBoundBytes": sum(
                row["responseByteLimit"] for row in requests
            ),
            "maxResponseBytes": max(row["responseByteLimit"] for row in requests),
            "recoverySeconds": gate_plan["recoverySeconds"],
            "productionReady": False,
            "legacyTransportCompatible": False,
        },
        "executionBlockers": [
            "limits production runner is bound to the limits-02 compiler",
            "owner permission envelope, window, nonce reservation and tariff acceptance",
            "frozen artifact, collector and comparator bindings through O7",
        ],
    }


def _case_index() -> list[dict[str, Any]]:
    return [
        {
            "id": f"{CAMPAIGN}/batch-malformed-middle",
            "residue": "R3",
            "condition": "BatchWrite continuation past a malformed item",
        },
        {
            "id": f"{CAMPAIGN}/batch-undecodable-value",
            "residue": "R3",
            "condition": "BatchWrite continuation past an undecodable value",
        },
        {
            "id": f"{CAMPAIGN}/batch-duplicate-document",
            "residue": "R3",
            "condition": "BatchWrite whole-request validation control",
        },
        {
            "id": f"{CAMPAIGN}/collection-id",
            "residue": "R4",
            "condition": "FS-LIMIT-COLLECTION-ID length boundary",
        },
        {
            "id": f"{CAMPAIGN}/subcollection-depth",
            "residue": "R4",
            "condition": "FS-LIMIT-SUBCOLLECTION-DEPTH boundary",
        },
        {
            "id": f"{CAMPAIGN}/document-name",
            "residue": "R4",
            "condition": "FS-LIMIT-DOCUMENT-NAME-BYTES boundary",
        },
    ]


def _check_no_confound(documents: dict[str, Any], limits: list[dict[str, Any]]) -> None:
    """Each boundary pair must differ from its control in exactly one limit."""
    measures = {
        "FS-LIMIT-COLLECTION-ID": lambda d: max(
            len(segment.encode())
            for index, segment in enumerate(
                d["resource"].split("/documents/", 1)[1].split("/")
            )
            if index % 2 == 0
        ),
        "FS-LIMIT-SUBCOLLECTION-DEPTH": lambda d: d["depth"],
        "FS-LIMIT-DOCUMENT-NAME-BYTES": lambda d: d["nameBytes"],
    }
    for label, document in documents.items():
        if not document["owned"]:
            continue
        entry = largest_index_entry_bytes(document["resource"], document["fields"])
        if entry > INDEX_ENTRY_BYTES_MAX:
            raise ValueError(
                f"{label} cannot be created: its index entry is {entry} bytes"
            )
    for limit in limits:
        accept = documents[f"{limit['label']}-accept"]
        refuse = documents[f"{limit['label']}-refuse"]
        measure = measures[limit["id"]]
        if [measure(accept), measure(refuse)] != limit["boundary"]:
            raise ValueError(f"{limit['id']} is not at its exact boundary pair")
        for document in (accept, refuse):
            if document["depth"] > SUBCOLLECTION_DEPTH_MAX + 1:
                raise ValueError(f"{limit['id']} confounds subcollection depth")
            if document["nameBytes"] > DOCUMENT_NAME_MAX + 1:
                raise ValueError(f"{limit['id']} confounds document name bytes")
        if limit["id"] != "FS-LIMIT-SUBCOLLECTION-DEPTH" and (
            accept["depth"] > SUBCOLLECTION_DEPTH_MAX
            or refuse["depth"] > SUBCOLLECTION_DEPTH_MAX
        ):
            raise ValueError(f"{limit['id']} exceeds the depth limit")
        if limit["id"] != "FS-LIMIT-DOCUMENT-NAME-BYTES" and (
            accept["nameBytes"] > DOCUMENT_NAME_MAX
            or refuse["nameBytes"] > DOCUMENT_NAME_MAX
        ):
            raise ValueError(f"{limit['id']} exceeds the document name limit")
        for document in (accept, refuse):
            relative = document["resource"].split("/documents/", 1)[1]
            longest = max(len(segment.encode()) for segment in relative.split("/"))
            if limit["id"] != "FS-LIMIT-COLLECTION-ID" and longest > COLLECTION_ID_MAX:
                raise ValueError(f"{limit['id']} confounds an identifier length")


def _response_limit(row: dict[str, Any], documents: dict[str, Any]) -> int:
    if row["method"] == "POST":
        writes = row["body"]["writes"]
        return max(
            65536, len(json.dumps(row["body"]).encode()) * 2 + 4096 * len(writes)
        )
    resource = row["path"].split("?", 1)[0].removeprefix("/v1/")
    document = next(d for d in documents.values() if d["resource"] == resource)
    full_bytes = len(
        json.dumps({"name": resource, "fields": document["fields"]}).encode()
    )
    # Allow document metadata and formatting, even for an unexpected success.
    # The transport must stop on overflow rather than treating a prefix as whole.
    return max(65536, full_bytes + 4096) if row["method"] in ("GET", "PATCH") else 65536
