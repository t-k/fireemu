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
INDEX_ENTRIES_PER_DOCUMENT_MAX = 40_000
INDEX_ENTRY_SUM_PER_DOCUMENT_MAX = 8_388_608
INDEXED_VALUE_TRUNCATION = 1_500
FIELD_PATH_BYTES_MAX = 1_500
FIELD_VALUE_BYTES_MAX = 1_048_487
DOCUMENT_BYTES_MAX = 1_048_576
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


def _catalog_entry(identifier: str) -> dict[str, Any]:
    catalog = json.loads(_CATALOG.read_bytes())
    return next(entry for entry in catalog["limits"] if entry["id"] == identifier)


def catalog_status(identifier: str) -> dict[str, str]:
    """What the catalog currently records for a limit, read rather than restated."""
    entry = _catalog_entry(identifier)
    return {
        "catalogImplemented": entry["implemented"],
        "catalogUnit": entry["unit"],
        "catalogBoundary": entry["boundary"],
    }


def name_charge_floor(prefix_bytes: int, name_bytes: int) -> dict[str, int]:
    """Smallest index-entry charges a document of this protocol name length can have.

    `storage_name_bytes` reduces to 17 plus the relative path length, so it does
    not depend on how the name is split into segments. The document and parent
    name charge an entry carries is therefore smallest when the last collection
    and document identifiers are as long as the identifier limit allows.
    """
    relative = name_bytes - prefix_bytes
    longest_final_pair = 2 * COLLECTION_ID_MAX + 2
    document = 17 + relative
    parent = 17 + relative - longest_final_pair
    if parent <= 17:
        raise ValueError("no parent document remains at this name length")
    smallest_sum = document + parent
    return {
        "smallestNameSum": smallest_sum,
        # One-byte field name, then the cheapest indexed value there is.
        "smallestIndexedFieldEntry": smallest_sum + 2 + 1 + 32,
        # The ownership marker references the document itself, so its indexed
        # value always sits at the truncation ceiling.
        "smallestMarkerBearingEntry": smallest_sum
        + len("_sharedOwner")
        + 1
        + INDEXED_VALUE_TRUNCATION
        + 32,
    }


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
    elif "mapValue" in value:
        size = 32 + sum(
            len(n.encode()) + 1 + _indexed_value_bytes(v)
            for n, v in value["mapValue"].get("fields", {}).items()
        )
    else:
        raise ValueError("unsupported indexed value")
    return min(size, INDEXED_VALUE_TRUNCATION)


def name_sum_bytes(resource: str) -> int:
    """`document_name_size` of the document plus of its parent document.

    Every automatic collection-scope index entry is charged both, which is why
    this quantity, not the protocol resource name, drives the index limits.
    """
    parent = "/".join(resource.split("/")[:-2])
    parent_bytes = (
        storage_name_bytes(parent) if parent.split("/documents/", 1)[-1] else 0
    )
    return storage_name_bytes(resource) + parent_bytes


def _entry_bytes(resource: str, path: str, value: dict[str, Any]) -> int:
    return (
        name_sum_bytes(resource)
        + len(path.encode())
        + 1
        + _indexed_value_bytes(value)
        + 32
    )


def index_usage(resource: str, fields: dict[str, Any]) -> dict[str, int]:
    """Automatic index usage under the project's default single-field modes.

    Mirrors `IndexSet::automatic_usage`: with no field override a collection's
    fields carry ascending, descending and array-membership modes, all at
    collection scope. A scalar therefore costs two entries, and an array costs
    two ordered entries plus two membership entries for each distinct element.
    No composite index is assumed, because this campaign declares none.
    """
    entries = total = largest = 0

    def walk(prefix: list[str], value_fields: dict[str, Any]) -> None:
        nonlocal entries, total, largest
        for name, value in sorted(value_fields.items()):
            path = ".".join([*prefix, name])
            ordered = _entry_bytes(resource, path, value)
            entries += 2
            total += 2 * ordered
            largest = max(largest, ordered)
            array = value.get("arrayValue") if isinstance(value, dict) else None
            if isinstance(array, dict) and isinstance(array.get("values"), list):
                seen = set()
                for item in array["values"]:
                    key = json.dumps(item, sort_keys=True)
                    if key in seen:
                        continue
                    seen.add(key)
                    member = _entry_bytes(resource, path, item)
                    entries += 2
                    total += 2 * member
                    largest = max(largest, member)
            nested = value.get("mapValue") if isinstance(value, dict) else None
            if isinstance(nested, dict):
                walk([*prefix, name], nested.get("fields", {}))

    walk([], fields)
    return {"entries": entries, "totalBytes": total, "maxEntryBytes": largest}


def largest_index_entry_bytes(resource: str, fields: dict[str, Any]) -> int:
    """Largest automatic single-field collection index entry for a document."""
    return index_usage(resource, fields)["maxEntryBytes"]


def document_bytes(resource: str, fields: dict[str, Any]) -> int:
    """Logical document size, the quantity `FS-LIMIT-DOCUMENT-BYTES` is measured on."""
    return (
        storage_name_bytes(resource)
        + 32
        + sum(
            len(name.encode()) + 1 + _field_value_bytes(value)
            for name, value in fields.items()
        )
    )


def _field_value_bytes(value: dict[str, Any]) -> int:
    if "referenceValue" in value:
        return storage_name_bytes(value["referenceValue"])
    if "integerValue" in value:
        return 8
    if "stringValue" in value:
        return len(value["stringValue"].encode()) + 1
    if "arrayValue" in value:
        members = value["arrayValue"].get("values")
        return (
            sum(_field_value_bytes(m) for m in members)
            if isinstance(members, list)
            else 0
        )
    if "mapValue" in value:
        return 32 + sum(
            len(n.encode()) + 1 + _field_value_bytes(v)
            for n, v in value["mapValue"].get("fields", {}).items()
        )
    raise ValueError("unsupported field value")


def name_sum_resource(root: str, leaf: str, name_sum: int) -> str:
    """A resource under `root` whose document and parent name bytes sum to `name_sum`.

    Padding pairs carry the length; the last pair's identifier fixes the parity,
    because the parent's name excludes exactly that pair.
    """
    base = storage_name_bytes(f"{root}/{leaf}")
    widest = COLLECTION_ID_MAX - 1
    for last in range(8, widest):
        if (name_sum + last + 3) % 2:
            continue
        target = (name_sum + last + 3) // 2
        remaining = target - base - (last + 3)
        if remaining < 0:
            continue
        pads: list[int] = []
        while remaining > 0:
            take = min(remaining - 3, widest)
            if take < 1:
                break
            pads.append(take)
            remaining -= take + 3
        if remaining:
            continue
        resource = (
            f"{root}/{leaf}"
            + "".join(f"/p/{'z' * n}" for n in pads)
            + f"/p/{'z' * last}"
        )
        if name_sum_bytes(resource) == name_sum:
            return resource
    raise ValueError(f"no owned resource reaches a name sum of {name_sum}")


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


def _padded_resource(root: str, leaf: str, target: int, collection: str = "p") -> str:
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
    per_pair_overhead = len(collection) + 2
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
    resource = base + "".join(f"/{collection}/{'z' * width}" for width in widths)
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


def _create_only_patch(
    document: dict[str, Any], *, positive: bool, pending: str | None = None
) -> dict[str, Any]:
    resource = document["resource"]
    expect: dict[str, Any] = {"positive": positive}
    if pending:
        # The expectation states the documented production behaviour for
        # something the local runtime or the local shadow cannot yet show. A
        # difference is recorded as a pending difference with this reason
        # rather than as a campaign failure.
        expect["pendingReason"] = pending
    return {
        "kind": "create-only-patch",
        "service": "firestore",
        "method": "PATCH",
        "path": "/v1/" + resource + "?currentDocument.exists=false",
        "body": {"name": resource, "fields": document["fields"]},
        "expect": expect,
    }


def _conditional_create(resource: str, fields: dict[str, Any]) -> dict[str, Any]:
    return {
        "update": {"name": resource, "fields": fields},
        "currentDocument": {"exists": False},
    }


def compile_limits_plan(
    project: str, database: str, nonce: str, part: str = "A"
) -> dict[str, Any]:
    """Compile one admitted part of the campaign and its ordered request plan."""
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

    # R3: BatchWrite continuation. Part A only.
    malformed: list[dict[str, Any]] = []
    undecodable: list[dict[str, Any]] = []
    duplicate: list[dict[str, Any]] = []
    if part == "A":
        malformed[:] = [
            add(f"batch-malformed-{side}", f"{root}/bw-a-{index}", None)
            for index, side in ((0, "prefix"), (2, "suffix"))
        ]
        undecodable[:] = [
            add(f"batch-undecodable-{side}", f"{root}/bw-b-{index}", None)
            for index, side in ((0, "prefix"), (1, "middle"), (2, "suffix"))
        ]
        duplicate[:] = [
            add(f"batch-duplicate-{side}", f"{root}/bw-c-{index}", None)
            for index, side in ((0, "first"), (1, "second"))
        ]
        for index, document in enumerate(malformed + undecodable + duplicate):
            document["fields"] = _fields(document["resource"], index)
        undecodable[1]["fields"] = _undecodable_fields(undecodable[1]["resource"])

    # R4: the write-path catalog limits. Every boundary below is derived from
    # the default single-field index configuration: ascending, descending and
    # array-membership modes at collection scope. The campaign declares no
    # composite index and no field override, so it requires no addition to
    # `conformance/firestore.indexes.json`.
    limits = _limit_specs(root, part)
    for spec in limits:
        for side in ("accept", "refuse"):
            entry = spec.get(side)
            if entry is None:
                continue
            document = add(
                f"{spec['label']}-{side}",
                entry["resource"],
                entry["fields"],
                owned=entry["owned"],
            )
            document["limitId"] = spec["id"]
            for key in ("mask", "canonicalPathBytes", "indexExempt"):
                if key in entry:
                    document[key] = entry[key]
            document["indexUsage"] = index_usage(entry["resource"], entry["fields"])
            document["documentBytes"] = document_bytes(
                entry["resource"], entry["fields"]
            )

    _check_no_confound(documents, limits)

    owned = [document for document in documents.values() if document["owned"]]
    requests: list[dict[str, Any]] = []
    for document in owned:
        requests.append(_preflight(document["resource"]))

    if part == "A":
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

    for spec in limits:
        requests.extend(_limit_requests(spec, documents, batch_path))

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
        # The shared Gate reserves 13 seconds plus the interval for every
        # recovery request inside a 1200-second ceiling, which is why the
        # campaign runs as two admitted parts rather than one.
        "wallSeconds": _wall_seconds(len(recovery_operations)),
        "recoverySeconds": _recovery_seconds(len(recovery_operations)),
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
        "campaignId": f"{CAMPAIGN}{part}",
        "part": part,
        "catalog": catalog,
        "nonce": nonce,
        "documents": documents,
        "cases": _case_index(limits, part),
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


# Number of automatic index entries a document carries before any array field:
# the ownership marker contributes an ascending and a descending entry.
MARKER_ENTRIES = 2
# An array field adds its own two ordered entries on top of two per element.
ARRAY_ORDERED_ENTRIES = 2


def _owned(resource: str, fields: dict[str, Any]) -> dict[str, Any]:
    return {"resource": resource, "fields": fields, "owned": True}


def _probe(resource: str, fields: dict[str, Any]) -> dict[str, Any]:
    return {"resource": resource, "fields": fields, "owned": False}


def _integers(count: int) -> dict[str, Any]:
    return {"arrayValue": {"values": [{"integerValue": str(i)} for i in range(count)]}}


def _entries_case(root: str) -> dict[str, Any]:
    """`FS-LIMIT-INDEX-ENTRIES-PER-DOCUMENT` at 40,000 automatic entries.

    A short document name keeps every membership entry small enough that the
    entry-sum limit stays far below its own maximum, so the count is the only
    limit that can explain the refusal. The count moves in steps of two because
    each distinct element carries both document-name directions, so the exact
    inclusive maximum is reached and the next representable total is 40,002.
    """
    elements = (
        INDEX_ENTRIES_PER_DOCUMENT_MAX - MARKER_ENTRIES - ARRAY_ORDERED_ENTRIES
    ) // 2
    sides = {}
    for side, count in (("accept", elements), ("refuse", elements + 1)):
        resource = f"{root}/iec-{side}"
        sides[side] = _owned(
            resource,
            {"_sharedOwner": _owner(resource), "a": _integers(count)},
        )
    return {
        "id": "FS-LIMIT-INDEX-ENTRIES-PER-DOCUMENT",
        "label": "index-entries",
        "boundaryUnit": "automatic index entries per document",
        "emit": "create-pair",
        "boundary": [
            INDEX_ENTRIES_PER_DOCUMENT_MAX,
            INDEX_ENTRIES_PER_DOCUMENT_MAX + 2,
        ],
        "measure": "entries",
        **catalog_status("FS-LIMIT-INDEX-ENTRIES-PER-DOCUMENT"),
        "elements": elements,
        **sides,
    }


def _entry_sum_case(root: str) -> dict[str, Any]:
    """`FS-LIMIT-INDEX-ENTRY-SUM-PER-DOCUMENT` at 8 MiB of index entries.

    A long document name makes each entry expensive, so the sum is reached with
    a few hundred elements instead of a payload that would breach the document
    limit first. A filler field whose name length is solved for carries the last
    bytes, and the refused variant lengthens the name by one byte, which raises
    every entry by one and the sum by the entry count.
    """
    for name_sum in range(INDEX_ENTRY_BYTES_MAX - 1546, 5000, -1):
        remainder = INDEX_ENTRY_SUM_PER_DOCUMENT_MAX - (4 * name_sum + 6158)
        if remainder <= 0 or remainder % 2:
            continue
        half = remainder // 2
        elements = (half - name_sum - 42) // (name_sum + 42)
        filler = half - (name_sum + 41) - elements * (name_sum + 42)
        if elements < 188 or not 1 <= filler <= COLLECTION_ID_MAX:
            continue
        sides = {}
        for side, total in (("accept", name_sum), ("refuse", name_sum + 1)):
            resource = name_sum_resource(root, f"ies-{side}", total)
            sides[side] = _owned(
                resource,
                {
                    "_sharedOwner": _owner(resource),
                    "a": _integers(elements),
                    "f" * filler: {"integerValue": "1"},
                },
            )
        if index_usage(**_as_args(sides["accept"]))["totalBytes"] != (
            INDEX_ENTRY_SUM_PER_DOCUMENT_MAX
        ):
            continue
        return {
            "id": "FS-LIMIT-INDEX-ENTRY-SUM-PER-DOCUMENT",
            "label": "index-entry-sum",
            "boundaryUnit": "summed bytes of a document's index entries",
            "emit": "create-pair",
            "boundary": [
                INDEX_ENTRY_SUM_PER_DOCUMENT_MAX,
                index_usage(**_as_args(sides["refuse"]))["totalBytes"],
            ],
            "measure": "totalBytes",
            **catalog_status("FS-LIMIT-INDEX-ENTRY-SUM-PER-DOCUMENT"),
            "elements": elements,
            "fillerNameBytes": filler,
            **sides,
        }
    raise ValueError("no index entry sum boundary under the default configuration")


def _as_args(entry: dict[str, Any]) -> dict[str, Any]:
    return {"resource": entry["resource"], "fields": entry["fields"]}


def _entry_bytes_case(root: str) -> dict[str, Any]:
    """`FS-LIMIT-INDEX-ENTRY-BYTES` at 7,680 bytes for one entry.

    The ownership marker references the document itself, so its indexed value is
    the truncation ceiling and the entry size is driven entirely by the document
    and parent name bytes. One byte of name separates the pair.
    """
    target = (
        INDEX_ENTRY_BYTES_MAX
        - (len("_sharedOwner") + 1)
        - INDEXED_VALUE_TRUNCATION
        - 32
    )
    sides = {}
    for side, name_sum in (("accept", target), ("refuse", target + 1)):
        resource = name_sum_resource(root, f"ieb-{side}", name_sum)
        sides[side] = _owned(
            resource,
            {"_sharedOwner": _owner(resource), "v": {"integerValue": "1"}},
        )
    return {
        "id": "FS-LIMIT-INDEX-ENTRY-BYTES",
        "label": "index-entry-bytes",
        "boundaryUnit": "bytes of one automatic index entry",
        "emit": "create-pair",
        "boundary": [INDEX_ENTRY_BYTES_MAX, INDEX_ENTRY_BYTES_MAX + 1],
        "measure": "maxEntryBytes",
        **catalog_status("FS-LIMIT-INDEX-ENTRY-BYTES"),
        **sides,
    }


def _indexed_value_case(root: str) -> dict[str, Any]:
    """`FS-LIMIT-INDEXED-FIELD-VALUE-BYTES`, a truncating maximum.

    The catalog records that production truncates the indexed representation at
    1,500 bytes rather than refusing, so this case is not an accept/refuse pair
    and must not be written as one. Both documents are sized so that their one
    indexed entry is exactly at the entry maximum under truncation. The second
    carries a value twice the truncation ceiling: if the indexed representation
    were charged in full its entry would be 9,180 bytes and the write would be
    refused. Accepting both is what confirms the truncation.
    """
    field = "s" * 20
    name_sum = INDEX_ENTRY_BYTES_MAX - (len(field) + 1) - INDEXED_VALUE_TRUNCATION - 32
    sides = {}
    for side, length in (
        ("accept", INDEXED_VALUE_TRUNCATION - 1),
        ("refuse", 2 * INDEXED_VALUE_TRUNCATION - 1),
    ):
        resource = name_sum_resource(root, f"ifv-{side}", name_sum)
        sides[side] = _owned(
            resource,
            {"_sharedOwner": _owner(resource), field: {"stringValue": "x" * length}},
        )
    return {
        "id": "FS-LIMIT-INDEXED-FIELD-VALUE-BYTES",
        "label": "indexed-value",
        "boundaryUnit": "logical bytes of the indexed value before truncation",
        "emit": "truncating-pair",
        "boundary": [INDEXED_VALUE_TRUNCATION, 2 * INDEXED_VALUE_TRUNCATION],
        "measure": "indexedValueBytes",
        **catalog_status("FS-LIMIT-INDEXED-FIELD-VALUE-BYTES"),
        "chargedInFullWouldBe": name_sum
        + len(field)
        + 1
        + 2 * INDEXED_VALUE_TRUNCATION
        + 32,
        **sides,
    }


def _field_path_case(root: str) -> dict[str, Any]:
    """`FS-LIMIT-FIELD-PATH-BYTES` at 1,500 canonical bytes of an update mask.

    The path is delivered through a `:batchWrite` create-only write rather than
    a `PATCH`, because the Gate recognizes a conditional creation proof from a
    batch write regardless of its update mask, while a `PATCH` proof requires an
    unadorned `currentDocument.exists=false` query. Two segments share the
    length so that neither reaches the field-name maximum.
    """
    sides = {}
    for side, total in (
        ("accept", FIELD_PATH_BYTES_MAX),
        ("refuse", FIELD_PATH_BYTES_MAX + 1),
    ):
        outer = "o" * (total // 2)
        inner = "i" * (total - len(outer) - 1)
        resource = f"{root}/fpb-{side}"
        sides[side] = _owned(
            resource,
            {
                "_sharedOwner": _owner(resource),
                outer: {"mapValue": {"fields": {inner: {"integerValue": "1"}}}},
            },
        )
        sides[side]["mask"] = ["_sharedOwner", f"{outer}.{inner}"]
        sides[side]["canonicalPathBytes"] = len(outer) + 1 + len(inner)
    return {
        "id": "FS-LIMIT-FIELD-PATH-BYTES",
        "label": "field-path",
        "boundaryUnit": "utf8-bytes of the canonical field path",
        "emit": "mask-pair",
        "boundary": [FIELD_PATH_BYTES_MAX, FIELD_PATH_BYTES_MAX + 1],
        "measure": "canonicalPathBytes",
        **catalog_status("FS-LIMIT-FIELD-PATH-BYTES"),
        **sides,
    }


def _field_value_case(root: str) -> dict[str, Any]:
    """`FS-LIMIT-FIELD-VALUE-BYTES` at 1,048,487 bytes for one value.

    Only the refusal is observable. An owned document's name, ownership marker
    and field overhead cost more than the 89 bytes between this maximum and
    `FS-LIMIT-DOCUMENT-BYTES`, so a value at the accepted boundary cannot fit
    inside any document in the owned namespace; the accepted side is already
    covered by the production matrix row `errors/rest-shapes`
    `#document-just-under-one-mebibyte`. The refused document breaches both
    limits at once, so the diagnostic text is the only thing that says which
    limit production enforced, and this campaign's comparator compares it.
    """
    resource = f"{root}/fvb-refuse"
    fields = {
        "_sharedOwner": _owner(resource),
        "b": {"stringValue": "x" * (FIELD_VALUE_BYTES_MAX + 1)},
    }
    return {
        "id": "FS-LIMIT-FIELD-VALUE-BYTES",
        "label": "field-value",
        "emit": "refuse-only",
        "boundary": [FIELD_VALUE_BYTES_MAX, FIELD_VALUE_BYTES_MAX + 1],
        "measure": "payloadBytes",
        # The catalog's unit field says logical bytes while its notes say a
        # string or bytes payload is measured on its raw length. This case takes
        # the notes, which are the half production was observed on; the two
        # aggregate cases observe both readings.
        "boundaryUnit": "raw payload bytes of one string or bytes value",
        **catalog_status("FS-LIMIT-FIELD-VALUE-BYTES"),
        "acceptedSideUnreachable": (
            "an owned document at this value exceeds FS-LIMIT-DOCUMENT-BYTES"
        ),
        "entangledWith": ["FS-LIMIT-DOCUMENT-BYTES"],
        "entanglementReason": (
            "A value one byte over this maximum also puts the document over "
            "FS-LIMIT-DOCUMENT-BYTES, because only 89 bytes separate the two "
            "maxima and an owned document's name and ownership marker cost more "
            "than that. The diagnostic text is the only thing that says which "
            "limit was enforced, and this campaign's comparator compares it."
        ),
        "refuse": _owned(resource, fields),
    }


def _aggregate_cases(root: str) -> list[dict[str, Any]]:
    """`FS-LIMIT-FIELD-VALUE-BYTES` applied to an aggregate value.

    The runtime's aggregate check reads the same maximum two ways one byte
    apart: a string or bytes payload is measured on its raw length, while a map
    or an array is measured with the official storage-size formula, which adds
    a trailing byte per string and 32 per map. These four documents make
    production say which metric it applies.

    None of the four can be accepted, because only 89 bytes separate this
    maximum from `FS-LIMIT-DOCUMENT-BYTES` and an owned name and ownership
    marker cost more than that. The evidence is therefore the diagnostic text:
    a message naming the property says the value metric fired, and a message
    about the document size says it did not.
    """
    cases = []
    for label, raw in (
        ("agg-string", FIELD_VALUE_BYTES_MAX),
        ("agg-map", FIELD_VALUE_BYTES_MAX),
    ):
        sides = {}
        for side, bump in (("accept", 0), ("refuse", 1)):
            resource = f"{root}/{label}-{side}"
            if label == "agg-string":
                # Raw payload exactly at the maximum, then one over. Its logical
                # size is one byte more than its raw size, so the two readings
                # disagree on the first of the pair.
                fields = {
                    "_sharedOwner": _owner(resource),
                    "b": {"stringValue": "x" * (raw + bump)},
                }
            else:
                # Logical size exactly at the maximum, then one over. A map has
                # no raw payload at all, so the raw reading can never refuse it.
                inner = raw + bump - 32 - 2 - 1
                fields = {
                    "_sharedOwner": _owner(resource),
                    "m": {"mapValue": {"fields": {"s": {"stringValue": "x" * inner}}}},
                }
            sides[side] = _owned(resource, fields)
        cases.append(
            {
                "id": "FS-LIMIT-FIELD-VALUE-BYTES",
                "label": label,
                "emit": "refuse-pair",
                "boundary": [FIELD_VALUE_BYTES_MAX, FIELD_VALUE_BYTES_MAX + 1],
                "measure": "aggregateBytes",
                "boundaryUnit": (
                    "raw payload bytes"
                    if label == "agg-string"
                    else "logical bytes of the aggregate value"
                ),
                "aggregateShape": "string" if label == "agg-string" else "nested-map",
                **catalog_status("FS-LIMIT-FIELD-VALUE-BYTES"),
                "entangledWith": ["FS-LIMIT-DOCUMENT-BYTES"],
                "entanglementReason": (
                    "Both members exceed FS-LIMIT-DOCUMENT-BYTES, because the accepted "
                    "side of this maximum does not fit in an owned document. The "
                    "diagnostic text is the discriminator."
                ),
                "metricEvidence": {
                    "namesTheProperty": "production applies the value metric to this shape",
                    "namesTheDocumentSize": "production does not apply the value metric to this shape",
                },
                **sides,
            }
        )
    return cases


def _implied_path_cases(root: str) -> list[dict[str, Any]]:
    """`FS-LIMIT-FIELD-PATH-BYTES` on the paths a document implies by nesting.

    A path a client names in an update mask is bounded when the mask is parsed.
    A path that exists only because a document nests values is a separate
    surface, and it has two shapes. Automatic index accounting walks a map held
    directly by a field, so an over-long path there is already refused; it never
    walks the elements of an array, so a map inside an array had an unbounded
    implied path until the write-path lane bounded it under the strict profile.
    Both shapes are observed, because production is expected to bound both.
    """
    cases = []
    for label, shape in (("implied-map", "map"), ("implied-array", "array")):
        sides = {}
        for side, total in (
            ("accept", FIELD_PATH_BYTES_MAX),
            ("refuse", FIELD_PATH_BYTES_MAX + 1),
        ):
            resource = f"{root}/{label}-{side}"
            leaf = {"integerValue": "1"}
            if shape == "map":
                outer = "o" * (total // 2)
                inner = "i" * (total - len(outer) - 1)
                value = {"mapValue": {"fields": {inner: leaf}}}
                fields = {"_sharedOwner": _owner(resource), outer: value}
                implied = f"{outer}.{inner}"
            else:
                outer = "a"
                inner = "i" * (total - len(outer) - 1)
                value = {
                    "arrayValue": {"values": [{"mapValue": {"fields": {inner: leaf}}}]}
                }
                fields = {"_sharedOwner": _owner(resource), outer: value}
                implied = f"{outer}.{inner}"
            entry = _owned(resource, fields)
            entry["canonicalPathBytes"] = len(implied.encode())
            sides[side] = entry
        cases.append(
            {
                "id": "FS-LIMIT-FIELD-PATH-BYTES",
                "label": label,
                "emit": "create-pair",
                "boundary": [FIELD_PATH_BYTES_MAX, FIELD_PATH_BYTES_MAX + 1],
                "measure": "canonicalPathBytes",
                "boundaryUnit": "utf8-bytes of the canonical field path",
                "pathShape": shape,
                **catalog_status("FS-LIMIT-FIELD-PATH-BYTES"),
                **sides,
            }
        )
    return cases


# The collection group the document-name case lives under. It is exempted from
# automatic indexing so a document named at the boundary can be created at all;
# keeping it distinct from the padding collection the index cases use means the
# exemption cannot reach them.
EXEMPT_COLLECTION = "nx"


def _document_name_case(root: str) -> dict[str, Any]:
    """`FS-LIMIT-DOCUMENT-NAME-BYTES` observed by a create, under an exemption.

    An automatic index entry is charged the document name and its parent's
    name, so the smallest possible entry for a document named at 6144 bytes is
    11040 bytes against a 7680-byte maximum: without an exemption this boundary
    cannot be written at all, which is why it and the index-entry limits are one
    decision. Exempting this collection group from automatic indexing removes
    every entry the document would generate, and the name limit is then the only
    thing the write can breach.

    The local shadow supervisor pins the historical index configuration and
    verifies its digest, so it cannot apply the exemption. The accepted side is
    therefore marked pending: the shadow will show the index-entry refusal the
    exemption exists to remove.
    """
    prefix_bytes = len(root.split("/documents/", 1)[0].encode()) + len("/documents/")
    figures = name_charge_floor(prefix_bytes, DOCUMENT_NAME_MAX)
    accept = _padded_resource(root, "name-exact", DOCUMENT_NAME_MAX, EXEMPT_COLLECTION)
    refuse = _padded_resource(
        root, "name-over", DOCUMENT_NAME_MAX + 1, EXEMPT_COLLECTION
    )
    return {
        "id": "FS-LIMIT-DOCUMENT-NAME-BYTES",
        "label": "document-name",
        "boundaryUnit": "utf8-bytes of the protocol resource name",
        "emit": "create-pair",
        "boundary": [DOCUMENT_NAME_MAX, DOCUMENT_NAME_MAX + 1],
        "measure": "nameBytes",
        **catalog_status("FS-LIMIT-DOCUMENT-NAME-BYTES"),
        "derivedFigures": figures,
        "indexExemption": {
            "collectionGroup": EXEMPT_COLLECTION,
            "fieldPath": "*",
            "indexes": [],
        },
        "indexExemptionReason": (
            "Without it every document named at this boundary is refused for "
            "FS-LIMIT-INDEX-ENTRY-BYTES before the name limit is reached."
        ),
        "pendingReason": (
            "the local shadow supervisor pins the historical index configuration "
            "and cannot apply the declared exemption, so the local run shows the "
            "index-entry refusal the exemption exists to remove"
        ),
        "accept": {**_owned(accept, _fields(accept, 104)), "indexExempt": True},
        "refuse": {**_probe(refuse, _fields(refuse, 105)), "indexExempt": True},
    }


def _limit_specs(root: str, part: str = "A") -> list[dict[str, Any]]:
    """The write-path limits this part of the campaign observes, in request order.

    The campaign runs as two admitted parts because the shared Gate reserves
    thirteen seconds plus the interval for every recovery request inside a
    1,200-second ceiling, which caps one allocation at about twenty-six owned
    documents. Part A carries the identifier and index limits, part B the value
    and path limits.
    """
    if part not in ("A", "B"):
        raise ValueError("campaign part must be A or B")
    if part == "B":
        return [
            *_implied_path_cases(root),
            _field_path_case(root),
            _field_value_case(root),
            *_aggregate_cases(root),
        ]
    return [
        {
            "id": "FS-LIMIT-COLLECTION-ID",
            "label": "collection-id",
            "boundaryUnit": "utf8-bytes of the collection identifier",
            "emit": "create-pair",
            "boundary": [COLLECTION_ID_MAX, COLLECTION_ID_MAX + 1],
            "measure": "collectionIdBytes",
            **catalog_status("FS-LIMIT-COLLECTION-ID"),
            "accept": _owned(
                f"{root}/cid-exact/{'i' * COLLECTION_ID_MAX}/x",
                _fields(f"{root}/cid-exact/{'i' * COLLECTION_ID_MAX}/x", 100),
            ),
            "refuse": _probe(
                f"{root}/cid-over/{'i' * (COLLECTION_ID_MAX + 1)}/x",
                _fields(f"{root}/cid-over/{'i' * (COLLECTION_ID_MAX + 1)}/x", 101),
            ),
        },
        {
            "id": "FS-LIMIT-SUBCOLLECTION-DEPTH",
            "label": "subcollection-depth",
            "boundaryUnit": "collection levels",
            "emit": "create-pair",
            "boundary": [SUBCOLLECTION_DEPTH_MAX, SUBCOLLECTION_DEPTH_MAX + 1],
            "measure": "depth",
            **catalog_status("FS-LIMIT-SUBCOLLECTION-DEPTH"),
            "accept": _owned(
                _depth_resource(root, "depth-exact", SUBCOLLECTION_DEPTH_MAX),
                _fields(
                    _depth_resource(root, "depth-exact", SUBCOLLECTION_DEPTH_MAX), 102
                ),
            ),
            "refuse": _probe(
                _depth_resource(root, "depth-over", SUBCOLLECTION_DEPTH_MAX + 1),
                _fields(
                    _depth_resource(root, "depth-over", SUBCOLLECTION_DEPTH_MAX + 1),
                    103,
                ),
            ),
        },
        _document_name_case(root),
        _entry_bytes_case(root),
        _entries_case(root),
        _entry_sum_case(root),
        _indexed_value_case(root),
    ]


def _limit_requests(
    spec: dict[str, Any], documents: dict[str, Any], batch_path: str
) -> list[dict[str, Any]]:
    """The ordered observation requests for one limit.

    A pending reason belongs to the case, not to one half of it: if the local
    side cannot yet show the documented production behaviour for the write, it
    cannot show it for the readback that follows either.
    """
    requests = _limit_request_shapes(spec, documents, batch_path)
    reason = spec.get("pendingReason")
    if reason:
        for request in requests:
            request["expect"]["pendingReason"] = reason
    return requests


def _limit_request_shapes(
    spec: dict[str, Any], documents: dict[str, Any], batch_path: str
) -> list[dict[str, Any]]:
    accept = documents.get(f"{spec['label']}-accept")
    refuse = documents[f"{spec['label']}-refuse"]
    pending = spec.get("pendingReason")
    emit = spec["emit"]
    if emit == "name-only":
        return [
            {
                "kind": "name-boundary-readback",
                "service": "firestore",
                "method": "GET",
                "path": "/v1/" + accept["resource"],
                "body": None,
                # A name at the boundary is a valid resource, so the request is
                # processed and answers typed absence, not a syntax refusal.
                "expect": {"status": 404, "typed": "NOT_FOUND"},
            },
            _create_only_patch(refuse, positive=False),
            _refusal_readback(refuse["resource"]),
        ]
    if emit == "refuse-pair":
        return [
            _create_only_patch(accept, positive=False, pending=pending),
            _readback(accept["resource"], present=False, kind="typed-readback"),
            _create_only_patch(refuse, positive=False, pending=pending),
            _readback(refuse["resource"], present=False, kind="typed-readback"),
        ]
    if emit == "refuse-only":
        return [
            _create_only_patch(refuse, positive=False, pending=pending),
            _readback(refuse["resource"], present=False, kind="typed-readback"),
        ]
    if emit == "truncating-pair":
        return [
            _create_only_patch(accept, positive=True),
            _create_only_patch(refuse, positive=True, pending=pending),
            _readback(refuse["resource"], present=True, kind="typed-readback"),
            _readback(
                accept["resource"], present=True, kind="unchanged-control-readback"
            ),
        ]
    if emit == "mask-pair":
        return [
            _masked_batch_write(
                batch_path, spec["accept"], positive=True, pending=pending
            ),
            _masked_batch_write(
                batch_path, spec["refuse"], positive=False, pending=pending
            ),
            _readback(refuse["resource"], present=False, kind="typed-readback"),
            _readback(
                accept["resource"], present=True, kind="unchanged-control-readback"
            ),
        ]
    post = (
        _refusal_readback(refuse["resource"])
        if not refuse["owned"]
        else _readback(refuse["resource"], present=False, kind="typed-readback")
    )
    return [
        _create_only_patch(accept, positive=True),
        _create_only_patch(refuse, positive=False, pending=pending),
        post,
        _readback(accept["resource"], present=True, kind="unchanged-control-readback"),
    ]


def _refusal_readback(resource: str) -> dict[str, Any]:
    return {
        "kind": "refusal-consistency-readback",
        "service": "firestore",
        "method": "GET",
        "path": "/v1/" + resource,
        "body": None,
        # The refused name is not a resource, so a read of it must be refused
        # the same way the write was. This is the post-state evidence for a
        # request-stage identifier limit.
        "expect": {"status": 400, "typed": "INVALID_ARGUMENT"},
    }


def _masked_batch_write(
    batch_path: str, entry: dict[str, Any], *, positive: bool, pending: str | None
) -> dict[str, Any]:
    resource = entry["resource"]
    write = _conditional_create(resource, entry["fields"])
    write["updateMask"] = {"fieldPaths": entry["mask"]}
    expect: dict[str, Any] = (
        {"status": 200, "itemCodes": [0], "landed": [resource]}
        if positive
        else {"status": 400, "typed": "INVALID_ARGUMENT", "landed": []}
    )
    if pending:
        expect["pendingReason"] = pending
    return {
        "kind": "batch-write",
        "case": f"field-path-{'accept' if positive else 'refuse'}",
        "service": "firestore",
        "method": "POST",
        "path": batch_path,
        "body": {"writes": [write]},
        "expect": expect,
    }


# The shared Gate's own per-request recovery reserve and its wall-clock ceiling.
GATE_REQUEST_SECONDS = 13
GATE_INTERVAL_SECONDS = 0.25
GATE_WALL_SECONDS_MAX = 1200
OBSERVATION_WINDOW_SECONDS = 300


def _recovery_seconds(operations: int) -> int:
    """The reserve the Gate demands for this many recovery requests, plus slack."""
    needed = operations * (GATE_REQUEST_SECONDS + GATE_INTERVAL_SECONDS)
    return int(needed) + 60


def _wall_seconds(operations: int) -> int:
    total = _recovery_seconds(operations) + OBSERVATION_WINDOW_SECONDS
    if total > GATE_WALL_SECONDS_MAX:
        raise ValueError(
            f"{operations} recovery requests do not fit the Gate's "
            f"{GATE_WALL_SECONDS_MAX}-second ceiling; split the campaign"
        )
    return total


def _case_index(limits: list[dict[str, Any]], part: str) -> list[dict[str, Any]]:
    batch = (
        []
        if part == "B"
        else [
            ("batch-malformed-middle", "BatchWrite continuation past a malformed item"),
            (
                "batch-undecodable-value",
                "BatchWrite continuation past an undecodable value",
            ),
            ("batch-duplicate-document", "BatchWrite whole-request validation control"),
        ]
    )
    cases = [
        {"id": f"{CAMPAIGN}{part}/{name}", "residue": "R3", "condition": condition}
        for name, condition in batch
    ]
    for spec in limits:
        case = {
            "id": f"{CAMPAIGN}{part}/{spec['label']}",
            "residue": "R4",
            "condition": f"{spec['id']} boundary",
            "limitId": spec["id"],
            "boundary": spec["boundary"],
            "emit": spec["emit"],
        }
        for key in (
            "catalogImplemented",
            "catalogUnit",
            "catalogBoundary",
            "derivedFigures",
            "boundaryUnit",
            "acceptedSideUnreachable",
            "chargedInFullWouldBe",
            "pendingReason",
            "aggregateShape",
            "pathShape",
            "metricEvidence",
            "entanglementReason",
            "indexExemption",
            "indexExemptionReason",
        ):
            if key in spec:
                case[key] = spec[key]
        cases.append(case)
    return cases


def _measure(spec: dict[str, Any], document: dict[str, Any]) -> int:
    """The quantity the limit under test is measured on, for one document."""
    measure = spec["measure"]
    if measure == "collectionIdBytes":
        segments = document["resource"].split("/documents/", 1)[1].split("/")
        return max(
            len(segment.encode())
            for index, segment in enumerate(segments)
            if index % 2 == 0
        )
    if measure == "indexedValueBytes":
        # The indexed representation before truncation: what production would
        # charge if it did not cap the indexed value.
        return max(
            _field_value_bytes(value)
            for name, value in document["fields"].items()
            if name != "_sharedOwner"
        )
    if measure == "aggregateBytes":
        # The metric the aggregate check reads: a string or bytes value on its
        # raw payload, a map or an array on its logical storage size.
        return max(
            len(value["stringValue"].encode())
            if "stringValue" in value
            else _field_value_bytes(value)
            for name, value in document["fields"].items()
            if name != "_sharedOwner"
        )
    if measure == "payloadBytes":
        # The raw string or bytes payload, which is what the field value limit
        # is measured on.
        return max(
            len(value["stringValue"].encode())
            if "stringValue" in value
            else len(value.get("bytesValue", ""))
            for name, value in document["fields"].items()
            if name != "_sharedOwner"
        )
    if measure in ("depth", "nameBytes", "documentBytes", "canonicalPathBytes"):
        return document[measure]
    return document["indexUsage"][measure]


def _refused_sides(spec: dict[str, Any]) -> set[str]:
    """Which halves of a case the campaign expects the server to refuse."""
    return {
        "create-pair": {"refuse"},
        "mask-pair": {"refuse"},
        "name-only": {"refuse"},
        "refuse-only": {"refuse"},
        "refuse-pair": {"accept", "refuse"},
        "truncating-pair": set(),
    }.get(spec.get("emit"), {"refuse"})


def _check_no_confound(documents: dict[str, Any], limits: list[dict[str, Any]]) -> None:
    """Each boundary pair must differ from its control in exactly one limit.

    A refusal is only evidence about the limit under test if every other limit
    is satisfied by the same request, so every created document is checked
    against all of them and each pair is checked against its own boundary.
    """
    for label, document in documents.items():
        if not document["owned"]:
            continue
        if document.get("indexExempt"):
            continue  # The declared exemption removes every automatic entry.
        usage = document.get("indexUsage") or index_usage(
            document["resource"], document["fields"]
        )
        limit_id = document.get("limitId")
        spec = next(
            (
                s
                for s in limits
                if f"{s['label']}-accept" == label or f"{s['label']}-refuse" == label
            ),
            {},
        )
        # A document the campaign expects to be refused may breach the limit
        # under test, and may breach a limit the campaign has declared it
        # cannot be separated from. A document it expects to create may not.
        allowed = set()
        if label.rsplit("-", 1)[-1] in _refused_sides(spec):
            allowed = {limit_id, *spec.get("entangledWith", ())}
        ceilings = (
            (
                "FS-LIMIT-INDEX-ENTRY-BYTES",
                usage["maxEntryBytes"],
                INDEX_ENTRY_BYTES_MAX,
            ),
            (
                "FS-LIMIT-INDEX-ENTRIES-PER-DOCUMENT",
                usage["entries"],
                INDEX_ENTRIES_PER_DOCUMENT_MAX,
            ),
            (
                "FS-LIMIT-INDEX-ENTRY-SUM-PER-DOCUMENT",
                usage["totalBytes"],
                INDEX_ENTRY_SUM_PER_DOCUMENT_MAX,
            ),
            (
                "FS-LIMIT-DOCUMENT-BYTES",
                document.get("documentBytes")
                or document_bytes(document["resource"], document["fields"]),
                DOCUMENT_BYTES_MAX,
            ),
            ("FS-LIMIT-DOCUMENT-NAME-BYTES", document["nameBytes"], DOCUMENT_NAME_MAX),
            (
                "FS-LIMIT-SUBCOLLECTION-DEPTH",
                document["depth"],
                SUBCOLLECTION_DEPTH_MAX,
            ),
        )
        for other, value, maximum in ceilings:
            if other in allowed or value <= maximum:
                continue
            raise ValueError(
                f"{label} would be refused by {other} ({value} exceeds {maximum})"
            )
    for spec in limits:
        observed = [
            _measure(spec, documents[f"{spec['label']}-{side}"])
            for side in ("accept", "refuse")
            if spec.get(side) is not None
        ]
        expected = spec["boundary"][-len(observed) :]
        if observed != expected:
            raise ValueError(
                f"{spec['id']} is not at its declared boundary: {observed} != {expected}"
            )


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
