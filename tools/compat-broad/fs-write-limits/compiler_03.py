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


def _create_only_patch(
    document: dict[str, Any], *, positive: bool, pending: bool = False
) -> dict[str, Any]:
    resource = document["resource"]
    expect: dict[str, Any] = {"positive": positive}
    if pending:
        # The catalog declares this limit unsupported. The expectation states
        # the documented production behaviour; a local difference is recorded
        # as a pending difference rather than as a campaign failure.
        expect["localImplementationPending"] = True
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

    # R4: the write-path catalog limits. Every boundary below is derived from
    # the default single-field index configuration: ascending, descending and
    # array-membership modes at collection scope. The campaign declares no
    # composite index and no field override, so it requires no addition to
    # `conformance/firestore.indexes.json`.
    limits = _limit_specs(root)
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
            for key in ("mask", "canonicalPathBytes"):
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
        # recovery request, so the reserve scales with the owned document count.
        "wallSeconds": 1200,
        "recoverySeconds": 810,
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
        "cases": _case_index(limits),
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
        "emit": "create-pair",
        "boundary": [
            INDEX_ENTRIES_PER_DOCUMENT_MAX,
            INDEX_ENTRIES_PER_DOCUMENT_MAX + 2,
        ],
        "measure": "entries",
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
            "emit": "create-pair",
            "boundary": [
                INDEX_ENTRY_SUM_PER_DOCUMENT_MAX,
                index_usage(**_as_args(sides["refuse"]))["totalBytes"],
            ],
            "measure": "totalBytes",
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
        "emit": "create-pair",
        "boundary": [INDEX_ENTRY_BYTES_MAX, INDEX_ENTRY_BYTES_MAX + 1],
        "measure": "maxEntryBytes",
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
        "emit": "truncating-pair",
        "boundary": [INDEXED_VALUE_TRUNCATION, 2 * INDEXED_VALUE_TRUNCATION],
        "measure": "indexedValueBytes",
        "catalogImplemented": "unsupported",
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
        "emit": "mask-pair",
        "boundary": [FIELD_PATH_BYTES_MAX, FIELD_PATH_BYTES_MAX + 1],
        "measure": "canonicalPathBytes",
        "catalogImplemented": "unsupported",
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
        "catalogImplemented": "unsupported",
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


def _limit_specs(root: str) -> list[dict[str, Any]]:
    """Every write-path limit this campaign observes, in request order."""
    return [
        {
            "id": "FS-LIMIT-COLLECTION-ID",
            "label": "collection-id",
            "emit": "create-pair",
            "boundary": [COLLECTION_ID_MAX, COLLECTION_ID_MAX + 1],
            "measure": "collectionIdBytes",
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
            "emit": "create-pair",
            "boundary": [SUBCOLLECTION_DEPTH_MAX, SUBCOLLECTION_DEPTH_MAX + 1],
            "measure": "depth",
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
        {
            "id": "FS-LIMIT-DOCUMENT-NAME-BYTES",
            "label": "document-name",
            "emit": "name-only",
            "boundary": [DOCUMENT_NAME_MAX, DOCUMENT_NAME_MAX + 1],
            "measure": "nameBytes",
            "accept": _probe(
                _padded_resource(root, "name-exact", DOCUMENT_NAME_MAX),
                _fields(_padded_resource(root, "name-exact", DOCUMENT_NAME_MAX), 104),
            ),
            "refuse": _probe(
                _padded_resource(root, "name-over", DOCUMENT_NAME_MAX + 1),
                _fields(
                    _padded_resource(root, "name-over", DOCUMENT_NAME_MAX + 1), 105
                ),
            ),
        },
        _entry_bytes_case(root),
        _entries_case(root),
        _entry_sum_case(root),
        _indexed_value_case(root),
        _field_path_case(root),
        _field_value_case(root),
    ]


def _limit_requests(
    spec: dict[str, Any], documents: dict[str, Any], batch_path: str
) -> list[dict[str, Any]]:
    """The ordered observation requests for one limit."""
    accept = documents.get(f"{spec['label']}-accept")
    refuse = documents[f"{spec['label']}-refuse"]
    pending = spec.get("catalogImplemented") == "unsupported"
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
    batch_path: str, entry: dict[str, Any], *, positive: bool, pending: bool
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
        expect["localImplementationPending"] = True
    return {
        "kind": "batch-write",
        "case": f"field-path-{'accept' if positive else 'refuse'}",
        "service": "firestore",
        "method": "POST",
        "path": batch_path,
        "body": {"writes": [write]},
        "expect": expect,
    }


def _case_index(limits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    batch = [
        ("batch-malformed-middle", "BatchWrite continuation past a malformed item"),
        (
            "batch-undecodable-value",
            "BatchWrite continuation past an undecodable value",
        ),
        ("batch-duplicate-document", "BatchWrite whole-request validation control"),
    ]
    cases = [
        {"id": f"{CAMPAIGN}/{name}", "residue": "R3", "condition": condition}
        for name, condition in batch
    ]
    for spec in limits:
        case = {
            "id": f"{CAMPAIGN}/{spec['label']}",
            "residue": "R4",
            "condition": f"{spec['id']} boundary",
            "limitId": spec["id"],
            "boundary": spec["boundary"],
            "emit": spec["emit"],
        }
        for key in (
            "catalogImplemented",
            "acceptedSideUnreachable",
            "chargedInFullWouldBe",
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


def _check_no_confound(documents: dict[str, Any], limits: list[dict[str, Any]]) -> None:
    """Each boundary pair must differ from its control in exactly one limit.

    A refusal is only evidence about the limit under test if every other limit
    is satisfied by the same request, so every created document is checked
    against all of them and each pair is checked against its own boundary.
    """
    for label, document in documents.items():
        if not document["owned"]:
            continue
        usage = document.get("indexUsage") or index_usage(
            document["resource"], document["fields"]
        )
        limit_id = document.get("limitId")
        spec = next((s for s in limits if s["id"] == limit_id), {})
        # A refused document may breach the limit under test, and may breach a
        # limit the campaign has declared it cannot be separated from.
        allowed = set()
        if label.endswith("-refuse"):
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
