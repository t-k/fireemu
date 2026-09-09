"""Own one temporary composite index in a fresh UUID collection group only."""

import re
import time

from aggregation_corpus import index_definition
from evidence_common import require
from probe import DATABASE, request, require_status


def resolved_operation(value: dict, name: str) -> bool:
    return (
        value.get("name") == name
        and value.get("done") is True
        and (
            isinstance(value.get("response"), dict)
            != isinstance(value.get("error"), dict)
        )
    )


def finish_operation(token: str, receipt: dict, persist) -> dict:
    name = receipt.get("operation", "")
    require(
        isinstance(name, str)
        and re.fullmatch(re.escape(DATABASE) + r"/operations/[A-Za-z0-9_-]+", name)
        is not None,
        "unknown create outcome; exact operation identity required for recovery",
    )
    # Firebase documents a several-minute minimum, even for an empty database.
    # This is an operational bound, not a claimed service SLA.
    deadline = time.monotonic() + 15 * 60
    while time.monotonic() < deadline:
        status, operation = request(
            f"https://firestore.googleapis.com/v1/{name}", token
        )
        require_status(status, 200)
        if not isinstance(operation, dict):
            raise TypeError("invalid operation readback")
        require(operation.get("name") == name, "operation identity changed")
        receipt["operationReadback"] = operation
        persist()
        if resolved_operation(operation, name):
            return operation
        time.sleep(5)
    raise ValueError("create operation remains unresolved")


def index_parent(collection: str) -> str:
    require(
        re.fullmatch(r"compat_[a-f0-9]{32}", collection) is not None,
        "index collection is not a private UUID namespace",
    )
    return f"{DATABASE}/collectionGroups/{collection}/indexes"


def owned_index(value: dict, collection: str) -> bool:
    return re.fullmatch(
        re.escape(index_parent(collection)) + r"/[A-Za-z0-9_-]+", value.get("name", "")
    ) is not None and all(
        value.get(key) == expected for key, expected in index_definition().items()
    )


def list_indexes(token: str, collection: str) -> list:
    status, value = request(
        f"https://firestore.googleapis.com/v1/{index_parent(collection)}", token
    )
    require_status(status, 200)
    if not isinstance(value, dict) or value.get("nextPageToken"):
        raise ValueError("unexpected index listing")
    indexes = value.get("indexes", [])
    require(
        isinstance(indexes, list) and all(isinstance(item, dict) for item in indexes),
        "invalid index listing",
    )
    return select_indexes(indexes, collection)


def select_indexes(indexes: list, collection: str) -> list:
    # Production may return indexes for other collection groups as well.
    # Their definitions never enter our ownership/deletion candidate set.
    parent = index_parent(collection) + "/"
    require(all(isinstance(item.get("name"), str) for item in indexes), "unnamed index")
    return [item for item in indexes if item["name"].startswith(parent)]


def prepare_index(token: str, collection: str, receipt: dict, persist) -> None:
    require(
        not list_indexes(token, collection),
        "fresh collection unexpectedly has indexes; leave them untouched",
    )
    receipt.update(
        {
            "collection": collection,
            "baselineEmpty": True,
            "createAttempted": True,
            "definition": index_definition(),
        }
    )
    persist()
    status, operation = request(
        f"https://firestore.googleapis.com/v1/{index_parent(collection)}",
        token,
        index_definition(),
    )
    require_status(status, 200)
    if not isinstance(operation, dict):
        raise TypeError("invalid index operation")
    receipt["operation"] = operation.get("name")
    persist()
    completed = finish_operation(token, receipt, persist)
    require("error" not in completed, "index creation failed")
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        indexes = list_indexes(token, collection)
        require(
            len(indexes) <= 1
            and all(owned_index(item, collection) for item in indexes),
            "unexpected index in owned namespace",
        )
        if indexes and indexes[0].get("state") == "READY":
            receipt["ready"] = indexes[0]
            persist()
            return
        time.sleep(2)
    raise ValueError("owned index did not become READY within the bounded wait")


def cleanup_index(
    token: str, collection: str, receipt: dict, persist=lambda: None
) -> None:
    if not receipt.get("createAttempted") or not receipt.get("baselineEmpty"):
        return
    try:
        # An empty list is not absence proof while a create may still materialize.
        finish_operation(token, receipt, persist)
        indexes = list_indexes(token, collection)
        require(
            all(owned_index(item, collection) for item in indexes),
            "refusing to delete an unrecognized index",
        )
        receipt["deletedNames"] = []
        for item in indexes:
            status, _ = request(
                f"https://firestore.googleapis.com/v1/{item['name']}",
                token,
                method="DELETE",
            )
            require_status(status, 200)
            receipt["deletedNames"].append(item["name"])
            persist()
        receipt["confirmedMissing"] = not list_indexes(token, collection)
    except Exception as error:  # noqa: BLE001 -- preserve a sanitized exact-namespace recovery receipt.
        receipt["confirmedMissing"] = False
        receipt["cleanupError"] = type(error).__name__
