"""Offline semantic comparison for the finite compiled IN query campaign."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote

from query_in_compiler import validate_plan
from query_in_production import (
    RawJournal,
    _reject_json_constant,
    _typed_query_row,
    _unique_json_object,
)

_TIMESTAMP = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$")
_PHASES = (("rows", "observation", 6), ("cleanup", "recovery", 3))
_RAW_LIMIT = 65536
_BUNDLE_LIMIT = 131072


def _read_json_file(path: Path, limit: int) -> Any:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        with os.fdopen(fd, "rb") as stream:
            encoded = stream.read(limit + 1)
    except BaseException:
        # fdopen owns the descriptor once it succeeds; this covers open/read
        # failures before ownership is transferred to the file object.
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    if len(encoded) > limit:
        raise ValueError("collection bundle capacity")
    return json.loads(
        encoded,
        parse_constant=_reject_json_constant,
        object_pairs_hook=_unique_json_object,
    )


def _json_media_type(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value.split(";", 1)[0].strip().lower() == "application/json"
    )


def load_collected_bundle(directory: str | Path) -> dict[str, Any]:
    """Load collector JSON and bind all nine immutable raw sidecars.

    The compact journal is trusted only for operation and receipt metadata.
    Raw response bytes are read from the manifest's named sidecars and remain
    the comparator's authority; no bytes are reconstructed from compact JSON.
    """
    root = Path(directory)
    bundle = _read_json_file(root / "collection.json", _BUNDLE_LIMIT)
    if not isinstance(bundle, dict):
        raise TypeError("collection bundle must be an object")
    rows = bundle.get("rows")
    cleanup = bundle.get("cleanup")
    if not isinstance(rows, list) or not isinstance(cleanup, list):
        raise TypeError("collection bundle journals are missing")
    if len(rows) != 6 or len(cleanup) != 3:
        raise ValueError("collection bundle does not contain nine journal rows")

    journal = RawJournal.reload(root / "raw")
    try:
        bindings = journal._bindings  # validated and immutable after reload
        if len(bindings) != 9:
            raise ValueError("collection bundle does not contain nine raw slots")
        by_slot: dict[int, dict[str, Any]] = {}
        for binding in bindings.values():
            phase = binding["phase"]
            index = binding["index"]
            slot = index if phase == "observation" else 6 + index
            if slot in by_slot:
                raise ValueError("collection bundle has duplicate raw slot")
            by_slot[slot] = binding
        if set(by_slot) != set(range(9)):
            raise ValueError("collection bundle does not contain nine raw slots")

        journal_rows = [*rows, *cleanup]
        raw: dict[str, Any] = {}
        for slot in range(9):
            binding = by_slot[slot]
            row = journal_rows[slot]
            if not isinstance(row, dict) or row.get("raw") != binding:
                raise ValueError(f"raw slot {slot} is not bound to its journal row")
            fd = os.open(binding["path"], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=journal._fd)
            try:
                with os.fdopen(fd, "rb") as stream:
                    body = stream.read(_RAW_LIMIT + 1)
            except BaseException:
                try:
                    os.close(fd)
                except OSError:
                    pass
                raise
            if len(body) > _RAW_LIMIT or len(body) != binding["byteCount"]:
                raise ValueError(f"raw slot {slot} byte count differs")
            digest = hashlib.sha256(body).hexdigest()
            if digest != binding["sha256"]:
                raise ValueError(f"raw slot {slot} hash differs")
            view = {
                "projectionVersion": 1,
                "sourceRawSha256": digest,
                "rawBody": body,
                "phase": binding["phase"],
                "index": binding["index"],
                "status": binding["status"],
                "complete": binding["complete"],
                "byteCount": binding["byteCount"],
                "contentType": binding["contentType"],
            }
            if slot == 2:
                semantic = journal.semantic_view(binding)
                view.update({key: value for key, value in semantic.items() if key != "rawBody"})
            row["rawSha256"] = digest
            raw[str(slot)] = view
        bundle["raw"] = raw
        return bundle
    finally:
        journal.close()


def _exact(left: Any, right: Any) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(_exact(left[key], right[key]) for key in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(_exact(a, b) for a, b in zip(left, right, strict=True))
    return left == right


def _timestamp_order(value: str) -> tuple[datetime, int]:
    base, _, fraction = value[:-1].partition(".")
    return datetime.fromisoformat(base), int(fraction.ljust(9, "0")) if fraction else 0


def _owned_path(value: str, plan: dict[str, Any]) -> str:
    document = "/v1/" + plan["document"]
    parent = "/v1/" + plan["parent"]
    if value == document:
        return "/v1/$owned-document"
    if value == document + "?currentDocument.exists=false":
        return "/v1/$owned-document?currentDocument.exists=false"
    if value == parent + ":runQuery":
        return "/v1/$owned-parent:runQuery"
    return value


def _timestamp_ranks(value: Any, *, key_name: str = "") -> dict[str, int]:
    found: set[str] = set()

    def visit(item: Any, field: str) -> None:
        if isinstance(item, dict):
            for name, child in item.items():
                visit(child, name)
        elif isinstance(item, list):
            for child in item:
                visit(child, field)
        elif isinstance(item, str):
            if field in {"createTime", "updateTime", "readTime"} and _TIMESTAMP.fullmatch(item):
                found.add(item)
            elif field == "path" and "?currentDocument.updateTime=" in item:
                timestamp = unquote(item.split("?currentDocument.updateTime=", 1)[1])
                if _TIMESTAMP.fullmatch(timestamp):
                    found.add(timestamp)

    visit(value, key_name)
    return {timestamp: index for index, timestamp in enumerate(sorted(found, key=_timestamp_order))}


def _typed_query_response(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(
        _typed_query_row(row) and (index == len(value) - 1 or row.get("done") is not True)
        for index, row in enumerate(value)
    )


def _canonical(value: Any, plan: dict[str, Any], timestamp_ranks: dict[str, int], *, timestamp_field: bool = False, key_name: str = "") -> Any:
    if isinstance(value, str):
        if key_name == "path":
            value = _owned_path(value, plan)
        if key_name in {"name", "resource", "targetResources"} and value == plan["document"]:
            return "$owned-document"
        if key_name == "parent" and value == plan["parent"]:
            return "$owned-parent"
        if timestamp_field and _TIMESTAMP.fullmatch(value):
            if value not in timestamp_ranks:
                timestamp_ranks[value] = len(timestamp_ranks)
            return {"$timestampRank": timestamp_ranks[value]}
        marker = "?currentDocument.updateTime="
        if key_name == "path" and marker in value:
            prefix, encoded = value.split(marker, 1)
            timestamp = unquote(encoded)
            if _TIMESTAMP.fullmatch(timestamp):
                if timestamp not in timestamp_ranks:
                    timestamp_ranks[timestamp] = len(timestamp_ranks)
                return {
                    "$timestampQueryPrefix": _owned_path(prefix, plan) + marker,
                    "$timestampRank": timestamp_ranks[timestamp],
                }
        return value
    if isinstance(value, list):
        return [_canonical(item, plan, timestamp_ranks, timestamp_field=timestamp_field, key_name=key_name) for item in value]
    if isinstance(value, dict):
        return {
            key: _canonical(item, plan, timestamp_ranks, timestamp_field=key in {"createTime", "updateTime", "readTime"}, key_name=key)
            for key, item in sorted(value.items())
        }
    return value


def _receipt_valid(receipt: Any, *, allow_skip: bool) -> bool:
    if not isinstance(receipt, dict) or receipt.get("complete") is not True:
        return False
    if receipt.get("failure") is not None:
        return False
    if "skipped" in receipt:
        return allow_skip and receipt.get("status") is None and receipt.get("body") is None and receipt["skipped"] in {
            "already-absent",
            "create-not-proven",
            "create-version-mismatch",
            "unsafe-delete",
        }
    return (
        type(receipt.get("status")) is int
        and 100 <= receipt["status"] <= 599
        and "body" in receipt
    )


def _recovery_request_matches(
    row: dict[str, Any], operation: dict[str, Any], prior: dict[str, Any]
) -> bool:
    request = row.get("request")
    if (operation.get("kind") != "cleanup-conditional-delete" or row.get("skipped")) and _exact(request, operation):
        return True
    if operation.get("kind") != "cleanup-conditional-delete":
        return False
    if not isinstance(request, dict) or not isinstance(request.get("path"), str):
        return False
    body = prior.get("body") if isinstance(prior, dict) else None
    update_time = body.get("updateTime") if isinstance(body, dict) else None
    suffix = "?currentDocument.updateTime=" + quote(update_time, safe="")
    expected = copy.deepcopy(operation)
    expected["path"] += suffix
    return isinstance(update_time, str) and _exact(request, expected)


def _typed_absence(row: dict[str, Any]) -> bool:
    body = row.get("body")
    error = body.get("error") if isinstance(body, dict) else None
    return (
        row.get("status") == 404
        and isinstance(error, dict)
        and type(error.get("code")) is int
        and error["code"] == 404
        and error.get("status") == "NOT_FOUND"
    )


def _owned_read(row: dict[str, Any], plan: dict[str, Any]) -> bool:
    body = row.get("body")
    return (
        row.get("status") == 200
        and isinstance(body, dict)
        and body.get("name") == plan["document"]
        and body.get("fields") == plan["fixtureFields"]
        and isinstance(body.get("updateTime"), str)
        and _TIMESTAMP.fullmatch(body["updateTime"]) is not None
    )


def _typed_invalid_argument(row: dict[str, Any]) -> bool:
    body = row.get("body")
    error = body.get("error") if isinstance(body, dict) else None
    return row.get("status") == 400 and isinstance(error, dict) and error.get("status") == "INVALID_ARGUMENT"


def _contract_match(plan: dict[str, Any], operation: dict[str, Any], row: dict[str, Any]) -> bool:
    if operation["kind"] in {"preflight-typed-absence", "cleanup-verify-absence"}:
        return _typed_absence(row)
    if operation["kind"] == "cleanup-ownership-read":
        return _typed_absence(row) or _owned_read(row, plan)
    if operation["kind"] == "cleanup-conditional-delete":
        return row.get("skipped") == "already-absent" or row.get("status") == 200
    if operation["kind"] in {"create-only-patch", "before-readback", "after-readback"}:
        return _owned_read(row, plan)
    if operation["kind"] == "positive-query":
        body = row.get("body")
        return (
            row.get("status") == 200
            and isinstance(body, dict)
            and set(body) == {"documents"}
            and body.get("documents") == [plan["expectedPositiveDocument"]]
        )
    if operation["kind"] == "diagnostic-query":
        return _typed_invalid_argument(row)
    return False


def _raw_views_semantically_equal(
    left: dict[str, Any], right: dict[str, Any], left_plan: dict[str, Any], right_plan: dict[str, Any]
) -> bool:
    """Allow run-generated timestamp bytes to differ after typed validation."""
    if set(left) != set(right):
        return False
    left_body = left.get("rawBody")
    right_body = right.get("rawBody")
    if not isinstance(left_body, bytes) or not isinstance(right_body, bytes):
        return False
    left_meta = {key: value for key, value in left.items() if key not in {"rawBody", "sourceRawSha256", "byteCount"}}
    right_meta = {key: value for key, value in right.items() if key not in {"rawBody", "sourceRawSha256", "byteCount"}}
    if not _exact(_canonical(left_meta, left_plan, _timestamp_ranks(left_meta)), _canonical(right_meta, right_plan, _timestamp_ranks(right_meta))):
        return False
    try:
        parsed_left = json.loads(left_body, parse_constant=_reject_json_constant, object_pairs_hook=_unique_json_object)
        parsed_right = json.loads(right_body, parse_constant=_reject_json_constant, object_pairs_hook=_unique_json_object)
    except (UnicodeError, ValueError, RecursionError):
        return False
    return _exact(
        _canonical(parsed_left, left_plan, _timestamp_ranks(parsed_left)),
        _canonical(parsed_right, right_plan, _timestamp_ranks(parsed_right)),
    )


def _validate_side(bundle: Any) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], list[bool]]:
    if not isinstance(bundle, dict):
        raise TypeError("evidence bundle must be an object")
    plan = bundle.get("plan")
    validate_plan(plan)
    if bundle.get("planDigest") is not None and bundle["planDigest"] != plan.get("planDigest"):
        raise ValueError("plan digest binding differs")
    if bundle.get("acquisitionValidated") is True or bundle.get("promotionReady") is True:
        raise ValueError("comparator cannot accept acquisition authority")
    rows = bundle.get("rows")
    cleanup = bundle.get("cleanup")
    if not isinstance(rows, list) or not isinstance(cleanup, list):
        raise TypeError("missing operation journals")
    if len(rows) != 6 or len(cleanup) != 3:
        raise ValueError("incomplete operation journals")
    for index, (row, operation) in enumerate(zip(rows, plan["observation"], strict=True)):
        if (
            not isinstance(row, dict)
            or type(row.get("index")) is not int
            or row["index"] != index
            or not _exact(row.get("request"), operation)
            or not _receipt_valid(row, allow_skip=False)
        ):
            raise ValueError(f"invalid observation journal row {index}")
    for index, (row, operation) in enumerate(zip(cleanup, plan["recovery"], strict=True)):
        if (
            not isinstance(row, dict)
            or type(row.get("index")) is not int
            or row["index"] != index
            or not _recovery_request_matches(row, operation, cleanup[0])
            or not _receipt_valid(row, allow_skip=True)
        ):
            raise ValueError(f"invalid recovery journal row {index}")
    if not (_typed_absence(cleanup[0]) or _owned_read(cleanup[0], plan)):
        raise ValueError("cleanup ownership read is not typed")
    if cleanup[1].get("skipped") == "already-absent" and not _typed_absence(cleanup[0]):
        raise ValueError("already-absent skip lacks typed absence proof")
    if cleanup[1].get("skipped") in {"create-not-proven", "create-version-mismatch", "unsafe-delete"}:
        raise ValueError("unsafe cleanup skip is indeterminate")
    if "skipped" not in cleanup[1] and not (
        cleanup[1].get("status") == 200
        and isinstance(cleanup[1].get("body"), dict)
        and _owned_read(cleanup[0], plan)
        and isinstance(cleanup[1].get("request"), dict)
        and isinstance(cleanup[0].get("body"), dict)
        and cleanup[1]["request"].get("path", "").endswith(
            "?currentDocument.updateTime="
            + quote(cleanup[0]["body"].get("updateTime", ""), safe="")
        )
    ):
        raise ValueError("cleanup delete receipt is not typed")
    if not _typed_absence(cleanup[2]):
        raise ValueError("cleanup absence is not typed")
    if not _owned_read(rows[1], plan):
        raise ValueError("create ownership is not proven")
    created_time = rows[1]["body"]["updateTime"]
    created_create_time = rows[1]["body"].get("createTime")
    for index in (3, 5):
        if not _owned_read(rows[index], plan) or rows[index]["body"]["updateTime"] != created_time or (created_create_time is not None and rows[index]["body"].get("createTime") != created_create_time):
            raise ValueError("readback version is not bound to creation")
    if _owned_read(cleanup[0], plan) and (cleanup[0]["body"]["updateTime"] != created_time or (created_create_time is not None and cleanup[0]["body"].get("createTime") != created_create_time)):
        raise ValueError("cleanup version is not bound to creation")
    ownership = bundle.get("ownership", {})
    if not isinstance(ownership, dict) or ownership.get("cleanupComplete") is not True:
        raise ValueError("ownership and cleanup evidence is incomplete")
    raw = bundle.get("raw")
    if raw is not None and not isinstance(raw, dict):
        raise ValueError("typed raw receipt evidence is malformed")
    if isinstance(raw, dict):
        if set(raw) != {str(index) for index in range(9)}:
            raise ValueError("typed raw receipt set is incomplete")
        journal = [*rows, *cleanup]
        for slot, view in raw.items():
            if not isinstance(slot, str) or not slot.isdigit() or not isinstance(view, dict):
                raise ValueError("typed raw receipt evidence is malformed")
            digest = view.get("sourceRawSha256")
            if not isinstance(digest, str) or len(digest) != 64:
                raise ValueError("typed raw receipt evidence is unbound")
            raw_row = journal[int(slot)] if int(slot) < len(journal) else None
            if not isinstance(raw_row, dict) or raw_row.get("rawSha256") != digest:
                raise ValueError("typed raw receipt is not bound to its journal row")
            if raw_row.get("skipped") is not None and view.get("complete") is True and view.get("status") is None:
                raise ValueError("skipped cleanup cannot have a complete raw receipt")
            raw_body = view.get("rawBody")
            if not isinstance(raw_body, bytes) or len(raw_body) > 65536:
                raise ValueError("typed raw receipt bytes are missing")
            if hashlib.sha256(raw_body).hexdigest() != digest:
                raise ValueError("typed raw receipt hash differs")
            expected_phase = "observation" if int(slot) < 6 else "recovery"
            expected_index = int(slot) if int(slot) < 6 else int(slot) - 6
            if view.get("phase") != expected_phase or view.get("index") != expected_index:
                raise ValueError("typed raw receipt slot differs")
            if view.get("status") != raw_row.get("status") or view.get("complete") is not raw_row.get("complete"):
                raise ValueError("typed raw receipt status differs")
            if view.get("byteCount") != len(raw_body) or not _json_media_type(view.get("contentType")):
                raise ValueError("typed raw receipt metadata differs")
            parsed_body = json.loads(raw_body, parse_constant=_reject_json_constant, object_pairs_hook=_unique_json_object)
            if int(slot) != 2 and parsed_body != raw_row.get("body"):
                raise ValueError(f"raw receipt body differs from journal row {slot}")
        query_time_consistent = True
        try:
            parsed = json.loads(raw["2"]["rawBody"], parse_constant=_reject_json_constant, object_pairs_hook=_unique_json_object)
            derived = ([
                {"name": item["document"]["name"], "fields": item["document"]["fields"]}
                for item in parsed
                if "document" in item
            ] if _typed_query_response(parsed) else None)
        except (UnicodeError, ValueError, RecursionError):
            derived = None
        if (
            derived is None
            or raw["2"].get("documents") != derived
            or derived != rows[2].get("body", {}).get("documents")
        ):
            raise ValueError("positive query projection is not row-bound")
        for item in parsed:
            document = item.get("document")
            created = rows[1]["body"]
            read_time = item.get("readTime")
            if isinstance(read_time, str) and _TIMESTAMP.fullmatch(read_time):
                for field in ("createTime", "updateTime"):
                    version = document.get(field, created.get(field)) if isinstance(document, dict) else created.get(field)
                    if isinstance(version, str) and _TIMESTAMP.fullmatch(version) and _timestamp_order(read_time) < _timestamp_order(version):
                        query_time_consistent = False
            if not isinstance(document, dict) or document.get("name") != plan["document"]:
                continue
            for field in ("createTime", "updateTime"):
                if field in document and field in created and document[field] != created[field]:
                    query_time_consistent = False
            if "createTime" in document and "updateTime" in document and _timestamp_order(document["createTime"]) > _timestamp_order(document["updateTime"]):
                query_time_consistent = False
    else:
        raise TypeError("typed raw receipt evidence is required")
    contract = [
        _contract_match(plan, operation, row)
        for operation, row in [
            *zip(plan["observation"], rows, strict=True),
            *zip(plan["recovery"], cleanup, strict=True),
        ]
    ]
    contract[2] = contract[2] and query_time_consistent
    return plan, rows, cleanup, contract


def _canonical_journal(
    plan: dict[str, Any], rows: list[dict[str, Any]], cleanup: list[dict[str, Any]]
) -> list[Any]:
    ranks = _timestamp_ranks([*rows, *cleanup])
    result: list[Any] = []
    for row in [*rows, *cleanup]:
        result.append(
            {
                "index": row["index"],
                "request": _canonical(row["request"], plan, ranks),
                "complete": row["complete"],
                "failure": row.get("failure"),
                "status": row.get("status"),
                "body": _canonical(row.get("body"), plan, ranks),
                "skipped": row.get("skipped"),
            }
        )
    return result


def compare_evidence(production: dict[str, Any], local: dict[str, Any]) -> dict[str, Any]:
    """Compare two retained bundles without asserting production acquisition."""
    result: dict[str, Any] = {
        "kind": "fs-query-in-boundary-semantic-kernel-v1",
        "semanticOnly": True,
        "classification": "INDETERMINATE",
        "acquisitionValidated": False,
        "promotionReady": False,
        "rows": [],
        "errors": [],
    }
    try:
        production_plan, production_rows, production_cleanup, production_contract = _validate_side(production)
        local_plan, local_rows, local_cleanup, local_contract = _validate_side(local)
    except (ValueError, TypeError, KeyError, IndexError) as error:
        result["errors"].append(str(error))
        return result
    try:
        left = _canonical_journal(production_plan, production_rows, production_cleanup)
        right = _canonical_journal(local_plan, local_rows, local_cleanup)
    except ValueError as error:
        result["errors"].append(str(error))
        return result
    for index, (a, b) in enumerate(zip(left, right, strict=True)):
        raw_a = {key: production_rows[index][key] for key in ("status", "body")} if index < 6 else production_cleanup[index - 6]
        raw_b = {key: local_rows[index][key] for key in ("status", "body")} if index < 6 else local_cleanup[index - 6]
        classification = "SEMANTIC_MISMATCH" if not (production_contract[index] and local_contract[index]) else ("SEMANTIC_MISMATCH" if not _exact(a, b) else (
            "MATCH" if _exact(raw_a, raw_b) else "EXPECTED_NONDETERMINISM"
        ))
        result["rows"].append({"index": index, "classification": classification})
    classes = {row["classification"] for row in result["rows"]}
    result["classification"] = next(
        value for value in ("SEMANTIC_MISMATCH", "EXPECTED_NONDETERMINISM", "MATCH") if value in classes
    )
    left_raw = production.get("raw")
    right_raw = local.get("raw")
    if left_raw is not None or right_raw is not None:
        if not isinstance(left_raw, dict) or not isinstance(right_raw, dict):
            result["classification"] = "INDETERMINATE"
            result["errors"].append("raw receipt pair is incomplete")
            return result
        raw_left = {
            key: {name: value for name, value in view.items() if name != "sourceRawSha256"}
            for key, view in left_raw.items()
        }
        raw_right = {
            key: {name: value for name, value in view.items() if name != "sourceRawSha256"}
            for key, view in right_raw.items()
        }
        if not _exact(raw_left, raw_right):
            result["classification"] = "SEMANTIC_MISMATCH"
            try:
                semantically_equal = (
                    set(left_raw) == set(right_raw)
                    and all(
                        _raw_views_semantically_equal(left_raw[key], right_raw[key], production_plan, local_plan)
                        for key in set(left_raw) & set(right_raw)
                    )
                )
            except ValueError as error:
                result["classification"] = "INDETERMINATE"
                result["errors"].append(str(error))
                return result
            if semantically_equal and all(row["classification"] != "SEMANTIC_MISMATCH" for row in result["rows"]):
                result["classification"] = "EXPECTED_NONDETERMINISM"
        elif result["classification"] == "MATCH" and left_raw != right_raw:
            result["classification"] = "EXPECTED_NONDETERMINISM"
    return result


def compare_rows(
    production_plan: dict[str, Any],
    production_rows: list[dict[str, Any]],
    local_plan: dict[str, Any],
    local_rows: list[dict[str, Any]],
    *,
    production_cleanup: list[dict[str, Any]] | None = None,
    local_cleanup: list[dict[str, Any]] | None = None,
    production_raw: dict[str, Any] | None = None,
    local_raw: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compatibility entry point for callers holding journals separately."""
    return compare_evidence(
        {"plan": production_plan, "rows": production_rows, "cleanup": production_cleanup or [], "ownership": {"cleanupComplete": True}, "raw": production_raw},
        {"plan": local_plan, "rows": local_rows, "cleanup": local_cleanup or [], "ownership": {"cleanupComplete": True}, "raw": local_raw},
    )


# Keep the adapter discoverable to callers that use the shorter bundle name.
load_bundle = load_collected_bundle
load_collector_bundle = load_collected_bundle


compare_collections = compare_evidence
