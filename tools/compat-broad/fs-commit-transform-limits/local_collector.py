"""Bounded local Commit transform collector; never performs production I/O."""

from __future__ import annotations

import copy
from urllib.parse import quote, urlsplit, parse_qs
from typing import Any, Callable

from transform_compiler import compile_plan


def _receipt(status: int, body: Any) -> dict[str, Any]:
    return {"complete": True, "failure": None, "status": status, "body": body}


def _absent() -> dict[str, Any]:
    return {"error": {"code": 404, "status": "NOT_FOUND"}}


def _resource(operation: dict[str, Any]) -> str:
    return operation["path"].split("?", 1)[0].removeprefix("/v1/")


def _typed_not_found(receipt: dict[str, Any]) -> bool:
    body = receipt.get("body")
    error = body.get("error") if isinstance(body, dict) else None
    return (
        receipt.get("complete") is True
        and receipt.get("failure") is None
        and receipt.get("status") == 404
        and isinstance(error, dict)
        and error.get("code") == 404
        and error.get("status") == "NOT_FOUND"
    )


class LocalTransformStore:
    """Small deterministic local adapter for the closed compiler plan."""

    def __init__(self, *, fail_kind: str | None = None) -> None:
        self.documents: dict[str, dict[str, Any]] = {}
        self.fail_kind = fail_kind
        self._version = 0

    def _time(self) -> str:
        self._version += 1
        return f"2026-01-01T00:00:{self._version:02d}Z"

    def execute(self, operation: dict[str, Any]) -> dict[str, Any]:
        if operation["kind"] == self.fail_kind:
            return {"complete": False, "failure": "local-injected-failure"}
        method = operation["method"]
        resource = _resource(operation)
        if method == "GET":
            document = self.documents.get(resource)
            return _receipt(200, copy.deepcopy(document)) if document else _receipt(404, _absent())
        if method == "PATCH":
            if resource in self.documents:
                return _receipt(409, {"error": {"code": 409, "status": "ALREADY_EXISTS"}})
            body = copy.deepcopy(operation["body"])
            body["updateTime"] = self._time()
            self.documents[resource] = body
            return _receipt(200, copy.deepcopy(body))
        if method == "POST":
            writes = operation["body"]["writes"]
            resource = writes[0]["transform"]["document"]
            count = sum(len(write["transform"]["fieldTransforms"]) for write in writes)
            if count > 500:
                return _receipt(400, {"error": {"code": 400, "status": "INVALID_ARGUMENT", "message": "field transform limit"}})
            document = copy.deepcopy(self.documents[resource])
            for write in writes:
                for transform in write["transform"]["fieldTransforms"]:
                    document["fields"][transform["fieldPath"]] = {"integerValue": "1"}
            document["updateTime"] = self._time()
            self.documents[resource] = document
            return _receipt(200, {"commitTime": document["updateTime"], "writeResults": [{"updateTime": document["updateTime"]} for _ in writes]})
        if method == "DELETE":
            version = parse_qs(urlsplit(operation["path"]).query).get("currentDocument.updateTime", [None])[0]
            document = self.documents.get(resource)
            if document is None:
                return _receipt(404, _absent())
            if version != document["updateTime"]:
                return _receipt(412, {"error": {"code": 412, "status": "FAILED_PRECONDITION"}})
            del self.documents[resource]
            return _receipt(200, {})
        raise ValueError(f"unsupported local operation: {method}")


def _row(index: int, request: dict[str, Any], receipt: dict[str, Any]) -> dict[str, Any]:
    return {"index": index, "request": copy.deepcopy(request), **copy.deepcopy(receipt)}


def collect_local(plan: dict[str, Any], execute: Callable[[dict[str, Any]], dict[str, Any]]) -> dict[str, Any]:
    expected = compile_plan(plan["project"], plan["database"], plan["nonce"])
    if plan != expected:
        raise ValueError("compiler plan drift")

    def dispatch(operation: dict[str, Any]) -> dict[str, Any]:
        try:
            return execute(copy.deepcopy(operation))
        except Exception as error:
            return {"complete": False, "failure": f"local-executor:{type(error).__name__}"}

    rows: list[dict[str, Any]] = []
    created: set[str] = set()
    for index, operation in enumerate(plan["observation"]):
        receipt = dispatch(operation)
        row = _row(index, operation, receipt)
        rows.append(row)
        if receipt.get("complete") is not True or receipt.get("failure") is not None:
            break
        kind = operation["kind"]
        body = receipt.get("body")
        resource = operation.get("resource") or _resource(operation)
        if kind == "preflight-typed-absence":
            if not _typed_not_found(receipt):
                break
        elif kind == "create-only-patch":
            fields = body.get("fields") if isinstance(body, dict) else None
            if receipt.get("status") != 200 or not isinstance(body, dict) or body.get("name") != resource or fields != operation["body"]["fields"]:
                break
            created.add(resource)
        elif kind in {"baseline-readback", "poststate-readback", "poststate-control-readback"}:
            expected_status = operation["expect"]["status"]
            if receipt.get("status") != expected_status or not isinstance(body, dict) or body.get("name") != resource:
                break
        elif kind == "commit-transform":
            expected = operation["expect"]["outcome"]
            if expected == "accepted" and receipt.get("status") != 200:
                break
            if expected == "refused" and not (400 <= receipt.get("status", 0) < 500):
                break
    cleanup: list[dict[str, Any]] = []
    recovery = plan["recovery"]
    for index, declared in enumerate(recovery):
        resource = declared["resource"]
        if resource not in created:
            cleanup.append(_row(index, declared, {"complete": True, "failure": None, "status": None, "body": {"skipped": "not-created"}, "skipped": True}))
            continue
        operation = copy.deepcopy(declared)
        if declared["kind"] == "cleanup-ownership-read":
            receipt = dispatch(operation)
            body = receipt.get("body")
            owned = (
                receipt.get("status") == 200
                and isinstance(body, dict)
                and body.get("name") == resource
                and body.get("fields", {}).get("_sharedOwner") == {"referenceValue": resource}
                and isinstance(body.get("updateTime"), str)
            )
            row = _row(index, operation, receipt)
            if receipt.get("complete") is not True or receipt.get("failure") is not None or (receipt.get("status") == 200 and not owned):
                row["complete"] = False
                row["failure"] = "ownership-mismatch"
            cleanup.append(row)
            continue
        if declared["kind"] == "cleanup-conditional-delete":
            previous = cleanup[index - 1]
            body = previous.get("body")
            if previous.get("complete") is not True or previous.get("failure") is not None or previous.get("status") != 200 or not isinstance(body, dict) or not body.get("updateTime"):
                cleanup.append(_row(index, declared, {"complete": False, "failure": "owned-read-unavailable", "status": None, "body": None}))
                continue
            operation["path"] += "?currentDocument.updateTime=" + quote(body["updateTime"], safe="")
        receipt = dispatch(operation)
        cleanup_row = _row(index, operation, receipt)
        cleanup_row["absent"] = operation["kind"] == "cleanup-verify-absence" and _typed_not_found(receipt)
        cleanup.append(cleanup_row)
    absence = {resource: any(row.get("request", {}).get("resource") == resource and row.get("request", {}).get("kind") == "cleanup-verify-absence" and row.get("absent") is True for row in cleanup) for resource in plan["ownedResources"]}
    recording = len(rows) == len(plan["observation"]) and all(row.get("complete") is True and row.get("failure") is None for row in rows)
    cleanup_complete = (not created) or (len(cleanup) == len(recovery) and all(row.get("complete") is True and (row.get("status") == 404 if row["request"]["kind"] == "cleanup-verify-absence" else row.get("status") in (200, None)) for row in cleanup) and all(absence.values()))
    return {"productionExecuted": False, "recordingComplete": recording, "cleanupComplete": cleanup_complete, "completed": recording and cleanup_complete, "rows": rows, "cleanup": cleanup, "resourceAbsence": absence}
