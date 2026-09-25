"""Test-only in-memory fixture; not an emulator or compatibility oracle."""

from __future__ import annotations

import copy
from typing import Any
from urllib.parse import parse_qs, urlsplit


def _receipt(status: int, body: Any) -> dict[str, Any]:
    return {"complete": True, "failure": None, "status": status, "body": body}


def _absent() -> dict[str, Any]:
    return {"error": {"code": 404, "status": "NOT_FOUND"}}


def _resource(operation: dict[str, Any]) -> str:
    return operation["path"].split("?", 1)[0].removeprefix("/v1/")


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
            return (
                _receipt(200, copy.deepcopy(document))
                if document
                else _receipt(404, _absent())
            )
        if method == "PATCH":
            if resource in self.documents:
                return _receipt(
                    409, {"error": {"code": 409, "status": "ALREADY_EXISTS"}}
                )
            body = copy.deepcopy(operation["body"])
            body["updateTime"] = self._time()
            self.documents[resource] = body
            return _receipt(200, copy.deepcopy(body))
        if method == "POST":
            writes = operation["body"]["writes"]
            resource = writes[0]["transform"]["document"]
            count = sum(len(write["transform"]["fieldTransforms"]) for write in writes)
            if count > 500:
                return _receipt(
                    400,
                    {
                        "error": {
                            "code": 400,
                            "status": "INVALID_ARGUMENT",
                            "message": "field transform limit",
                        }
                    },
                )
            document = copy.deepcopy(self.documents[resource])
            for write in writes:
                for transform in write["transform"]["fieldTransforms"]:
                    document["fields"][transform["fieldPath"]] = {"integerValue": "1"}
            document["updateTime"] = self._time()
            self.documents[resource] = document
            return _receipt(
                200,
                {
                    "commitTime": document["updateTime"],
                    "writeResults": [
                        {"updateTime": document["updateTime"]} for _ in writes
                    ],
                },
            )
        if method == "DELETE":
            version = parse_qs(urlsplit(operation["path"]).query).get(
                "currentDocument.updateTime", [None]
            )[0]
            document = self.documents.get(resource)
            if document is None:
                return _receipt(404, _absent())
            if version != document["updateTime"]:
                return _receipt(
                    412, {"error": {"code": 412, "status": "FAILED_PRECONDITION"}}
                )
            del self.documents[resource]
            return _receipt(200, {})
        raise ValueError(f"unsupported local operation: {method}")
