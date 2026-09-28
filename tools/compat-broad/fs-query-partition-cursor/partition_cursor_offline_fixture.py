"""Offline fixture transport that answers the compiled plan without any socket.

This module is test support. It never opens a connection, reads a credential or
produces production evidence; it replays the compiled expectations so collector
and shadow contracts can be exercised offline.
"""

from __future__ import annotations

import json

from partition_cursor_case import compile_plan

NONCE = "a" * 32
TIME = "2026-09-18T00:00:00.000001Z"


def plan() -> dict:
    return compile_plan("demo-project", "(default)", NONCE)


def _document(name: str, ordinal: int) -> dict:
    return {
        "name": name,
        "fields": {
            "n": {"integerValue": str(ordinal)},
            "g": {"stringValue": "a" if ordinal % 2 == 0 else "b"},
        },
        "createTime": TIME,
        "updateTime": TIME,
    }


def partition_cursor(name: str) -> dict:
    return {"values": [{"referenceValue": name}], "before": True}


class Transport:
    """An offline transport that answers the compiled plan as production would."""

    def __init__(
        self, value: dict, *, partitions: int = 0, page_token: str = ""
    ) -> None:
        self.plan = value
        self.partitions = partitions
        self.page_token = page_token
        self.sent: list[dict] = []
        self.raw = True
        self.fail_at: int | None = None
        self.create_status = 200
        self.write_results: int | None = None

    def _seeded(self) -> list[str]:
        return self.plan["ownedResources"][1:]

    def _partition_cursors(self) -> list[dict]:
        return [
            partition_cursor(name) for name in self._seeded()[1 : 1 + self.partitions]
        ]

    def _group_documents(self) -> list[str]:
        return self._seeded()[:12]

    def _range(self, request: dict) -> list:
        """Answer a reconstruction range the way a real runtime would: the slice
        of the ordered collection group that the supplied cursors describe."""
        query = request["body"]["structuredQuery"]
        names = self._group_documents()
        start, end = 0, len(names)
        begin = query.get("startAt")
        finish = query.get("endAt")
        if begin:
            start = names.index(begin["values"][0]["referenceValue"])
        if finish:
            end = names.index(finish["values"][0]["referenceValue"])
        return [
            {"document": _document(name, index + start)}
            for index, name in enumerate(names[start:end])
        ] or [{"readTime": TIME}]

    def _body(self, request: dict) -> tuple[int, dict]:
        kind = request["kind"]
        if kind == "preflight-typed-absence" or kind == "cleanup-verify-root-absence":
            return 404, {"error": {"status": "NOT_FOUND", "code": 404}}
        if kind == "create-only-patch":
            if self.create_status != 200:
                return self.create_status, {"error": {"status": "ALREADY_EXISTS"}}
            return 200, {
                "name": self.plan["ownedScope"],
                "fields": {"marker": {"stringValue": self.plan["campaignId"]}},
                "createTime": TIME,
                "updateTime": TIME,
            }
        if kind in ("seed-commit", "cleanup-seed-delete"):
            count = (
                self.write_results
                if self.write_results is not None
                else len(request["body"]["writes"])
            )
            return 200, {
                "writeResults": [{"updateTime": TIME} for _ in range(count)],
                "commitTime": TIME,
            }
        if kind in ("cleanup-ownership-read",):
            return 200, {
                "name": self.plan["ownedScope"],
                "fields": {"marker": {"stringValue": self.plan["campaignId"]}},
                "createTime": TIME,
                "updateTime": TIME,
            }
        if kind == "cleanup-root-delete":
            return 200, {}
        if kind.startswith("partition-reconstruction"):
            return 200, self._range(request)
        expect = self.plan[request["phase"]][request["index"]]["expect"]
        if expect.get("outcome") == "refused":
            return 400, {"error": {"status": "INVALID_ARGUMENT", "code": 400}}
        if request["path"].endswith(":partitionQuery"):
            body: dict = {"partitions": self._partition_cursors()}
            if self.page_token and "pageToken" not in request["body"]:
                body["nextPageToken"] = self.page_token
            return 200, body
        documents = expect.get("documents", [])
        return 200, [
            {
                "document": _document(
                    item["name"], int(item["fields"]["n"]["integerValue"])
                )
            }
            for item in documents
        ] or [{"readTime": TIME}]

    def __call__(self, request: dict) -> dict:
        self.sent.append(request)
        if self.fail_at is not None and len(self.sent) - 1 == self.fail_at:
            raise ConnectionError("offline transport failure")
        status, body = self._body(request)
        encoded = json.dumps(body).encode()
        receipt = {
            "status": status,
            "body": body,
            "complete": True,
            "contentType": "application/json; charset=UTF-8",
            "byteCount": len(encoded),
        }
        if self.raw:
            receipt["rawBody"] = encoded
        return receipt
