"""Drive the real collector with an injected executor, for offline tests.

Tests that assert on a collector result should assert on a result the collector
actually produced. Hand-written result literals drift from the collector's own
invariants, and a fixture the collector could never emit gives false assurance.

This module starts no emulator, sends no request and holds no credential.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from request_bytes_collector import collect_local
from request_bytes_compiler import compile_request_bytes_plan

PROJECT = "local-project"
DATABASE = "(default)"
NONCE = "0123456789abcdef0123456789abcdef"
VERSION = "2026-01-01T00:00:00.123456789Z"

#: The over-boundary outcomes a run can legitimately produce.
TYPED_413 = {
    "status": 413,
    "body": {"error": {"code": 413, "status": "INVALID_ARGUMENT"}},
}
EXPECTED_MESSAGE = "Request payload size exceeds the limit: 11534336 bytes."

TYPED_400 = {
    "status": 400,
    "body": {
        "error": {
            "code": 400,
            "message": EXPECTED_MESSAGE,
            "status": "INVALID_ARGUMENT",
        }
    },
}


def typed_400_with_message(message: str) -> dict[str, Any]:
    """A typed over-boundary refusal carrying an arbitrary message.

    The response cap is 2 MiB, so production can legitimately answer with a
    message far larger than the final result may carry.
    """
    return {
        "status": 400,
        "body": {
            "error": {
                "code": 400,
                "message": message,
                "status": "INVALID_ARGUMENT",
            }
        },
    }


#: The reviewer's three message conditions.
MESSAGE_NORMAL = EXPECTED_MESSAGE
MESSAGE_128_KIB = "x" * (128 * 1024)
MESSAGE_64_KIB_NEWLINES = "\n" * (64 * 1024)


#: The expected status and code with someone else's wording.
TYPED_400_OTHER_MESSAGE = {
    "status": 400,
    "body": {
        "error": {
            "code": 400,
            "message": "The request is too large.",
            "status": "INVALID_ARGUMENT",
        }
    },
}

#: The expected status and code with no message at all.
TYPED_400_NO_MESSAGE = {
    "status": 400,
    "body": {"error": {"code": 400, "status": "INVALID_ARGUMENT"}},
}
UNTYPED_413 = {
    "status": 413,
    "body": "<html><title>413 Request Entity Too Large</title></html>",
    "contentType": "text/html; charset=UTF-8",
}


def plan() -> dict[str, Any]:
    return compile_request_bytes_plan(PROJECT, DATABASE, NONCE)


def run_collector(
    output: Path, *, over: dict[str, Any] | None, value: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Run the full 258-slot schedule against a synthetic runtime.

    ``over`` is the response the over-boundary Commit receives; ``None`` accepts
    it, which is what a runtime with no request-byte enforcement would do.
    """
    value = value or plan()
    documents = {
        write["update"]["name"]: write["update"]["fields"]
        for probe in value["probes"]
        for write in probe["body"]["writes"]
    }
    live: set[str] = set()

    def respond(operation: dict[str, Any]) -> dict[str, Any]:
        kind, resource = operation["kind"], operation.get("resource")
        if kind == "conditional-create-commit":
            resources = next(
                probe["resources"]
                for probe in value["probes"]
                if probe["label"] == operation["probe"]
            )
            if operation["probe"] == "over" and over is not None:
                return {"status": over["status"], "body": over["body"]}
            live.update(resources)
            return {
                "status": 200,
                "body": {"writeResults": [{"updateTime": VERSION} for _ in resources]},
            }
        if kind == "cleanup-version-bound-delete":
            live.discard(resource)
            return {"status": 200, "body": {}}
        if resource in live:
            return {
                "status": 200,
                "body": {
                    "name": resource,
                    "fields": documents[resource],
                    "updateTime": VERSION,
                },
            }
        return {"status": 404, "body": {"error": {"code": 404, "status": "NOT_FOUND"}}}

    def execute(operation: dict[str, Any]) -> dict[str, Any]:
        partial = respond(operation)
        body = partial["body"]
        raw = (
            body.encode()
            if isinstance(body, str)
            else json.dumps(body, separators=(",", ":")).encode()
        )
        content_type = "application/json"
        if (
            operation["kind"] == "conditional-create-commit"
            and operation["probe"] == "over"
            and over is not None
        ):
            content_type = over.get("contentType", content_type)
        return {
            "complete": True,
            "failure": None,
            "status": partial["status"],
            "headers": {"content-type": content_type},
            "body": body,
            "bodyBytes": len(raw),
            "rawBodyBase64": base64.b64encode(raw).decode("ascii"),
        }

    return collect_local(value, execute, output)
