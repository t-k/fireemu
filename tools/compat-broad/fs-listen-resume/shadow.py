"""Pure local shadow ledger; it never opens a socket or invokes an SDK."""

from __future__ import annotations

from typing import Any

from .manifest import SDK, SHADOW, digest


def run_shadow(plan: dict[str, Any], scenario: str = "reconnect") -> dict[str, Any]:
    if scenario not in {"reconnect", "negative", "control"}:
        raise ValueError("unsupported shadow scenario")
    collection = plan["owner"]["collection"]
    one, two = f"{collection}/one", f"{collection}/two"
    events = [
        {
            "snapshotType": "initial",
            "document": one,
            "revision": 0,
            "changeKind": "added",
            "oldIndex": -1,
            "newIndex": 0,
            "lifecycle": "active",
            "errorCode": None,
            "tokenCase": None,
        },
        {
            "snapshotType": "delta",
            "document": one,
            "revision": 1,
            "changeKind": "modified",
            "oldIndex": 0,
            "newIndex": 0,
            "lifecycle": "active",
            "errorCode": None,
            "tokenCase": None,
        },
        {
            "snapshotType": "delta",
            "document": one,
            "revision": 2,
            "changeKind": "modified",
            "oldIndex": 0,
            "newIndex": 0,
            "lifecycle": "reconnected",
            "errorCode": None,
            "tokenCase": None,
        },
        {
            "snapshotType": "delta",
            "document": two,
            "revision": 0,
            "changeKind": "added",
            "oldIndex": -1,
            "newIndex": 1,
            "lifecycle": "reconnected",
            "errorCode": None,
            "tokenCase": None,
        },
    ]
    if scenario == "control":
        events[2]["lifecycle"] = "active"
        events[3]["lifecycle"] = "active"
    if scenario == "negative":
        events.extend(
            {
                "snapshotType": "error",
                "document": None,
                "revision": None,
                "changeKind": None,
                "oldIndex": None,
                "newIndex": None,
                "lifecycle": "reconnected",
                "errorCode": code,
                "tokenCase": token_case,
            }
            for token_case, code in (
                ("stale-token", "FAILED_PRECONDITION"),
                ("compacted-token", "FAILED_PRECONDITION"),
                ("session-reset", "ABORTED"),
            )
        )
    return {
        "schema": "o6-listen-resume-receipt-v1",
        "caseId": plan["caseId"],
        "planDigest": digest(plan),
        "productionExecuted": False,
        "sdk": dict(SDK),
        "shadow": dict(SHADOW),
        "sourceBinding": dict(plan["sourceBinding"]),
        "transportBinding": dict(plan["transportBinding"]),
        "collector": {"complete": True, "eventCount": len(events)},
        "transport": {
            "interruptionObserved": scenario != "control",
            "reconnectObserved": True,
        },
        "events": events,
        "cleanup": {one: True, two: True},
        "bounds": {
            "runCount": 1,
            "requestCount": 12,
            "durationSeconds": 1,
            "concurrency": 1,
            "snapshotCount": 4,
            "estimatedCostUsd": 0,
        },
    }
