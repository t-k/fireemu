"""Pure local shadow ledger; it never opens a socket or invokes an SDK."""

from __future__ import annotations

from typing import Any

from manifest import SDK, digest


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
            }
            for code in ("FAILED_PRECONDITION", "FAILED_PRECONDITION", "ABORTED")
        )
    return {
        "schema": "o6-listen-resume-receipt-v1",
        "caseId": plan["caseId"],
        "planDigest": digest(plan),
        "productionExecuted": False,
        "sdk": SDK,
        "collector": {"complete": True, "eventCount": len(events)},
        "transport": {
            "interruptionObserved": scenario != "control",
            "reconnectObserved": scenario != "negative",
        },
        "events": events,
        "cleanup": {one: True, two: True},
    }
