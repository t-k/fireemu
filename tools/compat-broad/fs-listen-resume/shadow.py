"""Pure local shadow ledger; it never opens a socket or invokes an SDK."""

from __future__ import annotations

from typing import Any

from .manifest import SDK, SHADOW, digest


def run_shadow(plan: dict[str, Any], scenario: str = "reconnect") -> dict[str, Any]:
    if scenario not in {"reconnect", "negative", "control"}:
        raise ValueError("unsupported shadow scenario")
    collection = plan["owner"]["collection"]
    one, two = f"{collection}/one", f"{collection}/two"
    expected_events = [
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
        expected_events[2]["lifecycle"] = "active"
        expected_events[3]["lifecycle"] = "active"
    return {
        "schema": "o6-listen-resume-preparation-v2",
        "status": "PREPARATION_ONLY",
        "caseId": plan["caseId"],
        "planDigest": digest(plan),
        "productionExecuted": False,
        "sdk": dict(SDK),
        "shadow": dict(SHADOW),
        "sourceBinding": dict(plan["sourceBinding"]),
        "transportBinding": dict(plan["transportBinding"]),
        "unsupportedObligations": list(plan["unsupportedObligations"]),
        "expectedLogicalEvents": expected_events,
    }
