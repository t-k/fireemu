"""Closed production allocation proposal; no permission or execution capability."""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parents[2] / "tools/compat-inventory"))

from compiler import compile_limits_plan
from shared_production import management

PROJECT = "fireemu-35fe6"
DATABASE = "(default)"


def production_plan(nonce: str) -> dict:
    compiled = compile_limits_plan(PROJECT, DATABASE, nonce)
    plan = compiled["localGatePlan"]
    # Management calls consume the same total phase counters as data operations.
    # Job journals retain their independent 16/12 operation bounds.
    plan.update(
        transport="limits-production-proposal-v1",
        wallSeconds=960,
        recoverySeconds=360,
        observationRequests=22,
        fixedCostMicrousd=40000,
        costMicrousd=44000,
        management={"observation": management(), "recovery": management()},
    )
    scope = f"project/{PROJECT}"
    firestore = f"{scope}/firestore/{DATABASE}"
    return {
        "kind": "fs-write-limits-production-allocation-v2",
        "campaignId": compiled["campaignId"],
        "gatePlan": plan,
        "totalRequestUpperBound": 40,
        "resourceUpperBound": 4,
        "concurrencyUpperBound": 1,
        "safetyClass": "OWNED_DATA",
        "resourceLocks": [
            {
                "key": f"{firestore}/documents/oracle/{nonce}/limits-02/*",
                "mode": "WRITE",
            },
            {"key": f"{firestore}/indexes", "mode": "READ"},
            {"key": f"{firestore}/ruleset", "mode": "READ"},
            {"key": f"{firestore}/database", "mode": "READ"},
            {"key": f"{scope}/auth/config", "mode": "READ"},
            {"key": f"{scope}/api-key-binding", "mode": "READ"},
        ],
        "productionReady": False,
        "unbound": [
            "owner permission, execution window and recovery owner",
            "configuration and API key binding",
            "artifact, collector and comparator digests",
            "production large-body transport and receipt collector",
            "tariff and storage/network ceiling acceptance",
            "global envelope reservation and resource lock admission",
        ],
    }
