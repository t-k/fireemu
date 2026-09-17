"""Offline publication manifest and admission contract for O5."""

from __future__ import annotations

import copy
from typing import Any

from compiler import CAMPAIGN, compile_plan, digest


def manifest() -> dict[str, Any]:
    plan = compile_plan("template-project", "(default)", "0" * 32)
    # Placeholders make the checked-in contract reproducible; a run must bind
    # both project and fresh nonce before any data operation.
    return {
        "schemaVersion": 1,
        "campaignId": CAMPAIGN,
        "status": "PREPARATION_ONLY",
        "productionExecuted": False,
        "productionReady": False,
        "planTemplate": plan,
        "sourceBoundary": "official Auth user SDK plus published Firestore Rules only",
        "forbiddenEvidence": [
            "admin-rest",
            "admin-credential",
            "local-rules-evaluator",
            "local-token",
        ],
        "requiredBeforeExecution": [
            "owner and recovery-owner approval",
            "fresh nonce reservation and shared lock",
            "project/database and SDK package-lock binding",
            "Rules A/B source and artifact digests",
            "bounded cost, retention, and execution window",
            "typed user-SDK receipt collector and independent comparator review",
        ],
    }


def bound_manifest(project: str, nonce: str) -> dict[str, Any]:
    value = manifest()
    value["plan"] = compile_plan(project, "(default)", nonce)
    value["planDigest"] = digest(value["plan"])
    value["manifestDigest"] = digest(value)
    return value


def validate_manifest(value: dict[str, Any]) -> None:
    if not isinstance(value, dict) or value.get("campaignId") != CAMPAIGN:
        raise ValueError("manifest campaign drift")
    if value.get("productionExecuted") is not False or value.get("productionReady") is not False:
        raise ValueError("manifest cannot authorize production")
    plan = value.get("plan")
    if not isinstance(plan, dict) or value.get("planDigest") != digest(plan):
        raise ValueError("plan digest mismatch")
    expected = bound_manifest(plan["project"], plan["nonce"])
    expected.pop("manifestDigest")
    actual = copy.deepcopy(value)
    actual.pop("manifestDigest", None)
    if actual != expected:
        raise ValueError("manifest binding drift")
