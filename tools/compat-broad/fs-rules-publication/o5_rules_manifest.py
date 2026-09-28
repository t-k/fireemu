"""Digest an offline observation case without granting execution authority."""

from __future__ import annotations

from typing import Any

from o5_rules_case import CAMPAIGN, compile_plan, digest


def manifest() -> dict[str, Any]:
    return {
        "schemaVersion": 2,
        "campaignId": CAMPAIGN,
        "status": "PREPARATION_ONLY",
        "productionExecuted": False,
        "productionReady": False,
        "planTemplate": compile_plan("template-project", "(default)", "0" * 32),
        "unresolved": [
            "project and database identity confirmation",
            "execution commit and SDK lock digest",
            "Rules A/B and restoration source and artifact byte digests",
            "resource owner and recovery owner",
            "nonce reservation and shared Rules publication lock",
            "wire request, cost, and execution-window limits",
            "typed production receipt collector",
            "conditional restoration of preexisting Rules and readback",
        ],
    }


def bound_manifest(project: str, nonce: str) -> dict[str, Any]:
    value = manifest()
    value["observationCase"] = compile_plan(project, "(default)", nonce)
    value["caseDigest"] = digest(value["observationCase"])
    value["templateDigest"] = digest(value)
    return value


def validate_manifest(value: Any) -> None:
    if not isinstance(value, dict):
        # ValueError is this package's reviewed rejection type; callers catch it.
        raise ValueError("invalid manifest")  # noqa: TRY004
    case = value.get("observationCase")
    if not isinstance(case, dict):
        raise ValueError("invalid observation case")  # noqa: TRY004
    project, nonce = case.get("project"), case.get("nonce")
    if not isinstance(project, str) or not isinstance(nonce, str):
        raise ValueError("invalid case identity")  # noqa: TRY004
    try:
        expected = bound_manifest(project, nonce)
    except (TypeError, ValueError) as error:
        raise ValueError("invalid case identity") from error
    if value != expected:
        raise ValueError("manifest preparation drift")
