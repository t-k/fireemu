"""Pure scope, request-budget and two-recording contract for the sandbox lane."""

from __future__ import annotations

import json

import txn_expiry_cases as cases
import txn_expiry_comparison as comparison
import txn_expiry_plan as plan_module

PROJECT = "fireemu-oracle-sbx"
DATABASE = "(default)"
CONDITIONS = {
    "idle-expiry": "FS-TRANSACTION/idle-expiry",
    "finished-token": "FS-TRANSACTION/failed-commit-and-rollback",
    "retry-token": "FS-TRANSACTION/retry-token-lifecycle",
}
CASE_IDS = frozenset(case["id"] for case in cases.CASES)
SECRET_MARKERS = ("Bearer ", "refresh_token", "client_secret", "ya29.")


def validate_scope(value):
    """Require the frozen thirteen cases and the approved sandbox target."""
    if value.get("projectId") != PROJECT:
        raise ValueError("sandbox project differs from frozen scope")
    if value.get("database") != DATABASE:
        raise ValueError("sandbox database differs from frozen scope")
    if value.get("campaign") != cases.CAMPAIGN or value.get("casesDigest") != cases.cases_digest():
        raise ValueError("case corpus differs from frozen scope")
    actual = [step["caseId"] for step in value["operations"] if step["caseId"]]
    if len(actual) != 13 or set(actual) != CASE_IDS:
        raise ValueError("the plan must execute each of the thirteen cases once")
    if len(value["resources"]) != 5:
        raise ValueError("the plan must own exactly five documents")
    mapping = {}
    for case in cases.CASES:
        condition = CONDITIONS.get(case["group"])
        if condition is None:
            raise ValueError("case group outside frozen closure")
        mapping[condition] = mapping.get(condition, 0) + 1
    if mapping != {
        "FS-TRANSACTION/idle-expiry": 5,
        "FS-TRANSACTION/failed-commit-and-rollback": 3,
        "FS-TRANSACTION/retry-token-lifecycle": 5,
    }:
        raise ValueError("case-to-condition mapping differs from frozen closure")
    return mapping


class RequestBudget:
    """Charge each intended send before dispatch and reserve recovery capacity."""

    def __init__(self, plan):
        validate_scope(plan)
        budget = plan["budget"]
        self.observation_limit = sum(
            step["phase"] != "cleanup" for step in plan["operations"]
        )
        self.recovery_limit = budget["dataRequests"] - self.observation_limit
        if self.recovery_limit < sum(
            step["phase"] == "cleanup" for step in plan["operations"]
        ):
            raise ValueError("recovery request reserve is too small")
        self.management_limit = budget["metadataRequests"]
        self.credential_limit = budget["credentialRequests"]
        self.total_limit = budget["requests"]
        self.observation = 0
        self.recovery = 0
        self.management = 0
        self.credential = 0

    @property
    def data(self):
        return self.observation + self.recovery

    @property
    def total(self):
        return self.data + self.management + self.credential

    def charge(self, kind, *, phase=None):
        if kind == "data":
            if phase not in ("observation", "recovery"):
                raise ValueError("data request phase required")
            field = phase
            limit = self.observation_limit if phase == "observation" else self.recovery_limit
        elif kind in ("management", "credential") and phase is None:
            field = kind
            limit = getattr(self, f"{kind}_limit")
        else:
            raise ValueError("request kind outside sandbox budget")
        if getattr(self, field) >= limit or self.total >= self.total_limit:
            raise ValueError(f"{field} request limit reached")
        setattr(self, field, getattr(self, field) + 1)
        return self.total


def _project(receipt):
    if (
        receipt.get("complete") is not True
        or receipt.get("missingCases") != []
        or receipt.get("unrecovered") != []
        or receipt.get("openTransactions") != []
    ):
        raise ValueError("a complete recovered receipt is required")
    if (
        receipt.get("target") != "production"
        or receipt.get("timing") != "wall-clock"
        or receipt.get("projectId") != PROJECT
        or receipt.get("database") != DATABASE
        or receipt.get("campaign") != cases.CAMPAIGN
        or receipt.get("casesDigest") != cases.cases_digest()
        or receipt.get("sourceDigest") != plan_module.source_digest()
    ):
        raise ValueError("receipt source, corpus or target differs")
    count = receipt.get("requestCount")
    if type(count) is not int or not 0 <= count <= plan_module.compile_plan(
        receipt["nonce"], "0" * 32
    )["budget"]["dataRequests"]:
        raise ValueError("receipt data request count is outside the bound")
    rendered = json.dumps(receipt, ensure_ascii=False)
    if any(marker in rendered for marker in SECRET_MARKERS):
        raise ValueError("receipt contains a secret marker")
    result = {}
    post_states = {}
    for row in receipt.get("rows", []):
        case_id = row.get("caseId")
        if case_id:
            if case_id not in CASE_IDS or case_id in result or row.get("complete") is not True:
                raise ValueError("case row missing, repeated or incomplete")
            observed = row.get("observed") or {}
            result[case_id] = {
                "rpc": row.get("rpc"),
                "role": row.get("role"),
                "code": observed.get("code"),
                "status": observed.get("status"),
                "message": comparison.normalize_message(observed.get("message"), receipt),
            }
        verified = row.get("verifiesCase")
        if verified:
            if verified not in CASE_IDS or verified in post_states or row.get("complete") is not True:
                raise ValueError("case post-state missing, repeated or incomplete")
            document = row.get("document") or {}
            post_states[verified] = {
                "role": row.get("role"),
                "exists": document.get("exists"),
                "state": ((document.get("fields") or {}).get("state") or {}).get("stringValue"),
            }
    if set(result) != CASE_IDS:
        raise ValueError("receipt case set differs from frozen corpus")
    for case in cases.CASES:
        if case["postState"] and case["id"] not in post_states:
            raise ValueError("case post-state readback is missing")
    return {case_id: {**result[case_id], "postState": post_states.get(case_id)} for case_id in sorted(CASE_IDS)}


def freeze(first, second):
    """Freeze only two independent, complete recordings with equal semantics."""
    if first.get("nonce") == second.get("nonce"):
        raise ValueError("recordings reused a nonce")
    left, right = _project(first), _project(second)
    if left != right:
        raise ValueError("the two sandbox recordings differ")
    return {
        "kind": "fs-transaction-sandbox-two-recordings-v1",
        "campaign": cases.CAMPAIGN,
        "sourceDigest": first["sourceDigest"],
        "casesDigest": first["casesDigest"],
        "projectId": PROJECT,
        "database": DATABASE,
        "nonces": [first["nonce"], second["nonce"]],
        "cases": left,
    }
