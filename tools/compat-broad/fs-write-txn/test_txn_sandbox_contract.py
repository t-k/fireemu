"""The sandbox campaign rejects scope drift and unsafe two-pass evidence."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import txn_expiry_cases as cases
import txn_expiry_plan as plan
import txn_sandbox_contract as sandbox


NONCE = "0123456789abcdef0123456789abcdef"
OWNER = "11111111222233334444555566667777"


def frozen_plan():
    return plan.compile_plan(NONCE, OWNER)


def receipt(nonce=NONCE):
    return {
        "complete": True,
        "campaign": cases.CAMPAIGN,
        "casesDigest": cases.cases_digest(),
        "sourceDigest": plan.source_digest(),
        "projectId": sandbox.PROJECT,
        "database": sandbox.DATABASE,
        "target": "production",
        "timing": "wall-clock",
        "nonce": nonce,
        "requestCount": 70,
        "preflight": {
            "rulesetName": "projects/fireemu-oracle-sbx/rulesets/ruleset-a",
            "rulesSourceSha256": "a" * 64,
        },
        "missingCases": [],
        "unrecovered": [],
        "openTransactions": [],
        "rows": [
            {
                "caseId": case["id"],
                "rpc": case["expectedLocal"]["rpc"],
                "role": case["resources"][0] if case["resources"] else None,
                "complete": True,
                "observed": {
                    "code": case["expectedLocal"]["code"],
                    "status": case["expectedLocal"]["status"],
                    "message": case["expectedLocal"]["message"],
                },
            }
            for case in cases.CASES
        ] + [
            {
                "verifiesCase": case["id"],
                "role": role,
                "complete": True,
                "document": {
                    "exists": state is not None,
                    "fields": {"state": {"stringValue": state}} if state is not None else {},
                },
            }
            for case in cases.CASES
            for role, state in (case["postState"] or {}).items()
        ],
    }


def test_scope_is_exact_thirteen_cases_and_sandbox_database():
    scope = sandbox.validate_scope(frozen_plan())
    assert scope == {
        "FS-TRANSACTION/idle-expiry": 5,
        "FS-TRANSACTION/failed-commit-and-rollback": 3,
        "FS-TRANSACTION/retry-token-lifecycle": 5,
    }
    with pytest.raises(ValueError, match="project"):
        sandbox.validate_scope(plan.compile_plan(NONCE, OWNER, project="other-project"))
    with pytest.raises(ValueError, match="database"):
        sandbox.validate_scope(plan.compile_plan(NONCE, OWNER, database="other"))


def test_budget_reserves_recovery_even_after_observation_limit():
    budget = sandbox.RequestBudget(frozen_plan())
    for _ in range(budget.observation_limit):
        budget.charge("data", phase="observation")
    with pytest.raises(ValueError, match="observation"):
        budget.charge("data", phase="observation")
    budget.charge("data", phase="recovery")
    assert budget.data == budget.observation_limit + 1
    for _ in range(budget.management_limit):
        budget.charge("management")
    with pytest.raises(ValueError, match="management"):
        budget.charge("management")
    for _ in range(budget.credential_limit):
        budget.charge("credential")
    with pytest.raises(ValueError, match="credential"):
        budget.charge("credential")
    assert budget.management_limit == 9
    assert budget.total_limit == frozen_plan()["budget"]["requests"] + 1
    assert budget.total <= budget.total_limit


def test_freeze_requires_two_complete_independent_matching_receipts():
    first = receipt()
    second = receipt("fedcba9876543210fedcba9876543210")
    frozen = sandbox.freeze(first, second)
    assert len(frozen["cases"]) == 13
    assert frozen["sourceDigest"] == plan.source_digest()
    with pytest.raises(ValueError, match="nonce"):
        sandbox.freeze(first, first)
    changed = receipt(second["nonce"])
    changed["rows"][1]["observed"]["code"] = 7
    with pytest.raises(ValueError, match="differ"):
        sandbox.freeze(first, changed)
    incomplete = receipt(second["nonce"])
    incomplete["complete"] = False
    with pytest.raises(ValueError, match="complete"):
        sandbox.freeze(first, incomplete)
    changed_rules = receipt(second["nonce"])
    changed_rules["preflight"]["rulesSourceSha256"] = "b" * 64
    with pytest.raises(ValueError, match="Rules source"):
        sandbox.freeze(first, changed_rules)


def test_freeze_rejects_secret_marker_and_missing_case():
    first = receipt()
    second = receipt("fedcba9876543210fedcba9876543210")
    first["rows"][0]["observed"]["message"] = "Bearer secret"
    with pytest.raises(ValueError, match="secret"):
        sandbox.freeze(first, second)
    first = receipt()
    first["rows"].pop()
    with pytest.raises(ValueError, match="case"):
        sandbox.freeze(first, second)
