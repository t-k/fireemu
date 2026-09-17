"""Deterministic local shadow; it never contacts an Auth endpoint."""

from __future__ import annotations

import copy
from typing import Any

from o1_auth_account_linking_compiler import CASE_ID, CONTRACT, validate_plan


def run_shadow(plan: dict[str, Any], *, allow_duplicate_emails: bool) -> dict[str, Any]:
    if plan.get("caseId") != CASE_ID or plan.get("productionExecuted") is not False:
        raise ValueError("invalid production-disabled plan")
    validate_plan(plan)
    email = f"marker-{plan['nonceDigest'][:12]}@example.test"
    users = {
        "A": {
            "uid": "local-a",
            "email": email,
            "providers": [{"providerId": "password", "subject": "A"}],
        },
        "B": {
            "uid": "local-b",
            "email": f"b-{plan['nonceDigest'][:12]}@example.test",
            "providers": [{"providerId": "password", "subject": "B"}],
        },
    }
    before = copy.deepcopy(users)
    operations = [
        {
            "id": "configuration-read",
            "status": "success",
            "allowDuplicateEmails": allow_duplicate_emails,
        },
        {"id": "signup-a", "status": "success", "account": "A"},
        {"id": "signup-b", "status": "success", "account": "B"},
        {"id": "same-provider-signin", "status": "success", "uid": "local-a"},
        {"id": "password-signin-b", "status": "success", "uid": "local-b"},
    ]
    users["B"]["providers"].append(
        {"providerId": "google.com", "subject": "provider-a"}
    )
    operations.append(
        {
            "id": "provider-collision",
            "status": "accepted",
            "uid": "local-b",
            "providerOwner": "B",
            "emailOwner": "A",
            "emailOwnershipMode": "multiple" if allow_duplicate_emails else "single",
        }
    )
    readback = {"A": copy.deepcopy(users["A"]), "B": copy.deepcopy(users["B"])}
    operations.extend(
        [
            {
                "id": "readback-a",
                "status": "success",
                "user": readback["A"],
            },
            {
                "id": "readback-b",
                "status": "success",
                "user": readback["B"],
            },
            {"id": "delete-a", "status": "success", "account": "A"},
            {"id": "delete-b", "status": "success", "account": "B"},
            {"id": "absence-a", "status": "absent", "account": "A"},
            {"id": "absence-b", "status": "absent", "account": "B"},
        ]
    )
    return {
        "contract": CONTRACT,
        "caseId": CASE_ID,
        "status": "PREPARATION",
        "productionExecuted": False,
        "allowDuplicateEmails": allow_duplicate_emails,
        "before": before,
        "after": {},
        "readback": readback,
        "operations": operations,
        "cleanup": {
            "complete": True,
            "ownedAccounts": ["A", "B"],
            "providerBoundary": "local-only",
        },
        "productionExpectation": None,
    }
