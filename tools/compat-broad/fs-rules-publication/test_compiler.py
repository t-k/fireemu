from __future__ import annotations

import copy

import pytest

from compiler import CAMPAIGN, compile_plan, validate_plan


def test_plan_is_deterministic_and_has_the_finite_transition_shape() -> None:
    plan = compile_plan("fireemu-35fe6", "(default)", "a" * 32)
    assert plan == compile_plan("fireemu-35fe6", "(default)", "a" * 32)
    assert plan["campaignId"] == CAMPAIGN
    assert [op["kind"] for op in plan["observation"]] == [
        "user-sdk-owned-a",
        "user-sdk-owned-a-control",
        "user-sdk-owned-a-repeat",
        "user-sdk-owned-b-denied",
        "user-sdk-public-b-control",
        "user-sdk-owned-u2-denied",
    ]
    assert [op["kind"] for op in plan["recovery"]] == [
        "cleanup-owned-document",
        "cleanup-public-document",
        "cleanup-users-and-rules",
    ]
    assert plan["budget"] == {
        "authUsersMaximum": 2,
        "documentsMaximum": 2,
        "rulesPublicationsMaximum": 3,
        "userSdkReadsMaximum": 6,
        "observationRequests": 6,
        "recoveryRequests": 9,
        "requestUpperBound": 15,
    }
    assert plan["productionReady"] is False
    assert plan["budget"]["recoveryRequests"] == 9
    assert plan["budget"]["requestUpperBound"] == 15
    assert plan["nonceReservation"]["fresh"] is True
    assert plan["nonceReservation"]["reused"] is False


def test_plan_owns_only_nonce_scoped_documents_and_no_credentials() -> None:
    plan = compile_plan("demo", "(default)", "b" * 32)
    assert plan["ownedResources"] == [plan["ownedDocument"], plan["publicDocument"]]
    assert all("b" * 32 in path for path in plan["ownedResources"])
    assert plan["rulesets"]["A"]["decision"] == "allow-owned-user"
    assert plan["rulesets"]["B"]["decision"] == "deny-owned-user"
    assert plan["rulesets"]["B"]["publicDecision"] == "allow-public"
    assert plan["negativeCredentials"] == [
        "empty-bearer",
        "malformed-bearer",
        "admin-shaped-credential",
    ]


@pytest.mark.parametrize(
    "mutation",
    ["nonce", "project", "owned", "operation", "budget", "rules"],
)
def test_validate_plan_rejects_binding_drift(mutation: str) -> None:
    plan = compile_plan("demo", "(default)", "c" * 32)
    changed = copy.deepcopy(plan)
    if mutation == "nonce":
        changed["nonce"] = "d" * 32
    elif mutation == "project":
        changed["project"] = "other"
    elif mutation == "owned":
        changed["ownedDocument"] += "/foreign"
    elif mutation == "operation":
        changed["observation"][3]["path"] += "?changed=true"
    elif mutation == "budget":
        changed["budget"]["userSdkReadsMaximum"] = 7
    else:
        changed["rulesets"]["B"]["decision"] = "allow-owned-user"
    with pytest.raises(ValueError):
        validate_plan(changed)
