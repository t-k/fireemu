"""The campaign plan is finite, bounded, owner-blocked and cheap."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parents[1]))

import txn_expiry_cases as cases
import txn_expiry_plan as plan

NONCE = "o3expiry-0000000000000001"
OWNER = "11111111222233334444555566667777"


def compiled():
    return plan.compile_plan(NONCE, OWNER)


def test_plan_binds_the_frozen_case_table():
    value = compiled()
    assert value["campaign"] == cases.CAMPAIGN
    assert value["casesDigest"] == cases.cases_digest()
    assert value["contract"] == plan.CONTRACT


def test_every_case_is_executed_exactly_once():
    value = compiled()
    observed = [step["caseId"] for step in value["operations"] if step["caseId"]]
    assert sorted(observed) == sorted(case["id"] for case in cases.CASES)


def test_every_operation_is_bounded_and_named():
    value = compiled()
    slots = [step["slot"] for step in value["operations"]]
    assert len(slots) == len(set(slots))
    for step in value["operations"]:
        assert step["rpc"] in cases.RPCS
        assert step["phase"] in plan.PHASES
        assert step["maxResponseBytes"] <= plan.MAX_RESPONSE_BYTES


def test_documents_stay_below_the_nonce_prefix():
    value = compiled()
    prefix = value["documentPrefix"]
    assert NONCE in prefix
    assert len(value["resources"]) == len(cases.RESOURCE_ROLES)
    for resource in value["resources"]:
        assert resource["path"].startswith(prefix + "/")


def test_every_owned_document_is_cleaned_up_with_a_proof():
    value = compiled()
    for resource in value["resources"]:
        role = resource["role"]
        phases = [
            step["slot"]
            for step in value["operations"]
            if step["phase"] == "cleanup" and step["role"] == role
        ]
        assert f"cleanup/owned-read/{role}" in phases
        assert f"cleanup/conditional-delete/{role}" in phases
        assert f"cleanup/typed-absence/{role}" in phases


def test_every_transaction_the_plan_opens_is_also_closed():
    value = compiled()
    opened = set()
    closed = set()
    for step in value["operations"]:
        if step["rpc"] == "BeginTransaction" and step["opensTransaction"]:
            opened.add(step["opensTransaction"])
        if step["closesTransaction"]:
            closed.add(step["closesTransaction"])
    assert opened, "the campaign must open transactions"
    assert opened == closed, f"unclosed transactions: {sorted(opened - closed)}"


def test_waits_are_finite_and_sum_below_the_time_envelope():
    value = compiled()
    total = sum(step["waitSeconds"] for step in value["operations"])
    assert total == cases.maximum_elapsed_seconds()
    assert total < value["budget"]["wallSeconds"]


def test_budget_is_finite_and_covers_every_request():
    value = compiled()
    budget = value["budget"]
    requests = len(value["operations"])
    assert requests <= budget["dataRequests"]
    assert budget["requests"] == (
        budget["dataRequests"]
        + budget["metadataRequests"]
        + budget["credentialRequests"]
    )
    assert budget["accounts"] == 0
    assert budget["concurrency"] == 1
    assert budget["resources"] == len(value["resources"])


def test_planning_ceiling_stays_far_below_one_dollar():
    value = compiled()
    estimate = plan.budget_estimate(value)
    assert estimate["totalPlanningMicrousd"] == value["budget"]["costMicrousd"]
    assert estimate["totalPlanningMicrousd"] < 1_000_000
    assert estimate["isExpectedInvoice"] is False


def test_locks_are_read_only_except_the_owned_document_namespace():
    value = compiled()
    locks = plan.resource_locks(value)
    exclusive = [lock for lock in locks if lock["mode"] == "EXCLUSIVE"]
    assert len(exclusive) == 1
    assert value["documentPrefix"] in exclusive[0]["key"]
    assert {lock["mode"] for lock in locks} == {"EXCLUSIVE", "READ"}


def test_proposal_without_a_permission_is_blocked_owner():
    proposal = plan.proposal(NONCE, OWNER)
    assert proposal["status"] == "BLOCKED_OWNER"
    assert proposal["permissionGranted"] is False
    assert proposal["ownerFieldsRequired"]
    assert "permission" not in proposal


def test_proposal_is_credential_free():
    proposal = plan.proposal(NONCE, OWNER)
    rendered = repr(proposal)
    for secret in ("refresh_token", "client_secret", "Bearer ", "ya29."):
        assert secret not in rendered


def test_manifest_digest_changes_when_the_case_table_changes(monkeypatch):
    before = plan.manifest(NONCE, OWNER)
    trimmed = tuple(cases.CASES[:-1])
    monkeypatch.setattr(cases, "CASES", trimmed)
    after = plan.manifest(NONCE, OWNER)
    assert before["casesDigest"] != after["casesDigest"]


def test_source_digest_covers_exactly_the_declared_modules():
    inputs = plan.source_inputs()
    assert set(inputs) == set(plan.SOURCE_FILES)
    for value in inputs.values():
        assert len(value) == 64
    assert len(plan.source_digest()) == 64


def test_plan_rejects_a_malformed_nonce_or_owner():
    for bad in ("", "short", "has space", "../escape"):
        with pytest.raises(ValueError):
            plan.compile_plan(bad, OWNER)
    with pytest.raises(ValueError):
        plan.compile_plan(NONCE, "nothex")


def test_required_permission_forbids_reobservation():
    value = compiled()
    required = plan.required_permission(value)
    assert required["allowedReobservations"] == 0
    assert required["accountUpperBound"] == 0
    assert required["concurrencyUpperBound"] == 1
    assert required["costUpperMicrousd"] == value["budget"]["costMicrousd"]
    assert required["casesDigest"] == cases.cases_digest()


def test_every_operation_declares_a_per_request_timeout():
    value = compiled()
    for step in value["operations"]:
        assert isinstance(step["timeoutSeconds"], int)
        assert 0 < step["timeoutSeconds"] <= plan.CONTENDED_REQUEST_TIMEOUT_SECONDS


def test_the_contended_requests_get_the_longer_timeout():
    value = compiled()
    contended = {
        step["slot"]: step["timeoutSeconds"]
        for step in value["operations"]
        if step["timeoutSeconds"] != plan.DEFAULT_REQUEST_TIMEOUT_SECONDS
    }
    assert contended == {
        "idle/lock-held": plan.CONTENDED_REQUEST_TIMEOUT_SECONDS,
        "idle/lock-released": plan.CONTENDED_REQUEST_TIMEOUT_SECONDS,
    }


def test_timeouts_plus_waits_fit_inside_the_wall_envelope():
    value = compiled()
    worst = value["bounds"]["worstCaseSeconds"]
    assert worst == sum(
        step["timeoutSeconds"] + step["waitSeconds"] for step in value["operations"]
    )
    assert worst <= value["budget"]["wallSeconds"]


def test_headroom_covers_a_rollback_for_every_begin_the_plan_sends():
    """Any begin can issue a token, including one the case table expects to fail."""
    value = compiled()
    begins = len([s for s in value["operations"] if s["rpc"] == "BeginTransaction"])
    opened = len([s for s in value["operations"] if s["opensTransaction"]])
    assert begins > opened, "the campaign must exercise refused begins"
    assert plan.DATA_SLOT_HEADROOM >= begins


def test_every_elapsed_case_names_the_transaction_whose_idle_time_it_measures():
    value = compiled()
    by_case = {s["caseId"]: s for s in value["operations"] if s["caseId"]}
    for case in cases.CASES:
        step = by_case[case["id"]]
        if case["requiresElapsedSeconds"]:
            assert step["idleOfTransaction"], f"{case['id']} measures nothing"
        else:
            assert step["idleOfTransaction"] is None


def test_the_unissued_retry_token_reuses_the_published_corpus_constant():
    assert plan.unissued_retry_token("any-nonce") == bytes(8)


def test_every_case_that_names_a_document_is_read_back_immediately():
    """The state a case leaves behind is read before anything can overwrite it."""
    value = compiled()
    steps = value["operations"]
    for index, step in enumerate(steps):
        if not step["caseId"] or not step["role"]:
            continue
        following = steps[index + 1]
        assert following["verifiesCase"] == step["caseId"], step["slot"]
        assert following["rpc"] == "GetDocument"
        assert following["role"] == step["role"]
        assert following["caseId"] is None


def test_a_readback_never_stands_behind_a_later_write_to_the_same_role():
    value = compiled()
    steps = value["operations"]
    for index, step in enumerate(steps):
        if not step.get("verifiesCase"):
            continue
        previous = steps[index - 1]
        assert previous["caseId"] == step["verifiesCase"]
        assert previous["role"] == step["role"]


def test_every_declared_post_state_has_a_readback_that_can_prove_it():
    value = compiled()
    verified = {
        step["verifiesCase"] for step in value["operations"] if step.get("verifiesCase")
    }
    for case in cases.CASES:
        if case["postState"]:
            assert case["id"] in verified, case["id"]


def test_the_declared_time_bound_covers_recovery_as_well_as_observation():
    """The owner grants one window; the run uses observation then recovery."""
    value = plan.compile_plan(NONCE, OWNER)
    budget = value["budget"]
    assert budget["observationSeconds"] == plan.WALL_SECONDS
    assert budget["recoverySeconds"] == plan.RECOVERY_SECONDS
    assert budget["wallSeconds"] == (plan.WALL_SECONDS + plan.RECOVERY_SECONDS)
    permission = plan.required_permission(value)
    assert permission["timeUpperBound"] == budget["wallSeconds"]


def test_the_collector_recovers_inside_the_window_the_plan_declares():
    import txn_expiry_collector as collector

    assert collector.RECOVERY_SECONDS == plan.RECOVERY_SECONDS
