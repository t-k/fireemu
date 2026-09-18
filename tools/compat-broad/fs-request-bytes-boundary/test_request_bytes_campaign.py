"""Offline tests for the request-byte campaign artifact and its validator."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from request_bytes_campaign import (
    CASE_IDS,
    LOCAL_EXPECTATION,
    REFUSAL_EXPECTATION,
    campaign_digest,
    compile_request_bytes_campaign,
    validate_request_bytes_campaign,
)
from request_bytes_compiler import (
    DOCUMENT_COUNT,
    REQUEST_LIMIT,
    REQUEST_TARGETS,
    compile_request_bytes_plan,
)

PROJECT = "fireemu-35fe6"
DATABASE = "(default)"
NONCE = "a32e23a844ac11484405c005bb1a9e27"
SPEC = HERE.parents[2] / "spec/compatibility/fs-request-bytes-campaign.json"


@pytest.fixture
def campaign() -> dict:
    return compile_request_bytes_campaign(PROJECT, DATABASE, NONCE)


def test_campaign_validates(campaign: dict) -> None:
    validate_request_bytes_campaign(campaign)


def test_campaign_is_deterministic() -> None:
    first = compile_request_bytes_campaign(PROJECT, DATABASE, NONCE)
    second = compile_request_bytes_campaign(PROJECT, DATABASE, NONCE)
    assert campaign_digest(first) == campaign_digest(second)


def test_boundary_covers_the_exact_limit_and_one_byte_either_side(
    campaign: dict,
) -> None:
    assert campaign["boundary"]["limit"] == 10_485_760
    assert campaign["boundary"]["acceptedBytes"] == [10_485_759, 10_485_760]
    assert campaign["boundary"]["refusedBytes"] == [10_485_761]
    assert [case["requestBytes"] for case in campaign["cases"]] == list(REQUEST_TARGETS)


def test_only_the_over_case_expects_a_refusal(campaign: dict) -> None:
    by_id = {case["id"]: case for case in campaign["cases"]}
    assert by_id[CASE_IDS[0]]["productionExpectation"] == "accepted"
    assert by_id[CASE_IDS[1]]["productionExpectation"] == "accepted"
    assert by_id[CASE_IDS[2]]["productionExpectation"] == "refused"
    assert by_id[CASE_IDS[2]]["refusalShape"] == REFUSAL_EXPECTATION
    assert by_id[CASE_IDS[0]]["refusalShape"] is None


def test_refusal_shape_names_the_typed_codes_and_the_non_proofs() -> None:
    codes = {item["httpStatus"]: item for item in REFUSAL_EXPECTATION["typed"]}
    assert codes[400]["classification"] == "expected"
    assert codes[413]["classification"] == "semantic-discrepancy"
    assert all(item["errorStatus"] == "INVALID_ARGUMENT" for item in codes.values())
    assert all(item["errorCode"] == item["httpStatus"] for item in codes.values())
    assert REFUSAL_EXPECTATION["notRefusal"]
    assert REFUSAL_EXPECTATION["untypedTransportRefusal"]["state"] == "commit-uncertain"


def test_refused_case_requires_an_absent_post_state_and_no_delete(
    campaign: dict,
) -> None:
    over = campaign["cases"][2]
    assert over["postState"]["readbackCount"] == DOCUMENT_COUNT
    assert over["postState"]["expected"] == "every owned resource absent"
    assert over["cleanup"]["versionBoundDeletes"] == 0
    assert over["cleanup"]["absenceProofs"] == DOCUMENT_COUNT


def test_accepted_cases_delete_every_owned_resource(campaign: dict) -> None:
    for case in campaign["cases"][:2]:
        assert case["cleanup"]["versionBoundDeletes"] == DOCUMENT_COUNT
        assert case["cleanup"]["absenceProofs"] == DOCUMENT_COUNT


def test_accounting_matches_the_compiled_schedule(campaign: dict) -> None:
    plan = compile_request_bytes_plan(PROJECT, DATABASE, NONCE)
    assert campaign["accounting"]["httpRequests"] == plan["bounds"]["totalRequestBound"]
    assert campaign["accounting"]["documentWrites"] == 2 * DOCUMENT_COUNT
    assert campaign["accounting"]["documentDeletes"] == 2 * DOCUMENT_COUNT
    assert campaign["accounting"]["documentReads"] == 3 * DOCUMENT_COUNT * 4
    assert campaign["accounting"]["uploadedBytes"] == sum(REQUEST_TARGETS)
    assert (
        campaign["planDigest"]
        == hashlib.sha256(
            json.dumps(plan, separators=(",", ":"), ensure_ascii=False).encode()
        ).hexdigest()
    )


def test_cost_sits_far_under_the_hard_ceiling(campaign: dict) -> None:
    cost = campaign["cost"]
    assert 0 < cost["estimatedCostUsd"] < 0.001
    assert cost["hardCostCeilingUsd"] == 0.5
    assert cost["networkCostUsd"] == 0.0
    assert "Ingress is not billed" in cost["networkNote"]


def test_budget_declares_a_recovery_window_that_fits(campaign: dict) -> None:
    window = campaign["budget"]["recoveryWindow"]
    assert window["reserveSeconds"] < campaign["budget"]["maxDurationSeconds"]
    assert window["reserveDeletes"] >= campaign["accounting"]["documentDeletes"]
    assert "read-only" in window["authority"]
    assert "NOT_FOUND" in window["exitCondition"]
    assert window["onExhaustion"]


def test_owner_block_binds_a_fresh_nonce_to_every_owned_scope(campaign: dict) -> None:
    owner = campaign["owner"]
    assert owner["nonce"] == NONCE
    assert owner["nonceDigest"] == hashlib.sha256(NONCE.encode()).hexdigest()
    assert owner["nonceHandling"]
    assert owner["resourceCount"] == 3 * DOCUMENT_COUNT
    assert len(set(owner["scopes"])) == 3
    assert all(NONCE in scope for scope in owner["scopes"])
    assert NONCE in owner["scope"]


def test_batchwrite_and_grpc_are_excluded_with_a_reason(campaign: dict) -> None:
    excluded = {
        item["operation"]: item["reason"] for item in campaign["excludedOperations"]
    }
    assert set(excluded) == {"BatchWrite", "gRPC Commit"}
    assert all(reason for reason in excluded.values())
    assert campaign["operations"] == ["Commit"]


def test_local_expectation_records_the_pending_implementation(campaign: dict) -> None:
    local = campaign["localExpectation"]
    assert local is LOCAL_EXPECTATION or local == LOCAL_EXPECTATION
    assert local["localEnforcement"] == "implementation pending"
    assert local["expectedCollectorFailures"] == ["over:unexpected-success"]
    assert local["expectedCompleted"] is False
    assert local["expectedResourceAbsence"] is True


def test_campaign_does_not_authorize_production(campaign: dict) -> None:
    assert campaign["productionExecuted"] is False
    assert campaign["formalCompatibilityClaim"] is False
    assert campaign["authorizesProductionExecution"] is False


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(
            lambda c: c.update(operations=["Commit", "BatchWrite"]),
            id="widened-operations",
        ),
        pytest.param(
            lambda c: c.update(excludedOperations=[]), id="batchwrite-not-excluded"
        ),
        pytest.param(
            lambda c: c["boundary"].update(refusedBytes=[]), id="no-refused-probe"
        ),
        pytest.param(
            lambda c: c["boundary"].update(acceptedBytes=[10_485_759]),
            id="exact-limit-dropped",
        ),
        pytest.param(
            lambda c: c["boundary"].update(metricStatus="established"),
            id="metric-promoted",
        ),
        pytest.param(
            lambda c: c["cases"][2].update(productionExpectation="accepted"),
            id="over-expected-accepted",
        ),
        pytest.param(
            lambda c: c["cases"][2].update(refusalShape=None),
            id="refusal-shape-removed",
        ),
        pytest.param(
            lambda c: c["cases"][2]["cleanup"].update(versionBoundDeletes=17),
            id="delete-on-refused-probe",
        ),
        pytest.param(
            lambda c: c["cases"][2]["postState"].update(expected="anything"),
            id="refused-post-state-relaxed",
        ),
        pytest.param(
            lambda c: c["cases"][0]["cleanup"].update(absenceProofs=0),
            id="absence-proof-dropped",
        ),
        pytest.param(
            lambda c: c["cases"][0]["postState"].update(readbackCount=1),
            id="partial-readback",
        ),
        pytest.param(
            lambda c: c["localExpectation"].update(localEnforcement="implemented"),
            id="local-difference-masked",
        ),
        pytest.param(
            lambda c: c["localExpectation"].update(expectedCompleted=True),
            id="local-run-expected-clean",
        ),
        pytest.param(
            lambda c: c["localExpectation"].update(expectedResourceAbsence=False),
            id="local-absence-waived",
        ),
        pytest.param(
            lambda c: c["owner"].update(nonce="not-a-nonce"), id="nonce-malformed"
        ),
        pytest.param(
            lambda c: c["owner"].update(nonceDigest="0" * 64), id="nonce-digest-unbound"
        ),
        pytest.param(
            lambda c: c["owner"].update(scopes=c["owner"]["scopes"][:1] * 3),
            id="probe-scopes-collapsed",
        ),
        pytest.param(
            lambda c: c["owner"].update(
                scopes=["projects/other/databases/(default)/documents/x"] * 3
            ),
            id="scope-escape",
        ),
        pytest.param(
            lambda c: c.update(ownerPreconditions=[{"id": "credential"}]),
            id="admission-precondition-dropped",
        ),
        pytest.param(
            lambda c: c["accounting"].update(documentWrites=1), id="accounting-drift"
        ),
        pytest.param(
            lambda c: c["planBounds"].update(totalRequestBound=9999),
            id="schedule-bound-drift",
        ),
        pytest.param(
            lambda c: c["planBounds"].update(maxInFlight=4), id="in-flight-widened"
        ),
        pytest.param(
            lambda c: c["cost"].update(estimatedCostUsd=0.9), id="estimate-over-ceiling"
        ),
        pytest.param(
            lambda c: c["cost"].update(estimatedCostUsd=0.000001),
            id="estimate-not-from-accounting",
        ),
        pytest.param(
            lambda c: c["budget"].update(maxConcurrency=4), id="concurrency-widened"
        ),
        pytest.param(
            lambda c: c["budget"].update(maxDeletes=0), id="budget-delete-drift"
        ),
        pytest.param(
            lambda c: c["budget"].pop("recoveryWindow"), id="recovery-window-removed"
        ),
        pytest.param(
            lambda c: c["budget"]["recoveryWindow"].update(reserveSeconds=100_000),
            id="recovery-window-does-not-fit",
        ),
        pytest.param(
            lambda c: c["budget"]["recoveryWindow"].update(reserveDeletes=1),
            id="recovery-reserve-too-small",
        ),
        pytest.param(
            lambda c: c["budget"]["recoveryWindow"].update(onExhaustion=""),
            id="recovery-exhaustion-unspecified",
        ),
        pytest.param(
            lambda c: c.update(refusalExpectation={"typed": []}),
            id="refusal-expectation-emptied",
        ),
        pytest.param(
            lambda c: c.update(authorizesProductionExecution=True),
            id="claims-production-authority",
        ),
        pytest.param(
            lambda c: c.update(formalCompatibilityClaim=True), id="claims-compatibility"
        ),
        pytest.param(lambda c: c.update(catalogMaximum=1), id="catalog-maximum-drift"),
        pytest.param(lambda c: c["cases"].pop(), id="probe-dropped"),
    ],
)
def test_validator_rejects_mutated_campaigns(campaign: dict, mutate) -> None:
    mutated = copy.deepcopy(campaign)
    mutate(mutated)
    with pytest.raises((ValueError, TypeError, KeyError, IndexError)):
        validate_request_bytes_campaign(mutated)


def test_checked_in_campaign_artifact_matches_the_compiler() -> None:
    published = json.loads(SPEC.read_text())
    validate_request_bytes_campaign(published)
    rebuilt = compile_request_bytes_campaign(
        published["owner"]["project"], published["owner"]["database"], NONCE
    )
    assert published["owner"]["nonceDigest"] == rebuilt["owner"]["nonceDigest"]
    assert published == rebuilt
    assert REQUEST_LIMIT == published["catalogMaximum"]
