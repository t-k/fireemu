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
    _accept_combinations,
    campaign_digest,
    compile_request_bytes_campaign,
    gate_charging_plan,
    probe_usage,
    validate_request_bytes_campaign,
)
from request_bytes_compiler import (
    DOCUMENT_COUNT,
    REQUEST_LIMIT,
    REQUEST_TARGETS,
    compile_request_bytes_plan,
)

PROJECT = "fireemu-oracle-sbx"
DATABASE = "(default)"
NONCE = "388fe93ebfaafdec90477c6e938eb77a"
SPEC = HERE.parents[2] / "spec/compatibility/fs-request-bytes-campaign.json"


@pytest.fixture(scope="module")
def campaign() -> dict:
    """Compiled once for the module.

    Compiling builds the three 11 MiB bodies, so a per-test fixture dominated
    the suite. Every test that changes the artifact deep-copies it first, so
    sharing the compiled value is safe; a test that mutated it directly would
    leak into its neighbours, which is what the deep copies are for.
    """
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
    assert campaign["boundary"]["limit"] == 11_534_336
    assert campaign["boundary"]["acceptedBytes"] == [11_534_335, 11_534_336]
    assert campaign["boundary"]["refusedBytes"] == [11_534_337]
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
    assert campaign["accounting"]["dataRequests"] == plan["bounds"]["totalRequestBound"]
    assert campaign["accounting"]["managementRequests"] == 7
    assert campaign["accounting"]["httpRequests"] == 265
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


def test_local_expectation_records_the_implemented_limit(campaign: dict) -> None:
    local = campaign["localExpectation"]
    assert local == LOCAL_EXPECTATION
    assert "strict profile" in local["localEnforcement"]
    assert "MAX_STRICT_COMMIT_RAW_BYTES" in local["enforcementSource"]
    assert "API_REQUEST_BYTES = 10 * 1024 * 1024 remains in force" in local[
        "enforcementSource"
    ]
    assert local["catalogState"] == "implemented"
    assert local["observedProbeOutcomes"]["over"] == "refused"
    assert local["observedRefusal"]["httpStatus"] == 400
    assert local["observedRefusal"]["errorStatus"] == "INVALID_ARGUMENT"
    assert (
        local["observedRefusal"]["message"]
        == "Request payload size exceeds the limit: 11534336 bytes."
    )
    assert local["observedRefusal"]["classification"] == "expected"
    assert local["expectedCollectorFailures"] == []
    assert local["expectedCompleted"] is True
    assert local["expectedResourceAbsence"] is True


def test_saved_production_evidence_is_scoped_to_observed_raw_rest_cases(
    campaign: dict,
) -> None:
    local = campaign["localExpectation"]
    scope = local["differenceFromProductionExpectation"]
    assert "successful 11 MiB write with readback" in scope
    assert "11 MiB plus one byte" in scope
    assert "does not establish preservation" in scope
    assert "other transports" in scope
    assert local["classification"] == "local-shape-matches-production-expectation"


def test_the_superseded_413_baseline_stays_on_the_record(campaign: dict) -> None:
    local = campaign["localExpectation"]
    assert "413" in local["supersededBaseline"]
    assert local["emulatorProfileRefusal"]["rest"]["httpStatus"] == 413
    assert (
        local["emulatorProfileRefusal"]["rest"]["message"] == "request body too large"
    )
    assert local["emulatorProfileRefusal"]["grpc"]["errorStatus"] == "OUT_OF_RANGE"


def test_the_refusal_is_recorded_per_transport(campaign: dict) -> None:
    """A reader comparing a production receipt needs status, code and message."""
    rows = campaign["localExpectation"]["observedRefusalByTransport"]
    assert set(rows) == {"rest", "grpc"}
    rest, grpc = rows["rest"], rows["grpc"]
    assert rest["httpStatus"] == 400
    assert rest["errorCode"] == 400
    assert rest["errorStatus"] == "INVALID_ARGUMENT"
    assert rest["message"] == "Request payload size exceeds the limit: 11534336 bytes."
    # gRPC carries a google.rpc.Code, not an HTTP status.
    assert grpc["httpStatus"] is None
    assert grpc["errorCode"] == 3
    assert grpc["errorStatus"] == "INVALID_ARGUMENT"
    assert grpc["message"] == "Request payload size exceeds the limit: 10485760 bytes."
    # This campaign compiles REST bodies only, and the record says so.
    assert "not this campaign" in grpc["observedBy"]


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
            lambda c: c["boundary"].update(acceptedBytes=[REQUEST_LIMIT - 1]),
            id="exact-limit-dropped",
        ),
        pytest.param(
            lambda c: c["boundary"].update(metricStatus="established"),
            id="metric-promoted",
        ),
        pytest.param(
            lambda c: c["boundary"].update(catalogMaximum=REQUEST_LIMIT),
            id="catalog-maximum-conflated-with-route-boundary",
        ),
        pytest.param(
            lambda c: c["boundary"]["routeSpecificException"].update(
                evidence="catalog"
            ),
            id="route-exception-evidence-misrepresented",
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
            lambda c: c["localExpectation"].update(localEnforcement=""),
            id="local-enforcement-unnamed",
        ),
        pytest.param(
            lambda c: c["localExpectation"].update(catalogState="unsupported"),
            id="catalog-state-stale",
        ),
        pytest.param(
            lambda c: c["localExpectation"].update(supersededBaseline=""),
            id="superseded-baseline-dropped",
        ),
        pytest.param(
            lambda c: c["localExpectation"]["observedRefusalByTransport"][
                "grpc"
            ].update(httpStatus=400),
            id="grpc-given-an-http-status",
        ),
        pytest.param(
            lambda c: c["localExpectation"]["observedRefusalByTransport"][
                "grpc"
            ].update(errorCode=400),
            id="grpc-code-not-from-google-rpc",
        ),
        pytest.param(
            lambda c: c["localExpectation"]["observedRefusalByTransport"][
                "grpc"
            ].update(observedBy="this campaign"),
            id="grpc-claimed-as-observed",
        ),
        pytest.param(
            lambda c: c["localExpectation"]["observedRefusalByTransport"][
                "rest"
            ].update(message="something else"),
            id="rest-row-disagrees-with-observation",
        ),
        pytest.param(
            lambda c: c["localExpectation"].pop("observedRefusalByTransport"),
            id="transports-not-separated",
        ),
        pytest.param(
            lambda c: c["localExpectation"].update(
                differenceFromProductionExpectation="They match, so production is confirmed."
            ),
            id="agreement-read-as-confirmation",
        ),
        pytest.param(
            lambda c: c["localExpectation"].update(expectedCompleted=False),
            id="local-outcome-misreported",
        ),
        pytest.param(
            lambda c: c["localExpectation"].update(expectedResourceAbsence=False),
            id="local-absence-waived",
        ),
        pytest.param(
            lambda c: c["localExpectation"].update(
                observedRefusal={
                    "httpStatus": 413,
                    "errorCode": 413,
                    "errorStatus": "INVALID_ARGUMENT",
                    "message": "request body too large",
                    "classification": "expected",
                }
            ),
            id="local-refusal-code-drift",
        ),
        pytest.param(
            lambda c: c["localExpectation"].update(
                differenceFromProductionExpectation=""
            ),
            id="local-difference-absorbed",
        ),
        pytest.param(
            lambda c: c["localExpectation"].update(enforcementSource=""),
            id="enforcement-source-unnamed",
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
    assert 10_485_760 == published["catalogMaximum"]


def test_route_specific_rest_commit_boundary_does_not_rewrite_catalog_maximum() -> None:
    compiled = compile_request_bytes_campaign("demo-project", "(default)", NONCE)
    assert compiled["catalogMaximum"] == 10_485_760
    assert compiled["boundary"]["limit"] == REQUEST_LIMIT == 11_534_336
    exception = compiled["boundary"]["routeSpecificException"]
    assert exception["operation"] == "REST Commit"
    assert exception["limit"] == REQUEST_LIMIT
    assert exception["evidence"] == "saved-production-comparison"
    routes = compiled["productionPreflight"]["routes"]
    assert all(
        "demo-project" in routes[slot] for slot in ("project", "database", "auth")
    )
    validate_request_bytes_campaign(compiled)


# --- Transport deadline -------------------------------------------------------


def test_the_budget_timeout_is_the_transport_ceiling(campaign: dict) -> None:
    from request_bytes_remote_transport import TIMEOUT

    assert campaign["budget"]["perRequestTimeoutSeconds"] == TIMEOUT
    assert campaign["transportDeadline"]["perRequestSeconds"] == TIMEOUT


def test_the_deadline_carries_its_derivation_and_its_consequence(
    campaign: dict,
) -> None:
    deadline = campaign["transportDeadline"]
    derivation = deadline["derivation"]
    assert derivation["uploadBits"] == REQUEST_TARGETS[-1] * 8
    assert deadline["perRequestSeconds"] >= derivation["derivedRequirementSeconds"]
    assert "cannot remove" in deadline["consequenceIfMissed"]
    assert "never silent" in deadline["detection"]
    assert deadline["ownerAction"]
    assert len(deadline["enforcedBy"]) == 2


def test_the_slowest_usable_upstream_rate_is_reachable(campaign: dict) -> None:
    deadline = campaign["transportDeadline"]
    rate = deadline["slowestUsableUpstreamBitsPerSecond"]
    assert rate == round(
        REQUEST_TARGETS[-1]
        * 8
        / (deadline["perRequestSeconds"] - deadline["nonUploadReserveSeconds"])
    )
    assert rate < 2_000_000


def test_the_untyped_refusal_is_never_a_refusal_proof(campaign: dict) -> None:
    untyped = campaign["refusalExpectation"]["untypedTransportRefusal"]
    assert untyped["classification"] == "untyped-transport-refusal"
    assert untyped["resultKey"] == "untypedOverRefusal"
    assert untyped["isRefusalProof"] is False
    assert "read-only" in untyped["recoveryAuthority"]


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(
            lambda c: c["budget"].update(perRequestTimeoutSeconds=600),
            id="budget-timeout-above-the-transport-ceiling",
        ),
        pytest.param(
            lambda c: c["transportDeadline"].update(perRequestSeconds=5),
            id="deadline-below-its-derivation",
        ),
        pytest.param(
            lambda c: c["transportDeadline"]["derivation"].update(uploadBits=1),
            id="derivation-not-at-boundary-size",
        ),
        pytest.param(
            lambda c: c["transportDeadline"].update(consequenceIfMissed=""),
            id="consequence-unstated",
        ),
        pytest.param(
            lambda c: c["transportDeadline"].update(detection=""),
            id="detection-unstated",
        ),
        pytest.param(
            lambda c: c["transportDeadline"].update(enforcedBy=[]),
            id="enforcement-unnamed",
        ),
        pytest.param(
            lambda c: c["transportDeadline"].update(nonUploadReserveSeconds=0),
            id="reserve-does-not-fit",
        ),
        pytest.param(
            lambda c: c["transportDeadline"].update(
                slowestUsableUpstreamBitsPerSecond=1
            ),
            id="rate-does-not-follow",
        ),
        pytest.param(lambda c: c.pop("transportDeadline"), id="deadline-not-published"),
    ],
)
def test_validator_rejects_deadline_drift(campaign: dict, mutate) -> None:
    mutated = copy.deepcopy(campaign)
    mutate(mutated)
    with pytest.raises((ValueError, TypeError, KeyError)):
        validate_request_bytes_campaign(mutated)


# --- Budget must cover the outcome the campaign exists to detect --------------


def test_the_budget_maxima_cover_every_probe_being_accepted(campaign: dict) -> None:
    """An unexpected over-success creates and recovers all 51 documents."""
    budget = campaign["budget"]
    assert budget["maxWrites"] == 3 * DOCUMENT_COUNT
    assert budget["maxDeletes"] == 3 * DOCUMENT_COUNT
    assert budget["maxDocuments"] == 3 * DOCUMENT_COUNT


def test_the_forecast_is_published_but_binds_nothing(campaign: dict) -> None:
    budget = campaign["budget"]
    assert budget["expectedWrites"] == 2 * DOCUMENT_COUNT
    assert budget["expectedDeletes"] == 2 * DOCUMENT_COUNT
    assert budget["expectedWrites"] < budget["maxWrites"]
    assert campaign["accounting"]["documentWrites"] == budget["expectedWrites"]
    assert campaign["maximumUsage"]["documentWrites"] == budget["maxWrites"]
    assert budget["budgetBasis"]


def test_the_request_bound_and_peak_live_set_do_not_rise(campaign: dict) -> None:
    """Probes are cleaned up one at a time and refused deletes are zero-wire."""
    budget = campaign["budget"]
    assert budget["maxDataRequests"] == 258
    assert budget["maxManagementRequests"] == 7
    assert budget["maxHttpRequests"] == 265
    assert budget["maxPeakLiveDocuments"] == DOCUMENT_COUNT
    assert campaign["maximumUsage"]["dataRequests"] == 258
    assert campaign["maximumUsage"]["managementRequests"] == 7
    assert campaign["maximumUsage"]["httpRequests"] == 265
    assert campaign["maximumUsage"]["peakLiveDocuments"] == DOCUMENT_COUNT


def test_the_recovery_reserve_covers_the_maximum_not_the_forecast(
    campaign: dict,
) -> None:
    window = campaign["budget"]["recoveryWindow"]
    assert window["reserveDeletes"] >= campaign["maximumUsage"]["documentDeletes"]


def test_the_ceiling_clears_the_maximum_cost(campaign: dict) -> None:
    cost = campaign["cost"]
    assert cost["maximumCostUsd"] >= cost["estimatedCostUsd"]
    assert cost["maximumCostUsd"] < cost["hardCostCeilingUsd"]


@pytest.mark.parametrize(
    "accepted",
    [
        pytest.param(combination, id="".join("A" if f else "R" for f in combination))
        for combination in _accept_combinations()
    ],
)
def test_every_accept_refuse_combination_fits_the_reservation(
    campaign: dict, accepted: tuple
) -> None:
    """Each probe accepted needs 17 creates and 17 version-bound recoveries."""
    budget = campaign["budget"]
    usage = probe_usage(accepted)
    live = sum(1 for flag in accepted if flag)
    assert usage["documentWrites"] == live * DOCUMENT_COUNT
    assert usage["documentDeletes"] == usage["documentWrites"]
    assert usage["documentWrites"] <= budget["maxWrites"]
    assert usage["documentDeletes"] <= budget["maxDeletes"]
    assert usage["documentReads"] <= budget["maxReads"]
    assert usage["httpRequests"] <= budget["maxHttpRequests"]
    assert usage["peakLiveDocuments"] <= budget["maxPeakLiveDocuments"]
    assert usage["documentDeletes"] <= budget["recoveryWindow"]["reserveDeletes"]


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(
            lambda c: c["budget"].update(maxWrites=34), id="budget-assumes-the-outcome"
        ),
        pytest.param(
            lambda c: c["budget"].update(maxDeletes=34), id="deletes-assume-the-outcome"
        ),
        pytest.param(
            lambda c: c["budget"].update(maxDocuments=34), id="documents-assume-outcome"
        ),
        pytest.param(
            lambda c: c["maximumUsage"].update(documentDeletes=34),
            id="maximum-cannot-recover-what-it-creates",
        ),
        pytest.param(
            lambda c: c["maximumUsage"].update(documentWrites=34),
            id="maximum-below-all-accepted",
        ),
        pytest.param(
            lambda c: c["maximumUsage"].update(peakLiveDocuments=51),
            id="peak-live-inflated",
        ),
        pytest.param(lambda c: c.pop("maximumUsage"), id="maximum-not-published"),
        pytest.param(
            lambda c: c["budget"].update(expectedWrites=51), id="forecast-drift"
        ),
        pytest.param(lambda c: c["budget"].pop("budgetBasis"), id="basis-unstated"),
        pytest.param(
            lambda c: c["cost"].pop("maximumCostUsd"), id="maximum-cost-not-published"
        ),
        pytest.param(
            lambda c: c["cost"].update(maximumCostUsd=0.9),
            id="maximum-cost-over-the-ceiling",
        ),
    ],
)
def test_validator_rejects_a_budget_that_assumes_the_outcome(
    campaign: dict, mutate
) -> None:
    mutated = copy.deepcopy(campaign)
    mutate(mutated)
    with pytest.raises((ValueError, TypeError, KeyError)):
        validate_request_bytes_campaign(mutated)


# --- The reserve and the ceiling are sized by the maximum ---------------------


def test_the_recovery_reserve_covers_two_reads_per_owned_resource(
    campaign: dict,
) -> None:
    """An ownership read and an absence proof for each of the 51 resources."""
    window = campaign["budget"]["recoveryWindow"]
    assert window["reserveReads"] >= campaign["maximumUsage"]["distinctResources"] * 2


def test_the_hard_ceiling_clears_the_maximum_cost(campaign: dict) -> None:
    cost = campaign["cost"]
    assert cost["hardCostCeilingUsd"] >= cost["maximumCostUsd"]


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(
            lambda c: c["budget"]["recoveryWindow"].update(reserveDeletes=34),
            id="reserve-deletes-sized-by-the-forecast",
        ),
        pytest.param(
            lambda c: c["budget"]["recoveryWindow"].update(reserveReads=1),
            id="reserve-reads-unbounded",
        ),
        pytest.param(
            lambda c: c["budget"]["recoveryWindow"].update(reserveReads=101),
            id="reserve-reads-one-short",
        ),
        pytest.param(
            lambda c: c["cost"].update(hardCostCeilingUsd=0.0002),
            id="ceiling-below-the-maximum-cost",
        ),
        pytest.param(
            lambda c: c["cost"].update(maximumCostUsd=0.0000001),
            id="maximum-cost-below-the-forecast",
        ),
    ],
)
def test_validator_rejects_a_reserve_or_ceiling_sized_by_the_forecast(
    campaign: dict, mutate
) -> None:
    mutated = copy.deepcopy(campaign)
    mutate(mutated)
    with pytest.raises((ValueError, TypeError, KeyError)):
        validate_request_bytes_campaign(mutated)


# --- The wall-clock arithmetic closes under the shared Gate's formula ---------


def test_the_reservation_is_what_the_real_gate_charges(campaign: dict) -> None:
    """Computed by calling shared_gate, not by re-deriving its formula.

    The previous version copied REQUEST_SECONDS out of the Gate and did its own
    arithmetic, so it agreed with a Gate that no longer existed.
    """
    import shared_gate

    plan = compile_request_bytes_plan(PROJECT, DATABASE, NONCE)
    gate = gate_charging_plan(plan)
    seconds = shared_gate.request_seconds(gate)
    reservation = campaign["budget"]["schedulingReservation"]
    assert reservation["chargedBy"] == "shared_gate"
    assert reservation["recoverySeconds"] == pytest.approx(
        shared_gate._recovery_time(gate, seconds)
    )
    assert reservation["observationSeconds"] == pytest.approx(
        shared_gate._observation_time(gate, seconds)
    )
    assert shared_gate._valid_schedule(gate["jobs"]["request-bytes"])
    assert shared_gate._ceiling_honoured(gate, seconds)


def test_every_slot_reserves_its_own_bound(campaign: dict) -> None:
    """An 11 MiB upload and a small cleanup read cannot share one honest bound."""
    plan = compile_request_bytes_plan(PROJECT, DATABASE, NONCE)
    schedule = gate_charging_plan(plan)["jobs"]["request-bytes"]["schedule"]
    assert len(schedule) == 258
    commits = [entry for entry in schedule if entry["creates"]]
    smalls = [entry for entry in schedule if not entry["creates"]]
    assert len(commits) == len(REQUEST_TARGETS)
    assert all(entry["seconds"] == 60.0 for entry in commits)
    assert all(entry["seconds"] == 3.0 for entry in smalls)


def _gate_allocation(campaign: dict, wall: float, recovery: float) -> dict:
    plan = compile_request_bytes_plan(PROJECT, DATABASE, NONCE)
    allocation = dict(gate_charging_plan(plan))
    allocation.update(
        contract="shared-local-v2",
        wallSeconds=wall,
        recoverySeconds=recovery,
        costMicrousd=int(campaign["cost"]["maximumCostUsd"] * 1_000_000) + 1,
        observationRequests=campaign["budget"]["maxHttpRequests"],
        requestCostMicrousd=1,
    )
    return allocation


def test_the_real_gate_accepts_the_published_windows(campaign: dict, tmp_path) -> None:
    """The decisive check: the Gate itself admits this allocation."""
    import shared_gate

    budget = campaign["budget"]
    shared_gate.create(
        tmp_path / "gate",
        _gate_allocation(
            campaign,
            budget["maxDurationSeconds"],
            budget["recoveryWindow"]["reserveSeconds"],
        ),
    )


@pytest.mark.parametrize(
    ("wall", "recovery"),
    [
        pytest.param(900, 300, id="the-windows-this-lane-published-before"),
        pytest.param(900, 500, id="reserve-raised-but-wall-too-small"),
        pytest.param(1100, 300, id="wall-raised-but-reserve-too-small"),
    ],
)
def test_the_real_gate_refuses_windows_that_cannot_pay(
    campaign: dict, tmp_path, wall, recovery
) -> None:
    import shared_gate

    with pytest.raises(ValueError):
        shared_gate.create(
            tmp_path / f"gate-{wall}-{recovery}",
            _gate_allocation(campaign, wall, recovery),
        )


def test_the_published_windows_pay_for_the_reservation(campaign: dict) -> None:
    budget = campaign["budget"]
    reservation = budget["schedulingReservation"]
    window = budget["recoveryWindow"]
    assert window["reserveSeconds"] >= reservation["recoverySeconds"]
    assert reservation["totalSeconds"] <= budget["maxDurationSeconds"]
    assert budget["maxDurationSeconds"] <= reservation["gateWallCapSeconds"]
    assert (
        reservation["observationSeconds"]
        <= budget["maxDurationSeconds"] - window["reserveSeconds"]
    )


def test_a_small_slot_cannot_outrun_its_own_reservation(campaign: dict) -> None:
    """A reservation nothing enforces is a wish."""
    budget = campaign["budget"]
    from request_bytes_remote_transport import SMALL_REQUEST_TIMEOUT

    assert budget["smallRequestTimeoutSeconds"] == SMALL_REQUEST_TIMEOUT
    assert (
        budget["smallRequestTimeoutSeconds"]
        <= budget["schedulingReservation"]["smallRequestSeconds"]
    )
    assert budget["smallRequestTimeoutSeconds"] <= budget["perRequestTimeoutSeconds"]


def test_a_small_slot_reserves_far_more_than_a_round_trip(campaign: dict) -> None:
    """The bound should be about an order of magnitude over an HTTPS round trip."""
    assert campaign["budget"]["schedulingReservation"]["smallRequestSeconds"] >= 3.0


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(
            lambda c: c["budget"]["recoveryWindow"].update(reserveSeconds=300),
            id="the-old-reserve-cannot-pay-for-its-slots",
        ),
        pytest.param(
            lambda c: c["budget"].update(maxDurationSeconds=900),
            id="the-old-wall-does-not-fit-the-schedule",
        ),
        pytest.param(
            lambda c: c["budget"].update(maxDurationSeconds=1300),
            id="wall-above-the-gate-cap",
        ),
        pytest.param(
            lambda c: c["budget"].update(smallRequestTimeoutSeconds=60.0),
            id="timeout-does-not-enforce-the-reservation",
        ),
        pytest.param(
            lambda c: c["budget"]["schedulingReservation"].update(intervalSeconds=0.0),
            id="interval-below-the-gate-floor",
        ),
        pytest.param(
            lambda c: c["budget"]["schedulingReservation"].update(recoverySlots=51),
            id="recovery-slot-count-drift",
        ),
        pytest.param(
            lambda c: c["budget"]["schedulingReservation"].update(recoverySeconds=1.0),
            id="reservation-arithmetic-faked",
        ),
        pytest.param(
            lambda c: c["budget"].pop("schedulingReservation"),
            id="reservation-not-published",
        ),
    ],
)
def test_validator_rejects_windows_that_cannot_pay_for_the_schedule(
    campaign: dict, mutate
) -> None:
    mutated = copy.deepcopy(campaign)
    mutate(mutated)
    with pytest.raises((ValueError, TypeError, KeyError)):
        validate_request_bytes_campaign(mutated)


def test_the_campaign_digest_is_reproducible_from_the_published_file() -> None:
    """An admission record names a digest a reader must be able to recompute.

    The digest used to depend on key insertion order, so the object this module
    builds and the same artifact loaded back from its sorted JSON file hashed
    differently.
    """
    published = json.loads(SPEC.read_text())
    rebuilt = compile_request_bytes_campaign(
        published["owner"]["project"], published["owner"]["database"], NONCE
    )
    assert published == rebuilt
    assert campaign_digest(published) == campaign_digest(rebuilt)


def test_the_campaign_digest_ignores_key_order_but_not_value() -> None:
    published = json.loads(SPEC.read_text())
    reordered = dict(reversed(list(published.items())))
    assert list(reordered) != list(published)
    assert campaign_digest(reordered) == campaign_digest(published)
    changed = {**published, "catalogMaximum": 1}
    assert campaign_digest(changed) != campaign_digest(published)


# --- The Gate constants this module still copies are bound to its behaviour ---
#
# GATE_INTERVAL_FLOOR_SECONDS and GATE_WALL_CAP_SECONDS are local copies of two
# inline literals in shared_gate.create. Importing named constants is the better
# fix and is with shared_gate's owner; until then these pin the copies to what
# the Gate actually does, so a change there fails here rather than silently
# admitting a plan the Gate refuses.


def _minimal_allocation(campaign: dict, **overrides) -> dict:
    plan = compile_request_bytes_plan(PROJECT, DATABASE, NONCE)
    allocation = dict(gate_charging_plan(plan))
    allocation.update(
        contract="shared-local-v2",
        wallSeconds=campaign["budget"]["maxDurationSeconds"],
        recoverySeconds=campaign["budget"]["recoveryWindow"]["reserveSeconds"],
        costMicrousd=int(campaign["cost"]["maximumCostUsd"] * 1_000_000) + 1,
        observationRequests=campaign["budget"]["maxHttpRequests"],
        requestCostMicrousd=1,
    )
    allocation.update(overrides)
    return allocation


def test_the_gate_really_refuses_an_interval_below_our_floor(
    campaign: dict, tmp_path
) -> None:
    import shared_gate
    from request_bytes_campaign import GATE_INTERVAL_FLOOR_SECONDS

    below = GATE_INTERVAL_FLOOR_SECONDS / 2
    with pytest.raises(ValueError):
        shared_gate.create(
            tmp_path / "below", _minimal_allocation(campaign, intervalSeconds=below)
        )
    # And accepts the floor itself, so the copy is neither too high nor too low.
    shared_gate.create(
        tmp_path / "at-floor",
        _minimal_allocation(campaign, intervalSeconds=GATE_INTERVAL_FLOOR_SECONDS),
    )


def test_the_gate_really_refuses_a_wall_above_our_cap(campaign: dict, tmp_path) -> None:
    import shared_gate
    from request_bytes_campaign import GATE_WALL_CAP_SECONDS

    with pytest.raises(ValueError):
        shared_gate.create(
            tmp_path / "above",
            _minimal_allocation(campaign, wallSeconds=GATE_WALL_CAP_SECONDS + 1),
        )
    shared_gate.create(
        tmp_path / "at-cap",
        _minimal_allocation(campaign, wallSeconds=GATE_WALL_CAP_SECONDS),
    )


def test_the_campaign_interval_is_a_choice_not_the_gate_floor(campaign: dict) -> None:
    """Two different quantities that happen to be equal today.

    The floor is the least the Gate permits anyone; the interval is what this
    schedule declares. If they were the same name, a change to the Gate's
    minimum would silently change this campaign's pacing.
    """
    from request_bytes_campaign import (
        CAMPAIGN_INTERVAL_SECONDS,
        GATE_INTERVAL_FLOOR_SECONDS,
    )

    declared = campaign["budget"]["schedulingReservation"]["intervalSeconds"]
    assert declared == CAMPAIGN_INTERVAL_SECONDS
    # The floor's only job here is to say the choice is legal.
    assert declared >= GATE_INTERVAL_FLOOR_SECONDS


def test_the_wall_cap_is_a_ceiling_not_this_campaigns_wall(campaign: dict) -> None:
    from request_bytes_campaign import GATE_WALL_CAP_SECONDS

    wall = campaign["budget"]["maxDurationSeconds"]
    assert wall < GATE_WALL_CAP_SECONDS, (
        "the campaign wall is its own figure, checked against the Gate's ceiling"
    )
    assert campaign["budget"]["schedulingReservation"]["gateWallCapSeconds"] == (
        GATE_WALL_CAP_SECONDS
    )
