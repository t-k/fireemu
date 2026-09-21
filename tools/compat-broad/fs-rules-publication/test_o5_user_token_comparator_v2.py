"""Acquisition comparator: a positive path that only fully bound bundles reach.

Every bundle here is collected by the real collector in bound mode through the
scripted transport of the collector tests, then one binding at a time is
mutated. No test opens a socket, holds a credential or touches production.
"""

from __future__ import annotations

import copy

import pytest
from o5_user_token_case import compile_case, digest
from o5_user_token_collector import (
    COLLECTOR_CONTRACT,
    ENVIRONMENT_PRODUCTION,
    READBACK_PUBLISH_ECHO,
    ROLE_LOCAL_SHADOW,
    ROLE_PRODUCTION,
    collect,
)
from o5_user_token_comparator_v2 import (
    CLASSIFICATIONS,
    COMPARATOR_CONTRACT,
    INDETERMINATE,
    MATCH,
    REFUSED,
    SEMANTIC_MISMATCH,
    compare,
)
from test_o5_user_token_collector import Transport
from test_o5_user_token_collector_bound import (
    LOCAL_ENDPOINT,
    LOCAL_TENANT,
    PRODUCTION_ENDPOINT,
    acquisition_for,
)

PROJECT = "fireemu-35fe6"
NONCE = "a" * 32
PRODUCTION_TENANT = "o5-user-token-tenant"


def production_plan() -> dict:
    return compile_case(PROJECT, "(default)", NONCE, PRODUCTION_TENANT)


def local_plan(nonce: str = NONCE) -> dict:
    return compile_case(PROJECT, "(default)", nonce, LOCAL_TENANT)


def bound_local(plan: dict, run_id: str = "local-1") -> dict:
    return collect(
        plan,
        Transport(plan, endpoint=LOCAL_ENDPOINT),
        role=ROLE_LOCAL_SHADOW,
        run_id=run_id,
        acquisition=acquisition_for(plan, ROLE_LOCAL_SHADOW),
    )


def bound_pair() -> tuple[dict, dict, dict]:
    """Two fully bound, agreeing bundles and the production plan."""
    plan = production_plan()
    production = collect(
        plan,
        Transport(plan, endpoint=PRODUCTION_ENDPOINT),
        role=ROLE_PRODUCTION,
        run_id="production-1",
        acquisition=acquisition_for(plan, ROLE_PRODUCTION),
    )
    return production, bound_local(local_plan()), plan


def errors_of(result: dict) -> str:
    return " ".join(result["errors"])


# ---------------------------------------------------------------------------
# Positive path
# ---------------------------------------------------------------------------


def test_the_comparator_has_four_classifications_and_a_distinct_contract() -> None:
    assert set(CLASSIFICATIONS) == {MATCH, SEMANTIC_MISMATCH, INDETERMINATE, REFUSED}
    assert COMPARATOR_CONTRACT != "fs-rules-user-token-comparator-v2"


def test_two_fully_bound_agreeing_bundles_match_on_every_row() -> None:
    production, local, plan = bound_pair()
    result = compare(production, local, plan)
    assert result["errors"] == []
    assert result["classification"] == MATCH
    assert result["acquisitionValidated"] is True
    assert result["productionObserved"] is True
    assert result["promotionReady"] is True
    assert len(result["rows"]) == 30
    assert [row["index"] for row in result["rows"]] == list(range(30))
    assert all(row["classification"] == MATCH for row in result["rows"])
    assert set(result["conditions"].values()) == {MATCH}
    assert set(result["conditions"]) == set(plan["conditions"])


def test_the_admitted_manifest_digest_is_checked_when_supplied() -> None:
    production, local, plan = bound_pair()
    admitted = production["acquisition"]["campaignManifestDigest"]
    assert (
        compare(production, local, plan, manifest_digest=admitted)["classification"]
        == MATCH
    )
    result = compare(production, local, plan, manifest_digest="0" * 64)
    assert result["classification"] == REFUSED
    assert "manifest-mismatch:admitted" in result["errors"]


def test_a_disagreeing_row_is_a_semantic_mismatch_that_names_the_row() -> None:
    production, local, plan = bound_pair()
    production["rows"][1]["observed"]["status"] = "OK"
    result = compare(production, local, plan)
    assert result["classification"] == SEMANTIC_MISMATCH
    assert result["acquisitionValidated"] is True
    assert result["promotionReady"] is False
    mismatched = [row for row in result["rows"] if row["classification"] != MATCH]
    assert [row["caseId"] for row in mismatched] == [plan["observation"][1]["caseId"]]
    assert mismatched[0]["reasons"] == ["status"]
    assert (
        result["conditions"][plan["observation"][1]["condition"]] == SEMANTIC_MISMATCH
    )


def test_principal_valued_fields_compare_by_presence_not_by_uid() -> None:
    production, local, plan = bound_pair()
    production["rows"][0]["observed"]["fields"]["ownerUid"] = "abc123"
    local["rows"][0]["observed"]["fields"]["ownerUid"] = "principal:owner-a"
    assert compare(production, local, plan)["classification"] == MATCH
    production["rows"][0]["observed"]["fields"]["ownerUid"] = ""
    assert compare(production, local, plan)["classification"] == SEMANTIC_MISMATCH


# ---------------------------------------------------------------------------
# Negative 1: a local run labelled as production
# ---------------------------------------------------------------------------


def test_a_local_run_relabelled_as_production_is_refused() -> None:
    _, local, plan = bound_pair()
    forged = copy.deepcopy(local)
    forged["provenance"]["role"] = ROLE_PRODUCTION
    forged["provenance"]["runId"] = "relabelled"
    forged["productionExecuted"] = True
    result = compare(forged, local, plan)
    assert result["classification"] == REFUSED
    assert "production:local-mislabelled-as-production" in result["errors"]
    assert result["rows"] == []


def test_a_relabelled_environment_is_still_refused_by_its_endpoints_and_artifact() -> (
    None
):
    production, local, plan = bound_pair()
    forged = copy.deepcopy(local)
    forged["provenance"]["role"] = ROLE_PRODUCTION
    forged["provenance"]["runId"] = "relabelled"
    forged["productionExecuted"] = True
    forged["acquisition"]["environment"] = {"kind": ENVIRONMENT_PRODUCTION}
    forged["acquisition"]["nonceReservation"] = production["acquisition"][
        "nonceReservation"
    ]
    forged["acquisition"]["ownerPermission"] = production["acquisition"][
        "ownerPermission"
    ]
    forged["acquisition"]["window"] = production["acquisition"]["window"]
    result = compare(forged, local, plan)
    assert result["classification"] == REFUSED
    assert "production:local-mislabelled-as-production" in result["errors"]
    # And the principals it minted are the local shadow's.
    assert any(
        error.startswith("principal-shared-across-sides") for error in result["errors"]
    )


def test_a_production_bundle_relabelled_as_local_is_refused() -> None:
    production, _, plan = bound_pair()
    forged = copy.deepcopy(production)
    forged["provenance"]["role"] = ROLE_LOCAL_SHADOW
    forged["provenance"]["runId"] = "relabelled"
    result = compare(production, forged, plan)
    assert result["classification"] == REFUSED
    assert "local:local-claims-production" in result["errors"]


# ---------------------------------------------------------------------------
# Negative 2: manifest digest mismatch
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("side", ["production", "local"])
def test_a_manifest_digest_that_is_not_the_recomputed_one_is_refused(side) -> None:
    production, local, plan = bound_pair()
    target = production if side == "production" else local
    target["acquisition"]["campaignManifestDigest"] = "1" * 64
    result = compare(production, local, plan)
    assert result["classification"] == REFUSED
    assert "manifest-mismatch" in result["errors"]


def test_a_missing_manifest_digest_is_named() -> None:
    production, local, plan = bound_pair()
    del local["acquisition"]["campaignManifestDigest"]
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert "local:missing-binding:campaignManifestDigest" in result["errors"]


# ---------------------------------------------------------------------------
# Negative 3: ruleset mismatch and generation order
# ---------------------------------------------------------------------------


def test_a_ruleset_source_digest_drift_is_named() -> None:
    production, local, plan = bound_pair()
    production["transport"]["rulesetReleases"][0]["sourceDigest"] = "2" * 64
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert "production:ruleset-mismatch:A:source" in result["errors"]


def test_a_ruleset_readback_that_differs_from_the_source_is_named() -> None:
    production, local, plan = bound_pair()
    production["transport"]["rulesetReleases"][1]["readback"]["digest"] = "3" * 64
    result = compare(production, local, plan)
    assert result["classification"] != MATCH
    assert "production:ruleset-mismatch:B:readback" in result["errors"]


def test_a_production_readback_must_be_a_release_get() -> None:
    production, local, plan = bound_pair()
    production["transport"]["rulesetReleases"][0]["readback"]["kind"] = (
        READBACK_PUBLISH_ECHO
    )
    result = compare(production, local, plan)
    assert result["classification"] != MATCH
    assert "production:ruleset-mismatch:A:readback-kind" in result["errors"]


def test_a_transition_row_that_predates_its_release_is_named() -> None:
    production, local, plan = bound_pair()
    release_b = production["transport"]["rulesetReleases"][1]
    first_b = production["rows"][release_b["beforeIndex"]]
    release_b["activeFrom"] = first_b["at"] + 1.0
    result = compare(production, local, plan)
    assert result["classification"] != MATCH
    assert (
        f"production:ruleset-generation-order:{first_b['caseId']}" in result["errors"]
    )


def test_a_missing_release_is_named() -> None:
    production, local, plan = bound_pair()
    production["transport"]["rulesetReleases"].pop()
    production["budget"]["rulesetSpent"] = 1
    result = compare(production, local, plan)
    assert result["classification"] != MATCH
    assert any(
        error.startswith("production:ruleset-generation-order:")
        for error in result["errors"]
    )


def test_a_row_under_the_wrong_ruleset_label_is_named() -> None:
    production, local, plan = bound_pair()
    production["rows"][27]["ruleset"] = "A"
    result = compare(production, local, plan)
    assert result["classification"] != MATCH
    assert any("ruleset-mismatch:row:" in error for error in result["errors"])


# ---------------------------------------------------------------------------
# Negative 4: principal mismatch
# ---------------------------------------------------------------------------


def test_row_principal_drift_and_fingerprint_drift_are_named() -> None:
    production, local, plan = bound_pair()
    production["rows"][2]["credentialRef"] = "owner-a"
    result = compare(production, local, plan)
    assert result["classification"] != MATCH
    assert any(
        error.startswith("production:principal-drift:") for error in result["errors"]
    )
    production, local, plan = bound_pair()
    local["rows"][2]["credentialFingerprint"] = "0" * 16
    result = compare(production, local, plan)
    assert result["classification"] != MATCH
    assert any(
        error.startswith("local:principal-fingerprint:") for error in result["errors"]
    )


@pytest.mark.parametrize(
    "field,value,reason",
    [
        ("claimsDigest", "4" * 64, "claims"),
        ("tenant", "other-tenant", "tenant"),
        ("provider", "google.com", "provider"),
        ("uidFingerprint", "not-hex", "fingerprint"),
    ],
)
def test_a_principal_that_does_not_match_the_plan_is_named(
    field, value, reason
) -> None:
    production, local, plan = bound_pair()
    production["acquisition"]["principals"]["owner-a"][field] = value
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert f"production:principal-mismatch:owner-a:{reason}" in result["errors"]


def test_identical_principals_on_both_sides_are_refused() -> None:
    production, local, plan = bound_pair()
    local["acquisition"]["principals"] = copy.deepcopy(
        production["acquisition"]["principals"]
    )
    for entry in local["acquisition"]["principals"].values():
        entry["tenant"] = None
    local["acquisition"]["principals"]["tenant-d"]["tenant"] = LOCAL_TENANT
    result = compare(production, local, plan)
    assert result["classification"] == REFUSED
    assert (
        "principal-shared-across-sides:"
        "owner-a,other-b,anonymous-c,tenant-d,revoked-e,disabled-f,deleted-g"
        in result["errors"]
    )


# ---------------------------------------------------------------------------
# Negative 5: incomplete record
# ---------------------------------------------------------------------------


def test_an_incomplete_recording_is_named() -> None:
    production, local, plan = bound_pair()
    local["recordingComplete"] = False
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert "local:recording-incomplete" in result["errors"]


def test_missing_rows_are_named() -> None:
    production, local, plan = bound_pair()
    production["rows"].pop()
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert "production:row-count" in result["errors"]
    assert result["rows"] == []


def test_an_aborted_run_and_infrastructure_failures_are_named() -> None:
    production, local, plan = bound_pair()
    production["abort"] = "deadline-exhausted"
    production["infrastructureFailures"] = ["x:timeout"]
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert "production:recording-aborted" in result["errors"]
    assert "production:recording-incomplete:infrastructure" in result["errors"]


def test_a_row_without_a_receipt_is_named() -> None:
    production, local, plan = bound_pair()
    production["rows"][5]["observed"] = None
    production["rows"][5]["failure"] = "transport:TimeoutError"
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    case_id = plan["observation"][5]["caseId"]
    assert f"production:row-failed:{case_id}" in result["errors"]
    assert f"production:row-unobserved:{case_id}" in result["errors"]


# ---------------------------------------------------------------------------
# Negative 6: cleanup unknown
# ---------------------------------------------------------------------------


def test_a_cleanup_step_with_a_failure_is_unknown_cleanup() -> None:
    production, local, plan = bound_pair()
    production["cleanup"]["documentSteps"][0]["failure"] = "transport:TimeoutError"
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert "production:cleanup-unknown:readback" in result["errors"]


def test_an_absence_that_was_not_typed_is_unknown_cleanup() -> None:
    production, local, plan = bound_pair()
    absence = next(
        step
        for step in production["cleanup"]["documentSteps"]
        if step["kind"] == "absence"
    )
    absence["observed"]["documentPresent"] = None
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert (
        f"production:cleanup-unknown:not-absent:{absence['resource']}"
        in result["errors"]
    )


def test_outstanding_resources_and_a_skipped_delete_are_unknown_cleanup() -> None:
    production, local, plan = bound_pair()
    local["cleanup"]["outstandingAccounts"] = ["owner-a"]
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert "local:cleanup-unknown:outstandingAccounts" in result["errors"]
    production, local, plan = bound_pair()
    steps = local["cleanup"]["accountSteps"]
    delete = next(step for step in steps if step["kind"] == "account-delete")
    steps.remove(delete)
    local["budget"]["recoverySpent"] -= 1
    local["transport"]["receipts"] -= 1
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert (
        f"local:cleanup-unknown:step-sequence:{delete['accountRef']}"
        in result["errors"]
    )


def test_a_cleanup_complete_flag_without_steps_is_unknown_cleanup() -> None:
    production, local, plan = bound_pair()
    production["cleanup"]["documentSteps"] = []
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert any(
        error.startswith("production:cleanup-unknown:no-readback:")
        for error in result["errors"]
    )


# ---------------------------------------------------------------------------
# Negative 7: time and count contradictions
# ---------------------------------------------------------------------------


def test_an_observation_count_that_disagrees_with_the_rows_is_named() -> None:
    production, local, plan = bound_pair()
    production["budget"]["observationSpent"] = 25
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert "production:count-contradiction:observation-spent" in result["errors"]


def test_non_monotonic_row_timestamps_are_named() -> None:
    production, local, plan = bound_pair()
    production["rows"][3]["at"] = production["rows"][2]["at"]
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert "production:time-contradiction:rows-not-monotonic" in result["errors"]


def test_a_wire_sequence_that_regresses_or_disagrees_in_count_is_named() -> None:
    production, local, plan = bound_pair()
    production["rows"][4]["wireSequence"] = 1
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert "production:count-contradiction:wire-sequence" in result["errors"]
    production, local, plan = bound_pair()
    production["transport"]["receipts"] += 1
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert "production:count-contradiction:wire-receipts" in result["errors"]


def test_a_row_outside_the_observation_span_or_deadline_is_named() -> None:
    production, local, plan = bound_pair()
    production["rows"][-1]["at"] = production["transport"]["clock"]["finished"] + 1
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert "production:time-contradiction:rows-outside-observation" in result["errors"]
    production, local, plan = bound_pair()
    clock = production["transport"]["clock"]
    clock["observationFinished"] = clock["started"] + 601.0
    clock["finished"] = clock["observationFinished"]
    production["transport"]["wallClock"]["finishedAt"] = (
        production["transport"]["wallClock"]["startedAt"] + 601.0
    )
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert "production:time-contradiction:deadline" in result["errors"]


def test_a_wall_clock_that_contradicts_the_monotonic_span_is_named() -> None:
    production, local, plan = bound_pair()
    production["transport"]["wallClock"]["finishedAt"] += 3600
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert "production:time-contradiction:wall-clock" in result["errors"]


def test_a_run_outside_its_approved_window_is_named() -> None:
    production, local, plan = bound_pair()
    production["acquisition"]["window"]["expiresAt"] = (
        production["transport"]["wallClock"]["startedAt"] - 1
    )
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert "production:time-contradiction:outside-window" in result["errors"]


def test_a_recovery_count_that_disagrees_with_the_steps_is_named() -> None:
    production, local, plan = bound_pair()
    local["budget"]["recoverySpent"] -= 1
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert "local:count-contradiction:recovery-spent" in result["errors"]
    production, local, plan = bound_pair()
    local["budget"]["recoverySpent"] = local["budget"]["recoveryCeiling"] + 1
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert "local:count-contradiction:recovery-ceiling" in result["errors"]


# ---------------------------------------------------------------------------
# Negative 8: self-comparison
# ---------------------------------------------------------------------------


def test_the_same_run_on_both_sides_is_refused() -> None:
    production, local, plan = bound_pair()
    local["provenance"]["runId"] = production["provenance"]["runId"]
    result = compare(production, local, plan)
    assert result["classification"] == REFUSED
    assert "self-comparison" in result["errors"]


def test_the_same_object_on_both_sides_is_refused() -> None:
    production, _, plan = bound_pair()
    result = compare(production, production, plan)
    assert result["classification"] == REFUSED
    assert "self-comparison" in result["errors"]


# ---------------------------------------------------------------------------
# Negative 9: authority claimed without bindings
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("flag", ["productionReady", "acquisitionValidated"])
def test_a_bundle_claiming_authority_is_refused(flag) -> None:
    production, local, plan = bound_pair()
    production[flag] = True
    result = compare(production, local, plan)
    assert result["classification"] == REFUSED
    assert "production:bundle-claims-authority" in result["errors"]


def test_a_production_bundle_without_acquisition_bindings_is_indeterminate() -> None:
    plan = production_plan()
    production = collect(plan, Transport(plan), role=ROLE_PRODUCTION, run_id="p")
    assert production["contract"] == COLLECTOR_CONTRACT
    production["productionExecuted"] = True
    _, local, _ = bound_pair()
    result = compare(production, local, plan)
    assert result["classification"] in (INDETERMINATE, REFUSED)
    assert result["classification"] != MATCH
    assert "production:missing-acquisition-bindings" in result["errors"]


@pytest.mark.parametrize(
    "binding", ["nonceReservation", "ownerPermission", "window", "principals"]
)
def test_a_production_bundle_missing_one_binding_is_named(binding) -> None:
    production, local, plan = bound_pair()
    production["acquisition"][binding] = None
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert f"production:missing-binding:{binding}" in result["errors"]


def test_a_local_bundle_needs_its_artifact_and_must_not_hold_a_reservation() -> None:
    production, local, plan = bound_pair()
    local["acquisition"]["artifact"] = None
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert "local:missing-binding:artifact" in result["errors"]
    production, local, plan = bound_pair()
    local["acquisition"]["nonceReservation"] = production["acquisition"][
        "nonceReservation"
    ]
    result = compare(production, local, plan)
    assert result["classification"] == REFUSED
    assert "local:local-claims-reservation" in result["errors"]


def test_a_reservation_for_another_nonce_is_named() -> None:
    production, local, plan = bound_pair()
    production["acquisition"]["nonceReservation"]["nonceDigest"] = digest("f" * 32)
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert "production:nonce-reservation-mismatch:nonce" in result["errors"]


# ---------------------------------------------------------------------------
# Collector identity, endpoints, contracts and malformed input
# ---------------------------------------------------------------------------


def test_a_copied_observer_digest_fails_against_the_sources_on_disk() -> None:
    production, local, plan = bound_pair()
    name = next(iter(production["observer"]["sourceDigests"]))
    production["observer"]["sourceDigests"][name] = "5" * 64
    result = compare(production, local, plan)
    assert result["classification"] == REFUSED
    assert "production:observer-digest-drift" in result["errors"]
    production, local, plan = bound_pair()
    local["observer"]["observerDigest"] = "6" * 64
    result = compare(production, local, plan)
    assert result["classification"] == REFUSED
    assert "local:observer-digest-drift" in result["errors"]


def test_a_production_endpoint_outside_the_allowlist_is_refused() -> None:
    production, local, plan = bound_pair()
    production["rows"][7]["endpoint"] = "example.com:443"
    result = compare(production, local, plan)
    assert result["classification"] == REFUSED
    assert "production:endpoint-outside-allowlist" in result["errors"]


def test_a_local_run_that_reached_a_non_loopback_host_is_refused() -> None:
    production, local, plan = bound_pair()
    local["transport"]["endpoints"].append("firestore.googleapis.com:443")
    result = compare(production, local, plan)
    assert result["classification"] == REFUSED
    assert "local:local-reached-nonloopback" in result["errors"]


def test_a_row_without_an_endpoint_is_unbound() -> None:
    production, local, plan = bound_pair()
    production["rows"][0]["endpoint"] = None
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert any(
        error.startswith("production:missing-binding:endpoint:row:")
        for error in result["errors"]
    )


def test_a_wrong_role_and_a_wrong_contract_are_refused() -> None:
    production, local, plan = bound_pair()
    local["provenance"]["role"] = "administrator"
    result = compare(production, local, plan)
    assert result["classification"] == REFUSED
    assert "local:role-mismatch" in result["errors"]
    production, local, plan = bound_pair()
    production["contract"] = "fs-rules-user-token-collector-v2"
    result = compare(production, local, plan)
    assert result["classification"] == REFUSED
    assert "production:collector-contract-drift" in result["errors"]


def test_a_local_shadow_of_another_nonce_is_refused() -> None:
    production, _, plan = bound_pair()
    local = bound_local(local_plan("f" * 32), run_id="local-2")
    result = compare(production, local, plan)
    assert result["classification"] == REFUSED
    assert "local:campaign-identity-drift" in result["errors"]


def test_a_case_digest_drift_is_refused() -> None:
    production, local, plan = bound_pair()
    local["planDigest"] = "7" * 64
    result = compare(production, local, plan)
    assert result["classification"] == REFUSED
    assert "local:case-digest-drift" in result["errors"]


@pytest.mark.parametrize("bad", [None, [], "bundle", {}, {"contract": "other"}])
def test_malformed_bundles_never_match(bad) -> None:
    production, local, plan = bound_pair()
    for result in (compare(bad, local, plan), compare(production, bad, plan)):
        assert result["classification"] in (INDETERMINATE, REFUSED)
        assert result["rows"] == []


def test_a_malformed_plan_is_refused_before_any_binding_check() -> None:
    production, local, _ = bound_pair()
    result = compare(production, local, {"project": []})
    assert result["classification"] == REFUSED
    assert len(result["errors"]) == 1
    assert result["errors"][0].startswith("plan-invalid:")


def test_every_result_classification_is_in_the_vocabulary() -> None:
    production, local, plan = bound_pair()
    for left, right in ((production, local), (local, production), (None, None)):
        assert compare(left, right, plan)["classification"] in CLASSIFICATIONS


def test_the_first_comparator_module_is_untouched_by_this_one() -> None:
    import o5_user_token_comparator as first

    assert not hasattr(first, "MATCH")
    assert first.CLASSIFICATIONS == (first.INDETERMINATE,)
