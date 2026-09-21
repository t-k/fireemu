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
    ENVIRONMENT_LOCAL,
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
    acquisition_for,
    bound_transport,
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
        bound_transport(plan, ROLE_LOCAL_SHADOW),
        role=ROLE_LOCAL_SHADOW,
        run_id=run_id,
        acquisition=acquisition_for(plan, ROLE_LOCAL_SHADOW),
    )


def bound_pair() -> tuple[dict, dict, dict]:
    """Two fully bound, agreeing bundles and the production plan."""
    plan = production_plan()
    production = collect(
        plan,
        bound_transport(plan, ROLE_PRODUCTION),
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
    assert len(result["rows"]) == 33
    assert [row["index"] for row in result["rows"]] == list(range(33))
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


def test_a_relabelled_environment_is_still_refused_by_its_artifact_and_principals() -> (
    None
):
    """A local bundle relabelled as production, with its environment label,
    reservation, permission and window copied from a production bundle, is
    still refused by the artifact it carries and the principals it shares.
    (Its loopback endpoints refuse it too; that signal is isolated below.)"""
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


# Each of the three local-mislabelled-as-production signals, isolated. Every
# test below starts from the real bound production bundle and changes exactly
# one binding, so that deleting that one check in the comparator fails
# exactly one test. Mutants verified on 2026-09-21 against this file: (a)
# replacing `side.fail("local-mislabelled-as-production")` under `if loopback`
# in _admit_endpoint with `pass` fails the loopback signal test and the
# short-a-row test below, nothing else; (b) the same replacement under
# `kind == ENVIRONMENT_LOCAL` in _admit_acquisition fails only the environment
# signal test; (c) the same replacement under `artifact is not None` fails
# only the artifact signal test.


def _relabel_endpoints(bundle: dict, endpoint: str) -> None:
    for row in bundle["rows"]:
        row["endpoint"] = endpoint
    for release in bundle["transport"]["rulesetReleases"]:
        release["endpoint"] = endpoint
    for action in bundle["transport"]["principalActions"]:
        action["endpoint"] = endpoint
    for key in ("documentSteps", "accountSteps"):
        for step in bundle["cleanup"][key]:
            step["endpoint"] = endpoint
    bundle["transport"]["endpoints"] = [endpoint]
    bundle["acquisition"]["endpoint"] = [endpoint]
    bundle["acquisition"]["rulesetReleases"] = bundle["transport"]["rulesetReleases"]


def test_signal_loopback_endpoints_alone_refuse_a_production_bundle() -> None:
    production, local, plan = bound_pair()
    _relabel_endpoints(production, LOCAL_ENDPOINT)
    result = compare(production, local, plan)
    assert result["classification"] == REFUSED
    assert result["errors"] == ["production:local-mislabelled-as-production"]


def test_signal_local_environment_kind_alone_refuses_a_production_bundle() -> None:
    production, local, plan = bound_pair()
    production["acquisition"]["environment"] = {"kind": ENVIRONMENT_LOCAL}
    result = compare(production, local, plan)
    assert result["classification"] == REFUSED
    assert result["errors"] == ["production:local-mislabelled-as-production"]


def test_signal_an_artifact_binding_alone_refuses_a_production_bundle() -> None:
    production, local, plan = bound_pair()
    production["acquisition"]["artifact"] = copy.deepcopy(
        local["acquisition"]["artifact"]
    )
    result = compare(production, local, plan)
    assert result["classification"] == REFUSED
    assert result["errors"] == ["production:local-mislabelled-as-production"]


def test_a_production_bundle_short_a_row_is_still_refused_for_its_endpoints() -> None:
    """A row-count mismatch does not hide where the requests went."""
    production, local, plan = bound_pair()
    _relabel_endpoints(production, LOCAL_ENDPOINT)
    production["rows"].pop()
    result = compare(production, local, plan)
    assert result["classification"] == REFUSED
    assert "production:local-mislabelled-as-production" in result["errors"]
    assert "production:row-count" in result["errors"]


def test_a_production_identity_drift_is_refused_even_with_a_copied_plan_digest() -> (
    None
):
    """The production identity check is not isolated from case-digest-drift:
    a bundle that declares another tenant and copies the production plan
    digest is refused by both, by design (the recompiled plan differs)."""
    production, local, plan = bound_pair()
    production["provenance"]["case"]["tenant"] = LOCAL_TENANT
    result = compare(production, local, plan)
    assert result["classification"] == REFUSED
    assert "production:case-identity-drift" in result["errors"]


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
    production["rows"][30]["ruleset"] = "A"
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


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b["rows"].__setitem__(3, "not-a-row"),
        lambda b: b["rows"].__setitem__(3, None),
        lambda b: b["cleanup"]["documentSteps"][0].__setitem__("observed", "str"),
        lambda b: b["cleanup"]["accountSteps"][0].__setitem__("observed", 7),
        lambda b: b["transport"]["rulesetReleases"][0].__setitem__("label", ["A"]),
        lambda b: b["transport"]["rulesetReleases"][0].__setitem__("label", {"A": 1}),
        lambda b: b["transport"].__setitem__("rulesetReleases", [None]),
        lambda b: b["transport"].__setitem__("clock", "soon"),
        lambda b: b["budget"].__setitem__("deadlineSeconds", "JUNK"),
        lambda b: b["acquisition"].__setitem__("principals", ["owner-a"]),
        lambda b: b.__setitem__(
            "cleanup", {"documentSteps": "x", "accountSteps": None}
        ),
    ],
)
@pytest.mark.parametrize("side", ["production", "local"])
def test_malformed_shapes_are_named_and_never_raise(mutate, side) -> None:
    production, local, plan = bound_pair()
    mutate(production if side == "production" else local)
    result = compare(production, local, plan)
    assert result["classification"] in (INDETERMINATE, REFUSED)
    assert result["errors"]
    assert not any(e.startswith("comparator-exception") for e in result["errors"])


def test_an_unforeseen_exception_becomes_an_indeterminate_error(monkeypatch) -> None:
    import o5_user_token_comparator_v2 as module

    def explode(*args, **kwargs):
        raise KeyError("unexpected")

    monkeypatch.setattr(module, "_admit_transport", explode)
    production, local, plan = bound_pair()
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert "comparator-exception:KeyError" in result["errors"]
    assert result["rows"] == []


@pytest.mark.parametrize(
    "field,value,error",
    [
        ("deadlineSeconds", "JUNK", "count-contradiction:deadlineSeconds"),
        ("deadlineSeconds", None, "count-contradiction:deadlineSeconds"),
        ("recoveryDeadlineSeconds", -1, "count-contradiction:recoveryDeadlineSeconds"),
        ("recoveryCeiling", 1000, "count-contradiction:recovery-ceiling"),
        ("observationCeiling", 31, "count-contradiction:observation-ceiling"),
        ("rulesetCeiling", 3, "count-contradiction:ruleset-ceiling"),
        ("principalActionSpent", 2, "count-contradiction:principal-action-spent"),
        ("principalActionCeiling", 0, "count-contradiction:principal-action-ceiling"),
    ],
)
def test_every_budget_bound_is_mandatory_on_the_match_path(field, value, error) -> None:
    production, local, plan = bound_pair()
    production["budget"][field] = value
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert f"production:{error}" in result["errors"]


@pytest.mark.parametrize(
    "name",
    ["scripted-A-1", "ya29.a0AfH6SMB", "AIzaSyD-example", "projects/other/x/y", ""],
)
def test_a_production_release_must_be_named_by_a_rules_api_resource(name) -> None:
    production, local, plan = bound_pair()
    production["transport"]["rulesetReleases"][0]["releaseName"] = name
    production["acquisition"]["rulesetReleases"] = production["transport"][
        "rulesetReleases"
    ]
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert "production:ruleset-mismatch:A:release-name" in result["errors"]


@pytest.mark.parametrize(
    "name", ["endpoint", "observerDigest", "rulesetReleases", "wireCounts"]
)
def test_an_acquisition_mirror_that_contradicts_its_canonical_field_is_named(
    name,
) -> None:
    production, local, plan = bound_pair()
    production["acquisition"][name] = "drifted"
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert f"production:acquisition-mirror-drift:{name}" in result["errors"]


def test_a_raw_account_identifier_in_a_bundle_is_named() -> None:
    production, local, plan = bound_pair()
    production["cleanup"]["accountSteps"][0]["observed"]["uid"] = (
        "L7fNfbBctFzloK39kcvtQpSrtUFx"
    )
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert "production:unredacted-identifier:1" in result["errors"]


def test_row_method_and_credential_class_are_bound_to_the_plan() -> None:
    production, local, plan = bound_pair()
    production["rows"][16]["method"] = "get"
    local["rows"][4]["credentialClass"] = "user-id-token"
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert any(e.startswith("production:method-drift:") for e in result["errors"])
    assert any(e.startswith("local:credential-class-drift:") for e in result["errors"])


def test_cleanup_steps_must_be_timestamped_monotonically() -> None:
    production, local, plan = bound_pair()
    steps = production["cleanup"]["documentSteps"]
    steps[1]["at"] = steps[0]["at"] - 1
    result = compare(production, local, plan)
    assert result["classification"] == INDETERMINATE
    assert "production:time-contradiction:cleanup-not-monotonic" in result["errors"]


def test_every_result_classification_is_in_the_vocabulary() -> None:
    production, local, plan = bound_pair()
    for left, right in ((production, local), (local, production), (None, None)):
        assert compare(left, right, plan)["classification"] in CLASSIFICATIONS


def test_the_first_comparator_module_is_untouched_by_this_one() -> None:
    import o5_user_token_comparator as first

    assert not hasattr(first, "MATCH")
    assert first.CLASSIFICATIONS == (first.INDETERMINATE,)


# ---------------------------------------------------------------------------
# Principal actions (RULES-REVOKE-005): accept, act, refuse, all bound
# ---------------------------------------------------------------------------


def test_a_matching_pair_reports_the_revocation_hypothesis_without_classifying_it() -> (
    None
):
    """Both scripted sides return the compiled (local) statuses, so the rows
    match; the hypothesis says production would accept the three within-exp
    tokens, so those three read as contrary and the four controls as
    hypothesized. Classification is untouched."""
    production, local, plan = bound_pair()
    result = compare(production, local, plan)
    assert result["classification"] == MATCH
    assert result["hypotheses"] == {
        "credential-revocation": {"rows": 7, "asHypothesized": 4, "contrary": 3}
    }
    contrary = [r for r in result["rows"] if r["hypothesisOutcome"] == "contrary"]
    assert [r["caseId"] for r in contrary] == [
        "a-revoked-refresh-tokens-within-exp",
        "a-disabled-account-within-exp",
        "a-deleted-account-within-exp",
    ]
    assert all(r["productionHypothesis"]["status"] == "OK" for r in contrary)
    assert all(r["classification"] == MATCH for r in contrary)
    assert all(
        r["productionHypothesis"] is None and r["hypothesisOutcome"] is None
        for r in result["rows"]
        if r["condition"] != "credential-revocation"
    )


def test_a_production_that_behaves_as_hypothesized_is_a_mismatch_that_reads_as_expected() -> (
    None
):
    production, local, plan = bound_pair()
    for row in production["rows"]:
        if row["caseId"].endswith("-within-exp"):
            row["observed"]["status"] = "OK"
            row["observed"]["documentPresent"] = True
    result = compare(production, local, plan)
    assert result["classification"] == SEMANTIC_MISMATCH
    assert result["conditions"]["credential-revocation"] == SEMANTIC_MISMATCH
    assert result["hypotheses"]["credential-revocation"] == {
        "rows": 7,
        "asHypothesized": 7,
        "contrary": 0,
    }
    mismatched = [r["caseId"] for r in result["rows"] if r["classification"] != MATCH]
    assert mismatched == [
        "a-revoked-refresh-tokens-within-exp",
        "a-disabled-account-within-exp",
        "a-deleted-account-within-exp",
    ]


@pytest.mark.parametrize(
    "mutate,error",
    [
        (lambda a: a.pop(), "principal-action:count"),
        (
            lambda a: a[0].__setitem__("action", "disable"),
            "principal-action:revoked-e:identity",
        ),
        (
            lambda a: a[0].__setitem__("beforeIndex", 23),
            "principal-action:revoked-e:identity",
        ),
        (
            lambda a: a[0].__setitem__("validSince", a[0]["authTime"]),
            "principal-action:revoked-e:validSince",
        ),
        (
            lambda a: a[1].__setitem__("validSince", 5),
            "principal-action:disabled-f:validSince",
        ),
        (
            lambda a: a[0].__setitem__("authTime", -1),
            "principal-action:revoked-e:authTime",
        ),
        (
            lambda a: a[1]["readback"].__setitem__("disabled", False),
            "principal-action:disabled-f:readback",
        ),
        (
            lambda a: a[2]["readback"].__setitem__("present", True),
            "principal-action:deleted-g:readback",
        ),
        (
            lambda a: a[0]["readback"].__setitem__("uidFingerprint", "0" * 16),
            "principal-action:revoked-e:principal",
        ),
        (lambda a: a[0].__setitem__("at", 0.0), "principal-action:revoked-e:order"),
        (
            lambda a: a[0].__setitem__("endpoint", LOCAL_ENDPOINT),
            "local-mislabelled-as-production",
        ),
    ],
)
def test_an_unproven_principal_action_is_named(mutate, error) -> None:
    production, local, plan = bound_pair()
    mutate(production["transport"]["principalActions"])
    result = compare(production, local, plan)
    assert result["classification"] != MATCH
    assert f"production:{error}" in result["errors"]


def test_an_action_that_is_not_between_its_control_and_its_row_is_named() -> None:
    production, local, plan = bound_pair()
    action = production["transport"]["principalActions"][0]
    action["at"] = production["rows"][action["beforeIndex"]]["at"] + 1
    result = compare(production, local, plan)
    assert "production:principal-action:revoked-e:order" in result["errors"]


def test_account_presence_at_recovery_must_match_what_the_campaign_did() -> None:
    production, local, plan = bound_pair()
    steps = production["cleanup"]["accountSteps"]
    readback = next(
        s
        for s in steps
        if s["kind"] == "account-readback" and s["accountRef"] == "deleted-g"
    )
    readback["observed"]["accountPresent"] = True
    readback["observed"]["uid"] = "principal:deleted-g"
    result = compare(production, local, plan)
    assert (
        "production:cleanup-unknown:present-at-readback:deleted-g" in result["errors"]
    )
    production, local, plan = bound_pair()
    steps = production["cleanup"]["accountSteps"]
    own = [s for s in steps if s["accountRef"] == "other-b"]
    own[0]["observed"]["accountPresent"] = False
    own[0]["observed"]["uid"] = None
    for step in own[1:]:
        steps.remove(step)
    result = compare(production, local, plan)
    assert "production:cleanup-unknown:absent-at-readback:other-b" in result["errors"]
