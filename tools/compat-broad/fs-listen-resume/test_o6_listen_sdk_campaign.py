import copy

import pytest
from o6_listen_resume import cases
from o6_listen_resume.campaign import (
    BUDGET,
    SCHEMA,
    SDK_INTEGRITY,
    SDK_PIN,
    STATUS_BLOCKED,
    STATUS_PREPARED,
    campaign_digest,
    compile_campaign,
    count_operations,
    estimate_cost_usd,
    owned_paths,
    validate_campaign,
)

NONCE = "0123456789abcdef0123456789abcdef"
PERMISSION = "o6-listen-sdk-0f1e2d3c4b5a6978"


def test_campaign_is_deterministic_and_blocked_without_a_permission():
    first = compile_campaign(NONCE)
    assert first == compile_campaign(NONCE)
    assert first["schema"] == SCHEMA
    assert first["status"] == STATUS_BLOCKED
    assert first["permission"] is None
    assert first["productionExecuted"] is False
    assert validate_campaign(first)


def test_supplying_a_campaign_permission_only_reaches_prepared():
    prepared = compile_campaign(NONCE, permission=PERMISSION)
    assert prepared["status"] == STATUS_PREPARED
    assert prepared["permission"] == PERMISSION
    assert prepared["productionExecuted"] is False
    assert validate_campaign(prepared)
    assert campaign_digest(prepared) != campaign_digest(compile_campaign(NONCE))


@pytest.mark.parametrize(
    "permission",
    ["", "o6-listen-sdk-", "fs-write-txn-0f1e2d3c4b5a6978", "o6-listen-sdk-XYZ"],
)
def test_permissions_from_other_campaigns_are_rejected(permission):
    with pytest.raises(ValueError, match="permission"):
        compile_campaign(NONCE, permission=permission)


@pytest.mark.parametrize("nonce", ["", "abc", "Z" * 32, "0" * 31 + "!"])
def test_campaign_rejects_a_non_128_bit_hex_nonce(nonce):
    with pytest.raises(ValueError, match="nonce"):
        compile_campaign(nonce)


@pytest.mark.parametrize(
    "project,database", [("other-project", "(default)"), ("fireemu-35fe6", "other")]
)
def test_campaign_restricts_project_and_database(project, database):
    with pytest.raises(ValueError, match="project/database"):
        compile_campaign(NONCE, project=project, database=database)


def test_owned_paths_are_nonce_scoped_and_do_not_collide_with_other_lanes():
    paths = owned_paths(NONCE)
    assert paths["run"] == f"o6_listen/{{uid}}/runs/{NONCE}"
    for key in ("alpha", "beta", "gamma", "absent"):
        assert paths[key].startswith(f"o6_listen/{{uid}}/runs/{NONCE}/docs/")
    assert paths["private"] == "o6_listen_private/{uid}"
    assert len(set(paths.values())) == len(paths)


def test_planned_counts_fit_the_frozen_budget():
    counts = count_operations()
    assert counts["writes"] <= BUDGET["maxWrites"]
    assert counts["deletes"] <= BUDGET["maxDeletes"]
    assert counts["reads"] <= BUDGET["maxReads"]
    assert counts["rawSnapshotAllowance"] <= BUDGET["maxSnapshots"]
    assert counts["rawSnapshotAllowance"] > counts["snapshots"]
    assert counts["cleanupReads"] <= BUDGET["cleanupReserveReads"]
    assert counts["cleanupDeletes"] <= BUDGET["cleanupReserveDeletes"]
    assert counts["listenerRegistrations"] >= len(cases.CASES)
    assert counts["listenerRegistrations"] <= BUDGET["maxListenerRegistrations"]


def test_estimated_cost_stays_far_below_one_dollar():
    campaign = compile_campaign(NONCE)
    assert campaign["estimatedCostUsd"] == estimate_cost_usd()
    assert campaign["estimatedCostUsd"] < 0.01
    assert campaign["budget"]["estimatedCostUsd"] < 1
    assert campaign["budget"]["hardCostCeilingUsd"] < 1


def test_budget_bounds_runs_concurrency_accounts_and_deadline():
    budget = compile_campaign(NONCE)["budget"]
    assert budget["maxRuns"] == 1
    assert budget["maxConcurrency"] == 1
    # Two principals: the case client's account and the second principal of
    # the cross-identity and revocation cases.
    assert budget["maxAccounts"] == 2
    assert budget["maxClients"] == 3
    assert 0 < budget["maxDurationSeconds"] <= 900


def test_sdk_pin_binds_resolved_versions_and_integrity_digests():
    campaign = compile_campaign(NONCE)
    assert campaign["sdk"] == dict(SDK_PIN)
    assert campaign["sdkIntegrity"] == dict(SDK_INTEGRITY)
    assert set(campaign["sdk"]) == set(campaign["sdkIntegrity"])
    for value in campaign["sdkIntegrity"].values():
        assert value.startswith("sha512-")
    assert campaign["sourceBinding"]["lockfileDigest"] == (
        "77320cd304149c5c3e99289b7548757e307c08373bf02a811a5ae8518775704c"
    )
    assert campaign["sourceBinding"]["evidence"] == "declaration-only"


def test_source_binding_tracks_the_case_catalog_digest():
    campaign = compile_campaign(NONCE)
    assert campaign["sourceBinding"]["catalogDigest"] == cases.catalog_digest()


def test_transport_records_that_the_raw_resume_token_is_not_visible():
    transport = compile_campaign(NONCE)["transport"]
    assert transport["kind"] == "grpc-listen"
    assert transport["resumeBoundary"] == "sdk-managed"
    assert transport["rawResumeTokenVisible"] is False


def test_owner_preconditions_are_stated_with_a_verifiable_check():
    campaign = compile_campaign(NONCE)
    ids = {item["id"] for item in campaign["ownerPreconditions"]}
    assert ids == {
        "rules-fragment",
        "throwaway-account",
        "single-field-index",
        "clean-prefix",
    }
    for item in campaign["ownerPreconditions"]:
        assert item["requirement"] and item["verifiable"]
    assert campaign["requiredRulesDigest"]
    assert "request.auth != null" in campaign["requiredRulesFragment"]


def test_permission_envelope_forbids_reuse_and_secret_capture():
    envelope = compile_campaign(NONCE)["permissionEnvelope"]
    assert envelope["inheritsFrom"] is None
    forbids = " ".join(envelope["forbids"])
    assert "reuse of any earlier compat-broad permission" in forbids
    assert "identity token" in forbids


def test_campaign_records_the_paths_it_cannot_observe():
    paths = {entry["path"] for entry in compile_campaign(NONCE)["unobservedPaths"]}
    assert {
        "browser-webchannel",
        "android-sdk",
        "apple-sdk",
        "tenant-isolation",
        "raw-resume-token",
    } == paths


@pytest.mark.parametrize(
    "mutate",
    [
        lambda c: c.update(productionExecuted=True),
        lambda c: c.update(status="MATCH"),
        lambda c: c["budget"].update(hardCostCeilingUsd=1000),
        lambda c: c["sdk"].update(firebase="13.0.0"),
        lambda c: c["sourceBinding"].update(lockfileDigest="0" * 64),
        lambda c: c["owner"].update(nonceDigest="0" * 64),
        lambda c: c.update(estimatedCostUsd=99.0),
        lambda c: c["caseIds"].append("FS-LISTEN-SDK-901"),
        lambda c: c.update(requiredRulesFragment="allow read, write: if true;"),
    ],
)
def test_validation_rejects_drift_from_the_frozen_manifest(mutate):
    campaign = compile_campaign(NONCE)
    mutate(campaign)
    assert not validate_campaign(campaign)


def test_validation_rejects_a_permission_smuggled_into_a_blocked_manifest():
    campaign = compile_campaign(NONCE)
    campaign["permission"] = PERMISSION
    assert not validate_campaign(campaign)


def test_validation_rejects_a_prepared_manifest_without_a_permission():
    campaign = compile_campaign(NONCE, permission=PERMISSION)
    campaign["permission"] = None
    assert not validate_campaign(campaign)


@pytest.mark.parametrize("value", [None, [], "campaign", {"schema": "other"}])
def test_validation_rejects_non_manifest_input(value):
    assert not validate_campaign(value)


def test_manifest_outputs_are_not_backed_by_mutable_module_constants():
    campaign = compile_campaign(NONCE)
    campaign["budget"]["maxRuns"] = 99
    campaign["sdk"]["firebase"] = "drift"
    fresh = compile_campaign(NONCE)
    assert fresh["budget"]["maxRuns"] == 1
    assert fresh["sdk"]["firebase"] == "12.18.0"
    assert validate_campaign(fresh)


def test_campaign_digest_is_stable_across_deep_copies():
    campaign = compile_campaign(NONCE, permission=PERMISSION)
    assert campaign_digest(campaign) == campaign_digest(copy.deepcopy(campaign))
