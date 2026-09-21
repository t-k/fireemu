"""Bound collection: the collector records what the acquisition comparator
verifies, through an injected transport, with no socket and no credential."""

from __future__ import annotations

import copy
import json
import time

import pytest
from o5_user_token_campaign import admitted_manifest_digest, source_digests
from o5_user_token_case import compile_case, digest
from o5_user_token_collector import (
    COLLECTOR_CONTRACT,
    ENVIRONMENT_LOCAL,
    ENVIRONMENT_PRODUCTION,
    READBACK_PUBLISH_ECHO,
    READBACK_RELEASE_GET,
    ROLE_LOCAL_SHADOW,
    ROLE_PRODUCTION,
    collect,
)
from test_o5_user_token_collector import Transport

PROJECT = "fireemu-35fe6"
NONCE = "a" * 32
LOCAL_TENANT = "fireemu-00000000000000000001"
PRODUCTION_ENDPOINT = "firestore.googleapis.com:443"
LOCAL_ENDPOINT = "127.0.0.1:52879"


def plan_for(role: str) -> dict:
    tenant = LOCAL_TENANT if role == ROLE_LOCAL_SHADOW else "o5-user-token-tenant"
    return compile_case(PROJECT, "(default)", NONCE, tenant)


def principals_for(plan: dict, salt: str) -> dict:
    return {
        entry["ref"]: {
            "uidFingerprint": digest(["uid", plan["nonce"], salt, entry["ref"]])[:16],
            "provider": "anonymous" if entry["kind"] == "anonymous" else "email",
            "tenant": entry["tenant"],
            "claimsDigest": digest(entry["claims"]),
        }
        for entry in plan["ownedAccounts"]
    }


def acquisition_for(plan: dict, role: str) -> dict:
    """The launcher bindings a bound run of ``role`` carries."""
    manifest_digest = admitted_manifest_digest(PROJECT, "(default)", plan["nonce"])
    now = time.time()
    if role == ROLE_PRODUCTION:
        return {
            "environment": {"kind": ENVIRONMENT_PRODUCTION},
            "campaignManifestDigest": manifest_digest,
            "nonceReservation": {
                "reservationId": "reservation-1",
                "campaignId": plan["campaignId"],
                "nonceDigest": digest(plan["nonce"]),
            },
            "ownerPermission": {
                "kind": "owner-permission",
                "permissionDigest": "a" * 64,
            },
            "artifact": None,
            "principals": principals_for(plan, "production"),
            "window": {"startsAt": now - 60, "expiresAt": now + 3600},
        }
    return {
        "environment": {"kind": ENVIRONMENT_LOCAL},
        "campaignManifestDigest": manifest_digest,
        "nonceReservation": None,
        "ownerPermission": None,
        "artifact": {"artifactSha256": "b" * 64, "sourceCommit": "c" * 40},
        "principals": principals_for(plan, "local"),
        "window": None,
    }


def bound(
    role: str, transport: Transport | None = None, **kwargs
) -> tuple[dict, Transport]:
    plan = plan_for(role)
    endpoint = PRODUCTION_ENDPOINT if role == ROLE_PRODUCTION else LOCAL_ENDPOINT
    transport = transport or Transport(plan, endpoint=endpoint)
    bundle = collect(
        plan,
        transport,
        role=role,
        run_id=f"{role}-run",
        acquisition=acquisition_for(plan, role),
        **kwargs,
    )
    return bundle, transport


def test_a_bound_run_records_releases_wire_facts_and_observer_identity() -> None:
    bundle, transport = bound(ROLE_PRODUCTION)
    assert bundle["contract"] == COLLECTOR_CONTRACT
    assert bundle["recordingComplete"] is True
    assert bundle["abort"] is None
    releases = bundle["transport"]["rulesetReleases"]
    assert [release["label"] for release in releases] == ["A", "B"]
    assert [release["beforeIndex"] for release in releases] == [0, 27]
    for release in releases:
        assert release["readback"]["kind"] == READBACK_RELEASE_GET
        assert release["readback"]["digest"] == release["sourceDigest"]
        assert release["endpoint"] == PRODUCTION_ENDPOINT
        first_dependent = bundle["rows"][release["beforeIndex"]]
        assert release["activeFrom"] <= first_dependent["at"]
    assert bundle["budget"]["rulesetCeiling"] == 2
    assert bundle["budget"]["rulesetSpent"] == 2
    assert bundle["transport"]["endpoints"] == [PRODUCTION_ENDPOINT]
    assert bundle["transport"]["sequenceMonotonic"] is True
    assert bundle["transport"]["receipts"] == len(transport.requests)
    assert bundle["transport"]["firstSequence"] == 1
    assert bundle["transport"]["lastSequence"] == len(transport.requests)
    stamps = [row["at"] for row in bundle["rows"]]
    assert stamps == sorted(stamps)
    sequences = [row["wireSequence"] for row in bundle["rows"]]
    assert sequences == sorted(sequences)
    assert all(row["endpoint"] == PRODUCTION_ENDPOINT for row in bundle["rows"])
    for step in bundle["cleanup"]["documentSteps"] + bundle["cleanup"]["accountSteps"]:
        assert step["endpoint"] == PRODUCTION_ENDPOINT
        assert isinstance(step["wireSequence"], int)
    assert bundle["observer"]["sourceDigests"] == source_digests()
    assert bundle["observer"]["observerDigest"] == digest(source_digests())
    clock = bundle["transport"]["clock"]
    assert clock["started"] <= clock["observationFinished"] <= clock["finished"]
    wall = bundle["transport"]["wallClock"]
    assert wall["startedAt"] <= wall["finishedAt"]
    assert bundle["provenance"]["case"]["tenant"] == "o5-user-token-tenant"


def test_a_bound_run_is_admitted_by_the_acquisition_comparator() -> None:
    from o5_user_token_comparator_v2 import MATCH, compare

    production, _ = bound(ROLE_PRODUCTION)
    local, _ = bound(ROLE_LOCAL_SHADOW)
    result = compare(production, local, plan_for(ROLE_PRODUCTION))
    assert result["errors"] == []
    assert result["classification"] == MATCH
    assert len(result["rows"]) == 30


def test_the_ruleset_release_is_requested_and_journaled_before_the_first_row(
    tmp_path,
) -> None:
    path = tmp_path / "journal.jsonl"
    bundle, transport = bound(ROLE_LOCAL_SHADOW, journal_path=path)
    kinds = [request.get("phase") for request in transport.requests]
    assert kinds[0] == "ruleset"
    assert kinds[28] == "ruleset"
    assert transport.requests[0]["ruleset"] == "A"
    assert transport.requests[28]["ruleset"] == "B"
    assert transport.requests[0]["sourceDigest"] == digest(
        plan_for(ROLE_LOCAL_SHADOW)["rulesets"]["A"]["source"]
    )
    entries = [json.loads(line) for line in path.read_text().splitlines()]
    journaled = [entry["kind"] for entry in entries]
    assert journaled[:3] == ["run", "acquisition", "accounts"]
    assert journaled.index("ruleset-request") < journaled.index("request")
    assert journaled.index("ruleset-release") < journaled.index("request")
    acquisition = next(entry for entry in entries if entry["kind"] == "acquisition")
    assert acquisition["environment"] == ENVIRONMENT_LOCAL
    assert acquisition["observerDigest"] == bundle["observer"]["observerDigest"]
    assert bundle["transport"]["rulesetReleases"][0]["readback"]["kind"] == (
        READBACK_PUBLISH_ECHO
    )


def test_an_unbound_run_issues_no_release_and_records_no_acquisition() -> None:
    plan = plan_for(ROLE_PRODUCTION)
    transport = Transport(plan)
    bundle = collect(plan, transport, role=ROLE_PRODUCTION, run_id="unbound")
    assert all(request.get("phase") != "ruleset" for request in transport.requests)
    assert bundle["acquisition"] is None
    assert bundle["transport"]["rulesetReleases"] == []
    assert bundle["transport"]["endpoints"] == []
    assert bundle["budget"]["rulesetCeiling"] == 0
    assert bundle["rows"][0]["endpoint"] is None
    assert bundle["productionExecuted"] is False
    assert bundle["recordingComplete"] is True


def test_production_executed_is_derived_from_the_endpoints_reached() -> None:
    production, _ = bound(ROLE_PRODUCTION)
    assert production["productionExecuted"] is True
    assert production["productionReady"] is False
    local, _ = bound(ROLE_LOCAL_SHADOW)
    assert local["productionExecuted"] is False


def test_a_receipt_without_wire_facts_aborts_a_bound_run() -> None:
    plan = plan_for(ROLE_PRODUCTION)
    transport = Transport(plan, endpoint=PRODUCTION_ENDPOINT)

    def forgetful(request: dict) -> dict:
        receipt = transport(request)
        if request.get("phase") != "recovery" and request.get("index") == 2:
            del receipt["endpoint"]
            del receipt["wireSequence"]
        return receipt

    bundle = collect(
        plan,
        forgetful,
        role=ROLE_PRODUCTION,
        run_id="forgetful",
        acquisition=acquisition_for(plan, ROLE_PRODUCTION),
    )
    assert bundle["abort"] == "unbound-receipt"
    assert len(bundle["rows"]) == 3
    assert bundle["rows"][2]["observed"] is None
    assert bundle["recordingComplete"] is False
    assert bundle["cleanup"]["cleanupComplete"] is True


@pytest.mark.parametrize(
    "role,endpoint,failure",
    [
        (ROLE_PRODUCTION, "example.com:443", "endpoint-not-allowlisted"),
        (ROLE_PRODUCTION, LOCAL_ENDPOINT, "endpoint-outside-environment"),
        (ROLE_LOCAL_SHADOW, PRODUCTION_ENDPOINT, "endpoint-outside-environment"),
        (ROLE_LOCAL_SHADOW, "http://127.0.0.1:1", "invalid-endpoint"),
    ],
)
def test_an_endpoint_outside_the_environment_is_recorded_and_refused(
    role, endpoint, failure
) -> None:
    plan = plan_for(role)
    transport = Transport(plan, endpoint=endpoint, readback_kind=READBACK_RELEASE_GET)
    bundle = collect(
        plan,
        transport,
        role=role,
        run_id="foreign",
        acquisition=acquisition_for(plan, role),
    )
    # The first receipt is the Ruleset release, so the run stops there.
    assert bundle["abort"] == failure
    assert bundle["rows"] == []
    assert bundle["transport"]["rulesetReleases"] == []
    assert bundle["infrastructureFailures"] == [f"ruleset:A:{failure}"]
    assert bundle["productionExecuted"] is False
    assert bundle["recordingComplete"] is False
    # Recovery still runs; its receipts are refused for the same reason and
    # nothing is deleted on the strength of a foreign endpoint.
    assert bundle["cleanup"]["cleanupComplete"] is False
    assert not any(request.get("kind") == "delete" for request in transport.requests)


def test_a_wire_sequence_that_regresses_aborts_a_bound_run() -> None:
    plan = plan_for(ROLE_LOCAL_SHADOW)
    transport = Transport(plan, endpoint=LOCAL_ENDPOINT)

    def replaying(request: dict) -> dict:
        receipt = transport(request)
        if request.get("phase") != "recovery" and request.get("index") == 4:
            receipt["wireSequence"] = 1
        return receipt

    bundle = collect(
        plan,
        replaying,
        role=ROLE_LOCAL_SHADOW,
        run_id="replay",
        acquisition=acquisition_for(plan, ROLE_LOCAL_SHADOW),
    )
    assert bundle["abort"] == "wire-sequence-regressed"
    assert bundle["transport"]["sequenceMonotonic"] is False
    assert bundle["recordingComplete"] is False


@pytest.mark.parametrize(
    "mutation,failure",
    [
        ({"readbackDigest": "0" * 64}, "ruleset-readback-mismatch"),
        ({"readbackKind": "guessed"}, "ruleset-readback-unknown"),
        ({"releaseName": ""}, "ruleset-release-unnamed"),
        (
            {"complete": False, "failure": "publish-refused"},
            "incomplete-ruleset-receipt",
        ),
        ({"rules": "content"}, "unknown-receipt-key:rules"),
    ],
)
def test_a_release_whose_readback_is_not_the_plan_source_stops_the_run(
    mutation, failure
) -> None:
    plan = plan_for(ROLE_LOCAL_SHADOW)
    transport = Transport(plan, endpoint=LOCAL_ENDPOINT)

    def drifting(request: dict) -> dict:
        receipt = transport(request)
        if request.get("phase") == "ruleset" and request["ruleset"] == "B":
            receipt.update(mutation)
        return receipt

    bundle = collect(
        plan,
        drifting,
        role=ROLE_LOCAL_SHADOW,
        run_id="drift",
        acquisition=acquisition_for(plan, ROLE_LOCAL_SHADOW),
    )
    assert bundle["abort"] == failure
    assert len(bundle["rows"]) == 27
    assert [r["label"] for r in bundle["transport"]["rulesetReleases"]] == ["A"]
    assert bundle["infrastructureFailures"] == [f"ruleset:B:{failure}"]
    assert bundle["cleanup"]["cleanupComplete"] is True


def test_a_release_step_counts_against_its_own_ceiling_only() -> None:
    bundle, _ = bound(ROLE_LOCAL_SHADOW)
    assert bundle["budget"]["observationSpent"] == 30
    assert bundle["budget"]["rulesetSpent"] == 2
    assert bundle["budget"]["recoverySpent"] == len(
        bundle["cleanup"]["documentSteps"] + bundle["cleanup"]["accountSteps"]
    )


@pytest.mark.parametrize(
    "flag,marker",
    [
        ("leak", "credential-leak:idToken"),
        ("nested_leak", "credential-leak:refreshToken"),
        ("token_value", "credential-leak:token-shaped-value"),
    ],
)
def test_structural_redaction_still_aborts_a_bound_run(flag, marker) -> None:
    plan = plan_for(ROLE_PRODUCTION)
    transport = Transport(plan, endpoint=PRODUCTION_ENDPOINT, **{flag: True})
    bundle = collect(
        plan,
        transport,
        role=ROLE_PRODUCTION,
        run_id="leaky",
        acquisition=acquisition_for(plan, ROLE_PRODUCTION),
    )
    assert bundle["abort"] == marker
    assert len(bundle["rows"]) == 1
    assert bundle["rows"][0]["observed"] is None
    assert bundle["recordingComplete"] is False
    assert "secret" not in repr(bundle)


@pytest.mark.parametrize(
    "value", ["ya29.a0AfH6SMBexample", "AIzaSyDexampleexample", "1//0gexample-refresh"]
)
def test_a_google_credential_prefix_in_any_receipt_aborts_the_run(value) -> None:
    plan = plan_for(ROLE_PRODUCTION)
    transport = Transport(plan, endpoint=PRODUCTION_ENDPOINT)

    def leaking(request: dict) -> dict:
        receipt = transport(request)
        if request.get("phase") == "ruleset":
            receipt["releaseName"] = value
        return receipt

    bundle = collect(
        plan,
        leaking,
        role=ROLE_PRODUCTION,
        run_id="leaky-prefix",
        acquisition=acquisition_for(plan, ROLE_PRODUCTION),
    )
    assert bundle["abort"] == "credential-leak:token-shaped-value"
    assert bundle["rows"] == []
    assert value[4:] not in repr(bundle)


def test_the_collector_replaces_every_uid_its_readbacks_returned() -> None:
    """Redaction is the collector's, not the publishing runner's: a bundle
    carries principal labels wherever a readback uid appeared, in rows and
    in recovery steps, in bound and unbound runs alike."""
    plan = plan_for(ROLE_LOCAL_SHADOW)
    uids = {
        entry["ref"]: f"L7fNfbBctFzloK39kcvtQpS{i:05d}"
        for i, entry in enumerate(plan["ownedAccounts"])
    }
    transport = Transport(plan, endpoint=LOCAL_ENDPOINT)

    def with_uids(request: dict) -> dict:
        receipt = transport(request)
        if request.get("kind") == "account-readback" and receipt.get("uid"):
            receipt["uid"] = uids[request["accountRef"]]
        if request.get("phase") != "recovery" and request.get("index") == 0:
            receipt["fields"] = {"ownerUid": uids["owner-a"], "document": "owned-a"}
        return receipt

    for acquisition in (acquisition_for(plan, ROLE_LOCAL_SHADOW), None):
        bundle = collect(
            plan,
            with_uids,
            role=ROLE_LOCAL_SHADOW,
            run_id="redact",
            acquisition=acquisition,
        )
        assert (
            bundle["rows"][0]["observed"]["fields"]["ownerUid"] == "principal:owner-a"
        )
        readbacks = [
            step
            for step in bundle["cleanup"]["accountSteps"]
            if step["kind"] == "account-readback"
        ]
        assert {step["observed"]["uid"] for step in readbacks} == {
            f"principal:{step['accountRef']}" for step in readbacks
        }
        assert bundle["redactedPrincipals"] == sorted(
            f"principal:{ref}" for ref in uids
        )
        assert not any(uid in repr(bundle) for uid in uids.values())
        # The delete precondition still carried the real identifier to the transport.
        deletes = [r for r in transport.requests if r.get("kind") == "account-delete"]
        assert all(r["precondition"]["uid"] in uids.values() for r in deletes)
        transport.requests.clear()
        transport.present = {resource: True for resource in plan["ownedResources"]}
        transport.accounts = {entry["ref"]: True for entry in plan["ownedAccounts"]}


def test_a_token_shaped_value_in_a_release_receipt_aborts_before_any_row() -> None:
    plan = plan_for(ROLE_PRODUCTION)
    transport = Transport(plan, endpoint=PRODUCTION_ENDPOINT)

    def leaking(request: dict) -> dict:
        receipt = transport(request)
        if request.get("phase") == "ruleset":
            receipt["releaseName"] = "aaaaaa.bbbbbb.cccccc"
        return receipt

    bundle = collect(
        plan,
        leaking,
        role=ROLE_PRODUCTION,
        run_id="leaky-release",
        acquisition=acquisition_for(plan, ROLE_PRODUCTION),
    )
    assert bundle["abort"] == "credential-leak:token-shaped-value"
    assert bundle["rows"] == []
    assert "bbbbbb" not in repr(bundle)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda a: a.__setitem__("environment", {"kind": ENVIRONMENT_LOCAL}),
        lambda a: a.__setitem__("campaignManifestDigest", "short"),
        lambda a: a["nonceReservation"].__setitem__("nonceDigest", digest("b" * 32)),
        lambda a: a["nonceReservation"].__setitem__("campaignId", "OTHER"),
        lambda a: a.__setitem__(
            "ownerPermission", {"kind": "x", "permissionDigest": "y"}
        ),
        lambda a: (
            a.__setitem__(
                "artifact", {"artifactSha256": "b" * 64, "sourceCommit": "c" * 40}
            )
            or a.__setitem__("principals", {"stranger": a["principals"]["owner-a"]})
        ),
        lambda a: a.__setitem__("window", {"startsAt": 5.0, "expiresAt": 1.0}),
        lambda a: a.__setitem__("idToken", "value"),
        lambda a: a.__setitem__("extra", None),
        lambda a: a["principals"]["owner-a"].__setitem__(
            "uidFingerprint", "aaaaaa.bbbbbb.cccccc"
        ),
    ],
)
def test_malformed_or_contradicting_bindings_are_refused_before_any_request(
    mutate,
) -> None:
    plan = plan_for(ROLE_PRODUCTION)
    acquisition = acquisition_for(plan, ROLE_PRODUCTION)
    mutate(acquisition)
    transport = Transport(plan, endpoint=PRODUCTION_ENDPOINT)
    with pytest.raises((TypeError, ValueError)):
        collect(
            plan,
            transport,
            role=ROLE_PRODUCTION,
            run_id="refused",
            acquisition=acquisition,
        )
    assert transport.requests == []


def test_the_recorded_bindings_are_a_copy_not_the_launcher_object() -> None:
    plan = plan_for(ROLE_LOCAL_SHADOW)
    acquisition = acquisition_for(plan, ROLE_LOCAL_SHADOW)
    original = copy.deepcopy(acquisition)
    bundle = collect(
        plan,
        Transport(plan, endpoint=LOCAL_ENDPOINT),
        role=ROLE_LOCAL_SHADOW,
        run_id="copy",
        acquisition=acquisition,
    )
    assert acquisition == original
    recorded = bundle["acquisition"]
    assert recorded["environment"] == original["environment"]
    assert recorded["artifact"] == original["artifact"]
    assert recorded["observerDigest"] == bundle["observer"]["observerDigest"]
    assert recorded["endpoint"] == [LOCAL_ENDPOINT]
    assert recorded["wireCounts"]["receipts"] == bundle["transport"]["receipts"]
    recorded["principals"]["owner-a"]["uidFingerprint"] = "changed"
    assert acquisition == original


def test_a_broken_wall_clock_is_recorded_as_absent_not_invented() -> None:
    def broken() -> float:
        raise OSError("no wall clock")

    bundle, _ = bound(ROLE_LOCAL_SHADOW, wall_clock=broken)
    assert bundle["transport"]["wallClock"] == {"startedAt": None, "finishedAt": None}
    assert bundle["recordingComplete"] is True
