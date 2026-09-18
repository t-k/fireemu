import pytest
from o6_listen_resume import cases
from o6_listen_resume.cases import (
    CASES,
    COMPARISON_AGGREGATE,
    COMPARISON_ORDERED,
    ROLE_OBSERVATION,
    case_ids,
    catalog,
    catalog_digest,
    get_case,
)


def test_case_identifiers_are_unique_and_namespaced():
    ids = case_ids()
    assert len(ids) == len(set(ids))
    assert all(identifier.startswith("FS-LISTEN-SDK-") for identifier in ids)


def test_every_observation_case_has_a_control_or_negative_counterpart():
    observations = {c["caseId"] for c in CASES if c["role"] == ROLE_OBSERVATION}
    covered = {c["controlFor"] for c in CASES if c["role"] != ROLE_OBSERVATION}
    assert observations
    assert observations == covered


def test_control_cases_reference_an_existing_observation_case():
    for case in CASES:
        if case["controlFor"] is not None:
            assert get_case(case["controlFor"])["role"] == ROLE_OBSERVATION


def test_declared_dimensions_cover_the_blocking_condition_topics():
    dimensions = {case["dimension"] for case in CASES}
    assert dimensions == {
        "document-event-order",
        "pending-writes",
        "query-change-order",
        "resume-after-break",
        "unsubscribe",
        "auth-switch",
    }


def test_every_case_declares_expected_local_events_and_discriminators():
    for case in CASES:
        assert case["expectedLocal"], case["caseId"]
        assert case["discriminators"], case["caseId"]
        assert case["comparison"] in {COMPARISON_ORDERED, COMPARISON_AGGREGATE}


def test_expected_events_only_name_declared_listeners():
    for case in CASES:
        declared = {listener["name"] for listener in case["listeners"]}
        # A recovery listener is registered by a step, not by the static list.
        declared |= {
            step["listener"] for step in case["steps"] if step["kind"] == "listen"
        }
        for event in case["expectedLocal"]:
            assert event["listener"] in declared, case["caseId"]


def test_expected_events_only_name_declared_documents():
    for case in CASES:
        declared = set(case["documents"])
        for event in case["expectedLocal"]:
            assert set(event["docs"]) <= declared, case["caseId"]
            for change in event["changes"]:
                assert change["doc"] in declared, case["caseId"]


def test_steps_only_touch_declared_documents():
    for case in CASES:
        declared = set(case["documents"])
        for step in case["steps"]:
            if "doc" in step:
                assert step["doc"] in declared, case["caseId"]


def test_resume_case_requires_metadata_changes_and_break_and_resume_steps():
    case = get_case("FS-LISTEN-SDK-104")
    assert case["listeners"][0]["includeMetadataChanges"] is True
    kinds = [step["kind"] for step in case["steps"]]
    assert kinds.count("break") == 1
    assert kinds.count("resume") == 1
    assert kinds.index("break") < kinds.index("resume")
    assert "no-duplicate-added-for-unchanged-document" in case["invariants"]


def test_resume_control_has_no_break_step():
    control = get_case("FS-LISTEN-SDK-104C")
    assert all(step["kind"] not in {"break", "resume"} for step in control["steps"])
    assert control["expectedLocal"] == get_case("FS-LISTEN-SDK-104")["expectedLocal"]


def test_unsubscribe_case_declares_a_quiet_window_and_a_witness_listener():
    case = get_case("FS-LISTEN-SDK-105")
    assert {listener["name"] for listener in case["listeners"]} == {
        "primary",
        "witness",
    }
    quiet = [step for step in case["steps"] if step["kind"] == "quiet"]
    assert quiet and quiet[0]["listener"] == "primary" and quiet[0]["seconds"] > 0
    assert "no-event-after-unsubscribe" in case["invariants"]
    assert not any(
        event["listener"] == "primary" and event["snapshotKind"] == "delta"
        for event in case["expectedLocal"]
    )


def test_auth_switch_case_expects_a_permission_denied_terminal_error():
    case = get_case("FS-LISTEN-SDK-106")
    assert case["requiresRules"] is True
    errors = [
        event for event in case["expectedLocal"] if event["snapshotKind"] == "error"
    ]
    assert [event["error"] for event in errors] == ["permission-denied"]
    kinds = [step["kind"] for step in case["steps"]]
    assert kinds.count("signOut") == 1
    assert kinds.index("signOut") < kinds.index("awaitError")


def test_negative_auth_case_expects_no_snapshot_before_the_error():
    case = get_case("FS-LISTEN-SDK-106N")
    assert case["role"] == "negative"
    assert [event["snapshotKind"] for event in case["expectedLocal"]] == ["error"]
    assert "zero-snapshots-before-error" in case["invariants"]


def test_required_rules_fragment_denies_unauthenticated_access():
    fragment = cases.REQUIRED_RULES_FRAGMENT
    assert "request.auth != null" in fragment
    assert "request.auth.uid == uid" in fragment
    assert "if true" not in fragment
    assert "{document=**}" not in fragment


def test_catalog_digest_is_stable_and_binds_the_rules_fragment():
    first = catalog_digest()
    assert first == catalog_digest()
    assert catalog()["requiredRulesDigest"]
    assert len(first) == 64


def test_catalog_is_a_copy_that_cannot_mutate_the_frozen_cases():
    snapshot = catalog()
    snapshot["cases"][0]["caseId"] = "drift"
    assert catalog()["cases"][0]["caseId"] == "FS-LISTEN-SDK-101"


def test_unobserved_paths_name_browser_and_both_declared_mobile_platforms():
    paths = {entry["path"] for entry in catalog()["unobservedPaths"]}
    assert {
        "browser-webchannel",
        "android-sdk",
        "apple-sdk",
        "raw-resume-token",
    } == paths
    for entry in catalog()["unobservedPaths"]:
        assert entry["reason"] and entry["plan"]


@pytest.mark.parametrize("case_id", ["FS-LISTEN-SDK-999", "", "nope"])
def test_unknown_case_identifier_is_rejected(case_id):
    with pytest.raises(KeyError):
        get_case(case_id)


def test_catalog_nested_structures_cannot_be_mutated_through_a_snapshot():
    snapshot = catalog()
    snapshot["cases"][0]["steps"].append({"kind": "write", "doc": "rogue"})
    snapshot["cases"][0]["expectedLocal"][0]["error"] = "drift"
    assert catalog_digest() == catalog_digest()
    assert all(
        step["kind"] != "write" or step["doc"] != "rogue"
        for step in catalog()["cases"][0]["steps"]
    )


def test_get_case_returns_a_copy():
    case = get_case("FS-LISTEN-SDK-101")
    case["steps"].clear()
    assert get_case("FS-LISTEN-SDK-101")["steps"]
