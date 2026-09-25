"""Bind the checked-in local shadow evidence to the current working tree.

The receipt under `spec/compatibility/` was produced by running the collector
against an owned local `fireemu` instance. These checks fail if the sources it
names have changed, if the catalog has drifted, or if any case stopped agreeing
with its expected local result. They say nothing about production.
"""

import hashlib
import json
from pathlib import Path

from o6_listen_resume import cases
from o6_listen_resume.observation import compute_source_digests

REPO_ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = REPO_ROOT / "spec/compatibility/fs-listen-sdk-local-shadow.json"


def _receipt():
    return json.loads(EVIDENCE.read_text(encoding="utf-8"))


def test_the_local_shadow_ran_to_completion_with_proven_cleanup():
    receipt = _receipt()
    assert receipt["complete"] is True
    assert receipt["productionExecuted"] is False
    assert receipt["environment"]["kind"] == "local-fireemu"
    assert receipt["cleanup"]["complete"] is True
    assert receipt["budget"]["exhausted"] is False
    assert receipt["cleanupBudget"]["exhausted"] is False


def test_every_cleanup_row_proves_absence_or_never_created_the_document():
    outcomes = {row["name"]: row["outcome"] for row in _receipt()["cleanup"]["rows"]}
    assert set(outcomes) == {
        "alpha",
        "beta",
        "gamma",
        "absent",
        "private",
        "privateB",
    }
    assert set(outcomes.values()) <= {
        "deleted-and-absent",
        "not-created",
        "already-deleted-earlier",
    }


def test_the_evidence_names_the_sources_that_produced_it():
    receipt = _receipt()
    current = compute_source_digests(REPO_ROOT)
    for relative, value in receipt["sourceDigests"].items():
        assert value == current[relative], relative
    assert receipt["catalogDigest"] == cases.catalog_digest()
    assert receipt["environment"]["sourceCommit"]


def test_the_evidence_carries_no_secret_material():
    raw = EVIDENCE.read_text(encoding="utf-8")
    for marker in ("password", "idToken", "refreshToken", "Bearer "):
        assert marker not in raw


def test_every_case_agreed_with_its_expected_local_result():
    receipt = _receipt()
    rows = {row["caseId"]: row for row in receipt["cases"]}
    assert set(rows) == set(cases.case_ids())
    for case in cases.CASES:
        row = rows[case["caseId"]]
        assert row["complete"] is True, case["caseId"]
        assert row["listenersClosed"] is True, case["caseId"]
        assert row["invariantViolations"] == [], case["caseId"]
        fields = case["comparedFields"]
        observed = [
            {key: event.get(key) for key in fields} for event in row["observed"]
        ]
        expected = [
            {key: event.get(key) for key in fields} for event in case["expectedLocal"]
        ]
        assert observed == expected, case["caseId"]


def test_every_listener_case_actually_delivered_or_declared_silence():
    for row in _receipt()["cases"]:
        case = cases.get_case(row["caseId"])
        if case["expectedLocal"]:
            assert row["observed"], row["caseId"]
        else:
            assert case["invariants"], row["caseId"]


def test_the_shadow_recorded_an_ordered_transport_timeline():
    timeline = _receipt()["transportTimeline"]
    assert timeline
    stamps = [entry["atMs"] for entry in timeline]
    assert stamps == sorted(stamps)
    kinds = {entry["kind"] for entry in timeline}
    assert {"connect", "disconnect", "reconnect"} <= kinds
    for entry in timeline:
        assert entry["derivedFrom"]
        assert entry["caseId"]


def test_the_resume_case_is_the_one_that_broke_and_recovered():
    timeline = _receipt()["transportTimeline"]
    breaking = {
        entry["caseId"]
        for entry in timeline
        if entry["kind"] in {"break-requested", "resume-requested"}
    }
    assert breaking == {"FS-LISTEN-SDK-104"}


def test_the_revocation_case_is_the_one_that_revoked_and_both_accounts_were_removed():
    receipt = _receipt()
    revoking = {
        entry["caseId"]
        for entry in receipt["transportTimeline"]
        if entry["kind"] == "revoke-requested"
    }
    assert revoking == {"FS-LISTEN-SDK-109"}
    cleanup = receipt["lifecycle"]["accountCleanup"]
    assert cleanup["complete"] is True
    assert set(cleanup["accounts"]) == {"primary", "secondary"}
    assert all(
        row["outcome"] == "deleted-and-absent" for row in cleanup["accounts"].values()
    )


def test_the_shadow_names_the_fireemu_binary_it_actually_ran():
    environment = _receipt()["environment"]
    assert environment["fireemuBinary"] == "target/debug/fireemu"
    assert len(environment["fireemuBinaryDigest"]) == 64
    assert environment["fireemuBinaryDigest"] != "unreadable"
    assert len(environment["fireemuSourceCommit"]) == 40
    # The runtime was built from the same tree that produced the collector.
    assert environment["fireemuSourceCommit"] == environment["sourceCommit"]


def test_the_shadow_records_no_absolute_personal_path():
    raw = EVIDENCE.read_text(encoding="utf-8")
    assert "/Users/" not in raw
    assert "/home/" not in raw


def test_the_local_ruleset_contains_the_required_fragment_verbatim():
    rules = (
        REPO_ROOT / "tools/compat-broad/fs-listen-resume/fs-listen-sdk.rules"
    ).read_text(encoding="utf-8")
    for line in cases.REQUIRED_RULES_FRAGMENT.strip().splitlines():
        assert line.strip() in rules, line


def test_the_shadow_names_the_ruleset_it_ran_under():
    environment = _receipt()["environment"]
    assert (
        environment["rulesPath"]
        == "tools/compat-broad/fs-listen-resume/fs-listen-sdk.rules"
    )
    recomputed = hashlib.sha256(
        (REPO_ROOT / environment["rulesPath"]).read_bytes()
    ).hexdigest()
    assert environment["rulesDigest"] == recomputed


def test_cleanup_rows_publish_no_run_nonce_and_no_account_identifier():
    for row in _receipt()["cleanup"]["rows"]:
        assert "path" not in row
        assert len(row["pathDigest"]) == 64


def test_the_receipt_keeps_every_cleanup_pass_not_only_the_final_one():
    receipt = _receipt()
    passes = receipt["cleanupPasses"]
    assert [item["pass"] for item in passes] == [*cases.case_ids(), "final"]
    # Every pass, including the one after the case that ends signed out, must
    # have been able to read and delete under the campaign Rules.
    assert all(item["complete"] is True for item in passes), [
        item["pass"] for item in passes if item["complete"] is not True
    ]
    # The final pass alone understates the run, so the receipt carries the total.
    assert receipt["totalDeleted"] == sum(item["deleted"] for item in passes)
    assert receipt["totalDeleted"] > receipt["cleanup"]["deleted"]


def test_the_final_pass_does_not_call_an_earlier_deletion_never_created():
    final = next(
        item for item in _receipt()["cleanupPasses"] if item["pass"] == "final"
    )
    outcomes = {row["outcome"] for row in final["rows"]}
    assert "already-deleted-earlier" in outcomes
    assert outcomes <= {"already-deleted-earlier", "not-created", "deleted-and-absent"}
