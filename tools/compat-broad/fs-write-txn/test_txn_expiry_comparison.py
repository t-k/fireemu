"""The comparator separates infrastructure failure from semantic disagreement."""

import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parents[1]))

import txn_expiry_cases as cases
import txn_expiry_collector as collector
import txn_expiry_comparison as comparison
import txn_expiry_plan as plan_module


def receipt(target, *, project, nonce, timing):
    prefix = plan_module.document_prefix(nonce)
    rows = []
    elapsed = 0
    for case in cases.CASES:
        required = case["requiresElapsedSeconds"]
        waited = None
        if required > elapsed:
            waited = {"mode": timing, "seconds": required - elapsed}
            elapsed = required
        expected = case["expectedLocal"]
        message = expected["message"]
        if case["id"] == "idle-expiry/commit-after-idle":
            message = f'Document "{project}/{prefix}/locked-a" is gone. {message}'
        rows.append(
            {
                "slot": case["id"],
                "phase": case["group"],
                "caseId": case["id"],
                "rpc": expected["rpc"],
                "role": case["resources"][0] if case["resources"] else None,
                "observed": {
                    "code": expected["code"],
                    "status": expected["status"],
                    "message": message,
                },
                "complete": True,
                "waited": waited,
                "expectedLocal": dict(expected),
            }
        )
    return {
        "kind": collector.CONTRACT,
        "campaign": cases.CAMPAIGN,
        "casesDigest": cases.cases_digest(),
        "sourceDigest": plan_module.source_digest(),
        "target": target,
        "timing": timing,
        "projectId": project,
        "database": "(default)",
        "documentPrefix": prefix,
        "nonce": nonce,
        "rows": rows,
        "cleanup": [],
        "unrecovered": [],
        "missingCases": [],
        "failure": None,
        "complete": True,
    }


def production():
    return receipt(
        "production",
        project="fireemu-35fe6",
        nonce="o3expiry-prod-000000000001",
        timing=collector.WALL_CLOCK,
    )


def local(timing=collector.CONTROL_CLOCK):
    return receipt(
        "local",
        project="fireemu-test",
        nonce="o3expiry-local-00000000001",
        timing=timing,
    )


def test_agreeing_runs_across_projects_are_expected_nondeterminism():
    result = comparison.compare(production(), local())
    assert result["classification"] == comparison.EXPECTED_NONDETERMINISM
    assert result["acquisitionValidated"] is False
    assert result["promotionReady"] is False


def test_identical_identities_and_semantics_are_a_match():
    value = production()
    other = copy.deepcopy(value)
    other["target"] = "local"
    other["timing"] = collector.WALL_CLOCK
    assert comparison.compare(value, other)["classification"] == comparison.MATCH


def test_a_different_code_is_a_semantic_mismatch():
    value = local()
    value["rows"][1]["observed"]["code"] = 0
    value["rows"][1]["observed"]["status"] = "OK"
    result = comparison.compare(production(), value)
    assert result["classification"] == comparison.SEMANTIC_MISMATCH
    assert "idle-expiry/commit-after-idle" in result["differences"]


def test_a_different_diagnostic_is_a_semantic_mismatch():
    value = local()
    for row in value["rows"]:
        if row["caseId"] == "retry-token/retry-with-committed-previous":
            row["observed"]["message"] = "Invalid retry transaction id."
    result = comparison.compare(production(), value)
    assert result["classification"] == comparison.SEMANTIC_MISMATCH


def test_request_bound_resource_identities_do_not_create_a_mismatch():
    result = comparison.compare(production(), local())
    assert result["classification"] != comparison.SEMANTIC_MISMATCH


def test_an_incomplete_receipt_is_indeterminate_not_a_mismatch():
    value = local()
    value["failure"] = "deadline-reached"
    result = comparison.compare(production(), value)
    assert result["classification"] == comparison.INDETERMINATE
    assert any(r["code"] == "collection-failed" for r in result["reasons"])


def test_unrecovered_resources_are_indeterminate():
    value = production()
    value["unrecovered"] = ["locked-a"]
    result = comparison.compare(value, local())
    assert result["classification"] == comparison.INDETERMINATE
    assert any(r["code"] == "unrecovered-resources" for r in result["reasons"])


def test_a_production_receipt_with_simulated_time_is_refused():
    value = production()
    value["timing"] = collector.CONTROL_CLOCK
    result = comparison.compare(value, local())
    assert result["classification"] == comparison.INDETERMINATE
    assert any(r["code"] == "production-timing-simulated" for r in result["reasons"])


def test_a_receipt_that_did_not_reach_the_idle_limit_is_refused():
    value = production()
    for row in value["rows"]:
        if row["waited"]:
            row["waited"]["seconds"] = 1
    result = comparison.compare(value, local())
    assert result["classification"] == comparison.INDETERMINATE
    assert any(r["code"] == "elapsed-time-not-reached" for r in result["reasons"])


def test_a_receipt_carrying_credential_material_is_refused():
    value = local()
    value["note"] = "Authorization: Bearer ya29.something"
    result = comparison.compare(production(), value)
    assert result["classification"] == comparison.INDETERMINATE
    assert any(r["code"] == "credential-material-in-receipt" for r in result["reasons"])


def test_a_stale_case_table_binding_is_refused():
    value = local()
    value["casesDigest"] = "0" * 64
    result = comparison.compare(production(), value)
    assert result["classification"] == comparison.INDETERMINATE
    assert any(r["code"] == "cases-digest" for r in result["reasons"])


def test_the_timing_mechanism_difference_is_recorded_not_hidden():
    result = comparison.compare(production(), local())
    assert result["timing"]["mechanismDiffers"] is True
    assert result["timing"]["note"]


def test_local_self_contract_accepts_the_frozen_expected_results():
    result = comparison.local_self_contract(local())
    assert result["classification"] == comparison.MATCH
    assert result["disagreements"] == {}
    assert sorted(result["casesChecked"]) == sorted(c["id"] for c in cases.CASES)


def test_local_self_contract_reports_a_disagreeing_case():
    value = local()
    value["rows"][1]["observed"]["code"] = 0
    result = comparison.local_self_contract(value)
    assert result["classification"] == comparison.SEMANTIC_MISMATCH
    assert "idle-expiry/commit-after-idle" in result["disagreements"]
