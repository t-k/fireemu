"""The published campaign evidence stays bound to the modules that produced it.

If this fails after editing a campaign module, regenerate the manifest with the
command named in the failure message. A stale published manifest is a broken
binding, not a cosmetic difference.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parents[1]))

import txn_expiry_cases as cases
import txn_expiry_comparison as comparison
import txn_expiry_plan as plan

ROOT = Path(__file__).resolve().parents[3]
RUNS = ROOT / "spec/compatibility/broad-runs"
MANIFEST = RUNS / "fs-transaction-expiry-retry-04-manifest.json"
SHADOW = RUNS / "fs-transaction-expiry-retry-04-local-shadow.json"

REGENERATE = (
    "regenerate with: uv run --python 3.12 python -c \"import sys; "
    "sys.path[:0]=['tools/compat-broad/fs-write-txn','tools/compat-broad']; "
    "import json,txn_expiry_plan as p; "
    "print(json.dumps(p.proposal('o3expiry-reference-000000001','0'*32)))\""
)


def manifest():
    return json.loads(MANIFEST.read_bytes())


def shadow():
    return json.loads(SHADOW.read_bytes())


def test_published_manifest_is_blocked_owner_and_carries_no_permission():
    value = manifest()
    assert value["status"] == "BLOCKED_OWNER"
    assert value["permissionGranted"] is False
    assert "permission" not in value
    assert value["ownerFieldsRequired"]


def test_published_manifest_binds_the_current_case_table():
    value = manifest()
    assert value["manifest"]["casesDigest"] == cases.cases_digest(), REGENERATE


def test_published_manifest_binds_the_current_module_sources():
    value = manifest()
    assert value["manifest"]["sourceDigest"] == plan.source_digest(), REGENERATE


def test_published_manifest_keeps_the_budget_far_below_one_dollar():
    budget = manifest()["manifest"]["plan"]["budget"]
    assert budget["costMicrousd"] < 100_000
    assert budget["accounts"] == 0
    assert budget["concurrency"] == 1


def test_published_manifest_holds_one_exclusive_lock_only():
    locks = manifest()["manifest"]["resourceLocks"]
    assert [lock["mode"] for lock in locks].count("EXCLUSIVE") == 1


def test_published_manifest_records_what_is_not_prepared():
    entries = manifest()["manifest"]["notPrepared"]
    assert len(entries) == len(cases.NOT_PREPARED)


def test_published_manifest_carries_no_credential_material():
    rendered = MANIFEST.read_text()
    for marker in comparison.CREDENTIAL_MARKERS:
        assert marker not in rendered


def test_local_shadow_result_is_complete_and_recovered():
    value = shadow()
    assert value["complete"] is True
    assert value["productionExecuted"] is False
    assert value["acquisitionValidated"] is False
    assert value["promotionReady"] is False
    assert value["receipt"]["unrecovered"] == []
    assert value["receipt"]["missingCases"] == []
    assert value["receipt"]["failure"] is None


def test_local_shadow_observed_every_case_against_the_real_runtime():
    value = shadow()
    observed = {row["caseId"] for row in value["receipt"]["rows"] if row["caseId"]}
    assert observed == {case["id"] for case in cases.CASES}
    assert value["selfContract"]["classification"] == comparison.MATCH


def test_local_shadow_records_that_its_elapsed_time_was_simulated():
    value = shadow()
    assert value["receipt"]["timing"] == "control-clock"
    waited = [row["waited"] for row in value["receipt"]["rows"] if row["waited"]]
    assert waited
    assert all(entry["mode"] == "control-clock" for entry in waited)


def test_local_shadow_stayed_inside_the_planned_request_budget():
    value = shadow()
    budget = manifest()["manifest"]["plan"]["budget"]
    assert value["receipt"]["requestCount"] <= budget["dataRequests"]


def test_a_local_shadow_receipt_cannot_stand_in_for_production():
    value = shadow()
    result = comparison.compare(value["receipt"], value["receipt"])
    assert result["classification"] == comparison.INDETERMINATE
    assert any(r["code"] == "wrong-target" for r in result["reasons"])
