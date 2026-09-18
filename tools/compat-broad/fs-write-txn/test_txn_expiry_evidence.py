"""The published campaign evidence stays bound to the modules that produced it.

If this fails after editing a campaign module, regenerate the manifest with the
command named in the failure message. A stale published manifest is a broken
binding, not a cosmetic difference.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parents[1]))

import txn_expiry_cases as cases
import txn_expiry_comparison as comparison
import txn_expiry_plan as plan
import txn_expiry_shadow as shadow_module

ROOT = Path(__file__).resolve().parents[3]
RUNS = ROOT / "spec/compatibility/broad-runs"
MANIFEST = RUNS / "fs-transaction-expiry-retry-04-manifest.json"
SHADOW = RUNS / "fs-transaction-expiry-retry-04-local-shadow.json"

REGENERATE = (
    'regenerate with: uv run --python 3.12 python -c "import sys; '
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


def test_the_published_shadow_is_exactly_what_the_generator_emits():
    """A hand-augmented or hand-redacted evidence file must fail here."""
    value = shadow()
    generated = shadow_module.build_shadow_document(
        before=value["sourceDigestBefore"],
        after=value["sourceDigestAfter"],
        artifact_sha=value["artifactSha256"],
        binding={
            key: value["runtime"][key]
            for key in (
                "artifactSha256",
                "sourceCommit",
                "sourceRoot",
                "runtimeInputsDigest",
                "runtimeInputCount",
                "runtimeInputsClean",
            )
        },
        version=value["runtime"]["version"],
        nonce=value["nonce"],
        owner_id=value["ownerId"],
        elapsed=value["elapsedSeconds"],
        child=value["child"],
        receipt=value["receipt"],
        contract=value["selfContract"],
    )
    assert set(generated) == set(value), set(generated) ^ set(value)
    assert set(generated["runtime"]) == set(value["runtime"])
    assert generated == value, "the published record is not the generator's output"


def test_the_published_shadow_keeps_the_child_computed_artifact_proof():
    value = shadow()
    instance = value["receipt"]["instance"]
    assert instance["artifactSha256"] == value["artifactSha256"]
    assert value["runtime"]["childObservedArtifactSha256"] == value["artifactSha256"]
    assert instance["wrongTokenStatus"] == 403


def test_the_published_shadow_measured_its_waits():
    value = shadow()
    waited = [row["waited"] for row in value["receipt"]["rows"] if row["waited"]]
    assert waited
    for entry in waited:
        assert entry["measuredSeconds"] >= entry["requestedSeconds"]
    idle = {
        row["caseId"]: row["idleSeconds"]
        for row in value["receipt"]["rows"]
        if "idleSeconds" in row
    }
    for case in cases.CASES:
        if case["requiresElapsedSeconds"]:
            assert idle[case["id"]] >= case["requiresElapsedSeconds"]


def test_the_published_shadow_released_every_transaction_it_opened():
    value = shadow()
    assert value["receipt"]["openTransactions"] == []
    for entry in value["receipt"]["transactionReleases"]:
        assert entry["released"] is True


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


def test_local_shadow_artifact_is_bound_to_this_branch_source():
    value = shadow()
    runtime = value["runtime"]
    assert len(runtime["sourceCommit"]) == 40
    assert len(runtime["runtimeInputsDigest"]) == 64
    assert runtime["runtimeInputsClean"] is True
    assert runtime["artifactSha256"] == value["artifactSha256"]
    assert str(ROOT) == runtime["sourceRoot"], (
        "the rehearsal artifact must be built in this worktree, "
        "never taken from the shared checkout or a sibling worktree"
    )


def test_local_shadow_runtime_inputs_match_the_current_rust_source():
    """The artifact must still describe the Rust source in this worktree.

    The commit itself moves whenever tooling or documentation is committed, so
    the binding that matters is the hashed Rust input set, not the SHA.
    """
    import sys as _sys

    _sys.path.insert(0, str(ROOT / "tools/compat-inventory"))
    from broad_contract import digest
    from evidence_common import runtime_inputs

    value = shadow()
    assert value["runtime"]["runtimeInputsDigest"] == digest(runtime_inputs(ROOT)), (
        "regenerate the local shadow: the recorded artifact no longer describes "
        "the Rust source in this worktree"
    )


def _stable(value, volatile):
    """Strip the keys whose values legitimately differ between two runs."""
    if isinstance(value, dict):
        return {
            key: _stable(entry, volatile)
            for key, entry in value.items()
            if key not in volatile
        }
    if isinstance(value, list):
        return [_stable(entry, volatile) for entry in value]
    return value


def test_the_published_shadow_equals_a_fresh_run_modulo_volatile_keys():
    """Run the shadow yourself and point this at its shadow.json.

    Set FIREEMU_O3_FRESH_SHADOW to the path of a freshly produced shadow.json.
    Without it there is nothing to compare against, so the check is skipped
    rather than silently passing.
    """
    import os

    fresh_path = os.environ.get("FIREEMU_O3_FRESH_SHADOW")
    if not fresh_path:
        pytest.skip("set FIREEMU_O3_FRESH_SHADOW to a fresh shadow.json to compare")
    fresh = json.loads(Path(fresh_path).read_bytes())
    volatile = set(shadow_module.VOLATILE_KEYS)

    def prepared(value):
        scrubbed = shadow_module.scrub_run_identity(
            value,
            nonce=value["nonce"],
            owner_id=value["ownerId"],
            prefix=value["receipt"]["documentPrefix"],
        )
        return _stable(scrubbed, volatile)

    assert prepared(fresh) == prepared(shadow())


def test_the_published_shadow_was_produced_by_the_current_modules():
    value = shadow()
    assert value["sourceDigestBefore"] == plan.source_digest(), (
        "rerun the local shadow: it was produced by an older collector"
    )
    assert value["sourceDigestAfter"] == value["sourceDigestBefore"]
