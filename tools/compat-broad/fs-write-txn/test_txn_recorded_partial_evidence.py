"""Recorded production parity stays distinct from the frozen parent closure."""

import json
import re
import sys
from pathlib import Path

sys.path[:0] = [str(Path(__file__).parent), str(Path(__file__).parents[1]), str(Path(__file__).parents[2] / "compat-inventory")]
import txn_expiry_cases as cases
import txn_expiry_comparison as comparison
import txn_expiry_plan as plan
from broad_contract import digest
from evidence_common import runtime_inputs, runtime_inputs_at_commit

ROOT = Path(__file__).resolve().parents[3]
PATH = ROOT / "spec/compatibility/broad-runs/fs-transaction-expiry-retry-04-recorded-comparison-v1.json"
CLOSURE = ROOT / "spec/compatibility/closure/FS-TRANSACTION.json"


def evidence():
    return json.loads(PATH.read_bytes())


def test_recorded_case_projection_and_post_state_are_bound_to_both_recordings():
    value = evidence()
    assert value["casesDigest"] == cases.cases_digest()
    assert value["sourceDigest"] == plan.source_digest()
    ids = [row["caseId"] for row in value["cases"]]
    assert len(ids) == len(set(ids)) == value["caseCount"] == 13
    assert set(ids) == {row["id"] for row in cases.CASES}
    projection = {row["caseId"]: {key: entry for key, entry in row.items() if key != "caseId"} for row in value["cases"]}
    post_states = value["postStates"]
    declared_post_states = {row["id"] for row in cases.CASES if row.get("postState")}
    assert declared_post_states <= set(post_states) <= set(ids)
    for row in cases.CASES:
        if row.get("postState"):
            observed = post_states[row["id"]]
            assert observed["document"]["exists"] is True
            assert observed["document"]["fields"]["state"]["stringValue"] == row["postState"][observed["role"]]
    assert len(value["recordings"]) == 2
    assert len({row["reference"]["sha256"] for row in value["recordings"]}) == 2
    for row in value["recordings"]:
        assert row["complete"] is True and row["timing"] == "wall-clock"
        assert row["target"] == "production" and row["pythonVersion"] == "3.12.13"
        assert row["projectionDigest"] == digest(projection)
        assert row["postStateDigest"] == digest(post_states)
        assert row["dataRequests"] == 67 and row["sandboxRequests"] == 75
        assert row["ownedDocumentsAbsent"] == 5
        assert row["openTransactions"] == row["unconfirmedTransactionStarts"] == row["unrecovered"] == 0


def test_current_recorded_artifact_has_a_successful_build_and_current_rust_inputs():
    value = evidence()
    artifact = value["artifact"]
    assert re.fullmatch(r"[a-f0-9]{40}", artifact["sourceCommit"])
    assert artifact["sourceUnchanged"] is True and artifact["exitCode"] == 0
    assert artifact["buildCommand"] == ["cargo", "build", "--locked", "-p", "fireemu", "--bin", "fireemu"]
    assert re.fullmatch(r"[a-f0-9]{64}", artifact["artifactSha256"])
    current = runtime_inputs(ROOT)
    assert current == runtime_inputs_at_commit(artifact["sourceCommit"], ROOT)
    assert artifact["runtimeInputsDigest"] == digest(current)
    assert artifact["runtimeInputCount"] == len(current)


def test_both_profiles_match_every_case_in_both_production_recordings():
    value = evidence()
    assert set(value["profiles"]) == {"strict", "emulator"}
    ids = sorted(row["caseId"] for row in value["cases"])
    for profile in value["profiles"].values():
        assert profile["acquisitionComplete"] is True
        assert profile["artifactSha256"] == value["artifact"]["artifactSha256"]
        assert profile["sourceCommit"] == value["artifact"]["sourceCommit"]
        assert profile["runtimeInputsDigest"] == value["artifact"]["runtimeInputsDigest"]
        assert profile["runtimeInputsClean"] is True and profile["productionRequests"] == 0
        assert profile["ownedDocumentsAbsent"] == 5
        assert profile["openTransactions"] == profile["unconfirmedTransactionStarts"] == 0
        assert profile["child"] == {"exitCode": 0, "signal": None, "stopped": True}
        assert profile["pythonRuntime"]["pythonVersion"] == "3.12.13"
        assert profile["historicalLocalSelfContract"] == comparison.SEMANTIC_MISMATCH
        assert len(profile["results"]) == 2
        for result in profile["results"]:
            assert result["classification"] == comparison.EXPECTED_NONDETERMINISM
            assert not result.get("differences") and result["casesCompared"] == ids
            assert result["acquisitionValidated"] is False and result["promotionReady"] is False
            binding = result["bindings"]
            assert binding["productionSourceDigest"] == binding["localSourceDigest"] == value["sourceDigest"]
            assert binding["productionProjectionDigest"] == binding["localProjectionDigest"] == value["recordings"][0]["projectionDigest"]
            assert binding["productionPostStateDigest"] == binding["localPostStateDigest"] == value["recordings"][0]["postStateDigest"]
            assert result["timing"]["mechanismDiffers"] is True


def test_repaired_cases_preserve_the_committed_rollback_refusal():
    rows = {row["caseId"]: row for row in evidence()["cases"]}
    for name in ("idle-expiry/rollback-after-idle", "finished-token/rollback-after-rollback", "retry-token/retry-with-committed-previous"):
        assert rows[name]["code"] == 0 and rows[name]["status"] == "OK"
    assert rows["retry-token/retry-with-read-only-previous"]["code"] == 3
    assert rows["retry-token/retry-with-read-only-previous"]["message"] == "Cannot retry a read-only transaction"
    assert rows["finished-token/rollback-after-commit"]["code"] == 10
    assert rows["finished-token/rollback-after-commit"]["message"] == "The referenced transaction has expired or is no longer valid."
    changed = {"idle-expiry/rollback-after-idle", "finished-token/rollback-after-rollback", "retry-token/retry-with-committed-previous", "retry-token/retry-with-read-only-previous"}
    for profile in evidence()["profiles"].values():
        assert set(profile["beforeRepair"]["differenceCaseIds"]) == changed
        assert profile["beforeRepair"]["classification"] == comparison.SEMANTIC_MISMATCH


def test_partial_recordings_do_not_promote_unobserved_conditions_or_official_emulator():
    value = evidence()
    closure = json.loads(CLOSURE.read_bytes())
    assert value["coverage"] == "PARTIAL"
    assert value["authorizesProduction"] is value["acquisitionValidated"] is value["promotionReady"] is False
    counts = {"FS-TRANSACTION/idle-expiry": 5, "FS-TRANSACTION/failed-commit-and-rollback": 3, "FS-TRANSACTION/retry-token-lifecycle": 5}
    assert {name: len(ids) for name, ids in value["conditionMap"].items()} == counts
    mapped = [case for ids in value["conditionMap"].values() for case in ids]
    assert len(mapped) == len(set(mapped)) == 13
    assert set(mapped) == {row["caseId"] for row in value["cases"]}
    assert len(closure["conditions"]) == 18
    assert closure["parentStatus"] == "IMPLEMENTING" and closure["closureReview"]["decision"] == "PENDING"
    assert closure["profileComparison"]["emulatorCompatibilityCheck"] == "PENDING_LOCAL_OBSERVATION"
    for condition in closure["conditions"]:
        assert condition["status"] != "VERIFIED"
        if condition["conditionId"] in counts:
            assert condition["status"] == "PRODUCTION_RECORDED"
            partial = condition["partialEvidence"]
            assert partial["coverage"] == "PARTIAL" and partial["remainingBoundaries"]
            assert partial["caseIds"] == value["conditionMap"][condition["conditionId"]]
            assert partial["reference"] == str(PATH.relative_to(ROOT))
        else:
            assert condition["productionObservation"] == "UNOBSERVED_BY_RECORDED_CORPUS"


def test_public_partial_summary_retains_no_credentials_or_absolute_paths():
    rendered = PATH.read_text()
    for marker in comparison.CREDENTIAL_MARKERS + ('"/Users/', '"/home/', '"/private/', '"/tmp/', '"pythonExecutable":', 'rulesetName', 'client.apiKey'):
        assert marker not in rendered
