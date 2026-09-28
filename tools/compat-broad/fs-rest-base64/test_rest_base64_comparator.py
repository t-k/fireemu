import copy
import hashlib
import importlib.util
import json
from pathlib import Path

# This directory is not a package. Importing the CLI as top-level `comparator`
# would shadow fs-write-limits/comparator.py during whole-tree pytest collection.
# Load the unchanged CLI by path, without modifying sys.path or sys.modules.
_spec = importlib.util.spec_from_file_location(
    "_fs_rest_base64_comparator", Path(__file__).with_name("comparator.py")
)
assert _spec is not None and _spec.loader is not None
_comparator = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_comparator)
CASE_ID = _comparator.CASE_ID
EXPECTED_PROGRAM_DIGEST = _comparator.EXPECTED_PROGRAM_DIGEST
_digest = _comparator._digest
compare_evidence = _comparator.compare_evidence

ROOT = Path(__file__).resolve().parents[3]
MATRIX = ROOT / "conformance/firestore-production-matrix.json"
EXPECTED_SOURCE = "a" * 40
EXPECTED_ARTIFACT = "b" * 64


def evidence():
    historical = json.loads(MATRIX.read_bytes())
    expected = next(
        row["steps"]["write-bad-base64"]["production"]
        for row in historical["programs"]
        if row["id"] == "errors/rest-shapes"
    )
    actual = {
        "status": 400,
        "code": expected["code"],
        "message": expected["message"],
        "http": {
            "contract": "bounded-http-v1",
            "status": 400,
            "complete": True,
            "failure": None,
            "truncated": False,
            "digestScope": "full",
            "bodyKind": "json",
            "contentType": "application/json",
            "contentTypeTruncated": False,
            "receivedBytes": 12,
            "retainedBytes": 12,
            "bodySha256": "c" * 64,
        },
    }
    row = {"id": CASE_ID, "actual": actual, "collectionComplete": True}
    cases = {
        "kind": "second-broad-local-http-v1",
        "recordingComplete": True,
        "productionExecuted": False,
        "cases": [row],
        "selectedPrograms": [_comparator._historical_program()],
    }
    cases_bytes = json.dumps(cases, sort_keys=True, separators=(",", ":")).encode()
    manifest = {
        "status": "incomplete",
        "stopReason": "child-completed",
        "exitCode": 0,
        "recordingComplete": True,
        "productionExecuted": False,
        "executionCommit": EXPECTED_SOURCE,
        "artifactSha256": EXPECTED_ARTIFACT,
        "build": {"artifactSha256": EXPECTED_ARTIFACT, "inputs": {"src": "d" * 64}},
        "runtimeInputs": {"src": "d" * 64},
        "executionInputs": {"src": "e" * 64},
        "configurationDigest": "f" * 64,
        "partialResultSha256": hashlib.sha256(cases_bytes).hexdigest(),
        "ownedProcess": {"stopped": True, "listenersClosed": True},
        "cases": [copy.deepcopy(row)],
    }
    manifest["parentManifestSha256"] = _digest(manifest)
    return manifest, cases, historical, hashlib.sha256(cases_bytes).hexdigest()


def rebind(manifest, cases):
    encoded = json.dumps(cases, sort_keys=True, separators=(",", ":")).encode()
    manifest["partialResultSha256"] = hashlib.sha256(encoded).hexdigest()
    manifest["cases"] = copy.deepcopy(cases["cases"])
    manifest.pop("parentManifestSha256", None)
    manifest["parentManifestSha256"] = _digest(manifest)
    return manifest["partialResultSha256"]


def compare(manifest, cases, historical, source=EXPECTED_SOURCE, cases_sha256=None):
    return compare_evidence(
        manifest,
        cases,
        historical,
        expected_source_commit=source,
        current_cases_sha256=cases_sha256,
    )


def test_exact_saved_error_matches_only_with_bound_current_receipt():
    manifest, cases, historical, cases_sha256 = evidence()

    result = compare(manifest, cases, historical, cases_sha256=cases_sha256)

    assert result["status"] == "match"
    assert result["id"] == CASE_ID
    assert result["historicalProgramDigest"] == EXPECTED_PROGRAM_DIGEST
    assert result["productionExecuted"] is False


def test_status_and_code_equality_with_different_message_is_mismatch():
    manifest, cases, historical, _ = evidence()
    cases["cases"][0]["actual"]["message"] = "invalid base64"
    cases_sha256 = rebind(manifest, cases)

    result = compare(manifest, cases, historical, cases_sha256=cases_sha256)

    assert result["status"] == "mismatch"
    assert result["firstDifference"] == "$.message"


def test_missing_incomplete_or_unbound_current_evidence_is_indeterminate():
    manifest, cases, historical, cases_sha256 = evidence()
    cases["cases"][0]["actual"]["http"]["complete"] = False

    result = compare(manifest, cases, historical, cases_sha256=cases_sha256)
    assert result["status"] == "indeterminate"

    manifest, cases, historical, cases_sha256 = evidence()
    manifest["artifactSha256"] = "not-a-digest"
    result = compare(manifest, cases, historical, cases_sha256=cases_sha256)
    assert result["status"] == "indeterminate"

    manifest, cases, historical, cases_sha256 = evidence()
    manifest["partialResultSha256"] = "0" * 64
    result = compare(manifest, cases, historical, cases_sha256=cases_sha256)
    assert result["status"] == "indeterminate"


def test_wrong_source_commit_and_historical_matrix_are_inapplicable():
    manifest, cases, historical, cases_sha256 = evidence()
    result = compare(
        manifest, cases, historical, source="f" * 40, cases_sha256=cases_sha256
    )
    assert result["status"] == "indeterminate"

    manifest, cases, historical, cases_sha256 = evidence()
    altered = copy.deepcopy(historical)
    altered["programs"][0]["id"] = "drift"
    result = compare(manifest, cases, altered, cases_sha256=cases_sha256)
    assert result["status"] == "indeterminate"


def test_duplicate_target_receipts_fail_closed():
    manifest, cases, historical, _ = evidence()
    cases["cases"].append(copy.deepcopy(cases["cases"][0]))
    cases_sha256 = rebind(manifest, cases)

    result = compare(manifest, cases, historical, cases_sha256=cases_sha256)
    assert result["status"] == "indeterminate"


def test_complete_success_receipt_without_error_message_is_a_status_mismatch():
    for message in (None, ""):
        manifest, cases, historical, _ = evidence()
        actual = cases["cases"][0]["actual"]
        actual["status"] = 200
        actual["code"] = "OK"
        actual["http"]["status"] = 200
        actual["message"] = message
        cases_sha256 = rebind(manifest, cases)

        result = compare(manifest, cases, historical, cases_sha256=cases_sha256)

        assert result["status"] == "mismatch"
        assert result["firstDifference"] == "$.status"

    manifest, cases, historical, _ = evidence()
    actual = cases["cases"][0]["actual"]
    actual["status"] = 200
    actual["code"] = "OK"
    actual["http"]["status"] = 200
    actual.pop("message")
    cases_sha256 = rebind(manifest, cases)
    result = compare(manifest, cases, historical, cases_sha256=cases_sha256)
    assert result["status"] == "mismatch"
    assert result["firstDifference"] == "$.status"


def test_missing_duplicate_or_drifted_current_program_is_indeterminate():
    for selected_programs in (
        [],
        [
            _comparator._historical_program(),
            _comparator._historical_program(),
        ],
    ):
        manifest, cases, historical, _ = evidence()
        cases["selectedPrograms"] = selected_programs
        cases_sha256 = rebind(manifest, cases)
        assert (
            compare(manifest, cases, historical, cases_sha256=cases_sha256)["status"]
            == "indeterminate"
        )

    manifest, cases, historical, _ = evidence()
    changed_step = next(
        step
        for step in cases["selectedPrograms"][0]["steps"]
        if step["id"] == "write-bad-base64"
    )
    changed_step["path"] = "/changed/path"
    cases_sha256 = rebind(manifest, cases)
    result = compare(manifest, cases, historical, cases_sha256=cases_sha256)
    assert result["status"] == "indeterminate"
