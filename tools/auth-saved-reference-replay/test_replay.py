"""Tests for the immutable Auth saved-reference replay contract."""

import copy
import json
import shutil
from pathlib import Path

import pytest
from replay import CORPORA, compare, evaluate, load_spec, typed_equal


PRIVATE_BUNDLE = Path("docs.local/logs/2026-09-14/auth-saved-reference-replay-b3e57fef")


def saved(name):
    return json.loads(CORPORA[name]["receipt"].read_bytes())


def local_from_saved(name, source="a" * 40):
    receipt = saved(name)
    production = receipt["production"]
    return {
        "target": "local",
        "status": "passed",
        "cases": copy.deepcopy(production["cases"]),
        "cleanup": copy.deepcopy(production["cleanup"]),
        "runtimeSourceCommit": source,
        "artifact": {"kind": "local-build", "sha256": "b" * 64},
        "build": {"artifactSha256": "b" * 64, "exitCode": 0, "inputs": {}},
        "ownedProcess": {"exitCode": 0, "stopped": True, "listenersClosed": True},
        "configuration": {
            "sha256": "c" * 64,
            "fileSha256": "d" * 64,
            "value": {"profile": "strict", "schemaVersion": 1},
        },
    }


def test_replay_spec_binds_runtime_to_the_run_manifest():
    spec = load_spec()
    assert spec["schemaVersion"] == 2
    assert spec["runtimeSourceBinding"] == "run-manifest.sourceCommit"
    assert "sourceCommit" not in spec


def test_typed_json_distinguishes_boolean_integer_and_float():
    assert typed_equal({"value": True}, {"value": True})
    assert not typed_equal({"value": True}, {"value": 1})
    assert not typed_equal({"value": False}, {"value": 0})
    assert not typed_equal({"value": 1}, {"value": 1.0})


def test_replay_matches_saved_production_rows_without_requiring_config_shape():
    receipt = saved("auth-basic-v2")
    result = compare("auth-basic-v2", local_from_saved("auth-basic-v2"), receipt)
    assert result["classification"] == "MATCH"
    assert result["matchCount"] == 12
    assert result["configurationComparison"]["classification"] == "SEPARATE_EVIDENCE"


def test_replay_rejects_wrong_row_order():
    receipt = saved("auth-profile")
    local = local_from_saved("auth-profile")
    local["cases"][0], local["cases"][1] = local["cases"][1], local["cases"][0]
    with pytest.raises(ValueError, match="incomplete"):
        compare("auth-profile", local, receipt)


def test_replay_keeps_boolean_integer_mismatch_visible():
    receipt = saved("auth-display-name")
    local = local_from_saved("auth-display-name")
    local["cases"][0]["checks"]["httpOk"] = 1
    with pytest.raises(ValueError, match="Auth observation contract failed"):
        compare("auth-display-name", local, receipt)


def test_replay_rejects_missing_source_and_incomplete_cleanup():
    receipt = saved("auth-password")
    local = local_from_saved("auth-password")
    del local["runtimeSourceCommit"]
    with pytest.raises(ValueError, match="source commit"):
        compare("auth-password", local, receipt)

    local = local_from_saved("auth-password")
    local["cleanup"]["uidAbsent"] = False
    with pytest.raises(ValueError, match="incomplete"):
        compare("auth-password", local, receipt)


def test_replay_rejects_unstopped_process():
    receipt = saved("auth-basic-v2")
    local = local_from_saved("auth-basic-v2")
    local["ownedProcess"]["listenersClosed"] = False
    with pytest.raises(ValueError, match="closed"):
        compare("auth-basic-v2", local, receipt)


def test_replay_rejects_artifact_provenance_mismatch():
    receipt = saved("auth-profile")
    local = local_from_saved("auth-profile")
    local["build"]["artifactSha256"] = "d" * 64
    with pytest.raises(ValueError, match="provenance"):
        compare("auth-profile", local, receipt)


def test_replay_rejects_exact_type_tampering_in_cleanup_and_process():
    receipt = saved("auth-basic-v2")
    local = local_from_saved("auth-basic-v2")
    local["cleanup"]["uidAbsent"] = 1
    with pytest.raises(ValueError, match="incomplete"):
        compare("auth-basic-v2", local, receipt)

    local = local_from_saved("auth-basic-v2")
    local["ownedProcess"]["exitCode"] = True
    with pytest.raises(ValueError, match="integer"):
        compare("auth-basic-v2", local, receipt)


def private_bundle_copy(tmp_path, suffix="bundle"):
    if not PRIVATE_BUNDLE.is_dir():
        pytest.skip("private fixed replay bundle is not available")
    destination = tmp_path / suffix
    shutil.copytree(PRIVATE_BUNDLE, destination)
    return destination


def test_manifest_tampering_is_rejected_before_comparison(tmp_path):
    bundle = private_bundle_copy(tmp_path)
    manifest_path = bundle / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["corpora"]["auth-profile"]["configurationSha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="configuration is not bound"):
        evaluate(bundle, tmp_path / "result.json", "b3e57fef9edff8e09fbf93cea6666b7f51c3fd61")


def test_manifest_probe_and_process_tampering_is_rejected(tmp_path):
    bundle = private_bundle_copy(tmp_path, "probe-bundle")
    manifest_path = bundle / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["corpora"]["auth-profile"]["probeInputsSha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="probe input digest"):
        evaluate(bundle, tmp_path / "result.json", "b3e57fef9edff8e09fbf93cea6666b7f51c3fd61")

    bundle = private_bundle_copy(tmp_path, "process-bundle")
    report_path = bundle / "auth-profile/local.json"
    report = json.loads(report_path.read_text())
    report["ownedProcess"]["stopped"] = 0
    report_path.write_text(json.dumps(report))
    manifest = json.loads((bundle / "run-manifest.json").read_text())
    manifest["corpora"]["auth-profile"]["localReportSha256"] = __import__("hashlib").sha256(report_path.read_bytes()).hexdigest()
    manifest["corpora"]["auth-profile"]["localReportBytes"] = report_path.stat().st_size
    (bundle / "run-manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="stopped flag"):
        evaluate(bundle, tmp_path / "result.json", "b3e57fef9edff8e09fbf93cea6666b7f51c3fd61")


def test_fixed_bundle_evaluation_is_deterministic(tmp_path):
    bundle = private_bundle_copy(tmp_path)
    first = evaluate(bundle, tmp_path / "first.json", "b3e57fef9edff8e09fbf93cea6666b7f51c3fd61")
    second = evaluate(bundle, tmp_path / "second.json", "b3e57fef9edff8e09fbf93cea6666b7f51c3fd61")
    assert first["comparisonDigest"] == second["comparisonDigest"]
    assert first["allCasesMatch"] is True
