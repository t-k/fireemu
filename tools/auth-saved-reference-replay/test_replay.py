"""Tests for the immutable Auth saved-reference replay contract."""

import copy
import json
import shutil
import sys
import types
from pathlib import Path

import pytest
import replay
import run_replay
from replay import (
    BUILD_COMMAND,
    CORPORA,
    compare,
    digest,
    evaluate,
    expected_probe_inputs,
    expected_runtime_inputs,
    file_digest,
    load_contract,
    load_spec,
    typed_equal,
    validate_artifact_binding,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "compat-inventory"))
import owned_runner

sys.path.pop(0)


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


def write_complete_failed_bundle(tmp_path):
    root = tmp_path / "complete-failed-bundle"
    root.mkdir(mode=0o700)
    source = "a" * 40
    source_path = root / "source-fireemu"
    launch_path = root / "launch" / "fireemu"
    launch_path.parent.mkdir(mode=0o700)
    source_path.write_bytes(b"owned-fireemu-artifact")
    launch_path.write_bytes(source_path.read_bytes())
    artifact = file_digest(source_path)
    artifact_binding = {
        "sourcePath": str(source_path),
        "sourceSha256": artifact,
        "launchCopyPath": str(launch_path),
        "launchCopySha256": artifact,
    }
    configuration = {
        "sha256": "c" * 64,
        "fileSha256": "d" * 64,
        "value": {"profile": "strict", "schemaVersion": 1},
    }
    inputs = expected_runtime_inputs()
    corpora = {}
    for name in CORPORA:
        report = local_from_saved(name, source)
        report.update(
            {
                "status": "failed",
                "artifact": {"kind": "local-build", "sha256": artifact},
                "build": {
                    "artifactSha256": artifact,
                    "exitCode": 0,
                    "inputs": inputs,
                    **artifact_binding,
                },
                "ownedProcess": {
                    "exitCode": 0,
                    "stopped": True,
                    "listenersClosed": True,
                },
                "configuration": configuration,
                "probeInputs": expected_probe_inputs(name),
            }
        )
        corpus = root / name
        corpus.mkdir(mode=0o700)
        report_path = corpus / "local.json"
        report_path.write_text(json.dumps(report, sort_keys=True) + "\n")
        corpora[name] = {
            "status": "failed",
            "localReport": f"{name}/local.json",
            "localReportSha256": file_digest(report_path),
            "localReportBytes": report_path.stat().st_size,
            "artifactSha256": artifact,
            "runtimeSourceCommit": source,
            "cleanup": {"uidAbsent": True, "emailAbsent": True},
            "listenersClosed": True,
            "processExitCode": 0,
            "probeInputsSha256": digest(report["probeInputs"]),
            "configurationSha256": configuration["sha256"],
            "configurationFileSha256": configuration["fileSha256"],
        }
    manifest = {
        "schemaVersion": 2,
        "kind": "auth-saved-reference-replay-local-v2",
        "sourceCommit": source,
        "build": {
            "command": BUILD_COMMAND,
            "exitCode": 0,
            "artifactSha256": artifact,
            "inputs": inputs,
            **artifact_binding,
        },
        "artifactSha256": artifact,
        "corpora": corpora,
    }
    (root / "run-manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n")
    return root, source


def test_replay_spec_binds_runtime_to_the_run_manifest():
    spec = load_spec()
    assert spec["schemaVersion"] == 2
    assert spec["runtimeSourceBinding"] == "run-manifest.sourceCommit"
    assert "sourceCommit" not in spec


def test_run_rejects_dangling_output_root_symlink(tmp_path):
    output_root = tmp_path / "output-alias"
    output_root.symlink_to(tmp_path / "missing-output")
    with pytest.raises(ValueError, match="output root must not already exist"):
        run_replay.run(output_root)


def test_manifest_requires_durable_artifact_path_and_hash_binding(tmp_path):
    bundle, _source = write_complete_failed_bundle(tmp_path)
    manifest_path = bundle / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    for key in ("sourcePath", "sourceSha256", "launchCopyPath", "launchCopySha256"):
        manifest["build"].pop(key)
    manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n")
    with pytest.raises(ValueError, match="artifact binding"):
        validate_artifact_binding(
            manifest["build"], manifest["artifactSha256"], bundle
        )


@pytest.mark.parametrize("mutation, message", [("path", "source and launch paths"), ("bytes", "launch hash")])
def test_manifest_rejects_launch_copy_substitution_or_postcopy_mutation(tmp_path, mutation, message):
    bundle, _source = write_complete_failed_bundle(tmp_path)
    manifest_path = bundle / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if mutation == "path":
        manifest["build"]["launchCopyPath"] = manifest["build"]["sourcePath"]
        manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n")
    else:
        Path(manifest["build"]["launchCopyPath"]).write_bytes(b"changed-after-launch")
    with pytest.raises(ValueError, match=message):
        validate_artifact_binding(
            manifest["build"], manifest["artifactSha256"], bundle
        )


def test_manifest_rejects_symlinked_artifact_copy(tmp_path):
    bundle, _source = write_complete_failed_bundle(tmp_path)
    manifest = json.loads((bundle / "run-manifest.json").read_text())
    launch_path = Path(manifest["build"]["launchCopyPath"])
    target = launch_path.with_name("real-fireemu")
    launch_path.rename(target)
    launch_path.symlink_to(target)
    with pytest.raises(ValueError, match="symlink"):
        validate_artifact_binding(
            manifest["build"], manifest["artifactSha256"], bundle
        )


def test_manifest_rejects_hardlinked_artifact_copy(tmp_path):
    bundle, _source = write_complete_failed_bundle(tmp_path)
    manifest = json.loads((bundle / "run-manifest.json").read_text())
    source_path = Path(manifest["build"]["sourcePath"])
    launch_path = Path(manifest["build"]["launchCopyPath"])
    launch_path.unlink()
    launch_path.hardlink_to(source_path)
    with pytest.raises(ValueError, match="hardlink"):
        validate_artifact_binding(
            manifest["build"], manifest["artifactSha256"], bundle
        )


def test_manifest_rejects_parent_path_alias_for_artifact_copy(tmp_path):
    bundle, _source = write_complete_failed_bundle(tmp_path)
    manifest = json.loads((bundle / "run-manifest.json").read_text())
    launch_path = Path(manifest["build"]["launchCopyPath"])
    manifest["build"]["launchCopyPath"] = str(
        launch_path.parent / ".." / launch_path.parent.name / launch_path.name
    )
    with pytest.raises(ValueError, match="contains '..'"):
        validate_artifact_binding(
            manifest["build"], manifest["artifactSha256"], bundle
        )


def test_manifest_rejects_parent_directory_symlink_alias(tmp_path):
    bundle, _source = write_complete_failed_bundle(tmp_path)
    manifest = json.loads((bundle / "run-manifest.json").read_text())
    launch_path = Path(manifest["build"]["launchCopyPath"])
    real_directory = launch_path.parent.with_name("launch-real")
    launch_path.parent.rename(real_directory)
    launch_path.parent.symlink_to(real_directory, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink parent"):
        validate_artifact_binding(
            manifest["build"], manifest["artifactSha256"], bundle
        )


def test_manifest_accepts_independent_shutil_copyfile_artifact(tmp_path):
    bundle, _source = write_complete_failed_bundle(tmp_path)
    manifest = json.loads((bundle / "run-manifest.json").read_text())
    source_path = Path(manifest["build"]["sourcePath"])
    launch_path = Path(manifest["build"]["launchCopyPath"])
    launch_path.unlink()
    shutil.copyfile(source_path, launch_path)
    validate_artifact_binding(manifest["build"], manifest["artifactSha256"], bundle)


def test_manifest_returns_fd_capability_for_path_replacement(tmp_path):
    bundle, _source = write_complete_failed_bundle(tmp_path)
    manifest = json.loads((bundle / "run-manifest.json").read_text())
    source_path = Path(manifest["build"]["sourcePath"])
    launch_path = Path(manifest["build"]["launchCopyPath"])
    binding = validate_artifact_binding(
        manifest["build"], manifest["artifactSha256"], bundle
    )
    verified_fd = binding.pop("_launchFd")
    try:
        preserved = launch_path.with_name("preserved-launch-fireemu")
        launch_path.rename(preserved)
        launch_path.hardlink_to(source_path)
        assert replay.os.fstat(verified_fd).st_ino != source_path.stat().st_ino
        assert replay.os.pread(verified_fd, 1024, 0) == source_path.read_bytes()
    finally:
        replay.os.close(verified_fd)


def test_manifest_rejects_launch_replacement_during_descriptor_read(
    tmp_path, monkeypatch
):
    bundle, _source = write_complete_failed_bundle(tmp_path)
    manifest = json.loads((bundle / "run-manifest.json").read_text())
    source_path = Path(manifest["build"]["sourcePath"])
    launch_path = Path(manifest["build"]["launchCopyPath"])
    original_read = replay.os.read
    replaced = False

    def replace_after_source_read(fd, size):
        nonlocal replaced
        chunk = original_read(fd, size)
        if not replaced and chunk:
            launch_path.unlink()
            launch_path.hardlink_to(source_path)
            replaced = True
        return chunk

    monkeypatch.setattr(replay.os, "read", replace_after_source_read)
    with pytest.raises(ValueError, match="hardlink|changed"):
        validate_artifact_binding(
            manifest["build"], manifest["artifactSha256"], bundle
        )


def test_manifest_rejects_independent_launch_replacement_during_read(
    tmp_path, monkeypatch
):
    bundle, _source = write_complete_failed_bundle(tmp_path)
    manifest = json.loads((bundle / "run-manifest.json").read_text())
    source_path = Path(manifest["build"]["sourcePath"])
    launch_path = Path(manifest["build"]["launchCopyPath"])
    original_inode = launch_path.stat().st_ino
    original_read = replay.os.read
    replaced = False

    def replace_after_launch_read(fd, size):
        nonlocal replaced
        before = replay.os.fstat(fd)
        chunk = original_read(fd, size)
        if not replaced and chunk and before.st_ino == original_inode:
            replacement = launch_path.with_name("replacement-fireemu")
            shutil.copyfile(source_path, replacement)
            launch_path.unlink()
            replacement.rename(launch_path)
            replaced = True
        return chunk

    monkeypatch.setattr(replay.os, "read", replace_after_launch_read)
    with pytest.raises(ValueError, match="changed"):
        validate_artifact_binding(
            manifest["build"], manifest["artifactSha256"], bundle
        )


def test_manifest_rejects_launch_replacement_after_path_recheck(tmp_path, monkeypatch):
    bundle, _source = write_complete_failed_bundle(tmp_path)
    manifest = json.loads((bundle / "run-manifest.json").read_text())
    source_path = Path(manifest["build"]["sourcePath"])
    launch_path = Path(manifest["build"]["launchCopyPath"])
    original_stat = replay.os.stat
    replaced = False

    def replace_after_launch_stat(path, *args, **kwargs):
        nonlocal replaced
        result = original_stat(path, *args, **kwargs)
        if not replaced and Path(path) == launch_path:
            launch_path.unlink()
            launch_path.hardlink_to(source_path)
            replaced = True
        return result

    monkeypatch.setattr(replay.os, "stat", replace_after_launch_stat)
    with pytest.raises(ValueError, match="hardlink|after verification|before opening"):
        validate_artifact_binding(
            manifest["build"], manifest["artifactSha256"], bundle
        )


def test_manifest_rejects_launch_replacement_after_final_stat(tmp_path, monkeypatch):
    bundle, _source = write_complete_failed_bundle(tmp_path)
    manifest = json.loads((bundle / "run-manifest.json").read_text())
    source_path = Path(manifest["build"]["sourcePath"])
    launch_path = Path(manifest["build"]["launchCopyPath"])
    original_stat = replay.os.stat
    launch_stats = 0

    def replace_after_final_stat(path, *args, **kwargs):
        nonlocal launch_stats
        result = original_stat(path, *args, **kwargs)
        if Path(path) == launch_path:
            launch_stats += 1
            if launch_stats == 2:
                launch_path.unlink()
                launch_path.hardlink_to(source_path)
        return result

    monkeypatch.setattr(replay.os, "stat", replace_after_final_stat)
    with pytest.raises(ValueError, match="hardlink|while reading|before use|after verification"):
        validate_artifact_binding(
            manifest["build"], manifest["artifactSha256"], bundle
        )


def test_manifest_rejects_launch_replacement_after_bound_descriptor_stat(
    tmp_path, monkeypatch
):
    bundle, _source = write_complete_failed_bundle(tmp_path)
    manifest = json.loads((bundle / "run-manifest.json").read_text())
    source_path = Path(manifest["build"]["sourcePath"])
    launch_path = Path(manifest["build"]["launchCopyPath"])
    original_fstat = replay.os.fstat
    fstats = 0

    def replace_after_bound_fstat(fd):
        nonlocal fstats
        result = original_fstat(fd)
        fstats += 1
        if fstats == 5:
            launch_path.unlink()
            launch_path.hardlink_to(source_path)
        return result

    monkeypatch.setattr(replay.os, "fstat", replace_after_bound_fstat)
    with pytest.raises(ValueError, match="hardlink|while reading|before use|before opening"):
        validate_artifact_binding(
            manifest["build"], manifest["artifactSha256"], bundle
        )


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
        pytest.skip(
            "historical private v1 replay bundle is unavailable; "
            "current schema-v2 validation is covered by synthetic fixtures"
        )
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
        evaluate(
            bundle, tmp_path / "result.json", "b3e57fef9edff8e09fbf93cea6666b7f51c3fd61"
        )


def test_manifest_probe_and_process_tampering_is_rejected(tmp_path):
    bundle = private_bundle_copy(tmp_path, "probe-bundle")
    manifest_path = bundle / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["corpora"]["auth-profile"]["probeInputsSha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="probe input digest"):
        evaluate(
            bundle, tmp_path / "result.json", "b3e57fef9edff8e09fbf93cea6666b7f51c3fd61"
        )

    bundle = private_bundle_copy(tmp_path, "process-bundle")
    report_path = bundle / "auth-profile/local.json"
    report = json.loads(report_path.read_text())
    report["ownedProcess"]["stopped"] = 0
    report_path.write_text(json.dumps(report))
    manifest = json.loads((bundle / "run-manifest.json").read_text())
    manifest["corpora"]["auth-profile"]["localReportSha256"] = (
        __import__("hashlib").sha256(report_path.read_bytes()).hexdigest()
    )
    manifest["corpora"]["auth-profile"]["localReportBytes"] = report_path.stat().st_size
    (bundle / "run-manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="stopped flag"):
        evaluate(
            bundle, tmp_path / "result.json", "b3e57fef9edff8e09fbf93cea6666b7f51c3fd61"
        )


def test_fixed_bundle_evaluation_is_deterministic(tmp_path):
    bundle = private_bundle_copy(tmp_path)
    first = evaluate(
        bundle, tmp_path / "first.json", "b3e57fef9edff8e09fbf93cea6666b7f51c3fd61"
    )
    second = evaluate(
        bundle, tmp_path / "second.json", "b3e57fef9edff8e09fbf93cea6666b7f51c3fd61"
    )
    assert first["comparisonDigest"] == second["comparisonDigest"]
    assert first["allCasesMatch"] is True


def test_evaluate_validates_a_complete_failed_profile_fixture(tmp_path):
    bundle, source = write_complete_failed_bundle(tmp_path)
    result = evaluate(bundle, tmp_path / "result.json", source)
    assert result["allCasesMatch"] is True
    assert result["corpora"]["auth-profile"]["classification"] == "MATCH"


def test_complete_failed_report_reaches_semantic_mismatch_evaluation(tmp_path):
    bundle, source = write_complete_failed_bundle(tmp_path)
    local_path = bundle / "auth-profile/local.json"
    local = json.loads(local_path.read_text())
    local["cases"][2]["photoState"] = "other"
    local["cases"][2]["checks"]["photoMatches"] = False
    local["cases"][2]["passed"] = False
    local_path.write_text(json.dumps(local, sort_keys=True) + "\n")
    manifest_path = bundle / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["corpora"]["auth-profile"]["localReportSha256"] = file_digest(local_path)
    manifest["corpora"]["auth-profile"]["localReportBytes"] = local_path.stat().st_size
    manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n")

    result = evaluate(bundle, tmp_path / "result.json", source)

    assert result["allCasesMatch"] is False
    assert result["corpora"]["auth-profile"]["classification"] == "SEMANTIC_MISMATCH"
    assert result["corpora"]["auth-profile"]["mismatchCases"] == [
        local["cases"][2]["id"]
    ]


def test_evaluate_rejects_tampered_failed_status_after_real_validation(tmp_path):
    bundle, source = write_complete_failed_bundle(tmp_path)
    manifest_path = bundle / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["corpora"]["auth-profile"]["status"] = "passed"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n")
    with pytest.raises(ValueError, match="status does not match"):
        evaluate(bundle, tmp_path / "result.json", source)


@pytest.mark.parametrize("collision", ["regular", "symlink", "hardlink"])
def test_evaluate_preserves_input_bytes_for_real_fixture_collisions(tmp_path, collision):
    bundle, source = write_complete_failed_bundle(tmp_path)
    target = tmp_path / "result.json"
    if collision == "regular":
        target.write_bytes(b"original")
        protected = target
    elif collision == "symlink":
        protected = tmp_path / "symlink-target"
        protected.write_bytes(b"original")
        target.symlink_to(protected)
    else:
        protected = tmp_path / "hardlink-source"
        protected.write_bytes(b"original")
        target.hardlink_to(protected)
    before = protected.read_bytes()
    with pytest.raises(ValueError, match="already exists"):
        evaluate(bundle, target, source)
    assert protected.read_bytes() == before


@pytest.mark.parametrize(
    "input_kind", ["production-receipt", "local-report", "run-manifest"]
)
@pytest.mark.parametrize("collision", ["regular", "symlink", "hardlink"])
def test_evaluate_rejects_collision_with_bound_input_paths(
    tmp_path, input_kind, collision
):
    bundle, source = write_complete_failed_bundle(tmp_path)
    if input_kind == "production-receipt":
        protected = CORPORA["auth-profile"]["receipt"]
    elif input_kind == "local-report":
        protected = bundle / "auth-profile/local.json"
    else:
        protected = bundle / "run-manifest.json"

    original_inputs = {
        path: path.read_bytes()
        for path in [
            bundle / "auth-profile/local.json",
            bundle / "run-manifest.json",
        ]
    }
    if collision == "regular":
        target = protected
    else:
        target = tmp_path / f"{input_kind}-{collision}-target"
        if collision == "symlink":
            target.symlink_to(protected)
        else:
            target.hardlink_to(protected)

    before = protected.read_bytes()
    with pytest.raises(ValueError, match="already exists"):
        evaluate(bundle, target, source)

    assert protected.read_bytes() == before
    for path, content in original_inputs.items():
        assert path.read_bytes() == content


def test_run_accepts_a_complete_failed_report_and_writes_the_manifest(
    tmp_path, monkeypatch
):
    artifact_path = tmp_path / "artifact"
    artifact_path.write_bytes(b"artifact")
    artifact = file_digest(artifact_path)

    def fake_run(output):
        output.mkdir(mode=0o700)
        (output / "local.json").write_text("{}")
        return {
            "status": "failed",
            "artifact": {"sha256": artifact},
            "runtimeSourceCommit": "a" * 40,
            "cleanup": {"uidAbsent": True, "emailAbsent": True},
            "ownedProcess": {"listenersClosed": True, "exitCode": 0},
            "probeInputs": {},
            "configuration": {"sha256": "c" * 64, "fileSha256": "d" * 64},
        }

    fake = types.SimpleNamespace(run=fake_run, complete=lambda report: True)
    monkeypatch.setattr(run_replay, "RUNNERS", dict.fromkeys(CORPORA, fake))
    monkeypatch.setattr(run_replay, "load_runner", lambda path: fake)
    monkeypatch.setattr(
        owned_runner,
        "build_artifact",
        lambda: (
            artifact_path,
            {
                "command": BUILD_COMMAND,
                "artifactSha256": artifact,
                "exitCode": 0,
                "inputs": {},
            },
        ),
    )
    monkeypatch.setattr(
        run_replay.subprocess, "check_output", lambda *args, **kwargs: "a" * 40 + "\n"
    )

    manifest = run_replay.run(tmp_path / "bundle")
    assert manifest["sourceCommit"] == "a" * 40
    assert (tmp_path / "bundle/run-manifest.json").is_file()


def test_run_to_evaluate_preserves_complete_semantic_failure(tmp_path, monkeypatch):
    """A complete failed probe must reach the comparator as a mismatch."""

    source = "a" * 40
    artifact_path = tmp_path / "artifact"
    artifact_path.write_bytes(b"artifact")
    artifact = file_digest(artifact_path)
    inputs = expected_runtime_inputs()
    configuration = {
        "sha256": "c" * 64,
        "fileSha256": "d" * 64,
        "value": {"profile": "strict", "schemaVersion": 1},
    }

    def fake_run(output, name):
        report = local_from_saved(name, source)
        report.update(
            {
                "status": "failed",
                "artifact": {"kind": "local-build", "sha256": artifact},
                "build": {
                    "command": BUILD_COMMAND,
                    "artifactSha256": artifact,
                    "exitCode": 0,
                    "inputs": inputs,
                },
                "ownedProcess": {
                    "exitCode": 0,
                    "stopped": True,
                    "listenersClosed": True,
                },
                "configuration": configuration,
                "probeInputs": expected_probe_inputs(name),
            }
        )
        if name == "auth-profile":
            row = report["cases"][2]
            row["photoState"] = "other"
            row["checks"]["photoMatches"] = False
            row["passed"] = False
        output.mkdir(mode=0o700)
        (output / "local.json").write_text(json.dumps(report, sort_keys=True) + "\n")
        return report

    runners = {}
    for name in CORPORA:
        contract = load_contract(CORPORA[name]["contract"])
        runners[name] = types.SimpleNamespace(
            run=lambda output, name=name: fake_run(output, name),
            complete=contract.complete,
        )
    monkeypatch.setattr(
        run_replay, "RUNNERS", {name: Path(name) for name in CORPORA}
    )
    monkeypatch.setattr(
        run_replay, "load_runner", lambda path: runners[path.name]
    )
    monkeypatch.setattr(
        owned_runner,
        "build_artifact",
        lambda: (
            artifact_path,
            {
                "command": BUILD_COMMAND,
                "artifactSha256": artifact,
                "exitCode": 0,
                "inputs": inputs,
            },
        ),
    )
    real_check_output = run_replay.subprocess.check_output

    def fake_check_output(args, **kwargs):
        if args[:3] == ["git", "rev-parse", "HEAD"]:
            return source + "\n" if kwargs.get("text") else (source + "\n").encode()
        return real_check_output(args, **kwargs)

    monkeypatch.setattr(run_replay.subprocess, "check_output", fake_check_output)

    local_root = tmp_path / "bundle"
    manifest = run_replay.run(local_root)
    assert manifest["corpora"]["auth-profile"]["status"] == "failed"
    assert (local_root / "run-manifest.json").is_file()

    result = evaluate(local_root, tmp_path / "result.json", source)
    assert result["allCasesMatch"] is False
    assert result["corpora"]["auth-profile"]["classification"] == (
        "SEMANTIC_MISMATCH"
    )
    assert result["corpora"]["auth-profile"]["mismatchCases"] == [
        "set-photo"
    ]


def test_run_stops_when_a_report_is_incomplete(tmp_path, monkeypatch):
    artifact_path = tmp_path / "artifact"
    artifact_path.write_bytes(b"artifact")
    artifact = file_digest(artifact_path)
    fake = types.SimpleNamespace(
        run=lambda output: {"status": "incomplete"}, complete=lambda report: False
    )
    monkeypatch.setattr(run_replay, "RUNNERS", dict.fromkeys(CORPORA, fake))
    monkeypatch.setattr(run_replay, "load_runner", lambda path: fake)
    monkeypatch.setattr(
        owned_runner,
        "build_artifact",
        lambda: (
            artifact_path,
            {
                "command": BUILD_COMMAND,
                "artifactSha256": artifact,
                "exitCode": 0,
                "inputs": {},
            },
        ),
    )
    monkeypatch.setattr(
        run_replay.subprocess, "check_output", lambda *args, **kwargs: "a" * 40 + "\n"
    )

    with pytest.raises(ValueError, match="incomplete"):
        run_replay.run(tmp_path / "bundle")
    assert not (tmp_path / "bundle/run-manifest.json").exists()


def test_evaluate_writes_a_complete_semantic_mismatch(tmp_path, monkeypatch):
    local_root = tmp_path / "bundle"
    local_root.mkdir()
    (local_root / "run-manifest.json").write_text("{}")
    for name in CORPORA:
        corpus = local_root / name
        corpus.mkdir()
        (corpus / "local.json").write_text("{}")
    mismatch = {
        "classification": "SEMANTIC_MISMATCH",
        "caseCount": 1,
        "matchCount": 0,
        "mismatchCases": ["case"],
        "rows": [],
        "currentLocal": {},
        "configurationComparison": {},
    }
    monkeypatch.setattr(
        "replay.load_spec", lambda: {"corpora": [{"id": name} for name in CORPORA]}
    )
    monkeypatch.setattr("replay.validate_manifest", lambda *args: ({}, {}))
    monkeypatch.setattr("replay.compare", lambda *args: mismatch)
    result = evaluate(local_root, tmp_path / "result.json", "a" * 40)
    assert result["allCasesMatch"] is False
    assert json.loads((tmp_path / "result.json").read_text())["allCasesMatch"] is False


@pytest.mark.parametrize("collision", ["regular", "symlink", "hardlink"])
def test_evaluate_rejects_every_existing_output_collision(
    tmp_path, monkeypatch, collision
):
    local_root = tmp_path / "bundle"
    local_root.mkdir()
    (local_root / "run-manifest.json").write_text("{}")
    for name in CORPORA:
        corpus = local_root / name
        corpus.mkdir()
        (corpus / "local.json").write_text("{}")
    monkeypatch.setattr(
        "replay.load_spec", lambda: {"corpora": [{"id": name} for name in CORPORA]}
    )
    monkeypatch.setattr("replay.validate_manifest", lambda *args: ({}, {}))
    monkeypatch.setattr(
        "replay.compare",
        lambda *args: {
            "classification": "MATCH",
            "caseCount": 0,
            "matchCount": 0,
            "mismatchCases": [],
            "rows": [],
            "currentLocal": {},
            "configurationComparison": {},
        },
    )
    target = tmp_path / "result.json"
    if collision == "regular":
        target.write_text("original")
    elif collision == "symlink":
        target.with_name("symlink-target").write_text("original")
        target.symlink_to(target.with_name("symlink-target"))
    else:
        target.with_name("hardlink-source").write_text("original")
        target.hardlink_to(target.with_name("hardlink-source"))

    with pytest.raises(ValueError, match="already exists"):
        evaluate(local_root, target, "a" * 40)
