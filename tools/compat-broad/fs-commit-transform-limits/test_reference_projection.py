from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest
import reference_projection as projection

V6_RUN = (
    Path(os.environ["FIREEMU_COMMIT_TRANSFORM_V6_RUN"])
    if "FIREEMU_COMMIT_TRANSFORM_V6_RUN" in os.environ
    else None
)
V6_COMPILER = (
    Path(os.environ["FIREEMU_COMMIT_TRANSFORM_V6_COMPILER"])
    if "FIREEMU_COMMIT_TRANSFORM_V6_COMPILER" in os.environ
    else None
)


@pytest.fixture
def v6_copy(tmp_path):
    if V6_RUN is None or V6_COMPILER is None:
        pytest.skip("private v6 replay is unavailable")
    assert V6_RUN.is_dir(), f"configured v6 replay is unavailable: {V6_RUN}"
    assert V6_COMPILER.is_file(), f"configured v6 compiler is unavailable: {V6_COMPILER}"
    run = tmp_path / "local-run"
    shutil.copytree(V6_RUN, run)
    return run


def _run(tmp_path, result):
    run = tmp_path / "run"
    run.mkdir()
    (run / "plan.json").write_text("{}")
    (run / "result.json").write_text(json.dumps(result))
    return run


@pytest.mark.parametrize(
    "result",
    [
        {"recordingComplete": False, "cleanupComplete": True},
        {"recordingComplete": True, "cleanupComplete": False},
        {
            "recordingComplete": True,
            "cleanupComplete": True,
            "rows": [],
            "cleanup": [],
            "resourceAbsence": {"owned": False},
        },
    ],
)
def test_projection_refuses_incomplete_or_unbound_run(tmp_path, result):
    with pytest.raises((ValueError, KeyError, TypeError)):
        projection.project_run(_run(tmp_path, result))


def test_projection_refuses_overwrite(tmp_path, monkeypatch):
    output = tmp_path / "reference.json"
    output.write_text("existing")
    monkeypatch.setattr(projection, "project_run", lambda run, historical_compiler=None: {})
    with pytest.raises(ValueError, match="already exists"):
        projection.write_projection(tmp_path / "run", output)


@pytest.mark.parametrize("field", [
    "artifactSha256",
    "configurationDigest",
    "runtimeInputsDigest",
    "expectedRuntimeInputsDigest",
    "historicalCompilerSha256",
])
def test_projection_refuses_run_input_binding_mutations(v6_copy, field):
    path = v6_copy / "run-inputs.json"
    data = json.loads(path.read_text())
    data[field] = "0" * 64
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        projection.project_run(v6_copy, V6_COMPILER)


def test_projection_refuses_evidence_and_cleanup_mutations(v6_copy):
    evidence_path = v6_copy / "evidence.json"
    evidence = json.loads(evidence_path.read_text())
    evidence["sourceStable"] = False
    evidence_path.write_text(json.dumps(evidence))
    with pytest.raises(ValueError):
        projection.project_run(v6_copy, V6_COMPILER)

    assert V6_RUN is not None
    shutil.copytree(V6_RUN, v6_copy.parent / "cleanup-run")
    cleanup_run = v6_copy.parent / "cleanup-run"
    evidence_path = cleanup_run / "evidence.json"
    evidence = json.loads(evidence_path.read_text())
    evidence["ownedProcess"]["listenersClosed"] = False
    evidence_path.write_text(json.dumps(evidence))
    with pytest.raises(ValueError):
        projection.project_run(cleanup_run, V6_COMPILER)


def test_projection_refuses_deleted_file_with_recomputed_seal_map(v6_copy):
    evidence_path = v6_copy / "evidence.json"
    evidence = json.loads(evidence_path.read_text())
    (v6_copy / "result.json").unlink()
    del evidence["files"]["result.json"]
    evidence_path.write_text(json.dumps(evidence))
    with pytest.raises(ValueError, match="local run record is unreadable|sealed file digest map is incomplete|sealed run file set differs"):
        projection.project_run(v6_copy, V6_COMPILER)


def test_real_v6_projection_is_accepted_when_private_fixture_is_available():
    if V6_RUN is None or V6_COMPILER is None:
        pytest.skip("private v6 replay is unavailable")
    assert V6_RUN.is_dir(), f"configured v6 replay is unavailable: {V6_RUN}"
    assert V6_COMPILER.is_file(), f"configured v6 compiler is unavailable: {V6_COMPILER}"
    projected = projection.project_run(V6_RUN, V6_COMPILER)
    assert len(projected["rows"]) == 11
    assert len(projected["cleanup"]) == 6
