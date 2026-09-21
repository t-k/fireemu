from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

import reference_projection as projection
V6_RUN = Path("/Users/tk/work/firebase-emulator/docs.local/logs/2026-09-22/cx-evid-current-run-v6/local-run")
V6_COMPILER = Path("/Users/tk/work/firebase-emulator/docs.local/logs/2026-09-18/commit500-501-o8-run-v11/transform_compiler.py")


@pytest.fixture
def v6_copy(tmp_path):
    if not V6_RUN.is_dir() or not V6_COMPILER.is_file():
        pytest.skip("private v6 replay is unavailable")
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

    shutil.copytree(V6_RUN, v6_copy.parent / "cleanup-run")
    cleanup_run = v6_copy.parent / "cleanup-run"
    evidence_path = cleanup_run / "evidence.json"
    evidence = json.loads(evidence_path.read_text())
    evidence["ownedProcess"]["listenersClosed"] = False
    evidence_path.write_text(json.dumps(evidence))
    with pytest.raises(ValueError):
        projection.project_run(cleanup_run, V6_COMPILER)
