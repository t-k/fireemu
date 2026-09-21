from __future__ import annotations

import json

import pytest

import reference_projection as projection


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
