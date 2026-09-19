import importlib.util
from pathlib import Path


def load():
    path = Path(__file__).with_name("evaluate.py")
    assert path.exists(), "v5 evaluator must exist"
    spec = importlib.util.spec_from_file_location("current_explain_v5", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_current_contract_preserves_historical_normalization():
    module = load()
    assert module.contract()["productionExecuted"] is False
    assert module.contract()["normalization"] == module.v3.contract()["normalization"]


def test_missing_input_is_indeterminate(tmp_path):
    module = load()
    result = module.evaluate({"production": tmp_path / "absent"}, tmp_path, tmp_path)
    assert result["compatibility"] == "indeterminate"
    assert result["collectionComplete"] is False
    assert result["productionExecuted"] is False


import json
import os
import shutil

import pytest


@pytest.fixture
def private_inputs():
    base = os.environ.get("EXPLAIN_V5_PRIVATE_ROOT")
    if not base:
        pytest.skip("set EXPLAIN_V5_PRIVATE_ROOT for immutable real-input checks")
    base = Path(base)
    return base, {
        "production": base
        / "docs.local/logs/2026-09-14/campaign-explain-production-109a9b45",
        "originalLocal": base
        / "docs.local/logs/2026-09-14/campaign-explain-shadow-109a9b45",
        "currentLocal": base
        / "docs.local/logs/2026-09-17/query-explain-shadow-cce4a4f9b-v4",
    }


def test_actual_saved_replay(private_inputs):
    module = load()
    base, roots = private_inputs
    result = module.evaluate(
        roots,
        base / ".worktree/campaign-explain-reference-109a9b45",
        base / ".worktree/query-current-collector-cce4a4f9b",
    )
    assert result["compatibility"] in {"match", "mismatch"}, result.get("reason")
    assert len(result["rows"]) == 12
    assert result["historical"]["originalV2Compatibility"] == "mismatch"
    assert result["cleanupComplete"] and result["stateVerified"]


@pytest.mark.parametrize("which", ["production", "originalLocal", "currentLocal"])
def test_actual_input_tampering_is_indeterminate(private_inputs, tmp_path, which):
    module = load()
    base, roots = private_inputs
    changed = tmp_path / which
    shutil.copytree(roots[which], changed)
    path = changed / "result.json"
    path.chmod(0o600)
    path.write_bytes(path.read_bytes() + b" ")
    roots[which] = changed
    result = module.evaluate(
        roots,
        base / ".worktree/campaign-explain-reference-109a9b45",
        base / ".worktree/query-current-collector-cce4a4f9b",
    )
    assert result["compatibility"] == "indeterminate"
    assert "frozen " + which + " bytes or file set differ" in result["reason"]


@pytest.mark.parametrize("control", ["artifact.json", "process.json", "cleanup"])
def test_actual_current_validator_rejects_control_tampering(
    private_inputs, tmp_path, control
):
    module = load()
    base, roots = private_inputs
    changed = tmp_path / "current"
    shutil.copytree(roots["currentLocal"], changed)
    if control == "cleanup":
        path = changed / "result.json"
        value = json.loads(path.read_bytes())
        value["cleanupComplete"] = False
        path.write_text(json.dumps(value))
    else:
        (changed / control).write_text("{}")
    with pytest.raises(ValueError, match="current validator refused"):
        module.current_validation(
            base / ".worktree/query-current-collector-cce4a4f9b", changed
        )


def test_private_output_is_exclusive_and_mode_0600(tmp_path):
    module = load()
    writer = getattr(module, "write_private_result", None)
    assert writer is not None, "private output writer required"
    path = tmp_path / "comparison.json"
    previous = os.umask(0)
    try:
        writer(path, {"productionExecuted": False})
    finally:
        os.umask(previous)
    assert path.stat().st_mode & 0o777 == 0o600
    assert json.loads(path.read_bytes()) == {"productionExecuted": False}
    with pytest.raises(FileExistsError):
        writer(path, {})
    link = tmp_path / "link.json"
    link.symlink_to(path)
    with pytest.raises(FileExistsError):
        writer(link, {})
    assert json.loads(path.read_bytes()) == {"productionExecuted": False}
