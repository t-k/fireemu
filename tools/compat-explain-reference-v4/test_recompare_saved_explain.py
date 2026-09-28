import importlib.util
import json
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).with_name("recompare_saved_explain.py")
SPEC = importlib.util.spec_from_file_location("recompare_saved_explain", SCRIPT)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def invoke_main(monkeypatch, *, production, original_local, current_local, output):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(SCRIPT),
            "--production",
            str(production),
            "--original-local",
            str(original_local),
            "--current-local",
            str(current_local),
            "--historical-commit",
            "unused",
            "--output",
            str(output),
        ],
    )
    return module.main()


@pytest.fixture
def inputs(tmp_path):
    paths = {}
    for name in ("production", "original-local", "current-local"):
        path = tmp_path / f"{name}.json"
        path.write_bytes(f"{name}-bytes\n".encode())
        paths[name] = path
    return paths


def install_successful_recompare(monkeypatch):
    monkeypatch.setattr(
        module,
        "recompare",
        lambda *_args: {"compatibility": "match", "rows": []},
    )


def test_historical_commit_binding_accepts_matching_receipts():
    commit = "a" * 40

    assert (
        module._validate_historical_commit_binding(
            checkout_commit=commit,
            production_execution_commit=commit,
            original_local_execution_commit=commit,
        )
        is None
    )


def test_historical_commit_binding_rejects_mismatched_receipt():
    checkout_commit = "a" * 40

    with pytest.raises(ValueError, match="production executionCommit"):
        module._validate_historical_commit_binding(
            checkout_commit=checkout_commit,
            production_execution_commit="b" * 40,
            original_local_execution_commit=checkout_commit,
        )


@pytest.mark.parametrize("target", ["existing", "production", "symlink", "hardlink"])
def test_main_rejects_output_that_can_replace_an_input_or_existing_inode(
    monkeypatch, inputs, tmp_path, target
):
    install_successful_recompare(monkeypatch)
    output = tmp_path / "output.json"
    if target == "existing":
        output.write_bytes(b"existing-output\n")
    elif target == "production":
        output = inputs["production"]
    elif target == "symlink":
        sentinel = tmp_path / "sentinel.json"
        sentinel.write_bytes(b"symlink-target\n")
        output.symlink_to(sentinel)
    else:
        output.hardlink_to(inputs["production"])

    before = {name: path.read_bytes() for name, path in inputs.items()}
    existing_output = output.read_bytes() if output.is_file() else None

    with pytest.raises(ValueError, match="output must be a new regular file"):
        invoke_main(
            monkeypatch,
            production=inputs["production"],
            original_local=inputs["original-local"],
            current_local=inputs["current-local"],
            output=output,
        )

    assert {name: path.read_bytes() for name, path in inputs.items()} == before
    if existing_output is not None:
        assert output.read_bytes() == existing_output


def test_main_creates_independent_output_exclusively(monkeypatch, inputs, tmp_path):
    install_successful_recompare(monkeypatch)
    output = tmp_path / "nested" / "result.json"

    assert (
        invoke_main(
            monkeypatch,
            production=inputs["production"],
            original_local=inputs["original-local"],
            current_local=inputs["current-local"],
            output=output,
        )
        == 0
    )
    assert json.loads(output.read_text()) == {"compatibility": "match", "rows": []}

    with pytest.raises(ValueError, match="output must be a new regular file"):
        invoke_main(
            monkeypatch,
            production=inputs["production"],
            original_local=inputs["original-local"],
            current_local=inputs["current-local"],
            output=output,
        )


def test_main_preserves_inputs_when_comparison_fails(monkeypatch, inputs, tmp_path):
    monkeypatch.setattr(module, "recompare", lambda *_args: (_ for _ in ()).throw(ValueError("comparison failed")))
    output = tmp_path / "result.json"
    before = {name: path.read_bytes() for name, path in inputs.items()}

    with pytest.raises(ValueError, match="comparison failed"):
        invoke_main(
            monkeypatch,
            production=inputs["production"],
            original_local=inputs["original-local"],
            current_local=inputs["current-local"],
            output=output,
        )

    assert not output.exists()
    assert {name: path.read_bytes() for name, path in inputs.items()} == before


def test_main_normalizes_relative_input_paths_without_resolving_symlinks(
    monkeypatch, inputs, tmp_path
):
    captured = {}

    def fake_recompare(production, original_local, current_local, historical_commit):
        captured.update(
            production=production,
            original_local=original_local,
            current_local=current_local,
            historical_commit=historical_commit,
        )
        return {"compatibility": "match", "rows": []}

    monkeypatch.setattr(module, "recompare", fake_recompare)
    monkeypatch.chdir(tmp_path)
    for name in ("production", "original-local", "current-local"):
        (tmp_path / f"{name}.json").write_bytes(inputs[name].read_bytes())

    assert (
        invoke_main(
            monkeypatch,
            production=Path("production.json"),
            original_local=Path("original-local.json"),
            current_local=Path("current-local.json"),
            output=Path("result.json"),
        )
        == 0
    )
    assert all(path.is_absolute() for path in captured.values() if isinstance(path, Path))
    assert all(not path.is_symlink() for path in captured.values() if isinstance(path, Path))


def test_main_keeps_relative_symlink_input_rejected(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "production-target.json").write_text("{}")
    (tmp_path / "production.json").symlink_to(tmp_path / "production-target.json")
    (tmp_path / "original-local.json").write_text("{}")
    (tmp_path / "current-local.json").write_text("{}")

    with pytest.raises(ValueError, match="regular JSON file required"):
        invoke_main(
            monkeypatch,
            production=Path("production.json"),
            original_local=Path("original-local.json"),
            current_local=Path("current-local.json"),
            output=Path("result.json"),
        )
