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
