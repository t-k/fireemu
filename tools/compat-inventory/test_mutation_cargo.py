"""Exercise real Cargo metadata and output admission without compiling the workspace."""

import subprocess
import sys
from pathlib import Path

import pytest
from mutation_cargo import admit, reject_mutation_artifact


def workspace(path):
    path.mkdir()
    (path / "Cargo.toml").write_text(
        '[package]\nname="guard-fixture"\nversion="0.1.0"\nedition="2021"\n'
    )
    (path / "src").mkdir()
    (path / "src/lib.rs").write_text("pub fn value() -> u8 { 1 }\n")
    subprocess.run(
        ["cargo", "generate-lockfile", "--offline"],
        cwd=path,
        check=True,
        capture_output=True,
    )
    return path


def test_real_metadata_separates_both_directories_and_marks_artifacts(tmp_path):
    normal, mutant = [workspace(tmp_path / p) for p in ["normal", "mutant"]]
    output = tmp_path / "mutation"
    env = admit(normal, mutant, output, ["check", "--offline"])
    assert Path(env["CARGO_TARGET_DIR"]) == output / "target"
    assert Path(env["CARGO_BUILD_BUILD_DIR"]) == output / "build"
    with pytest.raises(ValueError, match="mutation"):
        reject_mutation_artifact(output / "target/debug/fireemu")
    reject_mutation_artifact(normal / "target/debug/fireemu")


@pytest.mark.parametrize("suffix", ["", "/nested", "/../"])
def test_overlapping_output_rejected(tmp_path, suffix):
    normal, mutant = [workspace(tmp_path / p) for p in ["normal", "mutant"]]
    with pytest.raises(ValueError, match="overlap"):
        admit(normal, mutant, Path(str(normal / "target") + suffix), ["check"])


def test_configured_build_directory_and_symlink_are_protected(tmp_path):
    normal, mutant = [workspace(tmp_path / p) for p in ["normal", "mutant"]]
    shared = tmp_path / "intermediate"
    shared.mkdir()
    (normal / ".cargo").mkdir()
    (normal / ".cargo/config.toml").write_text(f'[build]\nbuild-dir="{shared}"\n')
    alias = tmp_path / "alias"
    alias.symlink_to(shared, target_is_directory=True)
    with pytest.raises(ValueError, match="overlap"):
        admit(normal, mutant, alias, ["check"])


@pytest.mark.parametrize(
    "args",
    [
        ["check", "--target-dir=x"],
        ["test", "--config", 'build.build-dir="x"'],
        ["+nightly", "test"],
        ["alias"],
        ["check", "--manifest-path=x"],
    ],
)
def test_output_override_and_alias_rejected_before_cargo(tmp_path, args):
    with pytest.raises(ValueError):
        admit(tmp_path / "absent", tmp_path / "other", tmp_path / "output", args)


def test_cli_refuses_without_running_child(tmp_path):
    normal, mutant = [workspace(tmp_path / p) for p in ["normal", "mutant"]]
    result = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).with_name("mutation_cargo.py")),
            "--normal-workspace",
            str(normal),
            "--mutation-workspace",
            str(mutant),
            "--output-root",
            str(normal / "target"),
            "--",
            "check",
            "--offline",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert not (normal / "target").exists()


def test_cli_compiles_only_in_marked_isolated_outputs(tmp_path):
    normal, mutant = [workspace(tmp_path / p) for p in ["normal", "mutant"]]
    output = tmp_path / "isolated"
    result = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).with_name("mutation_cargo.py")),
            "--normal-workspace",
            str(normal),
            "--mutation-workspace",
            str(mutant),
            "--output-root",
            str(output),
            "--",
            "check",
            "--offline",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert (output / "build").exists()
    assert not (normal / "target").exists()
    assert not (mutant / "target").exists()


def test_previous_normal_artifacts_cannot_be_used_for_mutation(tmp_path):
    normal, mutant = [workspace(tmp_path / p) for p in ["normal", "mutant"]]
    output = tmp_path / "occupied"
    output.mkdir()
    (output / "old-binary").write_bytes(b"normal")
    with pytest.raises(ValueError, match="not owned"):
        admit(normal, mutant, output, ["check"])


def test_normal_build_rejects_marked_intermediate_directory_before_compilation(
    tmp_path,
):
    import os

    from owned_runner import validate_normal_build

    normal = workspace(tmp_path / "normal")
    marked = tmp_path / "mutation"
    marked.mkdir()
    (marked / ".fireemu-mutation-output").write_text("{}")
    (normal / ".cargo").mkdir()
    (normal / ".cargo/config.toml").write_text(f'[build]\nbuild-dir="{marked}/build"\n')
    with pytest.raises(ValueError, match="mutation"):
        validate_normal_build(normal, dict(os.environ))
    assert not (normal / "target").exists()


def test_explicit_binary_rejected_before_execution(tmp_path):
    from owned_runner import run_owned

    marked = tmp_path / "mutation"
    marked.mkdir()
    (marked / ".fireemu-mutation-output").write_text("{}")
    binary = marked / "fireemu"
    binary.write_text("not an executable")
    with pytest.raises(ValueError, match="mutation"):
        run_owned(binary, tmp_path / "receipt")
    assert not (tmp_path / "receipt").exists()


@pytest.mark.parametrize(
    "variable", ["CARGO_TARGET_DIR", "CARGO_BUILD_TARGET_DIR", "CARGO_BUILD_BUILD_DIR"]
)
def test_inherited_output_environment_cannot_be_used_for_mutation(tmp_path, variable):
    import os

    normal, mutant = [workspace(tmp_path / p) for p in ["normal", "mutant"]]
    shared = tmp_path / "shared-output"
    env = {
        k: v
        for k, v in os.environ.items()
        if k
        not in {"CARGO_TARGET_DIR", "CARGO_BUILD_TARGET_DIR", "CARGO_BUILD_BUILD_DIR"}
    }
    env[variable] = str(shared)
    result = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).with_name("mutation_cargo.py")),
            "--normal-workspace",
            str(normal),
            "--mutation-workspace",
            str(mutant),
            "--output-root",
            str(shared),
            "--",
            "check",
            "--offline",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "overlap" in result.stderr
    assert not shared.exists()
