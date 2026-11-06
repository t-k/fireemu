"""Tests for candidate compiled-input collection."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[2] / "compat-inventory"))
from evidence_common import binary_inputs
from txn_binary_inputs import txn_binary_inputs


def workspace(tmp_path):
    root = tmp_path / "workspace"
    (root / "crates/fireemu/src").mkdir(parents=True)
    (root / "crates/unlinked/src").mkdir(parents=True)
    (root / "crates/fireemu/Cargo.toml").write_text(
        '[package]\nname="fireemu"\nversion="0.1.0"\nedition="2021"\n'
    )
    (root / "crates/fireemu/src/main.rs").write_text("fn main() {}\n")
    (root / "crates/fireemu/src/unit_tests.rs").write_text("#[test] fn test_it() {}\n")
    (root / "crates/unlinked/Cargo.toml").write_text(
        '[package]\nname="unlinked"\nversion="0.1.0"\nedition="2021"\n'
    )
    (root / "crates/unlinked/src/lib.rs").write_text("pub fn unused() {}\n")
    (root / "Cargo.toml").write_text(
        '[workspace]\nmembers=["crates/fireemu", "crates/unlinked"]\nresolver="2"\n'
    )
    (root / "Cargo.lock").write_text("version = 3\n")
    subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    return root


def test_legacy_binary_inputs_retains_src_test_and_unlinked_crate(tmp_path):
    """Pin the legacy false invalidation before replacing it with candidate collection."""
    root = workspace(tmp_path)
    inputs = binary_inputs(root)
    assert "crates/fireemu/src/unit_tests.rs" in inputs
    assert "crates/unlinked/src/lib.rs" in inputs


def test_candidate_omits_uncompiled_src_test_and_unlinked_package_but_keeps_main(tmp_path):
    root = workspace(tmp_path)
    dep_info = "target/debug/fireemu: crates/fireemu/src/main.rs\n"
    before = txn_binary_inputs(root, dep_info)
    (root / "crates/fireemu/src/unit_tests.rs").write_text("#[test] fn changed() {}\n")
    (root / "crates/unlinked/src/lib.rs").write_text("pub fn changed() {}\n")
    inputs = txn_binary_inputs(root, dep_info)
    assert inputs == before
    assert "crates/fireemu/src/unit_tests.rs" not in inputs
    assert "crates/unlinked/src/lib.rs" not in inputs
    assert "crates/fireemu/src/main.rs" in inputs
    assert "Cargo.lock" in inputs


def test_compiled_product_path_is_bound_even_when_other_sources_are_excluded(tmp_path):
    root = workspace(tmp_path)
    (root / "crates/fireemu/src/product.rs").write_text("pub fn product() {}\n")
    dep_info = "target/debug/fireemu: crates/fireemu/src/main.rs crates/fireemu/src/product.rs\n"
    before = txn_binary_inputs(root, dep_info)
    assert "crates/fireemu/src/product.rs" in before
    (root / "crates/fireemu/src/product.rs").write_text("pub fn product_changed() {}\n")
    inputs = txn_binary_inputs(root, dep_info)
    assert inputs["crates/fireemu/src/product.rs"] != before["crates/fireemu/src/product.rs"]
    assert "crates/fireemu/src/unit_tests.rs" not in inputs


def test_all_dep_info_rules_bind_later_compiled_sources(tmp_path):
    root = workspace(tmp_path)
    product = root / "crates/fireemu/src/product.rs"
    product.write_text("pub fn product() {}\n")
    dep_info = (
        "target/debug/fireemu: crates/fireemu/src/main.rs\n"
        "target/debug/libproduct.rlib: crates/fireemu/src/product.rs\n"
        "crates/fireemu/src/product.rs:\n"
        "# env-dep:FEATURE=1\n"
    )
    before = txn_binary_inputs(root, dep_info)
    assert "crates/fireemu/src/product.rs" in before
    product.write_text("pub fn product_changed() {}\n")
    after = txn_binary_inputs(root, dep_info)
    assert after["crates/fireemu/src/product.rs"] != before["crates/fireemu/src/product.rs"]


def test_dep_info_includes_compiled_test_tree_file_and_escaped_space_path(tmp_path):
    root = workspace(tmp_path)
    compiled = root / "crates/fireemu/tests/fixture data.rs"
    compiled.parent.mkdir()
    compiled.write_text("pub const INPUT: &str = \"test\";\n")
    inputs = txn_binary_inputs(root, "target/debug/fireemu: crates/fireemu/src/main.rs crates/fireemu/tests/fixture\\ data.rs\n")
    assert "crates/fireemu/tests/fixture data.rs" in inputs


def test_lock_and_reachable_non_rust_asset_edits_change_candidate_map(tmp_path):
    root = workspace(tmp_path)
    asset = root / "crates/fireemu/config/default.json"
    asset.parent.mkdir()
    asset.write_text("{}\n")
    dep_info = "target/debug/fireemu: crates/fireemu/src/main.rs\n"
    before = txn_binary_inputs(root, dep_info)
    asset.write_text('{"changed":true}\n')
    asset_changed = txn_binary_inputs(root, dep_info)
    assert asset_changed["crates/fireemu/config/default.json"] != before["crates/fireemu/config/default.json"]
    (root / "Cargo.lock").write_text("version = 3\n# changed\n")
    lock_changed = txn_binary_inputs(root, dep_info)
    assert lock_changed["Cargo.lock"] != asset_changed["Cargo.lock"]


def test_deleted_compiled_input_is_rejected(tmp_path):
    root = workspace(tmp_path)
    source = root / "crates/fireemu/src/product.rs"
    source.write_text("pub fn product() {}\n")
    dep_info = "target/debug/fireemu: crates/fireemu/src/main.rs crates/fireemu/src/product.rs\n"
    txn_binary_inputs(root, dep_info)
    source.unlink()
    with pytest.raises(ValueError, match="input is missing"):
        txn_binary_inputs(root, dep_info)


def test_missing_lock_is_rejected(tmp_path):
    root = workspace(tmp_path)
    (root / "Cargo.lock").unlink()
    with pytest.raises(ValueError, match="Cargo input is missing"):
        txn_binary_inputs(root, "target/debug/fireemu: crates/fireemu/src/main.rs\n")


@pytest.mark.parametrize("dep_info", ["", "target/debug/fireemu", "target/debug/fireemu: ", "bad\\", "target: input\nmalformed"])
def test_malformed_or_empty_dep_info_fails_closed(tmp_path, dep_info):
    with pytest.raises(ValueError):
        txn_binary_inputs(workspace(tmp_path), dep_info)


def test_main_is_required_even_when_dep_info_names_other_inputs(tmp_path):
    root = workspace(tmp_path)
    (root / "crates/fireemu/src/main.rs").unlink()
    with pytest.raises(ValueError):
        txn_binary_inputs(root, "target/debug/fireemu: crates/unlinked/src/lib.rs\n")


def test_build_script_inventory_cannot_substitute_for_main_in_dep_info(tmp_path):
    root = workspace(tmp_path)
    (root / "crates/fireemu/build.rs").write_text("fn main() {}\n")
    (root / "crates/fireemu/src/other.rs").write_text("pub fn other() {}\n")
    with pytest.raises(ValueError, match="dep-info does not include"):
        txn_binary_inputs(root, "target/debug/fireemu: Cargo.lock\n")


def test_build_sensitive_package_binds_test_tree_rust_and_assets(tmp_path):
    root = workspace(tmp_path)
    (root / "crates/fireemu/build.rs").write_text("fn main() {}\n")
    test_asset = root / "crates/fireemu/tests/build-input.json"
    test_asset.parent.mkdir()
    test_asset.write_text("{}\n")
    inputs = txn_binary_inputs(root, "target/debug/fireemu: crates/fireemu/src/main.rs\n")
    assert "crates/fireemu/build.rs" in inputs
    assert "crates/fireemu/tests/build-input.json" in inputs
    assert "crates/fireemu/src/unit_tests.rs" in inputs


def test_ignored_workspace_file_is_not_bound(tmp_path):
    root = workspace(tmp_path)
    ignored = root / "crates/fireemu/private.json"
    ignored.write_text("ignored\n")
    (root / ".gitignore").write_text("/crates/fireemu/private.json\n")
    inputs = txn_binary_inputs(root, "target/debug/fireemu: crates/fireemu/src/main.rs\n")
    assert "crates/fireemu/private.json" not in inputs


def test_unavailable_metadata_fails_closed(tmp_path, monkeypatch):
    root = workspace(tmp_path)

    def unavailable(*args, **kwargs):
        raise subprocess.CalledProcessError(1, args[0], stderr="metadata unavailable")

    monkeypatch.setattr("txn_binary_inputs.subprocess.run", unavailable)
    with pytest.raises(ValueError, match="Cargo metadata is unavailable"):
        txn_binary_inputs(root, "target/debug/fireemu: crates/fireemu/src/main.rs\n")


def test_external_local_path_dependency_is_rejected(tmp_path):
    root = workspace(tmp_path)
    outside = tmp_path / "outside"
    (outside / "src").mkdir(parents=True)
    (outside / "Cargo.toml").write_text('[package]\nname="outside"\nversion="0.1.0"\nedition="2021"\n')
    (outside / "src/lib.rs").write_text("pub fn external() {}\n")
    (root / "crates/fireemu/Cargo.toml").write_text(
        '[package]\nname="fireemu"\nversion="0.1.0"\nedition="2021"\n'
        '[dependencies]\noutside={path="../../../outside"}\n'
    )
    subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=root, check=True, capture_output=True)
    with pytest.raises(ValueError, match="outside the workspace"):
        txn_binary_inputs(root, "target/debug/fireemu: crates/fireemu/src/main.rs\n")


def test_workspace_inputs_are_bound_to_manifest_and_exclude_dev_only_path_edges(tmp_path):
    root = workspace(tmp_path)
    for package, source in (("normal", "normal.rs"), ("devonly", "devonly.rs")):
        package_root = root / "crates" / package
        (package_root / "src").mkdir(parents=True)
        (package_root / "Cargo.toml").write_text(
            f'[package]\nname="{package}"\nversion="0.1.0"\nedition="2021"\n'
        )
        (package_root / "src/lib.rs").write_text("pub fn value() {}\n")
    (root / "crates/normal/build.rs").write_text("fn main() { let _ = include_str!(\"build-input.txt\"); }\n")
    (root / "crates/normal/build-input.txt").write_text("optional build input\n")
    optional_test_input = root / "crates/normal/tests/build-test-input.txt"
    optional_test_input.parent.mkdir()
    optional_test_input.write_text("retained conservatively\n")
    (root / "crates/fireemu/Cargo.toml").write_text(
        '[package]\nname="fireemu"\nversion="0.1.0"\nedition="2021"\n'
        '[dependencies.alias]\npackage="normal"\npath="../normal"\noptional=true\n'
        '[dev-dependencies]\ndevonly={path="../devonly"}\n'
    )
    (root / "Cargo.toml").write_text(
        '[workspace]\nmembers=["crates/fireemu", "crates/unlinked", "crates/normal", "crates/devonly"]\nresolver="2"\n'
    )
    subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=root, check=True, capture_output=True)
    inputs = txn_binary_inputs(root, "target/debug/fireemu: crates/fireemu/src/main.rs\n")
    assert "crates/normal/Cargo.toml" in inputs
    assert "crates/normal/src/lib.rs" in inputs
    assert "crates/normal/build.rs" in inputs
    assert "crates/normal/build-input.txt" in inputs
    assert "crates/normal/tests/build-test-input.txt" in inputs
    assert "crates/devonly/Cargo.toml" not in inputs


def test_real_cargo_dep_info_omits_a_source_reachable_only_under_cfg_test(tmp_path):
    root = workspace(tmp_path)
    normal = root / "crates/normal"
    (normal / "src").mkdir(parents=True)
    (normal / "Cargo.toml").write_text('[package]\nname="normal"\nversion="0.1.0"\nedition="2021"\n')
    (normal / "src/lib.rs").write_text("pub fn value() {}\n")
    (root / "crates/fireemu/Cargo.toml").write_text(
        '[package]\nname="fireemu"\nversion="0.1.0"\nedition="2021"\n'
        '[dependencies]\nnormal={path="../normal"}\n'
    )
    (root / "Cargo.toml").write_text(
        '[workspace]\nmembers=["crates/fireemu", "crates/unlinked", "crates/normal"]\nresolver="2"\n'
    )
    subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=root, check=True, capture_output=True)
    (root / "crates/fireemu/src/main.rs").write_text(
        '#[cfg(test)]\nmod unit_tests;\nfn main() { normal::value(); }\n'
    )
    (root / "crates/fireemu/src/unit_tests.rs").write_text("#[test] fn test_only() {}\n")
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(root / "target")
    subprocess.run(
        ["cargo", "build", "--offline", "--locked", "--bin", "fireemu", "--manifest-path", str(root / "Cargo.toml")],
        cwd=root, env=env, check=True, capture_output=True, text=True,
    )
    depfiles = list((root / "target/debug/deps").glob("*.d"))
    assert any(path.name.startswith("fireemu-") for path in depfiles)
    assert any(path.name.startswith("normal-") for path in depfiles)
    dep_info = "\n".join(path.read_text() for path in depfiles)
    inputs = txn_binary_inputs(root, dep_info)
    assert "crates/fireemu/src/main.rs" in inputs
    assert "crates/fireemu/src/unit_tests.rs" not in inputs
    assert "crates/normal/src/lib.rs" in inputs
    source = root / "crates/normal/src/lib.rs"
    source.write_text("pub fn value_changed() {}\n")
    after = txn_binary_inputs(root, dep_info)
    assert after["crates/normal/src/lib.rs"] != inputs["crates/normal/src/lib.rs"]


def test_metadata_requires_offline_locked_no_deps_workspace(tmp_path):
    root = workspace(tmp_path)
    result = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--offline", "--locked", "--format-version", "1", "--manifest-path", str(root / "Cargo.toml")],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(result.stdout)["workspace_members"]
