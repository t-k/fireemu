"""Durable journals must survive invalid replacement data."""

import json

import pytest
from evidence_common import (
    AGGREGATION_PROBE_FILES_V1,
    ROOT,
    probe_inputs,
    probe_inputs_at_commit,
    read,
    save,
    sha,
)


def test_versioned_aggregation_identity_ignores_unrelated_source_files(tmp_path):
    source = tmp_path / "compat-inventory"
    source.mkdir()
    for name in AGGREGATION_PROBE_FILES_V1:
        (source / name).write_bytes(name.encode())
    (source / "unrelated.py").write_bytes(b"new helper")

    identity = probe_inputs("aggregation-v1", source)

    assert set(identity) == set(AGGREGATION_PROBE_FILES_V1)
    assert identity == {name: sha(name.encode()) for name in AGGREGATION_PROBE_FILES_V1}


def test_historical_aggregation_identity_replays_the_recorded_commit():
    receipt = json.loads(
        (ROOT / "spec/compatibility/evidence/aggregation/local.json").read_bytes()
    )

    assert (
        probe_inputs_at_commit("aggregation-v1", receipt["probeSource"]["commit"])
        == receipt["probeSource"]["files"]
    )


def test_failed_serialization_preserves_previous_recovery_journal(tmp_path):
    path = tmp_path / "receipt.json"
    save(path, {"attempted": ["owned"]})
    with pytest.raises(ValueError):
        save(path, {"bad": float("nan")})
    assert json.loads(path.read_bytes()) == {"attempted": ["owned"]}


def test_bundle_paths_cannot_escape_the_evidence_root(tmp_path):
    root = tmp_path / "bundle"
    root.mkdir()
    outside = tmp_path / "outside.json"
    save(outside, {"private": True})
    (root / "link.json").symlink_to(outside)
    for name in ["../outside.json", str(outside), "link.json"]:
        with pytest.raises(ValueError):
            read(root, name)


# --- the inputs a debug fireemu binary is built from: the runtime inputs without the test-only trees ---

import subprocess

from evidence_common import (
    BINARY_INPUTS_SCHEME,
    binary_inputs,
    binary_inputs_at_commit,
    runtime_inputs,
    source_files_including_test_only_trees,
)

FILES = {
    "Cargo.toml": "workspace",
    "Cargo.lock": "lock",
    "rust-toolchain.toml": "toolchain",
    ".cargo/config.toml": "cargo config",
    "crates/a/Cargo.toml": "crate a",
    "crates/a/build.rs": "build script",
    "crates/a/src/lib.rs": "library",
    "crates/a/src/lib_tests.rs": "a test-only module that stays bound (it may be inline code)",
    "crates/a/src/service/tests/mod.rs": "a directory named tests inside src stays bound too",
    "crates/a/proto/x.proto": "proto",
    "crates/a/tests/it.rs": "integration test",
    "crates/a/tests/fixtures/data.json": "fixture",
    "crates/a/benches/b.rs": "bench",
    "crates/a/examples/e.rs": "example",
    "crates/a/proptest-regressions/it.txt": "regressions",
    "crates/b/src/main.rs": "binary",
    "crates/b/tests/other.rs": "integration test of b",
}
TEST_ONLY = {path for path in FILES if "/tests/" in path or "/benches/" in path or "/examples/" in path or "/proptest-regressions/" in path}


def repo(tmp_path, files=FILES):
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    for command in (["init", "-q"], ["add", "-A"], ["-c", "user.name=t", "-c", "user.email=t@example.test", "commit", "-q", "-m", "x"]):
        subprocess.run(["git", *command], cwd=tmp_path, check=True, capture_output=True)
    return tmp_path


def head(path):
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=path, text=True).strip()


def test_the_binary_inputs_are_the_runtime_inputs_without_the_test_only_trees(tmp_path):
    root = repo(tmp_path)
    assert set(runtime_inputs(root)) == set(FILES)
    assert set(binary_inputs(root)) == set(FILES) - TEST_ONLY
    assert binary_inputs(root) == {name: value for name, value in runtime_inputs(root).items() if name not in TEST_ONLY}
    # a source file that only looks like a test stays bound: it may be inline code of the binary
    assert "crates/a/src/lib_tests.rs" in binary_inputs(root)
    assert "crates/a/src/service/tests/mod.rs" in binary_inputs(root)


def test_a_change_to_a_test_tree_does_not_move_the_binary_inputs_and_any_other_change_does(tmp_path):
    root = repo(tmp_path)
    before = binary_inputs(root)
    for name in sorted(TEST_ONLY):
        (root / name).write_text("changed")
    (root / "crates/a/tests/new.rs").write_text("new integration test")
    assert binary_inputs(root) == before
    for name in sorted(set(FILES) - TEST_ONLY):
        (root / name).write_text("changed")
        assert binary_inputs(root) != before, name
        (root / name).write_text(FILES[name])
    (root / "crates/a/src/new.rs").write_text("a new source file")
    assert binary_inputs(root) != before


def test_the_binary_inputs_at_a_commit_equal_those_of_its_checkout(tmp_path):
    root = repo(tmp_path)
    assert binary_inputs_at_commit(head(root), root) == binary_inputs(root)
    assert set(binary_inputs_at_commit(head(root), root)) == set(FILES) - TEST_ONLY


def test_the_binary_inputs_say_which_definition_they_are():
    assert BINARY_INPUTS_SCHEME == "binary-v1"


def test_a_source_file_that_includes_a_test_only_tree_is_reported(tmp_path):
    files = {**FILES, "crates/a/src/lib.rs": 'const D: &str = include_str!("../tests/fixtures/data.json");'}
    root = repo(tmp_path, files)
    assert source_files_including_test_only_trees(root) == ["crates/a/src/lib.rs"]
    for text in ('include_bytes!("../benches/x")', '#[path = "../examples/e.rs"] mod e;', 'include!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/x.rs"))', "include_str!(\"../proptest-regressions/it.txt\")"):
        other = tmp_path / "crates/b/src/main.rs"
        other.write_text(text)
        assert "crates/b/src/main.rs" in source_files_including_test_only_trees(root)
    # a module path gated on a test build is that build's own
    other.write_text('#[cfg(all(test, unix))]\n#[path = "../../../tests/support/helper.rs"]\npub(crate) mod helper;')
    assert "crates/b/src/main.rs" not in source_files_including_test_only_trees(root)
    # but a gate that is not about tests does not excuse it
    other.write_text('#[cfg(unix)]\n#[path = "../../../tests/support/helper.rs"]\npub(crate) mod helper;')
    assert "crates/b/src/main.rs" in source_files_including_test_only_trees(root)
    other.write_text('include_str!("generated/UPSTREAM_COMMIT"); // tests are fine to mention')
    assert "crates/b/src/main.rs" not in source_files_including_test_only_trees(root)


def test_no_source_file_of_this_repository_includes_a_test_only_tree():
    assert source_files_including_test_only_trees(ROOT) == []
