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
    dependency_info_in_test_only_trees,
    dependency_info_paths,
    runtime_inputs,
    source_files_including_test_only_trees,
    ui_bundled,
)

FILES = {
    "Cargo.toml": "workspace",
    "Cargo.lock": "lock",
    "rust-toolchain.toml": "toolchain",
    ".cargo/config.toml": "cargo config",
    "crates/a/Cargo.toml": '[package]\nname = "a"\n',
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
TEST_ONLY = {path for path in FILES if path.split("/")[0] == "crates" and path.split("/")[2] in ("tests", "benches", "examples", "proptest-regressions")}   # the directories directly under a crate


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


def guard(tmp_path, files):
    """The guard's report for a repository with `files` added to the fixture's crates (each path relative to the root)."""
    root = repo(tmp_path, {**FILES, **files})
    return source_files_including_test_only_trees(root)


def test_a_one_line_include_of_a_test_only_tree_is_reported(tmp_path):
    assert guard(tmp_path, {"crates/a/src/lib.rs": 'const D: &str = include_str!("../tests/fixtures/data.json");'}) == ["crates/a/src/lib.rs"]
    for text in ('include_bytes!("../benches/x")', 'include!("../examples/e.rs");', 'include_str!("../proptest-regressions/it.txt")'):
        assert guard(tmp_path / text.split("!")[0], {"crates/b/src/main.rs": text}) == ["crates/b/src/main.rs"], text


def test_an_include_whose_path_is_on_another_line_than_its_macro_is_reported(tmp_path):
    source = 'const D: &str = include_str!(\n    concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data.rs"),\n);'
    assert guard(tmp_path, {"crates/a/src/multi.rs": source}) == ["crates/a/src/multi.rs"]
    assert guard(tmp_path / "again", {"crates/a/src/multi.rs": source.replace("tests", "docs")}) == []


def test_other_embedding_macros_and_attributes_are_reported_too(tmp_path):
    for text in ('static D: Dir = include_dir!("$CARGO_MANIFEST_DIR/tests");', '#[derive(RustEmbed)]\n#[folder = "tests/"]\nstruct Assets;', 'embed_file!("../tests/a.bin")'):
        assert guard(tmp_path / str(abs(hash(text))), {"crates/a/src/lib.rs": text}) == ["crates/a/src/lib.rs"], text


def test_a_module_path_into_a_test_only_tree_is_reported_unless_a_positive_test_gate_excuses_it(tmp_path):
    path = '#[path = "../../../tests/support/helper.rs"]\npub(crate) mod helper;'
    assert guard(tmp_path, {"crates/a/src/lib.rs": path}) == ["crates/a/src/lib.rs"]
    for gate in ("#[cfg(test)]", "#[cfg(all(test, unix))]", "#[cfg(all(unix, test))]"):
        assert guard(tmp_path / gate, {"crates/a/src/lib.rs": f"{gate}\n{path}"}) == [], gate
    for gate in ("#[cfg(not(test))]", "#[cfg(any(test, feature = \"fixtures\"))]", "#[cfg(unix)]", "#[cfg(not(all(test, unix)))]", "#[cfg_attr(not(test), path = \"../tests/x.rs\")]"):
        text = f"{gate}\n{path}" if "cfg_attr" not in gate else f"{gate}\nmod x;"
        assert guard(tmp_path / gate, {"crates/a/src/lib.rs": text}) == ["crates/a/src/lib.rs"], gate


def test_an_include_inside_a_test_gated_module_is_excused_and_one_outside_it_is_not(tmp_path):
    inside = '#[cfg(test)]\nmod tests {\n    fn f() {\n        let _ = include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/support/x.rs"));\n    }\n}\n'
    assert guard(tmp_path, {"crates/a/src/lib.rs": inside}) == []
    outside = inside + 'const D: &str = include_str!("../tests/y");\n'
    assert guard(tmp_path / "out", {"crates/a/src/lib.rs": outside}) == ["crates/a/src/lib.rs"]
    before = 'const D: &str = include_str!("../tests/y");\n' + inside
    assert guard(tmp_path / "before", {"crates/a/src/lib.rs": before}) == ["crates/a/src/lib.rs"]
    ungated = inside.replace("#[cfg(test)]\n", "")
    assert guard(tmp_path / "ungated", {"crates/a/src/lib.rs": ungated}) == ["crates/a/src/lib.rs"]
    negated = inside.replace("#[cfg(test)]", "#[cfg(not(test))]")
    assert guard(tmp_path / "negated", {"crates/a/src/lib.rs": negated}) == ["crates/a/src/lib.rs"]


def test_braces_in_strings_and_comments_do_not_end_a_test_module_early(tmp_path):
    body = '#[cfg(test)]\nmod tests {\n    // a stray } in a comment\n    const S: &str = "}";\n    const C: char = \'}\';\n    fn f<\'a>(x: &\'a str) {\n        let _ = include_str!("../../../tests/a");\n    }\n}\n'
    assert guard(tmp_path, {"crates/a/src/lib.rs": body}) == []


def test_a_build_script_that_names_a_test_only_tree_is_reported(tmp_path):
    script = 'fn main() {\n    let data = std::fs::read("tests/data.rs").unwrap();\n    println!("cargo:rerun-if-changed=tests/data.rs");\n}\n'
    assert guard(tmp_path, {"crates/a/build.rs": script}) == ["crates/a/build.rs"]
    assert guard(tmp_path / "ok", {"crates/a/build.rs": "fn main() { println!(\"cargo:rerun-if-changed=build.rs\"); }"}) == []


def test_a_manifest_that_points_a_target_or_the_build_script_into_a_test_only_tree_is_reported(tmp_path):
    for manifest in ('[package]\nname = "a"\nbuild = "tests/build.rs"\n', '[lib]\npath = "tests/lib.rs"\n', '[[bin]]\nname = "a"\npath = "benches/main.rs"\n', '[[bin]]\nname = "a"\npath = "src/../tests/main.rs"\n'):
        assert guard(tmp_path / str(abs(hash(manifest))), {"crates/a/Cargo.toml": manifest}) == ["crates/a/Cargo.toml"], manifest
    # the test, bench and example targets of a crate are the trees themselves: their paths are fine
    assert guard(tmp_path / "targets", {"crates/a/Cargo.toml": '[package]\nname = "a"\n[[bench]]\nname = "b"\npath = "benches/b.rs"\n[[test]]\nname = "t"\npath = "tests/t.rs"\n[lib]\npath = "src/lib.rs"\n'}) == []


def test_a_dependency_info_file_that_lists_a_test_only_tree_is_refused(tmp_path):
    root = repo(tmp_path)
    info = f"{root}/target/debug/fireemu: {root}/crates/a/src/lib.rs {root}/crates/a/tests/it.rs {root}/crates/b/src/main.rs {root}/crates/a/benches/b.rs /elsewhere/registry/src/x.rs\n"
    assert dependency_info_in_test_only_trees(info, root) == ["crates/a/benches/b.rs", "crates/a/tests/it.rs"]
    clean = f"{root}/target/debug/fireemu: {root}/crates/a/src/lib.rs {root}/crates/b/src/main.rs \\\n  {root}/crates/a/src/lib_tests.rs\n"
    assert dependency_info_in_test_only_trees(clean, root) == []
    # a path with an escaped space and a `..` is normalized before it is compared
    assert dependency_info_in_test_only_trees(f"x: {root}/crates/a/src/../tests/it.rs", root) == ["crates/a/tests/it.rs"]


def test_the_paths_a_dependency_info_file_lists_are_the_workspace_files_normalized(tmp_path):
    root = repo(tmp_path)
    info = f"{root}/target/debug/fireemu: {root}/crates/b/src/main.rs {root}/crates/a/src/../src/lib.rs /registry/x.rs {root}/crates/b/src/main.rs\n"
    assert dependency_info_paths(info, root) == ["crates/a/src/lib.rs", "crates/b/src/main.rs"]
    assert dependency_info_paths("", root) == []


def test_a_built_user_interface_bundle_is_noticed(tmp_path):
    root = repo(tmp_path)
    assert ui_bundled(root) is False
    (root / "ui/dist").mkdir(parents=True)
    assert ui_bundled(root) is False   # a directory without its entry page is not a bundle: the build script embeds nothing then
    (root / "ui/dist/index.html").write_text("<html></html>")
    assert ui_bundled(root) is True


def test_no_source_file_of_this_repository_includes_a_test_only_tree():
    assert source_files_including_test_only_trees(ROOT) == []


def test_an_include_with_a_space_before_its_bang_and_one_with_other_brackets_is_reported(tmp_path):
    assert guard(tmp_path / "space", {"crates/a/src/lib.rs": 'const D: &str = include_str !("../tests/x");'}) == ["crates/a/src/lib.rs"]
    assert guard(tmp_path / "square", {"crates/a/src/lib.rs": 'const D: &str = include_str![ "../tests/x" ];'}) == ["crates/a/src/lib.rs"]
    assert guard(tmp_path / "curly", {"crates/a/src/lib.rs": 'const D: &str = include_str!{ "../tests/x" };'}) == ["crates/a/src/lib.rs"]


def test_only_a_gate_that_is_exactly_test_excuses_a_module_path(tmp_path):
    path = '#[path = "../../../tests/support/helper.rs"]\npub(crate) mod helper;'
    for gate in ("#[cfg(testing)]", "#[cfg(test_support)]", '#[cfg(feature = "test")]'):
        assert guard(tmp_path / gate, {"crates/a/src/lib.rs": f"{gate}\n{path}"}) == ["crates/a/src/lib.rs"], gate


def test_a_test_gate_on_the_item_before_does_not_excuse_a_module_path_after_it(tmp_path):
    source = '#[cfg(test)]\nfn helper() {}\n#[path = "../../../tests/support/helper.rs"]\npub(crate) mod helper;'
    assert guard(tmp_path, {"crates/a/src/lib.rs": source}) == ["crates/a/src/lib.rs"]
    gated = '#[cfg(test)]\n#[allow(dead_code)]\n#[path = "../../../tests/support/helper.rs"]\npub(crate) mod helper;'
    assert guard(tmp_path / "ok", {"crates/a/src/lib.rs": gated}) == []   # attributes stacked on the same item


def test_an_include_right_after_a_test_module_is_outside_it(tmp_path):
    source = '#[cfg(test)]\nmod tests {}include_str!("../tests/y");'
    assert guard(tmp_path, {"crates/a/src/lib.rs": source}) == ["crates/a/src/lib.rs"]


def test_a_raw_string_with_braces_and_quotes_does_not_end_a_test_module_early(tmp_path):
    body = '#[cfg(test)]\nmod tests {\n    const S: &str = r#"} "quoted" {"#;\n    fn f() {\n        let _ = include_str!("../../../tests/a");\n    }\n}\n'
    assert guard(tmp_path, {"crates/a/src/lib.rs": body}) == []


def test_a_manifest_that_does_not_parse_is_reported(tmp_path):
    assert guard(tmp_path, {"crates/a/Cargo.toml": "[package\nname = = broken"}) == ["crates/a/Cargo.toml"]


def test_a_build_script_that_names_a_test_only_tree_only_in_a_gated_module_is_still_reported(tmp_path):
    # a build script is never a test build: the gate does not excuse it
    script = '#[cfg(test)]\nmod tests { const P: &str = include_str!("../tests/x"); }\nfn main() {}\n'
    assert guard(tmp_path, {"crates/a/build.rs": script}) == ["crates/a/build.rs"]


def test_a_dependency_info_file_with_continuation_lines_lists_all_of_its_files(tmp_path):
    root = repo(tmp_path)
    info = f"{root}/target/debug/fireemu: {root}/crates/a/src/lib.rs \\\n  {root}/crates/a/tests/it.rs \\\n  {root}/crates/b/src/main.rs\n"
    assert dependency_info_paths(info, root) == ["crates/a/src/lib.rs", "crates/a/tests/it.rs", "crates/b/src/main.rs"]


def test_a_raw_string_that_ends_in_a_backslash_does_not_hide_the_include_after_it(tmp_path):
    # in a raw string a backslash is a character, so `r"\"` is a complete string: the include that follows is code
    source = 'const S: &str = r"\\";\nconst D: &str = include_str!("../tests/y");\n'
    assert guard(tmp_path, {"crates/a/src/lib.rs": source}) == ["crates/a/src/lib.rs"]
