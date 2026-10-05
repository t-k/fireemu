"""The pure parts of the E04 idle replay: the replay table, the rows and the record."""
import pytest

import fs_txn_expiry_idle_replay as tool

TABLE = "x\n        elapsed=90,\ny\n        elapsed=20,\n        elapsed=90,\n        elapsed=0,\n        elapsed=90,\n"


def test_the_three_idle_waits_become_the_measured_idle_and_nothing_else_changes():
    text = tool.replay_cases_text(TABLE)
    assert text.count("elapsed=121,") == 3 and "elapsed=90," not in text
    assert text.replace("elapsed=121,", "elapsed=90,") == TABLE


@pytest.mark.parametrize("text", ["", TABLE.replace("        elapsed=90,\ny", "y"), TABLE + "        elapsed=90,\n", "        elapsed=121,\n" + TABLE])
def test_a_table_that_does_not_have_exactly_three_untouched_waits_is_refused(text):
    with pytest.raises(ValueError, match="exactly three"):
        tool.replay_cases_text(text)


def test_the_replay_copy_is_built_once_and_a_copy_that_differs_is_refused(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    (source / "txn_expiry_cases.py").write_text(TABLE)
    destination = tmp_path / "copy"
    tool.ensure_replay_tools(source, destination)
    assert (destination / "txn_expiry_cases.py").read_text() == tool.replay_cases_text(TABLE)
    assert tool.ensure_replay_tools(source, destination) == destination
    (destination / "txn_expiry_cases.py").write_text(TABLE)
    with pytest.raises(ValueError, match="differs"):
        tool.ensure_replay_tools(source, destination)


def side(code=10, state="created"):
    return {"projection": {"c1": {"code": code}, "c2": {"code": 0}}, "postStates": {"c1": {"state": state}, "c2": {"state": "x"}}}


def test_rows_pair_each_case_and_its_post_state_and_match_when_equal():
    rows = tool.compare_rows(side(), side())
    assert [row["caseId"] for row in rows] == ["c1", "c1#postState", "c2", "c2#postState"] and all(row["match"] for row in rows)


def test_a_different_projection_or_post_state_is_a_mismatch():
    assert [row["match"] for row in tool.compare_rows(side(), side(code=0))] == [False, True, True, True]
    assert [row["match"] for row in tool.compare_rows(side(), side(state="moved"))] == [True, False, True, True]


def test_different_case_inventories_are_refused():
    other = side()
    other["projection"].pop("c2")
    with pytest.raises(ValueError, match="inventories"):
        tool.compare_rows(side(), other)
    other = side()
    other["postStates"].pop("c2")
    with pytest.raises(ValueError, match="inventories"):
        tool.compare_rows(side(), other)


def test_the_local_idles_are_the_measured_ones_of_the_idle_steps_only():
    receipt = {"rows": [{"slot": "a", "idleOfTransaction": "a", "idleSeconds": 121.0}, {"slot": "b", "idleOfTransaction": None, "idleSeconds": None}, {"slot": "c", "idleOfTransaction": "c", "idleSeconds": None}, {"slot": "d"}]}
    assert tool.local_idles(receipt) == {"a": 121.0}


def test_the_record_counts_rows_and_mismatches_and_names_the_artifact():
    ok, bad = tool.compare_rows(side(), side()), tool.compare_rows(side(), side(code=0))
    record = tool.build_record(commit="c" * 40, binary_sha256="b" * 64, recording_digests=["1" * 64, "2" * 64], rows_by_recording=[ok, bad], idles={"idle/commit-after": 121.0}, cases_blob="9" * 40, file_digests={})
    assert record["artifact"] == {"sourceCommit": "c" * 40, "binarySha256": "b" * 64}
    assert record["summary"] == {"recordings": 2, "rows": 8, "mismatches": 1}
    assert [entry["mismatches"] for entry in record["recordings"]] == [0, 1]
    assert record["replay"]["idleWaitSeconds"] == 121 and record["replay"]["localIdleSeconds"] == {"idle/commit-after": 121.0}
    assert record["productionRequests"] == 0 and record["authorizesProduction"] is False


def test_a_case_that_reads_no_document_back_has_no_post_state_row():
    one = {"projection": {"c1": {"code": 10}, "c2": {"code": 0}}, "postStates": {"c1": {"state": "created"}}}
    rows = tool.compare_rows(one, one)
    assert [row["caseId"] for row in rows] == ["c1", "c1#postState", "c2"]


def test_an_existing_replay_copy_must_equal_the_tool_directory_except_for_the_case_table(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    (source / "txn_expiry_cases.py").write_text(TABLE)
    (source / "txn_expiry_shadow.py").write_text("shadow")
    (source / "__pycache__").mkdir()
    (source / "__pycache__" / "x.pyc").write_text("cache")
    destination = tmp_path / "copy"
    tool.ensure_replay_tools(source, destination)
    assert tool.ensure_replay_tools(source, destination) == destination
    # a stale copy of any other module is refused, not silently imported
    (destination / "txn_expiry_shadow.py").write_text("an older shadow")
    with pytest.raises(ValueError, match="differs"):
        tool.ensure_replay_tools(source, destination)
    (destination / "txn_expiry_shadow.py").write_text("shadow")
    # a file the copy lacks, and a file only the copy has, are refused too
    (destination / "extra.py").write_text("extra")
    with pytest.raises(ValueError, match="differs"):
        tool.ensure_replay_tools(source, destination)
    (destination / "extra.py").unlink()
    (destination / "txn_expiry_shadow.py").unlink()
    with pytest.raises(ValueError, match="differs"):
        tool.ensure_replay_tools(source, destination)
    # bytecode caches are not part of the comparison
    (destination / "txn_expiry_shadow.py").write_text("shadow")
    (destination / "__pycache__").mkdir(exist_ok=True)
    (destination / "__pycache__" / "other.pyc").write_text("another cache")
    assert tool.ensure_replay_tools(source, destination) == destination


def test_the_digests_of_the_files_the_replay_ran_are_named(tmp_path):
    directory = tmp_path / "tools"
    directory.mkdir()
    for name in ("txn_expiry_shadow.py", "txn_expiry_comparison.py", "txn_expiry_collector.py", "fs_txn_expiry_idle_replay.py", "txn_expiry_cases.py"):
        (directory / name).write_text(name)
    digests = tool.replayed_file_digests(directory)
    assert sorted(digests) == sorted(tool.REPLAYED_FILES)
    assert digests["txn_expiry_shadow.py"] == __import__("hashlib").sha256(b"txn_expiry_shadow.py").hexdigest()
    (directory / "txn_expiry_collector.py").unlink()
    with pytest.raises(ValueError, match="missing"):
        tool.replayed_file_digests(directory)


def test_the_record_names_the_files_it_ran():
    ok = tool.compare_rows(side(), side())
    record = tool.build_record(commit="c" * 40, binary_sha256="b" * 64, recording_digests=["1" * 64, "2" * 64], rows_by_recording=[ok, ok], idles={}, cases_blob="9" * 40, file_digests={"a.py": "5" * 64})
    assert record["replay"]["fileSha256"] == {"a.py": "5" * 64}


def test_a_tracked_overlay_directory_is_found_from_the_repository_root(tmp_path):
    import subprocess

    def git(*args):
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.test", *args], cwd=tmp_path, check=True, capture_output=True)

    git("init", "-q")
    (tmp_path / "tools/compat-broad/fs-write-txn").mkdir(parents=True)
    (tmp_path / "tools/compat-broad/fs-write-txn/a.py").write_text("x")
    git("add", "-A")
    git("commit", "-q", "-m", "x")
    assert tool.tracked_overlay_paths(tmp_path) == []
    (tmp_path / "tools/compat-broad/fs-write-txn-overlay-p12").mkdir()
    (tmp_path / "tools/compat-broad/fs-write-txn-overlay-p12/a.py").write_text("x")
    git("add", "-A")
    git("commit", "-q", "-m", "overlay")
    assert tool.tracked_overlay_paths(tmp_path) == ["tools/compat-broad/fs-write-txn-overlay-p12/a.py"]


def test_no_runner_built_overlay_directory_is_tracked():
    assert tool.tracked_overlay_paths(tool.HERE.parents[2]) == []
