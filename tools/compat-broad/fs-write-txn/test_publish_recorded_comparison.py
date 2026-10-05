"""The publisher refuses anything it cannot vouch for: an incomplete or mismatching replay, replays on different artifacts, a replay of another file, recordings that
disagree, and a published record that carries an identity of the run."""

import copy
import hashlib
import json

import pytest

import publish_recorded_comparison as publish

NONCE, OWNER, TOKEN = "a" * 32, "b" * 32, "tok-" + "c" * 20


def recording(n):
    return {"nonce": NONCE, "ownerId": OWNER, "n": n}


def write(tmp_path, n):
    path = tmp_path / f"recording-{n}.json"
    path.write_text(json.dumps(recording(n)))
    return path


def result(path, **overrides):
    value = {
        "metadata": {"commit": "1" * 40, "binary_sha256": "2" * 64, "profile": "strict", "compareToolSha256": "3" * 64, "clock": "real",
                     "productionFileSha256": hashlib.sha256(path.read_bytes()).hexdigest(), "program": "P", "planCorpusDigest": "4" * 64, "productionCorpusDigest": "4" * 64},
        "complete": True, "failure": None, "mismatches": 0,
        "cases": [{"caseId": "c", "production": {"code": 0, "details": ""}, "local": {"code": 0, "details": ""}, "match": True}],
        "reads": [{"site": "r", "production": {"code": 0}, "local": {"code": 0}, "match": True}],
    }
    value.update(overrides)
    return value


def projection(**overrides):
    value = {"program": "P", "packetName": "p", "corpusDigest": "4" * 64, "cases": [{"caseId": "c", "code": 0}], "reads": [], "tokens": {}, "cleanup": {"absent": True}}
    value.update(overrides)
    return value


def build(tmp_path, results=None, projections=None, paths=None):
    paths = paths or [write(tmp_path, 1), write(tmp_path, 2)]
    results = results or [result(path) for path in paths]
    return publish.build(program="P", key="p01", conditions=["FS-TRANSACTION/x"], recordings=paths, results=results,
                         projections=projections or [projection(), projection()], identities=[NONCE, OWNER, TOKEN])


def test_two_complete_matching_replays_on_one_artifact_are_published(tmp_path):
    observations, comparison = build(tmp_path)
    assert comparison["summary"] == {"recordings": 2, "rows": 4, "mismatches": 0}
    assert comparison["artifact"] == {"sourceCommit": "1" * 40, "binarySha256": "2" * 64}
    assert observations["corpora"][0]["agree"] is True
    assert observations["condition"] == ["FS-TRANSACTION/x"]


@pytest.mark.parametrize("override", [{"complete": False}, {"mismatches": 1}, {"mismatches": None}])
def test_an_incomplete_or_mismatching_replay_is_refused(tmp_path, override):
    paths = [write(tmp_path, 1), write(tmp_path, 2)]
    results = [result(paths[0]), result(paths[1], **override)]
    with pytest.raises(ValueError):
        build(tmp_path, results=results, paths=paths)


def test_replays_on_different_artifacts_or_tools_are_refused(tmp_path):
    paths = [write(tmp_path, 1), write(tmp_path, 2)]
    for key, other in (("commit", "9" * 40), ("binary_sha256", "9" * 64), ("compareToolSha256", "9" * 64), ("profile", "emulator")):
        results = [result(paths[0]), result(paths[1])]
        results[1]["metadata"][key] = other
        with pytest.raises(ValueError):
            build(tmp_path, results=results, paths=paths)


def test_a_replay_of_another_production_file_is_refused(tmp_path):
    paths = [write(tmp_path, 1), write(tmp_path, 2)]
    results = [result(paths[0]), result(paths[1])]
    results[1]["metadata"]["productionFileSha256"] = "9" * 64
    with pytest.raises(ValueError):
        build(tmp_path, results=results, paths=paths)


def test_recordings_whose_projections_differ_are_refused(tmp_path):
    with pytest.raises(ValueError):
        build(tmp_path, projections=[projection(), projection(cases=[{"caseId": "c", "code": 10}])])


def test_a_published_record_that_carries_an_identity_of_the_run_is_refused(tmp_path):
    leaky = projection(cases=[{"caseId": "c", "code": 0, "details": f"owner {OWNER}"}])
    with pytest.raises(ValueError):
        build(tmp_path, projections=[leaky, copy.deepcopy(leaky)])


def test_the_replay_clock_is_recorded_and_must_agree(tmp_path):
    paths = [write(tmp_path, 1), write(tmp_path, 2)]
    results = [result(paths[0], metadata={**result(paths[0])["metadata"], "clock": "virtual"}), result(paths[1])]
    with pytest.raises(ValueError):
        build(tmp_path, results=results, paths=paths)


def git(repo, *args):
    import subprocess

    env = {"PATH": "/usr/bin:/bin", "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True, env=env).stdout.strip()


def commit_files(repo, files, parent=None):
    """A commit made with plumbing (write-tree and commit-tree), so the fixture does not depend on the user's commit settings."""
    for name, text in files.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(text)
    git(repo, "add", "-A")
    tree = git(repo, "write-tree")
    commit = git(repo, "commit-tree", tree, *(["-p", parent] if parent else []), "-m", "fixture")
    git(repo, "update-ref", "HEAD", commit)
    return commit


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q")
    first = commit_files(root, {"tools/table.py": "v1\n"})
    commit_files(root, {"tools/table.py": "v2\n"}, parent=first)
    return root, first


def test_an_as_recorded_file_is_named_by_commit_blob_and_digest(repo, tmp_path):
    root, first = repo
    used = tmp_path / "table.py"
    used.write_text("v1\n")
    entry = publish.as_recorded_entry(root, "tools/table.py", first, used)
    assert entry == {"path": "tools/table.py", "commit": first, "blob": git(root, "rev-parse", f"{first}:tools/table.py"), "sha256": hashlib.sha256(b"v1\n").hexdigest()}


def test_a_replayed_file_that_is_not_the_committed_one_is_refused(repo, tmp_path):
    root, first = repo
    used = tmp_path / "table.py"
    used.write_text("v1 edited\n")
    with pytest.raises(ValueError):
        publish.as_recorded_entry(root, "tools/table.py", first, used)


def test_a_commit_that_is_not_in_the_history_is_refused(repo, tmp_path):
    root, first = repo
    head = git(root, "rev-parse", "HEAD")
    # a commit on the side: made from the first one, never reachable from HEAD
    side = commit_files(root, {"tools/table.py": "side\n"}, parent=first)
    git(root, "update-ref", "HEAD", head)
    used = tmp_path / "table.py"
    used.write_text("side\n")
    with pytest.raises(ValueError):
        publish.as_recorded_entry(root, "tools/table.py", side, used)


def test_the_as_recorded_files_are_published_with_the_comparison(tmp_path):
    paths = [write(tmp_path, 1), write(tmp_path, 2)]
    entry = {"path": "tools/table.py", "commit": "d" * 40, "blob": "e" * 40, "sha256": "f" * 64}
    _observations, comparison = publish.build(program="P", key="p01", conditions=["FS-TRANSACTION/x"], recordings=paths, results=[result(path) for path in paths],
                                              projections=[projection(), projection()], identities=[NONCE], as_recorded=[entry])
    assert comparison["asRecorded"] == [entry]


def test_fewer_than_two_projections_are_refused_as_a_value_error(tmp_path):
    paths = [write(tmp_path, 1), write(tmp_path, 2)]
    with pytest.raises(ValueError, match="two recordings"):
        publish.build(program="P", key="p01", conditions=["FS-TRANSACTION/x"], recordings=paths, results=[result(path) for path in paths], projections=[projection()], identities=[NONCE])


def test_a_replay_with_a_failure_is_refused_even_when_it_says_complete(tmp_path):
    paths = [write(tmp_path, 1), write(tmp_path, 2)]
    with pytest.raises(ValueError):
        build(tmp_path, results=[result(paths[0]), result(paths[1], failure="ValueError")], paths=paths)


def test_a_replay_whose_plan_is_not_the_recordings_corpus_is_refused(tmp_path):
    paths = [write(tmp_path, 1), write(tmp_path, 2)]
    other = result(paths[1])
    other["metadata"]["planCorpusDigest"] = "5" * 64
    with pytest.raises(ValueError):
        build(tmp_path, results=[result(paths[0]), other], paths=paths)


def test_a_missing_identity_is_ignored_rather_than_matched(tmp_path):
    paths = [write(tmp_path, 1), write(tmp_path, 2)]
    publish.build(program="P", key="p01", conditions=["FS-TRANSACTION/x"], recordings=paths, results=[result(path) for path in paths], projections=[projection(), projection()],
                  identities=[None, "", NONCE])


def test_the_records_authorize_no_production_request_and_number_the_recordings(tmp_path):
    observations, comparison = build(tmp_path)
    assert observations["authorizesProduction"] is False and comparison["authorizesProduction"] is False
    assert comparison["productionRequests"] == 0
    assert [entry["recording"] for entry in comparison["recordings"]] == [1, 2]


def test_the_ages_each_replay_reached_are_published_beside_its_rows(tmp_path):
    paths = [write(tmp_path, 1), write(tmp_path, 2)]
    ages = [{"site": "w", "production": 121.0, "local": 121.0, "difference": 0.0}]
    results = [result(paths[0], achievedAges=ages), result(paths[1])]
    _observations, comparison = build(tmp_path, results=results, paths=paths)
    assert comparison["recordings"][0]["achievedAges"] == ages
    assert "achievedAges" not in comparison["recordings"][1]
    assert comparison["summary"] == {"recordings": 2, "rows": 4, "mismatches": 0}   # ages are not rows


def test_a_table_file_that_was_replayed_as_recorded_is_named_once_by_its_as_recorded_entry(tmp_path):
    paths = [write(tmp_path, 1), write(tmp_path, 2)]
    table = {"path": "tools/compat-broad/fs-write-txn/fs_txn_table_p12.py", "sha256": "5" * 64}
    entry = {"path": table["path"], "commit": "6" * 40, "blob": "7" * 40, "sha256": "8" * 64}
    kwargs = dict(program="P", key="p12", conditions=["FS-TRANSACTION/x"], recordings=paths, results=[result(path) for path in paths], projections=[projection(), projection()], identities=[])
    _o, replayed = publish.build(table=table, as_recorded=[entry], **kwargs)
    assert "table" not in replayed and replayed["asRecorded"] == [entry]
    # a table the replay used as committed, and one beside a different as-recorded file, are named by `table`
    assert publish.build(table=table, **kwargs)[1]["table"] == table
    other = {**entry, "path": "tools/compat-broad/fs-write-txn/other.py"}
    assert publish.build(table=table, as_recorded=[other], **kwargs)[1]["table"] == table


def test_the_token_ages_the_emulator_saw_are_published_beside_the_rows(tmp_path):
    paths = [write(tmp_path, 1), write(tmp_path, 2)]
    ages = [{"site": "late-read", "production": 284.0, "emulator": 283.2, "difference": -0.8, "match": True}]
    _o, comparison = build(tmp_path, results=[result(paths[0], tokenAges=ages), result(paths[1])], paths=paths)
    assert comparison["recordings"][0]["tokenAges"] == ages and "tokenAges" not in comparison["recordings"][1]
    assert comparison["summary"] == {"recordings": 2, "rows": 4, "mismatches": 0}


def test_a_virtual_clock_replay_without_its_age_rows_is_refused_and_an_empty_list_is_kept(tmp_path):
    paths = [write(tmp_path, 1), write(tmp_path, 2)]
    virtual = lambda path, **extra: {**result(path, **extra), "metadata": {**result(path)["metadata"], "clock": "virtual"}}   # noqa: E731
    with pytest.raises(ValueError, match="age"):
        build(tmp_path, results=[virtual(paths[0]), virtual(paths[1], tokenAges=[])], paths=paths)
    _o, comparison = build(tmp_path, results=[virtual(paths[0], tokenAges=[]), virtual(paths[1], tokenAges=[])], paths=paths)
    assert [entry["tokenAges"] for entry in comparison["recordings"]] == [[], []]


def test_a_failed_age_row_is_refused_whatever_the_mismatch_count_says(tmp_path):
    paths = [write(tmp_path, 1), write(tmp_path, 2)]
    failed = [{"site": "late-read", "production": 284.0, "emulator": 260.0, "difference": -24.0, "match": False}]
    with pytest.raises(ValueError, match="age"):
        build(tmp_path, results=[result(paths[0], tokenAges=failed), result(paths[1])], paths=paths)


def test_an_age_row_without_a_match_flag_is_refused_too(tmp_path):
    paths = [write(tmp_path, 1), write(tmp_path, 2)]
    unflagged = [{"site": "late-read", "production": 284.0, "emulator": 284.0, "difference": 0.0}]
    with pytest.raises(ValueError, match="age"):
        build(tmp_path, results=[result(paths[0], tokenAges=unflagged), result(paths[1])], paths=paths)


# ---- a frozen-clock replay (P14): the order and clock rows, and the clock the replay was given ------------------------------------------------------------------

FROZEN = {"clock": "frozen", "clock_start": "2026-10-04T00:00:00Z", "advance_seconds": "3700", "advance_after": "grpc/tv/rollback-unknown"}


def frozen(path, **changes):
    value = result(path, orders=[{"site": "rest/w/writer-ab", "production": "after-anchor", "local": "after-anchor", "match": True}],
                   clock=[{"site": "rest/w/writer-bc", "production": True, "local": True, "match": True}])
    value["metadata"] = {**value["metadata"], **FROZEN, **changes}
    return value


def test_the_order_and_clock_rows_of_a_frozen_replay_are_published_and_counted(tmp_path):
    paths = [write(tmp_path, 1), write(tmp_path, 2)]
    _observations, comparison = build(tmp_path, results=[frozen(paths[0]), frozen(paths[1])], paths=paths)
    assert comparison["summary"]["rows"] == 2 * (2 + 1 + 1)
    for entry in comparison["recordings"]:
        assert entry["orders"][0]["site"] == "rest/w/writer-ab" and entry["clock"][0]["site"] == "rest/w/writer-bc"
    assert comparison["comparer"]["replayClock"] == "frozen"
    assert comparison["comparer"]["replay"] == {"clockStart": "2026-10-04T00:00:00Z", "advanceSeconds": "3700", "advanceAfter": "grpc/tv/rollback-unknown"}


@pytest.mark.parametrize("key", ["clock_start", "advance_seconds", "advance_after"])
def test_the_clock_a_frozen_replay_was_given_must_be_the_same_for_both_recordings(tmp_path, key):
    paths = [write(tmp_path, 1), write(tmp_path, 2)]
    with pytest.raises(ValueError, match="clock"):
        build(tmp_path, results=[frozen(paths[0]), frozen(paths[1], **{key: "other"})], paths=paths)


def test_a_replay_without_a_frozen_clock_publishes_no_replay_block(tmp_path):
    _observations, comparison = build(tmp_path)
    assert comparison["comparer"] == {"sha256": "3" * 64, "replayClock": "real"}
    assert all("orders" not in entry and "clock" not in entry for entry in comparison["recordings"])


def without(value, *keys):
    value["metadata"] = {name: item for name, item in value["metadata"].items() if name not in keys}
    return value


def test_a_frozen_replay_names_its_start_and_advances_by_a_pair_or_not_at_all(tmp_path):
    paths = [write(tmp_path, 1), write(tmp_path, 2)]
    # no start: not a frozen replay anyone can reproduce
    with pytest.raises(ValueError, match="clock"):
        build(tmp_path, results=[without(frozen(paths[0]), "clock_start"), without(frozen(paths[1]), "clock_start")], paths=paths)
    # an advance with no step to follow, or a step with no advance, is half a description
    for key in ("advance_seconds", "advance_after"):
        with pytest.raises(ValueError, match="clock"):
            build(tmp_path, results=[without(frozen(paths[0]), key), without(frozen(paths[1]), key)], paths=paths)
    # a frozen replay that never advanced the clock publishes its start alone
    both = [without(frozen(path), "advance_seconds", "advance_after") for path in paths]
    _observations, comparison = build(tmp_path, results=both, paths=paths)
    assert comparison["comparer"]["replay"] == {"clockStart": "2026-10-04T00:00:00Z"}


@pytest.mark.parametrize("clock", ["real", "virtual"])
def test_a_replay_on_another_clock_that_names_a_frozen_start_or_advance_is_refused(tmp_path, clock):
    paths = [write(tmp_path, 1), write(tmp_path, 2)]
    for extra in ({"clock_start": "2026-10-04T00:00:00Z"}, {"advance_seconds": "3700"}, {"advance_after": "x"}):
        both = [result(path) for path in paths]
        for entry in both:
            entry["metadata"] = {**entry["metadata"], "clock": clock, **extra}
            if clock == "virtual":
                entry["tokenAges"] = []
        with pytest.raises(ValueError, match="frozen"):
            build(tmp_path, results=both, paths=paths)
