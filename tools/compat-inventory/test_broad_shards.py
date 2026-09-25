"""compat-broad shards are sized by measured duration, and retired suites stay out."""

import json
from pathlib import Path

import pytest

from broad_shards import assign, discover, node_ids, plan


def write(root: Path, path: str, text: str = "") -> None:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)


WORKFLOW = """jobs:
  compat-broad-tests:
    env:
      RETIRED_SUITES: |
        tools/compat-broad/old
        tools/compat-broad/lane/test_stale.py
"""


@pytest.fixture
def repo(tmp_path):
    for path in [
        "tools/compat-broad/lane/test_a.py",
        "tools/compat-broad/lane/test_b.py",
        "tools/compat-broad/lane/test_stale.py",
        "tools/compat-broad/old/test_x.py",
        "tools/compat-broad/test_top.py",
        "tools/compat-broad/lane/helper.py",
    ]:
        write(tmp_path, path)
    write(tmp_path, ".github/workflows/compatibility-inventory.yml", WORKFLOW)
    return tmp_path


def test_discovery_excludes_retired_suites_by_file_or_directory(repo):
    assert discover(repo) == [
        "tools/compat-broad/lane/test_a.py",
        "tools/compat-broad/lane/test_b.py",
        "tools/compat-broad/test_top.py",
    ]


def test_assignment_balances_measured_durations_deterministically():
    durations = {"a": 100.0, "b": 60.0, "c": 50.0, "d": 40.0, "e": 10.0}
    shards = assign(list(durations), durations, shards=2, default=5.0)
    assert shards == [["a", "d"], ["b", "c", "e"]]
    assert assign(list(durations), durations, shards=2, default=5.0) == shards


def test_every_file_lands_in_exactly_one_shard(repo):
    durations = {"tools/compat-broad/lane/test_a.py": 30.0}
    result = plan(repo, durations, shards=2, budget=100.0, default=10.0)
    flat = [path for shard in result["shards"] for path in shard["arguments"]]
    assert sorted(flat) == discover(repo)
    assert len(flat) == len(set(flat))


def ids(path, count):
    return [f"{path}::test_{index:02d}" for index in range(count)]


def test_a_file_longer_than_the_split_limit_runs_as_contiguous_test_chunks(repo):
    long = "tools/compat-broad/lane/test_a.py"
    collected = []

    def collect(root, path):
        collected.append(path)
        return ids(path, 11)

    durations = {long: 500.0, "tools/compat-broad/lane/test_b.py": 0.0, "tools/compat-broad/test_top.py": 0.0}
    result = plan(repo, durations, shards=2, budget=400.0, default=10.0, collect=collect)
    assert collected == [long]
    tests = ids(long, 11)
    # 500 s is over the split limit (0.8 * 400 s), so it runs as chunks of about
    # 0.25 * 400 s: five chunks of whole, adjacent tests.
    expected = [tests[0:3], tests[3:5], tests[5:7], tests[7:9], tests[9:11]]
    flat = [argument for shard in result["shards"] for argument in shard["arguments"]]
    assert long not in flat
    assert len(flat) == len(set(flat))
    assert sorted(argument for argument in flat if argument.startswith(long)) == tests
    for chunk in expected:
        assert any(
            shard["arguments"][i : i + len(chunk)] == chunk
            for shard in result["shards"]
            for i in range(len(shard["arguments"]))
        )
    # Each chunk weighs its share of the file's tests: 3/11 and 2/11 of 500 s.
    assert [shard["seconds"] for shard in result["shards"]] == [227.3, 272.7]


def test_a_single_test_over_the_budget_is_refused(repo):
    long = "tools/compat-broad/lane/test_a.py"
    with pytest.raises(ValueError, match="over the 100 s budget"):
        plan(
            repo,
            {long: 500.0},
            shards=3,
            budget=100.0,
            default=10.0,
            collect=lambda root, path: ids(path, 1),
        )


def test_too_few_shards_are_refused(repo):
    durations = {"tools/compat-broad/lane/test_a.py": 70.0, "tools/compat-broad/lane/test_b.py": 70.0}
    with pytest.raises(ValueError, match="over the 100 s budget"):
        plan(repo, durations, shards=1, budget=100.0, default=10.0)


def test_collected_ids_are_rebased_on_the_repository_path():
    # pytest prints IDs relative to its rootdir, which is not the repository root.
    listing = "\n".join(
        [
            "lane/test_a.py::test_one",
            "lane/test_a.py::test_two[x::y]",
            "",
            "2 tests collected in 0.01s",
        ]
    )
    assert node_ids("tools/compat-broad/lane/test_a.py", listing) == [
        "tools/compat-broad/lane/test_a.py::test_one",
        "tools/compat-broad/lane/test_a.py::test_two[x::y]",
    ]
