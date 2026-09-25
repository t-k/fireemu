"""compat-broad shards are sized by measured duration, and retired suites stay out."""

import json
from pathlib import Path

import pytest

from broad_shards import assign, discover, plan


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
    flat = [path for shard in result["shards"] for path in shard["files"]]
    assert sorted(flat) == discover(repo)
    assert len(flat) == len(set(flat))


def test_a_shard_over_the_budget_is_refused(repo):
    durations = {"tools/compat-broad/lane/test_a.py": 500.0}
    with pytest.raises(ValueError, match="over the 100 s budget"):
        plan(repo, durations, shards=3, budget=100.0, default=10.0)
