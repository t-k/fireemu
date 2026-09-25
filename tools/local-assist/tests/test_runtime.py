"""Lock, cache and atomic output creation."""

import os

import pytest
from local_assist.runtime import (
    InferenceLock,
    OutputError,
    cache_get,
    cache_put,
    check_new_output_path,
    write_new_file,
)


def test_the_lock_admits_one_holder_and_is_released(tmp_path):
    first = InferenceLock(tmp_path / "state")
    second = InferenceLock(tmp_path / "state")
    assert first.acquire() is True
    assert second.acquire() is False
    first.release()
    assert second.acquire() is True
    second.release()


def test_output_must_be_a_new_absolute_file_in_an_existing_directory(tmp_path):
    with pytest.raises(OutputError, match="absolute"):
        check_new_output_path("relative.json")
    with pytest.raises(OutputError, match="does not exist"):
        check_new_output_path(str(tmp_path / "missing" / "x.json"))
    taken = tmp_path / "taken.json"
    taken.write_text("{}")
    with pytest.raises(OutputError, match="already exists"):
        check_new_output_path(str(taken))
    os.symlink(tmp_path / "elsewhere.json", tmp_path / "dangling.json")
    with pytest.raises(OutputError, match="already exists"):
        check_new_output_path(str(tmp_path / "dangling.json"))
    assert (
        check_new_output_path(str(tmp_path / "fresh.json")) == tmp_path / "fresh.json"
    )


def test_write_new_file_never_replaces_a_file_that_appeared_in_between(tmp_path):
    target = tmp_path / "result.json"
    write_new_file(target, b"first")
    assert target.read_bytes() == b"first"
    with pytest.raises(OutputError, match="already exists"):
        write_new_file(target, b"second")
    assert target.read_bytes() == b"first"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["result.json"]


def test_cache_round_trip_is_keyed_exactly(tmp_path):
    key = "a" * 64
    assert cache_get(tmp_path, key) is None
    cache_put(tmp_path, key, {"findings": [], "unknowns": [], "usage": {}})
    entry = cache_get(tmp_path, key)
    assert entry["cacheKey"] == key
    assert cache_get(tmp_path, "b" * 64) is None
    # A corrupted or mismatched entry is ignored rather than trusted.
    (tmp_path / "cache" / f"{key}.json").write_text('{"cacheKey": "other"}')
    assert cache_get(tmp_path, key) is None
    (tmp_path / "cache" / f"{key}.json").write_text("not json")
    assert cache_get(tmp_path, key) is None
    with pytest.raises(ValueError):
        cache_get(tmp_path, "../escape")
