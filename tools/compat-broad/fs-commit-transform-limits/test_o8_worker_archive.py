"""Contract tests for the deterministic O8 production worker archive."""

import hashlib
import importlib.util
import io
import zipfile
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]

_SPEC = importlib.util.spec_from_file_location("o8_bundle", HERE / "o8_bundle.py")
assert _SPEC is not None and _SPEC.loader is not None
o8_bundle = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(o8_bundle)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_worker_closure_names_only_reviewed_repository_sources() -> None:
    assert o8_bundle.WORKER_SOURCES
    for name, member in o8_bundle.WORKER_SOURCES.items():
        assert (ROOT / name).is_file(), name
        assert member.endswith(".py")
        assert "/" not in member
    assert "__main__.py" not in o8_bundle.WORKER_SOURCES.values()
    assert len(set(o8_bundle.WORKER_SOURCES.values())) == len(o8_bundle.WORKER_SOURCES)


def test_worker_archive_adds_exactly_the_fixed_dispatcher(tmp_path: Path) -> None:
    sources = {"witness.py": b"VALUE = 'reviewed'\n"}
    archive, sha = o8_bundle.build_worker_archive(sources)
    assert sha == digest(archive)
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        assert bundle.namelist() == ["__main__.py", "witness.py"]
        assert bundle.read("__main__.py") == o8_bundle.WORKER_DISPATCHER
    # The build is deterministic and independent of mapping order.
    assert (archive, sha) == o8_bundle.build_worker_archive(dict(sources))


def test_worker_archive_refuses_a_caller_supplied_dispatcher() -> None:
    with pytest.raises(ValueError):
        o8_bundle.build_worker_archive({"__main__.py": b"print('hostile')\n"})


def test_worker_archive_from_source_binds_every_frozen_digest(tmp_path: Path) -> None:
    frozen = {
        name: digest((ROOT / name).read_bytes()) for name in o8_bundle.WORKER_SOURCES
    }
    archive, sha = o8_bundle.build_worker_archive_from_source(ROOT, frozen)
    o8_bundle.verify_worker_archive(archive, frozen, sha)
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        assert sorted(bundle.namelist()) == sorted(
            ["__main__.py", *o8_bundle.WORKER_SOURCES.values()]
        )


def test_worker_archive_from_source_refuses_a_changed_or_missing_source(
    tmp_path: Path,
) -> None:
    frozen = {
        name: digest((ROOT / name).read_bytes()) for name in o8_bundle.WORKER_SOURCES
    }
    changed = dict(frozen)
    first = next(iter(changed))
    changed[first] = "0" * 64
    with pytest.raises(ValueError):
        o8_bundle.build_worker_archive_from_source(ROOT, changed)
    incomplete = {name: value for name, value in frozen.items() if name != first}
    with pytest.raises(ValueError):
        o8_bundle.build_worker_archive_from_source(ROOT, incomplete)


def test_verify_worker_archive_rejects_a_replaced_dispatcher(tmp_path: Path) -> None:
    frozen = {
        name: digest((ROOT / name).read_bytes()) for name in o8_bundle.WORKER_SOURCES
    }
    archive, _sha = o8_bundle.build_worker_archive_from_source(ROOT, frozen)
    members = {}
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        for info in bundle.infolist():
            members[info.filename] = bundle.read(info)
    members["__main__.py"] = b"print('replaced')\n"
    replaced = o8_bundle._encode(members)
    with pytest.raises(ValueError):
        o8_bundle.verify_worker_archive(replaced, frozen, digest(replaced))


def test_verify_worker_archive_fd_requires_an_unlinked_read_only_descriptor(
    tmp_path: Path,
) -> None:
    frozen = {
        name: digest((ROOT / name).read_bytes()) for name in o8_bundle.WORKER_SOURCES
    }
    archive, sha = o8_bundle.build_worker_archive_from_source(ROOT, frozen)
    with o8_bundle.unlinked_archive_fd(archive, sha) as fd:
        o8_bundle.verify_worker_archive_fd(fd, sha, frozen)
        with pytest.raises(ValueError):
            o8_bundle.verify_worker_archive_fd(fd, "0" * 64, frozen)
        wrong = dict(frozen)
        wrong[next(iter(wrong))] = "1" * 64
        with pytest.raises(ValueError):
            o8_bundle.verify_worker_archive_fd(fd, sha, wrong)
    linked = tmp_path / "linked.pyz"
    linked.write_bytes(archive)
    import os

    handle = os.open(linked, os.O_RDONLY)
    try:
        with pytest.raises(ValueError):
            o8_bundle.verify_worker_archive_fd(handle, sha, frozen)
    finally:
        os.close(handle)
