"""The provenance record must be recomputed locally, never trusted from a receipt."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from mfa_provenance import (
    BOUND_PATHS,
    ProvenanceError,
    compute_provenance,
    describe_worktree,
    repository_root,
    verify_binding,
)


def fake_tree(root: Path) -> None:
    for relative in BOUND_PATHS:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"contents of {relative}\n", encoding="utf-8")


def test_no_package_module_shapes_an_observation_without_being_bound() -> None:
    from mfa_provenance import unbound_package_modules

    # A new recorder or comparator cannot be added without binding it. The earlier
    # AUTH-MFA-TOTP-ENROLL-RETRY-01 modules keep the `totp_` prefix and are excluded by
    # name, because they are a separate non-executable package.
    assert unbound_package_modules(repository_root()) == []


def test_the_recorder_that_issues_the_requests_is_bound() -> None:
    assert "tools/compat-broad/auth-totp-enroll/mfa_local_shadow.py" in BOUND_PATHS


def test_every_bound_path_exists_in_this_repository() -> None:
    root = repository_root()
    missing = [relative for relative in BOUND_PATHS if not (root / relative).is_file()]
    assert missing == []
    assert len(set(BOUND_PATHS)) == len(BOUND_PATHS)


def test_provenance_digest_is_reproducible_and_path_sensitive(tmp_path: Path) -> None:
    fake_tree(tmp_path)
    first = compute_provenance(tmp_path)
    assert first == compute_provenance(tmp_path)
    assert set(first["paths"]) == set(BOUND_PATHS)
    assert all(len(value) == 64 for value in first["paths"].values())
    (tmp_path / BOUND_PATHS[0]).write_text("changed\n", encoding="utf-8")
    second = compute_provenance(tmp_path)
    assert second["digest"] != first["digest"]
    assert second["paths"][BOUND_PATHS[0]] != first["paths"][BOUND_PATHS[0]]


def test_a_missing_bound_path_is_refused_rather_than_skipped(tmp_path: Path) -> None:
    fake_tree(tmp_path)
    (tmp_path / BOUND_PATHS[1]).unlink()
    with pytest.raises(ProvenanceError, match="missing"):
        compute_provenance(tmp_path)


def test_a_caller_supplied_binding_is_only_accepted_when_it_is_recomputed(
    tmp_path: Path,
) -> None:
    fake_tree(tmp_path)
    truth = compute_provenance(tmp_path)
    assert verify_binding(truth, tmp_path) is True
    forged = json.loads(json.dumps(truth))
    forged["digest"] = "f" * 64
    assert verify_binding(forged, tmp_path) is False
    forged = json.loads(json.dumps(truth))
    forged["paths"][BOUND_PATHS[0]] = "0" * 64
    assert verify_binding(forged, tmp_path) is False
    dropped = json.loads(json.dumps(truth))
    dropped["paths"].pop(BOUND_PATHS[0])
    assert verify_binding(dropped, tmp_path) is False


def test_verification_refuses_records_that_are_not_shaped_like_provenance(
    tmp_path: Path,
) -> None:
    fake_tree(tmp_path)
    for record in (
        None,
        {},
        [],
        "digest",
        {"digest": "a" * 64},
        {"paths": {}, "digest": "a" * 64},
    ):
        assert verify_binding(record, tmp_path) is False


def test_worktree_description_reports_commit_and_cleanliness() -> None:
    calls: list[list[str]] = []

    def runner(arguments: list[str]) -> str:
        calls.append(arguments)
        if arguments[:2] == ["rev-parse", "HEAD"]:
            return "a" * 40 + "\n"
        if arguments[:2] == ["status", "--porcelain"]:
            return ""
        raise AssertionError(arguments)

    described = describe_worktree(Path("/nowhere"), runner=runner)
    assert described == {"commit": "a" * 40, "clean": True, "resolved": True}
    assert len(calls) == 2


def test_a_dirty_or_unresolvable_worktree_is_reported_honestly() -> None:
    def dirty(arguments: list[str]) -> str:
        return "a" * 40 if arguments[:2] == ["rev-parse", "HEAD"] else " M file\n"

    assert describe_worktree(Path("/nowhere"), runner=dirty)["clean"] is False

    def broken(arguments: list[str]) -> str:
        raise OSError("git is unavailable")

    assert describe_worktree(Path("/nowhere"), runner=broken) == {
        "commit": None,
        "clean": False,
        "resolved": False,
    }


def test_the_real_repository_provenance_can_be_computed() -> None:
    record = compute_provenance(repository_root())
    assert verify_binding(record, repository_root()) is True
    assert record["schema"] == "o2-mfa-provenance-v1"
    assert record["evidence"] == "recomputed-from-worktree"
