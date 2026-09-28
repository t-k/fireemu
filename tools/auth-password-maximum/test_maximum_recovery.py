"""Real private-file checks protect the bootstrap-to-verified identity boundary."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from maximum_contract import CASES, complete
from maximum_recorder import PROJECT, recovery_identity, save


def journal():
    return {
        "project": PROJECT,
        "email": "fireemu-basic-" + "a" * 32 + "@example.test",
        "marker": "fireemu-owned-" + "b" * 48,
        "creationAttempted": True,
    }


def test_private_verified_identity_round_trip(tmp_path):
    value = journal()
    path = tmp_path / "recovery.json"
    save(path, value)
    assert recovery_identity(path) == (value, None)
    save(tmp_path / "verified-account.json", {**value, "uid": "verified-uid"})
    assert recovery_identity(path) == (value, "verified-uid")
    with pytest.raises(FileExistsError):
        save(tmp_path / "verified-account.json", {**value, "uid": "replacement"})


@pytest.mark.parametrize(
    "change",
    [
        {"email": "other"},
        {"marker": "other"},
        {"project": "other"},
        {"uid": ""},
        {"uid": True},
        {"uid": "a" * 129},
    ],
)
def test_verified_identity_disagreement_is_rejected(tmp_path, change):
    value = journal()
    save(tmp_path / "recovery.json", value)
    save(tmp_path / "verified-account.json", {**value, "uid": "verified-uid", **change})
    with pytest.raises(ValueError):
        recovery_identity(tmp_path / "recovery.json")


def test_nonprivate_or_symlinked_identity_is_rejected(tmp_path):
    value = journal()
    save(tmp_path / "recovery.json", value)
    saved = tmp_path / "verified-account.json"
    save(saved, {**value, "uid": "verified-uid"})
    saved.chmod(0o644)
    with pytest.raises(ValueError):
        recovery_identity(tmp_path / "recovery.json")
    saved.chmod(0o600)
    linked = tmp_path / "linked"
    linked.mkdir()
    save(linked / "recovery.json", value)
    (linked / "verified-account.json").symlink_to(saved)
    with pytest.raises(ValueError):
        recovery_identity(linked / "recovery.json")


def test_execution_failure_is_distinct_from_semantic_mismatch():
    report = {
        "status": "failed",
        "cases": [{"id": name, "passed": False} for name in CASES],
        "cleanup": {"uidAbsent": True, "emailAbsent": True},
    }
    assert complete(report)
    for key in ["failure", "cleanupFailure", "childCleanupFailure"]:
        assert not complete({**report, key: "failure"})
    assert not complete({**report, "cleanup": {"emailAbsent": True}})


def test_cleanup_identity_is_persisted_and_rechecked_before_deletion(tmp_path):
    import maximum_recorder as recorder

    assert hasattr(recorder, "persist_cleanup_identity"), (
        "Automatic cleanup needs durable UID before DELETE"
    )
    value = journal()
    path = tmp_path / "recovery.json"
    save(path, value)
    recorder.persist_cleanup_identity(path, value["email"], value["marker"], "owned")
    assert recovery_identity(path) == (value, "owned")
    recorder.persist_cleanup_identity(path, value["email"], value["marker"], "owned")
    with pytest.raises(ValueError):
        recorder.persist_cleanup_identity(
            path, value["email"], value["marker"], "replacement"
        )
    with pytest.raises(ValueError):
        recorder.persist_cleanup_identity(path, "other", value["marker"], "owned")
