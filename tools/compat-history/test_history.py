"""Historical checks use real Git data, never receipt-selected executable code."""

import importlib.util
import subprocess
from pathlib import Path

import pytest


def module():
    path = Path(__file__).with_name("history.py")
    assert path.exists(), "Historical integrity runner required"
    spec = importlib.util.spec_from_file_location("history", path)
    assert spec and spec.loader
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args]).decode().strip()


@pytest.fixture
def repository(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q")
    (root / "frozen").mkdir()
    (root / "frozen/receipt.json").write_text('{"sourceCommit":"untrusted"}')
    (root / "runtime.rs").write_text("original runtime")
    git(root, "add", ".")
    git(
        root,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-qm",
        "anchor",
    )
    return root, git(root, "rev-parse", "HEAD")


def test_historical_snapshot_keeps_source_while_current_runtime_changes(repository):
    h = module()
    root, anchor = repository
    (root / "runtime.rs").write_text("patched runtime")
    with h.snapshot(root, anchor, ("frozen",)) as archived:
        assert (archived / "runtime.rs").read_text() == "original runtime"
        assert git(archived, "rev-parse", "HEAD") == anchor
        saved = archived
    assert not saved.exists()
    assert (root / "runtime.rs").read_text() == "patched runtime"


@pytest.mark.parametrize(
    "change", ["edited", "removed", "added", "ignored", "symlink", "parent-symlink"]
)
def test_frozen_membership_and_bytes_cannot_change(repository, change):
    h = module()
    root, anchor = repository
    receipt = root / "frozen/receipt.json"
    if change == "edited":
        receipt.write_text("tampered")
    elif change == "removed":
        receipt.unlink()
    elif change == "added":
        (root / "frozen/new.json").write_text("extra")
    elif change == "ignored":
        (root / "frozen/new.json").write_text("extra")
        (root / ".git/info/exclude").write_text("frozen/new.json\n")
    elif change == "symlink":
        receipt.unlink()
        receipt.symlink_to(root / "runtime.rs")
    else:
        (root / "frozen").rename(root / "elsewhere")
        (root / "frozen").symlink_to(root / "elsewhere", target_is_directory=True)
    with pytest.raises(ValueError):
        h.verify_frozen(root, anchor, ("frozen",))


def test_missing_anchor_fails_before_snapshot(repository):
    h = module()
    root, _ = repository
    with pytest.raises(ValueError), h.snapshot(root, "0" * 40, ("frozen",)):
        pytest.fail("Missing anchor accepted")


@pytest.mark.parametrize("path", ["../runtime.rs", "/tmp/escape", ":(glob)**", ""])
def test_path_selection_is_not_an_escape(repository, path):
    h = module()
    root, anchor = repository
    with pytest.raises(ValueError):
        h.verify_frozen(root, anchor, (path,))


def test_offline_environment_removes_live_optins_and_import_injection():
    h = module()
    assert h.offline_environment(
        {
            "PATH": "/bin",
            "AUTH_SESSION_TOKEN_LIVE_LOCAL": "1",
            "FIREEMU_EVIDENCE_BINARY": "/arbitrary/binary",
            "VIRTUAL_ENV": "/current/venv",
            "PYTHONPATH": "/untrusted",
            "PYTEST_ADDOPTS": "--override-ini=x",
        }
    ) == {"PATH": "/bin"}
