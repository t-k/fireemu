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


def test_snapshot_separates_current_immutable_inputs_from_anchor_execution_inputs(
    repository,
):
    h = module()
    root, anchor = repository
    (root / "mutable").mkdir()
    (root / "mutable/runner.py").write_text("anchor runner")
    git(root, "add", ".")
    git(
        root,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-qm",
        "execution inputs",
    )
    anchor = git(root, "rev-parse", "HEAD")
    (root / "mutable/runner.py").write_text("current runner")
    (root / "mutable/new-helper.py").write_text("current helper")

    with h.snapshot(
        root,
        anchor,
        ("frozen", "mutable"),
        current_prefixes=("frozen",),
    ) as archived:
        assert (archived / "mutable/runner.py").read_text() == "anchor runner"
        assert not (archived / "mutable/new-helper.py").exists()

    (root / "frozen/receipt.json").write_text("tampered")
    with pytest.raises(ValueError), h.snapshot(
        root,
        anchor,
        ("frozen", "mutable"),
        current_prefixes=("frozen",),
    ):
        pytest.fail("Changed immutable input accepted")


def test_snapshot_rechecks_current_inputs_after_body_failure(repository):
    h = module()
    root, anchor = repository
    receipt = root / "frozen/receipt.json"

    with (
        pytest.raises(ValueError, match="Frozen bytes changed"),
        h.snapshot(root, anchor, ("frozen",)),
    ):
        receipt.write_text("tampered")
        raise RuntimeError("archived checker failed")


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
            "PYTEST_PLUGINS": "sentinel",
            "UV_PROJECT_ENVIRONMENT": "/untrusted/venv",
            "UV_NO_SYNC": "1",
            "UV_CONFIG_FILE": "/untrusted/uv.toml",
            "HOME": "/untrusted/home",
        }
    ) == {
        "PATH": "/bin",
        "PYTHONNOUSERSITE": "1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    }


def sha(data):
    import hashlib

    return hashlib.sha256(data).hexdigest()


def test_rebound_file_must_match_both_recorded_digests(repository):
    h = module()
    root, anchor = repository
    receipt = root / "frozen/receipt.json"
    before = sha(receipt.read_bytes())
    receipt.write_text('{"sourceCommit":"masked"}')
    after = sha(receipt.read_bytes())
    h.verify_frozen(root, anchor, ("frozen",), {"frozen/receipt.json": (before, after)})
    # An unrecorded change of the same file, or a record naming other anchor bytes, is refused.
    with pytest.raises(ValueError):
        h.verify_frozen(root, anchor, ("frozen",))
    with pytest.raises(ValueError):
        h.verify_frozen(root, anchor, ("frozen",), {"frozen/receipt.json": (before, "0" * 64)})
    with pytest.raises(ValueError):
        h.verify_frozen(root, anchor, ("frozen",), {"frozen/receipt.json": ("0" * 64, after)})
    receipt.write_text('{"sourceCommit":"masked again"}')
    with pytest.raises(ValueError):
        h.verify_frozen(root, anchor, ("frozen",), {"frozen/receipt.json": (before, after)})


def test_rebind_is_limited_to_the_files_the_record_names(repository):
    h = module()
    root, anchor = repository
    receipt = root / "frozen/receipt.json"
    other = root / "frozen/other.json"
    other.write_text("{}")
    git(root, "add", ".")
    git(root, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "second")
    anchor = git(root, "rev-parse", "HEAD")
    before = sha(receipt.read_bytes())
    receipt.write_text("masked")
    other.write_text('{"edited":true}')
    with pytest.raises(ValueError):
        h.verify_frozen(
            root, anchor, ("frozen",), {"frozen/receipt.json": (before, sha(b"masked"))}
        )


def test_snapshot_applies_the_rebind_record_to_the_working_tree_only(repository):
    h = module()
    root, anchor = repository
    receipt = root / "frozen/receipt.json"
    before = sha(receipt.read_bytes())
    receipt.write_text("masked")
    import json

    record = root / h.REBIND_RECORD
    record.parent.mkdir(parents=True)
    record.write_text(
        json.dumps({"files": {"frozen/receipt.json": {"preSha256": before, "postSha256": sha(b"masked")}}})
    )
    assert h.load_rebound(root) == {"frozen/receipt.json": (before, sha(b"masked"))}
    with h.snapshot(root, anchor, ("frozen",)) as archived:
        # The anchor's own copy stays byte-exact.
        assert (archived / "frozen/receipt.json").read_text() == '{"sourceCommit":"untrusted"}'
    assert h.load_rebound(root / "frozen") == {}
