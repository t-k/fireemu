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


# ---- the rebind of frozen bytes (the oracle number mask) -------------------------------------------------------

OLD_DIGEST = "a" * 64
NEW_DIGEST = "b" * 64
NUMBER = b"123456789012"  # made up
ANCHOR_BYTES = b'{"project":"p","n":"' + NUMBER + b'","d":"' + OLD_DIGEST.encode() + b'"}'
MASKED_BYTES = b'{"project":"p","n":"<project-number>","d":"' + NEW_DIGEST.encode() + b'"}'
OFFSET = ANCHOR_BYTES.index(NUMBER)


def sha(data):
    import hashlib

    return hashlib.sha256(data).hexdigest()


def entry(**changes):
    value = {
        "preSha256": sha(ANCHOR_BYTES),
        "postSha256": sha(MASKED_BYTES),
        "maskedOccurrences": 1,
        "maskedOffsets": [OFFSET],
        "digestRewrites": [[OLD_DIGEST, NEW_DIGEST]],
    }
    value.update(changes)
    return value


@pytest.fixture
def masked(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q")
    (root / "frozen").mkdir()
    (root / "frozen/a.json").write_bytes(ANCHOR_BYTES)
    (root / "frozen/b.json").write_text("untouched")
    git(root, "add", ".")
    git(root, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "anchor")
    anchor = git(root, "rev-parse", "HEAD")
    (root / "frozen/a.json").write_bytes(MASKED_BYTES)
    return root, anchor


def check(h, root, anchor, name="frozen/a.json", value=None, current=None):
    if current is not None:
        (root / name).write_bytes(current)
    h.verify_frozen(root, anchor, ("frozen",), {"frozen/a.json": entry(), name: entry() if value is None else value})


def test_the_recorded_substitutions_are_accepted(masked):
    h = module()
    root, anchor = masked
    check(h, root, anchor)


@pytest.mark.parametrize(
    "current",
    [
        b'{"project":"q","n":"<project-number>","d":"' + NEW_DIGEST.encode() + b'"}',
        MASKED_BYTES + b" ",
        ANCHOR_BYTES,
        MASKED_BYTES.replace(b"<project-number>", b"<project-numbers>"),
        MASKED_BYTES.replace(NEW_DIGEST.encode(), b"c" * 64),
    ],
)
def test_arbitrary_new_bytes_are_refused_even_with_a_record_that_vouches_for_them(masked, current):
    h = module()
    root, anchor = masked
    (root / "frozen/a.json").write_bytes(current)
    # The record vouches for exactly these bytes (postSha256 updated to match); it must not matter.
    with pytest.raises(ValueError):
        check(h, root, anchor, value=entry(postSha256=sha(current)))


def test_a_record_entry_for_a_file_that_was_never_masked_is_refused(masked):
    h = module()
    root, anchor = masked
    other = root / "frozen/b.json"
    other.write_text("replaced")
    forged = {"preSha256": sha(b"untouched"), "postSha256": sha(b"replaced")}
    with pytest.raises(ValueError, match="no substitution"):
        check(h, root, anchor, name="frozen/b.json", value=forged)
    with pytest.raises(ValueError):
        check(h, root, anchor, name="frozen/b.json", value={**forged, "maskedOffsets": [0], "maskedOccurrences": 1})
    with pytest.raises(ValueError):
        check(h, root, anchor, name="frozen/b.json", value={**forged, "digestRewrites": [[OLD_DIGEST, NEW_DIGEST]]})


@pytest.mark.parametrize(
    "bad",
    [
        {"maskedOffsets": [OFFSET + 1]},  # inside the run: not a whole number
        {"maskedOffsets": [OFFSET - 1]},  # not a digit run
        {"maskedOffsets": [OFFSET, OFFSET]},  # duplicate
        {"maskedOffsets": [10**6]},  # outside the file
        {"maskedOffsets": [OFFSET], "maskedOccurrences": 2},
        {"maskedOffsets": []},  # the placeholder is then at an unlisted position
        {"preSha256": "0" * 64},
        {"editedAfterCascade": True},
        {"digestRewrites": [["c" * 64, NEW_DIGEST]]},  # the old digest is not in the file
        {"digestRewrites": [[OLD_DIGEST, "not hex"]]},
        {"digestRewrites": [[OLD_DIGEST, NEW_DIGEST], [OLD_DIGEST, NEW_DIGEST]]},
        {"digestRewrites": [[OLD_DIGEST.upper(), NEW_DIGEST]]},
        {"digestRewrites": [[OLD_DIGEST]]},
    ],
)
def test_a_malformed_or_inexact_entry_is_refused(masked, bad):
    h = module()
    root, anchor = masked
    with pytest.raises(ValueError):
        check(h, root, anchor, value=entry(**bad))


@pytest.mark.parametrize(
    "bad",
    [
        {"maskedOffsets": [OFFSET + 1]},
        {"maskedOffsets": [OFFSET - 1]},
        {"maskedOffsets": [0]},  # twelve bytes that are not digits
        {"maskedOffsets": [OFFSET, OFFSET], "maskedOccurrences": 2},
        {"maskedOffsets": [OFFSET + 20, OFFSET], "maskedOccurrences": 2},
        {"maskedOffsets": [OFFSET, OFFSET + 6]},
        {"maskedOffsets": [10**6]},
        {"maskedOccurrences": 2},
        {"preSha256": "0" * 64},
        {"editedAfterCascade": True},
        {"maskedOffsets": [], "digestRewrites": []},
        {"digestRewrites": [["c" * 64, NEW_DIGEST]]},
        {"digestRewrites": [[OLD_DIGEST, "not hex"]]},
        {"digestRewrites": [[OLD_DIGEST, NEW_DIGEST], [OLD_DIGEST, NEW_DIGEST]]},
        {"digestRewrites": [[OLD_DIGEST.upper(), NEW_DIGEST]]},
        {"digestRewrites": [[OLD_DIGEST]]},
        {"digestRewrites": ["x"]},
    ],
)
def test_rebuild_itself_refuses_a_structural_defect(bad):
    h = module()
    assert h.rebuild(ANCHOR_BYTES, entry(), "f") == MASKED_BYTES
    with pytest.raises(ValueError):
        h.rebuild(ANCHOR_BYTES, entry(**bad), "f")


def test_a_number_inside_a_longer_digit_run_is_not_a_whole_number(tmp_path):
    h = module()
    blob = b"x" + NUMBER + b"7y"
    with pytest.raises(ValueError, match="whole number"):
        h.rebuild(blob, {"preSha256": sha(blob), "maskedOffsets": [1]}, "f")
    blob = b"7" + NUMBER + b"y"
    with pytest.raises(ValueError, match="whole number"):
        h.rebuild(blob, {"preSha256": sha(blob), "maskedOffsets": [1]}, "f")


def test_digest_pairs_apply_at_once_and_do_not_chain(tmp_path):
    h = module()
    blob = ("x" + "a" * 64 + "y" + "b" * 64).encode()
    pairs = [["a" * 64, "b" * 64], ["b" * 64, "c" * 64]]
    rebuilt = h.rebuild(blob, {"preSha256": sha(blob), "digestRewrites": pairs}, "f")
    assert rebuilt == ("x" + "b" * 64 + "y" + "c" * 64).encode()


def test_a_file_outside_the_record_still_has_to_be_byte_exact(masked):
    h = module()
    root, anchor = masked
    (root / "frozen/b.json").write_text("replaced")
    with pytest.raises(ValueError):
        check(h, root, anchor)


def write_record(root, h, files):
    import json

    record = root / h.REBIND_RECORD
    record.parent.mkdir(parents=True, exist_ok=True)
    record.write_text(json.dumps({"files": files}))
    return sha(record.read_bytes())


def test_the_record_must_be_the_pinned_one(masked, monkeypatch):
    h = module()
    root, anchor = masked
    digest = write_record(root, h, {"frozen/a.json": entry()})
    assert h.load_rebound(root, pinned=digest) == {"frozen/a.json": entry()}
    record = root / h.REBIND_RECORD
    # One changed byte of the record (a recomputed postSha256 here) is refused, however consistent it looks.
    record.write_text(record.read_text().replace(sha(MASKED_BYTES), sha(b"other")))
    with pytest.raises(ValueError, match="pinned"):
        h.load_rebound(root, pinned=digest)
    monkeypatch.setattr(h, "REBIND_RECORD_SHA256", digest)
    with pytest.raises(ValueError, match="pinned"):
        h.verify_frozen(root, anchor, ("frozen",))
    with pytest.raises(ValueError, match="pinned"), h.snapshot(root, anchor, ("frozen",)):
        pytest.fail("snapshot accepted an unpinned record")


def test_without_a_record_nothing_may_differ(masked):
    h = module()
    root, anchor = masked
    assert h.load_rebound(root) == {}
    with pytest.raises(ValueError):
        h.verify_frozen(root, anchor, ("frozen",))


def test_verify_frozen_and_snapshot_read_the_pinned_record_of_their_root(masked, monkeypatch):
    h = module()
    root, anchor = masked
    monkeypatch.setattr(h, "REBIND_RECORD_SHA256", write_record(root, h, {"frozen/a.json": entry()}))
    h.verify_frozen(root, anchor, ("frozen",))
    with h.snapshot(root, anchor, ("frozen",)) as archived:
        # The anchor's own copy stays byte-exact.
        assert (archived / "frozen/a.json").read_bytes() == ANCHOR_BYTES


def test_an_archived_anchor_checkout_is_always_byte_exact(masked, monkeypatch):
    h = module()
    root, _ = masked
    digest = write_record(root, h, {"frozen/a.json": entry()})
    monkeypatch.setattr(h, "REBIND_RECORD_SHA256", digest)
    (root / "frozen/a.json").write_bytes(ANCHOR_BYTES)
    git(root, "add", ".")
    git(root, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "anchor with record")
    anchor = git(root, "rev-parse", "HEAD")
    (root / "frozen/a.json").write_bytes(MASKED_BYTES)
    # The anchor commit itself carries the record; the archived copy must still not use it.
    with h.snapshot(root, anchor, ("frozen",)) as archived:
        assert (archived / "frozen/a.json").read_bytes() == ANCHOR_BYTES


def test_the_checked_in_record_is_the_pinned_one_and_rebuilds_every_entry():
    h = module()
    entries = h.load_rebound(h.ROOT)
    assert entries, "the checked-in mask record is missing"
    parent = json_load(h.ROOT / h.REBIND_RECORD)["parentCommit"]
    try:
        git(h.ROOT, "cat-file", "-e", parent + "^{commit}")
    except subprocess.CalledProcessError:
        pytest.skip("the parent commit of the record is not in this clone")
    rebuilt = 0
    for name, value in entries.items():
        if value.get("editedAfterCascade"):
            continue
        blob = subprocess.check_output(["git", "-C", str(h.ROOT), "show", f"{parent}:{name}"])
        assert (h.ROOT / name).read_bytes() == h.rebuild(blob, value, name), name
        rebuilt += 1
    assert rebuilt > 400


def json_load(path):
    import json

    return json.loads(path.read_text())
