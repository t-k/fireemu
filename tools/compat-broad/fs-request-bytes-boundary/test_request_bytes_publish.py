"""Publishing the record and the citation is one generation, or none of it.

Publishing used to replace the record and only then read, validate and rewrite
the document. Each of these covers a way that left one run's record beside
another run's citation, with both publishers reporting success.

No emulator, no artifact, no network: every case works on a sandbox copy of the
two published files.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
import threading
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
for entry in (str(HERE), str(HERE.parent), str(ROOT / "tools/compat-inventory")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import request_bytes_shadow as shadow_module


def _sandbox(tmp_path: Path) -> Path:
    """A miniature checkout holding only the two published files."""
    root = tmp_path / "checkout"
    (root / "spec/compatibility/broad-runs").mkdir(parents=True)
    (root / "docs/compatibility").mkdir(parents=True)
    shutil.copy(
        ROOT / shadow_module.PUBLISHED_RECORD, root / shadow_module.PUBLISHED_RECORD
    )
    shutil.copy(
        ROOT / shadow_module.PREPARATION_DOC, root / shadow_module.PREPARATION_DOC
    )
    return root


def _run(tmp_path: Path, tag: str) -> Path:
    """A run directory whose record is identifiable by one repeated character."""
    output = tmp_path / f"run-{tag}"
    output.mkdir()
    record = json.loads((ROOT / shadow_module.PUBLISHED_RECORD).read_bytes())
    record["nonce"] = tag * 32
    (output / "local-shadow.json").write_text(json.dumps(record))
    return output


def _identities(root: Path) -> tuple[str, str]:
    record = json.loads((root / shadow_module.PUBLISHED_RECORD).read_bytes())
    document = (root / shadow_module.PREPARATION_DOC).read_text()
    cited = re.search(r"nonce `(.)", document)
    assert cited is not None, "the citation does not name a nonce"
    return record["nonce"][0], cited.group(1)


def test_a_normal_publish_leaves_a_consistent_pair(tmp_path):
    root = _sandbox(tmp_path)
    shadow_module.publish_run(_run(tmp_path, "a"), root=root)
    assert _identities(root) == ("a", "a")


def test_a_marker_defect_changes_neither_file(tmp_path):
    """Validation must finish before any existing file is touched."""
    root = _sandbox(tmp_path)
    document = root / shadow_module.PREPARATION_DOC
    document.write_text(document.read_text().replace(shadow_module.CITATION_END, ""))
    before_record = (root / shadow_module.PUBLISHED_RECORD).read_bytes()
    before_document = document.read_text()

    with pytest.raises(ValueError, match="citation markers"):
        shadow_module.publish_run(_run(tmp_path, "a"), root=root)

    assert (root / shadow_module.PUBLISHED_RECORD).read_bytes() == before_record
    assert document.read_text() == before_document


def test_a_failure_replacing_the_second_file_restores_the_first(tmp_path, monkeypatch):
    """Neither file may keep a value from a generation that did not complete."""
    root = _sandbox(tmp_path)
    before_record = (root / shadow_module.PUBLISHED_RECORD).read_bytes()
    before_document = (root / shadow_module.PREPARATION_DOC).read_text()

    real_replace = os.replace
    seen: list[str] = []

    def flaky(source, destination, *args, **kwargs):
        seen.append(str(destination))
        if str(destination).endswith(".md"):
            raise OSError("injected document replace refusal")
        return real_replace(source, destination, *args, **kwargs)

    monkeypatch.setattr(os, "replace", flaky)
    with pytest.raises(OSError, match="injected document replace refusal"):
        shadow_module.publish_run(_run(tmp_path, "a"), root=root)
    monkeypatch.undo()

    assert (root / shadow_module.PUBLISHED_RECORD).read_bytes() == before_record
    assert (root / shadow_module.PREPARATION_DOC).read_text() == before_document
    assert any(name.endswith(".md") for name in seen), "the document was never reached"


def test_a_failure_writing_the_second_temporary_touches_nothing(tmp_path, monkeypatch):
    root = _sandbox(tmp_path)
    before_record = (root / shadow_module.PUBLISHED_RECORD).read_bytes()
    before_document = (root / shadow_module.PREPARATION_DOC).read_text()

    real_write = shadow_module._write_temporary

    def flaky(target, data):
        # `_write_temporary` is handed the final path and derives the temporary
        # name itself, so the document is the one ending in `.md`.
        if str(target).endswith(".md"):
            raise OSError("injected temporary write refusal")
        return real_write(target, data)

    monkeypatch.setattr(shadow_module, "_write_temporary", flaky)
    with pytest.raises(OSError, match="injected temporary write refusal"):
        shadow_module.publish_run(_run(tmp_path, "a"), root=root)
    monkeypatch.undo()

    assert (root / shadow_module.PUBLISHED_RECORD).read_bytes() == before_record
    assert (root / shadow_module.PREPARATION_DOC).read_text() == before_document


def test_no_temporary_survives_a_failed_publish(tmp_path, monkeypatch):
    root = _sandbox(tmp_path)
    real_replace = os.replace

    def flaky(source, destination, *args, **kwargs):
        if str(destination).endswith(".md"):
            raise OSError("injected document replace refusal")
        return real_replace(source, destination, *args, **kwargs)

    monkeypatch.setattr(os, "replace", flaky)
    with pytest.raises(OSError):
        shadow_module.publish_run(_run(tmp_path, "a"), root=root)
    monkeypatch.undo()

    leftovers = sorted(path.name for path in root.rglob("*.publish-tmp"))
    assert leftovers == []


def test_concurrent_publishers_never_cross_a_record_with_another_citation(tmp_path):
    """Two runs racing must end A/A or B/B, never B/A."""
    root = _sandbox(tmp_path)
    outputs = {tag: _run(tmp_path, tag) for tag in "ab"}
    failures: list[BaseException] = []

    def publish(tag: str) -> None:
        try:
            for _ in range(8):
                shadow_module.publish_run(outputs[tag], root=root)
        except BaseException as error:  # noqa: BLE001 - reported below.
            failures.append(error)

    threads = [threading.Thread(target=publish, args=(tag,)) for tag in "ab"]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
        assert not thread.is_alive()

    assert not failures, failures
    record_identity, citation_identity = _identities(root)
    assert record_identity == citation_identity, (
        f"record is {record_identity!r} while the citation cites "
        f"{citation_identity!r}: a crossed generation"
    )


def _check_ignore(relative: str) -> bool:
    """Ask git itself, rather than reading .gitignore and hoping."""
    import subprocess

    return (
        subprocess.run(
            ["git", "check-ignore", "-q", relative],
            cwd=ROOT,
            capture_output=True,
            check=False,
        ).returncode
        == 0
    )


def test_the_lock_is_kept_out_of_the_tracked_tree():
    """A lock file in `git status` makes the next run refuse the checkout."""
    assert _check_ignore(shadow_module.PUBLICATION_LOCK)


@pytest.mark.parametrize("published", shadow_module.PUBLISHED_PATHS)
def test_a_stale_temporary_is_kept_out_of_the_tracked_tree(published):
    """A killed publisher must not leave a file that dirties the checkout."""
    assert _check_ignore(published + shadow_module.TEMPORARY_SUFFIX)


def test_a_stale_temporary_is_swept_when_the_lock_is_taken(tmp_path):
    """A publisher killed mid-write leaves side files; the next one clears them."""
    root = _sandbox(tmp_path)
    stale = [
        shadow_module._temporary_for(root / relative)
        for relative in shadow_module.PUBLISHED_PATHS
    ]
    for path in stale:
        path.write_bytes(b"left behind by a killed publisher")

    shadow_module.publish_run(_run(tmp_path, "a"), root=root)

    assert [path for path in stale if path.exists()] == []
    assert _identities(root) == ("a", "a")


def test_the_sweep_reports_what_it_removed(tmp_path):
    root = _sandbox(tmp_path)
    temporary = shadow_module._temporary_for(root / shadow_module.PUBLISHED_RECORD)
    temporary.write_bytes(b"stale")
    swept = shadow_module._sweep_stale_temporaries(root)
    assert swept == [shadow_module.PUBLISHED_RECORD + shadow_module.TEMPORARY_SUFFIX]
    assert not temporary.exists()
    assert shadow_module._sweep_stale_temporaries(root) == []


def test_a_non_utf8_pre_image_is_restored_as_bytes(tmp_path, monkeypatch):
    """The restore must not decode: a decode error would escape the handler."""
    root = _sandbox(tmp_path)
    record_path = root / shadow_module.PUBLISHED_RECORD
    document_path = root / shadow_module.PREPARATION_DOC
    # A pre-image that cannot be decoded as UTF-8. Contrived, but the restore
    # path must not depend on the old content being text at all.
    record_path.write_bytes(b"\xff\xfe not valid utf-8")
    before_document = document_path.read_text()

    real_replace = os.replace

    def flaky(source, destination, *args, **kwargs):
        if str(destination).endswith(".md"):
            raise OSError("injected document replace refusal")
        return real_replace(source, destination, *args, **kwargs)

    monkeypatch.setattr(os, "replace", flaky)
    with pytest.raises(OSError, match="injected document replace refusal"):
        shadow_module.publish_run(_run(tmp_path, "a"), root=root)
    monkeypatch.undo()

    assert record_path.read_bytes() == b"\xff\xfe not valid utf-8"
    assert document_path.read_text() == before_document
    assert sorted(path.name for path in root.rglob("*.publish-tmp")) == []
