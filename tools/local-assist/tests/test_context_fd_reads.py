"""Real filesystem race regressions for LOCAL-CONTEXT-FD-014.

Hooks schedule a rename/write at a specific check/open/read boundary. They do not
replace the parser, the bytes, or the filesystem with a fake implementation.
No model, HTTP endpoint, or production credential is used.
"""

import errno
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from local_assist import context_builder as cb
from local_assist.packet import InputSelection

SELECT = InputSelection("src/sample.rs", 1, 2)
INSIDE = b"FIRST\nSECOND\n"
OUTSIDE = b"OUTSIDE_SENTINEL\n"


@pytest.fixture
def area(tmp_path):
    base = tmp_path.resolve()
    root = base / "parent" / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "sample.rs").write_bytes(INSIDE)
    outside = base / "outside"
    (outside / "repo" / "src").mkdir(parents=True)
    (outside / "sample.rs").write_bytes(OUTSIDE)
    (outside / "repo" / "src" / "sample.rs").write_bytes(OUTSIDE)
    return base, root, outside


def schedule_after_validation(monkeypatch, action):
    real = cb.resolve_inside

    def checked_then_change(root, path):
        result = real(root, path)
        action()
        return result

    monkeypatch.setattr(cb, "resolve_inside", checked_then_change)


@pytest.mark.parametrize("location", ["leaf", "directory", "root-ancestor"])
def test_symlink_replacement_after_validation_never_returns_outside(area, monkeypatch, location):
    base, root, outside = area

    def swap():
        if location == "leaf":
            (root / "src/sample.rs").unlink()
            (root / "src/sample.rs").symlink_to(outside / "sample.rs")
        elif location == "directory":
            (root / "src").rename(root / "parked")
            (root / "src").symlink_to(outside, target_is_directory=True)
        else:
            (base / "parent").rename(base / "parked-parent")
            (base / "parent").symlink_to(outside, target_is_directory=True)

    schedule_after_validation(monkeypatch, swap)
    with pytest.raises(cb.ContextError, match="symlink|changed") as error:
        cb.read_selection(str(root), SELECT)
    assert OUTSIDE.decode().strip() not in str(error.value)
    assert (outside / "sample.rs").read_bytes() == OUTSIDE


def test_opened_directory_is_not_redirected_by_later_symlink(area, monkeypatch):
    _, root, outside = area
    real_open = os.open
    fired = False

    def open_then_replace(path, flags, *args, **kwargs):
        nonlocal fired
        fd = real_open(path, flags, *args, **kwargs)
        if path == "src" and not fired:
            fired = True
            (root / "src").rename(root / "parked")
            (root / "src").symlink_to(outside, target_is_directory=True)
        return fd

    monkeypatch.setattr(cb.os, "open", open_then_replace)
    result = cb.read_selection(str(root), SELECT)
    assert fired
    assert result.text == "FIRST\nSECOND"
    assert result.fileSha256 == hashlib.sha256(INSIDE).hexdigest()


def test_regular_atomic_replacement_before_open_is_read_and_hashed(area, monkeypatch):
    _, root, _ = area
    newer = b"NEW_FIRST\nNEW_SECOND\n"

    def swap():
        replacement = root / "replacement.rs"
        replacement.write_bytes(newer)
        replacement.replace(root / "src/sample.rs")

    schedule_after_validation(monkeypatch, swap)
    result = cb.read_selection(str(root), SELECT)
    assert result.text == "NEW_FIRST\nNEW_SECOND"
    assert result.fileSha256 == hashlib.sha256(newer).hexdigest()


@pytest.mark.parametrize("replacement", ["directory", "missing"])
def test_leaf_type_change_after_validation_is_refused(area, monkeypatch, replacement):
    _, root, _ = area

    def swap():
        leaf = root / "src/sample.rs"
        leaf.unlink()
        if replacement == "directory":
            leaf.mkdir()

    schedule_after_validation(monkeypatch, swap)
    with pytest.raises(cb.ContextError):
        cb.read_selection(str(root), SELECT)


def test_fifo_replacement_cannot_block_the_reader(tmp_path):
    # Run in a separate process: a broken implementation must not hang pytest.
    # subprocess.run kills/reaps its one child on timeout; that child spawns nothing.
    code = r'''
import json, os, sys
from pathlib import Path
from local_assist import context_builder as cb
from local_assist.packet import InputSelection
root = Path(sys.argv[1]).resolve()
root.mkdir()
p = root / 'source.rs'
p.write_text('ordinary\n')
real = cb.resolve_inside
def swap(root, path):
    result = real(root, path)
    p.unlink()
    os.mkfifo(p)
    return result
cb.resolve_inside = swap
try:
    cb.read_selection(str(root), InputSelection('source.rs', 1, 1))
except cb.ContextError:
    print(json.dumps({'refused': True}), flush=True)
else:
    raise AssertionError('FIFO must not become model input')
'''
    try:
        result = subprocess.run(
            [sys.executable, "-c", code, str(tmp_path / "fifo-root")],
            env={**os.environ, "PYTHONPATH": str(Path(cb.__file__).resolve().parents[1])},
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except subprocess.TimeoutExpired:
        pytest.fail("reader blocked opening a FIFO after validation")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"refused": True}


@pytest.mark.parametrize("change", ["grow", "truncate", "rewrite", "unlink", "mode"])
def test_file_changes_during_read_are_refused(area, monkeypatch, change):
    _, root, _ = area
    leaf = root / "src/sample.rs"
    leaf.write_bytes(b"A" * 131_072)
    # Make the original mtime distinct; restoring it below tests the ctime check.
    os.utime(leaf, ns=(1_000_000_000, 1_000_000_000))
    real_read = os.read
    fired = False

    def read_then_change(fd, count):
        nonlocal fired
        data = real_read(fd, count)
        if data and not fired:
            fired = True
            if change == "grow":
                with leaf.open("ab") as handle:
                    handle.write(b"B")
            elif change == "truncate":
                leaf.write_bytes(b"short")
            elif change == "rewrite":
                leaf.write_bytes(b"B" * 131_072)
                os.utime(leaf, ns=(1_000_000_000, 1_000_000_000))
            elif change == "unlink":
                leaf.unlink()
            else:
                leaf.chmod(0o400)
        return data

    monkeypatch.setattr(cb.os, "read", read_then_change)
    with pytest.raises(cb.ContextError, match="changed while reading"):
        cb.read_selection(str(root), SELECT)
    assert fired


@pytest.mark.parametrize("chunk_size", [1, 2, 3, 7, 65_536])
def test_short_reads_preserve_unicode_and_crlf(area, monkeypatch, chunk_size):
    _, root, _ = area
    text = "日本語😀\r\ne\u0301終わり\r\n"
    data = text.encode()
    (root / "src/sample.rs").write_bytes(data)
    real_read = os.read
    monkeypatch.setattr(cb.os, "read", lambda fd, n: real_read(fd, min(n, chunk_size)))
    result = cb.read_selection(str(root), SELECT)
    assert result.text == text[:-1]
    assert result.fileSha256 == hashlib.sha256(data).hexdigest()
    assert result.rangeSha256 == hashlib.sha256(data[:-1]).hexdigest()
    assert result.lineCount == 2


@pytest.mark.parametrize("length", [1, 15, 16])
def test_exact_file_byte_ceiling_and_smaller_are_readable(area, monkeypatch, length):
    _, root, _ = area
    data = b"x" * length
    (root / "src/sample.rs").write_bytes(data)
    monkeypatch.setattr(cb, "MAX_FILE_BYTES", 16)
    result = cb.read_selection(str(root), SELECT)
    assert result.text == data.decode()
    assert result.rangeBytes == length


def test_oversize_is_checked_on_the_opened_file_before_read(area, monkeypatch):
    _, root, _ = area
    monkeypatch.setattr(cb, "MAX_FILE_BYTES", 16)
    schedule_after_validation(monkeypatch, lambda: (root / "src/sample.rs").write_bytes(b"x" * 17))

    def no_read(*args):
        raise AssertionError("oversized file must be refused before reading")

    monkeypatch.setattr(cb.os, "read", no_read)
    with pytest.raises(cb.ContextError, match="larger than 16"):
        cb.read_selection(str(root), SELECT)


def test_growth_past_ceiling_is_bounded(area, monkeypatch):
    _, root, _ = area
    monkeypatch.setattr(cb, "MAX_FILE_BYTES", 16)
    leaf = root / "src/sample.rs"
    leaf.write_bytes(b"x" * 16)
    real_read = os.read
    observed = []

    def read_then_grow(fd, count):
        chunk = real_read(fd, min(count, 8))
        observed.append(len(chunk))
        if len(observed) == 1:
            with leaf.open("ab") as writer:
                writer.write(b"y" * 1024)
        return chunk

    monkeypatch.setattr(cb.os, "read", read_then_grow)
    with pytest.raises(cb.ContextError, match="larger than 16"):
        cb.read_selection(str(root), SELECT)
    assert sum(observed) == 17


def test_early_eof_does_not_become_a_complete_file(area, monkeypatch):
    _, root, _ = area
    real_read = os.read
    calls = 0

    def early_eof(fd, count):
        nonlocal calls
        calls += 1
        return real_read(fd, 2) if calls == 1 else b""

    monkeypatch.setattr(cb.os, "read", early_eof)
    with pytest.raises(cb.ContextError, match="changed while reading"):
        cb.read_selection(str(root), SELECT)


@pytest.mark.parametrize("payload, reason", [
    (b"good\x00bad", "binary content"),
    (b"bad\x80", "not valid UTF-8"),
    (b"-----BEGIN PRIVATE KEY-----\n", "credential-like content"),
])
def test_content_validation_is_not_skipped_after_fd_read(area, payload, reason):
    _, root, _ = area
    (root / "src/sample.rs").write_bytes(payload)
    with pytest.raises(cb.ContextError, match=reason):
        cb.read_selection(str(root), SELECT)


def test_resolved_symlink_alias_of_repo_root_remains_supported(area):
    base, root, _ = area
    alias = base / "root-alias"
    alias.symlink_to(root, target_is_directory=True)
    [result] = cb.read_inputs(str(alias), (SELECT,))
    assert result.text == "FIRST\nSECOND"


def test_spaces_and_japanese_path_are_supported(tmp_path):
    root = tmp_path.resolve() / "作業 space"
    directory = root / "テスト space"
    directory.mkdir(parents=True)
    (directory / "名前.rs").write_text("日本語\n", encoding="utf-8")
    [result] = cb.read_inputs(str(root), (InputSelection("テスト space/名前.rs", 1, 1),))
    assert result.text == "日本語"


def test_every_directory_and_leaf_is_opened_nofollow(area, monkeypatch):
    _, root, _ = area
    real_open = os.open
    calls = []

    def record_open(path, flags, *args, **kwargs):
        calls.append((path, flags, kwargs))
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(cb.os, "open", record_open)
    cb.read_selection(str(root), SELECT)
    assert calls[0][0] == os.sep
    for _, flags, _ in calls:
        assert flags & os.O_NOFOLLOW
    assert all(flags & os.O_DIRECTORY for _, flags, _ in calls[:-1])
    assert calls[-1][0] == "sample.rs"
    assert calls[-1][1] & os.O_NONBLOCK
    assert all("dir_fd" in kwargs for _, _, kwargs in calls[1:])


@pytest.mark.parametrize("failure_at", ["root", "src", "leaf", "read", "fstat"])
def test_all_opened_fds_are_closed_on_failure(area, monkeypatch, failure_at):
    _, root, _ = area
    real_open, real_close, real_read, real_fstat = os.open, os.close, os.read, os.fstat
    opened = set()
    closed = []
    fired = False

    def fail():
        nonlocal fired
        fired = True
        raise OSError(errno.EIO, "PRIVATE_ABSOLUTE_DESTINATION_MUST_NOT_APPEAR")

    def tracked_open(path, flags, *args, **kwargs):
        if ((failure_at == "root" and path == os.sep)
                or (failure_at == "src" and path == "src")
                or (failure_at == "leaf" and path == "sample.rs")):
            fail()
        fd = real_open(path, flags, *args, **kwargs)
        assert fd not in opened
        opened.add(fd)
        return fd

    def tracked_close(fd):
        assert fd in opened
        real_close(fd)
        opened.remove(fd)
        closed.append(fd)

    def tracked_read(fd, n):
        if failure_at == "read":
            fail()
        return real_read(fd, n)

    def tracked_fstat(fd):
        if failure_at == "fstat":
            fail()
        return real_fstat(fd)

    with monkeypatch.context() as patch:
        patch.setattr(cb.os, "open", tracked_open)
        patch.setattr(cb.os, "close", tracked_close)
        patch.setattr(cb.os, "read", tracked_read)
        patch.setattr(cb.os, "fstat", tracked_fstat)
        with pytest.raises(cb.ContextError) as error:
            cb.read_selection(str(root), SELECT)
    assert fired
    assert not opened
    assert "PRIVATE_ABSOLUTE_DESTINATION" not in str(error.value)
    assert closed or failure_at == "root"


def test_repeated_deep_reads_keep_only_constant_number_of_fds(tmp_path, monkeypatch):
    root = tmp_path.resolve() / "repo"
    pieces = [f"d{i}" for i in range(60)]
    directory = root.joinpath(*pieces)
    directory.mkdir(parents=True)
    (directory / "sample.rs").write_bytes(INSIDE)
    selection = InputSelection("/".join([*pieces, "sample.rs"]), 1, 2)
    real_open, real_close = os.open, os.close
    opened = set()
    peak = 0

    def tracked_open(*args, **kwargs):
        nonlocal peak
        fd = real_open(*args, **kwargs)
        opened.add(fd)
        peak = max(peak, len(opened))
        assert not os.get_inheritable(fd)
        return fd

    def tracked_close(fd):
        assert fd in opened
        real_close(fd)
        opened.remove(fd)

    with monkeypatch.context() as patch:
        patch.setattr(cb.os, "open", tracked_open)
        patch.setattr(cb.os, "close", tracked_close)
        for _ in range(50):
            assert cb.read_selection(str(root), selection).text == "FIRST\nSECOND"
            assert not opened
    assert peak <= 2


def test_unsupported_descriptor_mode_fails_before_open(area, monkeypatch):
    _, root, _ = area
    monkeypatch.setattr(cb, "_FD_READ_SUPPORTED", False)

    def no_open(*args, **kwargs):
        pytest.fail("unsupported platform must not fall back to pathname reads")

    monkeypatch.setattr(cb.os, "open", no_open)
    with pytest.raises(cb.ContextError, match="unsupported"):
        cb.read_selection(str(root), SELECT)

