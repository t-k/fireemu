"""The context builder reads only allowlisted text inside repoRoot and hashes what it read."""

import hashlib
import os

import pytest
from local_assist.context_builder import (
    ContextError,
    estimate_tokens,
    read_inputs,
    read_selection,
    render_numbered,
    resolve_repo_root,
)
from local_assist.packet import InputSelection


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    (root / "crates" / "x" / "tests").mkdir(parents=True)
    (root / "crates" / "x" / "tests" / "auth.rs").write_text(
        "\n".join(f"line {n}" for n in range(1, 51)) + "\n"
    )
    (root / "crates" / "x" / "src").mkdir()
    (root / "crates" / "x" / "src" / "token.rs").write_text("pub fn mint_token() {}\n")
    (root / ".env").write_text("SECRET=1\n")
    (root / ".env.local").write_text("SECRET=1\n")
    (root / "server.key").write_text("not really\n")
    (root / "service-account.json").write_text("{}\n")
    (root / "api-token.json").write_text("{}\n")
    (root / "docs.local").mkdir()
    (root / "LICENSE").mkdir()
    (root / "docs.local" / "notes.md").write_text("private\n")
    (root / "blob.bin").write_bytes(b"\x00\x01\x02")
    (root / "image.png").write_bytes(b"\x89PNG")
    (root / "latin.txt").write_bytes(b"caf\xe9\n")
    (root / "leak.md").write_text("-----BEGIN RSA PRIVATE KEY-----\nabc\n")
    outside = tmp_path / "outside.md"
    outside.write_text("outside\n")
    os.symlink(outside, root / "link.md")
    os.symlink(tmp_path, root / "dirlink")
    return root


def test_a_selection_is_read_with_content_hashes_and_effective_range(repo):
    [item] = read_inputs(str(repo), (InputSelection("crates/x/tests/auth.rs", 10, 12),))
    assert (item.startLine, item.endLine, item.requestedEndLine) == (10, 12, 12)
    assert item.lineCount == 50
    assert item.text == "line 10\nline 11\nline 12"
    assert item.rangeSha256 == hashlib.sha256(b"line 10\nline 11\nline 12").hexdigest()
    assert (
        item.fileSha256
        == hashlib.sha256((repo / "crates/x/tests/auth.rs").read_bytes()).hexdigest()
    )
    assert item.rangeBytes == len(b"line 10\nline 11\nline 12")
    rendered = render_numbered(item)
    assert rendered.startswith("=== crates/x/tests/auth.rs (lines 10-12 of 50) ===\n")
    assert "    10| line 10\n" in rendered
    assert rendered.endswith("    12| line 12\n")


def test_an_end_line_past_eof_is_clamped_and_recorded_not_silently_truncated(repo):
    [item] = read_inputs(
        str(repo), (InputSelection("crates/x/tests/auth.rs", 45, 200),)
    )
    assert item.endLine == 50
    assert item.requestedEndLine == 200
    assert item.text.endswith("line 50")


def test_a_start_line_past_eof_is_refused(repo):
    with pytest.raises(ContextError, match="beyond the last line"):
        read_inputs(str(repo), (InputSelection("crates/x/tests/auth.rs", 51, 60),))


@pytest.mark.parametrize(
    "path, reason",
    [
        ("../outside.md", "must not contain"),
        ("crates/../../outside.md", "must not contain"),
        ("/etc/passwd", "relative"),
        ("./crates/x/tests/auth.rs", "normalized"),
        ("crates//x/tests/auth.rs", "normalized"),
        ("crates\\x\\tests\\auth.rs", "backslash"),
        ("crates/x/tests/auth.rs\x00", "NUL"),
        ("link.md", "symlink"),
        ("dirlink/outside.md", "symlink"),
        (".env", "dotenv"),
        (".env.local", "dotenv"),
        ("server.key", "credential or key"),
        ("service-account.json", "credential or key"),
        ("api-token.json", "suggests credentials"),
        ("docs.local/notes.md", "not readable"),
        ("blob.bin", "not on the text allowlist"),
        ("image.png", "not on the text allowlist"),
        ("latin.txt", "not valid UTF-8"),
        ("leak.md", "credential-like content"),
        ("missing.rs", "not a regular file"),
        ("crates", "not on the text allowlist"),
        ("LICENSE", "not a regular file"),
    ],
)
def test_unsafe_inputs_are_refused(repo, path, reason):
    with pytest.raises(ContextError, match=reason):
        read_inputs(str(repo), (InputSelection(path, 1, 10),))


def test_source_files_named_after_tokens_stay_readable(repo):
    [item] = read_inputs(str(repo), (InputSelection("crates/x/src/token.rs", 1, 1),))
    assert item.text == "pub fn mint_token() {}"


def test_a_binary_file_with_an_allowed_extension_is_refused(repo):
    (repo / "fake.rs").write_bytes(b"fn main() {}\x00\n")
    with pytest.raises(ContextError, match="binary content"):
        read_inputs(str(repo), (InputSelection("fake.rs", 1, 1),))


def test_an_oversized_file_is_refused_before_it_is_read(repo, monkeypatch):
    from local_assist import context_builder

    monkeypatch.setattr(context_builder, "MAX_FILE_BYTES", 16)
    with pytest.raises(ContextError, match="larger than 16 bytes"):
        read_selection(
            resolve_repo_root(str(repo)), InputSelection("crates/x/tests/auth.rs", 1, 1)
        )


def test_repo_root_must_be_an_existing_absolute_directory(tmp_path):
    with pytest.raises(ContextError, match="absolute"):
        resolve_repo_root("relative/root")
    with pytest.raises(ContextError, match="not a directory"):
        resolve_repo_root(str(tmp_path / "missing"))


def test_the_token_estimate_is_conservative():
    assert estimate_tokens("") == 0
    assert estimate_tokens("abc") == 1
    assert estimate_tokens("a" * 300) == 100
    # Multibyte text counts bytes, not characters.
    assert estimate_tokens("あ" * 10) == 10
