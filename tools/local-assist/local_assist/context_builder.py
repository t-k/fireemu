"""Read-only, allowlisted context extraction from a repository snapshot.

The builder is the only component that touches the filesystem on behalf of
a packet. It reads plain text files under the packet's repoRoot, refuses
anything that could leave the root or look like a credential, and records a
content hash for every byte range that reaches the model.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import stat
from dataclasses import dataclass

from local_assist.packet import InputSelection

MAX_FILE_BYTES = 4 * 1024 * 1024
_FD_READ_SUPPORTED = (
    os.name == "posix"
    and os.open in os.supports_dir_fd
    and all(hasattr(os, flag) for flag in ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK"))
)
BYTES_PER_TOKEN = (
    3  # conservative: real tokenizers average 3.5-4 bytes per token on code
)

TEXT_EXTENSIONS = {
    "rs",
    "py",
    "md",
    "txt",
    "toml",
    "json",
    "jsonc",
    "yaml",
    "yml",
    "js",
    "mjs",
    "cjs",
    "ts",
    "mts",
    "cts",
    "tsx",
    "jsx",
    "proto",
    "sh",
    "bash",
    "zsh",
    "rules",
    "html",
    "css",
    "scss",
    "quint",
    "tla",
    "cfg",
    "ini",
    "lock",
    "csv",
    "log",
    "sql",
    "go",
    "java",
    "kt",
    "swift",
    "dart",
    "c",
    "h",
    "cpp",
    "hpp",
    "graphql",
    "xml",
    "svg",
    "conf",
    "properties",
}
TEXT_BASENAMES = {
    "makefile",
    "dockerfile",
    "containerfile",
    "justfile",
    "license",
    "readme",
    "changelog",
    "notice",
    "codeowners",
    ".gitignore",
    ".gitattributes",
    ".firebaserc",
    ".editorconfig",
    ".prettierrc",
    ".npmrc.example",
}
DATA_EXTENSIONS = {
    "json",
    "jsonc",
    "yaml",
    "yml",
    "toml",
    "txt",
    "ini",
    "cfg",
    "env",
    "properties",
    "csv",
    "conf",
    "xml",
}
SECRET_EXTENSIONS = {
    "pem",
    "key",
    "p12",
    "pfx",
    "jks",
    "keystore",
    "der",
    "gpg",
    "asc",
    "kdbx",
    "tfstate",
    "ovpn",
    "ppk",
    "crt",
    "cer",
}
SECRET_BASENAMES = {
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
    ".htpasswd",
    "credentials",
    "credentials.json",
    "secrets.json",
    "service-account.json",
    "serviceaccount.json",
    "token",
    "token.txt",
    "known_hosts",
    "authorized_keys",
}
SECRET_DIRECTORIES = {
    "docs.local",
    ".git",
    ".ssh",
    ".gnupg",
    ".aws",
    ".gcloud",
    "secrets",
}
SECRET_NAME_WORDS = re.compile(
    r"(^|[^a-z])(secret|credential|password|passwd|token|api[-_]?key|private[-_]?key|"
    r"service[-_]?account|receipt)s?([^a-z]|$)"
)
SSH_KEY_PREFIXES = ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519")
SECRET_CONTENT = re.compile(
    rb"-----BEGIN [A-Z ]*PRIVATE KEY-----|\"private_key\"\s*:|AKIA[0-9A-Z]{16}|"
    rb"ya29\.[0-9A-Za-z_-]{20,}|sk-ant-api[0-9A-Za-z_-]{10,}|gh[pousr]_[0-9A-Za-z]{30,}|"
    rb"xox[abpr]-[0-9A-Za-z-]{10,}"
)


class ContextError(ValueError):
    """The requested input is refused; nothing was read into the context."""


@dataclass(frozen=True)
class ReadInput:
    """One selected line range and the identity of the bytes actually read."""

    path: str
    startLine: int
    endLine: int
    requestedEndLine: int
    lineCount: int
    fileSha256: str
    rangeSha256: str
    rangeBytes: int
    text: str

    def identity(self) -> dict:
        return {
            "path": self.path,
            "startLine": self.startLine,
            "endLine": self.endLine,
            "requestedEndLine": self.requestedEndLine,
            "lineCount": self.lineCount,
            "fileSha256": self.fileSha256,
            "rangeSha256": self.rangeSha256,
            "rangeBytes": self.rangeBytes,
        }


def _refuse(path: str, reason: str) -> ContextError:
    return ContextError(f"input {path!r} refused: {reason}")


def check_relative_path(path: str) -> None:
    if "\x00" in path:
        raise _refuse(path, "NUL byte in path")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in path):
        raise _refuse(path, "control character in path")
    if "\\" in path:
        raise _refuse(path, "backslash in path")
    if path.startswith(("/", "~")):
        raise _refuse(path, "path must be relative to repoRoot")
    if len(path) > 1024:
        raise _refuse(path, "path is longer than 1024 characters")
    components = path.split("/")
    if any(component in ("", ".", "..") for component in components):
        raise _refuse(path, "path must be normalized and must not contain '..'")
    lowered = [component.lower() for component in components]
    for component in lowered:
        if component in SECRET_DIRECTORIES:
            raise _refuse(path, f"'{component}' is not readable by this tool")
        if component.startswith(".env"):
            raise _refuse(path, "dotenv files are never read")
        if component.startswith(SSH_KEY_PREFIXES):
            raise _refuse(path, "looks like an SSH key")
    basename = lowered[-1]
    extension = basename.rsplit(".", 1)[-1] if "." in basename[1:] else ""
    if basename in SECRET_BASENAMES or extension in SECRET_EXTENSIONS:
        raise _refuse(path, "looks like a credential or key file")
    if extension in DATA_EXTENSIONS and SECRET_NAME_WORDS.search(basename):
        raise _refuse(path, "data file whose name suggests credentials or receipts")
    if extension not in TEXT_EXTENSIONS and basename not in TEXT_BASENAMES:
        raise _refuse(
            path, f"extension {extension or '(none)'!r} is not on the text allowlist"
        )


def resolve_repo_root(repo_root: str) -> str:
    if not os.path.isabs(repo_root):
        raise ContextError("repoRoot must be absolute")
    real = os.path.realpath(repo_root)
    if not os.path.isdir(real):
        raise ContextError(f"repoRoot {repo_root!r} is not a directory")
    return real


def resolve_inside(real_root: str, path: str) -> str:
    """Return the absolute file path after refusing symlinks and escapes."""
    check_relative_path(path)
    current = real_root
    for component in path.split("/"):
        current = os.path.join(current, component)
        if os.path.islink(current):
            raise _refuse(path, "symlinks are not followed")
    full = current
    real_full = os.path.realpath(full)
    if real_full != full or not real_full.startswith(real_root + os.sep):
        raise _refuse(path, "resolves outside repoRoot")
    if not os.path.isfile(full):
        raise _refuse(path, "not a regular file")
    return full


def _file_version(info: os.stat_result) -> tuple[int, ...]:
    # atime is omitted: our own read may update it. ctime catches same-size rewrites
    # even when another writer restores mtime, and nlink catches unlink/replace.
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
        info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    )


def _read_regular_file(real_root: str, path: str) -> bytes:
    """Read through no-follow directory descriptors, not a re-resolved pathname.

    The earlier path checks provide policy and useful diagnostics, not a lock.
    Every component (including repoRoot ancestors) must still be a directory
    when opened. A rename after opening a directory cannot redirect its fd.
    This is not an OS sandbox: hard links, hostile mounts, and a malicious
    same-user process are outside the guarantee.
    """
    if not _FD_READ_SUPPORTED:
        raise _refuse(path, "no-follow descriptor reads are unsupported")
    if not os.path.isabs(real_root) or os.path.normpath(real_root) != real_root:
        raise _refuse(path, "repoRoot must be resolved before reading")
    check_relative_path(path)
    directory = file_fd = None
    try:
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        directory_flags |= getattr(os, "O_CLOEXEC", 0)
        directory = os.open(os.sep, directory_flags)
        components = [part for part in real_root.split(os.sep) if part]
        components.extend(path.split("/")[:-1])
        for component in components:
            child = os.open(component, directory_flags, dir_fd=directory)
            os.close(directory)
            directory = child
        # O_NONBLOCK prevents a replaced FIFO from hanging before fstat can reject it.
        file_fd = os.open(
            path.split("/")[-1],
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0),
            dir_fd=directory,
        )
        before = os.fstat(file_fd)
        if not stat.S_ISREG(before.st_mode):
            raise _refuse(path, "not a regular file")
        if before.st_size > MAX_FILE_BYTES:
            raise _refuse(path, f"file is larger than {MAX_FILE_BYTES} bytes")
        data = bytearray()
        while len(data) <= MAX_FILE_BYTES:
            chunk = os.read(file_fd, min(65_536, MAX_FILE_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > MAX_FILE_BYTES:
            raise _refuse(path, f"file is larger than {MAX_FILE_BYTES} bytes")
        after = os.fstat(file_fd)
        if _file_version(before) != _file_version(after) or len(data) != before.st_size:
            raise _refuse(path, "file changed while reading; use a stable snapshot")
        return bytes(data)
    except OSError:
        # Do not expose absolute destinations or filesystem exception contents.
        raise _refuse(path, "path changed, contains a symlink, or cannot be read") from None
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if directory is not None:
            os.close(directory)


def read_selection(real_root: str, selection: InputSelection) -> ReadInput:
    resolve_inside(real_root, selection.path)
    data = _read_regular_file(real_root, selection.path)
    if b"\x00" in data:
        raise _refuse(selection.path, "binary content (NUL byte)")
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise _refuse(selection.path, f"not valid UTF-8 ({error.reason})") from None
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    line_count = len(lines)
    if selection.startLine > line_count:
        raise _refuse(
            selection.path,
            f"startLine {selection.startLine} is beyond the last line ({line_count})",
        )
    end = min(selection.endLine, line_count)
    selected = b"\n".join(lines[selection.startLine - 1 : end])
    if SECRET_CONTENT.search(selected):
        raise _refuse(selection.path, "selected lines contain credential-like content")
    return ReadInput(
        path=selection.path,
        startLine=selection.startLine,
        endLine=end,
        requestedEndLine=selection.endLine,
        lineCount=line_count,
        fileSha256=hashlib.sha256(data).hexdigest(),
        rangeSha256=hashlib.sha256(selected).hexdigest(),
        rangeBytes=len(selected),
        text=selected.decode("utf-8"),
    )


def read_inputs(
    repo_root: str, selections: tuple[InputSelection, ...]
) -> list[ReadInput]:
    real_root = resolve_repo_root(repo_root)
    return [read_selection(real_root, selection) for selection in selections]


def render_numbered(item: ReadInput) -> str:
    """Render the selection with line numbers so citations can be checked."""
    header = f"=== {item.path} (lines {item.startLine}-{item.endLine} of {item.lineCount}) ===\n"
    body = "\n".join(
        f"{number:>6}| {line}"
        for number, line in enumerate(item.text.split("\n"), start=item.startLine)
    )
    return header + body + "\n"


def estimate_tokens(text: str) -> int:
    return math.ceil(len(text.encode("utf-8")) / BYTES_PER_TOKEN)
