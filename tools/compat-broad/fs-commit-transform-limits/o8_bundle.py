"""Deterministic, offline source-only zipapp for an O7-reviewed module closure.

The caller supplies the complete source manifest and the expected archive digest.
This module neither discovers modules nor grants execution permission.
"""

import fcntl
import hashlib
import io
import os
import re
import stat
import tempfile
import zipfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path

MAX_FILES = 128
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _names(manifest: Mapping[str, str]) -> list[str]:
    if not 1 <= len(manifest) <= MAX_FILES or "__main__.py" not in manifest:
        raise ValueError("invalid reviewed source closure")
    for name, expected in manifest.items():
        if (
            not isinstance(name, str)
            or re.fullmatch(r"[A-Za-z0-9_./-]+", name) is None
            or not name.endswith(".py")
            or name.startswith("/")
            or "\\" in name
            or any(part in ("", ".", "..") for part in name.split("/"))
            or not isinstance(expected, str)
            or len(expected) != 64
            or any(c not in "0123456789abcdef" for c in expected)
        ):
            raise ValueError("invalid reviewed source closure")
    return sorted(manifest)


def _source_bytes(root: Path, name: str) -> bytes:
    """Open every component without following a replaceable symlink."""
    try:
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            parts = name.split("/")
            for component in parts[:-1]:
                child = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=directory,
                )
                os.close(directory)
                directory = child
            source_fd = os.open(
                parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory
            )
            try:
                source_stat = os.fstat(source_fd)
                if (
                    not stat.S_ISREG(source_stat.st_mode)
                    or source_stat.st_size > MAX_FILE_BYTES
                ):
                    raise ValueError("source type or size rejected")
                with os.fdopen(source_fd, "rb", closefd=False) as source:
                    data = source.read(MAX_FILE_BYTES + 1)
            finally:
                os.close(source_fd)
        finally:
            os.close(directory)
    except OSError as error:
        raise ValueError("reviewed source unavailable") from error
    if len(data) > MAX_FILE_BYTES:
        raise ValueError("source too large")
    return data


def _encode(sources: Mapping[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(
        output, "w", compression=zipfile.ZIP_STORED, allowZip64=False
    ) as bundle:
        for name in sorted(sources):
            info = zipfile.ZipInfo(name, _TIMESTAMP)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            bundle.writestr(info, sources[name])
    archive = output.getvalue()
    if len(archive) > MAX_ARCHIVE_BYTES:
        raise ValueError("archive too large")
    return archive


def build_archive(root: Path, manifest: Mapping[str, str]) -> tuple[bytes, str]:
    """Build a canonical zipapp from precisely the reviewed source paths."""
    names = _names(manifest)
    sources = {name: _source_bytes(root, name) for name in names}
    if any(_digest(sources[name]) != manifest[name] for name in names):
        raise ValueError("reviewed source digest differs")
    archive = _encode(sources)
    return archive, _digest(archive)


def verify_archive(
    archive: bytes, manifest: Mapping[str, str], expected_sha256: str
) -> None:
    """Reject any byte or member that differs from the reviewed closure."""
    names = _names(manifest)
    if len(archive) > MAX_ARCHIVE_BYTES or _digest(archive) != expected_sha256:
        raise ValueError("archive digest or size differs")
    try:
        with zipfile.ZipFile(io.BytesIO(archive), "r") as bundle:
            infos = bundle.infolist()
            if len(infos) != len(names) or [info.filename for info in infos] != names:
                raise ValueError("archive member closure differs")
            if any(
                info.compress_type != zipfile.ZIP_STORED
                or info.file_size > MAX_FILE_BYTES
                or info.compress_size != info.file_size
                for info in infos
            ):
                raise ValueError("archive member format or size differs")
            sources = {info.filename: bundle.read(info) for info in infos}
    except (OSError, zipfile.BadZipFile, RuntimeError, EOFError) as error:
        raise ValueError("invalid source archive") from error
    if any(_digest(sources[name]) != manifest[name] for name in names):
        raise ValueError("archive source digest differs")
    if _encode(sources) != archive:
        raise ValueError("noncanonical source archive")


def verify_archive_fd(fd: int, expected_sha256: str) -> None:
    """Check an unlinked, read-only archive descriptor against reviewed bytes."""
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    info = os.fstat(fd)
    if flags & os.O_ACCMODE != os.O_RDONLY:
        raise ValueError("archive FD must be read-only")
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 0:
        raise ValueError("archive FD must be an unlinked regular file")
    if info.st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("archive FD too large")
    content = os.pread(fd, info.st_size + 1, 0)
    if len(content) != info.st_size or _digest(content) != expected_sha256:
        raise ValueError("archive FD digest differs")
    later = os.fstat(fd)
    if (
        later.st_dev,
        later.st_ino,
        later.st_size,
        later.st_mtime_ns,
        later.st_ctime_ns,
        later.st_nlink,
    ) != (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_nlink,
    ):
        raise ValueError("archive FD changed during verification")


@contextmanager
def unlinked_archive_fd(archive: bytes, expected_sha256: str) -> Iterator[int]:
    """Own the writable descriptor, close it, then expose an unlinked read-only FD.

    Callers must retain exclusive ownership of the archive bytes and descriptor.
    POSIX cannot revoke a writable descriptor leaked to another process before unlink.
    """
    if len(archive) > MAX_ARCHIVE_BYTES or _digest(archive) != expected_sha256:
        raise ValueError("archive digest or size differs")
    with tempfile.TemporaryDirectory(prefix="o8-archive-") as directory:
        path = Path(directory) / "bundle.pyz"
        writer = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400
        )
        try:
            view = memoryview(archive)
            while view:
                view = view[os.write(writer, view) :]
            os.fsync(writer)
        finally:
            os.close(writer)
        reader = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.unlink(path)
            verify_archive_fd(reader, expected_sha256)
            yield reader
            verify_archive_fd(reader, expected_sha256)
        finally:
            os.close(reader)
