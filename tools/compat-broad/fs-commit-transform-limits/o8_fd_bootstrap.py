"""External, offline gate for an exclusively owned O8 source zipapp.

Run with the pinned interpreter as: python -I -S -B o8_fd_bootstrap.py FD SHA256 [archive args...].
The caller must bind this bootstrap and the interpreter separately, create the archive
without exposing another writable alias, and pass only its unlinked read-only FD.
POSIX cannot revoke a writable alias held before unlink; this is a conditional
exclusive-writer-ownership claim, not kernel-enforced immutability.
"""

import fcntl
import hashlib
import os
import stat
import sys
import zipfile

MAX_ARCHIVE_BYTES = 32 * 1024 * 1024


def verify(fd: int, expected: str) -> None:
    if len(expected) != 64 or any(character not in "0123456789abcdef" for character in expected):
        raise ValueError("invalid archive digest")
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    before = os.fstat(fd)
    if flags & os.O_ACCMODE != os.O_RDONLY:
        raise ValueError("archive descriptor is writable")
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 0:
        raise ValueError("archive descriptor is not an unlinked regular file")
    if before.st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("archive too large")
    data = os.pread(fd, before.st_size + 1, 0)
    if len(data) != before.st_size or hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("archive digest differs")
    with os.fdopen(os.dup(fd), "rb") as reader:
        with zipfile.ZipFile(reader) as bundle:
            if "__main__.py" not in bundle.namelist():
                raise ValueError("archive main missing")
    after = os.fstat(fd)
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
        before.st_nlink,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
        after.st_nlink,
    ):
        raise ValueError("archive descriptor changed during validation")


def main() -> int:
    if not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode):
        raise ValueError("interpreter must use -I -S -B")
    if len(sys.argv) < 3 or not sys.argv[1].isascii() or not sys.argv[1].isdecimal():
        raise ValueError("expected descriptor and digest")
    fd = int(sys.argv[1])
    verify(fd, sys.argv[2])
    os.set_inheritable(fd, True)
    os.execv(
        sys.executable,
        [sys.executable, "-I", "-S", "-B", f"/dev/fd/{fd}", *sys.argv[3:]],
    )
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        print(f"O8 archive bootstrap refused: {error}", file=sys.stderr)
        sys.exit(1)
