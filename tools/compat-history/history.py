"""Verify immutable evidence at a reviewed Git anchor, never at a receipt-selected revision."""

import argparse
import os
import re
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

ANCHOR = "672db735ad36dc8f473b98bac2906f19f37bb70b"
ROOT = Path(__file__).resolve().parents[2]
TEST_DIRS = (
    "tools/compat-inventory",
    "tools/aggregation-limit",
    "tools/auth-basic",
    "tools/auth-basic-v2",
    "tools/auth-profile",
    "tools/auth-display-name",
    "tools/auth-password",
    "tools/auth-session-token",
)
CHECKERS = (
    "tools/compat-inventory/publish.py",
    "tools/publish-auth-basic.py",
    "tools/publish-auth-v2.py",
    "tools/auth-v2-approval.py",
    "tools/publish-auth-profile.py",
    "tools/auth-profile-approval.py",
    "tools/publish-auth-display-name.py",
    "tools/auth-display-name-approval.py",
    "tools/publish-auth-password.py",
    "tools/auth-password-approval.py",
    "tools/publish-auth-session-token.py",
)
FROZEN = (
    TEST_DIRS
    + CHECKERS[1:]
    + (
        "spec/compatibility/acquisition.json",
        "spec/compatibility/upstream",
        "spec/compatibility/observations",
    )
    + tuple(
        "spec/compatibility/evidence/" + name
        for name in (
            "aggregation",
            "history",
            "auth-basic",
            "auth-basic-v2",
            "auth-profile",
            "auth-display-name",
            "auth-password",
            "auth-session-token",
        )
    )
    + tuple(
        "docs/compatibility/" + name + ".md"
        for name in (
            "acquisition",
            "aggregation-evidence",
            "auth-basic-evidence",
            "auth-basic-source-review",
            "auth-basic-v2",
            "auth-basic-v2-approval",
            "auth-profile",
            "auth-profile-approval",
            "auth-display-name",
            "auth-display-name-approval",
            "auth-password",
            "auth-password-approval",
            "auth-session-token",
        )
    )
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def git(root, *args):
    try:
        return subprocess.check_output(
            ["git", "-c", "core.hooksPath=/dev/null", "-C", str(root), *args],
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as error:
        raise ValueError("Required local Git history unavailable") from error


def verify_frozen(root, anchor, prefixes):
    require(re.fullmatch(r"[0-9a-f]{40}", anchor), "Full pinned commit required")
    require(
        git(root, "rev-parse", anchor + "^{commit}").decode().strip() == anchor,
        "Wrong anchor",
    )
    require(bool(prefixes), "Frozen paths required")
    for prefix in prefixes:
        parts = PurePosixPath(prefix).parts
        require(
            bool(parts) and not prefix.startswith(("/", ":")) and ".." not in parts,
            "Unsafe frozen path",
        )
    listing = git(root, "ls-tree", "-r", "-z", anchor, "--", *prefixes)
    entries = {}
    for row in listing.split(b"\0"):
        if not row:
            continue
        meta, name = row.split(b"\t", 1)
        mode, kind, oid = meta.split()
        require(
            mode in (b"100644", b"100755") and kind == b"blob",
            "Nonregular frozen input",
        )
        entries[name.decode()] = oid.decode()
    require(bool(entries), "Empty frozen set")
    current = set(
        git(
            root,
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            *prefixes,
        )
        .decode()
        .split("\0")
    ) - {""}
    require(current == set(entries), "Frozen file membership changed")
    ignored = (
        git(
            root,
            "ls-files",
            "-z",
            "--others",
            "--ignored",
            "--exclude-standard",
            "--",
            *prefixes,
        )
        .decode()
        .split("\0")
    )
    for name in filter(None, ignored):
        parts = PurePosixPath(name).parts
        cache = name.startswith("tools/") and any(
            part in {".venv", "__pycache__", ".pytest_cache", ".ruff_cache"}
            for part in parts[:-1]
        )
        require(cache, "Ignored frozen file added: " + name)
    for name, oid in entries.items():
        path = root / name
        relative = PurePosixPath(name)
        require(
            path.is_file()
            and not any((root / p).is_symlink() for p in (relative, *relative.parents)),
            "Missing or linked frozen input",
        )
        require(
            path.read_bytes() == git(root, "cat-file", "blob", oid),
            "Frozen bytes changed: " + name,
        )


@contextmanager
def snapshot(root, anchor, prefixes):
    root = root.resolve()
    verify_frozen(root, anchor, prefixes)
    with tempfile.TemporaryDirectory(prefix="fireemu-history-") as temporary:
        archived = Path(temporary) / "source"
        subprocess.run(
            [
                "git",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "init.templateDir=",
                "clone",
                "--quiet",
                "--shared",
                "--local",
                "--no-checkout",
                str(root),
                str(archived),
            ],
            check=True,
        )
        git(archived, "checkout", "--quiet", "--detach", anchor)
        require(
            git(archived, "rev-parse", "HEAD").decode().strip() == anchor,
            "Wrong snapshot revision",
        )
        verify_frozen(archived, anchor, prefixes)
        yield archived
        verify_frozen(root, anchor, prefixes)


def offline_environment(source):
    return {
        key: value
        for key, value in source.items()
        if not key.endswith("LIVE_LOCAL")
        and not key.startswith(("PYTHON", "PYTEST", "GIT_"))
        and key not in {"FIREEMU_EVIDENCE_BINARY", "VIRTUAL_ENV"}
    }


def check(root=ROOT):
    env = offline_environment(os.environ)
    with snapshot(root, ANCHOR, FROZEN) as archived:
        uv = [
            "uv",
            "run",
            "--project",
            "tools/compat-inventory",
            "--locked",
            "--python",
            "3.12",
        ]
        subprocess.run(
            [*uv, "-m", "pytest", *TEST_DIRS, "-q"], cwd=archived, env=env, check=True
        )
        for checker in CHECKERS:
            subprocess.run([*uv, checker, "--check"], cwd=archived, env=env, check=True)
    print("Historical evidence unchanged and verified at " + ANCHOR)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", required=True)
    parser.parse_args()
    check()
