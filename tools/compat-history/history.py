"""Verify immutable evidence at a reviewed Git anchor, never at a receipt-selected revision."""

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

ANCHOR = "672db735ad36dc8f473b98bac2906f19f37bb70b"
ROOT = Path(__file__).resolve().parents[2]
# The one declared rebind of frozen bytes: the 2026-11-10 mask of the old oracle project number. The record lists,
# for every file it changed, the sha256 the file had at the anchor and the sha256 it has now.
REBIND_RECORD = "spec/compatibility/oracle-number-mask-2026-11-10.json"
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
HISTORICAL_ASSETS = (
    "spec/compatibility/acquisition.json",
    "spec/compatibility/upstream",
    "spec/compatibility/observations",
) + tuple(
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
) + tuple(
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
FROZEN = TEST_DIRS + CHECKERS[1:] + HISTORICAL_ASSETS
CURRENT_FROZEN = TEST_DIRS[1:] + CHECKERS + HISTORICAL_ASSETS


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


def load_rebound(root):
    """Frozen files the mask record changed, as {path: (sha256 at the anchor, sha256 now)}."""
    record = Path(root) / REBIND_RECORD
    if not record.is_file():
        return {}
    files = json.loads(record.read_bytes())["files"]
    return {name: (info["preSha256"], info["postSha256"]) for name, info in files.items()}


def verify_frozen(root, anchor, prefixes, rebound=None):
    """Compare the working tree with the anchor; `rebound` names the only files allowed to differ, each
    pinned to the exact bytes it had at the anchor and the exact bytes it must have now. Without `rebound`
    the record of `root` is used (none in an archived anchor checkout, so that checkout stays byte-exact)."""
    if rebound is None:
        rebound = load_rebound(root)
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
        blob = git(root, "cat-file", "blob", oid)
        if name in rebound:
            before, after = rebound[name]
            require(
                hashlib.sha256(blob).hexdigest() == before,
                "Rebind record does not match the anchor: " + name,
            )
            require(
                hashlib.sha256(path.read_bytes()).hexdigest() == after,
                "Frozen bytes changed after the rebind: " + name,
            )
        else:
            require(path.read_bytes() == blob, "Frozen bytes changed: " + name)


@contextmanager
def snapshot(root, anchor, prefixes, *, current_prefixes=None):
    root = root.resolve()
    current_prefixes = prefixes if current_prefixes is None else current_prefixes
    rebound = load_rebound(root)
    verify_frozen(root, anchor, current_prefixes, rebound)
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
                "--local",
                "--no-hardlinks",
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
        verify_frozen(archived, anchor, prefixes, {})
        try:
            yield archived
        finally:
            verify_frozen(root, anchor, current_prefixes, rebound)


def offline_environment(source):
    return {
        "PATH": source.get("PATH", os.defpath),
        "PYTHONNOUSERSITE": "1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    }


def check(root=ROOT):
    env = offline_environment(os.environ)
    with tempfile.TemporaryDirectory(prefix="fireemu-history-uv-") as environment:
        env["UV_PROJECT_ENVIRONMENT"] = str(Path(environment) / "venv")
        with snapshot(
            root, ANCHOR, FROZEN, current_prefixes=CURRENT_FROZEN
        ) as archived:
            check_archived(archived, env)


def check_archived(archived, env):
    uv = [
        "uv",
        "--no-config",
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
