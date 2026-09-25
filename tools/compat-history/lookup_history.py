"""Verify pre-lookup-authorization-fix observations and approvals at their fixed source."""

import argparse
import os
import subprocess

from history import ROOT, offline_environment, snapshot, verify_frozen

__all__ = ["verify_frozen"]
ANCHOR = "5c17391656aa31504611205270178533d8c7badf"
FROZEN = (
    "tools/auth-deleted-recheck",
    "tools/publish-auth-deleted-recheck.py",
    "tools/auth-deleted-recheck-approval.py",
    "tools/test_deleted_recheck.py",
    "tools/test_deleted_approval.py",
    "spec/compatibility/evidence/auth-deleted-recheck",
    "docs/compatibility/auth-deleted-recheck.md",
    "docs/compatibility/auth-deleted-recheck-approval.md",
)


def check():
    with snapshot(ROOT, ANCHOR, FROZEN) as archived:
        uv = [
            "uv",
            "run",
            "--project",
            "tools/compat-inventory",
            "--locked",
            "--python",
            "3.12",
        ]
        commands = [
            [
                "-m",
                "pytest",
                "tools/test_deleted_recheck.py",
                "tools/test_deleted_approval.py",
                "-q",
            ]
        ]
        commands.extend(
            [checker, "--check"]
            for checker in (
                "tools/publish-auth-deleted-recheck.py",
                "tools/auth-deleted-recheck-approval.py",
            )
        )
        for args in commands:
            subprocess.run(
                [*uv, *args],
                cwd=archived,
                env=offline_environment(os.environ),
                check=True,
            )
    print(
        "Pre-lookup-authorization-fix observations and approvals unchanged and verified at "
        + ANCHOR
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", required=True)
    parser.parse_args()
    check()
