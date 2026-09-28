"""Verify pre-deletion-fix observations and approvals at their fixed source."""

import argparse
import os
import subprocess

from history import ROOT, offline_environment, snapshot, verify_frozen

__all__ = ["verify_frozen"]
ANCHOR = "3e565f5775c255d8f39168f5aeb27258a770c6c8"
FROZEN = (
    "tools/auth-deleted",
    "tools/publish-auth-deleted.py",
    "spec/compatibility/evidence/auth-deleted",
    "docs/compatibility/auth-deleted.md",
    "tools/publish-auth-disabled-recheck.py",
    "tools/auth-disabled-recheck-approval.py",
    "tools/test_disabled_recheck.py",
    "tools/test_disabled_approval.py",
    "spec/compatibility/evidence/auth-disabled-recheck",
    "docs/compatibility/auth-disabled-recheck.md",
    "docs/compatibility/auth-disabled-recheck-approval.md",
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
                "tools/auth-deleted",
                "tools/test_disabled_recheck.py",
                "tools/test_disabled_approval.py",
                "-q",
            ]
        ]
        commands.extend(
            [checker, "--check"]
            for checker in (
                "tools/publish-auth-deleted.py",
                "tools/publish-auth-disabled-recheck.py",
                "tools/auth-disabled-recheck-approval.py",
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
        "Pre-deletion-fix observations and approvals unchanged and verified at "
        + ANCHOR
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", required=True)
    parser.parse_args()
    check()
