"""Verify pre-disable-fix observations and approvals at their fixed source."""

import argparse
import os
import subprocess

from history import ROOT, offline_environment, snapshot, verify_frozen

__all__ = ["verify_frozen"]
ANCHOR = "1856e4708c7abe2dd0e329f5593d6c46a32c6849"
FROZEN = (
    "tools/auth-disabled",
    "tools/publish-auth-disabled.py",
    "spec/compatibility/evidence/auth-disabled",
    "docs/compatibility/auth-disabled.md",
    "tools/publish-auth-password-unicode-recheck.py",
    "tools/auth-password-unicode-recheck-approval.py",
    "tools/test_unicode_recheck.py",
    "tools/test_unicode_approval.py",
    "spec/compatibility/evidence/auth-password-unicode-recheck",
    "docs/compatibility/auth-password-unicode-recheck.md",
    "docs/compatibility/auth-password-unicode-recheck-approval.md",
    "tools/auth-password-unicode-boundary",
    "tools/publish-auth-password-unicode-boundary.py",
    "tools/auth-password-unicode-boundary-approval.py",
    "tools/test_boundary_approval.py",
    "spec/compatibility/evidence/auth-password-unicode-boundary",
    "docs/compatibility/auth-password-unicode-boundary.md",
    "docs/compatibility/auth-password-unicode-boundary-approval.md",
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
                "tools/auth-disabled",
                "tools/auth-password-unicode-boundary",
                "tools/test_unicode_recheck.py",
                "tools/test_unicode_approval.py",
                "tools/test_boundary_approval.py",
                "-q",
            ]
        ]
        commands.extend(
            [checker, "--check"]
            for checker in (
                "tools/publish-auth-disabled.py",
                "tools/publish-auth-password-unicode-recheck.py",
                "tools/auth-password-unicode-recheck-approval.py",
                "tools/publish-auth-password-unicode-boundary.py",
                "tools/auth-password-unicode-boundary-approval.py",
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
        "Pre-disable-fix observations and approvals unchanged and verified at " + ANCHOR
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", required=True)
    parser.parse_args()
    check()
