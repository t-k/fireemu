"""Verify the original Unicode mismatch at its fixed pre-fix source."""

import argparse
import os
import subprocess

from history import ROOT, offline_environment, snapshot, verify_frozen

__all__ = ["verify_frozen"]
ANCHOR = "51724d98514bc54e1cb9a516c3cde74e4b66664e"
FROZEN = (
    "tools/auth-password-unicode",
    "tools/publish-auth-password-unicode.py",
    "spec/compatibility/evidence/auth-password-unicode",
    "docs/compatibility/auth-password-unicode.md",
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
        for args in (
            ["-m", "pytest", "tools/auth-password-unicode", "-q"],
            ["tools/publish-auth-password-unicode.py", "--check"],
        ):
            subprocess.run(
                [*uv, *args],
                cwd=archived,
                env=offline_environment(os.environ),
                check=True,
            )
    print("Original Unicode mismatch unchanged and verified at " + ANCHOR)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", required=True)
    parser.parse_args()
    check()
