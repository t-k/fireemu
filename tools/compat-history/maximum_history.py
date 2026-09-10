"""Verify maximum approval at its fixed trusted pre-field-authorization anchor."""

import argparse
import os
import subprocess

from history import ROOT, offline_environment, snapshot, verify_frozen

__all__ = ["verify_frozen"]

ANCHOR = "7d76ab0adc9db719d5d983bc2ca9ece1c0d459d0"
SLICES = ("auth-password-maximum",)
TEST_DIRS = tuple("tools/" + name for name in SLICES)
CHECKERS = tuple(
    path
    for name in SLICES
    for path in ("tools/publish-" + name + ".py", "tools/" + name + "-approval.py")
)
FROZEN = (
    TEST_DIRS
    + CHECKERS
    + tuple("spec/compatibility/evidence/" + name for name in SLICES)
    + tuple(
        "docs/compatibility/" + name + suffix + ".md"
        for name in SLICES
        for suffix in ("", "-approval")
    )
)


def check():
    env = offline_environment(os.environ)
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
        subprocess.run(
            [*uv, "-m", "pytest", *TEST_DIRS, "-q"], cwd=archived, env=env, check=True
        )
        for checker in CHECKERS:
            subprocess.run([*uv, checker, "--check"], cwd=archived, env=env, check=True)
    print("Maximum historical approval unchanged and verified at " + ANCHOR)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", required=True)
    parser.parse_args()
    check()
