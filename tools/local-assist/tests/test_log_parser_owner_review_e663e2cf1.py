"""Regression tests from the owner review of e663e2cf1 (2026-09-21).

Source: docs.local/reviews/2026-09-21/owner-review-e663e2cf1/
  review.md, test_fireemu_log_parser_review_e663e2c.py,
  fireemu_review_e663e2c_results.json

Adapted from the standalone FIREEMU_REPO-based script to this repo's
`local_assist.log_parser` import (see conftest.py), and from `parser` /
`run_case` fixtures to a plain module-level `run_case` matching the sibling
`test_log_parser_owner_review_892917a57.py` adoption.

One item: `_pytest_short()`'s rightmost `] - ` anchor (added to fix the
892917a57 review) scans the *message* too, not just the id. A raised
message containing its own `[...] - ...` (e.g. `ValueError("[payload] -
invalid")`) desyncs the split: `FAILED test_case.py::test_bad - ValueError:
[payload] - invalid` was read as name `test_bad - ValueError: [payload]`,
message `invalid`. With a traceback present, the detail block and the
broken short-summary row then fail to join, turning one failure into two
blocks.

At e663e2cf1: 2 positive controls passed, 4 regression cases failed.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from local_assist.log_parser import parse_log


def run_case(tmp_path: Path, source: str, *extra: str):
    (tmp_path / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    (tmp_path / "test_case.py").write_text(source, encoding="utf-8")
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith("PYTEST_") and k != "PYTHONPATH"
    }
    env.update(PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", COLUMNS="220")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-c",
            "pytest.ini",
            "-q",
            "--color=no",
            *extra,
            "test_case.py",
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    return parse_log(result.stdout), result.stdout


@pytest.mark.parametrize(
    "parameterized", [False, True], ids=["plain-id", "parameterized-id"]
)
@pytest.mark.parametrize(
    "traceback_mode", ["no", "long"], ids=["without-detail", "with-detail"]
)
def test_message_delimiter_cannot_become_part_of_nodeid(
    tmp_path, parameterized, traceback_mode
):
    source = (
        (
            'import pytest\n@pytest.mark.parametrize("value", ["ok"])\n'
            "def test_bad(value):\n"
        )
        if parameterized
        else "def test_bad():\n"
    ) + '    raise ValueError("[payload] - invalid")\n'
    expected_name = "test_bad[ok]" if parameterized else "test_bad"
    parsed, log = run_case(tmp_path, source, f"--tb={traceback_mode}")
    assert parsed.summary["failed"] == 1, log
    assert len(parsed.failures) == 1, parsed.to_dict()
    failure = parsed.failures[0]
    assert failure.group == "test_case.py", parsed.to_dict()
    assert failure.name == expected_name, parsed.to_dict()
    if traceback_mode == "no":
        assert failure.message == ["ValueError: [payload] - invalid"], parsed.to_dict()


@pytest.mark.parametrize("message", ["some - message - here", "x in [1, 2, 3]"])
def test_positive_message_controls(tmp_path, message):
    source = f"def test_bad():\n    raise ValueError({message!r})\n"
    parsed, log = run_case(tmp_path, source, "--tb=no")
    assert len(parsed.failures) == 1, log
    assert parsed.failures[0].group == "test_case.py", parsed.to_dict()
    assert parsed.failures[0].name == "test_bad", parsed.to_dict()
    assert parsed.failures[0].message == [f"ValueError: {message}"], parsed.to_dict()
