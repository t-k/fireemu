"""Regression tests from the owner review of 892917a57 (2026-09-21).

Source: docs.local/reviews/2026-09-21/owner-review-892917a57/
  review.md, test_fireemu_log_parser_review_892917a.py,
  fireemu_review_892917a_results.json

Adapted from the standalone FIREEMU_REPO-based script to this repo's
`local_assist.log_parser` import (see conftest.py). Two items:

1. `_pytest_short()` assumed balanced brackets inside a parametrize id; a
   value containing an unbalanced `[` or `]` desynced the id/message split.
2. `_join_short_summaries()` / `parse_pytest()` dropped the FAILED/ERROR
   kind through the join, so a body failure plus a teardown error of the
   same test produced four failure blocks instead of two joined ones.

At 892917a57: 2 positive controls passed, 3 regression cases failed.
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
    return parse_log(result.stdout)


def test_positive_control_plain_failure(tmp_path):
    parsed = run_case(tmp_path, "def test_bad():\n    assert False\n")
    assert len(parsed.failures) == 1
    assert parsed.failures[0].group == "test_case.py"
    assert parsed.failures[0].name == "test_bad"
    assert parsed.summary["failed"] == 1


def test_positive_control_balanced_parameter_with_separator(tmp_path):
    source = (
        'import pytest\n@pytest.mark.parametrize("value", ["[value - suffix]"])\n'
        "def test_bad(value):\n    assert False\n"
    )
    parsed = run_case(tmp_path, source, "--tb=no")
    assert len(parsed.failures) == 1
    assert parsed.failures[0].name == "test_bad[[value - suffix]]"
    assert parsed.failures[0].message == ["assert False"]


@pytest.mark.parametrize(
    "value,expected_name",
    [
        ("[", "test_bad[[]"),
        ("] - suffix", "test_bad[] - suffix]"),
    ],
)
def test_parameter_bracket_does_not_corrupt_nodeid(tmp_path, value, expected_name):
    source = (
        "import pytest\n"
        f'@pytest.mark.parametrize("value", [{value!r}])\n'
        "def test_bad(value):\n    assert False\n"
    )
    parsed = run_case(tmp_path, source, "--tb=no")
    assert len(parsed.failures) == 1
    assert parsed.failures[0].name == expected_name
    assert parsed.failures[0].message == ["assert False"]


def test_call_failure_and_teardown_error_are_not_duplicated(tmp_path):
    source = (
        "import pytest\n@pytest.fixture\ndef fixture():\n"
        '    yield\n    raise RuntimeError("teardown failure")\n'
        "def test_bad(fixture):\n    assert False\n"
    )
    parsed = run_case(tmp_path, source)
    assert parsed.summary["failed"] == 1
    assert parsed.summary["errors"] == 1
    assert len(parsed.failures) == 2, parsed.to_dict()
    assert all(item.group == "test_case.py" for item in parsed.failures)
    assert all(item.location is not None for item in parsed.failures)
