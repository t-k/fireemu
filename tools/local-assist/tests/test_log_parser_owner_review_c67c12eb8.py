"""Regression tests from the owner review of c67c12eb8 (2026-09-21).

Source: docs.local/reviews/2026-09-21/owner-review-c67c12eb8/
  review.md, test_fireemu_log_parser_review_c67c12e.py,
  fireemu_review_c67c12e_results.json

Adapted from the standalone FIREEMU_REPO-based script to this repo's
`local_assist.log_parser` import (see conftest.py), and from `parser` /
`run_case` fixtures to a plain module-level `run_case` matching the sibling
`test_log_parser_owner_review_892917a57.py` / `_e663e2cf1.py` adoptions.

Two items:

1. `parse_pytest()`'s PYTEST_VERBOSE progress-line match ran before the
   FAILED/ERROR short-summary parse and on any line, not just inside a
   verbose (-v) progress section. Its regex accepts any line ending in
   "... PASSED/FAILED/ERROR", so a short-summary row whose *message*
   happens to end that way -- "FAILED test_case.py::test_bad - ValueError:
   ERROR" -- was itself misread as "<nodeid> ERROR" and silently dropped
   instead of becoming a failure. Fixed by section (track the "short test
   summary info" banner and never try PYTEST_VERBOSE inside it) and by
   shape (a line starting with "FAILED "/"ERROR " is never a progress
   line: a real nodeid never starts with a bare status word).

2. `_well_formed_nodeid()` rejected any candidate whose bracket portion
   closed and then reopened, but a parametrize value can contain
   '] ... [' as literal text (value="] - [x" produces the entirely valid
   id "test_bad[] - [x]"), so the correct candidate was excluded and the
   truncated "test_bad[]" -- the only remaining candidate -- came back as
   uniquely well-formed and wrongly marked idResolved=True. Fixed by only
   disqualifying a reopen when something other than the bare " - " split
   separator sits between the close and it (real message text does; a
   parameter's own literal characters do not); when that no longer
   decides a case, more than one candidate stays well-formed and the line
   is kept raw with idResolved=False rather than guessing.

At c67c12eb8: 3 positive controls passed, 6 regression cases failed (4 for
item 1, 2 for item 2).
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


@pytest.mark.parametrize("message", ["ERROR", "FAILED", "PASSED"])
def test_status_word_in_failure_message_is_not_a_progress_line(tmp_path, message):
    source = f"def test_bad():\n    raise ValueError({message!r})\n"
    parsed, log = run_case(tmp_path, source, "--tb=no")
    assert parsed.summary["failed"] == 1, log
    assert len(parsed.failures) == 1, parsed.to_dict()
    failure = parsed.failures[0]
    assert failure.name == "test_bad"
    assert failure.group == "test_case.py"
    assert failure.message == [f"ValueError: {message}"]


def test_status_word_in_setup_error_message_is_not_a_progress_line(tmp_path):
    source = (
        "import pytest\n@pytest.fixture\ndef broken():\n"
        "    raise RuntimeError('ERROR')\ndef test_bad(broken):\n    pass\n"
    )
    parsed, log = run_case(tmp_path, source, "--tb=no")
    assert parsed.summary["errors"] == 1, log
    assert len(parsed.failures) == 1, parsed.to_dict()
    assert parsed.failures[0].message == ["RuntimeError: ERROR"]


@pytest.mark.parametrize("parameter", ["] - [x", "] - [suffix]"])
def test_reopened_bracket_cannot_create_a_false_resolved_id(tmp_path, parameter):
    source = (
        "import pytest\n"
        f"@pytest.mark.parametrize('value', [{parameter!r}])\n"
        "def test_bad(value):\n    assert False\n"
    )
    parsed, log = run_case(tmp_path, source, "--tb=no")
    assert parsed.summary["failed"] == 1, log
    assert len(parsed.failures) == 1, parsed.to_dict()
    failure = parsed.failures[0]
    expected = f"test_bad[{parameter}]"
    # Exact identity OR explicit uncertainty is acceptable; a wrong resolved ID is not.
    assert not failure.idResolved or failure.name == expected, parsed.to_dict()
    if failure.idResolved:
        assert failure.message == ["assert False"]
    else:
        assert failure.message == []
        assert expected in failure.name


@pytest.mark.parametrize("mode", ["--tb=long", "-v"])
def test_reopened_bracket_control_with_known_identity(tmp_path, mode):
    source = (
        "import pytest\n@pytest.mark.parametrize('value', ['] - [x'])\n"
        "def test_bad(value):\n    assert False\n"
    )
    parsed, log = run_case(tmp_path, source, mode)
    assert parsed.summary["failed"] == 1, log
    assert len(parsed.failures) == 1, parsed.to_dict()
    assert parsed.failures[0].name == "test_bad[] - [x]"
    assert parsed.failures[0].idResolved is True


def test_plain_message_control(tmp_path):
    parsed, log = run_case(
        tmp_path,
        "def test_bad():\n    raise ValueError('ordinary message')\n",
        "--tb=no",
    )
    assert parsed.summary["failed"] == 1, log
    assert len(parsed.failures) == 1
    assert parsed.failures[0].name == "test_bad"
    assert parsed.failures[0].message == ["ValueError: ordinary message"]
