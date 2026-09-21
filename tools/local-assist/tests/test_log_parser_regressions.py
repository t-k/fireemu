"""Failures must survive human-log formatting without requiring an LLM.

These are parser tests, not Firestore/Auth compatibility evidence. Subprocess
checks invoke installed pytest on deliberately failing throwaway tests only.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from local_assist.log_parser import parse_log, render_excerpt


def _pytest_log(footer: str, details: str = "") -> str:
    return "=== test session starts ===\n" + details + footer + "\n"


@pytest.mark.parametrize(
    "footer",
    [
        "=== 1 failed, 3 passed in 0.10s ===",
        "1 failed, 3 passed in 0.10s",
        "=== 1 failed, 3 passed in 1718.19s (0:28:38) ===",
    ],
)
def test_pytest_terminal_summary_is_read_before_generic_banner(footer):
    result = parse_log(_pytest_log(footer))
    assert result.summary["failed"] == 1
    assert result.summary["passed"] == 3
    assert result.summary["run"] == 4
    assert result.summary["line"] == 2


@pytest.mark.parametrize(
    "footer,expected",
    [
        ("4 passed in 0.01s", {"run": 4, "passed": 4, "failed": 0, "skipped": 0}),
        ("1 error in 0.01s", {"run": None, "errors": 1, "failed": 0}),
        ("2 errors in 0.01s", {"run": None, "errors": 2}),
        ("2 skipped in 0.01s", {"run": 2, "skipped": 2}),
        ("1 xfailed in 0.01s", {"run": 1, "xfailed": 1}),
        ("1 xpassed in 0.01s", {"run": 1, "xpassed": 1}),
        ("2 deselected in 0.01s", {"run": 0, "deselected": 2}),
        ("no tests ran in 0.01s", {"run": 0, "passed": 0, "failed": 0}),
        ("1 passed, 1 error in 0.01s", {"run": None, "passed": 1, "errors": 1}),
        (
            "2 failed, 6048 passed, 20 skipped, 4 warnings, 6 subtests passed in 1718.19s (0:28:38)",
            {
                "run": 6070,
                "failed": 2,
                "passed": 6048,
                "skipped": 20,
                "warnings": 4,
                "subtests passed": 6,
            },
        ),
    ],
)
def test_pytest_quiet_only_footer_and_distinct_outcome_counts(footer, expected):
    result = parse_log(footer + "\n")
    assert result.format == "pytest"
    for key, value in expected.items():
        assert result.summary[key] == value


@pytest.mark.parametrize(
    "status,nodeid,message",
    [
        ("FAILED", "tests/a.py::test_bad", "assert 0"),
        ("ERROR", "tests/a.py::test_needs_fixture", "RuntimeError: fixture"),
        ("ERROR", "tests/bad.py", "SyntaxError: invalid syntax"),
        ("FAILED", "tests/a.py::test_value[hello world]", "assert 1 == 2"),
        ("FAILED", "tests/a.py::TestThing::test_bad", "assert False"),
    ],
)
def test_short_summary_without_traceback_still_creates_a_failure(
    status, nodeid, message
):
    log = f"{status} {nodeid} - {message}\n"
    result = parse_log(log)
    assert len(result.failures) == 1
    failure = result.failures[0]
    group, sep, name = nodeid.partition("::")
    assert failure.group == group
    assert failure.name == (name if sep else nodeid)
    assert failure.message == [message]
    assert (failure.startLine, failure.endLine) == (1, 1)
    assert result.summary["failed"] is None
    assert result.summary["observedFailureBlocks"] == 1
    assert "terminal summary unavailable" in render_excerpt(result, "gate.log")


def test_detailed_and_short_pytest_failure_are_not_duplicated():
    log = "\n".join(
        [
            "=== FAILURES ===",
            "___ test_bad ___",
            "> assert 0",
            "E AssertionError",
            "tests/a.py:5: AssertionError",
            "=== short test summary info ===",
            "FAILED tests/a.py::test_bad - assert 0",
            "=== 1 failed in 0.01s ===",
        ]
    )
    result = parse_log(log)
    assert len(result.failures) == 1
    f = result.failures[0]
    assert f.group == "tests/a.py"
    assert f.location == "tests/a.py:5"
    assert (f.startLine, f.endLine) == (2, 5)


def test_same_named_tests_are_bound_by_recorded_source_not_last_suffix_match():
    log = "\n".join(
        [
            "=== FAILURES ===",
            "___ test_same ___",
            "E AssertionError: one",
            "a.py:2: AssertionError",
            "___ test_same ___",
            "E AssertionError: two",
            "b.py:2: AssertionError",
            "=== short test summary info ===",
            "FAILED a.py::test_same - one",
            "FAILED b.py::test_same - two",
            "2 failed in 0.01s",
        ]
    )
    result = parse_log(log)
    assert [(f.group, f.location) for f in result.failures] == [
        ("a.py", "a.py:2"),
        ("b.py", "b.py:2"),
    ]


def test_ambiguous_detail_is_not_falsely_attributed_to_a_file():
    log = "\n".join(
        [
            "=== FAILURES ===",
            "___ test_same ___",
            "E AssertionError: one",
            "___ test_same ___",
            "E AssertionError: two",
            "=== short test summary info ===",
            "FAILED a.py::test_same - one",
            "FAILED b.py::test_same - two",
            "2 failed in 0.01s",
        ]
    )
    result = parse_log(log)
    assert [f.group for f in result.failures] == ["pytest", "pytest", "a.py", "b.py"]
    assert result.summary["failed"] == 2  # Blocks are not the terminal count.


@pytest.mark.parametrize(
    "heading,nodeid",
    [
        ("TestThing.test_bad", "tests/a.py::TestThing::test_bad"),
        ("ERROR at setup of test_bad", "tests/a.py::test_bad"),
        ("ERROR at teardown of TestThing.test_bad", "tests/a.py::TestThing::test_bad"),
    ],
)
def test_detail_display_names_join_class_or_fixture_error_nodeids(heading, nodeid):
    log = "\n".join(
        [
            "=== ERRORS ===",
            f"___ {heading} ___",
            "E RuntimeError",
            "tests/a.py:3: RuntimeError",
            "=== short test summary info ===",
            f"ERROR {nodeid} - RuntimeError",
            "1 error in 0.01s",
        ]
    )
    result = parse_log(log)
    assert len(result.failures) == 1
    assert result.failures[0].group == "tests/a.py"
    assert "# errors: 1" in render_excerpt(result, "errors.log")


def test_repeated_summary_lines_are_deduplicated_without_losing_first_location():
    result = parse_log("FAILED a.py::test_bad - assert 0\n" * 2)
    assert len(result.failures) == 1
    assert result.failures[0].startLine == 1


@pytest.mark.parametrize(
    "fmt,log",
    [
        ("pytest", "FAILED a.py::test_bad - assert 0\n1 failed in 0.10s\n"),
        (
            "nextest",
            "    FAIL [ 0.01s] (1/1) crate test_bad\n    Summary [ 0.02s] 1 test run: 0 passed, 1 failed, 0 skipped\n",
        ),
    ],
)
def test_ansi_colors_keep_original_source_line_positions(fmt, log):
    colored = "\n".join(f"\x1b[31m{x}\x1b[0m" for x in log.splitlines())
    plain, colored = parse_log(log), parse_log(colored)
    assert colored.to_dict() == plain.to_dict()
    assert colored.format == fmt
    assert colored.failures[0].startLine == 1


def test_osc8_hyperlink_wrappers_do_not_corrupt_nodeids():
    log = "FAILED \x1b]8;;file:///tmp/a.py\x1b\\a.py::test_bad\x1b]8;;\x1b\\ - assert 0\n1 failed in 0.1s\n"
    result = parse_log(log)
    assert result.failures[0].group == "a.py"
    assert "\x1b" not in render_excerpt(result, "gate.log")


@pytest.mark.parametrize("counter", ["", "( 1/2) "])
@pytest.mark.parametrize(
    "status", ["FAIL", "TIMEOUT", "SIGSEGV", "ABORT", "EXECFAIL", "TRY 1 FAIL"]
)
def test_nextest_status_with_and_without_progress_counter(counter, status):
    result = parse_log(f"    {status} [ 0.01s] {counter}crate::tests test_bad\n")
    assert result.format == "nextest"
    assert len(result.failures) == 1
    assert result.failures[0].name == "test_bad"
    assert result.summary["failed"] is None


@pytest.mark.parametrize(
    "annotation", ["", " (2 slow)", " (1 flaky)", " (1 slow, 1 flaky)"]
)
def test_nextest_summary_does_not_silently_ignore_counts_after_annotations(annotation):
    text = (
        f"    Summary [ 0.02s] 3 tests run: 2 passed{annotation}, 1 failed, 8 skipped\n"
    )
    result = parse_log(text)
    assert result.summary == {
        "run": 3,
        "passed": 2,
        "failed": 1,
        "skipped": 8,
        "line": 1,
    }


def test_nextest_failed_retry_does_not_override_final_success_summary():
    text = "\n".join(
        [
            "  TRY 1 FAIL [ 0.01s] crate test_flaky",
            "  TRY 2 PASS [ 0.01s] crate test_flaky",
            "    Summary [ 0.02s] 1 test run: 1 passed (1 flaky), 0 skipped",
            "   FLAKY 2/3 [ 0.01s] crate test_flaky",
        ]
    )
    result = parse_log(text)
    assert result.summary["failed"] == 0
    assert result.summary["passed"] == 1
    assert len(result.failures) == 1  # Retry output remains useful for triage.
    assert result.failures[0].endLine == 1


@pytest.mark.parametrize(
    "tail",
    [", NEW FORMAT", ", 1 ???", " (1 slow, malformed)", ", 1 failed and truncated"],
)
def test_unknown_nextest_summary_tails_never_become_success(tail):
    result = parse_log("    Summary [ 0.02s] 1 test run: 1 passed" + tail + "\n")
    assert result.summary["passed"] is None
    assert result.summary["failed"] is None
    assert result.summary["line"] is None


@pytest.mark.parametrize(
    "text",
    [
        "=== test session starts ===\n",
        "    PASS [ 0.01s] crate t\n",
    ],
)
def test_missing_final_summary_is_unknown_not_zero_failures(text):
    result = parse_log(text)
    assert result.summary["failed"] is None
    assert result.summary["run"] is None
    assert result.summary["observedFailureBlocks"] == 0


@pytest.mark.parametrize(
    "text",
    ["hello world\n", "1 passed trailing text\n", "4 passed in 0.2s not a footer\n"],
)
def test_random_prose_is_not_a_terminal_summary(text):
    with pytest.raises(ValueError):
        parse_log(text)


def _run_real_pytest(tmp_path: Path, source: str, args: list[str]):
    (tmp_path / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    (tmp_path / "test_sample.py").write_text(source, encoding="utf-8")
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith("PYTEST_") and k != "PYTHONPATH"
    }
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-c",
            str(tmp_path / "pytest.ini"),
            *args,
            str(tmp_path / "test_sample.py"),
        ],
        cwd=tmp_path,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=20,
        check=False,
    )
    return completed, parse_log(completed.stdout)


@pytest.mark.parametrize(
    "args", [[], ["-q"], ["--tb=no"], ["--color=yes"], ["-q", "--tb=short"]]
)
def test_real_pytest_default_quiet_short_and_color_output(tmp_path, args):
    completed, result = _run_real_pytest(
        tmp_path,
        "def test_ok():\n    pass\n\ndef test_bad():\n    assert 1 == 2\n",
        args,
    )
    assert completed.returncode == 1
    assert result.summary["failed"] == result.summary["passed"] == 1
    assert result.summary["run"] == 2
    assert len(result.failures) == 1
    assert result.failures[0].group == "test_sample.py"
    assert result.failures[0].name == "test_bad"
    assert result.failures[0].endLine <= len(completed.stdout.splitlines())


@pytest.mark.parametrize(
    "source,expected",
    [
        (
            "import pytest\n@pytest.fixture\ndef broken():\n    raise RuntimeError('setup')\ndef test_error(broken):\n    pass\n",
            1,
        ),
        ("def broken(:\n    pass\n", 2),
    ],
)
@pytest.mark.parametrize("args", [["-q", "--tb=no"], []])
def test_real_pytest_setup_and_collection_error_only_logs(
    tmp_path, source, expected, args
):
    completed, result = _run_real_pytest(tmp_path, source, args)
    assert completed.returncode == expected
    assert result.summary["errors"] == 1
    assert result.summary["failed"] == 0
    assert result.summary["run"] is None
    assert len(result.failures) == 1
    assert "# errors: 1" in render_excerpt(result, "gate.log")


def test_real_pytest_teardown_error_does_not_double_count_test_execution(tmp_path):
    source = "import pytest\n@pytest.fixture\ndef broken():\n    yield\n    raise RuntimeError('teardown')\ndef test_error(broken):\n    pass\n"
    completed, result = _run_real_pytest(tmp_path, source, ["-q", "--tb=no"])
    assert completed.returncode == 1
    assert result.summary["passed"] == 1
    assert result.summary["errors"] == 1
    assert result.summary["run"] is None


def test_parameter_id_containing_summary_separator_is_not_split():
    text = "FAILED a.py::test_param[left - right] - assert 1 == 2 - details\n1 failed in 0.1s\n"
    result = parse_log(text)
    assert result.failures[0].name == "test_param[left - right]"
    assert result.failures[0].message == ["assert 1 == 2 - details"]


def test_one_unlocated_detail_does_not_guess_between_two_same_named_files():
    text = "\n".join(
        [
            "=== FAILURES ===",
            "___ test_same ___",
            "E AssertionError",
            "=== short test summary info ===",
            "FAILED a.py::test_same - one",
            "FAILED b.py::test_same - two",
            "2 failed in 0.1s",
        ]
    )
    result = parse_log(text)
    assert [f.group for f in result.failures] == ["pytest", "a.py", "b.py"]


@pytest.mark.parametrize(
    "value,expected_name",
    [
        ("[", "test_bad[[]"),
        ("a - b", "test_bad[a - b]"),
        ("[x[1]]", "test_bad[[x[1]]]"),
    ],
)
def test_short_summary_id_boundary_survives_unbalanced_or_dashed_brackets(
    value, expected_name
):
    # pytest does not escape '[' or ']' inside a parametrize id, so a value
    # containing either can desync a naive bracket-depth count: an
    # unbalanced '[' never lets depth return to 0, and an unbalanced ']'
    # can return depth to 0 too early. The line is built the same way
    # pytest builds it (name[value]), not from the expected id, so this
    # exercises the actual ambiguity rather than assuming the answer.
    text = f"FAILED test_case.py::test_bad[{value}] - assert False\n1 failed in 0.00s\n"
    result = parse_log(text)
    assert len(result.failures) == 1
    assert result.failures[0].name == expected_name
    assert result.failures[0].message == ["assert False"]
    assert result.failures[0].idResolved is True


def test_short_summary_id_boundary_is_unresolved_when_genuinely_ambiguous():
    # Owner review of e663e2cf1 (docs.local/reviews/2026-09-21/
    # owner-review-e663e2cf1/review.md): a parametrize value of "] - suffix"
    # used to resolve to "test_bad[] - suffix]" by trusting the rightmost
    # "] - " in the line. That anchor is exactly as consistent with reading
    # the id as "test_bad[]" and the rest ("- suffix] - assert False") as an
    # unparsed message: both candidates close a bracket group cleanly with
    # nothing reopening it afterwards, so nothing in the line itself picks
    # one over the other. Per the review, the parser must no longer guess:
    # it keeps the raw short-summary line and marks the id unresolved.
    text = (
        "FAILED test_case.py::test_bad[] - suffix] - assert False\n1 failed in 0.00s\n"
    )
    result = parse_log(text)
    assert len(result.failures) == 1
    failure = result.failures[0]
    assert failure.idResolved is False
    assert failure.group == "test_case.py"
    assert failure.name == "test_bad[] - suffix] - assert False"
    assert failure.message == []


@pytest.mark.parametrize(
    "nodeid,expected_name",
    [
        ("test_case.py::test_bad", "test_bad"),
        ("test_case.py::test_bad[v]", "test_bad[v]"),
    ],
)
def test_short_summary_dashed_message_is_not_mistaken_for_more_id(
    nodeid, expected_name
):
    text = (
        f"FAILED {nodeid} - AssertionError: some - message - here\n1 failed in 0.00s\n"
    )
    result = parse_log(text)
    assert len(result.failures) == 1
    assert result.failures[0].name == expected_name
    assert result.failures[0].message == ["AssertionError: some - message - here"]


def test_setup_error_only_joins_by_kind_and_phase():
    log = "\n".join(
        [
            "=== ERRORS ===",
            "___ ERROR at setup of test_bad ___",
            "E RuntimeError: boom",
            "tests/a.py:3: RuntimeError",
            "=== short test summary info ===",
            "ERROR tests/a.py::test_bad - RuntimeError: boom",
            "1 error in 0.01s",
        ]
    )
    result = parse_log(log)
    assert len(result.failures) == 1
    assert result.failures[0].group == "tests/a.py"
    # The join corrects .group from the placeholder "pytest"; the detail
    # block's own heading text is left as-is (see the class/fixture-error
    # test above), so the phase phrase stays for a human reading the excerpt.
    assert result.failures[0].name == "ERROR at setup of test_bad"


def test_collection_error_only_joins_by_kind_and_phase():
    log = "\n".join(
        [
            "=== ERRORS ===",
            "___ ERROR collecting tests/bad.py ___",
            "E SyntaxError: invalid syntax",
            "=== short test summary info ===",
            "ERROR tests/bad.py - SyntaxError: invalid syntax",
            "1 error in 0.01s",
        ]
    )
    result = parse_log(log)
    assert len(result.failures) == 1
    assert result.failures[0].group == "tests/bad.py"


def test_body_failure_and_teardown_error_join_separately_by_kind():
    # A body (call) failure and a teardown error of the same test share the
    # same nodeid in the short summary; only FAILED/ERROR plus the phase
    # recorded on each detail block ("test_bad" = body, "ERROR at teardown
    # of test_bad" = teardown) disambiguates which block each line joins.
    log = "\n".join(
        [
            "=== ERRORS ===",
            "___ ERROR at teardown of test_bad ___",
            "E RuntimeError: teardown failure",
            "tests/a.py:5: RuntimeError",
            "=== FAILURES ===",
            "___ test_bad ___",
            "E AssertionError: assert False",
            "tests/a.py:7: AssertionError",
            "=== short test summary info ===",
            "FAILED tests/a.py::test_bad - AssertionError: assert False",
            "ERROR tests/a.py::test_bad - RuntimeError: teardown failure",
            "1 failed, 1 error in 0.01s",
        ]
    )
    result = parse_log(log)
    assert len(result.failures) == 2
    assert {f.group for f in result.failures} == {"tests/a.py"}
    by_message = {f.message[0]: f for f in result.failures}
    assert "E AssertionError: assert False" in by_message
    assert "E RuntimeError: teardown failure" in by_message


def test_verbose_progress_line_resolves_an_otherwise_ambiguous_short_summary():
    # A verbose (-v) run prints "<nodeid> FAILED" while the test executes,
    # before the short summary. That nodeid is a known-good source of truth
    # -- unlike guessing from the short-summary line's own separators -- so
    # it should resolve a line that would otherwise be ambiguous (the same
    # "close then a stray, never-reopened ']'" shape as the owner review's
    # "] - suffix" case).
    log = "\n".join(
        [
            "test_case.py::test_bad[] - suffix] FAILED               [100%]",
            "",
            "=== short test summary info ===",
            "FAILED test_case.py::test_bad[] - suffix] - assert False",
            "1 failed in 0.01s",
        ]
    )
    result = parse_log(log)
    assert len(result.failures) == 1
    failure = result.failures[0]
    assert failure.idResolved is True
    assert failure.group == "test_case.py"
    assert failure.name == "test_bad[] - suffix]"
    assert failure.message == ["assert False"]


@pytest.mark.parametrize(
    "rest,expected_name,expected_message",
    [
        # A parametrize id bracket, then a message that opens and closes
        # its own fresh '[...]': the id's bracket group is well-formed, and
        # the alternative reading (extending the id through the message's
        # bracket) requires a '[' to reopen after the id's own bracket
        # already closed, which is never well-formed. Unambiguous.
        (
            "test_case.py::test_bad[x] - ValueError: [y] - z",
            "test_bad[x]",
            "ValueError: [y] - z",
        ),
        # A parametrize value containing ' - ', then a message with its own
        # bracket: same reasoning, the id's own bracket group still has to
        # close before any '-' or '[' from the message. Unambiguous.
        (
            "test_case.py::test_bad[a - b] - ValueError: [y]",
            "test_bad[a - b]",
            "ValueError: [y]",
        ),
        # No bracket in the id at all; the message has both a bracket and a
        # dash. Every candidate id extending past the first ' - ' contains
        # whitespace (it is message text), so only the shortest split (no
        # brackets, bare name) is well-formed.
        (
            "test_case.py::test_bad - some [thing] - here",
            "test_bad",
            "some [thing] - here",
        ),
    ],
)
def test_id_and_message_bracket_combinations_resolve_unambiguously(
    rest, expected_name, expected_message
):
    text = f"FAILED {rest}\n1 failed in 0.01s\n"
    result = parse_log(text)
    assert len(result.failures) == 1
    failure = result.failures[0]
    assert failure.idResolved is True
    assert failure.name == expected_name
    assert failure.message == [expected_message]


def test_message_bracket_without_its_own_open_is_still_ambiguous():
    # Contrast with the cases above: here the message's ']' is a stray,
    # never-reopened close (no fresh '[' of its own), so it has exactly the
    # same shape as the id's own bracket group closing early. Nothing in
    # the line picks one reading over the other, so this stays unresolved
    # even though a bracket ("[ok]") the id may legitimately own is present.
    text = "FAILED test_case.py::test_bad[ok] - ValueError: msg] - tail\n1 failed in 0.01s\n"
    result = parse_log(text)
    assert len(result.failures) == 1
    failure = result.failures[0]
    assert failure.idResolved is False
    assert failure.name == "test_bad[ok] - ValueError: msg] - tail"
    assert failure.message == []
