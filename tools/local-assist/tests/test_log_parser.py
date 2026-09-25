"""The parser extracts failure blocks without a model and keeps source line numbers."""

from pathlib import Path

import pytest
from local_assist.log_parser import parse_log, render_excerpt

FIXTURES = Path(__file__).parent / "fixtures"


def test_nextest_failures_are_extracted_with_source_lines_and_panic_messages():
    text = (FIXTURES / "nextest-excerpt.log").read_text()
    parsed = parse_log(text, "auto")
    assert parsed.format == "nextest"
    assert parsed.summary == {
        "run": 3062,
        "passed": 3054,
        "failed": 8,
        "skipped": 81,
        "line": 92,
    }
    names = [(f.group, f.name) for f in parsed.failures]
    # The summary tail repeats the failures; each one is reported once.
    assert len(names) == len(set(names)) == 8
    doctor = parsed.failures[0]
    assert doctor.group == "fireemu::doctor"
    assert (
        doctor.name
        == "doctor_names_the_binary_the_ui_bundle_the_runner_and_the_runtimes"
    )
    assert (doctor.startLine, doctor.endLine) == (6, 37)
    assert doctor.location == "crates/fireemu/tests/doctor.rs:98:5"
    assert doctor.message[0].startswith("thread 'doctor_names_the_binary")
    assert "the runner's firebase-functions range is reported:" in doctor.message
    assert not any("RUST_BACKTRACE" in line for line in doctor.message)
    body_less = next(f for f in parsed.failures if f.name.startswith("a_dotenv_file"))
    assert body_less.message == []
    assert body_less.location is None
    hub = next(f for f in parsed.failures if f.group == "fireemu::hub")
    assert hub.location == "crates/fireemu/tests/hub.rs:204:33"
    assert any("bundled Node runner" in line for line in hub.message)
    # Failures only listed in the summary tail still get their source lines.
    tail_only = next(f for f in parsed.failures if f.group == "fireemu::resources")
    assert tail_only.startLine == 99
    assert tail_only.message == []


def test_pytest_failures_are_extracted_with_assertion_lines_and_nodeids():
    text = (FIXTURES / "pytest-excerpt.log").read_text()
    parsed = parse_log(text, "auto")
    assert parsed.format == "pytest"
    assert parsed.summary["failed"] == 2
    assert parsed.summary["passed"] == 6048
    assert parsed.summary["skipped"] == 20
    assert len(parsed.failures) == 2
    first = parsed.failures[0]
    assert (
        first.name
        == "test_real_cli_with_missing_sdk_fails_after_persisting_launch_without_cloud_access"
    )
    assert first.group == "tools/compat-broad/fs-listen-resume/test_local_supervisor.py"
    assert (
        first.location
        == "tools/compat-broad/fs-listen-resume/test_local_supervisor.py:276"
    )
    assert any(line.startswith("E       AssertionError") for line in first.message)
    assert first.startLine == 8
    assert parsed.failures[1].startLine == 28


def test_excerpt_rendering_names_source_lines_for_every_failure():
    text = (FIXTURES / "nextest-excerpt.log").read_text()
    parsed = parse_log(text, "nextest")
    excerpt = render_excerpt(parsed, "gate.log")
    assert excerpt.startswith(
        "# nextest log excerpt from gate.log\n# summary: run=3062 passed=3054 failed=8 skipped=81\n"
    )
    assert "## failure 1: fireemu::doctor doctor_names_the_binary" in excerpt
    assert "source: gate.log:6-37" in excerpt
    assert "location: crates/fireemu/tests/doctor.rs:98:5" in excerpt
    assert excerpt.count("## failure ") == 8
    assert "(no failure message captured in the log)" in excerpt


def test_unknown_format_is_refused_instead_of_guessed():
    with pytest.raises(ValueError):
        parse_log("hello\nworld\n", "auto")
    with pytest.raises(ValueError):
        parse_log("hello\n", "junit")


def test_a_clean_nextest_log_has_no_failures():
    text = "        PASS [   0.023s] (   1/1) crate::mod a_test\n     Summary [  1.000s] 1 test run: 1 passed, 0 skipped\n"
    parsed = parse_log(text, "auto")
    assert parsed.failures == []
    assert parsed.summary["failed"] == 0
    assert parsed.summary["run"] == 1
