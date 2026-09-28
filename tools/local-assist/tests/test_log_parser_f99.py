"""Regression coverage for F99-03 pytest parameter-id boundary handling."""

from local_assist.log_parser import parse_log


def _parse_short_summary(row: str):
    text = "\n".join(
        (
            "============================= test session starts =============================",
            "=========================== short test summary info ============================",
            row,
            "=========================== 1 failed in 0.01s ===========================",
        )
    )
    return parse_log(text, "pytest").failures[0]


def test_parameter_text_between_reopened_brackets_stays_unresolved():
    failure = _parse_short_summary(
        "FAILED test_case.py::test_bad[] - label [x] - assert False"
    )

    assert failure.idResolved is False
    assert failure.name == "test_bad[] - label [x] - assert False"
    assert failure.message == []


def test_exception_text_between_reopened_brackets_stays_unresolved():
    failure = _parse_short_summary(
        "FAILED test_case.py::test_bad[] - ValueError: [payload"
    )

    assert failure.idResolved is False
    assert failure.name == "test_bad[] - ValueError: [payload"
    assert failure.message == []


def test_known_nodeid_resolves_the_short_summary_without_guessing():
    text = "\n".join(
        (
            "============================= test session starts =============================",
            "________________________________ test_case.py::test_good ________________________________",
            "E       AssertionError: boom",
            "=========================== short test summary info ============================",
            "FAILED test_case.py::test_good - AssertionError: boom",
            "=========================== 1 failed in 0.01s ===========================",
        )
    )

    failure = parse_log(text, "pytest").failures[0]
    assert failure.name == "test_good"
    assert failure.group == "test_case.py"
    assert failure.idResolved is True
