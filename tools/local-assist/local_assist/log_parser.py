"""Deterministic failure extraction from nextest and pytest logs.

No model is involved. The parser keeps the original log line numbers so a
later classification can always point back at the source excerpt.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

NEXTEST_STATUS = re.compile(
    r"^\s+(?P<status>PASS|FAIL|SLOW|LEAK|TIMEOUT|SIGABRT|SIGSEGV|SIGKILL|ABORT|"
    r"TRY \d+ (?:PASS|FAIL)|FLAKY|STRESS|SKIP|RETRY)"
    r"\s+\[\s*(?P<seconds>[\d.]+|>\s*[\d.]+)s\]\s+"
    r"\((?P<progress>[^)]*)\)\s+(?P<binary>\S+)\s+(?P<name>\S+)\s*$"
)
NEXTEST_SUMMARY = re.compile(
    r"^\s+Summary\s+\[\s*[\d.]+s\]\s+(?P<run>\d+) tests? run:\s+(?P<passed>\d+) passed"
    r"(?: \(\d+ slow\))?(?:, (?P<failed>\d+) failed)?(?:, (?P<skipped>\d+) skipped)?"
)
NEXTEST_SECTION = re.compile(r"^\s+(stdout|stderr) ───\s*$")
NEXTEST_RULE = re.compile(r"^─+\s*$")
RUST_PANIC = re.compile(
    r"^\s*thread '(?P<thread>[^']*)'.*panicked at (?P<location>\S+?):?$"
)
RUST_NOTE = re.compile(r"^\s*note: run with `RUST_BACKTRACE=1`")

PYTEST_BANNER = re.compile(r"^=+ (?P<title>.+?) =+$")
PYTEST_BLOCK = re.compile(r"^_+ (?P<name>.+?) _+$")
PYTEST_SHORT = re.compile(
    r"^(?P<status>FAILED|ERROR) (?P<nodeid>\S+)(?: - (?P<message>.*))?$"
)
PYTEST_FINAL = re.compile(
    r"^(?:=+ )?(?P<body>(?:\d+ (?:failed|passed|skipped|errors?|warnings?|xfailed|xpassed|"
    r"deselected|subtests passed)(?:, )?)+)"
    r"(?: in [\d.]+s)?"
)
PYTEST_LOCATION = re.compile(r"^(?P<path>[^\s:]+\.py):(?P<line>\d+): (?P<error>\S.*)$")

MAX_MESSAGE_LINES = 40


@dataclass
class Failure:
    """One failed test with its source location inside the log."""

    name: str
    group: str
    startLine: int
    endLine: int
    message: list[str] = field(default_factory=list)
    location: str | None = None


@dataclass
class ParsedLog:
    format: str
    summary: dict
    failures: list[Failure]

    def to_dict(self) -> dict:
        return {
            "format": self.format,
            "summary": self.summary,
            "failures": [asdict(failure) for failure in self.failures],
        }


def detect_format(lines: list[str]) -> str | None:
    for line in lines:
        if NEXTEST_STATUS.match(line) or NEXTEST_SUMMARY.match(line):
            return "nextest"
        if PYTEST_BANNER.match(line) and "test session starts" in line:
            return "pytest"
        if PYTEST_SHORT.match(line) and "::" in line:
            return "pytest"
    return None


def parse_log(text: str, fmt: str = "auto") -> ParsedLog:
    lines = text.splitlines()
    if fmt == "auto":
        detected = detect_format(lines)
        if detected is None:
            raise ValueError("cannot detect log format (expected nextest or pytest)")
        fmt = detected
    if fmt == "nextest":
        return parse_nextest(lines)
    if fmt == "pytest":
        return parse_pytest(lines)
    raise ValueError(f"unsupported log format: {fmt}")


def _panic_message(block: list[str]) -> tuple[list[str], str | None]:
    """Return the panic message lines (bounded) and the panic location."""
    message: list[str] = []
    location = None
    capturing = False
    for line in block:
        panic = RUST_PANIC.match(line)
        if panic and not capturing:
            location = panic.group("location").rstrip(":")
            capturing = True
            message.append(line.strip())
            continue
        if capturing:
            if RUST_NOTE.match(line):
                break
            stripped = line.strip()
            if not stripped and message and not message[-1]:
                continue
            message.append(stripped)
            if len(message) >= MAX_MESSAGE_LINES:
                message.append(
                    "... (message truncated by the parser, see the source lines)"
                )
                break
    while message and not message[-1]:
        message.pop()
    return message, location


def parse_nextest(lines: list[str]) -> ParsedLog:
    summary: dict = {}
    failures: list[Failure] = []
    seen: set[tuple[str, str]] = set()
    index = 0
    total = len(lines)
    while index < total:
        line = lines[index]
        status = NEXTEST_STATUS.match(line)
        if status is None:
            summary_match = NEXTEST_SUMMARY.match(line)
            if summary_match:
                summary = {
                    "run": int(summary_match.group("run")),
                    "passed": int(summary_match.group("passed")),
                    "failed": int(summary_match.group("failed") or 0),
                    "skipped": int(summary_match.group("skipped") or 0),
                    "line": index + 1,
                }
            index += 1
            continue
        if not status.group("status").endswith("FAIL") and status.group(
            "status"
        ) not in (
            "TIMEOUT",
            "SIGABRT",
            "SIGSEGV",
            "SIGKILL",
            "ABORT",
            "LEAK",
        ):
            index += 1
            continue
        start = index
        index += 1
        while index < total:
            probe = lines[index]
            if (
                NEXTEST_STATUS.match(probe)
                or NEXTEST_SUMMARY.match(probe)
                or NEXTEST_RULE.match(probe)
            ):
                break
            index += 1
        end = index
        while end > start + 1 and not lines[end - 1].strip():
            end -= 1
        key = (status.group("binary"), status.group("name"))
        block = lines[start + 1 : end]
        message, location = _panic_message(block)
        failure = Failure(
            name=status.group("name"),
            group=status.group("binary"),
            startLine=start + 1,
            endLine=end,
            message=message,
            location=location,
        )
        if key in seen:
            # The summary tail repeats failures without their output; keep the
            # first occurrence, which carries the body.
            continue
        seen.add(key)
        failures.append(failure)
    if not summary:
        summary = {
            "run": None,
            "passed": None,
            "failed": len(failures),
            "skipped": None,
            "line": None,
        }
    return ParsedLog(format="nextest", summary=summary, failures=failures)


def _pytest_message(block: list[str]) -> tuple[list[str], str | None]:
    message: list[str] = []
    location = None
    for line in block:
        if line.startswith(("E ", ">")):
            message.append(line.rstrip())
        loc = PYTEST_LOCATION.match(line)
        if loc:
            location = f"{loc.group('path')}:{loc.group('line')}"
            message.append(line.rstrip())
        if len(message) >= MAX_MESSAGE_LINES:
            message.append(
                "... (message truncated by the parser, see the source lines)"
            )
            break
    return message, location


def parse_pytest(lines: list[str]) -> ParsedLog:
    summary: dict = {}
    failures: list[Failure] = []
    short: dict[str, str] = {}
    in_failures = False
    block_start: int | None = None
    block_name: str | None = None

    def close_block(end_index: int) -> None:
        nonlocal block_start, block_name
        if block_start is None or block_name is None:
            return
        end = end_index
        while end > block_start + 1 and not lines[end - 1].strip():
            end -= 1
        message, location = _pytest_message(lines[block_start + 1 : end])
        failures.append(
            Failure(
                name=block_name,
                group="pytest",
                startLine=block_start + 1,
                endLine=end,
                message=message,
                location=location,
            )
        )
        block_start = None
        block_name = None

    for index, line in enumerate(lines):
        banner = PYTEST_BANNER.match(line)
        if banner:
            close_block(index)
            in_failures = banner.group("title").strip() in ("FAILURES", "ERRORS")
            continue
        if in_failures:
            block = PYTEST_BLOCK.match(line)
            if block:
                close_block(index)
                block_start = index
                block_name = block.group("name").strip()
                continue
        short_match = PYTEST_SHORT.match(line)
        if short_match:
            short[short_match.group("nodeid")] = short_match.group("message") or ""
            continue
        final = PYTEST_FINAL.match(line)
        if final and ("failed" in line or "passed" in line) and not summary:
            counts: dict[str, int | None] = {
                "run": None,
                "passed": 0,
                "failed": 0,
                "skipped": 0,
            }
            for part in final.group("body").split(", "):
                number, _, label = part.partition(" ")
                if not number.isdigit():
                    continue
                if label == "passed":
                    counts["passed"] = int(number)
                elif label == "failed":
                    counts["failed"] = int(number)
                elif label == "skipped":
                    counts["skipped"] = int(number)
                elif label.startswith("error"):
                    counts["errors"] = int(number)
            counts["run"] = sum(
                v
                for k, v in counts.items()
                if k in ("passed", "failed", "skipped", "errors") and v
            )
            counts["line"] = index + 1
            summary = counts
    close_block(len(lines))
    for failure in failures:
        for nodeid, message in short.items():
            if (
                nodeid.endswith("::" + failure.name)
                or nodeid.rsplit("::", 1)[-1] == failure.name
            ):
                failure.group = nodeid.split("::", 1)[0]
                if message and not failure.message:
                    failure.message = [message]
    if not summary:
        summary = {
            "run": None,
            "passed": None,
            "failed": len(failures),
            "skipped": None,
            "line": None,
        }
    return ParsedLog(format="pytest", summary=summary, failures=failures)


def render_excerpt(parsed: ParsedLog, source_name: str) -> str:
    """Render a compact, model-facing excerpt. Every block names its source lines."""
    out: list[str] = []
    summary = parsed.summary
    out.append(f"# {parsed.format} log excerpt from {source_name}")
    out.append(
        "# summary: run={run} passed={passed} failed={failed} skipped={skipped}".format(
            run=summary.get("run"),
            passed=summary.get("passed"),
            failed=summary.get("failed"),
            skipped=summary.get("skipped"),
        )
    )
    out.append("")
    for number, failure in enumerate(parsed.failures, start=1):
        out.append(f"## failure {number}: {failure.group} {failure.name}")
        out.append(f"source: {source_name}:{failure.startLine}-{failure.endLine}")
        if failure.location:
            out.append(f"location: {failure.location}")
        if failure.message:
            out.extend(failure.message)
        else:
            out.append("(no failure message captured in the log)")
        out.append("")
    return "\n".join(out).rstrip("\n") + "\n"
