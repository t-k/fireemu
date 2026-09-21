"""Deterministic failure extraction from nextest and pytest logs.

No model is involved. The parser keeps the original log line numbers so a
later classification can always point back at the source excerpt.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

NEXTEST_STATUS = re.compile(
    r"^\s*(?P<status>PASS|FAIL|SLOW|LEAK|TIMEOUT|SIGABRT|SIGSEGV|SIGKILL|ABORT|EXECFAIL|"
    r"TRY \d+ (?:PASS|FAIL)|FLAKY(?: \d+/\d+)?|STRESS|SKIP|RETRY)"
    r"\s+\[\s*(?P<seconds>[\d.]+|>\s*[\d.]+)s\]\s+"
    r"(?:\((?P<progress>[^)]*)\)\s+)?(?P<binary>\S+)\s+(?P<name>\S+)\s*$"
)
NEXTEST_SUMMARY = re.compile(
    r"^\s*Summary\s+\[\s*[\d.]+s\]\s+(?P<run>\d+) tests? run:\s+(?P<body>.+?)\s*$"
)
NEXTEST_COUNT = re.compile(
    r"(?P<count>\d+) (?P<label>passed|failed|skipped|leaky|flaky|timed out|exec failed)"
    r"(?: \((?P<qualifiers>\d+ (?:slow|flaky|leaky)(?:, \d+ (?:slow|flaky|leaky))*)\))?"
)
NEXTEST_SECTION = re.compile(r"^\s+(stdout|stderr) ───\s*$")
NEXTEST_RULE = re.compile(r"^\s*─+\s*$")
RUST_PANIC = re.compile(
    r"^\s*thread '(?P<thread>[^']*)'.*panicked at (?P<location>\S+?):?$"
)
RUST_NOTE = re.compile(r"^\s*note: run with `RUST_BACKTRACE=1`")

PYTEST_BANNER = re.compile(r"^=+ (?P<title>.+?) =+$")
PYTEST_BLOCK = re.compile(r"^_+ (?P<name>.+?) _+$")
PYTEST_SHORT = re.compile(r"^(?P<status>FAILED|ERROR) (?P<rest>.+)$")
# A verbose (-v) per-test progress line: "<nodeid> <STATUS> [ NN%]". Used
# only as a source of known nodeids for _pytest_short; never itself turned
# into a Failure (PASSED/SKIPPED nodeids are harmless extra candidates).
PYTEST_VERBOSE = re.compile(
    r"^(?P<nodeid>.+?)\s+(?:PASSED|FAILED|ERROR|SKIPPED|XFAIL|XPASS|RERUN)"
    r"(?:\s+\[\s*\d+%\s*\])?\s*$"
)
PYTEST_FINAL = re.compile(
    r"(?P<body>no tests ran|\d+ (?:failed|passed|skipped|errors?|warnings?|xfailed|xpassed|"
    r"deselected|subtests passed)(?:, \d+ (?:failed|passed|skipped|errors?|warnings?|"
    r"xfailed|xpassed|deselected|subtests passed))*)"
    r" in [0-9]+(?:\.[0-9]+)?s(?: \([0-9]+:[0-9]{2}:[0-9]{2}\))?"
)
# Strip presentation escapes, never whole lines: all source positions still
# refer to the original log, including a colorized run.
ANSI_CSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
ANSI_LINK = re.compile(r"\x1b\]8;[^\x07\x1b]*?(?:\x07|\x1b\\)")
PYTEST_LOCATION = re.compile(r"^(?P<path>[^\s:]+\.py):(?P<line>\d+): (?P<error>\S.*)$")

MAX_MESSAGE_LINES = 40


@dataclass
class Failure:
    """One failure/retry output block, not the overall run verdict."""

    name: str
    group: str
    startLine: int
    endLine: int
    message: list[str] = field(default_factory=list)
    location: str | None = None
    # False only for a pytest short-summary row whose id/message boundary
    # could not be resolved (see _pytest_short); `name` is then the raw,
    # unsplit rest of the line and `message` is empty.
    idResolved: bool = True


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


def _plain_line(line: str) -> str:
    return ANSI_CSI.sub("", ANSI_LINK.sub("", line))


def _well_formed_nodeid(candidate: str) -> bool:
    """Is `candidate` shaped like a pytest nodeid, not a nodeid-plus-message?

    pytest does not escape '[' or ']' inside a parametrize id, so neither
    the first nor the last separator in a short-summary line can be trusted
    to be the id/message boundary: a raised message can itself contain
    '[...]' or ' - ', and a parametrize value can itself contain ']' or a
    dash. This checks one candidate id in isolation, without assuming which
    split point produced it:

    - Everything before the first '[' (the whole candidate, if there is no
      '[') must contain no whitespace. A pytest id/path never does; a
      message glued onto the id by a wrong split always does (it is
      prefixed by " - " or contains an exception name like "ValueError: ").
    - A candidate containing '[' must end with ']' (its own wrapping
      bracket has to be the last thing before a message would start).
    - The bracket portion may be a single, possibly nested, group (pytest
      wraps the whole parametrize id in one more '[...]', so nesting is
      normal), or it may end in a stray, never-reopened ']' (the id's own
      bracket closed, and a later ']' from the message text follows with no
      further '[' before it). A close followed by a *reopen* with a fresh
      '[' is, on its own, not disqualifying either: a parametrize value is
      free to contain '] ... [' as literal text (e.g. a value of
      "] - [x"), which is exactly as well-formed a nodeid shape as a
      message glued on by a wrong split. What *is* disqualifying is a
      reopen with anything other than the bare " - " split separator
      between the close and it: real message text (an exception name, a
      colon, other words) between them means this candidate absorbed part
      of the message, not that the parameter value happened to close and
      reopen a bracket. When that ambiguity cannot be resolved this way
      either, more than one candidate stays well-formed and the caller
      keeps the raw line with the id unresolved rather than guess.
    """
    name_part, opened, bracket_part = candidate.partition("[")
    if not name_part or any(char.isspace() for char in name_part):
        return False
    if not opened:
        return True
    if not candidate.endswith("]"):
        return False
    depth = 0
    closed_once = False
    gap = ""
    for char in "[" + bracket_part:
        if char == "[":
            if depth == 0 and closed_once:
                if gap != " - ":
                    return False
                gap = ""
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                closed_once = True
                gap = ""
        elif depth == 0 and closed_once:
            gap += char
    return True


def _pytest_short(
    line: str, known_identities: frozenset[str] = frozenset()
) -> tuple[str, str, str, bool] | None:
    """Split a "FAILED ..."/"ERROR ..." short-summary line into its parts.

    Returns (status, nodeid, message, idResolved). `known_identities` are
    nodeid identities (no leading "path::") already seen elsewhere in the
    log -- a detail block heading or a verbose (-v) progress line -- and
    take priority over guessing: never decide the id boundary from the
    first or last separator in the line alone.
    """
    match = PYTEST_SHORT.fullmatch(line)
    if match is None:
        return None
    status = match.group("status")
    rest = match.group("rest")
    group, sep, tail = rest.partition("::")

    if sep and known_identities:
        best: str | None = None
        for identity in known_identities:
            if not tail.startswith(identity):
                continue
            remainder = tail[len(identity) :]
            if remainder and not remainder.startswith(" - "):
                continue
            if best is None or len(identity) > len(best):
                best = identity
        if best is not None:
            message = tail[len(best) :]
            if message.startswith(" - "):
                message = message[3:]
            return status, f"{group}::{best}", message, True

    # No known nodeid covers this line: enumerate every ' - ' split point
    # (plus "no split at all", for a message-less row) as a candidate
    # id/message boundary, and accept only if exactly one candidate is a
    # well-formed nodeid on its own. More than one, or none, means the line
    # is genuinely ambiguous from local text alone; keep it raw rather than
    # guess (see the owner review this fixes: a raised message containing
    # its own '[...] - ...' used to be silently folded into the id).
    candidates = [(rest, "")] + [
        (rest[: m.start()], rest[m.start() + 3 :]) for m in re.finditer(" - ", rest)
    ]
    valid = [pair for pair in candidates if _well_formed_nodeid(pair[0])]
    if len(valid) == 1:
        # A leading empty parameter group followed by another bracketed
        # segment can be either a value beginning with a close bracket or a
        # message whose text happens to contain brackets. The short summary
        # cannot distinguish those readings; retain the raw row instead of
        # silently truncating the nodeid at the first separator.
        first_separator = rest.find(" - ")
        if (
            "[]" in rest[: first_separator if first_separator >= 0 else len(rest)]
            and first_separator >= 0
            and "[" in rest[first_separator + 3 :]
        ):
            return status, rest, "", False
        nodeid, message = valid[0]
        return status, nodeid, message, True
    return status, rest, "", False


def _pytest_summary(line: str, line_number: int) -> dict | None:
    banner = PYTEST_BANNER.fullmatch(line)
    candidate = banner.group("title") if banner else line
    match = PYTEST_FINAL.fullmatch(candidate)
    if match is None:
        return None
    counts = {}
    body = match.group("body")
    if body != "no tests ran":
        for part in body.split(", "):
            number, label = part.split(" ", 1)
            label = {"error": "errors", "warning": "warnings"}.get(label, label)
            if label in counts:
                return None
            counts[label] = int(number)
    outcomes = ("passed", "failed", "skipped", "xfailed", "xpassed")
    # A teardown error can be reported alongside the same test's pass/failure;
    # collection errors aren't test executions. Don't invent a unique test count.
    run = None if counts.get("errors") else sum(counts.get(k, 0) for k in outcomes)
    if body != "no tests ran" and not any(
        k in counts for k in (*outcomes, "deselected", "errors")
    ):
        run = None
    return {
        "run": run,
        "passed": counts.pop("passed", 0),
        "failed": counts.pop("failed", 0),
        "skipped": counts.pop("skipped", 0),
        **counts,
        "line": line_number,
    }


def _nextest_summary(line: str, line_number: int) -> dict | None:
    match = NEXTEST_SUMMARY.fullmatch(line)
    if match is None:
        return None
    # Commas in the passed count's (slow, flaky, leaky) annotation are not
    # separators between outcome counts. Reject unrecognized tails in full.
    parts = re.split(r", (?![^()]*\))", match.group("body"))
    counts = {}
    for part in parts:
        count = NEXTEST_COUNT.fullmatch(part)
        if count is None or count.group("label") in counts:
            return None
        counts[count.group("label")] = int(count.group("count"))
    if "passed" not in counts:
        return None
    return {
        "run": int(match.group("run")),
        "passed": counts.pop("passed"),
        "failed": counts.pop("failed", 0),
        "skipped": counts.pop("skipped", 0),
        **counts,
        "line": line_number,
    }


def _incomplete_summary(failures: list[Failure]) -> dict:
    # Observed blocks are not a terminal failure count: logs may be truncated
    # and nextest retries can eventually pass. Preserve the distinction.
    return {
        "run": None,
        "passed": None,
        "failed": None,
        "skipped": None,
        "line": None,
        "observedFailureBlocks": len(failures),
    }


def detect_format(lines: list[str]) -> str | None:
    # Strong runner markers take precedence over a bare pytest-like footer.
    for raw in lines:
        line = _plain_line(raw)
        if NEXTEST_STATUS.match(line) or NEXTEST_SUMMARY.match(line):
            return "nextest"
        banner = PYTEST_BANNER.match(line)
        if banner and banner.group("title") in (
            "test session starts",
            "FAILURES",
            "ERRORS",
            "short test summary info",
        ):
            return "pytest"
        short = _pytest_short(line)
        if short and ("::" in short[1] or short[1].endswith(".py")):
            return "pytest"
    if any(_pytest_summary(_plain_line(line), 0) is not None for line in lines):
        return "pytest"
    return None


def parse_log(text: str, fmt: str = "auto") -> ParsedLog:
    lines = [_plain_line(line) for line in text.splitlines()]
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
            if NEXTEST_SUMMARY.match(line):
                summary = _nextest_summary(line, index + 1) or {}
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
            "EXECFAIL",
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
        summary = _incomplete_summary(failures)
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


# Phases whose short-summary status is FAILED vs ERROR: a body (call)
# failure is always reported as FAILED; setup, teardown and collection
# problems are always reported as ERROR. Matching on this in addition to
# the name keeps a body failure and a teardown error of the same test from
# being joined to each other's detail block.
_DETAIL_PHASE_PREFIXES = (
    ("ERROR at setup of ", "setup"),
    ("ERROR at teardown of ", "teardown"),
    ("ERROR collecting ", "collection"),
)
_PHASES_BY_STATUS = {
    "FAILED": frozenset({"body"}),
    "ERROR": frozenset({"setup", "teardown", "collection"}),
}


def _detail_identity_and_phase(name: str) -> tuple[str, str]:
    phase = "body"
    for prefix, prefix_phase in _DETAIL_PHASE_PREFIXES:
        if name.startswith(prefix):
            name = name[len(prefix) :]
            phase = prefix_phase
            break
    if name.endswith(".py"):
        # A collection-error path is not a dotted test class name.
        return name, "collection"
    base, bracket, parameters = name.partition("[")
    return base.replace(".", "::") + bracket + parameters, phase


def _detail_identity(name: str) -> str:
    identity, _phase = _detail_identity_and_phase(name)
    return identity


def _join_short_summaries(
    failures: list[Failure], short: list[tuple[str, str, str, int, bool]]
) -> None:
    """Join unambiguously; retain a standalone summary row when detail is absent.

    Same-named tests in different files must not be rebound to the last nodeid.
    Each summary entry and detailed block is matched at most once. A body
    failure and a teardown/setup/collection error of the same test share one
    nodeid in the short summary, so the FAILED/ERROR status plus the phase
    recorded on the detail block's own heading is required to tell them apart.
    """
    used: set[int] = set()

    def candidates_for(
        expected_phases: frozenset[str], group: str, name: str, nodeid: str
    ) -> list[int]:
        found = []
        for index, failure in enumerate(failures):
            if index in used or failure.group != "pytest":
                continue
            identity, phase = _detail_identity_and_phase(failure.name)
            if phase not in expected_phases:
                continue
            if identity != name and failure.name != nodeid:
                continue
            # A collection heading names the full source file explicitly;
            # its traceback may point into pytest's importer instead.
            if failure.location and identity != nodeid:
                source = failure.location.rsplit(":", 1)[0]
                if source != group and not source.endswith("/" + group):
                    continue
            found.append(index)
        return found

    for status, nodeid, message, line_number, id_resolved in short:
        group, separator, name = nodeid.partition("::")
        name = name if separator else nodeid
        if not id_resolved:
            # The id/message boundary could not be resolved (see
            # _pytest_short): `name` is the raw, unsplit rest of the line,
            # not a real identity, so it cannot be matched against a detail
            # block's heading. Keep it as its own standalone row.
            failures.append(
                Failure(
                    name=name,
                    group=group,
                    startLine=line_number,
                    endLine=line_number,
                    message=[],
                    idResolved=False,
                )
            )
            used.add(len(failures) - 1)
            continue
        strict_phases = _PHASES_BY_STATUS.get(status, frozenset())
        candidates = candidates_for(strict_phases, group, name, nodeid)
        if not candidates and status != "FAILED":
            # A detail heading without an "at setup/teardown/collecting of"
            # phrase (e.g. a bare dotted class.method name) still resolves
            # to phase "body"; a FAILED status never matches anything but
            # a body block, but an ERROR-family status may, in the absence
            # of a stricter match, still be the only detail block for it.
            candidates = candidates_for(strict_phases | {"body"}, group, name, nodeid)
        if len(candidates) == 1 and not failures[candidates[0]].location:
            # One remaining display block is still ambiguous when two different
            # files report the same name. The summary order is not provenance.
            possible = {
                other
                for other_status, other, _, _, _ in short
                if other_status == status and other.partition("::")[2] == name
            }
            if len(possible) > 1:
                candidates = []
        if len(candidates) == 1:
            index = candidates[0]
            used.add(index)
            failure = failures[index]
            failure.group = group
            if message and not failure.message:
                failure.message = [message]
        else:
            # --tb=no, collection errors and ambiguous display names still
            # have actionable identity and an honest source line in -r output.
            failures.append(
                Failure(
                    name=name,
                    group=group,
                    startLine=line_number,
                    endLine=line_number,
                    message=[message] if message else [],
                )
            )
            used.add(len(failures) - 1)


def parse_pytest(lines: list[str]) -> ParsedLog:
    summary: dict = {}
    failures: list[Failure] = []
    short: list[tuple[str, str, str, int, bool]] = []
    seen_short: set[tuple[str, str, str]] = set()
    in_failures = False
    in_short_summary = False
    block_start: int | None = None
    block_name: str | None = None
    # Nodeid identities (no leading "path::") already seen as a detail block
    # heading or a verbose (-v) progress line, in log order. Both always
    # precede the short-summary section they resolve, so a single forward
    # pass can feed each short-summary line every identity seen so far.
    known_identities: set[str] = set()

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
        known_identities.add(_detail_identity(block_name))
        block_start = None
        block_name = None

    for index, line in enumerate(lines):
        # A normal pytest final summary is itself a banner. Inspect it first,
        # otherwise the generic banner branch consumes it and loses all counts.
        final = _pytest_summary(line, index + 1)
        if final is not None:
            close_block(index)
            in_failures = False
            in_short_summary = False
            summary = final
            continue
        banner = PYTEST_BANNER.match(line)
        if banner:
            close_block(index)
            title = banner.group("title").strip()
            in_failures = title in ("FAILURES", "ERRORS")
            in_short_summary = title == "short test summary info"
            continue
        if in_failures:
            block = PYTEST_BLOCK.match(line)
            if block:
                close_block(index)
                block_start = index
                block_name = block.group("name").strip()
                continue
        # A verbose (-v) progress line and a short-summary row are told
        # apart by section, not by which regex happens to match first: the
        # progress regex is lenient enough (it accepts any status word,
        # including PASSED/FAILED/ERROR appearing at the end of a *message*)
        # that a "FAILED ... - ValueError: ERROR" row would otherwise be
        # misread as "<nodeid> ERROR" and silently dropped instead of
        # becoming a failure. Never try it inside the short test summary
        # info section, and never on a line that is itself a short-summary
        # row (those always start with "FAILED "/"ERROR "; a real nodeid
        # never does).
        if not in_short_summary and not line.startswith(("FAILED ", "ERROR ")):
            verbose = PYTEST_VERBOSE.match(line)
            if verbose:
                nodeid = verbose.group("nodeid")
                _, verbose_sep, verbose_tail = nodeid.partition("::")
                if verbose_sep:
                    known_identities.add(verbose_tail)
                continue
        short_match = _pytest_short(line, frozenset(known_identities))
        if short_match:
            status, nodeid, message, id_resolved = short_match
            key = (status, nodeid, message)
            if key not in seen_short:
                seen_short.add(key)
                short.append((status, nodeid, message, index + 1, id_resolved))
    close_block(len(lines))
    _join_short_summaries(failures, short)
    if not summary:
        summary = _incomplete_summary(failures)
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
    if summary.get("errors"):
        out.append(f"# errors: {summary['errors']} (separate from assertion failures)")
    if summary.get("line") is None:
        out.append(
            "# terminal summary unavailable; observed blocks are not a final verdict"
        )
    out.append("")
    for number, failure in enumerate(parsed.failures, start=1):
        out.append(f"## failure {number}: {failure.group} {failure.name}")
        out.append(f"source: {source_name}:{failure.startLine}-{failure.endLine}")
        if failure.location:
            out.append(f"location: {failure.location}")
        if not failure.idResolved:
            out.append(
                "(id boundary unresolved: the name above is the raw, "
                "unsplit short-summary line; no message was separated out)"
            )
        elif failure.message:
            out.extend(failure.message)
        else:
            out.append("(no failure message captured in the log)")
        out.append("")
    return "\n".join(out).rstrip("\n") + "\n"
