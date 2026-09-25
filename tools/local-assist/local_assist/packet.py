"""Task packet parsing and validation.

A packet is the only thing the caller hands to the tool. Everything in it is
validated at this boundary; the rest of the tool trusts the resulting values.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

KINDS = ("find-test-candidates", "classify-log", "propose-tests")
TASK_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")
MAX_QUESTION_CHARS = 2000
MAX_INPUTS = 16
MAX_FINDINGS = 50
MAX_OUTPUT_TOKENS = 1500
MAX_LINES_PER_INPUT = 2000
DEFAULT_DEADLINE_SECONDS = 120.0
MAX_DEADLINE_SECONDS = 900.0


class PacketError(ValueError):
    """The packet is malformed; nothing was executed."""


@dataclass(frozen=True)
class InputSelection:
    path: str
    startLine: int
    endLine: int


@dataclass(frozen=True)
class Packet:
    taskId: str
    kind: str
    repoRoot: str
    baseCommit: str
    question: str
    inputs: tuple[InputSelection, ...]
    maxFindings: int
    maxOutputTokens: int
    endpoint: str | None = None
    deadlineSeconds: float = DEFAULT_DEADLINE_SECONDS
    extra: dict = field(default_factory=dict)


def _control_free(value: str, name: str, limit: int) -> str:
    if not isinstance(value, str):
        raise PacketError(f"{name} must be a string")
    if not value.strip():
        raise PacketError(f"{name} must not be empty")
    if len(value) > limit:
        raise PacketError(f"{name} exceeds {limit} characters")
    if any(ord(ch) < 0x20 and ch not in "\n\t" for ch in value) or "\x7f" in value:
        raise PacketError(f"{name} contains control characters")
    return value


def _int_in(value: object, name: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PacketError(f"{name} must be an integer")
    if value < low or value > high:
        raise PacketError(f"{name} must be between {low} and {high}")
    return value


def validate_loopback_url(url: str) -> str:
    """Return the URL if it points at a loopback HTTP endpoint, else raise."""
    if not isinstance(url, str) or not url:
        raise PacketError("endpoint must be a non-empty string")
    if any(ord(ch) < 0x21 or ord(ch) == 0x7F for ch in url):
        raise PacketError("endpoint contains whitespace or control characters")
    parts = urlsplit(url)
    if parts.scheme != "http":
        raise PacketError("endpoint must use the http scheme (loopback only)")
    if parts.username or parts.password:
        raise PacketError("endpoint must not carry credentials")
    host = parts.hostname
    if host is None or host.lower() not in LOOPBACK_HOSTS:
        raise PacketError(f"endpoint host is not loopback: {host!r}")
    if parts.query or parts.fragment:
        raise PacketError("endpoint must not carry a query or fragment")
    return url


def parse_packet(raw: object) -> Packet:
    if not isinstance(raw, dict):
        raise PacketError("packet must be a JSON object")
    required = (
        "taskId",
        "kind",
        "repoRoot",
        "baseCommit",
        "question",
        "inputs",
        "maxFindings",
        "maxOutputTokens",
    )
    missing = [key for key in required if key not in raw]
    if missing:
        raise PacketError(f"packet is missing {', '.join(missing)}")
    known = set(required) | {"endpoint", "deadlineSeconds", "extra"}
    unknown = sorted(set(raw) - known)
    if unknown:
        raise PacketError(f"packet has unknown keys: {', '.join(unknown)}")

    task_id = raw["taskId"]
    if not isinstance(task_id, str) or not TASK_ID.match(task_id):
        raise PacketError("taskId must match [A-Za-z0-9][A-Za-z0-9._-]{0,79}")
    kind = raw["kind"]
    if kind not in KINDS:
        raise PacketError(f"kind must be one of {', '.join(KINDS)}")
    repo_root = raw["repoRoot"]
    if not isinstance(repo_root, str) or not repo_root.startswith("/"):
        raise PacketError("repoRoot must be an absolute path")
    if "\x00" in repo_root:
        raise PacketError("repoRoot contains a NUL byte")
    base_commit = raw["baseCommit"]
    if not isinstance(base_commit, str) or not COMMIT.match(base_commit):
        raise PacketError("baseCommit must be a 40-hex commit id")
    question = _control_free(raw["question"], "question", MAX_QUESTION_CHARS)

    inputs_raw = raw["inputs"]
    if not isinstance(inputs_raw, list) or not inputs_raw:
        raise PacketError("inputs must be a non-empty list")
    if len(inputs_raw) > MAX_INPUTS:
        raise PacketError(f"inputs must not exceed {MAX_INPUTS} entries")
    inputs: list[InputSelection] = []
    seen: set[tuple[str, int, int]] = set()
    for index, item in enumerate(inputs_raw):
        if not isinstance(item, dict):
            raise PacketError(f"inputs[{index}] must be an object")
        extra_keys = sorted(set(item) - {"path", "startLine", "endLine"})
        if extra_keys:
            raise PacketError(
                f"inputs[{index}] has unknown keys: {', '.join(extra_keys)}"
            )
        path = item.get("path")
        if not isinstance(path, str) or not path:
            raise PacketError(f"inputs[{index}].path must be a non-empty string")
        start = _int_in(
            item.get("startLine"), f"inputs[{index}].startLine", 1, 10_000_000
        )
        end = _int_in(item.get("endLine"), f"inputs[{index}].endLine", 1, 10_000_000)
        if end < start:
            raise PacketError(f"inputs[{index}] endLine is before startLine")
        if end - start + 1 > MAX_LINES_PER_INPUT:
            raise PacketError(
                f"inputs[{index}] selects more than {MAX_LINES_PER_INPUT} lines; narrow it"
            )
        key = (path, start, end)
        if key in seen:
            raise PacketError(f"inputs[{index}] duplicates an earlier selection")
        seen.add(key)
        inputs.append(InputSelection(path=path, startLine=start, endLine=end))

    max_findings = _int_in(raw["maxFindings"], "maxFindings", 1, MAX_FINDINGS)
    max_output = _int_in(
        raw["maxOutputTokens"], "maxOutputTokens", 64, MAX_OUTPUT_TOKENS
    )

    endpoint = raw.get("endpoint")
    if endpoint is not None:
        endpoint = validate_loopback_url(endpoint)
    deadline = raw.get("deadlineSeconds", DEFAULT_DEADLINE_SECONDS)
    if isinstance(deadline, bool) or not isinstance(deadline, (int, float)):
        raise PacketError("deadlineSeconds must be a number")
    # NaN compares false against every bound, so it must be refused explicitly.
    if not math.isfinite(deadline) or deadline <= 0 or deadline > MAX_DEADLINE_SECONDS:
        raise PacketError(
            f"deadlineSeconds must be within (0, {MAX_DEADLINE_SECONDS:g}]"
        )
    extra = raw.get("extra", {})
    if not isinstance(extra, dict):
        raise PacketError("extra must be an object")

    return Packet(
        taskId=task_id,
        kind=kind,
        repoRoot=repo_root,
        baseCommit=base_commit,
        question=question,
        inputs=tuple(inputs),
        maxFindings=max_findings,
        maxOutputTokens=max_output,
        endpoint=endpoint,
        deadlineSeconds=float(deadline),
        extra=extra,
    )
