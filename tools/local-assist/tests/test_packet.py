"""Packet validation is the trust boundary for everything the CLI does."""

import copy

import pytest
from local_assist.packet import PacketError, parse_packet, validate_loopback_url

VALID = {
    "taskId": "LOCAL-AUTH-TESTMAP-001",
    "kind": "find-test-candidates",
    "repoRoot": "/repo",
    "baseCommit": "0" * 40,
    "question": "which tests cover tenant refresh?",
    "inputs": [{"path": "crates/a/tests/x.rs", "startLine": 1, "endLine": 200}],
    "maxFindings": 5,
    "maxOutputTokens": 1200,
}


def test_a_valid_packet_parses_with_defaults():
    packet = parse_packet(VALID)
    assert packet.taskId == "LOCAL-AUTH-TESTMAP-001"
    assert packet.kind == "find-test-candidates"
    assert packet.inputs[0].path == "crates/a/tests/x.rs"
    assert packet.inputs[0].endLine == 200
    assert packet.endpoint is None
    assert packet.deadlineSeconds == 120.0


def _mutated(**changes):
    raw = copy.deepcopy(VALID)
    raw.update(changes)
    return raw


@pytest.mark.parametrize(
    "raw, reason",
    [
        ([], "JSON object"),
        ({k: v for k, v in VALID.items() if k != "inputs"}, "missing inputs"),
        (_mutated(unknownKey=1), "unknown keys"),
        (_mutated(taskId="../x"), "taskId"),
        (_mutated(taskId=""), "taskId"),
        (_mutated(kind="summarize"), "kind must be one of"),
        (_mutated(repoRoot="relative"), "absolute"),
        (_mutated(baseCommit="abc"), "40-hex"),
        (_mutated(question=""), "must not be empty"),
        (_mutated(question="x" * 2001), "exceeds"),
        (_mutated(question="bad\x00"), "control characters"),
        (_mutated(inputs=[]), "non-empty list"),
        (
            _mutated(inputs=[{"path": "a.rs", "startLine": 0, "endLine": 1}]),
            "startLine",
        ),
        (
            _mutated(inputs=[{"path": "a.rs", "startLine": 5, "endLine": 1}]),
            "before startLine",
        ),
        (
            _mutated(inputs=[{"path": "a.rs", "startLine": 1, "endLine": 2001}]),
            "narrow it",
        ),
        (_mutated(inputs=[{"path": "", "startLine": 1, "endLine": 2}]), "path"),
        (
            _mutated(inputs=[{"path": "a.rs", "startLine": 1, "endLine": 2, "x": 1}]),
            "unknown keys",
        ),
        (
            _mutated(
                inputs=[
                    {"path": "a.rs", "startLine": 1, "endLine": 2},
                    {"path": "a.rs", "startLine": 1, "endLine": 2},
                ]
            ),
            "duplicates",
        ),
        (_mutated(maxFindings=0), "maxFindings"),
        (_mutated(maxFindings=True), "maxFindings"),
        (_mutated(maxOutputTokens=5000), "maxOutputTokens"),
        (_mutated(endpoint="http://example.com/v1"), "not loopback"),
        (_mutated(endpoint="https://127.0.0.1:8011/v1"), "http scheme"),
        (
            _mutated(endpoint="http://127.0.0.1@evil.example/v1"),
            "credentials|not loopback",
        ),
        (_mutated(endpoint="http://user:pw@127.0.0.1:8011/v1"), "credentials"),
        (_mutated(endpoint="http://127.0.0.1:8011/v1?x=1"), "query"),
        (_mutated(deadlineSeconds=0), "deadlineSeconds"),
        (_mutated(deadlineSeconds="120"), "deadlineSeconds"),
        (_mutated(extra=[]), "extra"),
    ],
)
def test_malformed_packets_are_refused(raw, reason):
    with pytest.raises(PacketError, match=reason):
        parse_packet(raw)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8011/v1/chat/completions",
        "http://localhost:8012/v1/chat/completions",
        "http://[::1]:8011/v1/chat/completions",
    ],
)
def test_loopback_endpoints_are_accepted(url):
    assert validate_loopback_url(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.2:8011/v1",
        "http://10.0.0.5:8011/v1",
        "http://127.0.0.1.example.com/v1",
        "http://0.0.0.0:8011/v1",
        "http://[::ffff:127.0.0.1]:8011/v1",
        "ftp://127.0.0.1/v1",
        "http://127.0.0.1:8011/v1 ",
        "",
    ],
)
def test_non_loopback_endpoints_are_refused(url):
    with pytest.raises(PacketError):
        validate_loopback_url(url)
