"""Regression tests for the explicit completion contract."""

import json

from local_assist.context_builder import read_inputs
from local_assist.inference import (
    Prompt,
    RuntimeIdentity,
    build_messages,
    cache_key,
    run_inference,
)
from local_assist.transport import TransportError
from local_assist.packet import parse_packet


def _case(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "case.rs").write_text("fn case() {}\n", encoding="utf-8")
    packet = parse_packet(
        {
            "taskId": "completion-contract",
            "kind": "find-test-candidates",
            "repoRoot": str(repo),
            "baseCommit": "a" * 40,
            "question": "Find the case test.",
            "inputs": [{"path": "case.rs", "startLine": 1, "endLine": 1}],
            "maxFindings": 1,
            "maxOutputTokens": 256,
            "deadlineSeconds": 5,
        }
    )
    inputs = read_inputs(packet.repoRoot, packet.inputs)
    prompt = Prompt(packet.kind, "Return JSON.", "completion-contract@1")
    messages = build_messages(packet, inputs, prompt)
    runtime = RuntimeIdentity("http://127.0.0.1:1/v1/chat/completions", "m", "m", "Q4_K_M")
    return packet, inputs, prompt, messages, runtime


def _reply(finish_reason):
    return {
        "model": "m",
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": json.dumps({"findings": [], "unknowns": []}),
                },
                **({"finish_reason": finish_reason} if finish_reason is not None else {}),
            }
        ],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
    }


def test_missing_finish_reason_is_unknown_and_never_repaired(tmp_path):
    case = _case(tmp_path)
    calls = []

    def transport(*args):
        calls.append(args)
        return _reply(None)

    result = run_inference(*case, transport, True)
    assert result.finishStatus == "server-error"
    assert result.serverStateUnknown is True
    assert result.repairAttempted is False
    assert len(calls) == 1


def test_normal_stop_is_accepted(tmp_path):
    case = _case(tmp_path)
    result = run_inference(*case, lambda *args: _reply("stop"), True)
    assert result.finishStatus == "ok"


def test_nonstop_terminal_reason_is_not_repaired(tmp_path):
    case = _case(tmp_path)
    calls = []

    def transport(*args):
        calls.append(args)
        return _reply("length")

    result = run_inference(*case, transport, True)
    assert result.finishStatus == "schema-invalid"
    assert result.repairAttempted is False
    assert len(calls) == 1


def test_response_contract_version_separates_cache_keys(tmp_path):
    packet, inputs, prompt, _, runtime = _case(tmp_path)
    first = cache_key(packet, inputs, prompt, runtime, "json_schema")
    import local_assist.inference as module

    old = module.RESPONSE_CONTRACT_VERSION
    try:
        module.RESPONSE_CONTRACT_VERSION = old + 1
        assert cache_key(packet, inputs, prompt, runtime, "json_schema") != first
    finally:
        module.RESPONSE_CONTRACT_VERSION = old


def test_failed_repair_keeps_first_response_usage(tmp_path):
    case = _case(tmp_path)
    replies = iter(
        [
            {
                "model": "m",
                "choices": [
                    {"message": {"content": "not json"}, "finish_reason": "stop"}
                ],
                "usage": {"prompt_tokens": 7, "completion_tokens": 3},
            },
            TransportError("server-error", "repair failed", inflight=True),
        ]
    )

    def transport(*args):
        reply = next(replies)
        if isinstance(reply, BaseException):
            raise reply
        return reply

    result = run_inference(*case, transport, True)
    assert result.finishStatus == "server-error"
    assert result.serverStateUnknown is True
    assert result.repairAttempted is True
    assert result.usage["promptTokens"] == 7
    assert result.usage["completionTokens"] == 3
