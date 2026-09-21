"""Script-side validation of model output and the single-repair inference loop."""

from __future__ import annotations

import json

import pytest
from local_assist.context_builder import read_inputs
from local_assist.inference import (
    RuntimeIdentity,
    accept_findings,
    budget_check,
    build_messages,
    cache_key,
    load_prompt,
    probe_runtime,
    response_schema,
    run_inference,
    validate_response,
)
from local_assist.packet import InputSelection, parse_packet
from local_assist.transport import TransportError

GOOD = {
    "claim": "c",
    "path": "a.rs",
    "startLine": 1,
    "endLine": 2,
    "evidence": "e",
}


@pytest.mark.parametrize(
    "kind, obj, fragment",
    [
        ("find-test-candidates", [], "not a JSON object"),
        ("find-test-candidates", {"findings": []}, "unknowns must be an array"),
        (
            "find-test-candidates",
            {"findings": [], "unknowns": [], "x": 1},
            "unexpected top-level",
        ),
        (
            "find-test-candidates",
            {"findings": {}, "unknowns": []},
            "findings must be an array",
        ),
        (
            "find-test-candidates",
            {"findings": [GOOD, GOOD, GOOD], "unknowns": []},
            "more than 2",
        ),
        (
            "find-test-candidates",
            {"findings": [{**GOOD, "confidence": 0.9}], "unknowns": []},
            "unexpected keys",
        ),
        (
            "find-test-candidates",
            {"findings": [{**GOOD, "claim": "bad\x00"}], "unknowns": []},
            "control",
        ),
        (
            "find-test-candidates",
            {"findings": [{**GOOD, "startLine": "1"}], "unknowns": []},
            "positive integer",
        ),
        (
            "find-test-candidates",
            {"findings": [{**GOOD, "startLine": True}], "unknowns": []},
            "positive integer",
        ),
        (
            "find-test-candidates",
            {"findings": [{**GOOD, "endLine": 0}], "unknowns": []},
            "positive integer",
        ),
        (
            "find-test-candidates",
            {"findings": [{**GOOD, "startLine": 5}], "unknowns": []},
            "before startLine",
        ),
        (
            "find-test-candidates",
            {"findings": [{**GOOD, "evidence": " "}], "unknowns": []},
            "must not be empty",
        ),
        (
            "find-test-candidates",
            {"findings": [], "unknowns": [1]},
            "unknowns[0] must be a string",
        ),
        ("classify-log", {"findings": [GOOD], "unknowns": []}, "missing category"),
        (
            "classify-log",
            {"findings": [{**GOOD, "category": "cosmic"}], "unknowns": []},
            "allowed categories",
        ),
        (
            "propose-tests",
            {"findings": [{**GOOD, "positiveControl": "p"}], "unknowns": []},
            "missing refusalPostState",
        ),
        (
            "propose-tests",
            {
                "findings": [{**GOOD, "positiveControl": "", "refusalPostState": "r"}],
                "unknowns": [],
            },
            "positiveControl must not be empty",
        ),
    ],
)
def test_invalid_replies_are_named(kind, obj, fragment):
    errors = validate_response(kind, obj, 2)
    assert any(fragment in error for error in errors), errors


def test_valid_replies_have_no_errors():
    assert (
        validate_response(
            "find-test-candidates", {"findings": [GOOD], "unknowns": ["u"]}, 2
        )
        == []
    )
    assert (
        validate_response(
            "classify-log",
            {"findings": [{**GOOD, "category": "timeout"}], "unknowns": []},
            2,
        )
        == []
    )


def test_the_schema_sent_to_the_server_matches_the_local_validator():
    schema = response_schema("propose-tests", 3)
    assert schema["properties"]["findings"]["maxItems"] == 3
    items = schema["properties"]["findings"]["items"]
    assert set(items["required"]) == {
        "claim",
        "path",
        "startLine",
        "endLine",
        "evidence",
        "positiveControl",
        "refusalPostState",
    }
    assert items["additionalProperties"] is False
    assert schema["additionalProperties"] is False


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "a.rs").write_text("\n".join(f"line {n}" for n in range(1, 31)) + "\n")
    return root


def test_findings_must_sit_inside_the_read_range_of_a_packet_input(repo):
    inputs = read_inputs(str(repo), (InputSelection("a.rs", 5, 10),))
    accepted, dropped = accept_findings(
        [
            {**GOOD, "startLine": 5, "endLine": 10, "evidence": "line 7\nline 8"},
            {**GOOD, "startLine": 6, "endLine": 6, "evidence": "line   6"},
            {**GOOD, "startLine": 4, "endLine": 6},
            {**GOOD, "startLine": 9, "endLine": 11},
            {**GOOD, "path": "b.rs", "startLine": 5, "endLine": 6},
        ],
        inputs,
    )
    assert [
        (f["startLine"], f["endLine"], f["evidenceVerified"]) for f in accepted
    ] == [
        (5, 10, True),
        (6, 6, True),
    ]
    assert dropped == [
        "dropped finding citing a.rs:4-6: not inside any packet input",
        "dropped finding citing a.rs:9-11: not inside any packet input",
        "dropped finding citing b.rs:5-6: not inside any packet input",
    ]


def test_evidence_outside_the_cited_lines_is_not_verified(repo):
    inputs = read_inputs(str(repo), (InputSelection("a.rs", 1, 30),))
    accepted, _ = accept_findings(
        [{**GOOD, "startLine": 2, "endLine": 3, "evidence": "line 9"}], inputs
    )
    assert accepted[0]["evidenceVerified"] is False


def _packet(repo, **overrides):
    raw = {
        "taskId": "T-1",
        "kind": "find-test-candidates",
        "repoRoot": str(repo),
        "baseCommit": "b" * 40,
        "question": "q",
        "inputs": [{"path": "a.rs", "startLine": 1, "endLine": 30}],
        "maxFindings": 3,
        "maxOutputTokens": 200,
        "endpoint": "http://127.0.0.1:8011/v1/chat/completions",
        "deadlineSeconds": 5,
    }
    raw.update(overrides)
    return parse_packet(raw)


def test_budget_is_estimated_conservatively_and_reserves_the_output(repo):
    packet = _packet(repo)
    inputs = read_inputs(str(repo), packet.inputs)
    prompt = load_prompt(packet.kind)
    messages = build_messages(packet, inputs, prompt)
    fits, detail = budget_check(messages, 200, 16384)
    assert fits
    assert detail["availablePromptTokens"] == 16184
    assert detail["estimatedPromptTokens"] > 256
    fits, _ = budget_check(messages, 200, 1024)
    assert not fits


def test_prompt_version_changes_with_the_prompt_text(monkeypatch, tmp_path):
    from local_assist import inference

    original = load_prompt("classify-log").version
    assert original.startswith("classify-log@1-")
    prompts = tmp_path / "prompts"
    prompts.mkdir()
    (prompts / "common.txt").write_text("common")
    (prompts / "classify-log.txt").write_text("changed")
    monkeypatch.setattr(inference, "PROMPTS_DIR", prompts)
    assert load_prompt("classify-log").version != original


def test_cache_key_covers_kind_question_lines_hashes_prompt_and_runtime(repo):
    packet = _packet(repo)
    inputs = read_inputs(str(repo), packet.inputs)
    prompt = load_prompt(packet.kind)
    runtime = RuntimeIdentity(
        "http://127.0.0.1:8011/v1/chat/completions", "a", "m", "Q4"
    )
    base = cache_key(packet, inputs, prompt, runtime, "json_schema")
    assert (
        cache_key(
            _packet(repo, question="other"), inputs, prompt, runtime, "json_schema"
        )
        != base
    )
    assert (
        cache_key(_packet(repo, maxFindings=2), inputs, prompt, runtime, "json_schema")
        != base
    )
    narrower = read_inputs(str(repo), (InputSelection("a.rs", 1, 29),))
    assert cache_key(packet, narrower, prompt, runtime, "json_schema") != base
    other_runtime = RuntimeIdentity(runtime.endpoint, "a", "m", "Q8")
    assert cache_key(packet, inputs, prompt, other_runtime, "json_schema") != base
    assert cache_key(packet, inputs, prompt, runtime, "prompt") != base
    assert cache_key(packet, inputs, prompt, runtime, "json_schema") == base


class ScriptedTransport:
    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def __call__(self, method, url, body, timeout):
        self.calls.append((method, url, body, timeout))
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


def _completion(content: str, finish="stop"):
    return {
        "model": "m",
        "choices": [{"message": {"content": content}, "finish_reason": finish}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
    }


def _run(repo, transport, **overrides):
    packet = _packet(repo, **overrides)
    inputs = read_inputs(str(repo), packet.inputs)
    prompt = load_prompt(packet.kind)
    messages = build_messages(packet, inputs, prompt)
    runtime = RuntimeIdentity(packet.endpoint, None, "m", None)
    return run_inference(packet, inputs, prompt, messages, runtime, transport, True)


def test_usage_is_summed_across_the_repair_attempt(repo):
    transport = ScriptedTransport(
        [
            _completion("{}"),
            _completion(
                json.dumps(
                    {"findings": [{**GOOD, "evidence": "line 1"}], "unknowns": []}
                )
            ),
        ]
    )
    outcome = _run(repo, transport)
    assert outcome.finishStatus == "ok"
    assert outcome.repairAttempted is True
    assert outcome.usage == {"promptTokens": 20, "completionTokens": 10}
    assert outcome.findings[0]["evidenceVerified"] is True
    assert len(transport.calls) == 2
    assert all(call[3] <= 5 for call in transport.calls)


def test_a_timeout_during_the_repair_is_reported_as_timeout(repo):
    transport = ScriptedTransport(
        [_completion("{}"), TransportError("timeout", "request deadline exceeded")]
    )
    outcome = _run(repo, transport)
    assert outcome.finishStatus == "timeout"
    assert outcome.repairAttempted is True


def test_a_reply_without_choices_is_a_server_error(repo):
    transport = ScriptedTransport([{"model": "m"}])
    outcome = _run(repo, transport)
    assert outcome.finishStatus == "server-error"
    assert outcome.reason == "reply has no choices"
    assert len(transport.calls) == 1


def test_probe_runtime_reads_the_model_id_and_quant():
    transport = ScriptedTransport(
        [
            {
                "data": [
                    {
                        "id": "/models/Qwen3-Coder-Next-Q4_K_M.gguf",
                        "meta": {"n_params": 80, "size": 1},
                    }
                ]
            }
        ]
    )
    runtime = probe_runtime(
        "http://127.0.0.1:8011/v1/chat/completions", transport, 5, "fireemu-local"
    )
    assert transport.calls[0][:2] == ("GET", "http://127.0.0.1:8011/v1/models")
    assert runtime.modelId == "/models/Qwen3-Coder-Next-Q4_K_M.gguf"
    assert runtime.quant == "Q4_K_M"
    assert runtime.alias == "fireemu-local"
    assert runtime.to_dict()["meta"] == {"n_params": 80, "size": 1}


def test_probe_runtime_refuses_an_empty_model_list():
    transport = ScriptedTransport([{"data": []}])
    with pytest.raises(TransportError, match="did not list a model"):
        probe_runtime("http://127.0.0.1:8011/v1/chat/completions", transport, 5, None)
