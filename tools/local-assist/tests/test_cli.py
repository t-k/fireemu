"""End-to-end CLI behavior against a scripted loopback server."""

from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path

import pytest
from local_assist_fake_server import FakeLlamaServer
from main import main

BASE = "a" * 40
SPEC_TEXT = """# Tenant refresh

A refresh token minted for tenant A MUST be exchanged only for tenant A.
Exchanging it while naming tenant B MUST fail with INVALID_REFRESH_TOKEN
and MUST NOT rotate or revoke the original token.
"""
TEST_TEXT = "\n".join(  # noqa: FLY002
    [
        "use fireemu::auth::*;",
        "",
        "#[test]",
        "fn refresh_within_the_tenant_succeeds() {",
        '    let token = mint("tenant-a");',
        '    assert!(exchange(&token, "tenant-a").is_ok());',
        "}",
        "",
        "#[test]",
        "fn refresh_across_tenants_is_refused() {",
        '    let token = mint("tenant-a");',
        '    let err = exchange(&token, "tenant-b").unwrap_err();',
        '    assert_eq!(err.code, "INVALID_REFRESH_TOKEN");',
        "    assert!(still_valid(&token));",
        "}",
        "",
    ]
)


@pytest.fixture
def server():
    fake = FakeLlamaServer().start()
    yield fake
    fake.stop()


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    (root / "crates" / "auth" / "tests").mkdir(parents=True)
    (root / "crates" / "auth" / "tests" / "tenant.rs").write_text(TEST_TEXT)
    (root / "spec").mkdir()
    (root / "spec" / "tenant-refresh.md").write_text(SPEC_TEXT)
    return root


@pytest.fixture
def state_dir(tmp_path):
    return tmp_path / "state"


def write_packet(tmp_path, server, repo, **overrides) -> Path:
    packet = {
        "taskId": "LOCAL-TEST-001",
        "kind": "find-test-candidates",
        "repoRoot": str(repo),
        "baseCommit": BASE,
        "question": "which tests cover the tenant refresh positive control and the cross-tenant refusal?",
        "inputs": [
            {"path": "crates/auth/tests/tenant.rs", "startLine": 1, "endLine": 16}
        ],
        "maxFindings": 5,
        "maxOutputTokens": 600,
        "endpoint": server.endpoint
        if server
        else "http://127.0.0.1:1/v1/chat/completions",
        "deadlineSeconds": 5,
    }
    packet.update(overrides)
    path = tmp_path / f"{packet['taskId']}.packet.json"
    path.write_text(json.dumps(packet))
    return path


def run(tmp_path, packet_path, state_dir, name="result.json", extra_args=()):
    output = tmp_path / name
    code = main(
        [
            "--packet",
            str(packet_path),
            "--output",
            str(output),
            "--state-dir",
            str(state_dir),
            *extra_args,
        ]
    )
    result = json.loads(output.read_text()) if output.exists() else None
    return code, result, output


GOOD_FINDINGS = {
    "findings": [
        {
            "claim": "refresh_within_the_tenant_succeeds is the positive control: same-tenant exchange succeeds",
            "path": "crates/auth/tests/tenant.rs",
            "startLine": 4,
            "endLine": 7,
            "evidence": 'assert!(exchange(&token, "tenant-a").is_ok());',
        },
        {
            "claim": "refresh_across_tenants_is_refused covers the cross-tenant refusal and the token staying valid",
            "path": "crates/auth/tests/tenant.rs",
            "startLine": 10,
            "endLine": 15,
            "evidence": 'assert_eq!(err.code, "INVALID_REFRESH_TOKEN");\n    assert!(still_valid(&token));',
        },
    ],
    "unknowns": ["no test checks the audit log entry"],
}


def test_find_test_candidates_returns_validated_findings(
    tmp_path, server, repo, state_dir, capsys
):
    server.replies.append(GOOD_FINDINGS)
    packet = write_packet(tmp_path, server, repo)
    code, result, output = run(tmp_path, packet, state_dir)
    assert code == 0
    assert result["finishStatus"] == "ok"
    assert result["taskId"] == "LOCAL-TEST-001"
    assert result["kind"] == "find-test-candidates"
    assert result["baseCommit"] == BASE
    assert [f["startLine"] for f in result["findings"]] == [4, 10]
    assert all(f["evidenceVerified"] for f in result["findings"])
    assert result["unknowns"] == ["no test checks the audit log entry"]
    assert result["runtime"]["modelId"] == "fireemu-local-Q4_K_M.gguf"
    assert result["runtime"]["quant"] == "Q4_K_M"
    assert result["usage"]["promptTokens"] > 0
    assert result["usage"]["completionTokens"] > 0
    assert result["usage"]["timings"]["predicted_per_second"] == 50.0
    assert result["elapsedSeconds"] >= 0
    assert result["cache"] == {"hit": False, "key": result["cache"]["key"]}
    [hashes] = result["inputHashes"]
    assert hashes["path"] == "crates/auth/tests/tenant.rs"
    assert (hashes["startLine"], hashes["endLine"], hashes["requestedEndLine"]) == (
        1,
        15,
        16,
    )
    assert len(hashes["rangeSha256"]) == 64
    assert result["repairAttempted"] is False
    # The request went to the server once, with a JSON schema response format.
    [post] = server.posts()
    assert post["body"]["response_format"]["type"] == "json_schema"
    assert post["body"]["max_tokens"] == 600
    assert post["body"]["stream"] is False
    assert post["body"]["enable_thinking"] is False
    assert post["body"]["chat_template_kwargs"] == {"enable_thinking": False}
    # No alias pinned: the identity was read from the server, not verified.
    assert result["runtimeIdentityVerified"] is False
    assert result["runtime"]["meta"]["props"]["model_alias"] == server.model_id
    assert (
        "     4| fn refresh_within_the_tenant_succeeds() {"
        in post["body"]["messages"][1]["content"]
    )
    # stdout is a short summary, never the claims.
    out = capsys.readouterr().out
    assert "finishStatus=ok findings=2 unknowns=1" in out
    assert "crates/auth/tests/tenant.rs:4-7" in out
    assert "positive control" not in out
    assert str(output) in out
    assert oct(output.stat().st_mode & 0o777) == "0o600"


def test_classify_log_runs_over_a_parser_excerpt(tmp_path, server, repo, state_dir):
    fixture = Path(__file__).parent / "fixtures" / "nextest-excerpt.log"
    private = tmp_path / "private"
    private.mkdir()
    code = main(
        [
            "parse-log",
            "--input",
            str(fixture),
            "--output",
            str(private / "failures.json"),
            "--excerpt",
            str(private / "failures.txt"),
        ]
    )
    assert code == 0
    parsed = json.loads((private / "failures.json").read_text())
    assert parsed["summary"]["failed"] == 8
    excerpt_lines = (private / "failures.txt").read_text().count("\n")
    server.replies.append(
        {
            "findings": [
                {
                    "claim": "doctor_names_the_binary...: the functions runner artifact is missing from the build dir",
                    "category": "environment",
                    "path": "failures.txt",
                    "startLine": 4,
                    "endLine": 8,
                    "evidence": "location: crates/fireemu/tests/doctor.rs:98:5",
                }
            ],
            "unknowns": [
                "a_dotenv_file_the_official_parser_refuses... has no captured message"
            ],
        }
    )
    packet = write_packet(
        tmp_path,
        server,
        repo,
        taskId="LOCAL-LOG-001",
        kind="classify-log",
        repoRoot=str(private),
        question="group the failures by likely cause",
        inputs=[{"path": "failures.txt", "startLine": 1, "endLine": excerpt_lines}],
    )
    code, result, _ = run(tmp_path, packet, state_dir)
    assert code == 0
    assert result["finishStatus"] == "ok"
    assert result["findings"][0]["category"] == "environment"
    assert result["findings"][0]["evidenceVerified"] is True
    [post] = server.posts()
    schema = post["body"]["response_format"]["json_schema"]["schema"]
    assert "category" in schema["properties"]["findings"]["items"]["required"]


def test_propose_tests_requires_positive_control_and_refusal_post_state(
    tmp_path, server, repo, state_dir
):
    server.replies.append(
        {
            "findings": [
                {
                    "claim": "cross_tenant_refresh_is_refused_and_keeps_the_token: exchanging under tenant B fails",
                    "path": "spec/tenant-refresh.md",
                    "startLine": 3,
                    "endLine": 5,
                    "evidence": "Exchanging it while naming tenant B MUST fail with INVALID_REFRESH_TOKEN",
                    "positiveControl": "the same token exchanged under tenant A returns a new id token",
                    "refusalPostState": "INVALID_REFRESH_TOKEN; the original refresh token still exchanges under tenant A",
                }
            ],
            "unknowns": [],
        }
    )
    packet = write_packet(
        tmp_path,
        server,
        repo,
        taskId="LOCAL-PROPOSE-001",
        kind="propose-tests",
        question="propose tests for tenant refresh",
        inputs=[{"path": "spec/tenant-refresh.md", "startLine": 1, "endLine": 5}],
    )
    code, result, _ = run(tmp_path, packet, state_dir)
    assert code == 0
    finding = result["findings"][0]
    assert finding["positiveControl"].startswith("the same token")
    assert finding["refusalPostState"].startswith("INVALID_REFRESH_TOKEN")
    assert (finding["path"], finding["startLine"], finding["endLine"]) == (
        "spec/tenant-refresh.md",
        3,
        5,
    )
    assert finding["evidenceVerified"] is True


def test_a_finding_outside_the_packet_inputs_is_dropped_into_unknowns(
    tmp_path, server, repo, state_dir
):
    server.replies.append(
        {
            "findings": [
                GOOD_FINDINGS["findings"][0],
                {**GOOD_FINDINGS["findings"][1], "path": "crates/auth/src/lib.rs"},
                {**GOOD_FINDINGS["findings"][1], "startLine": 10, "endLine": 40},
                {
                    **GOOD_FINDINGS["findings"][1],
                    "evidence": "this line is not in the file",
                },
            ],
            "unknowns": [],
        }
    )
    packet = write_packet(tmp_path, server, repo)
    code, result, _ = run(tmp_path, packet, state_dir)
    assert code == 0
    assert [f["startLine"] for f in result["findings"]] == [4, 10]
    assert result["findings"][1]["evidenceVerified"] is False
    assert result["unknowns"] == [
        "dropped finding citing crates/auth/src/lib.rs:10-15: not inside any packet input",
        "dropped finding citing crates/auth/tests/tenant.rs:10-40: not inside any packet input",
    ]


def test_schema_invalid_output_gets_one_repair_then_fails(
    tmp_path, server, repo, state_dir, capsys
):
    server.replies.append("this is not json")
    server.replies.append({"findings": [{"claim": "x"}], "unknowns": []})
    packet = write_packet(tmp_path, server, repo)
    code, result, _ = run(tmp_path, packet, state_dir)
    assert code == 5
    assert result["finishStatus"] == "schema-invalid"
    assert result["repairAttempted"] is True
    assert "missing" in result["reason"]
    assert result["findings"] == []
    posts = server.posts()
    assert len(posts) == 2
    repair = posts[1]["body"]["messages"]
    assert repair[-2]["role"] == "assistant"
    assert repair[-1]["role"] == "user"
    assert "did not match the required schema" in repair[-1]["content"]
    err = capsys.readouterr().err
    assert "status=schema-invalid" in err
    assert "this is not json" not in err
    # Nothing was cached.
    assert not (state_dir / "cache").exists() or not list(
        (state_dir / "cache").iterdir()
    )


def test_a_repaired_reply_is_accepted(tmp_path, server, repo, state_dir):
    server.replies.append('```json\n{"findings": []}\n```')
    server.replies.append(GOOD_FINDINGS)
    packet = write_packet(tmp_path, server, repo)
    code, result, _ = run(tmp_path, packet, state_dir)
    assert code == 0
    assert result["repairAttempted"] is True
    assert len(result["findings"]) == 2
    assert result["usage"]["completionTokens"] > 0


def test_truncated_output_is_schema_invalid_without_repair(
    tmp_path, server, repo, state_dir
):
    server.replies.append('__length__{"findings": [')
    packet = write_packet(tmp_path, server, repo)
    code, result, _ = run(tmp_path, packet, state_dir)
    assert code == 5
    assert "finish_reason=length" in result["reason"]
    assert len(server.posts()) == 1


def test_a_zero_byte_timeout_keeps_the_lock_state_and_the_partial_record(
    tmp_path, server, repo, state_dir, capsys
):
    # The server accepts the request and sends nothing before the deadline.
    server.replies.append({"__raw__": {"delay": 3, "body": b"{}"}})
    packet = write_packet(tmp_path, server, repo, deadlineSeconds=0.5)
    code, result, _ = run(tmp_path, packet, state_dir)
    assert code == 4
    assert result["finishStatus"] == "timeout"
    assert result["findings"] == []
    assert result["serverStateUnknown"] is True
    assert result["inflightMarker"] == str(state_dir / "inflight.json")
    assert "--reset-lock" in result["reason"]
    assert len(server.posts()) == 1
    marker = json.loads((state_dir / "inflight.json").read_text())
    assert marker["taskId"] == "LOCAL-TEST-001"
    assert marker["endpoint"] == server.endpoint
    assert marker["pid"] == os.getpid()
    assert oct((state_dir / "inflight.json").stat().st_mode & 0o777) == "0o600"
    # The flock itself is free again: only the marker says "unknown".
    holder = open(state_dir / "inference.lock", "a+")  # noqa: SIM115
    fcntl.flock(holder.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    fcntl.flock(holder.fileno(), fcntl.LOCK_UN)
    holder.close()
    assert "--reset-lock" in capsys.readouterr().err


def test_after_an_unanswered_request_every_run_is_refused_until_reset(
    tmp_path, server, repo, state_dir, capsys
):
    server.replies.append({"__raw__": {"delay": 3, "body": b"{}"}})
    packet = write_packet(tmp_path, server, repo, deadlineSeconds=0.5)
    code, _, _ = run(tmp_path, packet, state_dir, name="first.json")
    assert code == 4
    requests_before = len(server.requests)
    server.replies.append(GOOD_FINDINGS)
    code, result, _ = run(tmp_path, packet, state_dir, name="second.json")
    assert code == 8
    assert result["finishStatus"] == "server-state-unknown"
    assert result["serverStateUnknown"] is True
    assert result["inflight"]["taskId"] == "LOCAL-TEST-001"
    assert "LOCAL-TEST-001" in result["reason"]
    assert result["findings"] == []
    # Not even the model probe went out: the server may still be generating.
    assert len(server.requests) == requests_before
    assert (state_dir / "inflight.json").exists()
    # The reset is an explicit operator step with the same state dir.
    assert main(["--reset-lock", "--state-dir", str(state_dir)]) == 0
    out = capsys.readouterr().out
    assert "removed marker for LOCAL-TEST-001" in out
    assert "did not check the server" in out
    assert not (state_dir / "inflight.json").exists()
    code, result, _ = run(tmp_path, packet, state_dir, name="third.json")
    assert code == 0
    assert result["finishStatus"] == "ok"
    assert not (state_dir / "inflight.json").exists()


def test_reset_lock_refuses_while_a_run_holds_the_lock(tmp_path, state_dir, capsys):
    state_dir.mkdir()
    (state_dir / "inflight.json").write_text('{"taskId": "X"}')
    holder = open(state_dir / "inference.lock", "a+")  # noqa: SIM115
    fcntl.flock(holder.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        assert main(["reset-lock", "--state-dir", str(state_dir)]) == 3
    finally:
        fcntl.flock(holder.fileno(), fcntl.LOCK_UN)
        holder.close()
    assert "status=busy" in capsys.readouterr().err
    assert (state_dir / "inflight.json").exists()
    assert main(["reset-lock", "--state-dir", str(state_dir)]) == 0
    assert main(["reset-lock", "--state-dir", str(state_dir)]) == 0
    assert "nothing to do" in capsys.readouterr().out


def test_reset_lock_takes_the_state_dir_from_the_config(tmp_path, state_dir):
    state_dir.mkdir()
    (state_dir / "inflight.json").write_text("{")  # torn marker
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"stateDir": str(state_dir)}))
    assert main(["--reset-lock", "--config", str(config)]) == 0
    assert not (state_dir / "inflight.json").exists()


def test_an_unreadable_marker_is_still_an_unknown_server_state(
    tmp_path, server, repo, state_dir
):
    state_dir.mkdir()
    (state_dir / "inflight.json").write_text("{not json")
    server.replies.append(GOOD_FINDINGS)
    packet = write_packet(tmp_path, server, repo)
    code, result, _ = run(tmp_path, packet, state_dir)
    assert code == 8
    assert result["inflight"] == {"unreadable": True}
    assert server.requests == []


def test_a_complete_error_response_clears_the_marker(tmp_path, server, repo, state_dir):
    server.replies.append({"__raw__": {"status": 500, "body": b"{}"}})
    packet = write_packet(tmp_path, server, repo)
    code, result, _ = run(tmp_path, packet, state_dir)
    assert code == 6
    assert "serverStateUnknown" not in result
    assert not (state_dir / "inflight.json").exists()


def test_a_refused_connection_leaves_no_marker(tmp_path, repo, state_dir):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"modelId": "pinned.gguf"}))
    packet = write_packet(tmp_path, None, repo)
    code, result, _ = run(
        tmp_path, packet, state_dir, extra_args=("--config", str(config))
    )
    assert code == 6
    assert result["reason"].startswith("connection failed")
    assert "serverStateUnknown" not in result
    assert not (state_dir / "inflight.json").exists()


def test_server_errors_are_reported_by_status_only(
    tmp_path, server, repo, state_dir, capsys
):
    server.replies.append(
        {"__raw__": {"status": 500, "body": b'{"error": "secret prompt echo"}'}}
    )
    packet = write_packet(tmp_path, server, repo)
    code, result, _ = run(tmp_path, packet, state_dir)
    assert code == 6
    assert result["finishStatus"] == "server-error"
    assert result["reason"] == "HTTP 500"
    assert "secret prompt echo" not in capsys.readouterr().err


def test_a_redirect_is_refused(tmp_path, server, repo, state_dir):
    server.replies.append(
        {
            "__raw__": {
                "status": 302,
                "body": b"",
                "headers": {"Location": "http://example.com/steal"},
            }
        }
    )
    packet = write_packet(tmp_path, server, repo)
    code, result, _ = run(tmp_path, packet, state_dir)
    assert code == 6
    assert "redirect refused" in result["reason"]
    assert len(server.posts()) == 1


def test_a_second_concurrent_run_is_busy(tmp_path, server, repo, state_dir):
    (state_dir).mkdir()
    holder = open(state_dir / "inference.lock", "a+")  # noqa: SIM115
    fcntl.flock(holder.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        server.replies.append(GOOD_FINDINGS)
        packet = write_packet(tmp_path, server, repo)
        code, result, _ = run(tmp_path, packet, state_dir)
    finally:
        fcntl.flock(holder.fileno(), fcntl.LOCK_UN)
        holder.close()
    assert code == 3
    assert result["finishStatus"] == "busy"
    assert server.posts() == []


def test_over_budget_input_returns_needs_narrower_input_without_a_request(
    tmp_path, server, repo, state_dir
):
    big = repo / "crates" / "auth" / "tests" / "big.rs"
    big.write_text("\n".join("x" * 120 for _ in range(500)) + "\n")
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"contextTokens": 4096}))
    packet = write_packet(
        tmp_path,
        server,
        repo,
        inputs=[{"path": "crates/auth/tests/big.rs", "startLine": 1, "endLine": 500}],
        maxOutputTokens=1500,
    )
    code, result, _ = run(
        tmp_path, packet, state_dir, extra_args=("--config", str(config))
    )
    assert code == 2
    assert result["finishStatus"] == "needs-narrower-input"
    assert (
        result["budget"]["estimatedPromptTokens"]
        > result["budget"]["availablePromptTokens"]
    )
    assert result["inputHashes"][0]["rangeBytes"] == 500 * 121 - 1
    assert server.requests == []


def test_an_existing_output_file_is_refused_before_anything_runs(
    tmp_path, server, repo, state_dir, capsys
):
    existing = tmp_path / "taken.json"
    existing.write_text("{}")
    packet = write_packet(tmp_path, server, repo)
    code = main(
        [
            "--packet",
            str(packet),
            "--output",
            str(existing),
            "--state-dir",
            str(state_dir),
        ]
    )
    assert code == 1
    assert existing.read_text() == "{}"
    assert "already exists" in capsys.readouterr().err
    assert server.requests == []


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://example.com/v1/chat/completions",
        "http://10.0.0.1:8011/v1/chat/completions",
    ],
)
def test_a_non_loopback_endpoint_is_refused(
    tmp_path, server, repo, state_dir, endpoint, capsys
):
    packet = write_packet(tmp_path, server, repo, endpoint=endpoint)
    code, result, _ = run(tmp_path, packet, state_dir)
    assert code == 1
    assert result is None
    assert "not loopback" in capsys.readouterr().err


def test_proxy_environment_is_ignored(tmp_path, server, repo, state_dir, monkeypatch):
    # A proxy on a closed port would break the request if it were honored.
    for key in (
        "http_proxy",
        "HTTP_PROXY",
        "https_proxy",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "all_proxy",
    ):
        monkeypatch.setenv(key, "http://127.0.0.1:1")
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.delenv("NO_PROXY", raising=False)
    server.replies.append(GOOD_FINDINGS)
    packet = write_packet(tmp_path, server, repo)
    code, result, _ = run(tmp_path, packet, state_dir)
    assert code == 0
    assert result["finishStatus"] == "ok"
    assert len(server.posts()) == 1


@pytest.mark.parametrize(
    "path",
    ["../outside.rs", ".env", "crates/auth/tests/link.rs", "crates/auth/tests/blob.rs"],
)
def test_unsafe_inputs_are_refused_before_any_request(
    tmp_path, server, repo, state_dir, path, capsys
):
    (tmp_path / "outside.rs").write_text("fn x() {}\n")
    (repo / ".env").write_text("X=1\n")
    os.symlink(tmp_path / "outside.rs", repo / "crates" / "auth" / "tests" / "link.rs")
    (repo / "crates" / "auth" / "tests" / "blob.rs").write_bytes(b"\x00\x01")
    packet = write_packet(
        tmp_path, server, repo, inputs=[{"path": path, "startLine": 1, "endLine": 5}]
    )
    code, result, _ = run(tmp_path, packet, state_dir)
    assert code == 1
    assert result is None
    assert "refused" in capsys.readouterr().err
    assert server.requests == []


def test_a_cached_result_is_reused_only_for_the_exact_key(
    tmp_path, server, repo, state_dir
):
    server.replies.append(GOOD_FINDINGS)
    packet = write_packet(tmp_path, server, repo)
    code, first, _ = run(tmp_path, packet, state_dir, name="first.json")
    assert code == 0 and first["cache"]["hit"] is False
    code, second, _ = run(tmp_path, packet, state_dir, name="second.json")
    assert code == 0
    assert second["cache"]["hit"] is True
    assert second["cache"]["key"] == first["cache"]["key"]
    assert second["findings"] == first["findings"]
    assert second["usage"] == first["usage"]
    assert len(server.posts()) == 1
    # Editing one selected byte changes the key and forces a fresh inference.
    target = repo / "crates" / "auth" / "tests" / "tenant.rs"
    target.write_text(target.read_text().replace("tenant-b", "tenant-c"))
    server.replies.append(GOOD_FINDINGS)
    code, third, _ = run(tmp_path, packet, state_dir, name="third.json")
    assert code == 0
    assert third["cache"]["hit"] is False
    assert third["cache"]["key"] != first["cache"]["key"]
    assert len(server.posts()) == 2
    # A different model identity also misses.
    server.model_id = "other-model-Q8_0.gguf"
    server.replies.append(GOOD_FINDINGS)
    code, fourth, _ = run(tmp_path, packet, state_dir, name="fourth.json")
    assert fourth["cache"]["hit"] is False
    assert len(server.posts()) == 3


def test_prompt_mode_config_sends_the_schema_in_the_prompt(
    tmp_path, server, repo, state_dir
):
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps({"responseFormat": "prompt", "alias": "fireemu-local"})
    )
    server.model_id = "fireemu-local"
    server.replies.append(GOOD_FINDINGS)
    packet = write_packet(tmp_path, server, repo)
    code, result, _ = run(
        tmp_path, packet, state_dir, extra_args=("--config", str(config))
    )
    assert code == 0
    [post] = server.posts()
    assert "response_format" not in post["body"]
    assert post["body"]["model"] == "fireemu-local"
    assert "JSON schema" in post["body"]["messages"][-1]["content"]
    assert result["runtime"]["alias"] == "fireemu-local"


def test_a_pinned_model_id_skips_the_probe(tmp_path, server, repo, state_dir):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"modelId": server.model_id, "quant": "Q4_K_M"}))
    server.replies.append(GOOD_FINDINGS)
    packet = write_packet(tmp_path, server, repo)
    code, result, _ = run(
        tmp_path, packet, state_dir, extra_args=("--config", str(config))
    )
    assert code == 0
    assert result["runtime"] == {
        "endpoint": server.endpoint,
        "alias": None,
        "modelId": server.model_id,
        "quant": "Q4_K_M",
    }
    # Pinning skips the probe, so nothing was verified against the server.
    assert result["runtimeIdentityVerified"] is False
    assert [r["method"] for r in server.requests] == ["POST"]


def test_a_completion_from_another_model_than_pinned_is_refused(
    tmp_path, server, repo, state_dir, capsys
):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"modelId": "pinned.gguf"}))
    server.replies.append(GOOD_FINDINGS)
    packet = write_packet(tmp_path, server, repo)
    code, result, _ = run(
        tmp_path, packet, state_dir, extra_args=("--config", str(config))
    )
    assert code == 7
    assert result["finishStatus"] == "runtime-mismatch"
    assert result["reason"] == (
        "completion reports model 'fireemu-local-Q4_K_M.gguf', expected 'pinned.gguf'"
    )
    assert result["findings"] == []
    assert result["runtime"]["modelReportedByCompletion"] == "fireemu-local-Q4_K_M.gguf"
    assert len(server.posts()) == 1
    assert "status=runtime-mismatch" in capsys.readouterr().err
    # A refused reply is never cached.
    assert not (state_dir / "cache").exists()


def _alias_config(tmp_path, **extra) -> str:
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"alias": "fireemu-local", **extra}))
    return str(config)


def test_a_pinned_alias_is_verified_against_models_and_props(
    tmp_path, server, repo, state_dir
):
    server.model_id = "fireemu-local"
    server.replies.append(GOOD_FINDINGS)
    packet = write_packet(tmp_path, server, repo)
    code, result, _ = run(
        tmp_path, packet, state_dir, extra_args=("--config", _alias_config(tmp_path))
    )
    assert code == 0
    assert result["runtimeIdentityVerified"] is True
    assert result["runtime"]["alias"] == "fireemu-local"
    assert result["runtime"]["modelId"] == "fireemu-local"
    assert result["runtime"]["quant"] == "Q4_K_M"  # from /props model_ftype
    assert result["runtime"]["meta"]["props"]["n_ctx"] == 16384
    assert [r["path"] for r in server.requests] == [
        "/v1/models",
        "/props",
        "/v1/chat/completions",
    ]
    [post] = server.posts()
    assert post["body"]["model"] == "fireemu-local"


def test_a_pinned_alias_is_verified_when_the_server_has_no_props(
    tmp_path, server, repo, state_dir
):
    server.model_id = "fireemu-local"
    server.props = None
    server.replies.append(GOOD_FINDINGS)
    packet = write_packet(tmp_path, server, repo)
    code, result, _ = run(
        tmp_path, packet, state_dir, extra_args=("--config", _alias_config(tmp_path))
    )
    assert code == 0
    assert result["runtimeIdentityVerified"] is True
    assert result["runtime"]["quant"] is None
    assert "props" not in result["runtime"].get("meta", {})


def test_a_models_alias_mismatch_sends_nothing_to_the_model(
    tmp_path, server, repo, state_dir, capsys
):
    # The fake serves fireemu-local-Q4_K_M.gguf; the config pins fireemu-local.
    server.replies.append(GOOD_FINDINGS)
    packet = write_packet(tmp_path, server, repo)
    code, result, _ = run(
        tmp_path, packet, state_dir, extra_args=("--config", _alias_config(tmp_path))
    )
    assert code == 7
    assert result["finishStatus"] == "runtime-mismatch"
    assert result["runtimeIdentityVerified"] is False
    assert result["runtime"] is None
    assert "config alias is 'fireemu-local'" in result["reason"]
    assert server.posts() == []
    assert "status=runtime-mismatch" in capsys.readouterr().err


def test_a_props_alias_mismatch_sends_nothing_to_the_model(
    tmp_path, server, repo, state_dir
):
    server.model_id = "fireemu-local"
    server.props["model_alias"] = "swapped-model"
    server.replies.append(GOOD_FINDINGS)
    packet = write_packet(tmp_path, server, repo)
    code, result, _ = run(
        tmp_path, packet, state_dir, extra_args=("--config", _alias_config(tmp_path))
    )
    assert code == 7
    assert "swapped-model" in result["reason"]
    assert server.posts() == []


def test_a_completion_naming_another_model_than_the_alias_is_refused(
    tmp_path, server, repo, state_dir
):
    server.model_id = "fireemu-local"
    server.reply_model = "fireemu-local-b"
    server.replies.append(GOOD_FINDINGS)
    packet = write_packet(tmp_path, server, repo)
    code, result, _ = run(
        tmp_path, packet, state_dir, extra_args=("--config", _alias_config(tmp_path))
    )
    assert code == 7
    assert result["finishStatus"] == "runtime-mismatch"
    assert result["runtimeIdentityVerified"] is True  # the probe did match
    assert result["runtime"]["modelReportedByCompletion"] == "fireemu-local-b"
    assert result["findings"] == []
    assert len(server.posts()) == 1


def test_an_explicitly_truncated_reply_is_needs_narrower_input(
    tmp_path, server, repo, state_dir
):
    server.reply_extra = {"truncated": True}
    server.replies.append(GOOD_FINDINGS)
    packet = write_packet(tmp_path, server, repo)
    code, result, _ = run(tmp_path, packet, state_dir)
    assert code == 2
    assert result["finishStatus"] == "needs-narrower-input"
    assert "truncated: true" in result["reason"]
    assert result["findings"] == []
    assert len(server.posts()) == 1
    assert not (state_dir / "cache").exists()


def test_dry_run_prepares_the_request_without_contacting_anything(
    tmp_path, server, repo, state_dir, capsys
):
    packet = write_packet(tmp_path, server, repo)
    code, result, output = run(
        tmp_path,
        packet,
        state_dir,
        extra_args=("--config", _alias_config(tmp_path), "--dry-run"),
    )
    assert code == 0
    assert result["finishStatus"] == "dry-run"
    assert result["reason"] == "prepared, not sent"
    assert server.requests == []
    assert not state_dir.exists()
    assert result["cache"] == {"hit": False, "key": None}
    assert result["runtimeIdentityVerified"] is False
    assert result["runtime"]["alias"] == "fireemu-local"
    assert result["budget"]["estimatedPromptTokens"] > 0
    [hashes] = result["inputHashes"]
    assert len(hashes["rangeSha256"]) == 64
    request = result["request"]
    assert request["endpoint"] == server.endpoint
    assert request["model"] == "fireemu-local"
    assert request["responseFormat"] == "json_schema"
    assert request["enableThinking"] is False
    assert request["maxTokens"] == 600
    assert [m["role"] for m in request["messages"]] == ["system", "user"]
    assert request["bodyBytes"] > 0 and len(request["bodySha256"]) == 64
    # Neither the excerpt nor the question text reaches the result or stdout.
    text = output.read_text()
    out = capsys.readouterr().out
    assert "refresh_within_the_tenant_succeeds" not in text
    assert "refresh_within_the_tenant_succeeds" not in out
    assert "finishStatus=dry-run" in out
    assert oct(output.stat().st_mode & 0o777) == "0o600"


def test_dry_run_still_refuses_over_budget_input(tmp_path, server, repo, state_dir):
    big = repo / "crates" / "auth" / "tests" / "big.rs"
    big.write_text("\n".join("x" * 120 for _ in range(500)) + "\n")
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"contextTokens": 2048}))
    packet = write_packet(
        tmp_path,
        server,
        repo,
        inputs=[{"path": "crates/auth/tests/big.rs", "startLine": 1, "endLine": 500}],
    )
    code, result, _ = run(
        tmp_path, packet, state_dir, extra_args=("--config", str(config), "--dry-run")
    )
    assert code == 2
    assert result["finishStatus"] == "needs-narrower-input"
    assert "request" not in result
    assert server.requests == []


def test_an_unreachable_server_is_a_server_error(tmp_path, repo, state_dir):
    packet = write_packet(tmp_path, None, repo)
    code, result, _ = run(tmp_path, packet, state_dir)
    assert code == 6
    assert result["finishStatus"] == "server-error"
    assert result["reason"].startswith("model probe failed")


def test_parse_log_refuses_to_overwrite_and_reports_counts(tmp_path, capsys):
    fixture = Path(__file__).parent / "fixtures" / "pytest-excerpt.log"
    output = tmp_path / "out.json"
    assert main(["parse-log", "--input", str(fixture), "--output", str(output)]) == 0
    assert (
        "pytest: run=6070 passed=6048 failed=2 skipped=20 failureBlocks=2"
        in capsys.readouterr().out
    )
    assert main(["parse-log", "--input", str(fixture), "--output", str(output)]) == 1
    assert "already exists" in capsys.readouterr().err


def test_a_trickling_server_cannot_hold_the_request_past_the_deadline(
    tmp_path, server, repo, state_dir
):
    import time

    body = json.dumps({"choices": [{"message": {"content": "{}"}}]}).encode()
    server.replies.append({"__raw__": {"trickle": {"body": body, "interval": 0.2}}})
    packet = write_packet(tmp_path, server, repo, deadlineSeconds=1)
    started = time.monotonic()
    code, result, _ = run(tmp_path, packet, state_dir)
    elapsed = time.monotonic() - started
    assert code == 4
    assert result["finishStatus"] == "timeout"
    assert elapsed < 3.0, elapsed
    assert len(server.posts()) == 1
    # Bytes did arrive, but no complete answer: the slot stays quarantined.
    assert result["serverStateUnknown"] is True
    assert (state_dir / "inflight.json").exists()
    # The abandoned connection is closed, so the server sees a broken pipe.
    deadline = time.monotonic() + 5
    while server.abandoned == 0 and time.monotonic() < deadline:
        time.sleep(0.05)
    assert server.abandoned == 1


def test_an_output_that_appears_mid_run_is_reported_not_raised(
    tmp_path, server, repo, state_dir, capsys, monkeypatch
):
    import main as main_module

    server.replies.append(GOOD_FINDINGS)
    packet = write_packet(tmp_path, server, repo)
    output = tmp_path / "late.json"
    original = main_module.write_new_file

    def racing_write(path, payload):
        path.write_text("{}")
        return original(path, payload)

    monkeypatch.setattr(main_module, "write_new_file", racing_write)
    code = main(
        [
            "--packet",
            str(packet),
            "--output",
            str(output),
            "--state-dir",
            str(state_dir),
        ]
    )
    assert code == 1
    assert output.read_text() == "{}"
    assert "result not written" in capsys.readouterr().err


def test_the_cache_key_separates_response_formats(tmp_path, server, repo, state_dir):
    server.replies.append(GOOD_FINDINGS)
    packet = write_packet(tmp_path, server, repo)
    code, first, _ = run(tmp_path, packet, state_dir, name="schema.json")
    assert code == 0 and first["cache"]["hit"] is False
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"responseFormat": "prompt"}))
    server.replies.append(GOOD_FINDINGS)
    code, second, _ = run(
        tmp_path,
        packet,
        state_dir,
        name="prompt.json",
        extra_args=("--config", str(config)),
    )
    assert code == 0
    assert second["cache"]["hit"] is False
    assert second["cache"]["key"] != first["cache"]["key"]
    assert len(server.posts()) == 2


def test_a_key_protected_server_needs_the_configured_key_file(
    tmp_path, repo, state_dir, capsys
):
    protected = FakeLlamaServer(api_key="local-secret-key-123").start()
    try:
        packet = write_packet(tmp_path, protected, repo)
        code, result, _ = run(tmp_path, packet, state_dir, name="nokey.json")
        assert code == 6
        assert (
            result["reason"]
            == "model probe failed: server refused the credential (HTTP 401)"
        )
        key_file = tmp_path / "api-key.txt"
        key_file.write_text("local-secret-key-123\n")
        config = tmp_path / "config.json"
        config.write_text(json.dumps({"apiKeyFile": str(key_file)}))
        # A key file other users can read is refused before any request.
        key_file.chmod(0o644)
        code, result, _ = run(
            tmp_path,
            packet,
            state_dir,
            name="loosekey.json",
            extra_args=("--config", str(config)),
        )
        assert code == 1 and result is None
        assert "readable by group or others" in capsys.readouterr().err
        key_file.chmod(0o600)
        # So is a symlink, whatever the target's mode.
        link = tmp_path / "api-key.link"
        link.symlink_to(key_file)
        config.write_text(json.dumps({"apiKeyFile": str(link)}))
        code, result, _ = run(
            tmp_path,
            packet,
            state_dir,
            name="linkkey.json",
            extra_args=("--config", str(config)),
        )
        assert code == 1 and result is None
        assert "must not be a symlink" in capsys.readouterr().err
        config.write_text(json.dumps({"apiKeyFile": str(key_file)}))
        requests_before = len(protected.requests)
        protected.replies.append(GOOD_FINDINGS)
        code, result, output = run(
            tmp_path,
            packet,
            state_dir,
            name="withkey.json",
            extra_args=("--config", str(config)),
        )
        assert code == 0
        assert len(result["findings"]) == 2
        # The two refusals sent nothing: only the successful run's requests.
        assert len(protected.requests) - requests_before == 3
        captured = capsys.readouterr()
        assert "local-secret-key-123" not in captured.out + captured.err
        assert "local-secret-key-123" not in output.read_text()
    finally:
        protected.stop()


def test_an_unusable_key_file_is_a_config_error(
    tmp_path, server, repo, state_dir, capsys
):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"apiKeyFile": str(tmp_path / "missing.txt")}))
    packet = write_packet(tmp_path, server, repo)
    code, result, _ = run(
        tmp_path, packet, state_dir, extra_args=("--config", str(config))
    )
    assert code == 1 and result is None
    assert "apiKeyFile" in capsys.readouterr().err
    assert server.requests == []
