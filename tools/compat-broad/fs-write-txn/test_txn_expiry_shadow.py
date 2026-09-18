"""The local shadow refuses to launch or to signal anything it does not own."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parents[1]))

import txn_expiry_shadow as shadow


def test_configuration_is_strict_and_pins_the_clock():
    assert shadow.CONFIG["profile"] == "strict"
    assert shadow.CONFIG["daemon"]["clockStart"]


def test_missing_artifact_does_not_create_the_output_directory(tmp_path):
    with pytest.raises((ValueError, FileNotFoundError)):
        shadow.run_shadow(tmp_path / "missing", tmp_path / "output")
    assert not (tmp_path / "output").exists()


def test_cli_exposes_the_expected_entry_points():
    result = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).with_name("txn_expiry_shadow.py")),
            "--help",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    for flag in ("--artifact", "--output", "--child", "--nonce", "--owner"):
        assert flag in result.stdout


def test_stop_refuses_to_signal_a_process_it_did_not_start():
    class Foreign:
        pid = 1

        def poll(self):
            return None

    with pytest.raises(RuntimeError):
        shadow.stop_child(Foreign(), Path("/nonexistent/fireemu-artifact"))


def test_every_declared_rest_status_maps_to_a_grpc_code():
    for status, code in shadow.STATUS_TO_CODE.items():
        assert isinstance(code, int)
        assert status.isupper()
    assert shadow.STATUS_TO_CODE["ABORTED"] == 10
    assert shadow.STATUS_TO_CODE["INVALID_ARGUMENT"] == 3


def test_transport_reports_an_oversized_response_as_incomplete(tmp_path):
    send = shadow.rest_transport("http://127.0.0.1:1")
    response = send(
        {
            "rpc": "Rollback",
            "database": "(default)",
            "projectId": "fireemu-test",
            "name": None,
            "body": {"transaction": "AA=="},
            "query": None,
            "maxResponseBytes": 16,
        }
    )
    assert response["complete"] is False


def test_an_unreachable_endpoint_is_incomplete_not_a_semantic_result():
    send = shadow.rest_transport("http://127.0.0.1:1", timeout=1)
    response = send(
        {
            "rpc": "BeginTransaction",
            "database": "(default)",
            "projectId": "fireemu-test",
            "name": None,
            "body": {"options": {"readWrite": {}}},
            "query": None,
            "maxResponseBytes": 4096,
        }
    )
    assert response["complete"] is False
    assert response["code"] is None


def test_saved_values_are_stable_json(tmp_path):
    target = tmp_path / "value.json"
    shadow.save(target, {"b": 1, "a": 2})
    assert json.loads(target.read_text()) == {"a": 2, "b": 1}
    assert target.read_text().endswith("\n")


def test_runtime_binding_names_the_commit_and_hashes_the_rust_inputs():
    root = Path(__file__).resolve().parents[3]
    binding = shadow.runtime_binding(Path(__file__), root)
    assert len(binding["sourceCommit"]) == 40
    assert len(binding["runtimeInputsDigest"]) == 64
    assert binding["runtimeInputCount"] > 0
    assert isinstance(binding["runtimeInputsClean"], bool)
    assert len(binding["artifactSha256"]) == 64


def test_runtime_binding_refuses_a_missing_artifact():
    root = Path(__file__).resolve().parents[3]
    with pytest.raises(FileNotFoundError):
        shadow.runtime_binding(Path("/nonexistent/fireemu"), root)


def synthetic_document(**overrides):
    binding = {
        "artifactSha256": "a" * 64,
        "sourceCommit": "b" * 40,
        "sourceRoot": "/somewhere",
        "runtimeInputsDigest": "c" * 64,
        "runtimeInputCount": 400,
        "runtimeInputsClean": True,
    }
    value = {
        "before": "d" * 64,
        "after": "d" * 64,
        "artifact_sha": "a" * 64,
        "binding": binding,
        "version": "fireemu 0.7.1",
        "nonce": "o3expiry-0000000000000001",
        "owner_id": "0" * 32,
        "elapsed": 1.0,
        "child": {"stopped": True, "signal": None, "exitCode": 0},
        "receipt": {
            "complete": True,
            "instance": {"wrongTokenStatus": 403, "artifactSha256": "a" * 64},
        },
        "contract": {"classification": "MATCH"},
    }
    value.update(overrides)
    return shadow.build_shadow_document(**value)


def test_the_builder_emits_the_publication_fields_itself():
    value = synthetic_document()
    assert value["productionExecuted"] is False
    assert value["note"] == shadow.PUBLICATION_NOTE
    assert value["runtime"]["version"] == "fireemu 0.7.1"
    assert value["runtime"]["wrongControlTokenStatus"] == 403
    assert value["complete"] is True


def test_the_builder_keeps_the_child_computed_artifact_proof():
    value = synthetic_document()
    assert value["runtime"]["childObservedArtifactSha256"] == "a" * 64
    assert value["receipt"]["instance"]["artifactSha256"] == "a" * 64


def test_a_child_that_ran_a_different_artifact_is_not_complete():
    value = synthetic_document(
        receipt={
            "complete": True,
            "instance": {"wrongTokenStatus": 403, "artifactSha256": "e" * 64},
        }
    )
    assert value["complete"] is False


def test_a_dirty_rust_tree_or_shifted_source_digest_is_not_complete():
    value = synthetic_document(
        binding={
            "artifactSha256": "a" * 64,
            "sourceCommit": "b" * 40,
            "sourceRoot": "/somewhere",
            "runtimeInputsDigest": "c" * 64,
            "runtimeInputCount": 400,
            "runtimeInputsClean": False,
        }
    )
    assert value["complete"] is False
    shifted = synthetic_document(after="f" * 64)
    assert shifted["complete"] is False


def test_the_transport_prefers_the_per_request_timeout_from_the_plan():
    send = shadow.rest_transport("http://127.0.0.1:1", timeout=99)
    response = send(
        {
            "rpc": "Rollback",
            "database": "(default)",
            "projectId": "fireemu-test",
            "name": None,
            "body": {"transaction": "AA=="},
            "query": None,
            "maxResponseBytes": 4096,
            "timeoutSeconds": 1,
        }
    )
    assert response["complete"] is False
