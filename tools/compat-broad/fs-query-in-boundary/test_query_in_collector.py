from __future__ import annotations

import base64
import copy
import json
import os
from pathlib import Path
from typing import Any

import pytest
from query_in_collector import _publish, collect_local
from query_in_compiler import compile_plan


def _ok(body: Any, status: int = 200) -> dict[str, Any]:
    return {"complete": True, "failure": None, "status": status, "body": body}


def _not_found() -> dict[str, Any]:
    return _ok({"error": {"code": 404, "status": "NOT_FOUND"}}, 404)


def _owned(
    plan: dict[str, Any],
    update_time: str = "2026-09-17T00:00:00.000000Z",
    create_time: str | None = None,
) -> dict[str, Any]:
    body = {
        "name": plan["document"],
        "fields": copy.deepcopy(plan["fixtureFields"]),
        "updateTime": update_time,
    }
    if create_time is not None:
        body["createTime"] = create_time
    return _ok(body)


def _transport(
    plan: dict[str, Any], *, mutate: bool = False, calls: list[str] | None = None
):
    state = {"present": False, "updateTime": "2026-09-17T00:00:00.000000Z"}

    def execute(operation: dict[str, Any]) -> dict[str, Any]:
        if calls is not None:
            calls.append(operation["kind"])
        if mutate:
            operation["executorOnly"] = True
        kind = operation["kind"]
        if kind in {"preflight-typed-absence", "cleanup-verify-absence"}:
            return _not_found() if not state["present"] else _owned(plan, state["updateTime"])
        if kind == "create-only-patch":
            state["present"] = True
            return _owned(plan, state["updateTime"])
        if kind == "cleanup-ownership-read":
            return _owned(plan, state["updateTime"]) if state["present"] else _not_found()
        if kind == "cleanup-conditional-delete":
            assert "currentDocument.updateTime=" in operation["path"]
            state["present"] = False
            return _ok({})
        if kind in {"positive-query", "diagnostic-query"}:
            return _ok({"documents": [plan["expectedPositiveDocument"]]})
        return _owned(plan, state["updateTime"])

    return execute


def _plan() -> dict[str, Any]:
    return compile_plan("fireemu-test", "(default)", "0123456789abcdef0123456789abcdef")


def test_collects_six_observations_three_recovery_and_exclusive_rows(tmp_path: Path) -> None:
    plan = _plan()
    before = copy.deepcopy(plan)
    result = collect_local(plan, _transport(plan, mutate=True), tmp_path / "receipt")

    assert result["completed"] is True
    assert result["recordingComplete"] is True
    assert result["cleanupComplete"] is True
    assert result["productionExecuted"] is False
    assert len(result["rows"]) == 6
    assert len(result["cleanup"]) == 3
    assert "executorOnly" not in result["rows"][0]["request"]
    assert plan == before
    assert sorted(p.name for p in (tmp_path / "receipt").iterdir()) == [
        "collection.json",
        "observation-00.json",
        "observation-01.json",
        "observation-02.json",
        "observation-03.json",
        "observation-04.json",
        "observation-05.json",
        "recovery-00.json",
        "recovery-01.json",
        "recovery-02.json",
    ]
    assert json.loads((tmp_path / "receipt" / "observation-04.json").read_text())["index"] == 4


def test_transport_raw_bytes_are_published_and_reloaded_for_all_nine_slots(
    tmp_path: Path,
) -> None:
    plan = _plan()
    transport = _transport(plan)

    def execute(operation: dict[str, Any]) -> dict[str, Any]:
        receipt = transport(operation)
        raw = json.dumps(receipt["body"], separators=(",", ":")).encode()
        return {
            **receipt,
            "rawBodyBase64": base64.b64encode(raw).decode("ascii"),
            "bodyBytes": len(raw),
            "contentType": "application/json; charset=UTF-8",
        }

    result = collect_local(plan, execute, tmp_path / "receipt")
    raw_dir = tmp_path / "receipt" / "raw"
    manifest = json.loads((raw_dir / "manifest.json").read_text())

    assert result["rawComplete"] is False
    assert result["completed"] is False
    assert result["rawSemanticMismatch"] is True
    assert result["rawFailures"] == []
    assert len(result["rawBindings"]) == 9
    assert len(manifest["bindings"]) == 9
    assert all({"phase", "index", "path", "sha256"} <= set(item) for item in manifest["bindings"])
    assert len(list(raw_dir.glob("*.raw"))) == 9
    assert result["rows"][2]["semanticView"]["difference"] == "unexpected-query-shape"


def test_missing_or_partial_raw_response_fails_closed_without_synthesizing_bytes(
    tmp_path: Path,
) -> None:
    plan = _plan()
    transport = _transport(plan)

    def execute(operation: dict[str, Any]) -> dict[str, Any]:
        receipt = transport(operation)
        raw = json.dumps(receipt["body"], separators=(",", ":")).encode()
        if operation["kind"] == "positive-query":
            return {**receipt, "contentType": "application/json"}
        if operation["kind"] == "diagnostic-query":
            return {
                **receipt,
                "rawBody": raw,
                "bodyBytes": len(raw) + 1,
                "contentType": "application/json",
            }
        return {
            **receipt,
            "rawBody": raw,
            "bodyBytes": len(raw),
            "contentType": "application/json",
        }

    result = collect_local(plan, execute, tmp_path / "receipt")

    assert result["rawComplete"] is False
    assert any("response-bytes-unavailable" in item for item in result["rawFailures"])
    assert not (tmp_path / "receipt" / "raw" / "observation-02.raw").exists()
    assert not (tmp_path / "receipt" / "raw" / "observation-04.raw").exists()


def test_mismatched_complete_non_query_raw_bytes_fail_closed(tmp_path: Path) -> None:
    plan = _plan()
    transport = _transport(plan)

    def execute(operation: dict[str, Any]) -> dict[str, Any]:
        receipt = transport(operation)
        if operation["kind"] == "positive-query":
            raw = json.dumps(
                [{"document": plan["expectedPositiveDocument"]}],
                separators=(",", ":"),
            ).encode()
        elif operation["kind"] == "preflight-typed-absence":
            raw = b"{}"
        else:
            raw = json.dumps(receipt["body"], separators=(",", ":")).encode()
        return {
            **receipt,
            "rawBody": raw,
            "bodyBytes": len(raw),
            "contentType": "application/json",
        }

    result = collect_local(plan, execute, tmp_path / "receipt")

    assert result["rawComplete"] is False
    assert result["rawSemanticMismatch"] is True
    assert result["rawVerifiedCompleted"] is False
    assert result["completed"] is False


def test_conflicting_raw_representations_fail_closed_across_nine_slots(tmp_path: Path) -> None:
    plan = _plan()
    transport = _transport(plan)

    def execute(operation: dict[str, Any]) -> dict[str, Any]:
        receipt = transport(operation)
        raw = json.dumps(receipt["body"], separators=(",", ":")).encode()
        result = {
            **receipt,
            "rawBody": raw,
            "rawBodyBase64": base64.b64encode(raw + b"x").decode("ascii"),
            "bodyBytes": len(raw),
            "rawBodyBytes": len(raw) + 1,
            "contentType": "application/json",
        }
        return result

    result = collect_local(plan, execute, tmp_path / "receipt")

    assert result["rawComplete"] is False
    assert result["completed"] is False
    assert result["rawBindings"] == []


@pytest.mark.parametrize("bad_field", ["rawBody", "rawBodyBase64", "bodyBytes", "rawBodyBytes"])
def test_malformed_explicit_raw_metadata_is_not_hidden_by_valid_metadata(
    tmp_path: Path, bad_field: str
) -> None:
    plan = _plan()
    transport = _transport(plan)

    def execute(operation: dict[str, Any]) -> dict[str, Any]:
        receipt = transport(operation)
        raw = json.dumps(receipt["body"], separators=(",", ":")).encode()
        result = {
            **receipt,
            "rawBody": raw,
            "rawBodyBase64": base64.b64encode(raw).decode("ascii"),
            "bodyBytes": len(raw),
            "rawBodyBytes": len(raw),
            "contentType": "application/json",
        }
        if operation["kind"] == "positive-query":
            result[bad_field] = None
        return result

    result = collect_local(plan, execute, tmp_path / "receipt")

    assert result["rawComplete"] is False
    assert result["completed"] is False
    assert len(result["rawBindings"]) == 8


def test_incomplete_raw_receipts_do_not_count_as_complete_raw_run(tmp_path: Path) -> None:
    plan = _plan()
    transport = _transport(plan)

    def execute(operation: dict[str, Any]) -> dict[str, Any]:
        receipt = transport(operation)
        raw = json.dumps(receipt["body"], separators=(",", ":")).encode()
        return {
            **receipt,
            "complete": False,
            "rawBody": raw,
            "bodyBytes": len(raw),
            "contentType": "application/json",
        }

    result = collect_local(plan, execute, tmp_path / "receipt")

    assert len(result["rawBindings"]) == 3
    assert result["rawComplete"] is False


def test_complete_namespace_mismatch_stops_before_create_and_preserves_receipt(tmp_path: Path) -> None:
    plan = _plan()

    def execute(operation: dict[str, Any]) -> dict[str, Any]:
        if operation["kind"] == "preflight-typed-absence":
            return _ok({"error": {"code": 404, "status": "NOT_FOUND", "name": "other"}}, 404)
        raise AssertionError("unsafe operation dispatched")

    result = collect_local(plan, execute, tmp_path / "receipt")

    assert len(result["rows"]) == 1
    assert result["rows"][0]["complete"] is True
    assert result["cleanup"][1]["skipped"] == "unsafe-delete"
    assert result["completed"] is False
    assert result["semanticMismatches"][0]["reason"] == "preflight-typed-absence"


def test_non_json_404_is_semantic_mismatch_and_never_proves_absence(tmp_path: Path) -> None:
    plan = _plan()

    def execute(operation: dict[str, Any]) -> dict[str, Any]:
        if operation["kind"] == "preflight-typed-absence":
            return _ok("not-json", 404)
        raise AssertionError("unsafe operation dispatched")

    result = collect_local(plan, execute, tmp_path / "receipt")

    assert result["rows"][0]["body"] == "not-json"
    assert result["resourceAbsence"][plan["document"]] is False
    assert result["cleanup"][1]["skipped"] == "unsafe-delete"


def test_cleanup_refuses_replacement_with_newer_version(tmp_path: Path) -> None:
    plan = _plan()
    seen: list[dict[str, Any]] = []

    def execute(operation: dict[str, Any]) -> dict[str, Any]:
        seen.append(copy.deepcopy(operation))
        if operation["kind"] == "preflight-typed-absence":
            return _not_found()
        if operation["kind"] == "create-only-patch":
            return _owned(plan, "2026-09-17T01:02:03.000000Z")
        if operation["kind"] == "cleanup-ownership-read":
            return _owned(plan, "2026-09-17T04:05:06.000000Z")
        if operation["kind"] == "cleanup-conditional-delete":
            raise AssertionError("replacement must not be deleted")
        if operation["kind"] == "cleanup-verify-absence":
            return _not_found()
        return _ok({"documents": []})

    result = collect_local(plan, execute, tmp_path / "receipt")
    assert not any(item["kind"] == "cleanup-conditional-delete" for item in seen)
    assert result["cleanup"][1]["skipped"] == "create-version-mismatch"
    assert result["cleanupComplete"] is False


@pytest.mark.parametrize("create_time", ["2026-09-17T02:02:03.000000Z", None])
def test_cleanup_refuses_create_time_mutation_or_missing_readback(
    tmp_path: Path, create_time: str | None
) -> None:
    plan = _plan()
    created = "2026-09-17T01:02:03.000000Z"
    seen: list[str] = []

    def execute(operation: dict[str, Any]) -> dict[str, Any]:
        seen.append(operation["kind"])
        if operation["kind"] == "preflight-typed-absence":
            return _not_found()
        if operation["kind"] == "create-only-patch":
            return _owned(plan, created, created)
        if operation["kind"] == "cleanup-ownership-read":
            return _owned(plan, created, create_time)
        if operation["kind"] == "cleanup-verify-absence":
            return _owned(plan, created, create_time)
        if operation["kind"] == "cleanup-conditional-delete":
            raise AssertionError("createTime mismatch must not authorize delete")
        return _ok({"documents": [plan["expectedPositiveDocument"]]})

    result = collect_local(plan, execute, tmp_path / "receipt")
    assert "cleanup-conditional-delete" not in seen
    assert result["cleanup"][1]["skipped"] == "create-version-mismatch"
    assert result["cleanupComplete"] is False


def test_preflight_existing_same_or_different_fields_never_creates_or_deletes(tmp_path: Path) -> None:
    plan = _plan()
    for fields in (plan["fixtureFields"], {"n": {"integerValue": "99"}}):
        calls: list[str] = []

        def execute(
            operation: dict[str, Any], fields=fields, calls=calls
        ) -> dict[str, Any]:
            calls.append(operation["kind"])
            if operation["kind"] == "preflight-typed-absence":
                return _owned(plan) if fields == plan["fixtureFields"] else _ok({"name": plan["document"], "fields": fields})
            if operation["kind"] == "cleanup-ownership-read":
                return _owned(plan)
            if operation["kind"] == "cleanup-verify-absence":
                return _owned(plan)
            raise AssertionError("preexisting document must not be mutated")

        result = collect_local(plan, execute, tmp_path / ("same" if fields == plan["fixtureFields"] else "different"))
        assert "create-only-patch" not in calls
        assert "cleanup-conditional-delete" not in calls
        assert result["cleanupComplete"] is False


def test_successful_unchanged_create_is_deleted_with_exact_version(tmp_path: Path) -> None:
    plan = _plan()
    create_time = "2026-09-17T01:02:03.000000Z"
    update_time = "2026-09-17T01:02:03.000000Z"
    seen: list[dict[str, Any]] = []

    def execute(operation: dict[str, Any]) -> dict[str, Any]:
        seen.append(copy.deepcopy(operation))
        if operation["kind"] == "preflight-typed-absence":
            return _not_found()
        if operation["kind"] in {"create-only-patch", "cleanup-ownership-read"}:
            return _owned(plan, update_time, create_time)
        if operation["kind"] == "cleanup-conditional-delete":
            assert f"currentDocument.updateTime={update_time.replace(':', '%3A')}" in operation["path"]
            return _ok({})
        if operation["kind"] == "cleanup-verify-absence":
            return _not_found()
        return _ok({"documents": [plan["expectedPositiveDocument"]]})

    result = collect_local(plan, execute, tmp_path / "receipt")
    assert result["cleanupComplete"] is True


def test_preexisting_same_fields_are_never_deleted_without_successful_create(tmp_path: Path) -> None:
    plan = _plan()
    calls: list[str] = []

    def execute(operation: dict[str, Any]) -> dict[str, Any]:
        calls.append(operation["kind"])
        if operation["kind"] == "preflight-typed-absence":
            return _not_found()
        if operation["kind"] == "create-only-patch":
            return _ok({"error": {"code": 409, "status": "ALREADY_EXISTS"}}, 409)
        if operation["kind"] == "cleanup-ownership-read":
            return _owned(plan)
        if operation["kind"] == "cleanup-verify-absence":
            return _owned(plan)
        raise AssertionError("preexisting document must not be deleted")

    result = collect_local(plan, execute, tmp_path / "receipt")

    assert calls == [
        "preflight-typed-absence",
        "create-only-patch",
        "cleanup-ownership-read",
        "cleanup-verify-absence",
    ]
    assert result["cleanup"][1]["skipped"] == "create-not-proven"
    assert result["cleanupComplete"] is False


def test_lost_create_response_retains_cleanup_responsibility_and_never_deletes(tmp_path: Path) -> None:
    plan = _plan()

    def execute(operation: dict[str, Any]) -> dict[str, Any]:
        if operation["kind"] == "preflight-typed-absence":
            return _not_found()
        if operation["kind"] == "create-only-patch":
            return {"complete": False, "failure": "transport-timeout"}
        if operation["kind"] == "cleanup-ownership-read":
            return _owned(plan)
        if operation["kind"] == "cleanup-verify-absence":
            return _owned(plan)
        raise AssertionError("lost create response must not authorize delete")

    result = collect_local(plan, execute, tmp_path / "receipt")

    assert result["attemptedResources"] == [plan["document"]]
    assert result["cleanup"][1]["skipped"] == "create-not-proven"
    assert result["cleanupComplete"] is False


def test_final_collection_publication_failure_is_returned_without_erasing_cleanup_fact(
    tmp_path: Path, monkeypatch
) -> None:
    plan = _plan()
    original_publish = __import__("query_in_collector")._publish

    def fail_final(directory_fd: int, filename: str, value: Any) -> None:
        if filename == "collection.json":
            raise OSError("final-link-failure")
        original_publish(directory_fd, filename, value)

    monkeypatch.setattr("query_in_collector._publish", fail_final)
    result = collect_local(plan, _transport(plan), tmp_path / "receipt")

    assert result["cleanupComplete"] is True
    assert result["persistenceComplete"] is False
    assert result["completed"] is False
    assert any("collection.json:OSError" in item for item in result["infrastructureFailures"])


def test_final_collection_collision_keeps_existing_file_and_reports_stale_recording(
    tmp_path: Path,
) -> None:
    plan = _plan()
    output = tmp_path / "receipt"
    transport = _transport(plan)
    calls: list[str] = []

    def execute(operation: dict[str, Any]) -> dict[str, Any]:
        if operation["kind"] == "cleanup-verify-absence":
            (output / "collection.json").write_text("old-record\n")
        return transport(operation)

    transport = _transport(plan, calls=calls)
    result = collect_local(plan, execute, output)

    assert (output / "collection.json").read_text() == "old-record\n"
    assert result["cleanupComplete"] is True
    assert result["completed"] is False
    assert len(calls) == 9
    assert result["recordingComplete"] is False
    assert result["persistenceComplete"] is False
    assert any("collection.json:FileExistsError" in item for item in result["infrastructureFailures"])
    assert not list(output.glob(".receipt-*"))


def test_final_collection_file_write_fault_reports_failure_after_real_rows(
    tmp_path: Path, monkeypatch
) -> None:
    original_fdopen = os.fdopen
    publication_count = 0

    class FailingStream:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def write(self, value):
            raise OSError("final-file-write-failure")

        def __getattr__(self, name):
            return getattr(self.stream, name)

    def fdopen(fd, mode, *args, **kwargs):
        nonlocal publication_count
        publication_count += 1
        stream = original_fdopen(fd, mode, *args, **kwargs)
        return FailingStream(stream) if publication_count == 10 else stream

    monkeypatch.setattr("query_in_collector.os.fdopen", fdopen)
    plan = _plan()
    calls: list[str] = []
    result = collect_local(plan, _transport(plan, calls=calls), tmp_path / "receipt")

    assert result["cleanupComplete"] is True
    assert result["recordingComplete"] is False
    assert result["persistenceComplete"] is False
    assert result["completed"] is False
    assert len(calls) == 9
    assert any("collection.json:OSError" in item for item in result["infrastructureFailures"])
    assert len(list((tmp_path / "receipt").glob("observation-*.json"))) == 6
    assert len(list((tmp_path / "receipt").glob("recovery-*.json"))) == 3
    assert not (tmp_path / "receipt" / "collection.json").exists()
    assert not list((tmp_path / "receipt").glob(".receipt-*"))


def test_final_collection_link_fault_reports_failure_after_real_rows(
    tmp_path: Path, monkeypatch
) -> None:
    original_link = os.link

    def link(src, dst, *args, **kwargs):
        if dst == "collection.json":
            raise OSError("final-link-failure")
        return original_link(src, dst, *args, **kwargs)

    monkeypatch.setattr("query_in_collector.os.link", link)
    plan = _plan()
    calls: list[str] = []
    result = collect_local(plan, _transport(plan, calls=calls), tmp_path / "receipt")

    assert result["cleanupComplete"] is True
    assert result["recordingComplete"] is False
    assert result["persistenceComplete"] is False
    assert result["completed"] is False
    assert len(calls) == 9
    assert any("collection.json:OSError" in item for item in result["infrastructureFailures"])
    assert len(list((tmp_path / "receipt").glob("observation-*.json"))) == 6
    assert len(list((tmp_path / "receipt").glob("recovery-*.json"))) == 3
    assert not (tmp_path / "receipt" / "collection.json").exists()
    assert not list((tmp_path / "receipt").glob(".receipt-*"))


@pytest.mark.parametrize("target_call", [20, 21])
def test_final_collection_file_or_directory_fsync_fault_reports_failure(
    tmp_path: Path, monkeypatch, target_call: int
) -> None:
    original_fsync = os.fsync
    calls = 0

    def fsync(fd):
        nonlocal calls
        calls += 1
        if calls == target_call:
            raise OSError("final-fsync-failure")
        return original_fsync(fd)

    monkeypatch.setattr("query_in_collector.os.fsync", fsync)
    plan = _plan()
    calls_seen: list[str] = []
    result = collect_local(plan, _transport(plan, calls=calls_seen), tmp_path / "receipt")

    assert result["cleanupComplete"] is True
    assert result["recordingComplete"] is False
    assert result["persistenceComplete"] is False
    assert result["completed"] is False
    assert len(calls_seen) == 9
    assert any("collection.json:OSError" in item for item in result["infrastructureFailures"])
    assert len(list((tmp_path / "receipt").glob("observation-*.json"))) == 6
    assert len(list((tmp_path / "receipt").glob("recovery-*.json"))) == 3
    collection = tmp_path / "receipt" / "collection.json"
    assert collection.exists() is (target_call == 21)
    assert not list((tmp_path / "receipt").glob(".receipt-*"))


def test_final_directory_fsync_fault_leaves_linked_collection_as_non_authoritative(
    tmp_path: Path, monkeypatch
) -> None:
    original_fsync = os.fsync
    calls = 0

    def fsync(fd):
        nonlocal calls
        calls += 1
        if calls == 21:
            raise OSError("final-directory-fsync-failure")
        return original_fsync(fd)

    monkeypatch.setattr("query_in_collector.os.fsync", fsync)
    plan = _plan()
    calls_seen: list[str] = []
    result = collect_local(plan, _transport(plan, calls=calls_seen), tmp_path / "receipt")
    collection = tmp_path / "receipt" / "collection.json"

    assert result["completed"] is False
    assert result["cleanupComplete"] is True
    assert result["persistenceComplete"] is False
    assert len(calls_seen) == 9
    assert json.loads(collection.read_text())["completed"] is True
    assert len(list((tmp_path / "receipt").glob("observation-*.json"))) == 6
    assert len(list((tmp_path / "receipt").glob("recovery-*.json"))) == 3
    assert not list((tmp_path / "receipt").glob(".receipt-*"))


def test_output_initialization_failure_sends_no_wire_operations(tmp_path: Path, monkeypatch) -> None:
    plan = _plan()
    calls: list[str] = []
    original_open = os.open

    def fail_output(path, flags, *args, **kwargs):
        if path == tmp_path:
            raise OSError("output-init-failure")
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr("query_in_collector.os.open", fail_output)

    def execute(operation: dict[str, Any]) -> dict[str, Any]:
        calls.append(operation["kind"])
        raise AssertionError("wire must not run when output initialization fails")

    result = collect_local(plan, execute, tmp_path / "receipt")

    assert calls == []
    assert result["attemptedResources"] == []
    assert result["persistenceComplete"] is False


def test_directory_path_swap_cannot_redirect_durable_rows(tmp_path: Path) -> None:
    plan = _plan()
    output = tmp_path / "receipt"
    owned = tmp_path / "owned-receipt"
    attacker = tmp_path / "attacker-receipt"
    state = {"swapped": False}
    transport = _transport(plan)

    def execute(operation: dict[str, Any]) -> dict[str, Any]:
        if operation["kind"] == "preflight-typed-absence":
            return _not_found()
        if operation["kind"] == "create-only-patch":
            owned.mkdir()
            attacker.mkdir()
            output.rename(owned)
            output.symlink_to(attacker, target_is_directory=True)
            state["swapped"] = True
            return transport(operation)
        return transport(operation)

    result = collect_local(plan, execute, output)

    assert state["swapped"] is True
    assert result["persistenceComplete"] is True
    assert result["attemptedResources"] == [plan["document"]]
    assert result["cleanup"][1]["request"]["kind"] == "cleanup-conditional-delete"
    assert result["cleanup"][1]["status"] == 200
    assert result["resourceAbsence"][plan["document"]] is True
    assert (owned / "observation-01.json").exists()
    assert not list(attacker.iterdir())


def test_incomplete_executor_receipt_stops_observation_but_runs_safe_recovery(tmp_path: Path) -> None:
    plan = _plan()
    calls: list[str] = []

    def execute(operation: dict[str, Any]) -> dict[str, Any]:
        calls.append(operation["kind"])
        if operation["kind"] == "preflight-typed-absence":
            return _not_found()
        if operation["kind"] == "create-only-patch":
            return {"complete": False, "failure": "transport-timeout"}
        if operation["kind"] == "cleanup-ownership-read":
            return _not_found()
        if operation["kind"] == "cleanup-verify-absence":
            return _not_found()
        raise AssertionError("delete must not be dispatched without owned read")

    result = collect_local(plan, execute, tmp_path / "receipt")

    assert calls[:2] == ["preflight-typed-absence", "create-only-patch"]
    assert result["rows"][1]["complete"] is False
    assert result["cleanup"][1]["skipped"] == "already-absent"
    assert result["infrastructureFailures"]
    assert result["completed"] is False


def test_oversized_receipt_is_bounded_but_retains_cleanup_responsibility(tmp_path: Path) -> None:
    plan = _plan()

    def execute(operation: dict[str, Any]) -> dict[str, Any]:
        if operation["kind"] == "preflight-typed-absence":
            return _not_found()
        if operation["kind"] == "create-only-patch":
            return _ok({"largeDiagnostic": "x" * 200_000})
        if operation["kind"] == "cleanup-ownership-read":
            return _owned(plan)
        if operation["kind"] == "cleanup-conditional-delete":
            return _ok({})
        if operation["kind"] == "cleanup-verify-absence":
            return _not_found()
        raise AssertionError("observation must stop after oversized mutation response")

    result = collect_local(plan, execute, tmp_path / "receipt")

    assert result["rows"][1]["failure"] == "receipt-too-large"
    assert len(json.dumps(result["rows"][1])) < 2_000
    assert result["cleanup"][1]["skipped"] == "create-not-proven"
    assert result["resourceAbsence"][plan["document"]] is True
    assert result["completed"] is False


def test_existing_output_symlink_fails_closed_without_unowned_delete(tmp_path: Path) -> None:
    plan = _plan()
    output = tmp_path / "receipt"
    attacker = tmp_path / "attacker-receipt"
    attacker.mkdir()
    output.symlink_to(attacker, target_is_directory=True)
    calls: list[str] = []

    def execute(operation: dict[str, Any]) -> dict[str, Any]:
        calls.append(operation["kind"])
        if operation["kind"] in {"preflight-typed-absence", "cleanup-ownership-read", "cleanup-verify-absence"}:
            return _not_found()
        raise AssertionError("create and delete require ownership evidence")

    result = collect_local(plan, execute, output)

    assert calls == []
    assert result["cleanup"] == []
    assert result["attemptedResources"] == []
    assert result["resourceAbsence"][plan["document"]] is False
    assert result["completed"] is False
    assert not list(attacker.iterdir())


def test_exclusive_publication_failure_cleans_temp_in_owned_inode(tmp_path: Path) -> None:
    owned = tmp_path / "owned"
    owned.mkdir()
    (owned / "row.json").write_text("existing")
    before_cwd = {path.name for path in Path.cwd().glob(".receipt-*")}
    directory_fd = os.open(owned, os.O_RDONLY | os.O_DIRECTORY)
    try:
        try:
            _publish(directory_fd, "row.json", {"complete": True})
        except FileExistsError:
            pass
        else:
            raise AssertionError("publication must remain exclusive")
    finally:
        os.close(directory_fd)

    assert not list(owned.glob(".receipt-*"))
    assert {path.name for path in Path.cwd().glob(".receipt-*")} == before_cwd
