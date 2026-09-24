import base64
import hashlib
import json
import sys

import pytest

sys.path.insert(0, "tools/compat-broad/fs-request-bytes-boundary")
sys.path.insert(0, "tools/compat-broad")

from request_bytes_collector import (
    _journal_digest,
    commit_versions,
    over_refusal_classification,
    readback_matches,
    typed_not_found,
    typed_over_refusal,
    validate_schedule,
)
from request_bytes_compiler import compile_request_bytes_plan


def plan():
    return compile_request_bytes_plan(
        "local-project", "(default)", "0123456789abcdef0123456789abcdef"
    )


def test_schedule_requires_observation_then_probe_cleanup():
    value = plan()
    validate_schedule(value)
    assert len(value["executionSchedule"]) == 258
    assert value["executionSchedule"][35]["phase"] == "recovery"
    assert value["executionSchedule"][86]["phase"] == "observation"


def test_commit_versions_requires_positional_complete_write_results():
    value = plan()
    resources = value["probes"][0]["resources"]
    receipt = {
        "complete": True,
        "failure": None,
        "status": 200,
        "body": {
            "writeResults": [
                {"updateTime": "2026-01-01T00:00:00.000000Z", "name": resource}
                for resource in resources
            ]
        },
    }
    assert len(commit_versions(receipt, resources)) == 17
    receipt["body"]["writeResults"][3]["name"] = resources[4]
    assert commit_versions(receipt, resources) is None


def test_over_refusal_is_typed_and_readback_never_accepts_foreign_document():
    refusal = {
        "complete": True,
        "failure": None,
        "status": 404,
        "body": {"error": {"code": 404, "status": "NOT_FOUND"}},
    }
    assert typed_not_found(refusal)
    value = plan()
    document = value["documents"][value["probes"][0]["resources"][0]]
    foreign = {
        "complete": True,
        "failure": None,
        "status": 200,
        "body": {
            "name": value["probes"][0]["resources"][1],
            "fields": {},
            "updateTime": "2026-01-01T00:00:00.000000Z",
        },
    }
    assert not readback_matches(
        foreign,
        value["probes"][0]["resources"][0],
        document["fieldsSha256"],
        value["nonce"],
        None,
    )


def test_schedule_mutation_is_rejected():
    value = plan()
    value["executionSchedule"][35], value["executionSchedule"][36] = (
        value["executionSchedule"][36],
        value["executionSchedule"][35],
    )
    with pytest.raises(ValueError):
        validate_schedule(value)


def test_journal_digest_is_ordered_and_byte_bound():
    first = [{"name": "row-000.json", "bytes": 12, "sha256": "a" * 64, "sequence": 0}]
    second = first + [
        {"name": "response-000.body", "bytes": 3, "sha256": "b" * 64, "sequence": 0}
    ]
    assert _journal_digest(first) != _journal_digest(second)
    assert _journal_digest(second) != _journal_digest(list(reversed(second)))


def test_failed_preflight_never_sends_commit_or_next_probe(tmp_path):
    from request_bytes_collector import collect_local

    value = plan()
    dispatched = []

    def execute(operation):
        dispatched.append(operation)
        if operation["kind"] == "preflight-typed-absence" and len(dispatched) == 1:
            return {
                "complete": True,
                "failure": None,
                "status": 200,
                "body": {"name": operation["resource"]},
            }
        return {
            "complete": True,
            "failure": None,
            "status": 404,
            "body": {"error": {"code": 404, "status": "NOT_FOUND"}},
        }

    result = collect_local(value, execute, tmp_path / "run")
    assert not result["completed"]
    assert not any(item["kind"] == "conditional-create-commit" for item in dispatched)
    assert not any(item["probe"] != "under" for item in dispatched)
    assert not any(item["method"] == "DELETE" for item in dispatched)
    assert result["localJournal"]["captureComplete"] is False


def test_lost_commit_response_holds_cleanup_responsibility(tmp_path):
    from request_bytes_collector import collect_local

    value = plan()
    dispatched = []

    def execute(operation):
        dispatched.append(operation)
        if operation["kind"] == "conditional-create-commit":
            return {"complete": False, "failure": "response-lost"}
        body = {"error": {"code": 404, "status": "NOT_FOUND"}}
        raw = json.dumps(body, separators=(",", ":")).encode()
        return {
            "complete": True,
            "failure": None,
            "status": 404,
            "body": body,
            "rawBodyBase64": base64.b64encode(raw).decode(),
            "bodyBytes": len(raw),
        }

    result = collect_local(value, execute, tmp_path / "run")
    assert any(item["kind"] == "conditional-create-commit" for item in dispatched)
    assert not result["completed"]
    assert not any(item["method"] == "DELETE" for item in dispatched)
    assert not any(item["probe"] != "under" for item in dispatched)
    assert result["resourceAbsence"] is False


def test_timestamp_accepts_firestore_precision_variants():
    from request_bytes_collector import commit_versions

    for timestamp in (
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:00.1Z",
        "2026-01-01T00:00:00.123456789Z",
    ):
        assert commit_versions(
            {
                "complete": True,
                "failure": None,
                "status": 200,
                "body": {"writeResults": [{"updateTime": timestamp}]},
            },
            ["resource"],
        ) == [timestamp]
    assert (
        commit_versions(
            {
                "complete": True,
                "failure": None,
                "status": 200,
                "body": {"writeResults": [{"updateTime": "2026-99-99T99:99:99.1Z"}]},
            },
            ["resource"],
        )
        is None
    )


def test_sentinel_capture_accounts_for_skipped_delete_slots_without_sidecars(
    tmp_path,
):
    from request_bytes_collector import collect_local
    from request_bytes_compiler import compile_request_bytes_sentinel_plan

    sentinel = compile_request_bytes_sentinel_plan(
        "local-project", "(default)", "0123456789abcdef0123456789abcdef"
    )
    dispatched = []

    def response(status, body):
        raw = (
            body.encode("utf-8")
            if isinstance(body, str)
            else json.dumps(body, separators=(",", ":")).encode()
        )
        return {
            "complete": True,
            "failure": None,
            "status": status,
            "body": body,
            "rawBodyBase64": base64.b64encode(raw).decode("ascii"),
            "bodyBytes": len(raw),
        }

    def execute(operation):
        dispatched.append(operation)
        if operation["kind"] == "conditional-create-commit":
            return response(413, "<html>gateway response</html>")
        return response(404, {"error": {"code": 404, "status": "NOT_FOUND"}})

    result = collect_local(sentinel, execute, tmp_path / "sentinel")

    assert result["completed"] is False
    assert result["requestCount"] == 81
    assert len(dispatched) == 81
    assert result["rowCount"] + result["recoveryRowCount"] == 101
    assert result["localJournal"]["rowCount"] == 101
    assert result["localJournal"]["sidecarCount"] == 81
    assert result["localJournal"]["captureComplete"] is True
    run_dir = tmp_path / "sentinel"
    rows = [json.loads(path.read_text()) for path in sorted(run_dir.glob("row-*.json"))]
    skipped_deletes = [
        row
        for row in rows
        if row["kind"] == "cleanup-version-bound-delete" and row["status"] == "skipped"
    ]
    assert len(skipped_deletes) == 20
    assert all("responseBodyFile" not in row for row in skipped_deletes)
    assert len(list(run_dir.glob("response-*.body"))) == 81


def test_sentinel_capture_remains_incomplete_when_an_actual_response_sidecar_is_missing(
    tmp_path,
):
    from request_bytes_collector import collect_local
    from request_bytes_compiler import compile_request_bytes_sentinel_plan

    sentinel = compile_request_bytes_sentinel_plan(
        "local-project", "(default)", "0123456789abcdef0123456789abcdef"
    )
    dispatched = []

    def execute(operation):
        dispatched.append(operation)
        receipt = {
            "complete": True,
            "failure": None,
            "status": 404,
            "body": {"error": {"code": 404, "status": "NOT_FOUND"}},
        }
        if len(dispatched) > 1:
            raw = json.dumps(receipt["body"], separators=(",", ":")).encode()
            receipt.update(
                rawBodyBase64=base64.b64encode(raw).decode("ascii"),
                bodyBytes=len(raw),
            )
        return receipt

    result = collect_local(sentinel, execute, tmp_path / "missing-sidecar")

    assert result["completed"] is False
    assert result["localJournal"]["captureComplete"] is False
    assert result["localJournal"]["sidecarCount"] < result["requestCount"]


@pytest.mark.parametrize(
    ("over_status", "over_classification"),
    [(400, "expected"), (413, "semantic-discrepancy")],
)
def test_three_probe_run_completes_with_typed_over_refusal(
    tmp_path, over_status, over_classification
):
    from request_bytes_collector import collect_local

    value = plan()
    documents = {
        write["update"]["name"]: write["update"]["fields"]
        for probe in value["probes"]
        for write in probe["body"]["writes"]
    }
    version = "2026-01-01T00:00:00.123456789Z"
    live = set()
    deletes = []

    def execute(operation):
        kind, resource = operation["kind"], operation.get("resource")
        if kind == "conditional-create-commit":
            if operation["probe"] == "over":
                return {
                    "complete": True,
                    "failure": None,
                    "status": over_status,
                    "body": {
                        "error": {
                            "code": over_status,
                            "status": "INVALID_ARGUMENT",
                        }
                    },
                }
            resources = next(
                probe["resources"]
                for probe in value["probes"]
                if probe["label"] == operation["probe"]
            )
            live.update(resources)
            return {
                "complete": True,
                "failure": None,
                "status": 200,
                "body": {"writeResults": [{"updateTime": version} for _ in resources]},
            }
        if kind == "cleanup-version-bound-delete":
            assert resource in live
            assert operation["path"].endswith(
                "currentDocument.updateTime=" + version.replace(":", "%3A")
            )
            deletes.append(resource)
            live.remove(resource)
            return {"complete": True, "failure": None, "status": 200, "body": {}}
        if resource in live:
            return {
                "complete": True,
                "failure": None,
                "status": 200,
                "body": {
                    "name": resource,
                    "fields": documents[resource],
                    "updateTime": version,
                },
            }
        return {
            "complete": True,
            "failure": None,
            "status": 404,
            "body": {"error": {"code": 404, "status": "NOT_FOUND"}},
        }

    def execute_with_raw(operation):
        receipt = execute(operation)
        raw = json.dumps(receipt["body"], separators=(",", ":")).encode()
        receipt["rawBodyBase64"] = base64.b64encode(raw).decode()
        receipt["bodyBytes"] = len(raw)
        return receipt

    result = collect_local(value, execute_with_raw, tmp_path / "run")
    assert result["completed"] is True
    assert result["cleanupComplete"] is True
    assert result["resourceAbsence"] is True
    assert result["localJournal"]["captureComplete"] is True
    assert result["localJournal"]["rowCount"] == len(value["executionSchedule"])
    assert result["localJournal"]["sidecarCount"] == result["requestCount"]
    journal_rows = [
        json.loads(path.read_text())
        for path in sorted((tmp_path / "run").glob("row-*.json"))
    ]
    skipped = [row for row in journal_rows if row["status"] == "skipped"]
    assert result["localJournal"]["skippedCount"] == 17
    assert result["localJournal"]["skippedSummary"] == [
        {
            "probe": "over",
            "kind": "cleanup-version-bound-delete",
            "reason": "creation-and-current-version-not-proven",
            "count": 17,
        }
    ]
    assert all(
        row["kind"] == "cleanup-version-bound-delete" and row["probe"] == "over"
        for row in skipped
    )
    assert all(
        row["status"] != "skipped"
        for row in journal_rows
        if row["kind"] in ("conditional-create-commit", "probe-readback")
    )
    refusal_raw = json.dumps(
        {"error": {"code": over_status, "status": "INVALID_ARGUMENT"}},
        separators=(",", ":"),
    ).encode()
    assert result["overRefusal"] == {
        "httpStatus": over_status,
        "errorCode": over_status,
        "errorStatus": "INVALID_ARGUMENT",
        "message": None,
        "messageBytes": None,
        "messageSha256": None,
        "messageTruncated": False,
        "responseBodyFile": "response-189.body",
        "responseBytes": len(refusal_raw),
        "responseSha256": hashlib.sha256(refusal_raw).hexdigest(),
        "classification": over_classification,
    }
    assert len(deletes) == 34
    assert not live
    sidecars = sorted((tmp_path / "run").glob("response-*.body"))
    assert len(sidecars) == result["requestCount"]
    for sidecar in sidecars:
        row = json.loads(
            (
                tmp_path
                / "run"
                / sidecar.name.replace("response-", "row-").replace(".body", ".json")
            ).read_text()
        )
        raw = sidecar.read_bytes()
        assert row["responseBytes"] == len(raw)
        assert row["responseSha256"] == hashlib.sha256(raw).hexdigest()
    assert len((tmp_path / "run" / "result.json").read_bytes()) <= 131_072


def test_missing_raw_response_cannot_complete_or_send_commit(tmp_path):
    from request_bytes_collector import collect_local

    value = plan()
    dispatched = []

    def execute(operation):
        dispatched.append(operation)
        return {
            "complete": True,
            "failure": None,
            "status": 404,
            "body": {"error": {"code": 404, "status": "NOT_FOUND"}},
        }

    result = collect_local(value, execute, tmp_path / "run")
    assert result["completed"] is False
    assert not any(item["kind"] == "conditional-create-commit" for item in dispatched)
    assert not list((tmp_path / "run").glob("response-*.body"))
    assert any(
        "response-bytes-unavailable"
        in json.loads(path.read_text())["receipt"].get("failure", "")
        for path in (tmp_path / "run").glob("row-*.json")
    )


def test_unexpected_over_success_keeps_creation_proof_for_cleanup(tmp_path):
    from request_bytes_collector import collect_local

    value = plan()
    documents = {
        write["update"]["name"]: write["update"]["fields"]
        for probe in value["probes"]
        for write in probe["body"]["writes"]
    }
    version = "2026-01-01T00:00:00Z"
    live = set()
    deletes = []

    def execute(operation):
        kind, resource = operation["kind"], operation.get("resource")
        if kind == "conditional-create-commit":
            resources = next(
                item["resources"]
                for item in value["probes"]
                if item["label"] == operation["probe"]
            )
            live.update(resources)
            body = {"writeResults": [{"updateTime": version} for _ in resources]}
            if operation["probe"] == "over":
                body["writeResults"] = [
                    {"updateTime": version, "name": resource} for resource in resources
                ]
            receipt = {"complete": True, "failure": None, "status": 200, "body": body}
        elif kind == "cleanup-version-bound-delete":
            assert resource in live
            deletes.append(resource)
            live.remove(resource)
            receipt = {"complete": True, "failure": None, "status": 200, "body": {}}
        elif resource in live:
            receipt = {
                "complete": True,
                "failure": None,
                "status": 200,
                "body": {
                    "name": resource,
                    "fields": documents[resource],
                    "updateTime": version,
                },
            }
        else:
            receipt = {
                "complete": True,
                "failure": None,
                "status": 404,
                "body": {"error": {"code": 404, "status": "NOT_FOUND"}},
            }
        raw = json.dumps(receipt["body"], separators=(",", ":")).encode()
        return {
            **receipt,
            "rawBodyBase64": base64.b64encode(raw).decode(),
            "bodyBytes": len(raw),
        }

    result = collect_local(value, execute, tmp_path / "run")
    assert len(deletes) == 51
    assert not live
    assert result["resourceAbsence"] is True
    assert result["cleanupComplete"] is False
    assert result["cleanupSafetyComplete"] is True
    assert "over:unexpected-success" in result["failures"]
    assert result["semanticOutcome"] == "unexpected-over-success"


@pytest.mark.parametrize(
    ("failure_kind", "failure_sequence"),
    [
        (failure_kind, failure_sequence)
        for failure_kind in ("row", "sidecar")
        for failure_sequence in (0, 17)
    ],
)
def test_recording_failure_stops_observation_but_runs_recovery(
    tmp_path, monkeypatch, failure_kind, failure_sequence
):
    import request_bytes_collector
    from request_bytes_collector import collect_local

    value = plan()
    documents = {
        write["update"]["name"]: write["update"]["fields"]
        for probe in value["probes"]
        for write in probe["body"]["writes"]
    }
    version = "2026-01-01T00:00:00Z"
    live = set()
    deletes = []
    calls = []
    failed = False
    original_publish = request_bytes_collector._publish

    def publish(directory, name, value, *, bounded=True):
        nonlocal failed
        if not failed and (
            (failure_kind == "row" and name == f"row-{failure_sequence:03d}.json")
            or (
                failure_kind == "sidecar"
                and name == f"response-{failure_sequence:03d}.body"
            )
        ):
            failed = True
            raise OSError("injected recording failure")
        return original_publish(directory, name, value, bounded=bounded)

    monkeypatch.setattr(request_bytes_collector, "_publish", publish)
    if failure_kind == "sidecar":
        original_open = request_bytes_collector.os.open

        def open_file(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal failed
            if path == f"response-{failure_sequence:03d}.body" and not failed:
                failed = True
                raise OSError("injected recording failure")
            return original_open(path, flags, mode, dir_fd=dir_fd)

        monkeypatch.setattr(request_bytes_collector.os, "open", open_file)

    def execute(operation):
        calls.append(operation)
        kind, resource = operation["kind"], operation.get("resource")
        if kind == "conditional-create-commit":
            resources = next(
                item["resources"]
                for item in value["probes"]
                if item["label"] == operation["probe"]
            )
            live.update(resources)
            body = {"writeResults": [{"updateTime": version} for _ in resources]}
            receipt = {"complete": True, "failure": None, "status": 200, "body": body}
        elif kind == "cleanup-version-bound-delete":
            assert resource in live
            deletes.append(resource)
            live.remove(resource)
            receipt = {"complete": True, "failure": None, "status": 200, "body": {}}
        elif resource in live:
            receipt = {
                "complete": True,
                "failure": None,
                "status": 200,
                "body": {
                    "name": resource,
                    "fields": documents[resource],
                    "updateTime": version,
                },
            }
        else:
            receipt = {
                "complete": True,
                "failure": None,
                "status": 404,
                "body": {"error": {"code": 404, "status": "NOT_FOUND"}},
            }
        raw = json.dumps(receipt["body"], separators=(",", ":")).encode()
        return {
            **receipt,
            "rawBodyBase64": base64.b64encode(raw).decode(),
            "bodyBytes": len(raw),
        }

    result = collect_local(value, execute, tmp_path / "run")
    assert result["completed"] is False
    assert result["resourceAbsence"] is False
    assert result["cleanupSafetyComplete"] is False
    assert len(deletes) == (17 if failure_sequence == 17 else 0)
    assert not any(item["probe"] != "under" for item in calls)
    if failure_sequence == 0:
        assert not any(item["kind"] == "conditional-create-commit" for item in calls)
    else:
        assert any(item["kind"] == "conditional-create-commit" for item in calls)
        assert not any(item["kind"] == "probe-readback" for item in calls)
    assert any(failure.startswith("recording:") for failure in result["failures"])


def test_fractional_and_boolean_over_refusal_codes_are_rejected():
    from request_bytes_collector import _error_status

    for code in (400.0, True):
        receipt = {
            "complete": True,
            "failure": None,
            "status": 400,
            "body": {"error": {"code": code, "status": "INVALID_ARGUMENT"}},
        }
        assert not _error_status(receipt, "INVALID_ARGUMENT")
        assert not typed_over_refusal(receipt)


def test_http_413_invalid_argument_is_a_complete_refusal_with_discrepancy_metadata():
    refusal = {
        "complete": True,
        "failure": None,
        "status": 413,
        "body": {"error": {"code": 413, "status": "INVALID_ARGUMENT"}},
    }
    assert typed_over_refusal(refusal)
    assert over_refusal_classification(refusal) == "semantic-discrepancy"


@pytest.mark.parametrize(
    "receipt",
    [
        {
            "complete": False,
            "failure": "response-lost",
            "status": 413,
            "body": {"error": {"code": 413, "status": "INVALID_ARGUMENT"}},
        },
        {
            "complete": True,
            "failure": None,
            "status": 200,
            "body": {"error": {"code": 200, "status": "INVALID_ARGUMENT"}},
        },
        {
            "complete": True,
            "failure": None,
            "status": 413,
            "body": {"error": {"code": 400, "status": "INVALID_ARGUMENT"}},
        },
        {
            "complete": True,
            "failure": None,
            "status": 413,
            "body": {"error": {"code": 413, "status": "FAILED_PRECONDITION"}},
        },
    ],
)
def test_413_over_refusal_controls_fail_closed(receipt):
    assert not typed_over_refusal(receipt)
    assert over_refusal_classification(receipt) is None


@pytest.mark.parametrize(
    "over_receipt",
    [
        {
            "complete": False,
            "failure": "response-lost",
            "status": 413,
            "body": {"error": {"code": 413, "status": "INVALID_ARGUMENT"}},
        },
        {
            "complete": True,
            "failure": None,
            "status": 413,
            "body": "not-json-error",
        },
        {
            "complete": True,
            "failure": None,
            "status": 200,
            "body": {"error": {"code": 200, "status": "INVALID_ARGUMENT"}},
        },
        {
            "complete": True,
            "failure": None,
            "status": 413,
            "body": {"error": {"code": 400, "status": "INVALID_ARGUMENT"}},
        },
    ],
)
def test_invalid_over_receipt_keeps_collection_incomplete_and_never_deletes(
    tmp_path, over_receipt
):
    from request_bytes_collector import collect_local

    value = plan()
    documents = {
        write["update"]["name"]: write["update"]["fields"]
        for probe in value["probes"]
        for write in probe["body"]["writes"]
    }
    version = "2026-01-01T00:00:00Z"
    live = set()
    dispatched = []
    over_dispatch_index = None

    def with_raw(receipt):
        if not receipt["complete"]:
            return receipt
        raw = json.dumps(receipt["body"], separators=(",", ":")).encode()
        return {
            **receipt,
            "rawBodyBase64": base64.b64encode(raw).decode(),
            "bodyBytes": len(raw),
        }

    def execute(operation):
        dispatched.append(operation)
        kind, resource = operation["kind"], operation.get("resource")
        if kind == "conditional-create-commit":
            if operation["probe"] == "over":
                nonlocal over_dispatch_index
                over_dispatch_index = len(dispatched) - 1
                return with_raw(over_receipt)
            resources = next(
                probe["resources"]
                for probe in value["probes"]
                if probe["label"] == operation["probe"]
            )
            live.update(resources)
            return with_raw(
                {
                    "complete": True,
                    "failure": None,
                    "status": 200,
                    "body": {
                        "writeResults": [{"updateTime": version} for _ in resources]
                    },
                }
            )
        if kind == "cleanup-version-bound-delete":
            live.remove(resource)
            return with_raw(
                {"complete": True, "failure": None, "status": 200, "body": {}}
            )
        if resource in live:
            return with_raw(
                {
                    "complete": True,
                    "failure": None,
                    "status": 200,
                    "body": {
                        "name": resource,
                        "fields": documents[resource],
                        "updateTime": version,
                    },
                }
            )
        return with_raw(
            {
                "complete": True,
                "failure": None,
                "status": 404,
                "body": {"error": {"code": 404, "status": "NOT_FOUND"}},
            }
        )

    result = collect_local(value, execute, tmp_path / "run")
    assert result["completed"] is False
    assert result["cleanupComplete"] is False
    assert result["cleanupSafetyComplete"] is False
    assert over_dispatch_index is not None
    assert not any(
        operation["kind"] == "cleanup-version-bound-delete"
        for operation in dispatched[over_dispatch_index + 1 :]
    )


def test_contradictory_raw_response_cannot_prove_preflight(tmp_path):
    from request_bytes_collector import collect_local

    value = plan()
    dispatched = []

    def execute(operation):
        dispatched.append(operation)
        raw = b"not-the-parsed-json"
        return {
            "complete": True,
            "failure": None,
            "status": 404,
            "body": {"error": {"code": 404, "status": "NOT_FOUND"}},
            "rawBodyBase64": base64.b64encode(raw).decode(),
            "bodyBytes": len(raw),
        }

    result = collect_local(value, execute, tmp_path / "run")
    assert result["completed"] is False
    assert not any(item["kind"] == "conditional-create-commit" for item in dispatched)


def test_symlinked_output_parent_is_rejected(tmp_path):
    from request_bytes_collector import collect_local

    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "link").symlink_to(real, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        collect_local(
            plan(),
            lambda _operation: pytest.fail("unexpected dispatch"),
            tmp_path / "link" / "run",
        )
    assert not (real / "run").exists()


@pytest.mark.parametrize(
    "bad_raw", ["%%%", base64.b64encode(b"x" * (2 * 1024 * 1024 + 1)).decode()]
)
def test_incomplete_malformed_recovery_receipt_keeps_responsibility(tmp_path, bad_raw):
    from request_bytes_collector import collect_local

    value = plan()
    resources = value["probes"][0]["resources"]
    fields = {
        write["update"]["name"]: write["update"]["fields"]
        for write in value["probes"][0]["body"]["writes"]
    }
    version = "2026-01-01T00:00:00Z"
    live = set()
    deletes = []

    def execute(operation):
        kind, resource = operation["kind"], operation.get("resource")
        if kind == "conditional-create-commit":
            live.update(resources)
            body = {"writeResults": [{"updateTime": version} for _ in resources]}
            status = 200
        elif kind == "cleanup-ownership-read" and resource == resources[0]:
            return {
                "complete": False,
                "failure": "response-lost",
                "rawBodyBase64": bad_raw,
            }
        elif kind == "cleanup-version-bound-delete":
            deletes.append(resource)
            live.remove(resource)
            body, status = {}, 200
        elif resource in live:
            body, status = (
                {"name": resource, "fields": fields[resource], "updateTime": version},
                200,
            )
        else:
            body, status = {"error": {"code": 404, "status": "NOT_FOUND"}}, 404
        raw = json.dumps(body, separators=(",", ":")).encode()
        return {
            "complete": True,
            "failure": None,
            "status": status,
            "body": body,
            "rawBodyBase64": base64.b64encode(raw).decode(),
            "bodyBytes": len(raw),
        }

    result = collect_local(value, execute, tmp_path / "run")
    assert result["completed"] is False
    assert result["cleanupComplete"] is False
    assert resources[0] in live
    assert resources[0] not in deletes
    assert (tmp_path / "run" / "result.json").exists()
    rows = [
        json.loads(path.read_text()) for path in (tmp_path / "run").glob("row-*.json")
    ]
    assert any(
        row["receipt"].get("failure") == "response-bytes-unavailable" for row in rows
    )


def test_the_refusal_message_is_recorded_and_bound_to_the_response_digest(tmp_path):
    """The message is part of the shape, so it cannot live only in a sidecar."""
    import sys as _sys

    _sys.path.insert(0, "tools/compat-broad/fs-request-bytes-boundary")
    from request_bytes_run_fixture import run_collector

    message = "Request payload size exceeds the limit: 11534336 bytes."
    result = run_collector(
        tmp_path / "run",
        over={
            "status": 400,
            "body": {
                "error": {
                    "code": 400,
                    "message": message,
                    "status": "INVALID_ARGUMENT",
                }
            },
        },
    )
    refusal = result["overRefusal"]
    assert refusal["message"] == message
    raw = json.dumps(
        {"error": {"code": 400, "message": message, "status": "INVALID_ARGUMENT"}},
        separators=(",", ":"),
    ).encode()
    assert refusal["responseBytes"] == len(raw)
    assert refusal["responseSha256"] == hashlib.sha256(raw).hexdigest()


# --- A long refusal message must not cost the run ----------------------------
#
# The response cap is 2 MiB and the final result is published under a 128 KiB
# row limit. Copying the message verbatim meant a long one completed every
# request, proved every resource absent, and then lost the whole run when
# result.json could not be written.


@pytest.mark.parametrize(
    ("label", "message"),
    [
        pytest.param(
            "normal",
            "Request payload size exceeds the limit: 11534336 bytes.",
            id="normal",
        ),
        pytest.param("ascii", "x" * (128 * 1024), id="128-kib-ascii"),
        pytest.param(
            "newlines", "\n" * (64 * 1024), id="64-kib-newlines-escaping-doubles"
        ),
    ],
)
def test_a_long_refusal_message_still_returns_a_final_result(tmp_path, label, message):
    import sys as _sys

    _sys.path.insert(0, "tools/compat-broad/fs-request-bytes-boundary")
    from request_bytes_collector import MAX_ROW_BYTES
    from request_bytes_run_fixture import run_collector, typed_400_with_message

    directory = tmp_path / label
    result = run_collector(directory, over=typed_400_with_message(message))
    published = (directory / "result.json").read_bytes()
    assert len(published) <= MAX_ROW_BYTES
    assert result["resourceAbsence"] is True
    assert result["completed"] is True
    refusal = result["overRefusal"]
    encoded = message.encode()
    assert refusal["messageBytes"] == len(encoded)
    assert refusal["messageSha256"] == hashlib.sha256(encoded).hexdigest()


def test_a_truncated_message_is_never_presented_as_the_whole_message(tmp_path):
    import sys as _sys

    _sys.path.insert(0, "tools/compat-broad/fs-request-bytes-boundary")
    from request_bytes_collector import MESSAGE_EXCERPT_BYTES
    from request_bytes_run_fixture import run_collector, typed_400_with_message

    message = "y" * (128 * 1024)
    result = run_collector(tmp_path / "run", over=typed_400_with_message(message))
    refusal = result["overRefusal"]
    assert refusal["messageTruncated"] is True
    # A reader that finds `message` may treat it as the whole text, so when the
    # text is partial the key is absent rather than holding a prefix.
    assert "message" not in refusal
    assert len(refusal["messageExcerpt"].encode()) <= MESSAGE_EXCERPT_BYTES


def test_the_full_message_survives_in_the_response_sidecar(tmp_path):
    """Bounding the result must not lose the observation."""
    import sys as _sys

    _sys.path.insert(0, "tools/compat-broad/fs-request-bytes-boundary")
    from request_bytes_run_fixture import run_collector, typed_400_with_message

    message = "z" * (128 * 1024)
    directory = tmp_path / "run"
    result = run_collector(directory, over=typed_400_with_message(message))
    refusal = result["overRefusal"]
    sidecar = directory / refusal["responseBodyFile"]
    raw = sidecar.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == refusal["responseSha256"]
    assert json.loads(raw)["error"]["message"] == message


def test_a_short_message_is_carried_whole(tmp_path):
    import sys as _sys

    _sys.path.insert(0, "tools/compat-broad/fs-request-bytes-boundary")
    from request_bytes_run_fixture import (
        EXPECTED_MESSAGE,
        run_collector,
        typed_400_with_message,
    )

    result = run_collector(
        tmp_path / "run", over=typed_400_with_message(EXPECTED_MESSAGE)
    )
    refusal = result["overRefusal"]
    assert refusal["messageTruncated"] is False
    assert refusal["message"] == EXPECTED_MESSAGE
    assert "messageExcerpt" not in refusal


# --- The final result must be publishable whatever the remote answers ---------


def test_the_publish_guard_names_the_field_that_grew():
    """A future inline field must fail here, not as a lost run in production."""
    import sys as _sys

    _sys.path.insert(0, "tools/compat-broad/fs-request-bytes-boundary")
    from request_bytes_collector import MAX_ROW_BYTES, _guard_publishable

    _guard_publishable({"completed": True, "failures": []})
    oversized = {
        "completed": True,
        "failures": [],
        "overRefusal": {"message": "x" * (2 * MAX_ROW_BYTES)},
    }
    with pytest.raises(ValueError) as raised:
        _guard_publishable(oversized)
    message = str(raised.value)
    assert "overRefusal" in message, "the guard must name the field that grew"
    assert str(MAX_ROW_BYTES) in message
    assert "bounded where it is written" in message


def test_the_guard_runs_before_the_result_is_published(tmp_path, monkeypatch):
    """The guard is on the path a real run takes, not only reachable directly."""
    import sys as _sys

    _sys.path.insert(0, "tools/compat-broad/fs-request-bytes-boundary")
    import request_bytes_collector as collector
    from request_bytes_run_fixture import run_collector, typed_400_with_message

    seen = []
    original = collector._guard_publishable

    def spy(result):
        seen.append(sorted(result))
        return original(result)

    monkeypatch.setattr(collector, "_guard_publishable", spy)
    run_collector(tmp_path / "run", over=typed_400_with_message("short message"))
    assert len(seen) == 1
    assert "overRefusal" in seen[0]


@pytest.mark.parametrize(
    "message",
    [
        pytest.param("x" * (128 * 1024), id="128-kib-ascii"),
        pytest.param("\n" * (64 * 1024), id="64-kib-newlines"),
    ],
)
def test_the_guard_never_fires_on_a_bounded_result(tmp_path, message):
    """Every field copied from a response is bounded, so the guard is silent."""
    import sys as _sys

    _sys.path.insert(0, "tools/compat-broad/fs-request-bytes-boundary")
    from request_bytes_run_fixture import run_collector, typed_400_with_message

    result = run_collector(tmp_path / "run", over=typed_400_with_message(message))
    assert result["completed"] is True
