import base64
import hashlib
import json
import sys

import pytest

sys.path.insert(0, "tools/compat-broad/fs-request-bytes-boundary")
sys.path.insert(0, "tools/compat-broad")

from request_bytes_collector import (
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
    assert result["overRefusal"] == {
        "httpStatus": over_status,
        "errorCode": over_status,
        "errorStatus": "INVALID_ARGUMENT",
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
                        "writeResults": [
                            {"updateTime": version} for _ in resources
                        ]
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
