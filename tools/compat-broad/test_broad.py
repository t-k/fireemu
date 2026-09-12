"""Offline boundaries of the broad local runner; no oracle calls."""

import pytest
from broad_contract import catalog, compare_program, local_origin


def program():
    return {
        "id": "a",
        "steps": [{"id": "create", "body": {"value": 1}}, {"id": "read"}],
    }


def test_comparison_preserves_types_missing_fields_and_order():
    p = program()
    historical = {
        "create": {
            "production": {
                "status": 200,
                "code": "OK",
                "body": {"x": 1, "list": [1, 2]},
            }
        },
        "read": {"production": {"status": 400, "code": "DENIED"}},
    }
    actual: dict = {
        "steps": {
            "create": {
                "status": 200,
                "code": "OK",
                "body": {"x": True, "list": [2, 1]},
            },
            "read": {"status": 400, "code": "DENIED"},
        }
    }
    result = compare_program(p, p, actual, historical)
    assert [r["status"] for r in result] == ["mismatch", "match"]
    assert result[0]["firstDifference"] == "$.body.list[0]"
    changed = {
        "steps": {
            "create": {
                "status": 200,
                "code": "OK",
                "body": {"x": 1, "list": [1, 2], "extra": None},
            }
        }
    }
    assert compare_program(p, p, changed, historical)[0]["status"] == "mismatch"


def test_same_id_changed_operation_is_not_compared():
    p = program()
    old = {**p, "steps": [{"id": "create", "body": {"value": 2}}, {"id": "read"}]}
    assert all(
        r["status"] == "indeterminate"
        for r in compare_program(p, old, {"steps": {}}, {})
    )


def test_missing_timeout_and_unobserved_rows_never_pass():
    p = program()
    rows = compare_program(
        p, p, {"steps": {"create": {"status": 0, "code": "probe-error"}}}, {}
    )
    assert all(r["status"] in {"not-run", "indeterminate"} for r in rows)


@pytest.mark.parametrize(
    "value",
    [
        "https://firestore.googleapis.com",
        "http://example.com",
        "http://127.0.0.1@evil.test",
        "http://127.0.0.1:1/path",
        "http://127.0.0.1:1?x=1",
        "http://localhost:80",
    ],
)
def test_remote_or_ambiguous_origins_are_refused(value):
    with pytest.raises(ValueError):
        local_origin(value)


def test_os_assigned_loopback_origin_is_accepted():
    assert local_origin("http://127.0.0.1:12345") == "http://127.0.0.1:12345"


def test_inventory_retains_unexecuted_editions_and_protocols():
    value = catalog()
    assert len(value["surfaces"]) >= 169
    ids = {f["id"] for f in value["families"]}
    assert {
        "auth-tenants",
        "auth-mfa",
        "fs-listen",
        "fs-enterprise",
        "fs-sdk",
        "fs-rules",
    } <= ids
    assert all(f["currentStatus"] == "not-run" for f in value["families"])
    assert all(s["currentStatus"] == "not-run" for s in value["surfaces"])
