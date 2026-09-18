"""The collector stays bounded, owns what it creates and always tries recovery.

These checks are offline and structural. They fix the collector's contract: the
deadline, the ownership proof, the cleanup order and the receipt shape. The
actual transaction semantics are verified separately against the real emulator
by the local shadow, not here.
"""

import base64
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parents[1]))

import txn_expiry_cases as cases
import txn_expiry_collector as collector
import txn_expiry_plan as plan_module

NONCE = "o3expiry-0000000000000001"
OWNER = "11111111222233334444555566667777"
PROJECT = "fireemu-test"


def options(**overrides):
    value = {
        "target": "local",
        "host": "127.0.0.1",
        "port": 8080,
        "projectId": PROJECT,
        "database": "(default)",
        "nonce": NONCE,
        "ownerId": OWNER,
        "timing": collector.CONTROL_CLOCK,
        "deadlineSeconds": 300,
    }
    value.update(overrides)
    return value


class Endpoint:
    """An offline endpoint that answers the plan's requests in order."""

    def __init__(self, *, deletable=True, owned=True):
        self.calls = []
        self.deletable = deletable
        self.owned = owned
        self.issued = 0
        self.documents = {}

    def __call__(self, request):
        self.calls.append(request)
        rpc = request["rpc"]
        if rpc == "BeginTransaction":
            self.issued += 1
            token = base64.b64encode(f"token-{self.issued}".encode()).decode()
            return {"code": 0, "status": "OK", "body": {"transaction": token}}
        if rpc == "Rollback":
            return {"code": 0, "status": "OK", "body": {}}
        if rpc == "Commit":
            for write in request["body"]["writes"]:
                if "delete" in write:
                    if not self.deletable:
                        return {
                            "code": 9,
                            "status": "FAILED_PRECONDITION",
                            "message": "precondition",
                        }
                    self.documents.pop(write["delete"], None)
                else:
                    self.documents[write["update"]["name"]] = write["update"]["fields"]
            return {"code": 0, "status": "OK", "body": {"writeResults": []}}
        if rpc == "GetDocument":
            name = request["name"]
            if name not in self.documents:
                return {"code": 5, "status": "NOT_FOUND", "message": "not found"}
            fields = dict(self.documents[name])
            if not self.owned:
                fields["owner"] = {"stringValue": "someone-else"}
            return {
                "code": 0,
                "status": "OK",
                "body": {
                    "name": name,
                    "fields": fields,
                    "updateTime": "2026-09-18T00:00:00.000001Z",
                },
            }
        raise AssertionError(f"unexpected rpc {rpc}")


def advances(record):
    def advance(seconds):
        record.append(seconds)

    return advance


def test_options_reject_a_non_loopback_local_target():
    with pytest.raises(ValueError):
        collector.validate_collector_options(options(host="example.test"))


def test_options_reject_a_production_target_off_the_fixed_host():
    with pytest.raises(ValueError):
        collector.validate_collector_options(
            options(target="production", host="127.0.0.1", timing=collector.WALL_CLOCK)
        )


def test_production_elapsed_time_cannot_be_simulated():
    with pytest.raises(ValueError):
        collector.validate_collector_options(
            options(
                target="production",
                host=collector.PRODUCTION_HOST,
                timing=collector.CONTROL_CLOCK,
            )
        )


def test_options_reject_a_malformed_nonce_or_deadline():
    with pytest.raises(ValueError):
        collector.validate_collector_options(options(nonce="short"))
    with pytest.raises(ValueError):
        collector.validate_collector_options(options(deadlineSeconds=0))
    with pytest.raises(ValueError):
        collector.validate_collector_options(
            options(deadlineSeconds=plan_module.WALL_SECONDS + 1)
        )


def test_control_clock_timing_requires_an_advance_callable():
    plan = plan_module.compile_plan(NONCE, OWNER, project=PROJECT)
    with pytest.raises(ValueError):
        collector.Collection(options(), plan, Endpoint())


def test_ownership_proof_requires_owner_role_nonce_and_update_time():
    fields = collector._marker_fields(OWNER, "control", NONCE, "created")
    document = {"fields": fields, "updateTime": "t"}
    assert collector.is_owned(document, OWNER, "control", NONCE)
    assert not collector.is_owned({"fields": fields}, OWNER, "control", NONCE)
    assert not collector.is_owned(document, OWNER, "locked-a", NONCE)
    assert not collector.is_owned(document, OWNER, "control", "other-nonce")
    assert not collector.is_owned(document, "0" * 32, "control", NONCE)


def test_a_full_pass_observes_every_case_and_recovers_every_resource():
    waits = []
    receipt = collector.collect(
        options(), Endpoint(), advance=advances(waits), monotonic=lambda: 0.0
    )
    observed = {row["caseId"] for row in receipt["rows"] if row["caseId"]}
    assert observed == {case["id"] for case in cases.CASES}
    assert receipt["missingCases"] == []
    assert receipt["unrecovered"] == []
    assert receipt["complete"] is True
    assert receipt["failure"] is None
    assert sum(waits) == cases.maximum_elapsed_seconds()


def test_each_case_row_carries_its_expected_local_result():
    receipt = collector.collect(
        options(), Endpoint(), advance=advances([]), monotonic=lambda: 0.0
    )
    for row in receipt["rows"]:
        if not row["caseId"]:
            assert "expectedLocal" not in row
            continue
        expected = collector.CASE_BY_ID[row["caseId"]]["expectedLocal"]
        assert row["expectedLocal"] == expected


def test_receipt_records_the_timing_mechanism():
    receipt = collector.collect(
        options(), Endpoint(), advance=advances([]), monotonic=lambda: 0.0
    )
    assert receipt["timing"] == collector.CONTROL_CLOCK
    waited = [row["waited"] for row in receipt["rows"] if row["waited"]]
    assert waited
    for entry in waited:
        assert entry["mode"] == collector.CONTROL_CLOCK
        assert entry["seconds"] > 0


def test_cleanup_never_deletes_a_document_it_cannot_prove_it_owns():
    endpoint = Endpoint(owned=False)
    receipt = collector.collect(
        options(), endpoint, advance=advances([]), monotonic=lambda: 0.0
    )
    deletes = [
        write
        for call in endpoint.calls
        if call["rpc"] == "Commit"
        for write in call["body"]["writes"]
        if "delete" in write
    ]
    assert deletes == []
    assert receipt["unrecovered"]
    for entry in receipt["cleanup"]:
        assert entry["failure"] == "ownership-not-proven"
        assert entry["skipped"] is True


def test_cleanup_deletes_under_the_observed_update_time():
    endpoint = Endpoint()
    collector.collect(options(), endpoint, advance=advances([]), monotonic=lambda: 0.0)
    deletes = [
        write
        for call in endpoint.calls
        if call["rpc"] == "Commit"
        for write in call["body"]["writes"]
        if "delete" in write
    ]
    assert deletes
    for write in deletes:
        assert write["currentDocument"]["updateTime"]


def test_a_refused_delete_is_retained_not_reported_as_recovered():
    receipt = collector.collect(
        options(),
        Endpoint(deletable=False),
        advance=advances([]),
        monotonic=lambda: 0.0,
    )
    assert receipt["complete"] is False
    assert sorted(receipt["unrecovered"]) == sorted(cases.RESOURCE_ROLES)
    for entry in receipt["cleanup"]:
        assert entry["failure"] == "conditional-delete-refused"


def test_the_deadline_stops_observation_and_cleanup_still_runs():
    ticks = iter([0.0] + [1000.0] * 200)
    receipt = collector.collect(
        options(),
        Endpoint(),
        advance=advances([]),
        monotonic=lambda: next(ticks),
    )
    assert receipt["failure"] == "deadline-reached"
    assert receipt["missingCases"]
    assert receipt["cleanup"]
    assert all(entry["skipped"] for entry in receipt["cleanup"])


def test_every_document_the_collector_touches_is_below_its_own_prefix():
    endpoint = Endpoint()
    collector.collect(options(), endpoint, advance=advances([]), monotonic=lambda: 0.0)
    prefix = f"documents/{plan_module.document_prefix(NONCE)}/"
    for call in endpoint.calls:
        if call["name"]:
            assert prefix in call["name"]
        for write in (call["body"] or {}).get("writes", []) if call["body"] else []:
            target = write.get("delete") or write["update"]["name"]
            assert prefix in target


def test_transport_failures_are_retained_not_turned_into_semantics():
    def failing(request):
        if request["rpc"] == "BeginTransaction":
            return {"code": None, "status": None, "message": None, "complete": False}
        return {"code": 0, "status": "OK", "body": {}}

    receipt = collector.collect(
        options(), failing, advance=advances([]), monotonic=lambda: 0.0
    )
    assert receipt["failure"] == "incomplete-response"
    assert receipt["complete"] is False


def test_receipt_binds_the_case_table_and_source_digest():
    receipt = collector.collect(
        options(), Endpoint(), advance=advances([]), monotonic=lambda: 0.0
    )
    assert receipt["casesDigest"] == cases.cases_digest()
    assert receipt["sourceDigest"] == plan_module.source_digest()
