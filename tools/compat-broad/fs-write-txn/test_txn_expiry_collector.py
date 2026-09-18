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
    """A control-clock advance that reports the virtual seconds it applied."""

    def advance(seconds):
        record.append(seconds)
        return seconds

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
        assert entry["measuredSeconds"] > 0
        assert entry["requestedSeconds"] > 0
        assert entry["startedAt"].endswith("Z")
        assert entry["endedAt"].endswith("Z")


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


class LockingEndpoint(Endpoint):
    """An endpoint that models per-transaction document locks.

    A transactional read takes the lock. An out-of-band write to a locked
    document is refused with ABORTED, exactly as a backend under pessimistic
    concurrency does, so a collector that never releases its transactions
    cannot delete what it created.
    """

    def __init__(self):
        super().__init__()
        self.locks = {}
        self.rollbacks = []

    def __call__(self, request):
        rpc = request["rpc"]
        body = request.get("body") or {}
        if rpc == "GetDocument":
            token = (request.get("query") or {}).get("transaction")
            if token is not None:
                self.locks[request["name"]] = token
            return super().__call__(request)
        if rpc == "Rollback":
            token = body.get("transaction")
            self.rollbacks.append(token)
            self.locks = {k: v for k, v in self.locks.items() if v != token}
            return super().__call__(request)
        if rpc == "Commit":
            token = body.get("transaction")
            for write in body.get("writes", []):
                target = write.get("delete") or write["update"]["name"]
                holder = self.locks.get(target)
                if holder is not None and holder != token:
                    self.calls.append(request)
                    return {
                        "code": 10,
                        "status": "ABORTED",
                        "message": "Too much contention on these documents.",
                    }
            return super().__call__(request)
        return super().__call__(request)


def test_wall_clock_elapsed_is_measured_not_copied_from_the_plan():
    clock = {"now": 0.0}

    def sleeper(seconds):
        clock["now"] += seconds

    receipt = collector.collect(
        options(timing=collector.WALL_CLOCK),
        Endpoint(),
        sleeper=sleeper,
        monotonic=lambda: clock["now"],
        wall=lambda: 1_800_000_000 + clock["now"],
    )
    waited = [row["waited"] for row in receipt["rows"] if row["waited"]]
    assert waited
    for entry in waited:
        assert entry["measuredSeconds"] == pytest.approx(entry["requestedSeconds"])
        assert entry["checkpoints"] >= 1


def test_a_sleeper_that_does_not_sleep_produces_zero_measured_elapsed():
    receipt = collector.collect(
        options(timing=collector.WALL_CLOCK),
        Endpoint(),
        sleeper=lambda seconds: None,
        monotonic=lambda: 0.0,
        wall=lambda: 1_800_000_000.0,
    )
    waited = [row["waited"] for row in receipt["rows"] if row["waited"]]
    assert waited
    for entry in waited:
        assert entry["measuredSeconds"] == 0
        assert entry["requestedSeconds"] > 0
    idle = [row["idleSeconds"] for row in receipt["rows"] if "idleSeconds" in row]
    assert idle and all(value == 0 for value in idle)


def test_idle_seconds_are_attributed_to_the_transaction_that_holds_the_lock():
    receipt = collector.collect(
        options(), Endpoint(), advance=advances([]), monotonic=lambda: 0.0
    )
    rows = {row["caseId"]: row for row in receipt["rows"] if row["caseId"]}
    assert rows["idle-expiry/commit-before-idle"]["idleOfTransaction"] == "d"
    assert rows["idle-expiry/commit-before-idle"]["idleSeconds"] == 20
    assert rows["idle-expiry/commit-after-idle"]["idleOfTransaction"] == "a"
    assert rows["idle-expiry/commit-after-idle"]["idleSeconds"] == 90
    assert rows["idle-expiry/rollback-after-idle"]["idleSeconds"] == 90


def test_wall_clock_waits_are_served_in_bounded_checkpointed_steps():
    clock = {"now": 0.0}
    seen = []

    def sleeper(seconds):
        assert seconds <= collector.CHECKPOINT_SECONDS
        clock["now"] += seconds

    receipt = collector.collect(
        options(timing=collector.WALL_CLOCK),
        Endpoint(),
        sleeper=sleeper,
        monotonic=lambda: clock["now"],
        wall=lambda: 1_800_000_000 + clock["now"],
        checkpoint=seen.append,
    )
    assert receipt["checkpoints"]
    assert seen == receipt["checkpoints"]
    assert len(seen) == (20 + 70) / collector.CHECKPOINT_SECONDS


def test_an_abort_after_the_locks_are_taken_still_returns_every_document():
    endpoint = LockingEndpoint()

    def monotonic():
        # Time jumps forward the moment all four transactional reads have taken
        # their locks, so the run aborts with every transaction still open.
        return 10_000.0 if len(endpoint.locks) >= 4 else 0.0

    receipt = collector.collect(
        options(),
        endpoint,
        advance=advances([]),
        monotonic=monotonic,
    )
    assert receipt["failure"] == "deadline-reached"
    released = {entry["transaction"] for entry in receipt["transactionReleases"]}
    assert released, "no transaction was released"
    assert receipt["openTransactions"] == []
    assert receipt["unrecovered"] == [], receipt["cleanup"]
    assert endpoint.rollbacks


def test_an_open_transaction_left_behind_makes_the_receipt_incomplete():
    def refusing(request):
        if request["rpc"] == "Rollback":
            return {"code": 3, "status": "INVALID_ARGUMENT", "message": "no"}
        return Endpoint()(request)

    endpoint = Endpoint()

    def transport(request):
        if request["rpc"] == "Rollback" and request["body"].get("transaction"):
            endpoint.calls.append(request)
            return {"code": 3, "status": "INVALID_ARGUMENT", "message": "refused"}
        return endpoint(request)

    receipt = collector.collect(
        options(), transport, advance=advances([]), monotonic=lambda: 0.0
    )
    assert receipt["openTransactions"]
    assert receipt["complete"] is False


def test_every_request_carries_the_plan_s_per_request_timeout():
    endpoint = Endpoint()
    collector.collect(options(), endpoint, advance=advances([]), monotonic=lambda: 0.0)
    timeouts = {call["timeoutSeconds"] for call in endpoint.calls}
    assert timeouts
    assert all(isinstance(value, int) and value > 0 for value in timeouts)
    assert plan_module.CONTENDED_REQUEST_TIMEOUT_SECONDS in timeouts
    assert plan_module.DEFAULT_REQUEST_TIMEOUT_SECONDS in timeouts


def _aborting_rollback(message):
    """An endpoint whose rollbacks are refused with ABORTED."""
    endpoint = Endpoint()

    def transport(request):
        if request["rpc"] == "Rollback":
            endpoint.calls.append(request)
            return {"code": 10, "status": "ABORTED", "message": message}
        return endpoint(request)

    return endpoint, transport


def test_a_contention_abort_does_not_count_as_releasing_a_transaction():
    _endpoint, transport = _aborting_rollback(
        "Too much contention on these documents. Please try again."
    )
    receipt = collector.collect(
        options(), transport, advance=advances([]), monotonic=lambda: 0.0
    )
    releases = receipt["transactionReleases"]
    assert releases
    unproven = [e for e in releases if e["idleSeconds"] is None]
    assert unproven, "a transaction that never took a lock must not be released"
    for entry in unproven:
        assert entry["released"] is False
        assert entry["failure"] == "rollback-aborted-without-proven-expiry"
        assert entry["message"]
    assert receipt["openTransactions"]
    assert receipt["complete"] is False


def test_an_expired_transaction_abort_counts_as_released_and_keeps_the_message():
    message = "The referenced transaction has expired or is no longer valid."
    _endpoint, transport = _aborting_rollback(message)
    receipt = collector.collect(
        options(), transport, advance=advances([]), monotonic=lambda: 0.0
    )
    expired = [
        entry
        for entry in receipt["transactionReleases"]
        if entry["idleSeconds"] is not None
        and entry["idleSeconds"] >= cases.DECLARED_IDLE_LIMIT_SECONDS
    ]
    assert expired
    for entry in expired:
        assert entry["released"] is True
        assert entry["expiryProven"] is True
        assert entry["message"] == message


def test_every_release_records_the_rollback_message():
    receipt = collector.collect(
        options(), Endpoint(), advance=advances([]), monotonic=lambda: 0.0
    )
    for entry in receipt["transactionReleases"]:
        assert "message" in entry
        assert "idleSeconds" in entry


class StatefulEndpoint:
    """An endpoint that keeps documents and honours create-only preconditions.

    The plain ``Endpoint`` above answers every write with OK, which cannot show
    what happens when the workspace this run means to create is already
    occupied. This one refuses a conditional create against an existing
    document, records every write that landed on a document it did not create,
    and remembers every delete.
    """

    def __init__(self, *, preexisting_role=None, prefix_owner=None):
        self.calls = []
        self.documents = {}
        self.foreign = set()
        self.deletes = []
        self.issued = 0
        self.preexisting_role = preexisting_role
        self.prefix_owner = prefix_owner

    def attach(self, collection):
        if self.preexisting_role:
            name = collection._name(self.preexisting_role)
            self.documents[name] = {"external": {"stringValue": "KEEP-THIS"}}
            self.foreign.add(name)

    def writes_to(self, name):
        """Every write this endpoint accepted or refused for one document."""
        found = []
        for call in self.calls:
            for write in (call.get("body") or {}).get("writes") or []:
                if (write.get("delete") or write.get("update", {}).get("name")) == name:
                    found.append(write)
        return found

    def __call__(self, request):
        self.calls.append(request)
        rpc = request["rpc"]
        if rpc == "BeginTransaction":
            self.issued += 1
            token = base64.b64encode(f"token-{self.issued}".encode()).decode()
            return {
                "code": 0,
                "status": "OK",
                "message": None,
                "complete": True,
                "body": {"transaction": token},
            }
        if rpc == "Rollback":
            return {
                "code": 0,
                "status": "OK",
                "message": None,
                "complete": True,
                "body": {},
            }
        if rpc == "GetDocument":
            name = request["name"]
            if name not in self.documents:
                return {
                    "code": 5,
                    "status": "NOT_FOUND",
                    "message": "not found",
                    "complete": True,
                }
            return {
                "code": 0,
                "status": "OK",
                "message": None,
                "complete": True,
                "body": {
                    "name": name,
                    "fields": dict(self.documents[name]),
                    "updateTime": "2026-09-18T00:00:00.000001Z",
                },
            }
        if rpc == "Commit":
            writes = request["body"]["writes"]
            for write in writes:
                name = write.get("delete") or write["update"]["name"]
                current = write.get("currentDocument") or {}
                if current.get("exists") is False and name in self.documents:
                    return {
                        "code": 6,
                        "status": "ALREADY_EXISTS",
                        "message": "already exists",
                        "complete": True,
                    }
            for write in writes:
                if "delete" in write:
                    self.deletes.append(write["delete"])
                    self.documents.pop(write["delete"], None)
                else:
                    name = write["update"]["name"]
                    self.documents[name] = dict(write["update"]["fields"])
            return {
                "code": 0,
                "status": "OK",
                "message": None,
                "complete": True,
                "body": {
                    "writeResults": [
                        {"updateTime": "2026-09-18T00:00:00.000001Z"} for _ in writes
                    ]
                },
            }
        raise AssertionError(f"unexpected rpc {rpc}")


def run_against(endpoint, **overrides):
    """Drive one collection against an endpoint that needs the plan to attach."""
    prepared = collector.validate_collector_options(options(**overrides))
    plan = plan_module.compile_plan(
        prepared["nonce"],
        prepared["ownerId"],
        project=prepared["projectId"],
        database=prepared["database"],
    )
    collection = collector.Collection(
        options(**overrides),
        plan,
        endpoint,
        advance=advances([]),
        monotonic=lambda: 0.0,
    )
    endpoint.attach(collection)
    return collection.run(), collection


def test_a_clean_workspace_establishes_every_precondition():
    endpoint = StatefulEndpoint()
    receipt, _ = run_against(endpoint)
    assert receipt["failure"] is None
    established = {
        entry["role"] for entry in receipt["preconditions"] if entry["created"]
    }
    assert established == set(cases.RESOURCE_ROLES)
    assert receipt["complete"] is True


def test_a_foreign_document_blocks_every_later_mutation_of_that_resource():
    """A document this run did not create is never overwritten and never deleted."""
    endpoint = StatefulEndpoint(preexisting_role="control")
    receipt, collection = run_against(endpoint)
    name = collection._name("control")
    writes = endpoint.writes_to(name)
    assert len(writes) == 1, writes
    assert writes[0]["currentDocument"] == {"exists": False}
    assert endpoint.deletes == []
    assert endpoint.documents[name] == {"external": {"stringValue": "KEEP-THIS"}}
    assert receipt["failure"] == "precondition-not-established"
    assert receipt["complete"] is False


def test_a_foreign_document_at_a_locked_role_is_preserved_too():
    endpoint = StatefulEndpoint(preexisting_role="locked-b")
    receipt, collection = run_against(endpoint)
    name = collection._name("locked-b")
    assert endpoint.documents[name] == {"external": {"stringValue": "KEEP-THIS"}}
    assert name not in endpoint.deletes
    assert endpoint.writes_to(name) == [
        {
            "update": {
                "name": name,
                "fields": collector._marker_fields(OWNER, "locked-b", NONCE, "created"),
            },
            "currentDocument": {"exists": False},
        }
    ]
    assert receipt["failure"] == "precondition-not-established"
    # Everything this run did create before it stopped is still given back.
    recovered = {e["role"] for e in receipt["cleanup"] if e["complete"]}
    assert recovered == {"control", "locked-a"}
    assert receipt["unrecovered"] == []


def test_cleanup_binds_to_this_run_s_creation_evidence_not_the_current_marker():
    endpoint = StatefulEndpoint(preexisting_role="control")
    receipt, _ = run_against(endpoint)
    entries = {entry["role"]: entry for entry in receipt["cleanup"]}
    assert entries["control"]["createdByThisRun"] is False
    assert entries["control"]["failure"] == "not-created-by-this-run"
    assert entries["control"]["skipped"] is True
    assert "control" not in receipt["unrecovered"]


def test_a_preflight_read_that_proves_nothing_stops_the_run():
    """An OK GetDocument without a document body is not proof of anything."""

    def transport(request):
        if request["rpc"] == "GetDocument":
            return {
                "code": 0,
                "status": "OK",
                "message": None,
                "complete": True,
                "body": {},
            }
        return {
            "code": 0,
            "status": "OK",
            "message": None,
            "complete": True,
            "body": {},
        }

    receipt = collector.collect(
        options(), transport, advance=advances([]), monotonic=lambda: 0.0
    )
    assert receipt["failure"] == "incomplete-response"
