"""Direct tests of the Gate facade: every admission check has a killing test.

The facade is the only line between the values the collector binds at run time
(page token, partition cursors, delete versions) and the wire, because the
shared Gate digests the frozen operation the facade returns while the wire
sends the runtime request. Each test below names, in its docstring, the mutant
of `partition_cursor_gate.py` it kills; the mutants are the independent review's
(G01..G18). Everything runs on a real Gate directory in tmp_path with an offline
oracle; no socket, no credential, no Ledger.
"""

import copy
import sys
import typing
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/o8-core"))
sys.path.insert(0, str(HERE))

import o4_partition_cursor_descriptor as campaign
import partition_cursor_gate as gate_projection
import shared_gate
from partition_cursor_case import compile_plan
from partition_cursor_gate import JOB, PartitionCursorGate
from partition_cursor_offline_fixture import TIME, partition_cursor
from test_partition_cursor_production import Clock, ProductionOracle

NONCE = "d" * 32


@pytest.fixture(autouse=True)
def clock(monkeypatch):
    monkeypatch.setattr(shared_gate, "time", Clock())


class Driver:
    """Drives the frozen schedule through the facade with honest requests."""

    def __init__(self, tmp_path, oracle_class=ProductionOracle, **options):
        self.plan = compile_plan(campaign.PROJECT, campaign.DATABASE, NONCE)
        self.gate_plan = campaign.gate_plan(self.plan, slot_seconds=6.0)
        # The facade is under test, not the management preflight.
        del self.gate_plan["management"]
        gate_projection.create(tmp_path / "gate", self.gate_plan)
        self.gate = PartitionCursorGate(tmp_path / "gate")
        self.gate.claim()
        self.oracle = oracle_class(self.plan, **options)
        self.schedule = self.gate_plan["jobs"][JOB]["schedule"]
        self.slot_map = gate_projection.slot_map(self.plan)
        self.gate_to_collector = {value: key for key, value in self.slot_map.items()}
        self.positions = {
            (entry["phase"], entry["index"]): position
            for position, entry in enumerate(self.schedule)
        }
        self.bodies = {}

    def frozen(self, phase, index):
        return self.gate.frozen_operation(phase, index)

    def runtime(self, phase, index):
        """The request the collector or the production ladder would send."""
        frozen = self.frozen(phase, index)
        collector_phase, collector_index = self.gate_to_collector[(phase, index)]
        request = {
            "phase": collector_phase,
            "index": collector_index,
            "kind": frozen["kind"],
            "method": frozen["method"],
            "path": frozen["path"],
            "body": copy.deepcopy(frozen["body"]),
        }
        kind = frozen["kind"]
        job = self.gate.snapshot()["jobs"][JOB]
        if kind == "partition-page-token-continuation":
            request["body"]["pageToken"] = self.bodies["partition-count-4-page-size-2"][
                "nextPageToken"
            ]
        elif kind.startswith("partition-reconstruction-range-"):
            partitions = self.bodies["partition-count-1"]["partitions"]
            slot = frozen["reconstructionSlot"]
            query = request["body"]["structuredQuery"]
            if slot:
                query["startAt"] = copy.deepcopy(partitions[slot - 1])
            if slot < len(partitions):
                query["endAt"] = copy.deepcopy(partitions[slot])
        elif kind == "cleanup-seed-delete":
            for write in request["body"]["writes"]:
                write["currentDocument"] = {
                    "updateTime": job["creationProofs"][write["delete"]]["updateTime"]
                }
        elif frozen["method"] == "DELETE":
            capture = job.get("captures", {}).get(str(frozen["versionFrom"]))
            if isinstance(capture, dict) and capture.get("status") == 200:
                request["path"] += (
                    "?currentDocument.updateTime=" + capture["updateTime"]
                )
        return request

    def dispatch(self, phase, index, request=None):
        request = self.runtime(phase, index) if request is None else request
        box = {}

        def send():
            receipt = self.oracle(request)
            box["body"] = receipt["body"]
            return receipt["status"], receipt["body"]

        result = self.gate.dispatch_slot(phase, index, request, send)
        if "body" in box:
            self.bodies[request["kind"]] = box["body"]
        return result

    def run_until(self, phase, index):
        """Dispatch every scheduled slot before the target, honestly."""
        target = self.positions[(phase, index)]
        job = self.gate.snapshot()["jobs"][JOB]
        for position in range(job["scheduleDone"], target):
            entry = self.schedule[position]
            if entry["phase"] == "observation" and job.get("stopReason") is not None:
                # The Gate's own recovery dispatch consumes these as skipped.
                continue
            self.dispatch(entry["phase"], entry["index"])

    def last_event(self):
        return self.gate.snapshot()["events"][-1]


class TamperingOracle(ProductionOracle):
    """An oracle whose answer for named kinds is replaced by the test."""

    overrides: typing.ClassVar[dict] = {}

    def _body(self, request):
        kind = request["kind"]
        if kind in self.overrides:
            return self.overrides[kind]
        return super()._body(request)


def test_the_frozen_schedule_places_residual_scans_before_the_root_ladder(tmp_path):
    """G18: residual scans sit after the seeded ladder and before the root's;
    the schedule ends on a recovery slot, or an abandoned run could never
    consume its tail."""
    driver = Driver(tmp_path)
    order = [(entry["phase"], entry["index"]) for entry in driver.schedule]
    residual = [driver.slot_map[("residual", index)] for index in range(2)]
    root_ladder = [
        driver.slot_map[("ladder", index)]
        for index in range(60, gate_projection.LADDER_DOCUMENTS * 3)
    ]
    seeded_last = driver.slot_map[("ladder", 59)]
    assert order[-1][0] == "recovery"
    assert order.index(seeded_last) < order.index(residual[0])
    assert order.index(residual[1]) < order.index(root_ladder[0])
    assert order[-3:] == root_ladder


def test_a_page_token_the_paged_response_did_not_supply_is_refused(tmp_path):
    """G01: the continuation must carry the token from this run's own paged
    response, not any token."""
    driver = Driver(tmp_path, partitions=1, page_token="this-run-token")
    driver.run_until("observation", 8)
    honest = driver.runtime("observation", 8)
    assert honest["body"]["pageToken"] == "this-run-token"
    forged = copy.deepcopy(honest)
    forged["body"]["pageToken"] = "another-token"
    with pytest.raises(ValueError, match="page token not supplied"):
        driver.gate.normalize("observation", 8, forged)
    assert driver.gate.normalize("observation", 8, honest)["kind"] == (
        "partition-page-token-continuation"
    )


def test_a_continuation_before_any_token_was_observed_is_refused(tmp_path):
    """G01/G16: no paged response carried a token, so no continuation can."""
    driver = Driver(tmp_path, partitions=1, page_token="")
    driver.run_until("observation", 8)
    request = driver.runtime("observation", 7)
    request["kind"] = "partition-page-token-continuation"
    request["body"]["pageToken"] = "invented"
    with pytest.raises(ValueError, match="page token not supplied"):
        driver.gate.normalize("observation", 8, request)


def test_a_token_from_another_partition_slot_is_not_the_continuation_token(tmp_path):
    """G16: only the `partition-count-4-page-size-2` response supplies the
    token; a token on the `partition-count-4` response is not harvested."""

    class Other(ProductionOracle):
        def _body(self, request):
            status, body = super()._body(request)
            if request["kind"] == "partition-count-4":
                body["nextPageToken"] = "from-the-wrong-slot"
            return status, body

    driver = Driver(tmp_path, Other, partitions=1, page_token="")
    driver.run_until("observation", 8)
    request = driver.runtime("observation", 7)
    request["kind"] = "partition-page-token-continuation"
    request["body"]["pageToken"] = "from-the-wrong-slot"
    with pytest.raises(ValueError, match="page token not supplied"):
        driver.gate.normalize("observation", 8, request)


def test_reconstruction_cursors_must_be_this_runs_partitions(tmp_path):
    """G02: a range bound to a cursor the partition response did not return is
    refused; the honest range is accepted."""
    driver = Driver(tmp_path, partitions=1, page_token="tok")
    driver.run_until("observation", 16)
    honest = driver.runtime("observation", 16)
    assert "endAt" in honest["body"]["structuredQuery"]
    forged = copy.deepcopy(honest)
    forged["body"]["structuredQuery"]["endAt"] = partition_cursor(
        driver.plan["ownedResources"][5]
    )
    with pytest.raises(ValueError, match="cursor differs"):
        driver.gate.normalize("observation", 16, forged)
    assert driver.gate.normalize("observation", 16, honest)["reconstructionSlot"] == 0


def test_partitions_come_only_from_the_single_split_point_response(tmp_path):
    """G15: the `partition-count-4` response returns other cursors; the
    reconstruction must follow `partition-count-1`, not the last partition
    response seen."""

    class Other(ProductionOracle):
        def _partition_cursors(self):
            names = self._seeded()
            if self.sent and self.sent[-1]["kind"] in (
                "partition-count-4",
                "partition-count-4-page-size-2",
            ):
                return [partition_cursor(names[3]), partition_cursor(names[7])]
            return super()._partition_cursors()

    driver = Driver(tmp_path, Other, partitions=1, page_token="tok")
    driver.run_until("observation", 16)
    assert len(driver.bodies["partition-count-4"]["partitions"]) == 2
    assert len(driver.bodies["partition-count-4-page-size-2"]["partitions"]) == 2
    honest = driver.runtime("observation", 16)
    forged = copy.deepcopy(honest)
    forged["body"]["structuredQuery"]["endAt"] = driver.bodies[
        "partition-count-4-page-size-2"
    ]["partitions"][0]
    with pytest.raises(ValueError, match="cursor differs"):
        driver.gate.normalize("observation", 16, forged)
    driver.gate.normalize("observation", 16, honest)


def test_extra_keys_in_a_reconstruction_query_are_refused(tmp_path):
    """G10: a query with a key the frozen slot does not carry differs."""
    driver = Driver(tmp_path, partitions=1, page_token="tok")
    driver.run_until("observation", 16)
    request = driver.runtime("observation", 16)
    request["body"]["structuredQuery"]["limit"] = 1
    with pytest.raises(ValueError, match="request differs"):
        driver.gate.normalize("observation", 16, request)
    request = driver.runtime("observation", 16)
    request["body"]["readTime"] = TIME
    with pytest.raises(ValueError, match="request differs"):
        driver.gate.normalize("observation", 16, request)


def test_a_request_whose_body_or_path_differs_from_the_frozen_slot_is_refused(tmp_path):
    """G10/G11: the plain slots are compared on method, path and body."""
    driver = Driver(tmp_path)
    driver.run_until("observation", 3)
    request = driver.runtime("observation", 3)
    request["body"]["structuredQuery"]["limit"] = 5
    with pytest.raises(ValueError, match="request differs"):
        driver.gate.normalize("observation", 3, request)
    request = driver.runtime("observation", 3)
    request["path"] = request["path"].replace(":runQuery", ":partitionQuery")
    with pytest.raises(ValueError, match="request differs"):
        driver.gate.normalize("observation", 3, request)
    request = driver.runtime("observation", 3)
    request["method"] = "GET"
    with pytest.raises(ValueError, match="request differs"):
        driver.gate.normalize("observation", 3, request)


def test_the_seed_delete_must_carry_the_journaled_creation_versions(tmp_path):
    """G03/G04/G17: every delete names a proven document with its proof
    version and nothing else."""
    driver = Driver(tmp_path, partitions=1, page_token="tok")
    driver.run_until("observation", 31)
    honest = driver.runtime("observation", 31)
    forged = copy.deepcopy(honest)
    forged["body"]["writes"][3]["currentDocument"]["updateTime"] = (
        "2026-01-01T00:00:00Z"
    )
    with pytest.raises(ValueError, match="not proven"):
        driver.gate.normalize("observation", 31, forged)
    forged = copy.deepcopy(honest)
    forged["body"]["writes"][3]["delete"] = driver.plan["ownedScope"] + "/cur/foreign"
    with pytest.raises(ValueError, match="not proven"):
        driver.gate.normalize("observation", 31, forged)
    forged = copy.deepcopy(honest)
    forged["body"]["writes"][3]["updateMask"] = {"fieldPaths": ["n"]}
    with pytest.raises(ValueError, match="frozen shape"):
        driver.gate.normalize("observation", 31, forged)
    forged = copy.deepcopy(honest)
    forged["body"]["writes"][3]["currentDocument"]["exists"] = True
    with pytest.raises(ValueError, match="frozen shape"):
        driver.gate.normalize("observation", 31, forged)
    forged = copy.deepcopy(honest)
    forged["body"]["writes"].pop()
    with pytest.raises(ValueError, match="delete batch differs"):
        driver.gate.normalize("observation", 31, forged)
    # G04: the frozen name itself is not enough; the journal must hold its
    # creation proof, or the delete is refused, never looked up blindly.
    unproven = honest["body"]["writes"][3]["delete"]
    with driver.gate.locked() as state:
        proof = state["jobs"][JOB]["creationProofs"].pop(unproven)
        shared_gate._save(driver.gate.path, state)
    with pytest.raises(ValueError, match="not proven"):
        driver.gate.normalize("observation", 31, honest)
    with driver.gate.locked() as state:
        state["jobs"][JOB]["creationProofs"][unproven] = proof
        shared_gate._save(driver.gate.path, state)
    assert (
        driver.gate.normalize("observation", 31, honest)["kind"]
        == "cleanup-seed-delete"
    )


def test_a_ladder_delete_version_must_match_the_read_and_the_proof(tmp_path):
    """G05/G05b/G06/G07: the delete carries the version its own ladder read
    captured, that read must equal the creation proof, and a resource without
    a proof is never deleted."""
    driver = Driver(tmp_path, partitions=1, page_token="tok")
    # Stop the observation early so the seeded documents are still present.
    driver.run_until("observation", 20)
    driver.gate.abandon_observation("test-stop")
    first_read = driver.slot_map[("ladder", 0)][1]
    driver.run_until("recovery", first_read)
    driver.dispatch("recovery", first_read)
    delete_index = first_read + 1
    resource = driver.frozen("recovery", delete_index)["resource"]
    honest = driver.runtime("recovery", delete_index)
    assert honest["path"].endswith("?currentDocument.updateTime=" + TIME)
    forged = copy.deepcopy(honest)
    forged["path"] = forged["path"].replace(TIME, "2026-01-01T00:00:00Z")
    with pytest.raises(ValueError, match="not proven"):
        driver.gate.normalize("recovery", delete_index, forged)
    forged = copy.deepcopy(honest)
    forged["path"] = forged["path"].split("?", 1)[0]
    with pytest.raises(ValueError, match="not proven"):
        driver.gate.normalize("recovery", delete_index, forged)
    with driver.gate.locked() as state:
        job = state["jobs"][JOB]
        proof = job["creationProofs"].pop(resource)
        shared_gate._save(driver.gate.path, state)
    with pytest.raises(ValueError, match="not proven"):
        driver.gate.normalize("recovery", delete_index, honest)
    with driver.gate.locked() as state:
        job = state["jobs"][JOB]
        job["creationProofs"][resource] = {
            **proof,
            "updateTime": "2026-01-01T00:00:00Z",
        }
        shared_gate._save(driver.gate.path, state)
    with pytest.raises(ValueError, match="not proven"):
        driver.gate.normalize("recovery", delete_index, honest)
    with driver.gate.locked() as state:
        state["jobs"][JOB]["creationProofs"][resource] = proof
        shared_gate._save(driver.gate.path, state)
    # G06: the ladder read must have seen the proof version. A read that saw
    # another version means the document changed since this run created it,
    # and a delete carrying the proof version must still be refused.
    with driver.gate.locked() as state:
        capture = state["jobs"][JOB]["captures"][str(first_read)]
        original_capture = dict(capture)
        capture["updateTime"] = "2026-01-01T00:00:00Z"
        shared_gate._save(driver.gate.path, state)
    with pytest.raises(ValueError, match="not proven"):
        driver.gate.normalize("recovery", delete_index, honest)
    with driver.gate.locked() as state:
        state["jobs"][JOB]["captures"][str(first_read)] = original_capture
        shared_gate._save(driver.gate.path, state)
    normalized = driver.gate.normalize("recovery", delete_index, honest)
    assert "versionFrom" not in normalized
    assert normalized["path"].endswith(
        "?currentDocument.updateTime=" + TIME.replace(":", "%3A")
    )


def test_a_ladder_delete_after_a_typed_absence_is_consumed_without_a_send(tmp_path):
    """The read found nothing, so the delete carries no version and the Gate
    skips the slot; the oracle sees no DELETE."""
    driver = Driver(tmp_path, partitions=1, page_token="tok")
    first_read = driver.slot_map[("ladder", 0)][1]
    driver.run_until("recovery", first_read)
    driver.dispatch("recovery", first_read)
    assert driver.last_event()["status"] == 404
    honest = driver.runtime("recovery", first_read + 1)
    assert "?" not in honest["path"]
    sent = len(driver.oracle.calls)
    outcome = driver.dispatch("recovery", first_read + 1, honest)
    assert outcome == (None, {"skipped": "absent-or-unavailable-cleanup-read"})
    assert len(driver.oracle.calls) == sent
    versioned = copy.deepcopy(honest)
    versioned["path"] += "?currentDocument.updateTime=" + TIME
    with pytest.raises(ValueError, match="request differs"):
        driver.gate.normalize("recovery", first_read + 1, versioned)


@pytest.mark.parametrize(
    "kind,status,body,message",
    [
        (
            "partition-count-1",
            200,
            {"partitions": "nope"},
            "G08: an untyped 200 partition body is not settled",
        ),
        (
            "partition-count-4",
            200,
            {"partitions": [{"values": []}]},
            "G08: a malformed cursor list is not settled",
        ),
        (
            "partition-count-1",
            503,
            {"unavailable": True},
            "G08: a 5xx with a plain body is not settled",
        ),
        (
            "partition-count-4",
            200,
            [{"readTime": TIME}],
            "G08: a stream answer to a partition query is not settled",
        ),
        (
            "partition-not-collection-group",
            400,
            {"error": {"code": 404, "status": "INVALID_ARGUMENT"}},
            "G13: a typed error whose code disagrees with the status is not settled",
        ),
    ],
)
def test_an_untyped_read_only_response_stops_the_run_unsettled(
    tmp_path, kind, status, body, message
):
    """G08/G13: every recognized read-only slot rejects an untyped response.

    The Shared Gate now recognizes partitionQuery as non-creating, so the
    refusal is recorded without a creation outcome while the facade still
    stops on malformed response bodies and mismatched typed errors.
    """

    class Untyped(TamperingOracle):
        overrides: typing.ClassVar[dict] = {kind: (status, body)}

    driver = Driver(tmp_path, Untyped, partitions=1, page_token="tok")
    index = next(
        position["index"]
        for position in (
            {"index": i}
            for i, op in enumerate(driver.gate_plan["jobs"][JOB]["observation"])
            if op["kind"] == kind
        )
    )
    driver.run_until("observation", index)
    with pytest.raises(ValueError, match="untyped|unusable"):
        driver.dispatch("observation", index)
    event = driver.last_event()
    assert event["failure"] == "UnsettledPartitionCursorResponse", message
    assert "creationOutcome" not in event
    assert driver.gate.snapshot()["jobs"][JOB]["stopped"] is True
    assert shared_gate.unconfirmed_creates(driver.gate.snapshot(), JOB) == 0


def test_a_delete_commit_acknowledging_fewer_writes_is_not_settled(tmp_path):
    """G09/G14: the delete Commit is settled only by an acknowledgement that
    carries one result per write and a commit time."""

    class Short(TamperingOracle):
        overrides: typing.ClassVar[dict] = {
            "cleanup-seed-delete": (
                200,
                {
                    "writeResults": [{"updateTime": TIME} for _ in range(19)],
                    "commitTime": TIME,
                },
            )
        }

    driver = Driver(tmp_path, Short, partitions=1, page_token="tok")
    driver.run_until("observation", 31)
    with pytest.raises(ValueError, match="untyped delete"):
        driver.dispatch("observation", 31)
    event = driver.last_event()
    assert event["creationOutcome"] == "unknown"
    assert event["failure"] == "UnsettledPartitionCursorResponse"
    assert driver.gate.snapshot()["jobs"][JOB]["stopped"] is True


def test_a_delete_commit_with_a_full_acknowledgement_is_settled(tmp_path):
    driver = Driver(tmp_path, partitions=1, page_token="tok")
    driver.run_until("observation", 31)
    driver.dispatch("observation", 31)
    event = driver.last_event()
    assert event["creationOutcome"] == "refused"
    assert event["settledBy"] == "partition-cursor-delete-commit"
    assert shared_gate.unconfirmed_creates(driver.gate.snapshot(), JOB) == 0


def test_a_typed_partition_refusal_is_settled_by_the_shared_gate_itself(tmp_path):
    driver = Driver(tmp_path, partitions=1, page_token="tok")
    driver.run_until("observation", 9)
    driver.dispatch("observation", 9)
    event = driver.last_event()
    assert event["status"] == 400
    assert "creationOutcome" not in event
    assert "settledBy" not in event
    assert shared_gate.unconfirmed_creates(driver.gate.snapshot(), JOB) == 0
