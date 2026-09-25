from __future__ import annotations

import copy
import json
import multiprocessing
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import limits_03_index_lifecycle as lifecycle
import pytest
from limits_03_descriptor import REQUEST_COST_MICROUSD
from limits_03_index_lifecycle import (
    build_index_lifecycle_plan,
    execute_production,
    run_loopback_index_lifecycle,
)

FIELD = "projects/fireemu-35fe6/databases/(default)/collectionGroups/nx/fields/*"
ANCESTOR = "projects/fireemu-35fe6/databases/(default)/collectionGroups/__default__/fields/*"


def inherited_baseline() -> dict:
    return {
        "name": FIELD,
        "indexConfig": {
            "indexes": [],
            "usesAncestorConfig": True,
            "ancestorField": ANCESTOR,
            "reverting": False,
        },
        "ttlConfig": {"state": "ENABLED"},
    }


class LoopbackFieldServer:
    """Independent test fixture for the real urllib client."""

    def __init__(self, baseline: dict, *, operation_error: bool = False, pending_operation_error: bool = False, foreign_operation: bool = False, operation_suffix: str | None = None, polls_before_done: int = 0, drop_patch_response: bool = False, trickle_field_response: bool = False):
        self.state = copy.deepcopy(baseline)
        self.baseline = copy.deepcopy(baseline)
        self.operation_error = operation_error
        self.pending_operation_error = pending_operation_error
        self.foreign_operation = foreign_operation
        self.operation_suffix = operation_suffix
        self.polls_before_done = polls_before_done
        self.drop_patch_response = drop_patch_response
        self.trickle_field_response = trickle_field_response
        self.requests: list[dict] = []
        self.operations: dict[str, int] = {}
        state = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                return

            def reply(self, status, body):
                raw = json.dumps(body, sort_keys=True).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                state.requests.append({"method": "GET", "path": self.path})
                if self.path == "/v1/" + FIELD:
                    if state.trickle_field_response:
                        raw = json.dumps(copy.deepcopy(state.state), sort_keys=True).encode()
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(raw)))
                        self.end_headers()
                        self.wfile.write(raw[:1])
                        self.wfile.flush()
                        threading.Event().wait(2)
                    else:
                        self.reply(200, copy.deepcopy(state.state))
                    return
                if self.path.startswith("/v1/projects/fireemu-35fe6/databases/(default)/operations/"):
                    if self.path not in state.operations:
                        self.reply(404, {"error": {"status": "NOT_FOUND"}})
                        return
                    state.operations[self.path] += 1
                    if (state.operation_error or state.pending_operation_error) and len(state.operations) == 1:
                        self.reply(200, {"name": self.path.removeprefix("/v1/"), "done": not state.pending_operation_error, "error": {"status": "FAILED_PRECONDITION"}})
                    elif state.operations[self.path] <= state.polls_before_done:
                        self.reply(200, {"name": self.path.removeprefix("/v1/"), "done": False})
                    else:
                        self.reply(200, {"name": self.path.removeprefix("/v1/"), "done": True})
                    return
                self.reply(404, {"error": {"status": "NOT_FOUND"}})

            def do_PATCH(self):
                size = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(size))
                state.requests.append({"method": "PATCH", "path": self.path, "body": body})
                path, _, query = self.path.partition("?")
                if path != "/v1/" + FIELD or query != "updateMask=indexConfig":
                    self.reply(400, {"error": "scope"})
                    return
                operation = "/v1/projects/fireemu-35fe6/databases/(default)/operations/op-" + str(len(state.operations) + 1)
                state.operations[operation] = 0
                if body.get("indexConfig") == {"indexes": []}:
                    state.state = {**state.state, "indexConfig": {"indexes": [], "usesAncestorConfig": False, "ancestorField": ANCESTOR, "reverting": False}}
                elif "indexConfig" not in body or body.get("indexConfig") == {}:
                    state.state = copy.deepcopy(state.baseline)
                else:
                    self.reply(400, {"error": "transition"})
                    return
                name = "projects/other/databases/(default)/operations/foreign" if state.foreign_operation else operation.removeprefix("/v1/")
                if state.operation_suffix is not None:
                    name = "projects/fireemu-35fe6/databases/(default)/operations/" + state.operation_suffix
                if state.drop_patch_response and len([request for request in state.requests if request["method"] == "PATCH"]) == 1:
                    self.connection.close()
                    return
                self.reply(200, {"name": name})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def test_plan_binds_actual_baseline_and_counts_every_index_lifecycle_call() -> None:
    baseline = {
        "name": "projects/fireemu-35fe6/databases/(default)/collectionGroups/nx/fields/*",
        "indexConfig": {"indexes": [], "usesAncestorConfig": True, "ancestorField": ANCESTOR, "reverting": False},
        "ttlConfig": {"state": "ENABLED"},
    }

    plan = build_index_lifecycle_plan(baseline)

    assert plan["fieldName"] == baseline["name"]
    assert plan["before"] == baseline
    assert plan["afterPatch"]["indexConfig"] == {"indexes": []}
    assert plan["restorePatch"] == {"name": FIELD}
    assert "ttlConfig" not in plan["afterPatch"]
    assert "ttlConfig" not in plan["restorePatch"]
    assert plan["updateMask"] == "indexConfig"
    assert plan["budget"]["minimumRequests"] == 7
    assert plan["budget"]["maximumRequests"] == 23
    assert plan["budget"]["requestCostMicrousd"] == REQUEST_COST_MICROUSD
    assert plan["budget"]["maximumCostMicrousd"] == 23 * REQUEST_COST_MICROUSD


def test_loopback_lifecycle_patches_polls_reads_and_restores_exact_baseline() -> None:
    baseline = inherited_baseline()
    server = LoopbackFieldServer(baseline)
    try:
        receipt = run_loopback_index_lifecycle(build_index_lifecycle_plan(baseline), server.origin)
    finally:
        server.close()

    assert receipt["success"] is True
    assert receipt["restored"] is True
    assert receipt["finalField"] == baseline
    assert receipt["budget"]["requests"] == 7
    assert receipt["budget"]["costMicrousd"] == 7 * REQUEST_COST_MICROUSD
    assert [event["kind"] for event in receipt["events"]] == [
        "read-before",
        "patch-after",
        "poll-after",
        "read-after",
        "patch-restore",
        "poll-restore",
        "read-restored",
    ]


def test_lifecycle_holds_on_bounded_poll_timeout_and_has_no_production_escape() -> None:
    baseline = inherited_baseline()
    server = LoopbackFieldServer(baseline, polls_before_done=2)
    plan = build_index_lifecycle_plan(baseline, poll_limit=2)
    try:
        receipt = run_loopback_index_lifecycle(plan, server.origin)
    finally:
        server.close()

    assert receipt["success"] is False
    assert receipt["heldOnFailure"] is True
    assert receipt["restored"] is False
    assert receipt["budget"]["requests"] == 7
    with pytest.raises(TypeError, match="ManagementSession"):
        execute_production(management_session=plan, phase="observation")


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: {**value, "name": value["name"].replace("fireemu-35fe6", "other")},
        lambda value: {**value, "indexConfig": {"indexes": "not-a-list"}},
    ],
)
def test_plan_refuses_nonactual_or_malformed_baseline(mutation) -> None:
    baseline = inherited_baseline()

    with pytest.raises((TypeError, ValueError), match="baseline|index configuration"):
        build_index_lifecycle_plan(mutation(baseline))


def test_explicit_custom_baseline_is_refused_before_any_wire() -> None:
    custom = inherited_baseline()
    custom["indexConfig"] = {"indexes": [{"order": "ASCENDING"}], "usesAncestorConfig": False, "ancestorField": ANCESTOR, "reverting": False}
    with pytest.raises(ValueError, match="inherited"):
        build_index_lifecycle_plan(custom)


def test_mutated_compiled_plan_is_rejected_before_any_wire() -> None:
    baseline = inherited_baseline()
    plan = build_index_lifecycle_plan(baseline)
    plan["before"]["ttlConfig"]["state"] = "DISABLED"
    with pytest.raises(ValueError, match="mutated"):
        run_loopback_index_lifecycle(plan, "http://127.0.0.1:1")


@pytest.mark.parametrize("server_kwargs", [{"operation_error": True}, {"pending_operation_error": True}, {"foreign_operation": True}])
def test_operation_error_or_foreign_route_attempts_bounded_restore(server_kwargs) -> None:
    baseline = inherited_baseline()
    server = LoopbackFieldServer(baseline, **server_kwargs)
    try:
        receipt = run_loopback_index_lifecycle(build_index_lifecycle_plan(baseline), server.origin)
    finally:
        server.close()

    assert receipt["success"] is False
    assert receipt["heldOnFailure"] is True
    assert [request["method"] for request in server.requests].count("PATCH") == 2
    assert receipt["budget"]["requests"] >= 3


@pytest.mark.parametrize("operation_suffix", ["", "op-1?fragment", "op-1#fragment"])
def test_empty_or_ambiguous_operation_suffix_is_rejected(operation_suffix) -> None:
    baseline = inherited_baseline()
    server = LoopbackFieldServer(baseline, operation_suffix=operation_suffix)
    try:
        receipt = run_loopback_index_lifecycle(build_index_lifecycle_plan(baseline), server.origin)
    finally:
        server.close()

    assert receipt["success"] is False
    assert receipt["heldOnFailure"] is True
    assert receipt["budget"]["requests"] == 3


def test_lost_patch_response_marks_apply_and_restores_once() -> None:
    baseline = inherited_baseline()
    server = LoopbackFieldServer(baseline, drop_patch_response=True)
    try:
        receipt = run_loopback_index_lifecycle(build_index_lifecycle_plan(baseline), server.origin)
    finally:
        server.close()

    assert receipt["success"] is False
    assert receipt["restored"] is True
    assert receipt["heldOnFailure"] is True
    assert [request["method"] for request in server.requests].count("PATCH") == 2
    assert not [process for process in multiprocessing.active_children() if process.is_alive()]


def test_trickled_response_has_hard_deadline_and_reaps_worker() -> None:
    baseline = inherited_baseline()
    server = LoopbackFieldServer(baseline, trickle_field_response=True)
    started = time.monotonic()
    try:
        with pytest.raises(TimeoutError, match="timed out|deadline"):
            lifecycle._request_bounded(server.origin, "GET", "/v1/" + FIELD, None, started + 0.2)
    finally:
        server.close()

    assert time.monotonic() - started < 1.5
    assert not [process for process in multiprocessing.active_children() if process.is_alive()]
