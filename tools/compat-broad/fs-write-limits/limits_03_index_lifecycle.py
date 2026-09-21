"""Closed, offline-plannable Firestore field-index lifecycle boundary.

The production entrypoint is deliberately absent: this module can construct a
bounded plan and exercise the same ordered effects against a loopback server,
but it cannot mint credentials, reserve a Ledger row, or contact Firestore.
"""

from __future__ import annotations

import copy
import hashlib
import json
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

PROJECT = "fireemu-35fe6"
DATABASE = "(default)"
COLLECTION_GROUP = "nx"
FIELD_PATH = "*"
REQUEST_COST_MICROUSD = 100
MIN_OPERATION_POLLS = 1
MAX_OPERATION_POLLS = 9


def _field_name() -> str:
    return (
        f"projects/{PROJECT}/databases/{DATABASE}/collectionGroups/"
        f"{COLLECTION_GROUP}/fields/{FIELD_PATH}"
    )


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _validate_baseline(baseline: dict[str, Any]) -> None:
    if not isinstance(baseline, dict) or baseline.get("name") != _field_name():
        raise ValueError("actual nx field baseline required")
    if "indexConfig" not in baseline:
        raise ValueError("actual index configuration required")
    if not isinstance(baseline["indexConfig"], dict):
        raise ValueError("actual index configuration must be an object")
    if not isinstance(baseline["indexConfig"].get("indexes"), list):
        raise ValueError("actual index configuration indexes must be a list")


def build_index_lifecycle_plan(
    baseline: dict[str, Any], *, poll_limit: int = MAX_OPERATION_POLLS
) -> dict[str, Any]:
    """Build a finite plan from the observed field, preserving unrelated config."""
    _validate_baseline(baseline)
    if type(poll_limit) is not int or not MIN_OPERATION_POLLS <= poll_limit <= MAX_OPERATION_POLLS:
        raise ValueError("finite operation poll limit required")
    before = copy.deepcopy(baseline)
    after_patch = copy.deepcopy(baseline)
    after_patch["indexConfig"] = {"indexes": []}
    restore_patch = copy.deepcopy(baseline)
    restore_patch["indexConfig"] = {}
    minimum_requests = 3 + 2 + 2 * MIN_OPERATION_POLLS
    maximum_requests = 3 + 2 + 2 * poll_limit
    return {
        "kind": "limits-03-index-lifecycle-plan-v1",
        "project": PROJECT,
        "database": DATABASE,
        "fieldName": _field_name(),
        "before": before,
        "beforeDigest": _digest(before),
        "afterPatch": after_patch,
        "restorePatch": restore_patch,
        "updateMask": "indexConfig",
        "operationPollLimit": poll_limit,
        "operationDeadlineSeconds": 12.0,
        "budget": {
            "minimumRequests": minimum_requests,
            "maximumRequests": maximum_requests,
            "requestCostMicrousd": REQUEST_COST_MICROUSD,
            "maximumCostMicrousd": maximum_requests * REQUEST_COST_MICROUSD,
        },
    }


def execute_production(*_args: Any, **_kwargs: Any) -> None:
    raise RuntimeError("production index lifecycle requires reviewed O8/Ledger integration")


def run_loopback_index_lifecycle(
    plan: dict[str, Any], *, operation_polls_before_done: int = 0
) -> dict[str, Any]:
    """Run the ordered lifecycle against a real loopback HTTP server.

    This is a boundary exercise, not a production transport. The production
    constructor remains refused; the server implements only the documented
    Field GET/PATCH and long-running Operation GET semantics.
    """
    if type(operation_polls_before_done) is not int or operation_polls_before_done < 0:
        raise ValueError("operation poll count must be non-negative")
    field_path = "/v1/" + plan["fieldName"]
    state = copy.deepcopy(plan["before"])
    operations: dict[str, dict[str, Any]] = {}
    requests: list[dict[str, Any]] = []
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: Any) -> None:
            return

        def _reply(self, status: int, value: dict[str, Any]) -> None:
            body = json.dumps(value, sort_keys=True).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            nonlocal state
            with lock:
                requests.append({"method": "GET", "path": self.path})
                if self.path == field_path:
                    self._reply(200, copy.deepcopy(state))
                    return
                if self.path.startswith("/v1/operations/"):
                    operation = operations.get(self.path)
                    if operation is None:
                        self._reply(404, {"error": "unknown operation"})
                        return
                    operation["polls"] += 1
                    self._reply(
                        200,
                        {
                            "name": self.path.removeprefix("/v1/"),
                            "done": operation["polls"] > operation_polls_before_done,
                        },
                    )
                    return
                self._reply(404, {"error": "unexpected path"})

        def do_PATCH(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            nonlocal state
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length))
            with lock:
                requests.append({"method": "PATCH", "path": self.path, "body": body})
                path, _, query = self.path.partition("?")
                if path != field_path or query != "updateMask=indexConfig":
                    self._reply(400, {"error": "exact indexConfig update mask required"})
                    return
                if body.get("name") != plan["fieldName"] or set(body) != {"name", "indexConfig"}:
                    self._reply(400, {"error": "exact field patch required"})
                    return
                if body["indexConfig"] == {"indexes": []}:
                    state = copy.deepcopy(plan["afterPatch"])
                elif body["indexConfig"] == {}:
                    state = copy.deepcopy(plan["before"])
                else:
                    self._reply(400, {"error": "unsupported index transition"})
                    return
                operation_path = f"/v1/operations/op-{len(operations) + 1}"
                operations[operation_path] = {"polls": 0}
                self._reply(200, {"name": operation_path.removeprefix("/v1/")})

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    events: list[dict[str, Any]] = []
    errors: list[str] = []
    started = time.monotonic()
    try:
        base_url = f"http://127.0.0.1:{server.server_port}"

        def call(method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
            data = None if body is None else json.dumps(body).encode()
            request = urllib.request.Request(base_url + path, data=data, method=method)
            if data is not None:
                request.add_header("Content-Type", "application/json")
            with urllib.request.urlopen(request, timeout=plan["operationDeadlineSeconds"]) as response:
                return json.loads(response.read())

        before = call("GET", field_path)
        if before != plan["before"]:
            raise ValueError("loopback before state differs")
        events.append({"kind": "read-before", "bodyDigest": _digest(before)})

        def transition(kind: str, patch: dict[str, Any]) -> None:
            response = call("PATCH", field_path + "?updateMask=indexConfig", patch)
            operation = "/v1/" + response["name"]
            events.append({"kind": kind, "operation": response["name"]})
            for _ in range(plan["operationPollLimit"]):
                status = call("GET", operation)
                if status.get("done") is True:
                    events.append({"kind": kind.replace("patch-", "poll-"), "operation": response["name"]})
                    return
            raise TimeoutError("bounded index operation poll limit exhausted")

        transition("patch-after", {"name": plan["fieldName"], "indexConfig": {"indexes": []}})
        after = call("GET", field_path)
        if after.get("indexConfig") != {"indexes": []} or after.get("ttlConfig") != plan["before"].get("ttlConfig"):
            raise ValueError("loopback after state differs")
        events.append({"kind": "read-after", "bodyDigest": _digest(after)})
        transition("patch-restore", {"name": plan["fieldName"], "indexConfig": {}})
        restored = call("GET", field_path)
        if restored != plan["before"]:
            raise ValueError("loopback restore differs from baseline")
        events.append({"kind": "read-restored", "bodyDigest": _digest(restored)})
        success = True
    except (OSError, TimeoutError, ValueError, urllib.error.URLError) as error:
        errors.append(type(error).__name__ + ": " + str(error))
        restored = copy.deepcopy(state)
        success = False
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    request_count = len(requests)
    return {
        "success": success,
        "restored": success and restored == plan["before"],
        "finalField": restored,
        "events": events,
        "requests": requests,
        "errors": errors,
        "budget": {
            "requests": request_count,
            "costMicrousd": request_count * REQUEST_COST_MICROUSD,
            "elapsedSeconds": time.monotonic() - started,
        },
        "heldOnFailure": not success,
    }
