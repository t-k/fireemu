"""Bounded Firestore Admin Field index lifecycle client."""

from __future__ import annotations

import copy
import hashlib
import json
import multiprocessing
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from limits_03_descriptor import REQUEST_COST_MICROUSD

PROJECT = "fireemu-35fe6"
DATABASE = "(default)"
COLLECTION_GROUP = "nx"
FIELD_PATH = "*"
ANCESTOR_FIELD = "projects/fireemu-35fe6/databases/(default)/collectionGroups/__default__/fields/*"
MIN_OPERATION_POLLS = 1
MAX_OPERATION_POLLS = 9
MAX_RESPONSE_BYTES = 64 * 1024


def _field_name() -> str:
    return f"projects/{PROJECT}/databases/{DATABASE}/collectionGroups/{COLLECTION_GROUP}/fields/{FIELD_PATH}"


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _validate_baseline(baseline: dict[str, Any]) -> None:
    if not isinstance(baseline, dict) or baseline.get("name") != _field_name():
        raise ValueError("actual nx field baseline required")
    config = baseline.get("indexConfig")
    if not isinstance(config, dict) or not isinstance(config.get("indexes"), list):
        raise TypeError("actual index configuration required")
    if config.get("usesAncestorConfig") is not True or config.get("ancestorField") != ANCESTOR_FIELD or config.get("reverting", False) is not False:
        raise ValueError("only the verified inherited nx baseline is supported")


def _plan_payload(baseline: dict[str, Any], poll_limit: int) -> dict[str, Any]:
    minimum_requests = 3 + 2 * MIN_OPERATION_POLLS + 2
    maximum_requests = 3 + 2 * poll_limit + 2
    return {
        "kind": "limits-03-index-lifecycle-plan-v2",
        "project": PROJECT,
        "database": DATABASE,
        "fieldName": _field_name(),
        "before": copy.deepcopy(baseline),
        "beforeDigest": _digest(baseline),
        "afterPatch": {"name": _field_name(), "indexConfig": {"indexes": []}},
        # Firestore documents an unset indexConfig as the ancestor restore.
        "restorePatch": {"name": _field_name()},
        "updateMask": "indexConfig",
        "operationPollLimit": poll_limit,
        "operationDeadlineSeconds": 12.0,
        "recoveryDeadlineSeconds": 12.0,
        "responseByteLimit": MAX_RESPONSE_BYTES,
        "budget": {
            "minimumRequests": minimum_requests,
            "maximumRequests": maximum_requests,
            "primaryReserveRequests": 3 + poll_limit,
            "recoveryReserveRequests": 2 + poll_limit,
            "requestCostMicrousd": REQUEST_COST_MICROUSD,
            "maximumCostMicrousd": maximum_requests * REQUEST_COST_MICROUSD,
        },
    }


def build_index_lifecycle_plan(baseline: dict[str, Any], *, poll_limit: int = MAX_OPERATION_POLLS) -> dict[str, Any]:
    _validate_baseline(baseline)
    if type(poll_limit) is not int or not MIN_OPERATION_POLLS <= poll_limit <= MAX_OPERATION_POLLS:
        raise ValueError("finite operation poll limit required")
    payload = _plan_payload(baseline, poll_limit)
    return {**payload, "planDigest": _digest(payload)}


def _validate_plan(plan: dict[str, Any]) -> None:
    if not isinstance(plan, dict) or not isinstance(plan.get("before"), dict):
        raise TypeError("closed index lifecycle plan required")
    rebuilt = build_index_lifecycle_plan(plan["before"], poll_limit=plan.get("operationPollLimit", -1))
    if plan != rebuilt:
        raise ValueError("index lifecycle plan was mutated after compilation")


def _loopback_origin(origin: str) -> str:
    parsed = urllib.parse.urlparse(origin)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"} or parsed.username is not None or parsed.password is not None or parsed.path not in ("", "/") or parsed.query or parsed.fragment or parsed.port is None:
        raise ValueError("verified loopback origin required")
    return origin.rstrip("/")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any):
        raise ValueError("redirect refused")


def _request(opener, origin: str, method: str, path: str, body: dict[str, Any] | None, deadline: float) -> dict[str, Any]:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("request deadline exhausted")
    data = None if body is None else json.dumps(body, sort_keys=True).encode()
    request = urllib.request.Request(origin + path, data=data, method=method)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    with opener.open(request, timeout=remaining) as response:
        length = response.headers.get("Content-Length")
        if length is not None and int(length) > MAX_RESPONSE_BYTES:
            raise ValueError("response exceeds bounded limit")
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ValueError("response exceeds bounded limit")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise TypeError("bounded JSON object required")
    return value


def _request_worker(connection, origin: str, method: str, path: str, body: dict[str, Any] | None, deadline: float) -> None:
    try:
        opener = urllib.request.build_opener(_NoRedirect())
        connection.send(("ok", _request(opener, origin, method, path, body, deadline)))
    except (OSError, TimeoutError, ValueError, urllib.error.URLError) as error:
        connection.send(("error", type(error).__name__, str(error)))
    finally:
        connection.close()


def _request_bounded(origin: str, method: str, path: str, body: dict[str, Any] | None, deadline: float) -> dict[str, Any]:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("request deadline exhausted")
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe(duplex=False)
    process = context.Process(target=_request_worker, args=(child, origin, method, path, body, deadline))
    process.start()
    child.close()
    try:
        if not parent.poll(remaining):
            process.terminate()
            process.join(timeout=1)
            if process.is_alive():
                process.kill()
                process.join(timeout=1)
            raise TimeoutError("request absolute deadline exhausted")
        try:
            result = parent.recv()
        except EOFError as error:
            raise OSError("bounded request worker exited without a result") from error
    finally:
        parent.close()
        if process.is_alive():
            process.terminate()
        process.join(timeout=1)
    if not result or result[0] != "ok":
        error_type, message = result[1], result[2]
        if error_type == "TimeoutError":
            raise TimeoutError(message)
        if error_type == "ValueError":
            raise ValueError(message)
        raise OSError(f"bounded request failed: {error_type}: {message}")
    return result[1]


def _validate_operation_name(name: Any) -> str:
    prefix = f"projects/{PROJECT}/databases/{DATABASE}/operations/"
    if not isinstance(name, str) or not name.startswith(prefix):
        raise ValueError("operation route is outside the bound project and database")
    operation_id = name.removeprefix(prefix)
    if re.fullmatch(r"[A-Za-z0-9._~-]+", operation_id) is None:
        raise ValueError("operation route is outside the bound project and database")
    return name


def run_loopback_index_lifecycle(plan: dict[str, Any], origin: str) -> dict[str, Any]:
    """Run against an independently owned verified loopback origin."""
    _validate_plan(plan)
    origin = _loopback_origin(origin)
    field_path = "/v1/" + plan["fieldName"]
    events: list[dict[str, Any]] = []
    errors: list[str] = []
    requests = 0
    applied = False
    restored = False
    final_field: dict[str, Any] | None = None
    started = time.monotonic()
    observation_deadline = started + plan["operationDeadlineSeconds"]
    recovery_deadline: float | None = None
    restore_attempted = False

    def call(method, path, body, deadline):
        nonlocal requests
        requests += 1
        return _request_bounded(origin, method, path, body, deadline)

    def transition(kind, patch, deadline):
        nonlocal applied, restore_attempted
        if kind == "patch-restore":
            restore_attempted = True
        if kind == "patch-after":
            applied = True
        response = call("PATCH", field_path + "?updateMask=indexConfig", patch, deadline)
        name = response.get("name")
        name = _validate_operation_name(name)
        events.append({"kind": kind, "operation": name})
        for _ in range(plan["operationPollLimit"]):
            status = call("GET", "/v1/" + name, None, deadline)
            if status.get("error") is not None:
                raise ValueError("index operation reported an error")
            if status.get("done") is True:
                events.append({"kind": kind.replace("patch-", "poll-"), "operation": name})
                return
        raise TimeoutError("bounded absolute operation deadline exhausted")

    try:
        before = call("GET", field_path, None, observation_deadline)
        if before != plan["before"]:
            raise ValueError("actual before state differs from compiled baseline")
        events.append({"kind": "read-before", "bodyDigest": _digest(before)})
        transition("patch-after", plan["afterPatch"], observation_deadline)
        after = call("GET", field_path, None, observation_deadline)
        expected_after_config = {
            "indexes": [],
            "usesAncestorConfig": False,
            "ancestorField": ANCESTOR_FIELD,
            "reverting": False,
        }
        after_config = after.get("indexConfig")
        normalized_after = {
            "indexes": after_config.get("indexes", []) if isinstance(after_config, dict) else None,
            "usesAncestorConfig": after_config.get("usesAncestorConfig", False) if isinstance(after_config, dict) else None,
            "ancestorField": after_config.get("ancestorField") if isinstance(after_config, dict) else None,
            "reverting": after_config.get("reverting", False) if isinstance(after_config, dict) else None,
        }
        if normalized_after != expected_after_config or after.get("ttlConfig") != plan["before"].get("ttlConfig"):
            raise ValueError("after state differs or unrelated configuration changed")
        events.append({"kind": "read-after", "bodyDigest": _digest(after)})
        recovery_deadline = time.monotonic() + plan["recoveryDeadlineSeconds"]
        transition("patch-restore", plan["restorePatch"], recovery_deadline)
        final_field = call("GET", field_path, None, recovery_deadline)
        if final_field != plan["before"]:
            raise ValueError("restored state differs from compiled baseline")
        events.append({"kind": "read-restored", "bodyDigest": _digest(final_field)})
        restored = True
    except (OSError, TimeoutError, ValueError, urllib.error.URLError) as error:
        errors.append(type(error).__name__ + ": " + str(error))
        if applied and not restored and not restore_attempted:
            try:
                recovery_deadline = time.monotonic() + plan["recoveryDeadlineSeconds"]
                transition("patch-restore", plan["restorePatch"], recovery_deadline)
                final_field = call("GET", field_path, None, recovery_deadline)
                restored = final_field == plan["before"]
                if restored:
                    events.append({"kind": "read-restored", "bodyDigest": _digest(final_field)})
                else:
                    errors.append("ValueError: bounded restoration did not match baseline")
            except (OSError, TimeoutError, ValueError, urllib.error.URLError) as recovery_error:
                errors.append("recovery " + type(recovery_error).__name__ + ": " + str(recovery_error))
    return {
        "success": restored and not errors,
        "restored": restored,
        "finalField": final_field,
        "events": events,
        "errors": errors,
        "budget": {"requests": requests, "costMicrousd": requests * REQUEST_COST_MICROUSD, "elapsedSeconds": time.monotonic() - started},
        "heldOnFailure": not (restored and not errors),
    }


def execute_production(*, management_session: Any, phase: str) -> dict[str, Any]:
    """Run one capability-bound lifecycle phase through the existing Gate session."""
    from limits_03_preflight import ManagementSession

    if not isinstance(management_session, ManagementSession):
        raise TypeError("existing capability-bound ManagementSession required")
    if phase not in ("observation", "recovery"):
        raise ValueError("closed lifecycle phase required")
    management_session.run(phase)
    return {
        "phase": phase,
        "events": [row for row in management_session.evidence if "index-lifecycle" in row["id"]],
        "restored": phase == "recovery" and not management_session.lifecycle_failed,
    }
