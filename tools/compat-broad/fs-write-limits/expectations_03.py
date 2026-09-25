"""Local expectation kernel for FS-WRITE-LIMITS-03.

These are local state invariants over an already collected journal. They are not
a production-reference comparator and they never certify acquisition. A complete
response that violates an expectation is recorded as a mismatch, not discarded.
"""

from __future__ import annotations

from typing import Any

# `shadow` puts the shared `tools/compat-broad` directory on the path, so it is
# imported before anything that lives there.
from compiler_03 import dispatched_operations
from shadow import digest, resolve_recovery, typed_absence

MUTATING = ("POST", "PATCH", "DELETE")


def _typed_error(status: Any, body: Any, code: int, name: str) -> bool:
    error = body.get("error") if isinstance(body, dict) else None
    return (
        type(status) is int
        and status == code
        and isinstance(error, dict)
        and error.get("code") == code
        and error.get("status") == name
    )


def owned_documents(plan: dict) -> list[dict]:
    """Documents this campaign owns and must reclaim.

    A name that exceeds a request-stage identifier limit is probed but never
    owned: the API does not consider it a resource, so typed absence cannot be
    proven for it and the Gate cannot release it.
    """
    return [document for document in plan["documents"].values() if document["owned"]]


def preflight_count(plan: dict) -> int:
    """Number of leading typed-absence preflights; every owned document has one."""
    count = 0
    for request in plan["requests"]:
        if request["kind"] != "preflight-typed-absence":
            break
        count += 1
    if count != len(owned_documents(plan)):
        raise ValueError("every owned document needs a leading absence preflight")
    return count


def _document_for(plan: dict, resource: str) -> dict | None:
    for document in plan["documents"].values():
        if document["resource"] == resource:
            return document
    return None


def _batch_landed(request: dict, status: Any, body: Any) -> dict[str, str]:
    """Return resource to version for the writes this response acknowledges."""
    landed: dict[str, str] = {}
    if status != 200 or not isinstance(body, dict):
        return landed
    writes = request["body"]["writes"]
    statuses, results = body.get("status"), body.get("writeResults")
    if (
        not isinstance(statuses, list)
        or not isinstance(results, list)
        or len(statuses) != len(writes)
        or len(results) != len(writes)
    ):
        return landed
    for write, entry, result in zip(writes, statuses, results, strict=True):
        update = write.get("update") if isinstance(write, dict) else None
        if (
            not isinstance(entry, dict)
            or entry.get("code", 0) != 0
            or not isinstance(update, dict)
            or not isinstance(result, dict)
        ):
            continue
        version = result.get("updateTime")
        if isinstance(version, str) and version:
            landed[update["name"]] = version
    return landed


def evaluate_rows(rows: list[dict], plan: dict, *, excused=()) -> list[dict]:
    """Evaluate an observation prefix against the declared local expectations.

    Every problem is returned; `excused` only labels them. A row is excused
    because of something about the side that produced this journal, never
    because of anything in the plan, so the caller supplies the set and a
    production collector supplies none. The plan's own `pendingReason` is
    documentation, not an instruction to skip a check: leaving it in the
    compiled request would excuse a production row as readily as a local one.
    """
    excused = set(excused)
    problems: list[dict] = []
    versions: dict[str, str] = {}
    operations = dispatched_operations(plan)
    for index, row in enumerate(rows):
        if (
            index >= len(operations)
            or row.get("index") != index
            or row.get("request") != operations[index]
        ):
            problems.append(
                {
                    "index": index,
                    "basis": "request identity/order mismatch",
                    "pending": False,
                }
            )
            continue
        request = plan["requests"][index]
        status, body = row.get("status"), row.get("body")
        if (
            row.get("complete") is not True
            or row.get("failure") is not None
            or type(status) is not int
        ):
            continue  # Infrastructure failures are not API semantic mismatches.
        reason = _row_reason(request, plan, status, body, versions)
        if reason:
            problem = {"index": index, "basis": reason, "pending": index in excused}
            declared = request["expect"].get("pendingReason")
            if problem["pending"] and declared:
                problem["reason"] = declared
            problems.append(problem)
    return problems


def pending_rows(plan: dict) -> list[int]:
    """Rows a local run may excuse, because the local side cannot show them.

    This is the candidate set a local caller passes as `excused`. It is never
    consulted by the collector or by any production path.
    """
    return [
        index
        for index, request in enumerate(
            plan["requests"][
                : len(plan["localGatePlan"]["jobs"]["limits"]["observation"])
            ]
        )
        if request["expect"].get("pendingReason")
    ]


def _row_reason(
    request: dict, plan: dict, status: int, body: Any, versions: dict[str, str]
) -> str | None:
    kind = request["kind"]
    expect = request["expect"]
    if kind == "batch-write":
        return _batch_reason(request, status, body, versions)
    resource = request["path"].split("?", 1)[0].removeprefix("/v1/")
    document = _document_for(plan, resource)
    if kind == "create-only-patch" and expect["positive"] is False:
        if not _typed_error(status, body, 400, "INVALID_ARGUMENT"):
            return "negative boundary was not refused with INVALID_ARGUMENT"
        return None
    if kind == "refusal-consistency-readback":
        if not _typed_error(status, body, 400, "INVALID_ARGUMENT"):
            return "a read of the refused name was not refused the same way"
        return None
    if expect.get("status") == 404:
        if not typed_absence(status, body):
            return "typed resource absence not proven"
        return None
    if (
        status != 200
        or not isinstance(body, dict)
        or body.get("name") != resource
        or body.get("fields") != document["fields"]
        or not isinstance(body.get("updateTime"), str)
        or not body["updateTime"]
    ):
        return "exact typed document/version not returned"
    if kind == "create-only-patch":
        versions[resource] = body["updateTime"]
        return None
    if resource in versions and body["updateTime"] != versions[resource]:
        return "readback changed the recorded creation version"
    versions.setdefault(resource, body["updateTime"])
    return None


def _batch_reason(
    request: dict, status: int, body: Any, versions: dict[str, str]
) -> str | None:
    expect = request["expect"]
    writes = request["body"]["writes"]
    if expect["status"] == 400:
        if not _typed_error(status, body, 400, "INVALID_ARGUMENT"):
            return "whole-request refusal was not a typed INVALID_ARGUMENT"
        return None
    if status != 200 or not isinstance(body, dict):
        return "BatchWrite did not return a per-item response"
    statuses, results = body.get("status"), body.get("writeResults")
    if (
        not isinstance(statuses, list)
        or not isinstance(results, list)
        or len(statuses) != len(writes)
        or len(results) != len(writes)
    ):
        return "BatchWrite did not return one status and one result per write"
    for entry, expected in zip(statuses, expect["itemCodes"], strict=True):
        if not isinstance(entry, dict) or entry.get("code", 0) != expected:
            return "BatchWrite per-item status codes differ from the expectation"
    landed = _batch_landed(request, status, body)
    if sorted(landed) != sorted(expect["landed"]):
        return "BatchWrite acknowledged a different set of writes"
    versions.update(landed)
    return None


def writes_safe(rows: list[dict], plan: dict, *, excused=()) -> bool:
    """Only a proven-absent namespace and intact controls authorize a mutation.

    Unlike the limits-02 collector this gates every mutating method, because
    this campaign sends its first writes over `:batchWrite` rather than `PATCH`.
    """
    excused = set(excused)
    preflights = preflight_count(plan)
    if len(rows) < preflights:
        return False
    operations = dispatched_operations(plan)
    versions: dict[str, str] = {}
    for index, row in enumerate(rows):
        if (
            index >= len(operations)
            or row.get("index") != index
            or digest(row.get("request")) != digest(operations[index])
            or row.get("complete") is not True
            or row.get("failure") is not None
            or row.get("dispatchFailure") is not None
        ):
            return False
        status, body = row.get("status"), row.get("body")
        if index < preflights:
            if not typed_absence(status, body):
                return False
            continue
        request = plan["requests"][index]
        if index in excused:
            # A row the caller has excused cannot serve as a safety invariant
            # for that run. Its journal integrity is still checked above; only
            # its API outcome is excused, and only when a caller asks.
            continue
        if request["kind"] == "batch-write":
            versions.update(_batch_landed(request, status, body))
            continue
        if request["kind"] in (
            "name-boundary-readback",
            "refusal-consistency-readback",
        ):
            continue
        resource = request["path"].split("?", 1)[0].removeprefix("/v1/")
        document = _document_for(plan, resource)
        if request["method"] == "PATCH" and request["expect"].get("positive") is True:
            if not _created(status, body, resource, document):
                return False
            versions[resource] = body["updateTime"]
        elif request["method"] == "GET" and resource in versions:
            if (
                not _created(status, body, resource, document)
                or body["updateTime"] != versions[resource]
            ):
                return False
    return True


def _created(status: Any, body: Any, resource: str, document: dict | None) -> bool:
    return (
        type(status) is int
        and status == 200
        and isinstance(body, dict)
        and body.get("name") == resource
        and document is not None
        and digest(body.get("fields")) == digest(document["fields"])
        and isinstance(body.get("updateTime"), str)
        and bool(body["updateTime"])
    )


def expected_landed(rows: list[dict], plan: dict) -> dict[str, str]:
    """Resources the observation journal says were created, with their versions."""
    landed: dict[str, str] = {}
    for index, row in enumerate(rows):
        if index >= len(plan["requests"]) or row.get("status") != 200:
            continue
        request = plan["requests"][index]
        body = row.get("body")
        if request["kind"] == "batch-write":
            landed.update(_batch_landed(request, row["status"], body))
        elif request["kind"] == "create-only-patch" and isinstance(body, dict):
            version = body.get("updateTime")
            if isinstance(version, str) and version:
                landed[request["path"].split("?", 1)[0].removeprefix("/v1/")] = version
    return landed


def validate_cleanup(receipt: dict, plan: dict) -> bool:
    """Check ordered cleanup against the Gate's creation proofs and journal."""
    gate_plan = plan["localGatePlan"]
    declared = gate_plan["jobs"]["limits"]
    operations = declared["recovery"]
    cleanup, gate = receipt.get("cleanup"), receipt.get("gate")
    if (
        not isinstance(cleanup, list)
        or len(cleanup) != len(operations)
        or not isinstance(gate, dict)
        or gate.get("plan") != gate_plan
        or gate.get("planDigest") != digest(gate_plan)
    ):
        return False
    jobs = gate.get("jobs")
    job = jobs.get("limits") if isinstance(jobs, dict) else None
    if (
        not isinstance(job, dict)
        or job.get("complete") is not True
        or job.get("inflight") is not False
        or job.get("observation") != len(declared["observation"])
        or job.get("recovery") != len(operations)
        or job.get("resources") != declared["resources"]
        or not isinstance(job.get("absent"), list)
        or sorted(job["absent"]) != sorted(declared["resources"])
    ):
        return False
    proofs = job.get("creationProofs")
    landed = expected_landed(receipt["rows"], plan)
    if not isinstance(proofs, dict) or sorted(proofs) != sorted(landed):
        return False
    for name, proof in proofs.items():
        if proof.get("name") != name or proof.get("updateTime") != landed[name]:
            return False
    for index, (row, declared_op) in enumerate(zip(cleanup, operations, strict=True)):
        if (
            not isinstance(row, dict)
            or row.get("index") != index
            or row.get("request") != resolve_recovery(declared_op, cleanup[:index])
            or row.get("complete") is not True
            or row.get("failure") is not None
            or row.get("dispatchFailure") is not None
        ):
            return False
        resource = declared_op["path"].removeprefix("/v1/")
        status, body = row.get("status"), row.get("body")
        stage = index % 3
        if stage == 1:
            if resource in proofs:
                if type(status) is not int or status != 200 or row.get("skipped"):
                    return False
            elif (
                status is not None
                or row.get("skipped") is not True
                or body != {"skipped": "absent-or-unavailable-cleanup-read"}
            ):
                return False
        elif stage == 2 or resource not in proofs:
            if not typed_absence(status, body) or row.get("skipped"):
                return False
        else:
            proof = proofs[resource]
            if (
                type(status) is not int
                or status != 200
                or row.get("skipped")
                or not isinstance(body, dict)
                or body.get("name") != resource
                or digest(body.get("fields")) != proof["fieldsDigest"]
                or body.get("updateTime") != proof["updateTime"]
            ):
                return False
    return True


def validate_local_receipt(receipt: dict, plan: dict, *, excused=()) -> bool:
    if receipt.get("productionExecuted") is not False or any(
        receipt.get(key) is not True
        for key in (
            "recordingComplete",
            "stateValidation",
            "cleanupComplete",
            "completed",
        )
    ):
        return False
    rows = receipt.get("rows")
    return (
        isinstance(rows, list)
        and len(rows) == len(plan["localGatePlan"]["jobs"]["limits"]["observation"])
        and all(
            row.get("complete") is True
            and row.get("failure") is None
            and type(row.get("status")) is int
            for row in rows
        )
        and not [
            problem
            for problem in evaluate_rows(rows, plan, excused=excused)
            if not problem["pending"]
        ]
        and validate_cleanup(receipt, plan)
        and receipt.get("resourceAbsence")
        == {d["resource"]: True for d in owned_documents(plan)}
    )
