"""Two closed REST sequences through the existing local Adapter; never production."""

from __future__ import annotations

import itertools

# ruff: noqa: BLE001 -- Preserve independent observation and recovery failures.
import json
import multiprocessing as mp
import time
from urllib.parse import quote

from batch_adapter import Adapter, observer_digest
from batch_contract import BASE, candidate
from broad_contract import digest
from shared_gate import Gate

LEGACY_CAMPAIGN_OBSERVER_SHA256 = (
    "074ab9bf07e137418a03f39472f77c4ff1b1c85a539d7d80a4c94d2f0b7b028e"
)


def op(path, method="GET", body=None):
    return {
        "service": "firestore",
        "path": "/v1/" + path,
        "method": method,
        "body": body,
        "privileged": True,
        "form": False,
    }


def field(value, resource=None):
    return {
        "a": {"integerValue": str(value)},
        **({"_sharedOwner": {"referenceValue": resource}} if resource is not None else {}),
    }


def manifest(nonce):
    """Current unobserved v2 fixtures own the _sharedOwner reference field."""
    if len(nonce) != 32 or any(c not in "0123456789abcdef" for c in nonce):
        raise ValueError("fresh hexadecimal namespace required")
    jobs = {}
    for key, names in [
        ("partial", ["first", "existing", "last"]),
        ("transaction-field", ["guard"]),
    ]:
        resources = [
            BASE + "/shared_runs/" + nonce + "-" + key + "/docs/" + n for n in names
        ]
        setup = resources[1] if key == "partial" else resources[0]
        operations = [op(r) for r in resources]
        operations.append(
            op(
                setup + "?currentDocument.exists=false",
                "PATCH",
                {"fields": field(7 if key == "partial" else 3, setup)},
            )
        )
        if key == "partial":
            writes = [
                {
                    "update": {"name": r, "fields": field(v, r)},
                    "currentDocument": {"exists": False},
                }
                for r, v in zip(resources, [1, 8, 9], strict=True)
            ]
            # The middle document still conflicts with its conditional setup create.
            body = {"writes": writes}
        else:
            body = {
                "writes": [
                    {"update": {"name": resources[0], "fields": field(4, resources[0])}}
                ],
                "transaction": "AA==",
            }
        operations.append(op(BASE + ":batchWrite", "POST", body))
        operations.extend(op(r) for r in resources)
        recovery = []
        for r in resources:
            index = len(recovery)
            recovery.extend([op(r), {**op(r, "DELETE"), "versionFrom": index}, op(r)])
        jobs[key] = {
            "resources": resources,
            "observation": operations,
            "recovery": recovery,
        }
    return {
        "contract": "shared-local-v2",
        "nonce": nonce,
        "jobs": jobs,
        "wallSeconds": 300,
        "recoverySeconds": 180,
        "observationRequests": 12,
        "intervalSeconds": 0.25,
        "requestCostMicrousd": 100,
        "costMicrousd": 42600,
        "fixedCostMicrousd": 40000,
        "coordinatorRequests": 2,
        "accounts": 0,
        "configurationChanges": 0,
        "metadataRequests": 0,
        "observerSha256": observer_digest(),
        "transport": "local-only",
        "collector": "existing-batch-adapter-shared-v2",
    }


def _explain_body(method, analyze, empty=False):
    query = {
        "from": [{"collectionId": "items"}],
        "offset": 0,
        **({"limit": 0} if empty else {}),
    }
    if method == "runQuery":
        return {"structuredQuery": query, "explainOptions": {"analyze": analyze}}
    return {
        "structuredAggregationQuery": {
            "structuredQuery": query,
            "aggregations": [{"alias": "count", "count": {}}],
        },
        "explainOptions": {"analyze": analyze},
    }


def _explain_collection_valid(value):
    """Transport collection accepts only a fully received JSON array."""
    return isinstance(value, list)


def _explain_recipe_valid(operation, value):
    """Validate one of the six concrete REST Explain response shapes."""
    if not _explain_collection_valid(value) or not value:
        return False
    body = operation.get("body", {})
    analyze = body.get("explainOptions", {}).get("analyze") is True
    aggregation = "structuredAggregationQuery" in body
    query = body.get("structuredQuery") or body.get("structuredAggregationQuery", {}).get(
        "structuredQuery", {}
    )
    empty = query.get("limit") == 0
    metrics = [row for row in value if isinstance(row, dict) and "explainMetrics" in row]
    if len(metrics) != 1 or not all(isinstance(row, dict) for row in value):
        return False
    if not analyze:
        return len(value) == 1 and set(value[0]) == {"explainMetrics"}
    if aggregation:
        return (
            len(value) == 1
            and set(value[0]) == {"result", "readTime", "explainMetrics"}
            and isinstance(value[0]["result"], dict)
        )
    if empty:
        return len(value) == 1 and set(value[0]) == {"readTime", "explainMetrics"}
    document_rows = [row for row in value if "document" in row]
    return (
        len(document_rows) > 0
        and all("readTime" in row for row in value)
        and all("explainMetrics" not in row for row in document_rows)
    )


def campaign_cases():
    """Typed campaign inventory; accepted rows use only the existing Adapter routes."""
    source = {
        "firestore": "crates/fireemu-adapter-grpc/tests/rest.rs",
        "service": "crates/fireemu-adapter-grpc/src/service/tests/explain_tests.rs",
        "auth": "crates/fireemu-adapter-http/tests/auth_flows.rs",
    }
    cases = []
    for method, label in [("runQuery", "query"), ("runAggregationQuery", "aggregation")]:
        for mode, analyze, empty in [
            ("plan-only", False, False),
            ("analyze", True, False),
            ("empty-analyze", True, True),
        ]:
            cases.append(
                {
                    "id": f"firestore/explain/{label}/{mode}",
                    "service": "firestore",
                    "method": "POST",
                    "path": f"/v1/{BASE}/campaign/{{freshNonce}}:{method}",
                    "body": _explain_body(method, analyze, empty),
                    "principal": "owned-firestore-admin",
                    "principalProof": "privileged Adapter access is reserved by shared_gate before dispatch",
                    "namespace": "projects/{project}/databases/(default)/documents/campaign/{freshNonce}",
                    "admission": "accepted",
                    "setup": "owned document absence then conditional create",
                    "readback": "typed Explain response and final document identity/state",
                    "cleanup": "existing journaled conditional DELETE and final absence read",
                    "comparator": "shared-production-pair typed JSON response comparison",
                    "budget": {
                        "requestCount": 1,
                        "wallSeconds": 300,
                        "requestCostMicrousd": 100,
                        "costMicrousd": 100,
                    },
                    "recoveryBudget": {
                        "requestCount": 6,
                        "seconds": 180,
                        "costMicrousd": 600,
                    },
                    "source": source["firestore"],
                }
            )
    outside = [
        ("firestore/explain/query/auth-refusal", "Query Explain rules refusal needs Rules setup"),
        ("firestore/explain/aggregation/auth-refusal", "Query Explain rules refusal needs Rules setup"),
        ("firestore/explain/query/transaction-ownership", "transaction rollback route is outside shared cleanup"),
        ("firestore/explain/aggregation/transaction-ownership", "transaction rollback route is outside shared cleanup"),
        ("auth/tenant/namespace-isolation", "existing Adapter has no tenant route admission"),
        ("auth/tenant/path-separator-refusal", "existing Adapter has no tenant route admission"),
        ("auth/tenant/implicit-defaults", "existing Adapter has no tenant route admission"),
        ("auth/tenant/rejected-project-no-id-consume", "existing Adapter has no tenant route admission"),
        ("auth/tenant/generated-id-skips-implicit", "existing Adapter has no tenant route admission"),
        ("auth/tenant/concurrent-patches", "existing Adapter has no tenant route admission"),
        ("auth/tenant/admin-routes-isolation", "existing Adapter has no tenant route admission"),
        ("auth/tenant/client-id-mismatch", "existing Adapter has no tenant route admission"),
        ("auth/tenant/cross-tenant-update", "existing Adapter has no tenant route admission"),
        ("auth/tenant/cross-tenant-refresh", "existing Adapter has no tenant route admission"),
    ]
    cases.extend(
        {
            "id": case_id,
            "service": "firestore" if case_id.startswith("firestore/") else "auth",
            "admission": "outside",
            "reason": reason,
            "source": source["service"] if case_id.startswith("firestore/") else source["auth"],
            "externalDependencies": [],
        }
        for case_id, reason in outside
    )
    return cases


def campaign_manifest(nonce):
    """Build a shared-gate plan for the six dispatchable Explain recipes."""
    if nonce != "{freshNonce}" and (
        len(nonce) != 32 or any(c not in "0123456789abcdef" for c in nonce)
    ):
        raise ValueError("fresh hexadecimal namespace required")
    parent = BASE + "/campaign/" + nonce
    resources = [parent + "/items/item-a", parent + "/items/item-b"]
    operations = [op(resource) for resource in resources]
    for resource, value in zip(resources, [7, 8], strict=True):
        operations.append(
            op(
                resource + "?currentDocument.exists=false",
                "PATCH",
                {"fields": field(value)},
            )
        )
    for method, analyze, empty in [
        ("runQuery", False, False),
        ("runQuery", True, False),
        ("runQuery", True, True),
        ("runAggregationQuery", False, False),
        ("runAggregationQuery", True, False),
        ("runAggregationQuery", True, True),
    ]:
        operations.append(op(parent + ":" + method, "POST", _explain_body(method, analyze, empty)))
    operations.extend(op(resource) for resource in resources)
    recovery = []
    for resource in resources:
        read_index = len(recovery)
        recovery.extend(
            [op(resource), {**op(resource, "DELETE"), "versionFrom": read_index}, op(resource)]
        )
    step_ids = [
        "setup/absence/item-a",
        "setup/absence/item-b",
        "setup/create/item-a",
        "setup/create/item-b",
        "explain/query/plan-only",
        "explain/query/analyze",
        "explain/query/empty-analyze",
        "explain/aggregation/plan-only",
        "explain/aggregation/analyze",
        "explain/aggregation/empty-analyze",
        "readback/item-a",
        "readback/item-b",
    ]
    return {
        "contract": "shared-local-v1",
        "nonce": nonce,
        "jobs": {
            "query-explain": {
                "resources": resources,
                "observation": operations,
                "recovery": recovery,
                "stepIds": step_ids,
            }
        },
        "wallSeconds": 300,
        "recoverySeconds": 180,
        "observationRequests": len(operations),
        "intervalSeconds": 0.25,
        "requestCostMicrousd": 100,
        "costMicrousd": 5000,
        "fixedCostMicrousd": 3000,
        "coordinatorRequests": 2,
        "accounts": 0,
        "configurationChanges": 0,
        "metadataRequests": 0,
        "observerSha256": observer_digest(),
        "transport": "local-only",
        "collector": "existing-batch-adapter-shared-v1",
    }


def campaign_proposal():
    """Return the unaccepted proposal without acquiring owner/environment inputs."""
    plan = campaign_manifest("{freshNonce}")
    plan["observerSha256"] = LEGACY_CAMPAIGN_OBSERVER_SHA256
    return {
        "kind": "production-campaign-slice-01-v2",
        "status": "proposal-only-unapproved",
        "sourceCommit": "1fc4dd044",
        "collector": "existing-batch-adapter-shared-v1",
        "admission": "existing-shared-gate-local-only",
        "ownerInputs": {
            "owner": None,
            "permissionReference": None,
            "startsAt": None,
            "endsAt": None,
            "nonce": None,
            "currentEnvironment": None,
        },
        "artifactSha256": None,
        "configurationDigest": None,
        "planTemplate": plan,
        "cases": campaign_cases(),
        "budget": {
            "observationRequests": plan["observationRequests"],
            "recoveryRequests": len(plan["jobs"]["query-explain"]["recovery"]),
            "totalRequests": plan["observationRequests"] + len(plan["jobs"]["query-explain"]["recovery"]) + plan["coordinatorRequests"],
            "wallSeconds": plan["wallSeconds"],
            "recoverySeconds": plan["recoverySeconds"],
            "costMicrousd": plan["costMicrousd"],
        },
        "productionExecutable": False,
        "networkCalls": 0,
        "unsupported": "Cases marked outside remain recorded but cannot be admitted by weakening existing guards.",
    }


def validate_campaign_proposal(proposal):
    """Fail closed when an offline proposal is presented as owner acceptance."""
    if proposal.get("kind") != "production-campaign-slice-01-v2":
        raise ValueError("campaign kind mismatch")
    owner = proposal.get("ownerInputs")
    if owner != {
        "owner": None,
        "permissionReference": None,
        "startsAt": None,
        "endsAt": None,
        "nonce": None,
        "currentEnvironment": None,
    }:
        raise ValueError("owner/window/nonce/environment acceptance must be unset")
    if proposal.get("artifactSha256") is not None or proposal.get("configurationDigest") is not None:
        raise ValueError("artifact/configuration acceptance is unavailable")
    if proposal.get("productionExecutable") is not False or proposal.get("networkCalls") != 0:
        raise ValueError("offline campaign cannot execute production")
    template = proposal.get("planTemplate", {})
    if template.get("nonce") != "{freshNonce}" or template.get("transport") != "local-only":
        raise ValueError("fresh local namespace template required")
    job = template.get("jobs", {}).get("query-explain", {})
    namespace_values = [
        *job.get("resources", []),
        *(operation.get("path", "") for operation in job.get("observation", [])),
        *(operation.get("path", "") for operation in job.get("recovery", [])),
    ]
    if not namespace_values or any("{freshNonce}" not in value for value in namespace_values):
        raise ValueError("namespace template drift")
    for case in proposal.get("cases", []):
        if case.get("admission") == "accepted":
            if case.get("service") != "firestore" or case.get("method") != "POST":
                raise ValueError("accepted campaign route is outside existing adapter")
            if ":runQuery" not in case.get("path", "") and ":runAggregationQuery" not in case.get("path", ""):
                raise ValueError("accepted Explain route is not closed")
            if case.get("budget", {}).get("requestCount") != 1 or case.get(
                "recoveryBudget", {}
            ).get("requestCount") != 6:
                raise ValueError("accepted recipe budget is incomplete")
        elif case.get("admission") != "outside":
            raise ValueError("unknown campaign admission")
    if digest(proposal) != digest(campaign_proposal()):
        raise ValueError("campaign closed proposal drift")
    return True


def save(path, value):
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")


def worker(output, key, origins):
    plan = json.loads((output / "gate/state.json").read_bytes())["plan"]
    import os
    import subprocess

    command = subprocess.check_output(
        ["ps", "-ww", "-p", str(os.getpid()), "-o", "args="], text=True
    ).strip()
    save(
        output / (key + "-process.json"),
        {"pid": os.getpid(), "argv": command.split(maxsplit=1)},
    )
    gate = Gate(output / "gate", key)
    gate.claim()
    adapter = Adapter(candidate(), plan["nonce"], output / key, local_origins=origins)
    adapter.shared_gate = gate
    run_scenario(adapter, plan, key)


def run_scenario(adapter, plan, key, before_cleanup=None):
    gate = adapter.shared_gate
    rows, cleanup = [], []
    failure = None
    collection_failure = None
    try:
        for index, operation in enumerate(plan["jobs"][key]["observation"]):
            status, body = adapter.request(**operation)
            job = plan["jobs"][key]
            row = {"index": index, "request": operation, "status": status, "body": body}
            if index < len(job.get("stepIds", [])):
                row["id"] = job["stepIds"][index]
            rows.append(row)
            save(adapter.output / "partial.json", rows)
            resources = plan["jobs"][key]["resources"]
            setup_end = 2 * len(resources) if key == "query-explain" else len(resources) + 1
            if (
                key == "query-explain"
                and setup_end <= index < len(plan["jobs"][key]["observation"]) - len(resources)
                and not _explain_collection_valid(body)
            ):
                collection_failure = collection_failure or (
                    "Explain transport did not return a JSON result array"
                )
            if index < len(resources):
                if status != 404:
                    raise ValueError("namespace-not-empty")
                adapter.record(
                    {
                        "kind": "document-attempt",
                        "name": resources[index],
                        "preflightAbsent": True,
                    }
                )
                adapter.documents.add(resources[index])
            elif status != 200 and len(resources) <= index < setup_end:
                raise ValueError("setup-refused")
    except Exception as error:
        failure = type(error).__name__ + ":" + str(error)
        gate.stop()
    finally:
        adapter.budget.recovery = True
        cleanup_allowed = True
        if before_cleanup is not None:
            try:
                before_cleanup()
            except Exception as error:
                cleanup_allowed = False
                failure = failure or type(error).__name__
        for index, declared in enumerate(plan["jobs"][key]["recovery"]):
            if not cleanup_allowed:
                break
            operation = dict(declared)
            source = operation.pop("versionFrom", None)
            if source is not None:
                prior = cleanup[source] if source < len(cleanup) else {}
                if prior.get("status") == 200 and isinstance(
                    prior.get("body"), dict
                ):
                    version = prior["body"].get("updateTime")
                    if isinstance(version, str) and version:
                        operation["path"] += "?currentDocument.updateTime=" + quote(
                            version, safe=""
                        )
            try:
                status, body = adapter.request(**operation)
                cleanup.append(
                    {
                        "index": index,
                        "request": operation,
                        "status": status,
                        "body": body,
                    }
                )
            except Exception as error:
                cleanup.append({"index": index, "failure": type(error).__name__})
            save(adapter.output / "cleanup.json", cleanup)
        complete = False
        try:
            gate.finish()
            complete = True
        except ValueError:
            pass
        # This is a local invariant, not a production-response expectation.
        states = rows[-len(plan["jobs"][key]["resources"]) :]
        if key == "query-explain":
            explain_start = 2 * len(plan["jobs"][key]["resources"])
            explain_rows = rows[explain_start : -len(states)]
            explain_operations = plan["jobs"][key]["observation"][explain_start : -len(states)]
            recipe_validation = len(explain_rows) == len(explain_operations) and all(
                row["status"] == 200 and _explain_recipe_valid(operation, row["body"])
                for row, operation in zip(explain_rows, explain_operations, strict=True)
            )
            safety = (
                len(rows) == len(plan["jobs"][key]["observation"])
                and recipe_validation
                and [row["status"] for row in states] == [200, 200]
            )
            state_validation = len(rows) == len(
                plan["jobs"][key]["observation"]
            ) and recipe_validation and [row["status"] for row in states] == [200, 200]
        else:
            expected = [1, 7, 9] if key == "partial" else [3]
            safety = len(rows) == len(plan["jobs"][key]["observation"]) and all(
                row["status"] == 200
                and row["body"].get("fields") == field(
                    value,
                    row["body"].get("name") if plan["contract"] == "shared-local-v2" else None,
                )
                for row, value in zip(states, expected, strict=True)
            )
            state_validation = len(rows) == len(
                plan["jobs"][key]["observation"]
            ) and all(row["status"] in (200, 404) for row in states)
        collection_complete = (
            collection_failure is None
            and len(rows) == len(plan["jobs"][key]["observation"])
        )
        result = {
            "recordingComplete": collection_complete,
            "collectionComplete": collection_complete,
            "cleanupComplete": complete,
            "safety": safety,
            "compatibility": "not-observed",
            "failure": failure or collection_failure,
            "rows": rows,
            "cleanup": cleanup,
            "adapterCounts": adapter.budget.counts,
            "stateVerified": state_validation,
            "stateValidation": state_validation,
        }
        state = gate.snapshot()
        dispatch = {
            phase: [
                {
                    "index": event["index"],
                    "requestDigest": event.get("requestDigest"),
                    "status": event.get("status"),
                    "responseDigest": event.get("responseDigest"),
                    "completed": event.get("completed"),
                }
                for event in state["events"]
                if event["job"] == key and event["phase"] == phase
            ]
            for phase in ("observation", "recovery")
        }
        result["principalEvidence"] = {
            "planDigest": state["planDigest"],
            "job": key,
            "nonce": adapter.nonce,
            "localOrigins": dict(adapter.local or {}),
            "dispatch": dispatch,
        }
        save(adapter.output / "result.json", result)
    return result


def execute(output, origins):
    ctx = mp.get_context("spawn")
    fixed_plan = json.loads((output / "gate/state.json").read_bytes())["plan"]
    jobs = list(fixed_plan["jobs"])
    processes = [
        ctx.Process(target=worker, args=(output, key, origins)) for key in jobs
    ]
    started = time.monotonic()
    try:
        for process in processes:
            process.start()
        for process in processes:
            process.join(
                max(0, fixed_plan["wallSeconds"] + 15 - (time.monotonic() - started))
            )
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(5)
                if process.is_alive():
                    process.kill()
                    process.join(5)
    state = Gate(output / "gate", jobs[0]).snapshot()
    results = {
        key: json.loads((output / key / "result.json").read_bytes())
        if (output / key / "result.json").exists()
        else {"recordingComplete": False, "cleanupComplete": False}
        for key in jobs
    }
    events = state["events"]
    invariant = (
        state["total"] <= 26
        and state["recovery"] <= 12
        and state["costMicrousd"] <= 42600
        and all(
            b["started"] - a["started"] >= 0.25 for a, b in itertools.pairwise(events)
        )
        and all(process.exitcode == 0 for process in processes)
    )
    wire_audit = True
    for key in jobs:
        receipt_path = output / key / "responses.jsonl"
        receipts = (
            [json.loads(line) for line in receipt_path.read_text().splitlines()]
            if receipt_path.exists()
            else []
        )
        dispatched = [event for event in events if event["job"] == key]
        wire_audit = (
            wire_audit
            and len(receipts) == len(dispatched)
            and all(
                receipt["phase"] == event["phase"]
                and receipt["response"].get("sharedRequestDigest")
                == event["requestDigest"]
                and receipt["response"]["httpStatus"] == event.get("status")
                and digest(receipt["response"]["body"]) == event.get("responseDigest")
                for receipt, event in zip(receipts, dispatched, strict=True)
            )
        )
    invariant = invariant and wire_audit
    completed = invariant and all(
        r["recordingComplete"] and r["cleanupComplete"] and r.get("safety")
        for r in results.values()
    )
    (output / "batch").mkdir(exist_ok=True)
    save(
        output / "batch/result.json",
        {
            "completed": completed,
            "failure": None if completed else "shared-scenarios-incomplete",
            "unrecovered": [
                key for key, result in results.items() if not result["cleanupComplete"]
            ],
            "productionExecuted": False,
            "sharedConstraints": invariant,
            "wireHistoryMatchesReservations": wire_audit,
            "jobs": results,
            "gate": state,
            "manifestSha256": digest(state["plan"]),
            "processExitCodes": [p.exitcode for p in processes],
            "elapsedSeconds": time.monotonic() - started,
        },
    )
    return completed
