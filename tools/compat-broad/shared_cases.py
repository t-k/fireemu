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


def op(path, method="GET", body=None):
    return {
        "service": "firestore",
        "path": "/v1/" + path,
        "method": method,
        "body": body,
        "privileged": True,
        "form": False,
    }


def field(value):
    return {"a": {"integerValue": str(value)}}


def manifest(nonce):
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
                {"fields": field(7 if key == "partial" else 3)},
            )
        )
        if key == "partial":
            writes = [
                {"update": {"name": r, "fields": field(v)}}
                for r, v in zip(resources, [1, 8, 9], strict=True)
            ]
            writes[1]["currentDocument"] = {"exists": False}
            body = {"writes": writes}
        else:
            body = {
                "writes": [{"update": {"name": resources[0], "fields": field(4)}}],
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
        "contract": "shared-local-v1",
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
        "collector": "existing-batch-adapter-shared-v1",
    }


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
    rows, cleanup = [], []
    failure = None
    try:
        for index, operation in enumerate(plan["jobs"][key]["observation"]):
            status, body = adapter.request(**operation)
            rows.append(
                {"index": index, "request": operation, "status": status, "body": body}
            )
            save(adapter.output / "partial.json", rows)
            resources = plan["jobs"][key]["resources"]
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
            elif index == len(resources) and status != 200:
                raise ValueError("setup-refused")
    except Exception as error:
        failure = type(error).__name__ + ":" + str(error)
        gate.stop()
    finally:
        adapter.budget.recovery = True
        for index, declared in enumerate(plan["jobs"][key]["recovery"]):
            operation = dict(declared)
            source = operation.pop("versionFrom", None)
            if source is not None:
                prior = cleanup[source] if source < len(cleanup) else {}
                if prior.get("status") == 200:
                    version = prior.get("body", {}).get("updateTime")
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
        expected = [1, 7, 9] if key == "partial" else [3]
        safety = len(rows) == len(plan["jobs"][key]["observation"]) and all(
            row["status"] == 200 and row["body"].get("fields") == field(value)
            for row, value in zip(states, expected, strict=True)
        )
        save(
            adapter.output / "result.json",
            {
                "recordingComplete": failure is None
                and len(rows) == len(plan["jobs"][key]["observation"]),
                "cleanupComplete": complete,
                "safety": safety,
                "compatibility": "not-observed",
                "failure": failure,
                "rows": rows,
                "cleanup": cleanup,
                "adapterCounts": adapter.budget.counts,
            },
        )


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
