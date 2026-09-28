"""Local shadow for the partition/cursor plan: expectation table and loopback run.

The shadow states what the local fireemu runtime is expected to answer for every
compiled slot and validates a collected bundle against that table. It never
contacts production: the transport factory refuses any origin outside the
declared loopback set, and every result stays preparation evidence.
"""

# ruff: noqa: BLE001 -- Preserve the final owned-process and cleanup facts after any failure.
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from partition_cursor_case import compile_plan, validate_plan
from partition_cursor_collector import (
    BENIGN_SKIPS,
    MAX_RAW_BYTES,
    collect_local,
    validate_origin,
    _documents,
    _typed_error,
)

from partition_cursor_wire import request as wire_request, validate_receipt

PROJECT = "demo-partition-cursor"
KNOWN_LOCAL_DIFFERENCES = {
    # Observed against the local artifact on 2026-09-18; each entry is an open
    # repair ticket, not an accepted behavior. A repair moves the shadow to
    # MATCHED, which is the regression signal for closing the ticket.
    # O4-REPAIR-001 was withdrawn: once cursor-too-many-values sent three values
    # against the normalized order length, the runtime refused it correctly, so
    # the earlier finding was the value-type rule of O4-REPAIR-002 misattributed.
    "cursor-reference-type-mismatch": "O4-REPAIR-002",
    "cursor-foreign-reference": "O4-REPAIR-003",
}
REQUEST_TIMEOUT_SECONDS = 20
_OWNED_WRITES = frozenset(
    {
        "create-only-patch",
        "seed-commit",
        "cleanup-ownership-read",
        "cleanup-seed-delete",
        "cleanup-root-delete",
    }
)


def _expectation(operation: dict[str, Any]) -> str:
    expect = operation["expect"]
    if expect.get("outcome") == "refused":
        return "typed-refusal"
    if expect.get("typed") == "NOT_FOUND":
        return "typed-absence"
    if operation["kind"] in _OWNED_WRITES:
        return "owned-write"
    if "maxPartitions" in expect:
        return "accepted-partitions"
    if expect.get("reconstruction"):
        return "accepted-reconstruction"
    return "accepted-documents"


def _contract_row(phase: str, index: int, operation: dict[str, Any]) -> dict[str, Any]:
    expect = operation["expect"]
    documents = expect.get("documents")
    return {
        "phase": phase,
        "index": index,
        "kind": operation["kind"],
        "expectation": _expectation(operation),
        "expectedStatus": expect.get("status", expect.get("statuses")),
        "expectedDocuments": len(documents) if documents is not None else None,
        "skippable": bool(expect.get("skippable")) or "reconstruction" in expect,
    }


def shadow_contract(plan: dict[str, Any]) -> dict[str, Any]:
    """State the expected local answer for every compiled slot; never a receipt."""
    validate_plan(plan)
    return {
        "schemaVersion": 1,
        "campaignId": plan["campaignId"],
        "planDigest": plan["planDigest"],
        "status": "PREPARATION_ONLY",
        "productionExecuted": False,
        "promotionReady": False,
        "observation": [
            _contract_row("observation", index, operation)
            for index, operation in enumerate(plan["observation"])
        ],
        "recovery": [
            _contract_row("recovery", index, operation)
            for index, operation in enumerate(plan["recovery"])
        ],
    }


def _indeterminate(reason: str) -> dict[str, Any]:
    return {
        "status": "INDETERMINATE",
        "reason": reason,
        "differences": [],
        "productionExecuted": False,
        "promotionReady": False,
    }


def _unretained(bundle: dict[str, Any], cleanup: dict[str, Any]) -> str | None:
    """Refuse to read any verdict out of a run that retained no wire bytes.

    A dispatched row without a verified raw sidecar, an incomplete publication
    or a binding count below the dispatched rows means the run cannot support a
    verdict, however its individual statuses read.
    """
    raw, publication = bundle.get("raw"), bundle.get("publication")
    if not isinstance(raw, dict) or not isinstance(publication, dict):
        return "unbound-evidence"
    dispatched = [
        row
        for row in bundle["rows"] + cleanup["rows"]
        if isinstance(row, dict) and row.get("status") != "skipped"
    ]
    if not dispatched:
        return "no-dispatched-row"
    if raw.get("complete") is not True or publication.get("complete") is not True:
        return "incomplete-retention"
    if raw.get("bindings") != len(dispatched):
        return "raw-bindings-below-dispatched-rows"
    if any(
        row.get("receipt") is None or (row.get("raw") or {}).get("present") is not True
        for row in dispatched
    ):
        return "unretained-dispatched-row"
    if any(
        not isinstance(row.get("receipt"), dict)
        or row["receipt"].get("complete") is not True
        or row.get("evidenceFailure") is True
        for row in dispatched
    ):
        # Retained diagnostic bytes do not establish a usable API observation.
        # Do not report a semantic difference when the wire/body binding failed.
        return "unusable-response-evidence"
    return None


def _row_difference(row: Any, expected: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(row, dict) or row.get("kind") != expected["kind"]:
        return {**expected, "reason": "unbound-row", "ticket": None}
    if row.get("status") == "pass":
        return None
    if row.get("status") == "skipped" and row.get("skipReason") in BENIGN_SKIPS:
        return None
    return {
        "phase": expected["phase"],
        "index": expected["index"],
        "kind": expected["kind"],
        "reason": row.get("skipReason") or row.get("failure") or row.get("status"),
        "ticket": KNOWN_LOCAL_DIFFERENCES.get(expected["kind"]),
    }


def validate_shadow(bundle: Any, plan: dict[str, Any]) -> dict[str, Any]:
    """Compare a collected local bundle against the contract, never promoting it."""
    try:
        contract = shadow_contract(plan)
    except (TypeError, ValueError):
        return _indeterminate("plan-drift")
    if not isinstance(bundle, dict):
        return _indeterminate("malformed-bundle")
    cleanup = bundle.get("cleanup")
    if (
        bundle.get("campaignId") != plan["campaignId"]
        or bundle.get("planDigest") != plan["planDigest"]
        or bundle.get("productionExecuted") is not False
        or bundle.get("promotionReady") is not False
        or not isinstance(bundle.get("rows"), list)
        or not isinstance(cleanup, dict)
        or not isinstance(cleanup.get("rows"), list)
    ):
        return _indeterminate("unbound-bundle")
    if len(bundle["rows"]) != len(contract["observation"]) or len(
        cleanup["rows"]
    ) != len(contract["recovery"]):
        return _indeterminate("row-count-drift")
    unbound = _unretained(bundle, cleanup)
    if unbound:
        return _indeterminate(unbound)
    differences = []
    for row, expected in zip(bundle["rows"], contract["observation"]):
        difference = _row_difference(row, expected)
        if difference:
            differences.append(difference)
    for row, expected in zip(cleanup["rows"], contract["recovery"]):
        difference = _row_difference(row, expected)
        if difference:
            differences.append(difference)
    if cleanup.get("complete") is not True:
        differences.append(
            {
                "phase": "recovery",
                "index": None,
                "kind": None,
                "reason": "cleanup-incomplete",
                "ticket": None,
            }
        )
    if bundle.get("status") != ("pass" if not differences else "incomplete"):
        # The bundle status carries facts no row does, the verified partition
        # reconstruction among them. A status that disagrees with the rows is an
        # unexplained disagreement whether or not any row differs, so it must
        # never be read as a verdict.
        return _indeterminate("status-disagrees-with-rows")
    if not differences:
        status = "MATCHED"
    elif all(difference["ticket"] for difference in differences):
        status = "DIFFERENT_KNOWN"
    else:
        status = "DIFFERENT"
    return {
        "status": status,
        "reason": None,
        "differences": differences,
        "productionExecuted": False,
        "promotionReady": False,
    }


def loopback_transport(origin: Any) -> Callable[[dict[str, Any]], dict[str, Any]]:
    """Build a transport that can only ever address a declared loopback origin."""
    validate_origin(origin)

    def transmit(request: dict[str, Any]) -> dict[str, Any]:
        return wire_request(origin, request, timeout=REQUEST_TIMEOUT_SECONDS)

    return transmit


def failing_transport(
    transmit: Callable[[dict[str, Any]], dict[str, Any]], fail_at: int
) -> Callable[[dict[str, Any]], dict[str, Any]]:
    """Wrap a transport so one dispatch fails, rehearsing recovery and cleanup."""
    sent = [0]

    def rehearsed(request: dict[str, Any]) -> dict[str, Any]:
        sent[0] += 1
        if sent[0] - 1 == fail_at:
            raise ConnectionError("rehearsed transport failure")
        return transmit(request)

    return rehearsed


def residual_documents(
    transmit: Callable[[dict[str, Any]], dict[str, Any]], plan: dict[str, Any]
) -> int | None:
    """Count owned documents left behind, independently of the collector rows."""
    receipt = transmit(
        {
            "phase": "verification",
            "index": 0,
            "kind": "residual-scan",
            "method": "POST",
            "path": "/v1/" + plan["databaseRoot"] + ":runQuery",
            "body": {
                "structuredQuery": {
                    "from": [
                        {
                            "collectionId": plan["groupCollection"],
                            "allDescendants": True,
                        }
                    ]
                }
            },
        }
    )
    try:
        body = validate_receipt(receipt)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return None
    documents = _documents(body)
    if receipt["status"] != 200 or documents is None:
        return None
    group = len(documents)
    root = transmit(
        {
            "phase": "verification",
            "index": 1,
            "kind": "residual-root",
            "method": "GET",
            "path": "/v1/" + plan["ownedScope"],
            "body": None,
        }
    )
    cursor = transmit(
        {
            "phase": "verification",
            "index": 2,
            "kind": "residual-cursor",
            "method": "POST",
            "path": "/v1/" + plan["ownedScope"] + ":runQuery",
            "body": {
                "structuredQuery": {
                    "from": [{"collectionId": plan["cursorCollection"]}]
                }
            },
        }
    )
    try:
        cursor_body, root_body = validate_receipt(cursor), validate_receipt(root)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return None
    cursor_documents = _documents(cursor_body)
    if cursor["status"] != 200 or cursor_documents is None:
        return None
    if any(doc["name"] not in plan["ownedResources"][1:] for doc in documents + cursor_documents):
        return None
    if root["status"] == 404:
        if not _typed_error(root_body, "NOT_FOUND", 404):
            return None
    elif root["status"] == 200:
        if (not isinstance(root_body, dict) or "error" in root_body
                or root_body.get("name") != plan["ownedScope"]):
            return None
    else:
        return None
    return group + int(root["status"] == 200) + len(cursor_documents)


# Versioned: the v1 and current-v2 records are historical and stay byte-identical.
SHADOW_RECORD = (
    Path(__file__).resolve().parents[3]
    / "spec/compatibility/broad-runs/fs-query-partition-cursor-current-v3-local-shadow.json"
)


def shadow_record(output: Path) -> dict[str, Any]:
    """Extract the committable record of one shadow run from its retained output.

    The record carries the artifact digest and source commit the run actually
    executed, so the published claim is reproducible from the run rather than
    copied into prose.
    """
    from partition_cursor_manifest import source_inputs

    report = json.loads((output / "manifest.json").read_bytes())
    summary = json.loads((output / "shadow.json").read_bytes())
    bundle = json.loads((output / "bundle" / "collection.json").read_bytes())
    return {
        "schemaVersion": 1,
        "kind": "fs-query-partition-cursor-local-shadow-v1",
        "campaignId": bundle["campaignId"],
        "productionExecuted": False,
        "promotionReady": False,
        "target": bundle["target"],
        "artifact": report["artifact"],
        "sourceInputs": source_inputs(),
        "run": {
            "parentStatus": report["status"],
            "bundleStatus": bundle["status"],
            "validation": summary["validation"]["status"],
            "cleanupComplete": summary["cleanupComplete"],
            "residualDocuments": summary["residualDocuments"],
            "observationRows": len(bundle["rows"]),
            "recoveryRows": len(bundle["cleanup"]["rows"]),
            "rawBindings": bundle["raw"]["bindings"],
            "rawComplete": bundle["raw"]["complete"],
            "publicationComplete": bundle["publication"]["complete"],
            "reconstruction": bundle["reconstruction"],
            "ownedProcess": report["ownedProcess"],
        },
        "differences": [
            {
                "kind": difference["kind"],
                "reason": difference["reason"],
                "ticket": difference["ticket"],
            }
            for difference in summary["validation"]["differences"]
        ],
    }


def write_shadow_record(output: Path) -> Path:
    """Publish the committable shadow record; rerun after any lane change."""
    SHADOW_RECORD.write_text(
        json.dumps(shadow_record(output), indent=1, sort_keys=True) + "\n"
    )
    return SHADOW_RECORD


def _socket_closed(origin: str) -> bool:
    parsed = urlsplit(origin)
    with socket.socket() as probe:
        probe.settimeout(2)
        try:
            probe.connect((parsed.hostname, parsed.port or 80))
        except OSError:
            return True
    return False


def _child(output: Path, nonce: str, fail_at: int | None = None) -> int:
    host = os.environ["FIRESTORE_EMULATOR_HOST"]
    origin = "http://" + host if "://" not in host else host
    plan = compile_plan(PROJECT, "(default)", nonce)
    (output / "instance.json").write_text(
        json.dumps({"pid": os.getpid(), "parentPid": os.getppid(), "origin": origin})
    )
    (output / "plan.json").write_text(json.dumps(plan, indent=1, sort_keys=True))
    transmit = loopback_transport(origin)
    collector = transmit if fail_at is None else failing_transport(transmit, fail_at)
    result = collect_local(plan, collector, output / "bundle", origin=origin)
    validation = validate_shadow(result, plan)
    residual = residual_documents(transmit, plan)
    summary = {
        "result": result["status"],
        "validation": validation,
        "cleanupComplete": result["cleanup"]["complete"],
        "residualDocuments": residual,
        "failAt": fail_at,
    }
    (output / "shadow.json").write_text(json.dumps(summary, indent=1, sort_keys=True))
    print(
        json.dumps(
            {
                "status": result["status"],
                "validation": validation["status"],
                "residualDocuments": residual,
            }
        )
    )
    if fail_at is not None:
        # A rehearsal succeeds only when the residual scan proved absence. An
        # unknown residual is a failure, never a pass.
        return 0 if residual == 0 else 1
    accepted = {"MATCHED", "DIFFERENT_KNOWN"}
    healthy = (
        validation["status"] in accepted
        and result["cleanup"]["complete"]
        and result["raw"]["complete"]
        and result["publication"]["complete"]
        and result["reconstruction"]["matches"] is True
        and result["status"] in ("pass", "incomplete")
        and residual == 0
    )
    return 0 if healthy else 1


def artifact_binding(binary: Path) -> dict[str, Any]:
    """Bind the artifact actually executed to its bytes and its source tree.

    A debug build is not bit-reproducible, so the digest identifies this build
    instance while the commit and the clean-tree flag identify its source. The
    binary must live inside the checkout that the commit describes; a binary
    from another worktree or from the shared checkout is refused.
    """
    binary = binary.resolve()
    root = Path(__file__).resolve().parents[3]
    if root not in binary.parents:
        raise ValueError("the artifact must be built inside this worktree")
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True
    ).strip()
    dirty = subprocess.check_output(
        ["git", "status", "--porcelain", "--", "crates", "Cargo.toml", "Cargo.lock"],
        cwd=root,
        text=True,
    ).strip()
    return {
        "path": str(binary.relative_to(root)),
        "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "byteCount": binary.stat().st_size,
        "sourceCommit": commit,
        "sourceTreeClean": not dirty,
        "reproducible": False,
    }


def run_against_artifact(binary: Path, output: Path, fail_at: int | None = None) -> int:
    """Supervise one owned local artifact and always report its final teardown."""
    binding = artifact_binding(binary)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    nonce = uuid.uuid4().hex
    config = {
        "schemaVersion": 1,
        "profile": "strict",
        "firestore": {"edition": "standard", "apiMode": "native"},
    }
    (output / "config.json").write_text(json.dumps(config))
    command = [
        str(binary), "exec", "--config", str(output / "config.json"),
        "--project", PROJECT, "--only", "firestore",
        "--firestore-port", "0", "--http-port", "0", "--hub-port", "0",
        "--ui-port", "0", "--logging-port", "0", "--log-verbosity", "silent",
        "--", sys.executable, str(Path(__file__).resolve()),
        "--child", str(output), "--nonce", nonce,
        *([] if fail_at is None else ["--fail-at", str(fail_at)]),
    ]  # fmt: skip
    report: dict[str, Any] = {
        "status": "incomplete",
        "productionExecuted": False,
        "artifact": binding,
        "command": command,
        "failAt": fail_at,
    }
    process = None
    try:
        with (output / "stderr.log").open("w") as errors:
            process = subprocess.Popen(command, stderr=errors)
            report["exitCode"] = process.wait(timeout=180)
    except (Exception, KeyboardInterrupt) as error:
        report["executionFailure"] = type(error).__name__
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        report["ownedProcess"] = {
            "pid": process.pid if process else None,
            "stopped": process is not None and process.poll() is not None,
            "listenersClosed": False,
        }
        try:
            instance = json.loads((output / "instance.json").read_bytes())
            report["ownedProcess"]["listenersClosed"] = _socket_closed(
                instance["origin"]
            )
        except Exception as error:
            report["listenerVerificationFailure"] = type(error).__name__
        try:
            report["shadow"] = json.loads((output / "shadow.json").read_bytes())
        except Exception as error:
            report["shadowFailure"] = type(error).__name__
        if (
            report.get("exitCode") == 0
            and report["ownedProcess"]["stopped"]
            and report["ownedProcess"]["listenersClosed"]
            and not any(key.endswith("Failure") for key in report)
        ):
            report["status"] = "pass"
        (output / "manifest.json").write_text(
            json.dumps(report, indent=1, sort_keys=True)
        )
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--child", type=Path)
    parser.add_argument("--nonce")
    parser.add_argument("--fail-at", type=int)
    arguments = parser.parse_args()
    if arguments.child:
        sys.exit(_child(arguments.child.resolve(), arguments.nonce, arguments.fail_at))
    if not arguments.binary or not arguments.output:
        parser.error("--binary and --output are required")
    sys.exit(
        run_against_artifact(
            arguments.binary.resolve(), arguments.output.resolve(), arguments.fail_at
        )
    )
