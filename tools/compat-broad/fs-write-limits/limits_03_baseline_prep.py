"""Bounded pre-O7 metadata baseline preparation for FS-WRITE-LIMITS-03."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(HERE))

from broad_contract import digest
from production_plan import baseline_preparation_plan
from production_bridge import source_digest
from reservations import Ledger
from shared_gate import create
from shared_production import Coordinator, ProductionGate

NONCE = re.compile(r"^[0-9a-f]{32}$")
PREPARATION_KIND = "limits-03-baseline-preparation-v1"
MAX_INPUT_BYTES = 64 * 1024
CAMPAIGN = "FS-WRITE-LIMITS-03"
METADATA_IDS = ("project", "database", "auth", "key")


def _permission(permission: dict, nonce: str) -> None:
    required = {
        "kind",
        "campaignId",
        "preparationId",
        "nonce",
        "issuedAt",
        "expiresAt",
        "ownerIdentity",
        "recoveryOwner",
        "project",
        "projectNumber",
        "database",
    }
    if not isinstance(permission, dict) or set(permission) != required:
        raise ValueError("exact baseline preparation permission required")
    if permission["kind"] != PREPARATION_KIND or permission["campaignId"] != CAMPAIGN:
        raise ValueError("baseline preparation campaign differs")
    if permission["nonce"] != nonce or not re.fullmatch(
        r"[0-9a-f]{32}", permission["preparationId"]
    ):
        raise ValueError("baseline preparation identity differs")
    if permission["project"] != "fireemu-35fe6" or permission["projectNumber"] != "592603257417":
        raise ValueError("baseline preparation project differs")
    if permission["database"] != "(default)":
        raise ValueError("baseline preparation database differs")
    if any(
        not isinstance(permission[key], str) or not permission[key].strip()
        for key in ("ownerIdentity", "recoveryOwner")
    ):
        raise ValueError("baseline preparation owner required")
    now = time.time()
    if (
        type(permission["issuedAt"]) not in (int, float)
        or type(permission["expiresAt"]) not in (int, float)
        or permission["issuedAt"] > now
        or now + 300 > permission["expiresAt"]
    ):
        raise ValueError("baseline preparation window too short")


def reserve_preparation(permission: dict, *, ledger_root: Path, output: Path):
    """Reserve one bounded metadata-only preparation in a supplied Ledger."""
    nonce = permission.get("nonce") if isinstance(permission, dict) else None
    if not isinstance(nonce, str) or NONCE.fullmatch(nonce) is None:
        raise ValueError("fresh preparation nonce required")
    _permission(permission, nonce)
    allocation = preparation_plan(nonce)
    gate_plan = allocation["gatePlan"]
    gate_plan["permissionDigest"] = digest(permission)
    gate_plan["collectorSourceDigest"] = source_digest()
    locks = allocation["resourceLocks"]
    budget = {"requests": 6, "accounts": 0, "resources": 1, "costMicrousd": 600}
    envelope = {
        "permissionDigest": digest(permission),
        "issuedAt": permission["issuedAt"],
        "expiresAt": permission["expiresAt"],
        "limits": budget,
        "concurrency": 1,
        "scopes": locks,
    }
    output = Path(output).resolve()
    if output.exists() or output.is_symlink():
        raise ValueError("fresh preparation output required")
    gate_path = output / "gate"
    claim = {
        "campaignId": CAMPAIGN,
        "manifestDigest": digest(allocation),
        "nonceDigest": digest(nonce),
        "gatePath": str(gate_path.resolve()),
        "gatePlanDigest": digest(gate_plan),
        "gateJob": "limits",
        "locks": locks,
        "budget": budget,
        "durationSeconds": 300,
    }
    ledger = Ledger(ledger_root)
    ticket = ledger.reserve(envelope, claim, gate_plan)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    create(gate_path, gate_plan)
    return ledger, ticket, allocation, gate_plan


def _metadata_packet(permission, nonce, ticket, allocation, evidence):
    if len(evidence) != 4 or [row.get("id") for row in evidence] != [
        "observation:project",
        "observation:database",
        "observation:auth",
        "observation:key",
    ]:
        raise ValueError("complete ordered metadata evidence required")
    project, database, auth, key = evidence
    if any(row.get("status") != 200 for row in evidence):
        raise ValueError("metadata baseline readback refused")
    project_value = project.get("value")
    database_value = database.get("value")
    key_value = key.get("value")
    if project_value != {"projectId": "fireemu-35fe6", "projectNumber": "592603257417"}:
        raise ValueError("wrong project readback")
    projection = database_value.get("projection") if isinstance(database_value, dict) else None
    if (
        not isinstance(database_value, dict)
        or not isinstance(projection, dict)
        or projection.get("name") != "projects/fireemu-35fe6/databases/(default)"
        or projection.get("type") != "FIRESTORE_NATIVE"
        or projection.get("databaseEdition") != "STANDARD"
        or not isinstance(database_value.get("projectionDigest"), str)
        or len(database_value["projectionDigest"]) != 64
    ):
        raise ValueError("wrong database readback")
    if (
        not isinstance(key_value, dict)
        or key_value.get("parent")
        != "projects/592603257417/locations/global"
        or not isinstance(key_value.get("name"), str)
    ):
        raise ValueError("wrong API-key project readback")
    if not isinstance(auth.get("responseDigest"), str) or len(auth["responseDigest"]) != 64:
        raise ValueError("Auth config digest missing")
    return {
        "kind": PREPARATION_KIND,
        "campaignId": CAMPAIGN,
        "preparationId": permission["preparationId"],
        "nonce": nonce,
        "permissionDigest": digest(permission),
        "sourceDigest": source_digest(),
        "allocationDigest": digest(allocation),
        "ticketDigest": digest(ticket),
        "project": project_value,
        "database": {
            "name": projection["name"],
            "type": projection["type"],
            "databaseEdition": projection["databaseEdition"],
            "projectionDigest": database_value["projectionDigest"],
        },
        "authConfigDigest": auth["responseDigest"],
        "apiKey": {"parent": key_value["parent"], "name": key_value["name"]},
        "slots": [
            "observation:access-command",
            "observation:tokeninfo",
            *[row["id"] for row in evidence],
        ],
        "evidence": [
            {
                "id": row["id"],
                "status": row["status"],
                "responseDigest": row["responseDigest"],
                "value": row.get("value", {}),
            }
            for row in evidence
        ],
        "completed": True,
    }


def capture_baseline(permission: dict, *, ledger_root: Path, output: Path, api_key: str):
    """Capture four current metadata readbacks under a prep reservation.

    Credential acquisition is delegated to the reviewed Coordinator, which
    invokes its existing bounded command/tokeninfo sequence. The API key is a
    private caller value and is never serialized into the packet.
    """
    if not isinstance(api_key, str) or not api_key.strip():
        raise ValueError("private API key required")
    nonce = permission.get("nonce") if isinstance(permission, dict) else None
    ledger, ticket, allocation, gate_plan = reserve_preparation(
        permission, ledger_root=ledger_root, output=output
    )
    gate = ProductionGate(output / "gate", "limits")
    gate.claim()
    ledger.validate(ticket, duration=13)
    coordinator = Coordinator(
        permission, nonce, output / "coordinator", gate, api_key
    )
    coordinator.acquire()
    routes = coordinator.metadata_routes()
    for action in ("project", "database", "auth", "key"):
        ledger.validate(ticket, duration=13)
        route = next(path for path, name in routes.items() if name == action)
        coordinator.request("metadata", route, method="GET", privileged=True)
    packet = _metadata_packet(
        permission, nonce, ticket, allocation, coordinator.metadata_evidence
    )
    packet["managementUsed"] = gate.snapshot()["managementUsed"]
    packet["gateDigest"] = digest(gate.snapshot())
    private = output / "baseline-packet.json"
    private.write_text(json.dumps(packet, sort_keys=True, indent=2) + "\n")
    private.chmod(0o600)
    return packet


def preparation_plan(nonce: str) -> dict:
    if not isinstance(nonce, str) or NONCE.fullmatch(nonce) is None:
        raise ValueError("fresh hexadecimal nonce required")
    allocation = baseline_preparation_plan(nonce)
    allocation["preparationKind"] = PREPARATION_KIND
    return allocation


def _read_private_json(fd: int) -> dict:
    if type(fd) is not int or fd < 0:
        raise ValueError("private handoff descriptor required")
    info = os.fstat(fd)
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("private handoff descriptor required")
    chunks = []
    size = 0
    while True:
        chunk = os.read(fd, min(8192, MAX_INPUT_BYTES + 1 - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
        if size > MAX_INPUT_BYTES:
            break
    raw = b"".join(chunks)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("bounded private handoff required")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("private handoff object required")
    return value


def _write_private(path: Path, value: dict) -> None:
    if path.exists() or path.is_symlink():
        raise ValueError("fresh preparation output required")
    path.mkdir(mode=0o700, parents=True, exist_ok=False)
    target = path / "preparation-plan.json"
    target.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    target.chmod(0o600)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nonce")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--handoff-fd", type=int, required=False)
    parser.add_argument("--permission-fd", type=int, required=False)
    parser.add_argument("--ledger", type=Path, required=False)
    parser.add_argument("--api-key-fd", type=int, required=False)
    args = parser.parse_args(argv)
    capture_mode = any(
        value is not None for value in (args.permission_fd, args.ledger, args.api_key_fd)
    )
    if capture_mode:
        if (
            args.permission_fd is None
            or args.ledger is None
            or args.api_key_fd is None
            or args.handoff_fd is not None
            or args.nonce is not None
        ):
            parser.error("capture requires only permission, ledger, and API-key handoff descriptors")
        permission = _read_private_json(args.permission_fd)
        key_handoff = _read_private_json(args.api_key_fd)
        if set(key_handoff) != {"apiKey"} or not isinstance(key_handoff["apiKey"], str):
            raise ValueError("private API-key handoff required")
        packet = capture_baseline(
            permission,
            ledger_root=args.ledger,
            output=args.output,
            api_key=key_handoff["apiKey"],
        )
        print(str(args.output / "baseline-packet.json"))
        return 0
    if args.nonce is None or args.handoff_fd is None:
        parser.error("plan mode requires --nonce and --handoff-fd")
    plan = preparation_plan(args.nonce)
    _read_private_json(args.handoff_fd)
    _write_private(
        args.output, {"kind": PREPARATION_KIND, "plan": plan, "planDigest": digest(plan)}
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
