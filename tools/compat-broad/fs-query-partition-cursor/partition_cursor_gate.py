"""Campaign-owned projection of the partition/cursor plan onto the shared Gate.

The shared Gate charges every wire call of a production campaign, journals it,
and is what the shared Ledger reads before it releases a reservation. Its
closed scenario model was written for per-document campaigns: a recovery slot
must address one assigned resource by path, a version-bound delete reads its
version from an earlier recovery read, and typed absence is proven by one GET
per assigned resource. The compiled partition/cursor plan does not have that
shape. Its cleanup deletes twenty documents in one Commit, proves absence with
two queries, and binds two observation slots to values only a response can
supply. This module is the bridge, and it changes nothing about the plan.

What it does:

- projects the 37 compiled slots onto one Gate job in a frozen execution
  schedule, and adds a Gate-native recovery ladder, one read, one version-bound
  delete and one typed-absence read per seeded document, so that a run that
  stops after the seed Commit still has an admissible way to remove what it
  created, and so that every assigned resource ends with the typed absence the
  Ledger requires;
- adds two residual-scan query slots that run only on a completed observation;
- maps each collector request onto its frozen Gate slot, verifying any value the
  request bound at run time (page token, partition cursors, delete versions)
  against this run's own journaled responses before the Gate sees it;
- settles the creation outcome of read-only RPCs the shared Gate does not
  recognize, so a partition query is not held as an unconfirmed write.

What it does not do: it does not weaken a Gate rule. The facade calls the frozen
Gate's own `dispatch`, which re-checks the slot, the process, the stop state,
the budgets and the ownership proofs under its lock. Nothing here can send a
request the Gate has not charged.

The Gate contract is `shared-local-v1`, which carries no ownership-marker
convention: the compiled documents cannot carry a `_sharedOwner` reference or a
nonce string without changing the case. Ownership is proven instead the way the
plan itself states it, `conditional-create-plus-exact-fields`, on resources the
Gate only accepts below the nonce-scoped owned path, which this module checks.
"""

from __future__ import annotations

import copy
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from partition_cursor_case import (
    CAMPAIGN,
    OBSERVATION_COUNT,
    PARTITION_DOCUMENTS,
    RECOVERY_COUNT,
    validate_plan,
)
from partition_cursor_collector import _partitions
from partition_cursor_wire import PRODUCTION_REQUEST_SECONDS, same_json
from shared_gate import INTERVAL_FLOOR_SECONDS, WALL_CAP_SECONDS, can_create
from shared_gate import Gate as FrozenGate
from shared_gate import create as frozen_create

JOB = "partition-cursor"
GATE_CONTRACT = "shared-local-v1"
OWNERSHIP_EVIDENCE = "conditional-create-plus-exact-fields-under-nonce-scope"
RECEIPT_KIND = "partition-cursor-acquisition-receipt-v1"
REQUEST_COST_MICROUSD = 1
INTERVAL_SECONDS = INTERVAL_FLOOR_SECONDS
MANAGEMENT_OBSERVATION_IDS = ("oauth-tokeninfo", "project", "database", "auth")
MANAGEMENT_RECOVERY_IDS = ("project", "database", "auth")
MANAGEMENT_SLOT_SECONDS = 13
MANAGEMENT_DURATION_SECONDS = 12.0
CREDENTIAL_IDS = ("oauth-tokeninfo",)
CREDENTIAL_SLOTS = ("tokeninfo",)
SEEDED_DOCUMENTS = PARTITION_DOCUMENTS + 8
# The ladder covers every owned document, the root last, so the schedule ends
# on a typed-absence read and the trailing residual scans sit before it.
LADDER_DOCUMENTS = SEEDED_DOCUMENTS + 1
LADDER_STEPS = 3
RESIDUAL_SLOTS = 2
# Every slot reserves at least the whole-worker wire ceiling plus spawn slack.
SLOT_FLOOR_SECONDS = PRODUCTION_REQUEST_SECONDS + 1.0
# The one read-only RPC the shared Gate does not recognize. `runQuery` with a
# bare `structuredQuery` is already a read to the Gate, so it never reaches the
# facade's settlement; `partitionQuery` takes the database parent only.
_READ_ONLY_RPC = re.compile(
    r"^/v1/projects/[^/?#:%]+/databases/[^/?#:%]+/documents:(partitionQuery)$"
)
_READ_ONLY_KEYS = {
    "partitionQuery": {"structuredQuery", "partitionCount", "pageSize", "pageToken"},
}
_TIMESTAMP = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$")

# Compiled plan slots that the Gate hosts in its observation phase although the
# plan calls them recovery: a Commit and two queries address no single assigned
# resource, which a Gate recovery slot must.
_PLAN_RECOVERY_AS_OBSERVATION = {
    1: "cleanup-seed-delete",
    3: "cleanup-verify-group-absence",
    4: "cleanup-verify-collection-absence",
}


def _read_only_rpc(operation: dict[str, Any]) -> str | None:
    """The read-only Firestore RPC this operation is, by exact shape, or None."""
    if (
        operation.get("service") != "firestore"
        or operation.get("method") != "POST"
        or not isinstance(operation.get("path"), str)
        or not isinstance(operation.get("body"), dict)
    ):
        return None
    match = _READ_ONLY_RPC.fullmatch(operation["path"])
    if match is None or not set(operation["body"]) <= _READ_ONLY_KEYS[match.group(1)]:
        return None
    return match.group(1)


def _operation(
    kind: str, method: str, path: str, *, body: Any = None, **extra: Any
) -> dict[str, Any]:
    return {
        "kind": kind,
        "service": "firestore",
        "method": method,
        "path": path,
        "body": body,
        "privileged": True,
        "form": False,
        **extra,
    }


def _residual_operations(plan: dict[str, Any]) -> list[dict[str, Any]]:
    """The two residual-scan queries, the shape `residual_documents` uses."""
    return [
        _operation(
            "residual-group-scan",
            "POST",
            "/v1/" + plan["databaseRoot"] + ":runQuery",
            body={
                "structuredQuery": {
                    "from": [
                        {
                            "collectionId": plan["groupCollection"],
                            "allDescendants": True,
                        }
                    ]
                }
            },
            parent=plan["databaseRoot"],
            targetResources=[],
        ),
        _operation(
            "residual-cursor-scan",
            "POST",
            "/v1/" + plan["ownedScope"] + ":runQuery",
            body={
                "structuredQuery": {
                    "from": [{"collectionId": plan["cursorCollection"]}]
                }
            },
            parent=plan["ownedScope"],
            targetResources=[],
        ),
    ]


def gate_operations(plan: dict[str, Any]) -> dict[str, Any]:
    """Project the compiled plan onto one Gate job: operations, schedule, slot map.

    The slot map sends a collector coordinate, `(phase, index)` in the compiled
    plan, plus the ladder and residual coordinates this module adds, to the Gate
    coordinate the frozen schedule admits it at. Gate observation slots 0..30
    are the compiled observation; 31..33 are the compiled recovery operations
    that address no single resource; 34..35 are the residual scans. Gate
    recovery slots 0..2 are the compiled ownership read, root delete and root
    absence read; the ladder follows, three slots per owned document, root last.
    """
    validate_plan(plan)
    owned = plan["ownedResources"]
    if len(owned) != LADDER_DOCUMENTS:
        raise ValueError("compiled plan does not own the expected documents")
    observation = [copy.deepcopy(item) for item in plan["observation"]]
    recovery_plan = plan["recovery"]
    slot_map: dict[tuple[str, int], tuple[str, int]] = {
        ("observation", index): ("observation", index)
        for index in range(OBSERVATION_COUNT)
    }
    for plan_index, kind in _PLAN_RECOVERY_AS_OBSERVATION.items():
        item = copy.deepcopy(recovery_plan[plan_index])
        if item["kind"] != kind:
            raise ValueError("compiled recovery order differs from the projection")
        # An integer versionFrom names a recovery capture to the Gate; the plan's
        # names an observation acknowledgement. The facade verifies the bound
        # versions against the Gate's own creation proofs instead.
        item.pop("versionFrom", None)
        slot_map[("recovery", plan_index)] = ("observation", len(observation))
        observation.append(item)
    for index, item in enumerate(_residual_operations(plan)):
        slot_map[("residual", index)] = ("observation", len(observation))
        observation.append(item)
    recovery: list[dict[str, Any]] = []
    ownership = copy.deepcopy(recovery_plan[0])
    root_delete = copy.deepcopy(recovery_plan[2])
    root_absence = copy.deepcopy(recovery_plan[5])
    if (
        ownership["kind"] != "cleanup-ownership-read"
        or root_delete["kind"] != "cleanup-root-delete"
        or root_absence["kind"] != "cleanup-verify-root-absence"
    ):
        raise ValueError("compiled recovery order differs from the projection")
    slot_map[("recovery", 0)] = ("recovery", len(recovery))
    recovery.append(ownership)
    root_delete["versionFrom"] = 0
    slot_map[("recovery", 2)] = ("recovery", len(recovery))
    recovery.append(root_delete)
    slot_map[("recovery", 5)] = ("recovery", len(recovery))
    recovery.append(root_absence)
    ladder_order = [*owned[1:], owned[0]]
    for position, name in enumerate(ladder_order):
        read = len(recovery)
        slot_map[("ladder", position * LADDER_STEPS)] = ("recovery", read)
        recovery.append(
            _operation("ladder-ownership-read", "GET", "/v1/" + name, resource=name)
        )
        slot_map[("ladder", position * LADDER_STEPS + 1)] = ("recovery", len(recovery))
        recovery.append(
            _operation(
                "ladder-version-bound-delete",
                "DELETE",
                "/v1/" + name,
                resource=name,
                versionFrom=read,
            )
        )
        slot_map[("ladder", position * LADDER_STEPS + 2)] = ("recovery", len(recovery))
        recovery.append(
            _operation("ladder-typed-absence", "GET", "/v1/" + name, resource=name)
        )
    seeded_ladder = SEEDED_DOCUMENTS * LADDER_STEPS
    order = (
        [("observation", index) for index in range(OBSERVATION_COUNT)]
        + [
            slot_map[("recovery", 0)],
            slot_map[("recovery", 1)],
            slot_map[("recovery", 2)],
        ]
        + [
            slot_map[("recovery", 3)],
            slot_map[("recovery", 4)],
            slot_map[("recovery", 5)],
        ]
        + [slot_map[("ladder", index)] for index in range(seeded_ladder)]
        + [slot_map[("residual", 0)], slot_map[("residual", 1)]]
        + [
            slot_map[("ladder", index)]
            for index in range(seeded_ladder, LADDER_DOCUMENTS * LADDER_STEPS)
        ]
    )
    if len(order) != len(observation) + len(recovery) or len(set(order)) != len(order):
        raise ValueError("projection schedule does not cover every slot once")
    if order[-1][0] != "recovery":
        raise ValueError("the frozen schedule must end on a recovery slot")
    return {
        "observation": observation,
        "recovery": recovery,
        "order": order,
        "slotMap": slot_map,
    }


def _schedule(projection: dict[str, Any], slot_seconds: float) -> list[dict[str, Any]]:
    entries = []
    for phase, index in projection["order"]:
        operation = projection[phase][index]
        entry = {"phase": phase, "index": index, "seconds": slot_seconds}
        # The Gate's own predicate decides what may be declared non-creating, so
        # the declaration can never disagree with the check that admits it.
        if not can_create(operation):
            entry["creates"] = False
        entries.append(entry)
    return entries


def creating_declaration_gap(plan: dict[str, Any]) -> list[str]:
    """Read-only slots the shared Gate still treats as able to create.

    A slot the collector may skip without a wire call, such as the page-token
    continuation when the paged response carried no token, can only be consumed
    zero-wire if the Gate accepts `creates: false` for it. Until the shared
    Gate recognizes `partitionQuery` as a read, those slots stay declared as
    creating and a benign skip on one of them stops the observation. This
    names them, so the gap is a fact on the record rather than a surprise.
    """
    projection = gate_operations(plan)
    return [
        f"{phase}:{index}:{projection[phase][index]['kind']}"
        for phase, index in projection["order"]
        if _read_only_rpc(projection[phase][index]) is not None
        and can_create(projection[phase][index])
    ]


def _management_entries(ids: tuple[str, ...]) -> list[dict[str, Any]]:
    return [
        {
            "id": item,
            "seconds": MANAGEMENT_SLOT_SECONDS,
            "duration": MANAGEMENT_DURATION_SECONDS,
            "timeout": MANAGEMENT_SLOT_SECONDS,
        }
        for item in ids
    ]


def management_seconds(ids: tuple[str, ...]) -> float:
    return len(ids) * (MANAGEMENT_SLOT_SECONDS + INTERVAL_SECONDS)


def gate_plan(
    plan: dict[str, Any],
    *,
    slot_seconds: float,
    wall_seconds: int,
    recovery_seconds: int,
    cost_microusd: int,
) -> dict[str, Any]:
    """The frozen Gate plan for one nonce; refused unless it fits the wall."""
    if (
        type(slot_seconds) not in (int, float)
        or isinstance(slot_seconds, bool)
        or not slot_seconds >= SLOT_FLOOR_SECONDS
    ):
        raise ValueError("slot reservation below the wire ceiling plus slack")
    if type(wall_seconds) is not int or type(recovery_seconds) is not int:
        raise ValueError("integer wall and recovery seconds required")
    if type(cost_microusd) is not int or cost_microusd <= 0:
        raise ValueError("positive integer cost ceiling required")
    projection = gate_operations(plan)
    segment = "/" + plan["nonce"] + "/"
    if any(segment not in "/" + name + "/" for name in plan["ownedResources"]):
        raise ValueError("assigned resource outside the nonce scope")
    schedule = _schedule(projection, slot_seconds)
    observation_time = len(projection["observation"]) * (
        slot_seconds + INTERVAL_SECONDS
    )
    observation_time += management_seconds(MANAGEMENT_OBSERVATION_IDS)
    recovery_time = len(projection["recovery"]) * (slot_seconds + INTERVAL_SECONDS)
    recovery_time += management_seconds(MANAGEMENT_RECOVERY_IDS)
    if (
        not 0 < recovery_seconds < wall_seconds <= WALL_CAP_SECONDS
        or recovery_time > recovery_seconds
        or observation_time > wall_seconds - recovery_seconds
    ):
        raise ValueError(
            "declared reservations do not fit the campaign wall: observation "
            f"{observation_time:.2f} s and recovery {recovery_time:.2f} s against "
            f"wall {wall_seconds} s with recovery reserve {recovery_seconds} s"
        )
    total_requests = len(projection["observation"]) + len(projection["recovery"])
    management_requests = len(MANAGEMENT_OBSERVATION_IDS) + len(MANAGEMENT_RECOVERY_IDS)
    if cost_microusd < (total_requests + management_requests) * REQUEST_COST_MICROUSD:
        raise ValueError("cost ceiling below the Gate's charged accounting")
    return {
        "contract": GATE_CONTRACT,
        "campaignId": CAMPAIGN,
        "nonce": plan["nonce"],
        "jobSlots": 1,
        "ownershipEvidence": OWNERSHIP_EVIDENCE,
        "requestSeconds": slot_seconds,
        "wallSeconds": wall_seconds,
        "recoverySeconds": recovery_seconds,
        "intervalSeconds": INTERVAL_SECONDS,
        "observationRequests": len(projection["observation"])
        + len(MANAGEMENT_OBSERVATION_IDS),
        "dataRequests": total_requests,
        "managementRequests": management_requests,
        "planSlots": OBSERVATION_COUNT + RECOVERY_COUNT,
        "ladderSlots": LADDER_DOCUMENTS * LADDER_STEPS,
        "residualSlots": RESIDUAL_SLOTS,
        "requestCostMicrousd": REQUEST_COST_MICROUSD,
        "costMicrousd": cost_microusd,
        "receiptKind": RECEIPT_KIND,
        "transportCeilingSeconds": PRODUCTION_REQUEST_SECONDS,
        "management": {
            "dispatchKind": "closed-v1",
            "observation": _management_entries(MANAGEMENT_OBSERVATION_IDS),
            "recovery": _management_entries(MANAGEMENT_RECOVERY_IDS),
            "credentialIds": list(CREDENTIAL_IDS),
            "credentialSlots": list(CREDENTIAL_SLOTS),
            "slotSeconds": MANAGEMENT_SLOT_SECONDS,
            "intervalSeconds": INTERVAL_SECONDS,
            "totalRequests": management_requests,
            "phaseSeconds": {
                "observation": management_seconds(MANAGEMENT_OBSERVATION_IDS),
                "recovery": management_seconds(MANAGEMENT_RECOVERY_IDS),
            },
            "principalBinding": {
                "alternatives": [
                    ["clientId", "subject", "requiredScopes"],
                    ["clientId", "verifiedEmail", "requiredScopes"],
                ],
                "claims": [
                    "issued_to",
                    "audience",
                    "user_id",
                    "email",
                    "verified_email",
                    "scope",
                    "expires_in",
                ],
            },
            "permissionExpiryBound": True,
        },
        "jobs": {
            JOB: {
                "resources": list(plan["ownedResources"]),
                "observation": projection["observation"],
                "recovery": projection["recovery"],
                "schedule": schedule,
            }
        },
    }


def create(path: Path, plan: dict[str, Any]) -> None:
    """Create the Gate directory through the frozen module's own admission."""
    frozen_create(path, plan)


def _partition_response_usable(body: Any) -> bool:
    return _partitions(body) is not None


def _typed_error(body: Any, status: int) -> bool:
    return (
        isinstance(body, dict)
        and set(body) == {"error"}
        and isinstance(body["error"], dict)
        and type(body["error"].get("code")) is int
        and body["error"]["code"] == status
        and isinstance(body["error"].get("status"), str)
        and bool(body["error"]["status"])
    )


def _delete_commit_usable(body: Any, count: int) -> bool:
    return (
        isinstance(body, dict)
        and "error" not in body
        and isinstance(body.get("writeResults"), list)
        and len(body["writeResults"]) == count
        and all(
            isinstance(item, dict) and "error" not in item
            for item in body["writeResults"]
        )
        and isinstance(body.get("commitTime"), str)
        and _TIMESTAMP.fullmatch(body["commitTime"]) is not None
    )


class PartitionCursorGate(FrozenGate):
    """Typed facade: maps collector requests onto frozen slots, settles reads."""

    def __init__(self, path: str | Path, job: str = JOB) -> None:
        super().__init__(path, job)
        # Values this run's own validated responses supplied, keyed by binding.
        # Only these can appear in a later bound request.
        self._observed: dict[str, Any] = {}

    def frozen_operation(self, phase: str, index: int) -> dict[str, Any]:
        operations = self.snapshot()["plan"]["jobs"][self.job][phase]
        if type(index) is not int or not 0 <= index < len(operations):
            raise ValueError("slot outside the frozen Gate plan")
        return copy.deepcopy(operations[index])

    def _same_request(self, runtime: dict[str, Any], frozen: dict[str, Any]) -> None:
        if (
            runtime.get("method") != frozen["method"]
            or runtime.get("path") != frozen["path"]
            or not same_json(runtime.get("body"), frozen["body"])
        ):
            raise ValueError("request differs from its frozen Gate slot")

    def _bound_version(
        self, snapshot: dict[str, Any], resource: str, capture_index: int
    ) -> str:
        """The one version a delete may carry: the journaled creation proof, as
        re-read by the ladder's own recovery read."""
        job = snapshot["jobs"][self.job]
        proof = job.get("creationProofs", {}).get(resource)
        capture = job.get("captures", {}).get(str(capture_index))
        if (
            proof is None
            or not isinstance(capture, dict)
            or capture.get("status") != 200
            or capture.get("name") != resource
            or capture.get("updateTime") != proof["updateTime"]
        ):
            raise ValueError("delete version not proven by this run's journal")
        return proof["updateTime"]

    def normalize(
        self, phase: str, index: int, runtime: dict[str, Any]
    ) -> dict[str, Any]:
        """Map one collector request onto its frozen Gate operation.

        Any value the collector bound at run time must equal what this run's
        own validated responses supplied, and the returned operation is the
        frozen one, so the Gate's digest check is against reviewed bytes.
        """
        if not isinstance(runtime, dict):
            raise ValueError("collector request required")  # noqa: TRY004 -- refusal class, not a type report
        frozen = self.frozen_operation(phase, index)
        kind = frozen["kind"]
        if kind == "partition-page-token-continuation":
            token = self._observed.get("pageToken")
            body = runtime.get("body")
            if (
                not isinstance(token, str)
                or not isinstance(body, dict)
                or body.get("pageToken") != token
            ):
                raise ValueError("page token not supplied by this run's paged response")
            stripped = {key: value for key, value in body.items() if key != "pageToken"}
            self._same_request({**runtime, "body": stripped}, frozen)
            return frozen
        if kind.startswith("partition-reconstruction-range-"):
            partitions = self._observed.get("partitions")
            body = runtime.get("body")
            query = body.get("structuredQuery") if isinstance(body, dict) else None
            if partitions is None or not isinstance(query, dict):
                raise ValueError(
                    "reconstruction range not derived from this run's partitions"
                )
            slot = frozen["reconstructionSlot"]
            expected: dict[str, Any] = {}
            if slot:
                expected["startAt"] = (
                    partitions[slot - 1] if slot - 1 < len(partitions) else None
                )
            if slot < len(partitions):
                expected["endAt"] = partitions[slot]
            for key in ("startAt", "endAt"):
                if not same_json(query.get(key), expected.get(key)):
                    raise ValueError(
                        "reconstruction cursor differs from this run's partitions"
                    )
            stripped = {
                key: value
                for key, value in query.items()
                if key not in ("startAt", "endAt")
            }
            self._same_request(
                {**runtime, "body": {**body, "structuredQuery": stripped}}, frozen
            )
            return frozen
        if kind == "cleanup-seed-delete":
            snapshot = self.snapshot()
            proofs = snapshot["jobs"][self.job].get("creationProofs", {})
            body = runtime.get("body")
            writes = body.get("writes") if isinstance(body, dict) else None
            if not isinstance(writes, list) or len(writes) != len(
                frozen["body"]["writes"]
            ):
                raise ValueError("delete batch differs from its frozen slot")
            normalized = []
            for write, expected in zip(writes, frozen["body"]["writes"], strict=True):
                # Exact shape: a write carries the delete name and the version
                # precondition and nothing else, so the normalization is
                # lossless and an extra key cannot ride along to the wire.
                if (
                    not isinstance(write, dict)
                    or set(write) != {"delete", "currentDocument"}
                    or not isinstance(write["currentDocument"], dict)
                    or set(write["currentDocument"]) != {"updateTime"}
                ):
                    raise ValueError("delete write differs from its frozen shape")
                name = write["delete"]
                version = write["currentDocument"]["updateTime"]
                if (
                    name != expected["delete"]
                    or name not in proofs
                    or version != proofs[name]["updateTime"]
                ):
                    raise ValueError("delete version not proven by this run's journal")
                normalized.append(
                    {"delete": name, "currentDocument": {"updateTime": None}}
                )
            self._same_request(
                {**runtime, "body": {**body, "writes": normalized}}, frozen
            )
            return frozen
        if frozen["method"] == "DELETE":
            resource = frozen["resource"]
            capture_index = frozen["versionFrom"]
            snapshot = self.snapshot()
            capture = (
                snapshot["jobs"][self.job].get("captures", {}).get(str(capture_index))
            )
            expected = {
                key: value for key, value in frozen.items() if key != "versionFrom"
            }
            if isinstance(capture, dict) and capture.get("status") == 200:
                version = self._bound_version(snapshot, resource, capture_index)
                prefix = frozen["path"] + "?currentDocument.updateTime="
                if runtime.get("path") != prefix + version:
                    raise ValueError("delete version not proven by this run's journal")
                self._same_request({**runtime, "path": frozen["path"]}, frozen)
                expected["path"] = prefix + quote(version, safe="")
                return expected
            # No usable version was read: the request carries none, and the
            # Gate consumes the slot without a send rather than deleting blind.
            self._same_request(runtime, frozen)
            return expected
        self._same_request(runtime, frozen)
        return frozen

    def dispatch_slot(self, phase: str, index: int, runtime: dict[str, Any], send):
        """Charge one frozen slot with the collector's request, through the Gate."""
        operation = self.normalize(phase, index, runtime)
        return super().dispatch(operation, phase == "recovery", send)

    def _record_response(self, state, operation, recovery, event, status, body):
        job = state["jobs"][self.job]
        try:
            self._record_partition_cursor_response(job, operation, event, status, body)
        except ValueError:
            job["stopped"] = True
            event["failure"] = "UnsettledPartitionCursorResponse"
            raise

    def _record_partition_cursor_response(self, job, operation, event, status, body):
        kind = operation.get("kind")
        if kind == "partition-count-1" and status == 200:
            partitions = _partitions(body)
            if partitions is None:
                raise ValueError("unusable partition response")
            self._observed["partitions"] = copy.deepcopy(partitions)
        if (
            kind == "partition-count-4-page-size-2"
            and status == 200
            and isinstance(body, dict)
        ):
            token = body.get("nextPageToken")
            if isinstance(token, str) and token:
                self._observed["pageToken"] = token
        if _read_only_rpc(operation) is not None:
            if not (
                _typed_error(body, status)
                or (status == 200 and _partition_response_usable(body))
            ):
                raise ValueError("untyped read-only response")
            if event.get("creationOutcome") == "unknown":
                # A read-only RPC cannot bring a document into existence. This
                # compatibility settlement remains only for legacy Gate plans
                # that classified the operation as creating.
                event["creationOutcome"] = "refused"
                event["settledBy"] = "partition-cursor-read-only-rpc"
            return
        if event.get("creationOutcome") != "unknown":
            return
        if kind == "cleanup-seed-delete":
            if _delete_commit_usable(body, len(operation["body"]["writes"])):
                event["creationOutcome"] = "refused"
                event["settledBy"] = "partition-cursor-delete-commit"
                return
            raise ValueError("untyped delete acknowledgement")


def slot_map(plan: dict[str, Any]) -> dict[tuple[str, int], tuple[str, int]]:
    return gate_operations(plan)["slotMap"]
