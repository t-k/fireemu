"""One-host shared reservations underneath O7; never grants production permission.

Full campaign upper bounds remain allocated forever, including unused capacity.
Only locks/concurrency are released after the registered Gate proves cleanup.
The O7 caller must use one shared root and bind its identity into every campaign.
"""

from __future__ import annotations

import contextlib
import copy
import fcntl
import json
import math
import re
import secrets
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from broad_contract import digest
from shared_gate import Gate, _save, validate_absence_proofs

DIMENSIONS = {"requests", "accounts", "resources", "costMicrousd"}
GENERATION_FIELDS = {"sourceCommit", "collectorSourceDigest", "sourceDigests"}
MAX_GENERATION_SOURCES = 64
# The source closure of the reservations written before a reservation recorded
# its own generation. Rows without a recorded generation predate that binding
# and can only be retired by proving this closure; every new row binds the
# generation it was acquired under instead. This is history, not a default.
COMMIT_SOURCE_COMMIT = "09c02557e9a537208a7912f039edb23c1131b1fc"
COMMIT_COLLECTOR_SOURCE_DIGEST = (
    "b9ae95ca922873d477fc171b08b2bc542721a699c5c0c6714ef22a4f846b54ca"
)
COMMIT_SOURCE_DIGESTS = {
    "shared_gate.py": "7913f62224ffe89a943adc5fa88437a3e94f38ff9c6eac5037599ee9233d7bcc",
    "reservations.py": "96adb8b4d6c482914f0eaf155fb70a9a3b6fc2b5f7f642d24638d2daac0bb7c9",
    "commit_reserved_adapter.py": "bd3baf3d46a0a252237d1b7b9cda950d4db8eb2658b2f7502a27d0d04b6fc2e3",
    "gate_adapter.py": "a5221f4c4d572a95018772067e5a8364fffea0bd199528da43cf45b470cdd2fa",
    "commit_acquisition.py": "b5c1df452eed0f4c322083b233e94fa77da3c1db27f443c3328e780e3d2d10b0",
}
LEGACY_COMMIT_GENERATION = {
    "sourceCommit": COMMIT_SOURCE_COMMIT,
    "collectorSourceDigest": COMMIT_COLLECTOR_SOURCE_DIGEST,
    "sourceDigests": COMMIT_SOURCE_DIGESTS,
}
MODES = {"READ": 0, "WRITE": 1, "EXCLUSIVE": 2}
MAX_BYTES = 16 * 1024 * 1024
MAX_RESERVATIONS = 10000


def _hash(value):
    if not isinstance(value, str) or re.fullmatch(r"[a-f0-9]{64}", value) is None:
        raise ValueError("SHA-256 binding required")


def _number(value):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError("finite nonnegative timestamp required")


def _budget(value):
    if (
        not isinstance(value, dict)
        or set(value) != DIMENSIONS
        or any(type(n) is not int or not 0 <= n < 2**63 for n in value.values())
    ):
        raise ValueError("closed integer budget required")


def _generation(value):
    """The source closure one reservation was acquired under.

    Proving it establishes that the abort runs sources identical to the
    acquisition's. It is an identity binding, not evidence of review.
    """
    if not isinstance(value, dict) or set(value) != GENERATION_FIELDS:
        raise ValueError("closed source generation required")
    if (
        not isinstance(value["sourceCommit"], str)
        or re.fullmatch(r"[a-f0-9]{40}", value["sourceCommit"]) is None
    ):
        raise ValueError("frozen source commit required")
    _hash(value["collectorSourceDigest"])
    sources = value["sourceDigests"]
    if (
        not isinstance(sources, dict)
        or not 1 <= len(sources) <= MAX_GENERATION_SOURCES
        or any(
            not isinstance(name, str)
            or re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name) is None
            or name in {".", ".."}
            for name in sources
        )
    ):
        raise ValueError("bounded acquisition source closure required")
    for name in sorted(sources):
        _hash(sources[name])


def _scope(lock):
    if (
        not isinstance(lock, dict)
        or set(lock) != {"key", "mode"}
        or not isinstance(lock["mode"], str)
        or lock["mode"] not in MODES
    ):
        raise ValueError("closed resource lock required")
    key = lock["key"]
    if not isinstance(key, str):
        raise TypeError("canonical scope required")
    parts = key.removesuffix("/*").split("/")
    if (
        len(parts) < 2
        or parts[0] != "project"
        or any(
            part in {".", ".."} or re.fullmatch(r"[A-Za-z0-9_().:@+-]+", part) is None
            for part in parts
        )
    ):
        raise ValueError("canonical project-qualified scope required")
    return tuple(parts)


def _ancestor(parent, child):
    return child[: len(parent)] == parent


def _firestore_resource_scope(resource):
    if not isinstance(resource, str):
        raise TypeError("canonical Firestore resource required")
    parts = resource.split("/")
    if (
        len(parts) < 7
        or parts[0] != "projects"
        or parts[2] != "databases"
        or parts[4] != "documents"
        or (len(parts) - 5) % 2 != 0
    ):
        raise ValueError("canonical Firestore resource required")
    key = "/".join(
        ("project", parts[1], "firestore", parts[3], "documents", *parts[5:])
    )
    return _scope({"key": key, "mode": "WRITE"})


def conflicts(left, right):
    a, b = _scope(left), _scope(right)
    return (_ancestor(a, b) or _ancestor(b, a)) and not (
        left["mode"] == right["mode"] == "READ"
    )


def _locks(value):
    if not isinstance(value, list) or not 1 <= len(value) <= 128:
        raise ValueError("bounded explicit resource locks required")
    scopes = [_scope(lock) for lock in value]
    if len(set(scopes)) != len(scopes):
        raise ValueError("duplicate canonical scope")


def _envelope(value):
    if not isinstance(value, dict) or set(value) != {
        "permissionDigest",
        "issuedAt",
        "expiresAt",
        "limits",
        "concurrency",
        "scopes",
    }:
        raise ValueError("closed envelope required")
    _hash(value["permissionDigest"])
    _number(value["issuedAt"])
    _number(value["expiresAt"])
    _budget(value["limits"])
    _locks(value["scopes"])
    if (
        value["issuedAt"] >= value["expiresAt"]
        or type(value["concurrency"]) is not int
        or not 1 <= value["concurrency"] <= MAX_RESERVATIONS
    ):
        raise ValueError("bounded window and concurrency required")


def _claim(value):
    if not isinstance(value, dict) or set(value) != {
        "campaignId",
        "manifestDigest",
        "nonceDigest",
        "gatePath",
        "gatePlanDigest",
        "locks",
        "budget",
        "durationSeconds",
    }:
        raise ValueError("closed campaign claim required")
    if (
        not isinstance(value["campaignId"], str)
        or re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", value["campaignId"]) is None
    ):
        raise ValueError("campaign identifier required")
    for key in ("manifestDigest", "nonceDigest", "gatePlanDigest"):
        _hash(value[key])
    _budget(value["budget"])
    _locks(value["locks"])
    if (
        type(value["durationSeconds"]) is not int
        or not 1 <= value["durationSeconds"] <= 1200
    ):
        raise ValueError("bounded duration required")
    path = value["gatePath"]
    if not isinstance(path, str) or str(Path(path).resolve()) != path:
        raise ValueError("absolute canonical Gate path required")


class Ledger:
    def __init__(self, path):
        if Path(path).is_symlink():
            raise ValueError("shared root must not be a symlink")
        self.path = Path(path).resolve()
        self.identity = None
        self.identity = self.snapshot()["identity"]

    @classmethod
    def create(cls, path):
        path = Path(path)
        path.mkdir(mode=0o700, parents=True, exist_ok=False)
        (path / "lock").touch(mode=0o600, exist_ok=False)
        _save(
            path,
            {
                "kind": "shared-reservations-v1",
                "identity": secrets.token_hex(32),
                "envelopes": {},
                "reservations": {},
            },
        )
        return cls(path)

    @contextlib.contextmanager
    def _locked(self):
        if self.path.stat().st_mode & 0o077 or any(
            (self.path / name).is_symlink() for name in ("lock", "state.json")
        ):
            raise ValueError("private regular shared ledger required")
        with (self.path / "lock").open("r+") as stream:
            until = time.monotonic() + 15
            while True:
                try:
                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= until:
                        raise ValueError("shared reservation lock deadline") from None
                    time.sleep(0.01)
            with (self.path / "state.json").open("rb") as source:
                raw = source.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise ValueError("bounded shared ledger exceeded")
            state = json.loads(raw)
            if state.get("kind") != "shared-reservations-v1" or self.identity not in (
                None,
                state.get("identity"),
            ):
                raise ValueError("shared ledger identity changed")
            _hash(state["identity"])
            for key, entry in state["envelopes"].items():
                _envelope(entry["envelope"])
                _budget(entry["allocated"])
                if digest(entry["envelope"]) != key:
                    raise ValueError("envelope binding changed")
                total = {
                    k: sum(
                        r["claim"]["budget"][k]
                        for r in state["reservations"].values()
                        if r["envelopeDigest"] == key
                    )
                    for k in DIMENSIONS
                }
                if total != entry["allocated"] or any(
                    total[k] > entry["envelope"]["limits"][k] for k in DIMENSIONS
                ):
                    raise ValueError("shared budget accounting changed")
            for row in state["reservations"].values():
                _claim(row["claim"])
                _number(row["deadline"])
                if (
                    row["envelopeDigest"] not in state["envelopes"]
                    or row["deadline"]
                    > state["envelopes"][row["envelopeDigest"]]["envelope"]["expiresAt"]
                ):
                    raise ValueError("reservation envelope changed")
                if "generation" in row:
                    _generation(row["generation"])
                if digest(row["claim"]) != row["claimDigest"] or row["state"] not in {
                    "held",
                    "closing",
                    "released",
                    "aborted-no-data",
                }:
                    raise ValueError("reservation binding changed")
            yield state

    def _save(self, state):
        if len(json.dumps(state, allow_nan=False).encode()) > MAX_BYTES:
            raise ValueError("bounded shared ledger exceeded")
        _save(self.path, state)

    def snapshot(self):
        with self._locked() as state:
            return state

    def reserve(self, envelope, claim, gate_plan, *, generation=None, now=None):
        if now is not None:
            _number(now)
        _envelope(envelope)
        _claim(claim)
        if generation is not None:
            _generation(generation)
        if (
            digest(gate_plan) != claim["gatePlanDigest"]
            or digest(gate_plan["nonce"]) != claim["nonceDigest"]
            or Path(claim["gatePath"]).exists()
        ):
            raise ValueError("fresh frozen Gate required")
        if (
            gate_plan.get("permissionDigest", envelope["permissionDigest"])
            != envelope["permissionDigest"]
        ):
            raise ValueError("Gate permission differs from shared envelope")
        recovery = sum(len(j["recovery"]) for j in gate_plan["jobs"].values()) + len(
            gate_plan.get("management", {}).get("recovery", [])
        )
        resources = {r for j in gate_plan["jobs"].values() for r in j["resources"]}
        if (
            claim["durationSeconds"] < gate_plan["wallSeconds"]
            or claim["budget"]["requests"]
            < gate_plan["observationRequests"]
            + recovery
            + gate_plan.get("coordinatorRequests", 0)
            or claim["budget"]["costMicrousd"] < gate_plan["costMicrousd"]
            or claim["budget"]["resources"] < len(resources)
        ):
            raise ValueError("Gate exceeds campaign sub-budget")
        for lock in claim["locks"]:
            if not any(
                _ancestor(_scope(scope), _scope(lock))
                and MODES[scope["mode"]] >= MODES[lock["mode"]]
                for scope in envelope["scopes"]
            ):
                raise ValueError("resource lock exceeds permission scope")
        key = digest(envelope)
        with self._locked() as state:
            decision_now = time.time() if now is None else now
            _number(decision_now)
            if (
                not envelope["issuedAt"] <= decision_now
                or decision_now + claim["durationSeconds"] > envelope["expiresAt"]
            ):
                raise ValueError("campaign outside permission window")
            for resource in resources:
                resource_scope = _firestore_resource_scope(resource)
                if not any(
                    _ancestor(_scope(lock), resource_scope)
                    and MODES[lock["mode"]] >= MODES["WRITE"]
                    for lock in claim["locks"]
                ):
                    raise ValueError("Gate resource lock is not covered")
            if any(
                entry["envelope"]["permissionDigest"] == envelope["permissionDigest"]
                and existing != key
                for existing, entry in state["envelopes"].items()
            ):
                raise ValueError("permission already bound to another envelope")
            rows = list(state["reservations"].values())
            if len(rows) >= MAX_RESERVATIONS or any(
                r["claim"]["nonceDigest"] == claim["nonceDigest"]
                or r["claim"]["gatePath"] == claim["gatePath"]
                for r in rows
            ):
                raise ValueError("reservation capacity or nonce/Gate reuse")
            active = [
                r for r in rows if r["state"] not in {"released", "aborted-no-data"}
            ]
            if any(
                conflicts(a, b)
                for r in active
                for a in r["claim"]["locks"]
                for b in claim["locks"]
            ):
                raise ValueError("production resource lock conflict")
            if (
                sum(r["envelopeDigest"] == key for r in active)
                >= envelope["concurrency"]
            ):
                raise ValueError("envelope concurrency exhausted")
            allocated = {
                k: sum(
                    r["claim"]["budget"][k] for r in rows if r["envelopeDigest"] == key
                )
                + claim["budget"][k]
                for k in DIMENSIONS
            }
            if any(allocated[k] > envelope["limits"][k] for k in DIMENSIONS):
                raise ValueError("envelope capacity exhausted")
            reservation = secrets.token_hex(32)
            ticket = {
                "ledgerPath": str(self.path),
                "ledgerIdentity": self.identity,
                "reservation": reservation,
                "claimDigest": digest(claim),
                "envelopeDigest": key,
            }
            state["envelopes"][key] = {"envelope": envelope, "allocated": allocated}
            row = {
                "claim": claim,
                "claimDigest": ticket["claimDigest"],
                "envelopeDigest": key,
                "state": "held",
                "deadline": decision_now + claim["durationSeconds"],
            }
            if generation is not None:
                # Bind the retirement path to this acquisition's own source
                # closure, so a later generation stays retirable without
                # editing canonical state by hand.
                row["generation"] = copy.deepcopy(generation)
            state["reservations"][reservation] = row
            self._save(state)
            return ticket

    def _row(self, state, ticket):
        row = state["reservations"].get(ticket.get("reservation"))
        if row is None or ticket != {
            "ledgerPath": str(self.path),
            "ledgerIdentity": self.identity,
            "reservation": ticket.get("reservation"),
            "claimDigest": row["claimDigest"],
            "envelopeDigest": row["envelopeDigest"],
        }:
            raise ValueError("exact shared reservation ticket required")
        return row

    def bound_claim(self, ticket):
        with self._locked() as state:
            return self._row(state, ticket)["claim"]

    def validate(self, ticket, *, now=None, duration=13):
        if now is not None:
            _number(now)
        if type(duration) is not int or duration < 1:
            raise ValueError("positive bounded operation required")
        with self._locked() as state:
            row = self._row(state, ticket)
            decision_now = time.time() if now is None else now
            _number(decision_now)
            if row["state"] != "held" or decision_now + duration > row["deadline"]:
                raise ValueError("shared reservation unavailable")
            return row["claimDigest"]

    def finish(self, ticket):
        # Close admission first; never hold ledger lock while waiting for Gate.
        with self._locked() as state:
            row = self._row(state, ticket)
            if row["state"] != "held":
                raise ValueError("reservation is not held")
            row["state"] = "closing"
            claim = row["claim"]
            self._save(state)
        try:
            if str(Path(claim["gatePath"]).resolve()) != claim["gatePath"]:
                raise ValueError("registered Gate path changed")
            gate = Gate(claim["gatePath"], "limits").snapshot()
            if (
                digest(gate["plan"]) != claim["gatePlanDigest"]
                or gate["coordinatorInflight"]
                or any(
                    j["complete"] is not True
                    or j["inflight"]
                    or set(j["absent"]) != set(j["resources"])
                    for j in gate["jobs"].values()
                )
                or gate["total"] > claim["budget"]["requests"]
                or gate["costMicrousd"] > claim["budget"]["costMicrousd"]
            ):
                raise ValueError("registered Gate cleanup/accounting incomplete")
            for job_name in gate["jobs"]:
                validate_absence_proofs(gate, job_name)
        except Exception:
            with self._locked() as state:
                self._row(state, ticket)["state"] = "held"
                self._save(state)
            raise
        with self._locked() as state:
            row = self._row(state, ticket)
            if row["state"] != "closing":
                raise ValueError("closing reservation changed")
            row["state"] = "released"
            row["finalGateDigest"] = digest(gate)
            self._save(state)

    def abort_no_data(self, ticket, record):
        """Retire a failed attempt only after persisted evidence proves no data dispatch."""
        if (
            not isinstance(record, dict)
            or set(record)
            != {
                "kind",
                "ticket",
                "planDigest",
                "gateDigest",
                "receiptPath",
                "receiptDigest",
                "collectorSourceDigest",
                "sourceCommit",
                "sourceDigests",
            }
            or record["kind"] != "shared-no-data-abort-v1"
            or record["ticket"] != ticket
        ):
            raise ValueError("exact no-data abort record required")
        for key in (
            "planDigest",
            "gateDigest",
            "receiptDigest",
            "collectorSourceDigest",
        ):
            _hash(record[key])
        claimed_generation = {key: record[key] for key in GENERATION_FIELDS}
        _generation(claimed_generation)
        receipt_path = Path(record["receiptPath"])
        if (
            str(receipt_path.resolve()) != record["receiptPath"]
            or receipt_path.is_symlink()
            or receipt_path.name != "receipt.json"
            or not receipt_path.is_file()
        ):
            raise ValueError("persisted canonical receipt required")
        with receipt_path.open("rb") as source:
            raw = source.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("bounded receipt required")
        receipt = json.loads(raw)
        if digest(receipt) != record["receiptDigest"]:
            raise ValueError("receipt digest changed")
        with self._locked() as state:
            row = self._row(state, ticket)
            # A reservation is retirable only by proving a source closure
            # identical to the one it was acquired under. Rows written before
            # the generation binding existed carry none and remain bound to the
            # legacy closure.
            if claimed_generation != row.get("generation", LEGACY_COMMIT_GENERATION):
                raise ValueError("acquisition source closure required")
            if row["state"] == "aborted-no-data":
                if row.get("abortRecordDigest") != digest(record):
                    raise ValueError("different terminal abort record")
                return
            if row["state"] not in {"held", "closing"} or (
                row["state"] == "closing"
                and row.get("abortRecordDigest") != digest(record)
            ):
                raise ValueError("reservation unavailable for no-data abort")
            claim = row["claim"]
            if (
                record["planDigest"] != claim["gatePlanDigest"]
                or receipt.get("kind") != "commit-acquisition-receipt-v2"
                or receipt.get("ticket") != ticket
                or receipt.get("claimDigest") != row["claimDigest"]
                or receipt.get("planDigest") != record["planDigest"]
                or receipt.get("reservationStateAtPublication") != "held"
                or receipt.get("executionKind") != "fixed-production-wire"
                or receipt.get("productionExecuted") is not False
                or receipt.get("collection", object()) is not None
                or receipt.get("releaseEligible") is not False
                or not isinstance(receipt.get("failure"), str)
                or not receipt["failure"]
                or receipt.get("chargedCalls") != receipt.get("gate", {}).get("total")
                or [item.get("slot") for item in receipt.get("credentialEvidence", [])]
                != ["refresh", "tokeninfo"]
                or any(
                    item.get("workerReaped") is not True
                    or item.get("complete") is not True
                    or item.get("verified") is not True
                    or item.get("status") != 200
                    for item in receipt["credentialEvidence"]
                )
                or [item.get("id") for item in receipt.get("metadata", [])]
                != ["observation:project", "observation:database"]
                or any(item.get("status") != 200 for item in receipt["metadata"])
                or receipt["gate"].get("managementUsed")
                != [
                    "observation:oauth-refresh",
                    "observation:oauth-tokeninfo",
                    "observation:project",
                    "observation:database",
                ]
                or digest(receipt.get("gate")) != record["gateDigest"]
                or receipt["gate"]["total"] > claim["budget"]["requests"]
                or receipt["gate"]["costMicrousd"] > claim["budget"]["costMicrousd"]
                or receipt["gate"]["plan"].get("collectorSourceDigest")
                != record["collectorSourceDigest"]
                or (
                    receipt.get("generation") is not None
                    and receipt["generation"] != claimed_generation
                )
                or str(receipt_path.parent / "gate") != claim["gatePath"]
            ):
                raise ValueError("receipt does not bind failed no-data attempt")
            if row["state"] == "held":
                row["state"] = "closing"
                row["abortRecordDigest"] = digest(record)
                self._save(state)
        gate = Gate(claim["gatePath"], "limits")
        stopped = gate.abort_no_data(
            record["planDigest"], record["gateDigest"], digest(record)
        )
        expected = copy.deepcopy(receipt["gate"])
        expected["stopped"] = True
        for job in expected["jobs"].values():
            job["stopped"] = True
        expected["noDataAbort"] = {
            "preGateDigest": record["gateDigest"],
            "recordDigest": digest(record),
        }
        if stopped != expected:
            raise ValueError("terminal Gate differs from reviewed abort proof")
        final_digest = digest(stopped)
        if digest(gate.snapshot()) != final_digest:
            raise ValueError("terminal Gate snapshot changed")
        with self._locked() as state:
            row = self._row(state, ticket)
            if row["state"] != "closing" or row.get("abortRecordDigest") != digest(
                record
            ):
                raise ValueError("closing abort reservation changed")
            row["state"] = "aborted-no-data"
            row["finalGateDigest"] = final_digest
            self._save(state)
