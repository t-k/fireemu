"""One admitted MFA campaign run, resumable, with the configuration lock on every path.

Order of operations, fresh run: consume the capability, reserve the shared Ledger,
read the private credential handoff, verify the bearer against the frozen principal,
verify the Web API key belongs to the approved project and bind its digest, read the
Auth configuration and refuse unless its digest is the frozen baseline, save the
pre-value, apply the campaign configuration, verify it by readback, walk the
thirty-three cases with real waits, delete every owned account and prove absence,
restore the configuration and verify it, write the receipt, release the reservation.

A resumed run holds the same reservation and the same run directory: it re-verifies
the credential, re-checks the Web API key against the digest the fresh run bound,
re-reads the configuration against the same frozen baseline (the previous stop
restored it), re-applies, and continues from the checkpoint. A stop that is not an
abandonment keeps the owned accounts, because the aged credentials they hold are the
campaign; the configuration is restored regardless.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import stat
import tempfile
import time
from pathlib import Path

import mfa_admission as admission
import mfa_descriptor as campaign
import mfa_gate
import mfa_production_transport as transport
import reservations
from broad_contract import digest
from mfa_cases import TOTP_STEP_ROLLOVER_SECONDS
from mfa_config_lock import VERIFIED_RESTORE_STATUSES, ConfigLock, ConfigLockError
from mfa_provenance import compute_provenance, describe_worktree
from mfa_timing import timing_mode
from mfa_walk import PROJECT, BudgetError, Refused, StopRequested

RUN_STATE_FILE = "run-state.json"
CALL_BUDGET_CONTRACT = "call-budget.json"
CALL_BUDGET_EVENTS = "call-budget-events"
INJECTED_EXECUTION = "injected-transport"
PRODUCTION_EXECUTION = "fixed-production-wire"
ABANDON_ALLOWANCE = campaign.SELECTED_REQUEST_CONTINGENCY["abandonTokeninfoRequests"]
RESTORE_FALLBACK_REQUESTS = campaign.SELECTED_REQUEST_CONTINGENCY[
    "restoreFallbackRequests"
]
UNGATED_RESTORE_ATTEMPTS = RESTORE_FALLBACK_REQUESTS // 2


def _envelope(permission: dict, claim: dict) -> dict:
    return {
        "permissionDigest": digest(permission),
        "issuedAt": permission["issuedAt"],
        "expiresAt": permission["expiresAt"],
        "limits": copy.deepcopy(claim["budget"]),
        "concurrency": 1,
        "scopes": copy.deepcopy(claim["locks"]),
    }


def _write_immutable(path: Path, value: dict) -> None:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    if len(encoded) > reservations.MAX_BYTES:
        raise ValueError("bounded immutable production evidence required")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path, follow_symlinks=False)
    finally:
        os.unlink(temporary)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _write_private(path: Path, value: dict) -> None:
    """Write the private run record so a reader never observes a partial file.

    Same shape as `mfa_config_lock._private_write` and for the same reason: a
    truncate-then-write in place leaves a zero-byte `run-state.json` for any stop
    between the truncate and the write, and `--resume` / `--abandon` read this
    file whole before anything else. A freshly created, uniquely named temporary
    file in the same directory, fsynced and then renamed onto the target, means a
    stop anywhere up to the rename leaves the previous record intact and a stop
    after it leaves the new one complete; a temporary file a stop left behind is
    just an unreferenced file beside `path`, never read by its exact name.
    """
    encoded = json.dumps(value, sort_keys=True, indent=2).encode() + b"\n"
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    replaced = False
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        replaced = True
    finally:
        if not replaced:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _read_private(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ValueError("private run record missing")
    info = path.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("private run record required")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("private run record malformed")  # noqa: TRY004 -- refusal class
    return value


def _read_private_temporary(path: Path) -> tuple[bytes, int]:
    """Read one crash residue without following links or trusting its pathname."""
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.geteuid()
        or before.st_mode & 0o077
        or before.st_size > reservations.MAX_BYTES
    ):
        raise ValueError("private temporary event required")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or opened.st_uid != os.geteuid()
            or opened.st_mode & 0o077
            or opened.st_size > reservations.MAX_BYTES
        ):
            raise ValueError("private temporary event required")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            payload = stream.read(reservations.MAX_BYTES + 1)
        if len(payload) != opened.st_size or len(payload) > reservations.MAX_BYTES:
            raise ValueError("private temporary event changed while reading")
        return payload, opened.st_nlink
    finally:
        if descriptor >= 0:
            os.close(descriptor)


class RequestBudgetRefused(ValueError):
    """The run exhausted or could not adopt its manifest-bound call budget."""


class MfaRequestBudget:
    """Durable pre-dispatch charges for calls outside the Gate's own journal."""

    def __init__(self, output: Path, spec: dict, *, create: bool = False) -> None:
        self.output = Path(output)
        self.spec = copy.deepcopy(spec)
        self.spec_digest = digest(self.spec)
        self.events = self.output / CALL_BUDGET_EVENTS
        contract = self.output / CALL_BUDGET_CONTRACT
        if create:
            self.events.mkdir(mode=0o700)
            _write_immutable(
                contract,
                {
                    "schema": "mfa-request-budget-contract-v1",
                    "spec": self.spec,
                    "specDigest": self.spec_digest,
                },
            )
            directory = os.open(self.output, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        else:
            try:
                saved = _read_private(contract)
            except (OSError, ValueError) as error:
                raise RequestBudgetRefused(
                    "manifest-bound request budget is missing or unreadable"
                ) from error
            if saved != {
                "schema": "mfa-request-budget-contract-v1",
                "spec": self.spec,
                "specDigest": self.spec_digest,
            }:
                raise RequestBudgetRefused("manifest-bound request budget differs")
            if self.events.is_symlink() or not self.events.is_dir():
                raise RequestBudgetRefused("request budget journal is missing")
        self._charges = self._read_charges()

    def _read_charges(self) -> list[dict]:
        temporary_pattern = re.compile(r"\.(\d{6})\.json\.([A-Za-z0-9_-]{8})\Z")
        committed_paths = {}
        temporary_paths = []
        for path in self.events.iterdir():
            if re.fullmatch(r"\d{6}\.json", path.name):
                committed_paths[path.name] = path
                continue
            match = temporary_pattern.fullmatch(path.name)
            if match is None:
                raise RequestBudgetRefused("request budget journal sequence differs")
            temporary_paths.append((int(match.group(1)), path))
        charges = []
        previous = "0" * 64
        allowances = self.spec.get("allowances")
        if not isinstance(allowances, dict) or any(
            not isinstance(category, str) or type(limit) is not int or limit < 0
            for category, limit in allowances.items()
        ):
            raise RequestBudgetRefused("manifest-bound request budget is malformed")
        counts = {category: 0 for category in allowances}
        for index in range(len(committed_paths)):
            name = f"{index:06d}.json"
            path = committed_paths.get(name)
            if path is None:
                raise RequestBudgetRefused("request budget journal sequence differs")
            try:
                event = _read_private(path)
            except (OSError, ValueError) as error:
                raise RequestBudgetRefused(
                    "request budget journal is unreadable"
                ) from error
            body = {key: value for key, value in event.items() if key != "eventDigest"}
            category = event.get("category")
            if (
                event.get("schema") != "mfa-request-charge-v1"
                or type(event.get("index")) is not int
                or event.get("index") != index
                or event.get("specDigest") != self.spec_digest
                or event.get("previousDigest") != previous
                or not isinstance(category, str)
                or category not in allowances
                or event.get("eventDigest") != digest(body)
            ):
                raise RequestBudgetRefused("request budget journal binding differs")
            counts[category] += 1
            if counts[category] > allowances[category]:
                raise RequestBudgetRefused("request budget journal exceeds allowance")
            previous = event["eventDigest"]
            charges.append(event)

        if len(committed_paths) != len(charges) or len(temporary_paths) > 1:
            raise RequestBudgetRefused("request budget journal sequence differs")
        for index, path in temporary_paths:
            if index > len(charges) or path.is_symlink():
                raise RequestBudgetRefused("request budget temporary event differs")
            try:
                payload, link_count = _read_private_temporary(path)
                event = json.loads(payload)
            except json.JSONDecodeError as error:
                if (
                    index != len(charges)
                    or link_count != 1
                    or not self._is_next_charge_prefix(
                        payload, index, charges, counts, allowances
                    )
                ):
                    raise RequestBudgetRefused(
                        "request budget temporary event is unreadable"
                    ) from error
                self._discard_temporary_event(path)
                continue
            except (OSError, ValueError) as error:
                raise RequestBudgetRefused(
                    "request budget temporary event is unreadable"
                ) from error
            if not isinstance(event, dict):
                raise RequestBudgetRefused("request budget temporary event differs")
            body = {key: value for key, value in event.items() if key != "eventDigest"}
            category = event.get("category")
            expected_previous = charges[index - 1]["eventDigest"] if index else "0" * 64
            if (
                event.get("schema") != "mfa-request-charge-v1"
                or type(event.get("index")) is not int
                or event.get("index") != index
                or event.get("specDigest") != self.spec_digest
                or event.get("previousDigest") != expected_previous
                or not isinstance(category, str)
                or category not in allowances
                or event.get("eventDigest") != digest(body)
            ):
                raise RequestBudgetRefused("request budget temporary event differs")
            if index < len(charges):
                if link_count != 2 or event != charges[index]:
                    raise RequestBudgetRefused("request budget temporary event differs")
            elif link_count != 1 or counts[category] >= allowances[category]:
                raise RequestBudgetRefused("request budget temporary event differs")
            self._discard_temporary_event(path)
        return charges

    def _is_next_charge_prefix(
        self,
        payload: bytes,
        index: int,
        charges: list[dict],
        counts: dict,
        allowances: dict,
    ) -> bool:
        previous = charges[index - 1]["eventDigest"] if index else "0" * 64
        for category, allowance in allowances.items():
            if counts[category] >= allowance:
                continue
            body = {
                "schema": "mfa-request-charge-v1",
                "index": index,
                "specDigest": self.spec_digest,
                "category": category,
                "previousDigest": previous,
            }
            encoded = json.dumps(
                {**body, "eventDigest": digest(body)},
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode()
            if len(payload) < len(encoded) and encoded.startswith(payload):
                return True
        return False

    def _discard_temporary_event(self, path: Path) -> None:
        try:
            path.unlink()
            directory = os.open(self.events, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError as error:
            raise RequestBudgetRefused(
                "request budget temporary event could not be recovered"
            ) from error

    @property
    def used(self) -> int:
        return len(self._charges)

    @property
    def allowance(self) -> int:
        return sum(self.spec["allowances"].values())

    def call(self, category: str, send):
        self._charges = self._read_charges()
        allowances = self.spec["allowances"]
        if category not in allowances:
            raise RequestBudgetRefused("request category is not manifest-bound")
        if (
            sum(event["category"] == category for event in self._charges)
            >= allowances[category]
        ):
            raise RequestBudgetRefused(f"request budget exhausted: {category}")
        previous = self._charges[-1]["eventDigest"] if self._charges else "0" * 64
        body = {
            "schema": "mfa-request-charge-v1",
            "index": len(self._charges),
            "specDigest": self.spec_digest,
            "category": category,
            "previousDigest": previous,
        }
        _write_immutable(
            self.events / f"{len(self._charges):06d}.json",
            {**body, "eventDigest": digest(body)},
        )
        self._charges.append({**body, "eventDigest": digest(body)})
        return send()


def request_budget_spec(
    inputs: dict, permission: dict, manifest: dict, gate_plan: dict
) -> dict:
    """Derive finite call authority only from the frozen plan and owner permission."""
    job = gate_plan["jobs"][mfa_gate.JOB]
    gate_slots = (
        len(job["observation"])
        + len(job["recovery"])
        + len(gate_plan["management"]["observation"])
        + len(gate_plan["management"]["recovery"])
    )
    selector = manifest.get("selector")
    base = (
        selector["declaredRequests"]
        if selector is not None
        else manifest["limits"]["maxRequests"]
    )
    contingency = (
        selector["requestContingency"]
        if selector is not None
        else campaign.SELECTED_REQUEST_CONTINGENCY
    )
    expected_contingency = {
        "resumeTokeninfoRequests": campaign.RESUME_ALLOWANCE,
        "abandonTokeninfoRequests": ABANDON_ALLOWANCE,
        "restoreFallbackRequests": RESTORE_FALLBACK_REQUESTS,
    }
    if contingency != expected_contingency or RESTORE_FALLBACK_REQUESTS % 2:
        raise RequestBudgetRefused("manifest-bound request contingency differs")
    if selector is not None and gate_slots + 1 != base:
        raise RequestBudgetRefused(
            "selected request budget does not match Gate closure"
        )
    return {
        "schema": "mfa-request-budget-v1",
        "inputsDigest": inputs["inputsDigest"],
        "planDigest": inputs["planDigest"],
        "permissionDigest": digest(permission),
        "gatePlanDigest": digest(gate_plan),
        "selector": selector["name"] if selector is not None else None,
        "baseRequests": base,
        "allowances": {
            "gate": gate_slots,
            "project-preflight": 1,
            "resume-tokeninfo": contingency["resumeTokeninfoRequests"],
            "abandon-tokeninfo": contingency["abandonTokeninfoRequests"],
            "restore-fallback": contingency["restoreFallbackRequests"],
        },
    }


class GateAdoptionRefused(ValueError):
    """The shared Gate could not be adopted by this process; nothing was sent."""


class GateSession:
    """The walk's session over the shared Gate facade and an inner transport.

    Every data request is admitted against its frozen slot before the inner session
    sends it, every management call is charged as its closed slot, and a planned
    finalize the walk cannot send is consumed as a journaled zero-wire skip.
    """

    def __init__(self, inner, gate: mfa_gate.MfaGate, budget: MfaRequestBudget) -> None:
        self.inner = inner
        self.gate = gate
        self.budget = budget
        self.phase = "observation"
        self._management_slots = [
            ("observation", name) for name in mfa_gate.MANAGEMENT_OBSERVATION_IDS
        ] + [("recovery", name) for name in mfa_gate.MANAGEMENT_RECOVERY_IDS]
        self.management_receipts: list[dict] = []

    @property
    def requests(self) -> int:
        return self.inner.requests

    def _dispatch(self, path, body, *, owner):
        recovery = self.phase == "recovery"

        def send():
            deadline = time.monotonic() + mfa_gate.DATA_SLOT_SECONDS
            if owner:
                request = lambda: self.inner.admin(path, body, deadline=deadline)
            else:
                request = lambda: self.inner.public(path, body, deadline=deadline)
            return self.budget.call("gate", request)

        return self.gate.dispatch_runtime(
            path, body, owner=owner, recovery=recovery, send=send
        )

    def public(self, path, body):
        return self._dispatch(path, body, owner=False)

    def admin(self, path, body):
        return self._dispatch(path, body, owner=True)

    def skip_planned(self, reason: str):
        return self.gate.skip_planned(reason, recovery=self.phase == "recovery")

    def sms_code(self) -> str:
        return self.inner.sms_code()

    def _management(self, expected: tuple[str, ...], call):
        """Charge the next closed management slot and run `call` inside it.

        The next declared slot must be exactly one of `expected`; a call that does
        not match is refused before anything is sent, so a slot is never spent on
        a request of another kind.
        """
        if not self._management_pending():
            raise ValueError("management slot out of order: none remain")
        phase, slot_id = self._management_pending()[0]
        if slot_id not in expected:
            raise ValueError(f"management slot out of order: next is {slot_id}")
        outcome: dict = {}

        def send(deadline):
            try:
                request = lambda: call(deadline)
                status, body = self.budget.call("gate", request)
            except Exception as error:  # noqa: BLE001 -- the slot is charged either way; the class is the evidence
                outcome["failure"] = type(error).__name__
                return {
                    "status": None,
                    "complete": False,
                    "workerReaped": True,
                    "bodyKind": None,
                    "body": None,
                }
            outcome["status"], outcome["body"] = status, body
            return {
                "status": status,
                "complete": True,
                "workerReaped": True,
                "bodyKind": "json",
                "body": body,
            }

        self._consumed = getattr(self, "_consumed", 0) + 1
        self.gate.management_dispatch(phase, slot_id, send)
        self.management_receipts.append(
            {
                "id": f"{phase}:{slot_id}",
                "chargedByBudget": True,
                "budgetCategory": "gate",
                **{k: v for k, v in outcome.items() if k != "body"},
            }
        )
        if "failure" in outcome:
            raise ValueError(f"management slot {slot_id} failed: {outcome['failure']}")
        return outcome["status"], outcome["body"]

    def _management_pending(self):
        return self._management_slots[getattr(self, "_consumed", 0) :]

    def tokeninfo(self, attest):
        """The tokeninfo slot; `attest(body)` turns the raw body into the attestation."""
        phase, slot_id = self._management_pending()[0]
        if slot_id != "oauth-tokeninfo":
            raise ValueError("management slot out of order")
        result: dict = {}

        def send(deadline):
            request = lambda: self.inner.tokeninfo(deadline=deadline)
            status, body = self.budget.call("gate", request)
            result["status"] = status
            if status != 200:
                return {
                    "status": status,
                    "complete": True,
                    "workerReaped": True,
                    "bodyKind": "json",
                    "body": None,
                }
            result["attestation"] = attest(body)
            return {
                "status": status,
                "complete": True,
                "workerReaped": True,
                "bodyKind": "json",
                "body": result["attestation"],
            }

        self._consumed = getattr(self, "_consumed", 0) + 1
        self.gate.management_dispatch(phase, slot_id, send)
        self.management_receipts.append(
            {
                "id": f"{phase}:{slot_id}",
                "status": result.get("status"),
                "chargedByBudget": True,
                "budgetCategory": "gate",
            }
        )
        if result.get("status") != 200:
            raise ValueError(f"tokeninfo answered {result.get('status')}")
        return result["attestation"]

    def read_config(self):
        return self._management(
            (
                "auth-config-readback",
                "auth-config-apply-readback",
                "auth-config-restore-readback",
            ),
            lambda deadline: self.inner.read_config(deadline=deadline),
        )

    def patch_config(self, body, mask):
        slot = (
            "auth-config-restore" if self.phase == "recovery" else "auth-config-apply"
        )
        return self._management(
            (slot,),
            lambda deadline: self.inner.patch_config(body, mask, deadline=deadline),
        )


def prior_state(output: Path, manifest: dict) -> dict:
    """What an earlier process of this run left behind, read before any request.

    Private files only: the collector checkpoint (owned accounts), the material
    store and the lock record. A resumed or abandoned run reports these even when
    it fails before it can act on them, so a receipt can never claim that nothing
    is owned while the previous process's accounts are alive.
    """
    from mfa_collector import load_checkpoint
    from mfa_config_lock import LOCK_FILE
    from mfa_walk import CHECKPOINT_FILE, MATERIAL_FILE, _private_read

    output = Path(output)
    prior = {
        "checkpoint": False,
        "material": (output / MATERIAL_FILE).is_file(),
        "lock": None,
        "ownedAccounts": 0,
        "outstandingAccounts": 0,
        "pendingDueAt": [],
    }
    checkpoint = output / CHECKPOINT_FILE
    if checkpoint.is_file():
        state = load_checkpoint(_private_read(checkpoint), plan=manifest)
        owned = [r for r in state["ownedResources"] if r["kind"] == "account"]
        prior.update(
            checkpoint=True,
            ownedAccounts=len(owned),
            outstandingAccounts=sum(
                not (r["deleted"] and r["absenceVerified"]) for r in owned
            ),
            pendingDueAt=[
                step["dueAt"]
                for step in state["steps"]
                if step["status"] == "pending" and step["dueAt"] is not None
            ],
        )
    lock = output / LOCK_FILE
    if lock.is_file():
        prior["lock"] = _read_private(lock)
    return prior


def remaining_seconds(prior: dict, now: float, *, manifest: dict, recovery: int) -> int:
    """What a resume still needs of its reservation: the critical path left plus recovery.

    A run that has not scheduled its aged rows yet needs the whole critical path; one
    that has needs the latest recorded due instant, the TOTP rollover behind it, and
    the recovery reserve.
    """
    critical = manifest["limits"]["criticalPathSeconds"]
    if prior["pendingDueAt"]:
        critical = (
            max(0.0, max(prior["pendingDueAt"]) - now) + TOTP_STEP_ROLLOVER_SECONDS
        )
    return int(critical) + int(recovery) + 1


def discover_unsettled(walk, gate, session, journal: list) -> dict:
    """Settle lost signups through their frozen, typed reconciliation slots."""
    untracked = []
    unproven = []
    for role in gate.unsettled_accounts():
        email = walk._email(role)
        if email is None:
            untracked.append(role)
            continue
        _status, _body = session.admin(
            f"/v1/projects/{PROJECT}/accounts:lookup",
            {"email": [email]},
        )
        settled = gate.settle_reconciled_creation(role)
        found = settled["uid"]
        if found is None:
            walk.settle_intent(role)
        elif settled.get("held") is True:
            unproven.append(role)
        else:
            walk.adopt_account(role, found)
    return {"untracked": untracked, "unproven": unproven}


def reconcile_gate_accounts(walk, gate) -> list[str]:
    """Own every account the Gate journaled as created that the walk does not know.

    The Gate records a creation the instant the answer arrives; the walk records
    its ownership a moment later. A death in between leaves the Gate's ledger
    ahead of the walk's, and the two must agree before cleanup or the receipt
    would count the walk's accounts as everything there is.
    """
    adopted = []
    accounts = gate.snapshot()["jobs"][mfa_gate.JOB].get("authAccounts", {})
    known = walk.material.value["accounts"]
    for role, record in accounts.items():
        if role in known:
            if known[role]["localId"] != record["uid"]:
                raise ValueError("Gate and walk disagree on an account identity")
            continue
        walk.adopt_account(role, record["uid"])
        adopted.append(role)
    return adopted


def ungated_restore(
    output,
    inner,
    lock_arguments,
    journal: list,
    *,
    budget: MfaRequestBudget,
    attempts: int = UNGATED_RESTORE_ATTEMPTS,
):
    """Restore the configuration outside the Gate, after the gated restore failed.

    The Gate's restore slot is one-shot and phase-ordered, so a transient failure
    of the restore PATCH or a death between the apply and its readback would leave
    the configuration applied with no path back. This retries the restore through
    the inner session, journaled as not charged by the Gate, and returns the lock
    whose record now says what happened.
    """

    def read():
        return budget.call(
            "restore-fallback",
            lambda: inner.read_config(deadline=time.monotonic() + 12.0),
        )

    def patch(body, mask):
        return budget.call(
            "restore-fallback",
            lambda: inner.patch_config(body, mask, deadline=time.monotonic() + 12.0),
        )

    lock = ConfigLock.resume(
        output,
        read=read,
        patch=patch,
        frozen_baseline_digest=lock_arguments["frozen_baseline_digest"],
    )
    for attempt in range(1, attempts + 1):
        try:
            lock.restore()
            journal.append(
                {
                    "id": "recover:auth-config-restore",
                    "attempt": attempt,
                    "status": lock.record["restoreStatus"],
                    "chargedByGate": False,
                    "chargedByBudget": True,
                    "budgetCategory": "restore-fallback",
                }
            )
            return lock
        except ConfigLockError:
            journal.append(
                {
                    "id": "recover:auth-config-restore",
                    "attempt": attempt,
                    "status": lock.record["restoreStatus"],
                    "chargedByGate": False,
                    "chargedByBudget": True,
                    "budgetCategory": "restore-fallback",
                }
            )
    return lock


def _check(stop_requested) -> None:
    if stop_requested is not None and stop_requested():
        raise StopRequested("stop requested")


def _validate_credentials(value) -> dict:
    if (
        not isinstance(value, dict)
        or set(value) != {"token", "apiKey"}
        or not transport.private_string(value["token"], 8192)
        or not transport.private_string(value["apiKey"], 512)
    ):
        raise ValueError("bounded bearer token and Web API key required")
    return value


def execute(
    *,
    capability,
    inputs,
    permission,
    credential_reader,
    ledger_root,
    output,
    sleeper,
    descriptor_,
    source_root,
    resume=False,
    abandon=False,
    stop_requested=None,
    session_factory=None,
):
    """Run, resume or abandon one admitted campaign. Returns the receipt plus status.

    `session_factory` is None in production, which binds the fixed transport through
    the capability. A rehearsal injects a session over a virtual clock; its receipt
    says `injected-transport` and can never be production evidence. A rehearsal is
    also the only execution that may continue after the shared Ledger refuses the
    reservation: the refusal is recorded by name, and the run then proves the Gate
    side; production raises instead.
    """
    if not admission.issued_capability(capability):
        raise ValueError("unissued O7 production capability")
    mode = timing_mode(sleeper)
    rehearsal = bool(descriptor_.frozen_bounds.get("rehearsal"))
    if session_factory is None and (mode != "wall-clock" or rehearsal):
        raise ValueError("production execution requires wall-clock timing")
    inputs, permission = copy.deepcopy(inputs), copy.deepcopy(permission)
    admission.validate_frozen_inputs(inputs, descriptor_)
    if digest(permission) != inputs["permissionDigest"]:
        raise ValueError("independent permission differs from frozen inputs")
    output = Path(output)
    if resume or abandon:
        if not output.is_dir() or output.is_symlink():
            raise ValueError("existing private run directory required to resume")
    elif output.exists() or output.is_symlink():
        raise ValueError("fresh production output required")
    ledger = reservations.Ledger(ledger_root)
    manifest = campaign.execution_plan(inputs["plan"])
    gate_plan = admission.gate_plan_for(inputs, permission, descriptor_)
    generation = admission.abort_generation(inputs, descriptor_)
    gate_plan.update(
        permissionDigest=digest(permission),
        collectorSourceDigest=generation["collectorSourceDigest"],
    )
    claim = admission.reservation_claim(
        inputs, gate_path=output / "gate", gate_plan=gate_plan, descriptor_=descriptor_
    )
    hosting = admission.hosting_check(claim, gate_plan)
    capability._consume(
        campaign_id=claim["campaignId"],
        inputs_digest=inputs["inputsDigest"],
        ledger_root=ledger_root,
    )
    execution_kind = (
        PRODUCTION_EXECUTION if session_factory is None else INJECTED_EXECUTION
    )
    prior = None
    if resume or abandon:
        run_state = _read_private(output / RUN_STATE_FILE)
        if run_state.get("inputsDigest") != inputs["inputsDigest"]:
            raise ValueError("run directory belongs to other frozen inputs")
        ticket = run_state["ticket"]
        # Read before any request: the accounts and the lock an earlier process
        # left are what this run answers for, whether or not it gets to act.
        prior = prior_state(output, manifest)
        if resume:
            if ticket is not None:
                # A resume must still fit the reservation: the critical path that
                # is left plus the recovery reserve, not a token thirteen seconds.
                ledger.validate(
                    ticket,
                    duration=remaining_seconds(
                        prior,
                        sleeper.now(),
                        manifest=manifest,
                        recovery=descriptor_.recovery_seconds,
                    ),
                )
            run_state["resumeCount"] += 1
            if run_state["resumeCount"] > campaign.RESUME_ALLOWANCE:
                raise ValueError("resume allowance exhausted")
        else:
            # Recovery only. The reservation deadline is not consulted: a run found
            # dead after it must still be restored and cleaned, and the row keeps
            # its allocation either way. The approval window is the owner's and is
            # checked by the launcher; the owner re-mints it for a late recovery.
            run_state["abandonCount"] = run_state.get("abandonCount", 0) + 1
            if run_state["abandonCount"] > ABANDON_ALLOWANCE:
                raise ValueError("abandon allowance exhausted")
    else:
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
        _write_immutable(output / "inputs.json", inputs)
        reservation_refusal = None
        try:
            ticket = ledger.reserve(
                _envelope(permission, claim), claim, gate_plan, generation=generation
            )
        except ValueError as error:
            if execution_kind != INJECTED_EXECUTION or not rehearsal:
                raise
            # A rehearsal records the shared Ledger's own refusal and goes on to
            # prove the Gate side without a reservation; production never does.
            ticket = None
            reservation_refusal = str(error)
        run_state = {
            "inputsDigest": inputs["inputsDigest"],
            "ticket": ticket,
            "reservationRefusal": reservation_refusal,
            "claimDigest": digest(claim),
            "gatePlanDigest": digest(gate_plan),
            "resumeCount": 0,
            "receipts": [],
        }
        mfa_gate.create(output / "gate", gate_plan)
    budget_spec = request_budget_spec(inputs, permission, manifest, gate_plan)
    output = output.resolve()
    request_budget = MfaRequestBudget(
        output, budget_spec, create=not (resume or abandon)
    )
    _write_private(output / RUN_STATE_FILE, run_state)
    gate = mfa_gate.MfaGate(output / "gate")
    if resume or abandon:
        # Before the credential is read: the shared Gate refuses every dispatch
        # from a process other than the one that claimed it, so a resume or an
        # abandon adopts it first or is refused here by name.
        try:
            adoption = gate.adopt()
        except ValueError as error:
            raise GateAdoptionRefused(str(error)) from error
        run_state.setdefault("adoptions", []).append(adoption)
        _write_private(output / RUN_STATE_FILE, run_state)
    else:
        gate.claim()
    started_wall = sleeper.now()
    wall_seconds = manifest["limits"]["maxWallSeconds"]

    def deadline_for():
        return time.monotonic() + mfa_gate.DATA_SLOT_SECONDS

    stop_point = "schedule-not-started"
    failure = None
    stopped = False
    walk = None
    lock = None
    credential_evidence = None
    session = None
    inner = None
    untracked: list = []
    unproven: list = []
    try:
        credentials = _validate_credentials(credential_reader())
        # Bound before the raw value is discarded, so a resume can re-check the
        # same physical key without holding it any longer than the fresh run does.
        api_key_digest = hashlib.sha256(credentials["apiKey"].encode()).hexdigest()
        if session_factory is None:
            inner = transport.ProductionSession(
                capability=capability,
                token=credentials["token"],
                api_key=credentials["apiKey"],
                deadline_for=deadline_for,
            )
        else:
            inner = session_factory(capability, credentials, deadline_for)
        credentials = None
        session = GateSession(inner, gate, request_budget)
        lock_arguments = {
            "read": session.read_config,
            "patch": session.patch_config,
            "frozen_baseline_digest": permission["authConfigBaselineDigest"],
        }
        if resume or abandon:
            # The key was bound to the approved project once, at the fresh run's
            # preflight; a resume or an abandon re-checks the same physical key by
            # digest before anything else, so a swapped key for another project
            # cannot reach a signUp or a configuration patch through this path
            # either. A missing digest means the run predates this check or never
            # got past its own preflight, and refuses the same way.
            stop_point = "preflight-key-project"
            if run_state.get("apiKeyDigest") != api_key_digest:
                raise ValueError(
                    "Web API key differs from the key verified for this run"
                )
            # The bearer is verified against the frozen principal again. The Gate's
            # tokeninfo slot was spent by the first process and the shared Gate has
            # no slot for a second one, so this call is counted by the session and
            # recorded as not charged by the Gate.
            stop_point = "preflight-tokeninfo"
            request_category = "abandon-tokeninfo" if abandon else "resume-tokeninfo"
            status, body = request_budget.call(
                request_category,
                lambda: inner.tokeninfo(deadline=time.monotonic() + 12.0),
            )
            if status != 200:
                raise ValueError(f"tokeninfo answered {status}")
            credential_evidence = transport.verify_tokeninfo(
                body,
                permission["credentialPrincipal"],
                required_seconds=descriptor_.recovery_seconds
                if abandon
                else remaining_seconds(
                    prior,
                    sleeper.now(),
                    manifest=manifest,
                    recovery=descriptor_.recovery_seconds,
                ),
            )
            session.management_receipts.append(
                {
                    "id": f"{'abandon' if abandon else 'resume'}:oauth-tokeninfo",
                    "status": status,
                    "chargedByGate": False,
                    "chargedByBudget": True,
                    "budgetCategory": request_category,
                }
            )
            # The Gate's observation preflight was spent by the first process; the
            # configuration stays applied under the held lock across a pause, so a
            # resumed run continues from the lock record rather than re-reading.
            session._consumed = len(gate.snapshot()["managementUsed"])
            stop_point = "resume-prior-state"
            if prior["lock"] is not None:
                lock = ConfigLock.resume(output, **lock_arguments)
            if prior["checkpoint"]:
                walk = descriptor_.collector(
                    session,
                    manifest,
                    output,
                    sleeper=sleeper,
                    resume=True,
                    stop_requested=stop_requested,
                )
                stop_point = "recover-unsettled"
                reconcile_gate_accounts(walk, gate)
                unsettled = discover_unsettled(
                    walk, gate, session, session.management_receipts
                )
                untracked = unsettled["untracked"]
                unproven = unsettled["unproven"]
            elif not abandon:
                raise ValueError("no checkpoint to resume; abandon the run instead")
            if abandon:
                stop_point = "cleanup"
                raise StopRequested("abandon requested")
            stop_point = "cases"
            walk.run()
        else:
            stop_point = "preflight-tokeninfo"
            credential_evidence = session.tokeninfo(
                lambda body: transport.verify_tokeninfo(
                    body,
                    permission["credentialPrincipal"],
                    required_seconds=descriptor_.window_seconds,
                )
            )
            # The Web API key selects the project for every public call (signUp
            # first of all); nothing else binds it to the approved project the way
            # the admin routes are pinned by their literal path. This read-only,
            # key-only call is the one place that binding is checked, before the
            # key is used for the configuration patch or any signUp. The verified
            # digest is bound into the private run record so a resume re-checks
            # the same physical key.
            stop_point = "preflight-key-project"
            status, body = request_budget.call(
                "project-preflight",
                lambda: inner.project_config(deadline=time.monotonic() + 12.0),
            )
            if status != 200:
                raise ValueError(f"project-config preflight answered {status}")
            transport.verify_key_project(body, PROJECT)
            run_state["apiKeyDigest"] = api_key_digest
            _write_private(output / RUN_STATE_FILE, run_state)
            session.management_receipts.append(
                {
                    "id": "preflight:auth-key-project",
                    "status": status,
                    "chargedByGate": False,
                    "chargedByBudget": True,
                    "budgetCategory": "project-preflight",
                }
            )
            stop_point = "preflight-config-readback"
            lock = ConfigLock(output, **lock_arguments)
            lock.preflight()
            stop_point = "config-apply"
            lock.apply()
            sleeper.sleep_until(
                sleeper.now() + campaign.CONFIG_ENFORCEMENT_LAG_SECONDS,
                on_tick=lambda _now: _check(stop_requested),
            )
            stop_point = "acquisition"
            walk = descriptor_.collector(
                session,
                manifest,
                output,
                sleeper=sleeper,
                resume=False,
                stop_requested=stop_requested,
            )
            stop_point = "cases"
            walk.run()
    except StopRequested as error:
        stopped = True
        failure = type(error).__name__
    except (
        Refused,
        BudgetError,
        ConfigLockError,
        ValueError,
        KeyError,
        TypeError,
    ) as error:
        failure = type(error).__name__
        # A wire failure mid-cases stays terminal: the shared Gate consumed the
        # slot the failed request occupied, so the case cannot be sent again and a
        # resume would meet every later slot out of order.
    except Exception as error:  # noqa: BLE001 -- after the credential was read a receipt is always written; only the class is kept
        failure = type(error).__name__
    finally:
        if stop_point == "cases" and walk is not None and failure is not None:
            stop_point = (
                "acquisition" if walk.material.value["origin"] is None else "cases"
            )
        resumable = stopped and not abandon and walk is not None
        cleanup = {
            "ownedAccounts": 0,
            "deleted": 0,
            "absent": 0,
            "complete": not resumable,
            "attempted": not resumable,
        }
        if (
            walk is None
            and prior is not None
            and (prior["checkpoint"] or prior["material"])
        ):
            # A resumed or abandoned run that could not act still owns what the
            # earlier process created; nothing here was attempted or completed. A
            # run that died before its walk wrote a checkpoint created nothing.
            cleanup = {
                "ownedAccounts": prior["ownedAccounts"],
                "deleted": prior["ownedAccounts"] - prior["outstandingAccounts"],
                "absent": prior["ownedAccounts"] - prior["outstandingAccounts"],
                "complete": False,
                "attempted": False,
            }
        gate_complete = False
        gate_refusal = None
        if session is not None and not resumable:
            # Open the Gate's recovery phase: consume what observation left, clean
            # up whatever was created, and skip the slots of accounts that never
            # were, so the configuration restore behind them is reachable.
            snapshot = gate.snapshot()
            job = snapshot["jobs"][mfa_gate.JOB]
            planned = len(snapshot["plan"]["jobs"][mfa_gate.JOB]["observation"])
            if job["observation"] < planned and job.get("stopReason") is None:
                try:
                    gate.abandon_observation(failure or "observation-incomplete")
                except ValueError as error:
                    gate_refusal = type(error).__name__
            session.phase = "recovery"
            try:
                if walk is not None:
                    reconcile_gate_accounts(walk, gate)
                if walk is not None and gate.unsettled_accounts():
                    unsettled = discover_unsettled(
                        walk, gate, session, session.management_receipts
                    )
                    untracked = unsettled["untracked"]
                    unproven = unsettled["unproven"]
                if walk is not None:
                    walk.cleanup()
            except Exception as error:  # noqa: BLE001 -- the restore behind cleanup must never be skipped
                failure = failure or type(error).__name__
            try:
                gate.drain_recovery()
            except ValueError as error:
                gate_refusal = gate_refusal or type(error).__name__
        if walk is not None:
            owned = [r for r in walk.state["ownedResources"] if r["kind"] == "account"]
            all_absent = all(r["deleted"] and r["absenceVerified"] for r in owned)
            cleanup = {
                "ownedAccounts": len(owned),
                "deleted": sum(r["deleted"] for r in owned),
                "absent": sum(r["absenceVerified"] for r in owned),
                "complete": (not resumable) and all_absent,
                "attempted": not resumable,
            }
            if cleanup["attempted"] and not cleanup["complete"]:
                stop_point = "cleanup"
                failure = failure or "CleanupIncomplete"
        if lock is not None and not resumable:
            if session is not None:
                session.phase = "recovery"
            try:
                lock.restore()
            except ConfigLockError:
                # The gated restore is one-shot and phase-ordered; what it could
                # not do, the un-gated retry does, journaled as such.
                try:
                    lock = ungated_restore(
                        output,
                        inner,
                        lock_arguments,
                        session.management_receipts,
                        budget=request_budget,
                    )
                except RequestBudgetRefused as error:
                    failure = failure or type(error).__name__
                    if stop_point != "cleanup":
                        stop_point = "restore"
                if lock.record["restoreStatus"] not in VERIFIED_RESTORE_STATUSES:
                    failure = failure or "ConfigLockError"
                    if stop_point != "cleanup":
                        stop_point = "restore"
            except RequestBudgetRefused as error:
                failure = failure or type(error).__name__
                if stop_point != "cleanup":
                    stop_point = "restore"
        if session is not None and not resumable and cleanup["complete"]:
            try:
                gate.finish()
                gate_complete = True
            except ValueError as error:
                gate_refusal = type(error).__name__
        admission.revoke_production_capability(capability)
    if (untracked or unproven) and failure is None:
        failure = "UntrackedAccount" if untracked else "UnprovenAccount"
    walk_state = copy.deepcopy(walk.state) if walk is not None else None
    rows = walk.ordered_rows() if walk is not None else []
    complete = bool(
        walk is not None
        and failure is None
        and walk.complete()
        and cleanup["complete"]
        and lock is not None
        and lock.record["restoreStatus"] in VERIFIED_RESTORE_STATUSES
        and gate_complete
    )
    if stop_point == "cases" and failure is None and complete:
        stop_point = None
    snapshot = gate.snapshot()
    _write_immutable(
        output / f"gate-snapshot-{len(run_state['receipts']):02d}.json", snapshot
    )
    receipt = admission.build_receipt(
        inputs,
        walk_state=walk_state,
        rows=rows,
        configuration=lock.evidence() if lock is not None else None,
        credential=credential_evidence,
        cleanup=cleanup,
        generation=generation,
        execution_kind=execution_kind,
        timing_mode=mode,
        stop_point=stop_point,
        failure=failure,
        resumable=resumable,
    )
    receipt.update(
        ticket=ticket,
        reservationRefusal=run_state.get("reservationRefusal"),
        claimDigest=digest(claim),
        planDigest=digest(gate_plan),
        gateDigest=digest(snapshot),
        gateComplete=gate_complete,
        gateRefusal=gate_refusal,
        accountEvidence=mfa_gate.account_evidence(snapshot),
        managementEvidence=session.management_receipts if session is not None else [],
        chargedCalls=snapshot["total"],
        hostingRefusals=hosting,
        resumeCount=run_state["resumeCount"],
        abandonCount=run_state.get("abandonCount", 0),
        adoptions=run_state.get("adoptions", []),
        untrackedIntents=list(untracked),
        unprovenIntents=list(unproven),
        configurationStillApplied=bool(
            lock is not None
            and lock.record["changeAttempted"]
            and lock.record["restoreStatus"] not in VERIFIED_RESTORE_STATUSES
        ),
        wallElapsedSeconds=sleeper.now() - started_wall,
        wallBudgetSeconds=wall_seconds,
        reservationStateAtPublication="held" if ticket is not None else "unreserved",
        releaseEligible=complete and ticket is not None,
        releaseRecord="release.json" if complete else None,
        requestsCharged=session.requests if session is not None else 0,
        requestBudget={
            "schema": budget_spec["schema"],
            "used": request_budget.used,
            "allowance": request_budget.allowance,
            "baseRequests": budget_spec["baseRequests"],
            "contingencyAllowance": request_budget.allowance
            - budget_spec["allowances"]["gate"]
            - budget_spec["allowances"]["project-preflight"],
        },
    )
    admission.screen_receipt(receipt)
    sequence = len(run_state["receipts"])
    receipt_path = output / (
        "receipt.json" if not resumable else f"receipt-{sequence:02d}.json"
    )
    if receipt_path.exists():
        receipt_path = output / f"receipt-{sequence:02d}.json"
    _write_immutable(receipt_path, receipt)
    run_state["receipts"].append(
        {
            "path": receipt_path.name,
            "sha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
        }
    )
    _write_private(output / RUN_STATE_FILE, run_state)
    record = comparison_record(
        manifest,
        walk,
        lock,
        permission,
        source_root=source_root,
        execution_kind=execution_kind,
        requests=session.requests if session else 0,
    )
    _write_immutable(output / f"production-record-{sequence:02d}.json", record)
    released = False
    release = None
    release_refusal = None
    if complete and ticket is None:
        release_refusal = "Unreserved"
    elif complete and hosting:
        # The shared Ledger releases a row only through the shared Gate's Firestore
        # cleanup proof, which this campaign's Gate cannot supply; the row stays
        # held and the release record names why rather than turning a known
        # refusal into a missing-proof error.
        release_refusal = "HostingRefused"
    elif complete:
        try:
            ledger.finish(ticket)
            released = True
        except Exception as error:  # noqa: BLE001 -- never report an unverified release
            release_refusal = type(error).__name__
    if complete:
        release = {
            "receiptDigest": digest(receipt),
            "ticket": ticket,
            "failure": release_refusal,
            "hostingRefusals": hosting,
            "reservationRefusal": run_state.get("reservationRefusal"),
            "gateComplete": gate_complete,
            "reservationFinal": (
                ledger.snapshot()["reservations"][ticket["reservation"]]
                if ticket is not None
                else None
            ),
        }
        _write_immutable(output / "release.json", release)
    return {
        **receipt,
        "failure": failure,
        "reservationReleased": released,
        "releaseRefusal": release_refusal,
        "release": release,
        "comparisonRecord": record,
        "executionStarted": True,
    }


def comparison_record(
    manifest, walk, lock, permission, *, source_root, execution_kind, requests
):
    """The receipt in the comparator's shape, so the shadow can be compared against it."""
    state = walk.state if walk is not None else None
    restored = (
        lock is not None and lock.record["restoreStatus"] in VERIFIED_RESTORE_STATUSES
    )
    owned = (
        [r for r in state["ownedResources"] if r["kind"] == "account"] if state else []
    )
    complete = walk is not None and walk.complete()
    return {
        "schema": "o2-mfa-production-record-v1",
        "campaignId": campaign.CAMPAIGN,
        "campaign": copy.deepcopy(manifest),
        "side": "production" if execution_kind == PRODUCTION_EXECUTION else "rehearsal",
        "productionExecuted": execution_kind == PRODUCTION_EXECUTION,
        "recordingComplete": complete,
        "requestsCharged": requests,
        "maxRequests": manifest["limits"]["maxRequests"],
        "provenance": compute_provenance(Path(source_root)),
        "worktree": describe_worktree(Path(source_root)),
        "rows": walk.ordered_rows() if walk is not None else [],
        "recovery": {
            "cleanupVerified": bool(owned)
            and all(r["deleted"] and r["absenceVerified"] for r in owned),
            "remainingOwnedResources": sum(
                not (r["deleted"] and r["absenceVerified"]) for r in owned
            ),
            "configurationMutated": bool(
                lock is not None and lock.record["changeAttempted"]
            ),
            "configurationRestored": restored,
            "ownedAccounts": len(owned),
        },
        "ownerApproval": {
            "approvedBy": permission.get("ownerIdentity"),
            "manifestDigest": digest(manifest),
            "nonceDigest": manifest["owner"]["nonceDigest"],
            "grant": "one-run",
        },
    }
