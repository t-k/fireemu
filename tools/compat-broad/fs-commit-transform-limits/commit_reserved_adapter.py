"""Commit-specific binding over the existing Coordinator and shared Ledger.

This module does not authorize execution. The outer boundary must validate the
independent owner permission and freeze source/artifact inputs before reserving.
"""

from __future__ import annotations

import copy
import hashlib
import time
from pathlib import Path

from broad_contract import digest
from commit_remote_transport import prepare
from gate_adapter import ROOT, CommitGate, _limits_bridge, _load, production_gate_plan
from reservations import Ledger
from shared_production import Coordinator

credential_preparation = _load(
    "_commit_credential_preparation",
    ROOT / "tools/compat-broad/fs-write-txn/credential_prep.py",
)


def validate_handoff(handoff, permission, api_key):
    """Validate an explicitly supplied private handoff, without discovering ADC."""
    if (
        not isinstance(handoff, dict)
        or set(handoff) != {"kind", "permissionDigest", "apiKey", "adc"}
        or handoff["kind"] != "commit-authorized-user-v1"
        or handoff["permissionDigest"] != digest(permission)
        or handoff["apiKey"] != api_key
        or digest(api_key) != permission.get("apiKeyDigest")
        or not credential_preparation.private_string(api_key, 256)
    ):
        raise ValueError("bound Commit credential handoff required")
    adc = handoff["adc"]
    credential_preparation.build_request("refresh", adc)
    credential_preparation.validate_principal(permission.get("credentialPrincipal"))
    if (
        digest(adc) != permission.get("authorizedUserDigest")
        or adc["client_id"] != permission["credentialPrincipal"]["clientId"]
    ):
        raise ValueError("authorized user differs from owner permission")


def source_inputs():
    """Closed source set plus the existing transitive shared/limits source digest."""
    here = Path(__file__).resolve().parent
    names = (
        "commit_acquisition.py",
        "commit_baseline.py",
        "commit_reserved_adapter.py",
        "gate_adapter.py",
        "commit_production.py",
        "commit_production_bridge.py",
        "commit_remote_transport.py",
        "transform_compiler.py",
        "transform_comparator.py",
    )
    paths = [here / name for name in names]
    paths += [
        path
        for path in (ROOT / "tools/compat-broad").glob("*.py")
        if path.name
        not in {
            "campaign_explain.py",
            "campaign_explain_shadow.py",
            "test_campaign_explain.py",
        }
    ]
    paths.append(ROOT / "tools/compat-broad/production-admission/reservations.py")
    paths.append(ROOT / "tools/compat-broad/fs-write-txn/credential_prep.py")
    # The campaign-generic admission core is executable code this acquisition
    # runs, so it is frozen by name rather than left to a directory glob.
    paths.append(ROOT / "tools/compat-broad/o8-core/o8_admission.py")
    paths.append(ROOT / "tools/compat-broad/o8-core/o8_campaign.py")
    values = {
        str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in paths
    }
    values.update(_limits_bridge.source_inputs())
    return values


def source_digest():
    return digest(source_inputs())


class CommitReservedCoordinator(Coordinator):
    """Charge metadata through Coordinator while rechecking the shared lease."""

    def __init__(
        self,
        permission,
        nonce,
        output,
        gate,
        api_key,
        *,
        ledger,
        ticket,
        binding_check=None,
        credential_handoff=None,
    ):
        if not isinstance(ledger, Ledger) or not isinstance(gate, CommitGate):
            raise TypeError("shared Ledger and Commit Gate required")
        binding = {
            "permissionDigest": digest(permission),
            "collectorSourceDigest": source_digest(),
        }
        projected = production_gate_plan(gate.compiler, binding)
        claim = ledger.bound_claim(ticket)
        if (
            gate.compiler["nonce"] != nonce
            or digest(gate.snapshot()["plan"]) != digest(projected)
            or claim["gatePath"] != str(gate.path.resolve())
            or claim["gatePlanDigest"] != digest(projected)
        ):
            raise ValueError("reservation belongs to another Commit Gate")
        self._credential_handoff = copy.deepcopy(credential_handoff)
        self.credential_evidence = []
        self._binding_check = binding_check
        self.ledger = ledger
        self.ticket = copy.deepcopy(ticket)
        self._binding = copy.deepcopy(binding)
        self._ledger_identity = (ledger, str(ledger.path), ledger.identity)
        self._ticket_digest = digest(ticket)
        self._claim_digest = digest(claim)
        self._gate = gate
        self._gate_path = str(gate.path.resolve())
        self._nonce = nonce
        self._key_digest = digest(api_key)
        ledger.validate(ticket)
        self._verified_identity = None
        super().__init__(permission, nonce, output, gate, api_key)

    def acquire(self, recovery=False):
        from commit_production import _save

        self.budget.recovery = recovery
        if self._verified_identity is not None:
            self.access()
            required = 180 if recovery else 1200
            if not self.credential.usable(time.monotonic(), required):
                raise ValueError("credential no longer covers reserved phase")
            return
        if recovery:
            raise ValueError("Commit never refreshes credentials during recovery")
        validate_handoff(self._credential_handoff, self.permission, self.api_key)
        token = expiry = verified = None
        for ordinal, slot in enumerate(("refresh", "tokeninfo"), 1):

            def attempt(slot=slot, ordinal=ordinal):
                nonlocal token, expiry, verified
                self.reserve("metadata")
                charge = {
                    "slot": slot,
                    "ordinal": ordinal,
                    "ticketDigest": digest(self.ticket),
                    "permissionDigest": digest(self.permission),
                    "chargedAt": time.time(),
                }
                _save(self.output / f"oauth-{slot}-charge.json", charge)
                self.validate_reservation()
                state, _ = self.management_context
                self._validate_plan(state)
                if (
                    time.monotonic() + 13
                    > state["started"]
                    + state["plan"]["wallSeconds"]
                    - state["plan"]["recoverySeconds"]
                ):
                    raise ValueError("credential preparation phase deadline")
                sent = time.monotonic()
                result = credential_preparation._private_request(
                    slot,
                    self._credential_handoff["adc"] if slot == "refresh" else token,
                )
                receipt = {
                    "slot": slot,
                    "chargeDigest": digest(charge),
                    "complete": result.get("complete") is True,
                    "workerReaped": result.get("workerReaped") is True,
                    "status": result.get("status"),
                    "receivedBytes": result.get("receivedBytes", 0),
                    "verified": False,
                }
                try:
                    if (
                        not receipt["complete"]
                        or not receipt["workerReaped"]
                        or type(receipt["status"]) is not int
                        or receipt["status"] != 200
                    ):
                        raise ValueError("bounded OAuth response incomplete")
                    if slot == "refresh":
                        token, expiry = credential_preparation.refresh_result(
                            result.get("body"), sent
                        )
                    else:
                        verified, facts = credential_preparation.verified_credential(
                            token,
                            expiry,
                            result.get("body"),
                            self.permission["credentialPrincipal"],
                            sent,
                        )
                        if not verified.usable(time.monotonic(), 1200):
                            raise ValueError(
                                "credential does not cover whole Commit allocation"
                            )
                        receipt["claims"] = facts
                    receipt["verified"] = True
                finally:
                    _save(self.output / f"oauth-{slot}-receipt.json", receipt)
                    self.credential_evidence.append(receipt)

            try:
                self.gate.manage(self, "oauth-" + slot, attempt)
            except Exception:
                self.credential.fail()
                raise
        self.credential = verified
        self._credential_handoff = None
        self._verified_identity = (
            self.credential,
            digest(self.credential.token),
            self.credential.expiry,
            self.credential.attempts,
        )

    def access(self):
        token = super().access()
        if self._verified_identity != (
            self.credential,
            digest(token),
            self.credential.expiry,
            self.credential.attempts,
        ):
            raise ValueError("Commit verified credential identity changed")
        return token

    def request(self, *args, **kwargs):
        result = super().request(*args, **kwargs)
        if type(result[0]) is not int or not isinstance(result[1], dict):
            raise ValueError("typed metadata response required")
        return result

    def validate_reservation(self, duration=13):
        if self._binding_check is not None:
            self._binding_check()
        if (
            (self.ledger, str(self.ledger.path), self.ledger.identity)
            != self._ledger_identity
            or digest(self.ticket) != self._ticket_digest
            or digest(self.permission) != self._binding["permissionDigest"]
            or source_digest() != self._binding["collectorSourceDigest"]
            or self.gate is not self._gate
            or str(self.gate.path.resolve()) != self._gate_path
            or self.nonce != self._nonce
            or self.local is not None
            or digest(self.api_key) != self._key_digest
            or self.key_digest != self._key_digest
            or time.time() + duration > self.permission["expiresAt"]
            or self.ledger.validate(self.ticket, duration=duration)
            != self._claim_digest
        ):
            raise ValueError("reserved Commit binding changed")

    def reserve(self, service, duration=12):
        super().reserve(service, duration)
        self.validate_reservation(duration + 1)
        state, _ = self.management_context
        self._validate_plan(state)
        deadline = (
            state["started"]
            + state["plan"]["wallSeconds"]
            - (0 if self.budget.recovery else state["plan"]["recoverySeconds"])
        )
        if time.monotonic() + duration + 1 > deadline:
            raise ValueError("Commit management phase deadline")

    def _validate_plan(self, state):
        if digest(state["plan"]) != digest(
            production_gate_plan(self.gate.compiler, self._binding)
        ):
            raise ValueError("reserved Commit plan changed")

    def bind_wire(self, transmit):
        """Consume the collector's one-shot charged permit, without redispatch."""

        def wire(operation):
            recovery, deadline = self.gate.consume_commit_permit(operation)
            self.budget.recovery = recovery
            self.validate_reservation()
            # The collector is holding the Gate lock: use the immutable plan
            # captured by the Gate, never reacquire its file lock here.
            if self.ready is not True or time.monotonic() + 13 > deadline:
                raise ValueError("Commit preflight or phase deadline")
            token = self.access()
            phase = "recovery" if recovery else "observation"
            comparable = copy.deepcopy(operation)
            if comparable.get("kind") == "cleanup-conditional-delete":
                comparable["path"] = comparable["path"].split("?", 1)[0]
            candidates = []
            for index, declared in enumerate(self.gate.compiler[phase]):
                declared = copy.deepcopy(declared)
                declared.pop("versionFrom", None)
                if digest(declared) == digest(comparable):
                    candidates.append(index)
            if len(candidates) != 1:
                raise ValueError("closed Commit wire position required")
            value = {
                "nonce": self.nonce,
                "phase": phase,
                "index": candidates[0],
                "operation": operation,
                "token": token,
            }
            prepare(value)
            result = transmit(value)
            if isinstance(result, dict) and result.get("status") in (401, 403):
                self.credential.fail()
            return result

        return wire
