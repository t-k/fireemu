"""Bounded collector for the FS-RULES user-token observation matrix.

The collector performs no I/O of its own except its journal. All traffic goes
through an injected ``execute`` callable, so a test drives the whole contract
without a network, a credential, or a process.

Redaction is structural rather than best effort. A compiled operation carries a
credential *reference* label, never a token, so the collector never holds an ID
token, a refresh token, an API key or a password. The transport resolves the
label. A receipt is scanned recursively: a credential-shaped key or a
token-shaped value anywhere inside it aborts the run, and no later row is
attempted. Observation and recovery receipts share the same allowlist.

Budgets are enforced, not declared. A request ceiling and a monotonic deadline
bound observation; a separate reserve and a separate, longer deadline bound
recovery, so cleanup cannot be starved by an exhausted observation budget and
also cannot run unbounded.

Owned resources are the campaign's documents *and* the throwaway accounts it
created. Both are recovered here.

A run is *bound* when the launcher supplies ``acquisition``: the environment,
the campaign manifest digest, the nonce reservation or the artifact, and the
principal fingerprints. A bound run demands more of the transport. Every
receipt must name the endpoint it reached and the transport's own wire
sequence number, the endpoint must belong to the environment, and each Ruleset
is released through an explicit step whose readback the collector checks
against the plan before the first row that depends on it. The bundle records
all of that, together with the collector's own source digests and its clocks,
under ``observer``, ``transport`` and ``acquisition``. Recording those bindings
grants nothing: the acquisition comparator verifies them and the bundle stays
``productionReady: False``.
"""

from __future__ import annotations

import json
import math
import os
import re
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from o5_user_token_campaign import source_digests
from o5_user_token_case import (
    ACCOUNT_PRINCIPALS,
    CAMPAIGN,
    POST_SIGN_IN_DELETE,
    POST_SIGN_IN_DISABLE,
    POST_SIGN_IN_REVOKE,
    digest,
    principal_actions,
    validate_case,
)
from o5_user_token_semantics import BINDINGS_KEY, capture_principal_fields

COLLECTOR_CONTRACT = "fs-rules-user-token-collector-v4"

ROLE_PRODUCTION = "production-user-token"
ROLE_LOCAL_SHADOW = "local-fireemu-shadow"
ROLES = (ROLE_PRODUCTION, ROLE_LOCAL_SHADOW)

# The environment a bundle was acquired in. A role names the side of a
# comparison; the environment, the endpoints and the artifact binding are what
# a comparator checks the role against.
ENVIRONMENT_PRODUCTION = "production-oracle"
ENVIRONMENT_LOCAL = "local-fireemu"
ENVIRONMENTS = (ENVIRONMENT_PRODUCTION, ENVIRONMENT_LOCAL)

# Hosts a production acquisition may reach, and the loopback hosts a local
# shadow must not leave. A receipt names the host the transport connected to;
# the collector classifies it and a comparator refuses a mixed or foreign set.
PRODUCTION_HOSTS = frozenset(
    {
        "firestore.googleapis.com",
        "identitytoolkit.googleapis.com",
        "firebaserules.googleapis.com",
    }
)
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})

# How a Ruleset release readback was obtained. A production transport reads the
# active release back through the Rules API; the local runtime has no readback
# route, so its transport echoes the digest of the bytes it published.
READBACK_RELEASE_GET = "release-get"
READBACK_PUBLISH_ECHO = "publish-echo"
READBACK_KINDS = (READBACK_RELEASE_GET, READBACK_PUBLISH_ECHO)

_ENDPOINT = re.compile(
    r"^(?P<host>[a-z0-9.-]{1,253}|\[[0-9a-f:]{2,39}\]|::1)(?::(?P<port>[0-9]{1,5}))?$"
)

# A key containing any of these substrings, at any depth and in any case, means
# a credential escaped the transport.
FORBIDDEN_KEY_TOKENS = (
    "apikey",
    "assertion",
    "authorization",
    "bearer",
    "cookie",
    "credential",
    "password",
    "passwd",
    "privatekey",
    "refresh",
    "secret",
    "serviceaccount",
    "token",
)

# Receipt keys the collector accepts. Anything else is a contract drift. The
# two wire keys are what a transport records about the connection it made:
# the host and port it reached, and its own request counter.
WIRE_RECEIPT_KEYS = frozenset({"endpoint", "wireSequence"})
OBSERVATION_RECEIPT_KEYS = (
    frozenset(
        {
            "status",
            "code",
            "httpStatus",
            "documentPresent",
            "fields",
            "failure",
            "complete",
        }
    )
    | WIRE_RECEIPT_KEYS
)
RECOVERY_RECEIPT_KEYS = (
    frozenset(
        {
            "status",
            "code",
            "httpStatus",
            "documentPresent",
            "accountPresent",
            "version",
            "uid",
            "tenantId",
            "fields",
            "failure",
            "complete",
        }
    )
    | WIRE_RECEIPT_KEYS
)
RULESET_RECEIPT_KEYS = (
    frozenset(
        {
            "status",
            "code",
            "httpStatus",
            "failure",
            "complete",
            "releaseName",
            "readbackKind",
            "readbackDigest",
        }
    )
    | WIRE_RECEIPT_KEYS
)

# A principal action receipt: the administrator action the transport applied
# to one owned account, the token facts it read (seconds, never the token),
# and an accounts:lookup readback of the account, fingerprinted.
PRINCIPAL_ACTION_RECEIPT_KEYS = (
    frozenset(
        {
            "status",
            "code",
            "httpStatus",
            "failure",
            "complete",
            "action",
            "authTime",
            "validSince",
            "present",
            "disabled",
            "uidFingerprint",
        }
    )
    | WIRE_RECEIPT_KEYS
)

_ACQUISITION_KEYS = frozenset(
    {
        "environment",
        "campaignManifestDigest",
        "nonceReservation",
        "ownerPermission",
        "artifact",
        "principals",
        "window",
    }
)
_ENVIRONMENT_FOR_ROLE = {
    ROLE_PRODUCTION: ENVIRONMENT_PRODUCTION,
    ROLE_LOCAL_SHADOW: ENVIRONMENT_LOCAL,
}
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX16 = re.compile(r"^[0-9a-f]{16}$")
_RELEASE_NAME = re.compile(r"^[A-Za-z0-9_./:-]{1,256}$")

_MAX_RECEIPT_KEYS = 24
_MAX_DEPTH = 6
_MAX_NODES = 256
_MAX_STRING = 4096
_JWT_SHAPE = re.compile(r"^[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*$")
# Google credential shapes that are not JWTs: OAuth access tokens, API keys and
# refresh tokens. A value with one of these prefixes is refused wherever a
# token-shaped value is.
_SECRET_PREFIXES = ("ya29.", "AIza", "1//")

RULES_MANAGEMENT_OBSERVATION = (
    "baseline-release-get",
    "baseline-ruleset-get",
    "baseline-executable-get",
    "create-a",
    "create-a-get",
    "patch-a",
    "patch-a-get",
    "patch-a-executable",
    "create-b",
    "create-b-get",
    "patch-b",
    "patch-b-get",
    "patch-b-executable",
)
RULES_MANAGEMENT_RECOVERY = (
    "restore-patch",
    "restore-get",
    "restore-executable",
    "restore-get-executable",
    "delete-a-get",
    "delete-a",
    "delete-a-absence",
    "delete-b-get",
    "delete-b",
    "delete-b-absence",
)
_RULESET_RESOURCE = re.compile(r"^projects/fireemu-35fe6/rulesets/[A-Za-z0-9_-]{1,128}$")
_RELEASE_RESOURCE = re.compile(r"^projects/fireemu-35fe6/releases/[A-Za-z0-9_.-]{1,128}$")


class RulesManagementReceipt(dict):
    """Typed Gate receipt carrying transport facts outside the REST body."""

    def __init__(self, value: Mapping[str, Any], *, endpoint: str | None = None, wire_sequence: int | None = None, response_body: Mapping[str, Any] | None = None):
        super().__init__(value)
        self.endpoint = endpoint
        self.wire_sequence = wire_sequence
        self.response_body = dict(response_body) if isinstance(response_body, Mapping) else None


def _rules_management_proof(
    slot: str, operation: Mapping[str, Any], body: Mapping[str, Any], status: int
) -> dict[str, Any]:
    """Build the sanitized Gate proof; REST response data never crosses it."""
    action = operation.get("action")
    subject_name = operation.get("rulesetName") or body.get("name")
    effect: dict[str, Any] | None = None
    if status == 404:
        effect = {
            "subject": str(subject_name or "ruleset/unknown"),
            "proof": {"kind": "absence", "resource": str(subject_name or "ruleset/unknown")},
        }
    elif action == "get" and isinstance(body.get("source"), dict):
        files = body["source"].get("files", [])
        content = files[0].get("content") if files and isinstance(files[0], dict) else None
        effect = {
            "subject": "release/baseline" if slot == "baseline-ruleset-get" else str(subject_name),
            "proof": {"kind": "ruleset", "name": body.get("name"), "sourceDigest": digest(content)},
        }
    elif action == "create":
        effect = {
            "subject": str(body.get("name")),
            "proof": {"kind": "ruleset", "name": body.get("name"), "sourceDigest": operation.get("sourceDigest")},
        }
    elif action in {"release-get", "release-patch", "release-get-executable"}:
        effect = {
            "subject": "release/baseline" if slot.startswith("baseline-") else "release/cloud.firestore",
            "proof": {"kind": "release", "name": body.get("name") or operation.get("releaseName"), "rulesetName": body.get("rulesetName")},
        }
    effects = [effect] if effect is not None and all(effect["proof"].get(key) is not None for key in ("kind",)) else []
    return {"kind": "rules-management-proof-v1", "responseDigest": digest(body), "effects": effects}


class RulesManagementError(ValueError):
    """A bounded management refusal with a collector-safe reason."""

    def __init__(self, reason: str, *, failure: str | None = None):
        super().__init__(reason)
        self.reason = reason
        self.failure = failure


def _management_cursor(gate) -> dict[str, list[str]]:
    """Return the durable management cursor without treating skips as receipts.

    Gate versions in this lane expose used operation identities and, when the
    recovery skip API is available, typed skip records.  The collector only
    consumes their identity fields here; skip disposition remains Gate-owned.
    """
    snapshot = gate.snapshot()
    used = snapshot.get("managementUsed", [])
    skipped = snapshot.get("managementSkipped", [])
    if not isinstance(used, list) or not isinstance(skipped, list):
        raise ValueError("typed management cursor required")
    used_ids = [identity for identity in used if isinstance(identity, str)]
    skipped_ids: list[str] = []
    for entry in skipped:
        identity = entry.get("id") if isinstance(entry, dict) else entry
        if not isinstance(identity, str):
            raise ValueError("typed management skip required")
        skipped_ids.append(identity)
    if len(used_ids) != len(used):
        raise ValueError("typed management receipt identity required")
    declared = [
        f"{phase}:{entry['id']}"
        for phase in ("observation", "recovery")
        for entry in snapshot.get("plan", {}).get("management", {}).get(phase, [])
        if isinstance(entry, dict) and isinstance(entry.get("id"), str)
    ]
    consumed = set(used_ids) | set(skipped_ids)
    ordered = [identity for identity in declared if identity in consumed]
    return {"used": used_ids, "skipped": skipped_ids, "ordered": ordered}


def _phase_cursor(cursor: Mapping[str, list[str]], phase: str) -> list[str]:
    """Select a phase's consumed identities; Gate supplies compiler order."""
    prefix = phase + ":"
    ordered = cursor.get("ordered")
    identities = ordered if isinstance(ordered, list) else cursor["used"] + cursor["skipped"]
    return [identity for identity in identities if identity.startswith(prefix)]


class RulesManagementSession:
    """Gate-owned Rules lifecycle with response-derived resource bindings.

    The callback is deliberately narrow: it receives a prepared transport
    operation and an absolute deadline and must return the bounded worker
    receipt. Names used after a create/read are copied only from validated
    response bodies; no plan-time or caller-supplied resource map is trusted.
    """

    def __init__(self, *, gate, ledger, ticket, execute, plan, setup_prefix=None, lifecycle_slice=None):
        if gate is None or ledger is None or not isinstance(ticket, dict):
            raise ValueError("Rules management requires real Gate and Ledger ownership")
        gate_plan = gate.snapshot().get("plan", {})
        management = gate_plan.get("management", {})
        observation_ids = [entry.get("id") for entry in management.get("observation", [])]
        rules_observation_ids = list(RULES_MANAGEMENT_OBSERVATION)
        lifecycle_bound = lifecycle_slice is not None
        if not lifecycle_bound and observation_ids[-len(rules_observation_ids) :] != rules_observation_ids:
            raise ValueError("Rules management observation suffix differs")
        observation_prefix_ids = (
            [identity for identity in observation_ids if identity not in rules_observation_ids]
            if lifecycle_bound
            else observation_ids[: -len(rules_observation_ids)]
        )
        recovery_ids = [entry.get("id") for entry in management.get("recovery", [])]
        rules_recovery_ids = list(RULES_MANAGEMENT_RECOVERY)
        if not lifecycle_bound and recovery_ids[-len(rules_recovery_ids) :] != rules_recovery_ids:
            raise ValueError("Rules management recovery suffix differs")
        recovery_prefix_ids = (
            [identity for identity in recovery_ids if identity not in rules_recovery_ids]
            if lifecycle_bound
            else recovery_ids[: -len(rules_recovery_ids)]
        )
        if lifecycle_slice is not None:
            if not isinstance(lifecycle_slice, dict):
                raise ValueError("compiled Rules lifecycle slice required")
            declared_observation = lifecycle_slice.get("observationIds")
            declared_recovery = lifecycle_slice.get("recoveryIds")
            if not isinstance(declared_observation, list) or not isinstance(declared_recovery, list):
                raise ValueError("compiled Rules lifecycle slice malformed")
            if declared_observation != rules_observation_ids or declared_recovery != rules_recovery_ids:
                raise ValueError("compiled Rules lifecycle slice differs")
            if any(identity not in observation_ids for identity in declared_observation) or any(identity not in recovery_ids for identity in declared_recovery):
                raise ValueError("compiled Rules lifecycle slice absent")
        if observation_prefix_ids or recovery_prefix_ids:
            if not isinstance(setup_prefix, dict):
                raise ValueError("compiled setup prefix proof required")
            proof_observation_ids = setup_prefix.get("observationIds", setup_prefix.get("ids"))
            proof_recovery_ids = setup_prefix.get("recoveryIds", [])
            if proof_observation_ids != observation_prefix_ids or proof_recovery_ids != recovery_prefix_ids:
                raise ValueError("compiled setup prefix differs")
            if setup_prefix.get("planDigest") != plan.get("planDigest"):
                raise ValueError("compiled setup prefix plan differs")
            if not isinstance(setup_prefix.get("journalDigest"), str) or not setup_prefix["journalDigest"]:
                raise ValueError("compiled setup journal proof required")
            if not isinstance(setup_prefix.get("proofDigest"), str) or not setup_prefix["proofDigest"]:
                raise ValueError("compiled setup ownership proof required")
        elif setup_prefix is not None:
            raise ValueError("unexpected compiled setup prefix")
        if (
            gate_plan.get("campaignId") != CAMPAIGN
            or gate_plan.get("project") != plan.get("project")
            or gate_plan.get("database") != plan.get("database")
            or (not lifecycle_bound and recovery_ids[-len(RULES_MANAGEMENT_RECOVERY) :] != list(RULES_MANAGEMENT_RECOVERY))
        ):
            raise ValueError("Rules management Gate plan binding differs")
        state = ledger.snapshot()
        reservation = ticket.get("reservation")
        row = state.get("reservations", {}).get(reservation)
        claim = row.get("claim") if isinstance(row, dict) else None
        if (
            ticket.get("ledgerPath") != str(ledger.path)
            or not isinstance(claim, dict)
            or claim.get("campaignId") != CAMPAIGN
            or claim.get("nonceDigest") != digest(plan.get("nonce"))
            or claim.get("manifestDigest") != digest(plan)
            or claim.get("gatePath") != str(gate.path.resolve())
            or claim.get("gatePlanDigest") != digest(gate_plan)
        ):
            raise ValueError("Rules management Ledger claim binding differs")
        self.gate = gate
        self.ledger = ledger
        self.ticket = ticket
        self.execute = execute
        self.plan = plan
        self.setup_prefix = dict(setup_prefix) if isinstance(setup_prefix, dict) else None
        self.setup_observation_prefix = observation_prefix_ids
        self.setup_recovery_prefix = recovery_prefix_ids
        self.lifecycle_slice = {
            "observationIds": list(rules_observation_ids),
            "recoveryIds": list(rules_recovery_ids),
        }
        self.baseline: dict[str, Any] | None = None
        self.created: dict[str, str] = {}
        self.owned: dict[str, dict[str, Any]] = {}
        self.active: dict[str, str] = {}
        self.receipts: list[dict[str, Any]] = []
        self.release_evidence: list[dict[str, Any]] = []
        self.observation_outcome = "coordinator-cancelled"
        self.observation_complete = False
        self.recovery_allowed = True
        self.journal = None

    def snapshot(self) -> dict[str, Any]:
        """Expose only response-derived lifecycle state for partial recovery."""
        return {
            "baseline": dict(self.baseline) if self.baseline is not None else None,
            "created": dict(self.created),
            "owned": {label: dict(state) for label, state in self.owned.items()},
            "active": dict(self.active),
            "releases": [dict(entry) for entry in self.release_evidence],
            "managementReceipts": [dict(entry) for entry in self.receipts],
        }

    def close_observation(self) -> None:
        """Close an interrupted observation cursor before recovery slots begin."""
        if self.observation_outcome == "may-have-landed":
            self.gate.abort_management_observation()
        else:
            self.gate.cancel_management_observation()

    def bind_journal(self, journal) -> None:
        """Attach the collector's existing durable journal for ownership facts."""
        self.journal = journal

    def _record_ownership(self, label: str) -> None:
        if self.journal is not None and label in self.owned:
            state = self.owned[label]
            self.journal.record(
                "rules-management-ownership",
                {
                    "label": label,
                    "name": state["name"],
                    "sourceDigest": state["sourceDigest"],
                    "phase": state["phase"],
                },
            )

    def _record_management(self, kind: str, payload: dict[str, Any]) -> None:
        if self.journal is not None:
            self.journal.record(kind, payload)

    def _dispatch(self, phase: str, slot: str, operation: dict[str, Any], *, allow_status: frozenset[int] = frozenset()) -> dict[str, Any]:
        self._record_management(
            "rules-management-intent",
            {
                "phase": phase,
                "slot": slot,
                "operationDigest": digest(operation),
            },
        )
        raw_response_body: dict[str, Any] | None = None

        def send(deadline: float) -> dict[str, Any]:
            nonlocal raw_response_body
            if self.ledger is not None:
                self.ledger.validate(self.ticket, duration=8)
            request = {
                "kind": "rules-lifecycle",
                "phase": "ruleset",
                "managementPhase": phase,
                "managementSlot": slot,
                **operation,
            }
            try:
                raw = self.execute(request, deadline=deadline)
            except BaseException:
                self.observation_outcome = "may-have-landed"
                self.recovery_allowed = False
                raise
            if not isinstance(raw, dict):
                raise ValueError("bounded Rules worker receipt required")
            endpoint = getattr(raw, "endpoint", None)
            wire_sequence = getattr(raw, "wire_sequence", None)
            self.receipts.append(
                {
                    "phase": phase,
                    "slot": slot,
                    "at": time.monotonic(),
                    "endpoint": endpoint,
                    "wireSequence": wire_sequence,
                }
            )
            self._record_management(
                "rules-management-receipt",
                {
                    "phase": phase,
                    "slot": slot,
                    "wireSequence": wire_sequence,
                    "endpoint": endpoint,
                    "responseDigest": digest(raw),
                },
            )
            credential_failure = _scan_management_receipt(raw)
            if credential_failure is not None:
                raise RulesManagementError(credential_failure)
            if isinstance(raw, RulesManagementReceipt) and raw.response_body is not None:
                raw_response_body = dict(raw.response_body)
                return raw
            status = raw.get("status")
            if not isinstance(status, int):
                raise ValueError("typed Rules HTTP status required")
            body = raw.get("body")
            if not isinstance(body, dict):
                raise ValueError("Rules management JSON body required")
            raw_response_body = dict(body)
            proof = _rules_management_proof(slot, operation, body, status)
            return RulesManagementReceipt(
                {
                "status": status,
                "complete": raw.get("complete") is not False,
                "workerReaped": raw.get("workerReaped", True) is True,
                "bodyKind": "json",
                    "body": proof,
                },
                endpoint=endpoint,
                wire_sequence=wire_sequence,
            )

        receipt = self.gate.management_dispatch(phase, slot, send)
        if phase == "observation" and receipt.get("complete") is False:
            self.observation_outcome = "may-have-landed"
        if not isinstance(receipt, dict) or receipt.get("complete") is not True or receipt.get("workerReaped") is not True:
            raise ValueError("Rules management slot incomplete")
        status = receipt.get("status")
        if not isinstance(status, int) or not (200 <= status < 300 or status in allow_status):
            raise ValueError("Rules management HTTP failure")
        persisted_proof = receipt.get("body")
        if isinstance(persisted_proof, dict) and persisted_proof.get("kind") == "rules-management-proof-v1":
            if raw_response_body is None or persisted_proof.get("responseDigest") != digest(raw_response_body):
                raise ValueError("Rules management proof digest mismatch")
        body = raw_response_body
        if body is None and isinstance(receipt, RulesManagementReceipt):
            body = receipt.response_body
        if not isinstance(body, dict):
            raise ValueError("Rules management JSON body required")
        if status in allow_status:
            error = body.get("error")
            if status != 404 or not isinstance(error, dict) or error.get("code") != 404:
                raise ValueError("typed Ruleset absence required")
        return body

    @staticmethod
    def _release(body: Any, expected_name: str | None = None) -> tuple[str, str]:
        if not isinstance(body, dict) or not {"name", "rulesetName"}.issubset(body):
            raise ValueError("release readback shape refused")
        name, ruleset = body["name"], body["rulesetName"]
        if not isinstance(name, str) or _RELEASE_RESOURCE.fullmatch(name) is None or not isinstance(ruleset, str) or _RULESET_RESOURCE.fullmatch(ruleset) is None:
            raise ValueError("release resource binding refused")
        if expected_name is not None and name != expected_name:
            raise ValueError("registered release binding changed")
        return name, ruleset

    @staticmethod
    def _ruleset(body: Any, expected_digest: str | None, expected_name: str | None = None) -> str:
        if not isinstance(body, dict) or not {"name", "source"}.issubset(body):
            raise ValueError("Ruleset readback shape refused")
        name, source = body["name"], body["source"]
        if not isinstance(name, str) or _RULESET_RESOURCE.fullmatch(name) is None or not isinstance(source, dict) or set(source) != {"files"}:
            raise ValueError("Ruleset resource binding refused")
        files = source["files"]
        if not isinstance(files, list) or len(files) != 1 or not isinstance(files[0], dict) or set(files[0]) != {"name", "content"} or files[0]["name"] != "firestore.rules" or not isinstance(files[0]["content"], str) or (expected_digest is not None and digest(files[0]["content"]) != expected_digest):
            raise ValueError("Ruleset source digest mismatch")
        if expected_name is not None and name != expected_name:
            raise ValueError("Ruleset name changed")
        return name

    @staticmethod
    def _ruleset_digest(body: Any) -> str:
        if not isinstance(body, dict) or not isinstance(body.get("source"), dict):
            raise ValueError("Ruleset source required")
        files = body["source"].get("files")
        if not isinstance(files, list) or len(files) != 1 or not isinstance(files[0], dict) or not isinstance(files[0].get("content"), str):
            raise ValueError("Ruleset source required")
        return digest(files[0]["content"])

    def run_observation(self, labels: tuple[str, ...] | None = None) -> dict[str, Any]:
        """Capture the baseline, publish A/B, and verify each active release."""
        if self.baseline is None:
            release_name, baseline_ruleset = self._release(
                self._dispatch("observation", "baseline-release-get", {"action": "release-get", "releaseName": "projects/fireemu-35fe6/releases/cloud.firestore"})
            )
            baseline_body = self._dispatch("observation", "baseline-ruleset-get", {"action": "get", "rulesetName": baseline_ruleset})
            baseline_digest = self._ruleset_digest(baseline_body)
            baseline_ruleset = self._ruleset(baseline_body, None, baseline_ruleset)
            executable = self._dispatch("observation", "baseline-executable-get", {"action": "release-get-executable", "releaseName": release_name})
            if executable.get("rulesetName") != baseline_ruleset:
                raise ValueError("baseline executable differs")
            self.baseline = {"releaseName": release_name, "rulesetName": baseline_ruleset, "sourceDigest": baseline_digest}
            self._record_management("rules-management-baseline", dict(self.baseline))
        release_name = self.baseline["releaseName"]
        labels = labels or ("A", "B")
        for label in labels:
            if label in self.active:
                continue
            patch_base = label.lower()
            source_digest = digest(self.plan["rulesets"][label]["source"])
            created = self._dispatch("observation", f"create-{patch_base}", {"action": "create", "label": label, "sourceDigest": source_digest})
            if not isinstance(created, dict) or not isinstance(created.get("name"), str) or _RULESET_RESOURCE.fullmatch(created["name"]) is None:
                raise ValueError("created Ruleset name missing")
            self.owned[label] = {
                "name": created["name"],
                "sourceDigest": source_digest,
                "phase": "created-unverified",
            }
            self._record_ownership(label)
            name = self._ruleset(self._dispatch("observation", f"create-{patch_base}-get", {"action": "get", "rulesetName": created["name"]}), source_digest, created["name"])
            self.created[label] = name
            self.owned[label]["phase"] = "created-verified"
            self.owned[label]["name"] = name
            self.owned[label]["sourceDigest"] = source_digest
            self.owned[label]["phase"] = "patch-uncertain"
            self._record_ownership(label)
            self._dispatch("observation", f"patch-{patch_base}", {"action": "release-patch", "releaseName": release_name, "rulesetName": name})
            patch_receipt = self.receipts[-1]
            active_name, active_ruleset = self._release(self._dispatch("observation", f"patch-{patch_base}-get", {"action": "release-get", "releaseName": release_name}), release_name)
            if active_name != release_name or active_ruleset != name:
                raise ValueError("active Ruleset binding differs")
            executable = self._dispatch("observation", f"patch-{patch_base}-executable", {"action": "release-get-executable", "releaseName": release_name})
            if executable.get("rulesetName") != name:
                raise ValueError("active executable differs")
            self.active[label] = name
            self.owned[label]["phase"] = "active-verified"
            self._record_ownership(label)
            self.release_evidence.append(
                {
                    "label": label,
                    "sourceDigest": source_digest,
                    "releaseName": release_name,
                    "readback": {"kind": READBACK_RELEASE_GET, "digest": source_digest},
                    "endpoint": patch_receipt.get("endpoint"),
                    "wireSequence": patch_receipt.get("wireSequence"),
                    "beforeIndex": next(
                        operation["index"] for operation in self.plan["observation"]
                        if operation["ruleset"] == label
                    ),
                    "activeFrom": patch_receipt.get("at"),
                }
            )
        self.observation_complete = set(("A", "B")) <= set(self.active)
        return {
            **self.snapshot(),
        }

    def run_recovery(self) -> dict[str, Any]:
        """Restore only the captured baseline and prove created absence."""
        if self.baseline is None:
            raise ValueError("Rules observation baseline required before recovery")
        if self.setup_recovery_prefix:
            cursor = _management_cursor(self.gate)
            actual = _phase_cursor(cursor, "recovery")
            expected = ["recovery:" + slot for slot in self.setup_recovery_prefix]
            if actual[: len(expected)] != expected:
                raise ValueError("compiled setup recovery prefix not consumed")
        release_name = self.baseline["releaseName"]
        current_name, current_target = self._release(
            self._dispatch("recovery", "restore-patch", {"action": "release-get", "releaseName": release_name}),
            release_name,
        )
        owned_names = {
            state["name"]
            for state in self.owned.values()
            if isinstance(state.get("name"), str)
        }
        if current_target != self.baseline["rulesetName"] and current_target not in owned_names:
            raise ValueError("foreign current Ruleset refuses restore")
        self._dispatch(
            "recovery",
            "restore-get",
            {
                "action": "release-patch",
                "releaseName": release_name,
                "rulesetName": self.baseline["rulesetName"],
            },
        )
        restored_name, restored_target = self._release(
            self._dispatch("recovery", "restore-executable", {"action": "release-get", "releaseName": release_name}),
            release_name,
        )
        if restored_name != release_name or restored_target != self.baseline["rulesetName"]:
            raise ValueError("restore readback differs")
        executable = self._dispatch("recovery", "restore-get-executable", {"action": "release-get-executable", "releaseName": release_name})
        if executable.get("rulesetName") != self.baseline["rulesetName"]:
            raise ValueError("restored executable differs")
        held: list[str] = []
        for label, state in self.owned.items():
            name = state["name"]
            if state.get("phase") == "created-unverified":
                held.append(name)
                continue
            source_digest = state["sourceDigest"]
            self._ruleset(self._dispatch("recovery", f"delete-{label.lower()}-get", {"action": "get", "rulesetName": name}), source_digest, name)
            self._dispatch("recovery", f"delete-{label.lower()}", {"action": "delete", "rulesetName": name})
            self._dispatch("recovery", f"delete-{label.lower()}-absence", {"action": "get", "rulesetName": name}, allow_status=frozenset({404}))
        return {"restored": True, "rulesetName": self.baseline["rulesetName"], "held": held, "cleanupComplete": not held}



class BudgetExhausted(RuntimeError):
    """Raised internally when a bound stops further requests."""


def _now() -> float:
    return time.monotonic()


def credential_fingerprint(nonce: str, ref: str) -> str:
    """Bind a row to its principal without recording anything secret."""
    return digest(["credential-ref", nonce, ref])[:16]


_credential_fingerprint = credential_fingerprint


def endpoint_host(endpoint: str) -> str | None:
    """The host of a ``host[:port]`` endpoint a transport reported, or None.

    A scheme, a path, a query, userinfo or anything but a host and a port is
    not an endpoint but a URL, and a URL is not recorded.
    """
    match = _ENDPOINT.fullmatch(endpoint) if isinstance(endpoint, str) else None
    if match is None:
        return None
    port = match.group("port")
    if port is not None and not 0 < int(port) < 65536:
        return None
    host = match.group("host")
    return host[1:-1] if host.startswith("[") else host


def _scan(value: Any, depth: int, budget: list[int]) -> str | None:
    """Recursively reject credential-shaped keys and token-shaped values."""
    budget[0] -= 1
    if budget[0] < 0:
        return "receipt-too-large"
    if depth > _MAX_DEPTH:
        return "receipt-too-deep"
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if not isinstance(key, str):
                return "non-string-receipt-key"
            lowered = key.lower()
            for marker in FORBIDDEN_KEY_TOKENS:
                if marker in lowered:
                    return f"credential-leak:{key}"
            failure = _scan(nested, depth + 1, budget)
            if failure is not None:
                return failure
        return None
    if isinstance(value, (list, tuple)):
        for nested in value:
            failure = _scan(nested, depth + 1, budget)
            if failure is not None:
                return failure
        return None
    if isinstance(value, str):
        if len(value) > _MAX_STRING:
            return "receipt-string-too-long"
        if any(character < " " or character == "\x7f" for character in value):
            return "control-character-in-receipt"
        if _JWT_SHAPE.fullmatch(value) or value.startswith(_SECRET_PREFIXES):
            return "credential-leak:token-shaped-value"
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return "nonfinite-receipt-value"
    if isinstance(value, (bool, int, float)) or value is None:
        return None
    return "unsupported-receipt-value"


def _scan_management_receipt(value: Any) -> str | None:
    """Scan management metadata while allowing Rules source text newlines."""
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if not isinstance(key, str):
                return "non-string-receipt-key"
            lowered = key.lower()
            for marker in FORBIDDEN_KEY_TOKENS:
                if marker in lowered:
                    return f"credential-leak:{key}"
            if (
                key == "endpoint"
                and isinstance(nested, str)
                and endpoint_host(nested) in PRODUCTION_HOSTS | LOOPBACK_HOSTS
            ):
                continue
            if key == "content":
                continue
            failure = _scan_management_receipt(nested)
            if failure is not None:
                return failure
        return None
    if isinstance(value, (list, tuple)):
        for nested in value:
            failure = _scan_management_receipt(nested)
            if failure is not None:
                return failure
        return None
    return _scan(value, 0, [_MAX_NODES])


def _accept(
    receipt: Any, allowed: frozenset[str]
) -> tuple[dict[str, Any] | None, str | None]:
    if not isinstance(receipt, Mapping):
        return None, "invalid-receipt"
    if len(receipt) > _MAX_RECEIPT_KEYS:
        return None, "receipt-too-large"
    failure = _scan(receipt, 0, [_MAX_NODES])
    if failure is not None:
        return None, failure
    unknown = sorted(key for key in receipt if key not in allowed)
    if unknown:
        return None, "unknown-receipt-key:" + ",".join(unknown)
    if receipt.get("complete") is True and receipt.get("failure") is not None:
        return None, "explicit-receipt-failure"
    return dict(receipt), None


class _Journal:
    """Append-only, fsynced record of every intent and outcome.

    A healthy journal records attempted resources. Any open/write/sync/close
    failure latches observation off and disqualifies completion. A partial
    journal is not a complete inventory or restart-time deletion authority.
    """

    def __init__(self, path: str | os.PathLike[str] | None) -> None:
        self.path = Path(path) if path is not None else None
        self._handle = None
        self.failures: list[str] = []
        if self.path is not None:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                self._handle = self.path.open("a", encoding="utf-8")
            except Exception as error:  # noqa: BLE001 -- keep recovery possible
                self.failures.append("journal-open:" + type(error).__name__)

    def record(self, kind: str, payload: dict[str, Any]) -> None:
        # After a partial write, never append records behind a corrupt line.
        # The failure latches observation off; typed recovery still uses its
        # original plan and reserve. A failed journal cannot yield a pass.
        if self._handle is None or self.failures:
            return
        try:
            line = json.dumps(
                {"kind": kind, **payload},
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            self._handle.write(line + "\n")
            self._handle.flush()
            os.fsync(self._handle.fileno())
        except Exception as error:  # noqa: BLE001 -- type only, no secret content
            self.failures.append("journal-record:" + type(error).__name__)

    def close(self) -> None:
        if self._handle is not None:
            try:
                self._handle.close()
            except Exception as error:  # noqa: BLE001 -- close is part of recording
                self.failures.append("journal-close:" + type(error).__name__)
            finally:
                self._handle = None


def open_ownership_journal(
    path: str | os.PathLike[str] | None,
    *,
    run_id: str,
    plan_digest: str,
) -> _Journal:
    """Open the one durable journal shared by setup, collection and recovery."""
    if not isinstance(run_id, str) or not run_id:
        raise ValueError("run identity required")
    if not isinstance(plan_digest, str) or not plan_digest:
        raise ValueError("plan digest required")
    journal = _Journal(path)
    journal.record("run", {"runId": run_id, "plan": plan_digest})
    return journal


class _Budget:
    def __init__(
        self,
        *,
        requests: int,
        recovery: int,
        rulesets: int,
        actions: int,
        deadline_seconds: float,
        recovery_deadline_seconds: float,
        clock: Callable[[], float],
    ) -> None:
        self._requests = requests
        self._recovery = recovery
        self._rulesets = rulesets
        self._actions = actions
        self._clock = clock
        self._clock_failure: str | None = None
        self._last_clock: float | int | None = None
        self.spent = 0
        self.recovery_spent = 0
        self.ruleset_spent = 0
        self.action_spent = 0
        self.started: float | int | None = None
        try:
            started = self._read_clock()
            self.started = started
        except BudgetExhausted:
            # The plan can already own setup resources. Return explicit held
            # responsibilities instead of losing the whole result on bad time.
            started = 0.0
        self._deadline = started + deadline_seconds
        self._recovery_deadline = started + recovery_deadline_seconds

    def _read_clock(self) -> float | int:
        if self._clock_failure is not None:
            raise BudgetExhausted(self._clock_failure)
        try:
            value = self._clock()
            valid = type(value) in (int, float) and math.isfinite(value) and value >= 0
        except Exception:  # noqa: BLE001 -- untrusted clock must never enable I/O
            self._clock_failure = "invalid-clock"
            raise BudgetExhausted(self._clock_failure) from None
        if not valid:
            self._clock_failure = "invalid-clock"
        elif self._last_clock is not None and value < self._last_clock:
            self._clock_failure = "clock-regressed"
        if self._clock_failure is not None:
            raise BudgetExhausted(self._clock_failure)
        self._last_clock = value
        return value

    def take_observation(self) -> float | int:
        if self.spent >= self._requests:
            raise BudgetExhausted("observation-request-ceiling")
        now = self._read_clock()
        if now >= self._deadline:
            raise BudgetExhausted("deadline-exhausted")
        self.spent += 1
        return now

    def take_ruleset(self) -> float | int:
        """A Ruleset release is an observation-phase request with its own ceiling."""
        if self.ruleset_spent >= self._rulesets:
            raise BudgetExhausted("ruleset-request-ceiling")
        now = self._read_clock()
        if now >= self._deadline:
            raise BudgetExhausted("deadline-exhausted")
        self.ruleset_spent += 1
        return now

    def take_action(self) -> float | int:
        """An administrator step between rows, with its own ceiling."""
        if self.action_spent >= self._actions:
            raise BudgetExhausted("principal-action-ceiling")
        now = self._read_clock()
        if now >= self._deadline:
            raise BudgetExhausted("deadline-exhausted")
        self.action_spent += 1
        return now

    def take_recovery(self) -> float | int:
        if self.recovery_spent >= self._recovery:
            raise BudgetExhausted("recovery-request-ceiling")
        now = self._read_clock()
        if now >= self._recovery_deadline:
            raise BudgetExhausted("recovery-deadline-exhausted")
        self.recovery_spent += 1
        return now

    def stamp(self) -> float | int | None:
        """A clock reading for the record, or None once the clock has failed."""
        try:
            return self._read_clock()
        except BudgetExhausted:
            return None


class _Wire:
    """What the transport says about every connection it made.

    A bound run requires the endpoint and the wire sequence on every receipt;
    an unbound run records them when present. Either way a value that is
    present must be well formed, allowlisted and, in a bound run, inside the
    environment the run was declared in.
    """

    def __init__(self, environment: str | None) -> None:
        self.environment = environment
        self.endpoints: set[str] = set()
        self.receipts = 0
        self.sequenced = 0
        self.first: int | None = None
        self.last: int | None = None
        self.monotonic = True

    def note(self, receipt: Mapping[str, Any]) -> tuple[dict[str, Any], str | None]:
        """Record the wire facts of one accepted receipt; name a contradiction."""
        self.receipts += 1
        facts: dict[str, Any] = {"endpoint": None, "wireSequence": None}
        endpoint = receipt.get("endpoint")
        sequence = receipt.get("wireSequence")
        bound = self.environment is not None
        if endpoint is None and sequence is None:
            return facts, "unbound-receipt" if bound else None
        if endpoint is None or sequence is None:
            return facts, "unbound-receipt"
        host = endpoint_host(endpoint) if isinstance(endpoint, str) else None
        if host is None:
            return facts, "invalid-endpoint"
        if host in PRODUCTION_HOSTS:
            reached = ENVIRONMENT_PRODUCTION
        elif host in LOOPBACK_HOSTS:
            reached = ENVIRONMENT_LOCAL
        else:
            return facts, "endpoint-not-allowlisted"
        if bound and reached != self.environment:
            return facts, "endpoint-outside-environment"
        if type(sequence) is not int or sequence < 0:
            return facts, "invalid-wire-sequence"
        facts = {"endpoint": endpoint, "wireSequence": sequence}
        self.endpoints.add(endpoint)
        self.sequenced += 1
        if self.first is None:
            self.first = sequence
        elif self.last is not None and sequence <= self.last:
            self.monotonic = False
            self.last = sequence
            return facts, "wire-sequence-regressed"
        self.last = sequence
        return facts, None

    def record(self) -> dict[str, Any]:
        return {
            "endpoints": sorted(self.endpoints),
            "receipts": self.receipts,
            "sequencedReceipts": self.sequenced,
            "firstSequence": self.first,
            "lastSequence": self.last,
            "sequenceMonotonic": self.monotonic and self.sequenced == self.receipts,
        }

    def reached_only(self, environment: str) -> bool:
        hosts = {endpoint_host(endpoint) for endpoint in self.endpoints}
        allowed = (
            PRODUCTION_HOSTS
            if environment == ENVIRONMENT_PRODUCTION
            else LOOPBACK_HOSTS
        )
        return bool(hosts) and hosts <= allowed and self.sequenced == self.receipts


def start_context(
    plan: Mapping[str, Any],
    *,
    environment: str | None,
    journal: Any,
    deadline_seconds: float = 600.0,
    recovery_deadline_seconds: float = 900.0,
    clock: Callable[[], float] = _now,
    attempted: list[str] | None = None,
    worker_state: dict[str, bool] | None = None,
) -> RulesRecoveryContext:
    """Create one bounded run context before setup; callers reuse it in collect."""
    if environment not in {None, ENVIRONMENT_PRODUCTION, ENVIRONMENT_LOCAL}:
        raise ValueError("unknown recovery environment")
    accounts = plan["ownedAccounts"]
    budget = _Budget(
        requests=len(plan["observation"]),
        recovery=3 * (len(plan["ownedResources"]) + len(accounts)),
        rulesets=ruleset_transitions(plan["observation"]),
        actions=len(principal_actions(plan)),
        deadline_seconds=float(deadline_seconds),
        recovery_deadline_seconds=float(recovery_deadline_seconds),
        clock=clock,
    )
    return RulesRecoveryContext(
        budget=budget,
        wire=_Wire(environment),
        journal=journal,
        attempted=attempted if attempted is not None else [],
        worker_state=worker_state,
    )


def _validate_acquisition(
    acquisition: Any, role: str, plan: Mapping[str, Any]
) -> dict[str, Any]:
    """Refuse a launcher binding set that is malformed, secret-bearing or that
    contradicts the role. The bindings are recorded, not trusted: the
    acquisition comparator verifies each one against the plan and the sources."""
    if not isinstance(acquisition, Mapping):
        raise TypeError("acquisition bindings must be a mapping")
    if set(acquisition) != _ACQUISITION_KEYS:
        raise ValueError("acquisition bindings must carry exactly the known keys")
    failure = _scan(acquisition, 0, [_MAX_NODES])
    if failure is not None:
        raise ValueError("acquisition bindings refused: " + failure)
    environment = acquisition["environment"]
    kind = environment.get("kind") if isinstance(environment, Mapping) else None
    if kind != _ENVIRONMENT_FOR_ROLE[role]:
        raise ValueError("acquisition environment contradicts the collector role")
    if not _hex(acquisition["campaignManifestDigest"], _HEX64):
        raise ValueError("campaign manifest digest required")
    reservation = acquisition["nonceReservation"]
    if reservation is not None and (
        not isinstance(reservation, Mapping)
        or set(reservation) != {"reservationId", "campaignId", "nonceDigest"}
        or not isinstance(reservation["reservationId"], str)
        or not reservation["reservationId"]
        or reservation["campaignId"] != CAMPAIGN
        or reservation["nonceDigest"] != digest(plan["nonce"])
    ):
        raise ValueError("nonce reservation does not bind this campaign nonce")
    permission = acquisition["ownerPermission"]
    if permission is not None and (
        not isinstance(permission, Mapping)
        or set(permission) != {"kind", "permissionDigest"}
        or not isinstance(permission["kind"], str)
        or not _hex(permission["permissionDigest"], _HEX64)
    ):
        raise ValueError("owner permission reference malformed")
    artifact = acquisition["artifact"]
    if artifact is not None and (
        not isinstance(artifact, Mapping)
        or set(artifact) != {"artifactSha256", "sourceCommit"}
        or not _hex(artifact["artifactSha256"], _HEX64)
        or not _hex(artifact["sourceCommit"], _HEX40)
    ):
        raise ValueError("artifact binding malformed")
    principals = acquisition["principals"]
    if not isinstance(principals, Mapping) or not set(principals) <= set(
        ACCOUNT_PRINCIPALS
    ):
        raise ValueError("principal bindings must name campaign principals only")
    for entry in principals.values():
        if (
            not isinstance(entry, Mapping)
            or set(entry) != {"uidFingerprint", "provider", "tenant", "claimsDigest"}
            or not _hex(entry["uidFingerprint"], _HEX16)
            or not isinstance(entry["provider"], str)
            or not (entry["tenant"] is None or isinstance(entry["tenant"], str))
            or not _hex(entry["claimsDigest"], _HEX64)
        ):
            raise ValueError("principal binding malformed")
    window = acquisition["window"]
    if window is not None and (
        not isinstance(window, Mapping)
        or set(window) != {"startsAt", "expiresAt"}
        or not all(_finite(window[key]) for key in ("startsAt", "expiresAt"))
        or not window["startsAt"] < window["expiresAt"]
    ):
        raise ValueError("approval window malformed")
    return json.loads(json.dumps(acquisition, allow_nan=False))


def _hex(value: Any, pattern: re.Pattern[str]) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _finite(value: Any) -> bool:
    return type(value) in (int, float) and math.isfinite(value)


def ruleset_transitions(operations: list[Mapping[str, Any]]) -> int:
    """How many releases the matrix needs: one per change of Ruleset label."""
    count = 0
    active = None
    for operation in operations:
        if operation["ruleset"] != active:
            active = operation["ruleset"]
            count += 1
    return count


def _request(operation: Mapping[str, Any], nonce: str) -> dict[str, Any]:
    return {
        "caseId": operation["caseId"],
        "index": operation["index"],
        "ruleset": operation["ruleset"],
        "method": operation["method"],
        "resources": list(operation["resources"]),
        "writes": [dict(write) for write in operation["writes"]],
        "createdDocuments": list(operation["createdDocuments"]),
        "credentialRef": operation["credential"]["ref"],
        "credentialClass": operation["credential"]["class"],
        "credentialFingerprint": _credential_fingerprint(
            nonce, operation["credential"]["ref"]
        ),
    }


def collect(
    plan: Mapping[str, Any],
    execute: Callable[[dict[str, Any]], Any],
    *,
    role: str,
    run_id: str,
    deadline_seconds: float = 600.0,
    recovery_deadline_seconds: float = 900.0,
    clock: Callable[[], float] = _now,
    journal_path: str | os.PathLike[str] | None = None,
    acquisition: Mapping[str, Any] | None = None,
    wall_clock: Callable[[], float] = time.time,
    management_session: RulesManagementSession | None = None,
    journal: _Journal | None = None,
    ownership: dict[str, dict[str, Any]] | None = None,
    recovery_dispatch: Callable[[dict[str, Any]], Any] | None = None,
    context: RulesRecoveryContext | None = None,
) -> dict[str, Any]:
    """Run the compiled matrix through ``execute`` under enforced bounds.

    The returned bundle is always ``productionReady: False``. Collecting rows is
    not authority to promote them; that is a separate review.

    With ``acquisition`` the run is bound: every receipt must carry the wire
    facts, the endpoints must belong to the declared environment, and each
    Ruleset is released through an explicit, checked step before the rows that
    depend on it.
    """
    validate_case(plan)
    if role not in ROLES:
        raise ValueError("unknown collector role")
    if not isinstance(run_id, str) or not run_id:
        raise ValueError("run identity required")
    for value in (deadline_seconds, recovery_deadline_seconds):
        if type(value) not in (int, float) or not 0 < value <= 3600:
            raise ValueError("deadline out of range")
    if recovery_deadline_seconds < deadline_seconds:
        raise ValueError("recovery deadline must not precede the observation deadline")
    bindings = (
        _validate_acquisition(acquisition, role, plan)
        if acquisition is not None
        else None
    )
    environment = bindings["environment"]["kind"] if bindings is not None else None

    nonce = plan["nonce"]
    operations = plan["observation"]
    accounts = plan["ownedAccounts"]
    transitions = ruleset_transitions(operations) if bindings is not None else 0
    action_count = len(principal_actions(plan)) if bindings is not None else 0
    if context is not None:
        budget = context.budget
        wire = context.wire
        journal = context.journal
        attempted = context.attempted
        worker_state = context.worker_state
    else:
        budget = _Budget(
            requests=len(operations),
            recovery=3 * (len(plan["ownedResources"]) + len(accounts)),
            rulesets=transitions,
            actions=action_count,
            deadline_seconds=float(deadline_seconds),
            recovery_deadline_seconds=float(recovery_deadline_seconds),
            clock=clock,
        )
        wire = _Wire(environment)
    wall_started = _read_wall_clock(wall_clock)
    sources = source_digests()
    observer = {
        "contract": COLLECTOR_CONTRACT,
        "sourceDigests": sources,
        "observerDigest": digest(sources),
    }
    journal_owned = context is None and journal is None
    journal = journal or open_ownership_journal(
        journal_path, run_id=run_id, plan_digest=plan["planDigest"]
    )
    if bindings is not None:
        reservation = bindings["nonceReservation"]
        journal.record(
            "acquisition",
            {
                "environment": environment,
                "campaignManifestDigest": bindings["campaignManifestDigest"],
                "reservationId": (
                    reservation["reservationId"] if reservation is not None else None
                ),
                "observerDigest": observer["observerDigest"],
            },
        )

    rows: list[dict[str, Any]] = []
    releases: list[dict[str, Any]] = []
    actions: list[dict[str, Any]] = []
    if context is None:
        attempted = []
    # Every account exists before the first row, so all of them are owned.
    attempted_accounts = [entry["ref"] for entry in accounts]
    journal.record("accounts", {"refs": attempted_accounts})
    failures: list[str] = []
    abort: str | None = None
    worker_reaped: bool | None = None
    if context is None:
        worker_state = {"unreaped": False}
    active_ruleset: str | None = None
    rules_management: dict[str, Any] | None = None

    try:
        if (
            bindings is not None
            and role == ROLE_PRODUCTION
            and management_session is None
        ):
            raise ValueError("production Rules management session required")
        if management_session is not None:
            if bindings is None or role != ROLE_PRODUCTION:
                raise ValueError("Rules management requires bound production acquisition")
            management_session.bind_journal(journal)
            rules_management = management_session.snapshot()
            rules_management = management_session.run_observation(labels=("A",))
            for receipt in management_session.receipts:
                facts, receipt_failure = wire.note(receipt)
                if receipt_failure is not None:
                    raise RulesManagementError(
                        receipt_failure,
                        failure=f"ruleset:A:{receipt_failure}",
                    )
            releases.extend(rules_management.get("releases", []))
            for _ in rules_management.get("releases", []):
                budget.take_ruleset()
        for operation in operations:
            if journal.failures:
                abort = "journal-failure"
                break
            if bindings is not None and management_session is None and operation["ruleset"] != active_ruleset:
                release, release_failure = _release_ruleset(
                    plan, execute, budget, wire, journal, operation,
                    worker_state=worker_state,
                )
                if release_failure is not None:
                    failures.append(f"ruleset:{operation['ruleset']}:{release_failure}")
                    abort = release_failure
                    break
                releases.append(release)
                active_ruleset = operation["ruleset"]
            elif management_session is not None and operation["ruleset"] not in management_session.active:
                observed_receipts = len(management_session.receipts)
                management_session.run_observation(labels=(operation["ruleset"],))
                for receipt in management_session.receipts[observed_receipts:]:
                    facts, receipt_failure = wire.note(receipt)
                    if receipt_failure is not None:
                        raise RulesManagementError(receipt_failure)
                releases.extend(
                    management_session.release_evidence[len(releases):]
                )
                budget.take_ruleset()
                rules_management = management_session.snapshot()
            if bindings is not None and operation.get("principalAction"):
                action, action_failure = _apply_principal_action(
                    execute, budget, wire, journal, operation, bindings,
                    worker_state=worker_state,
                )
                if action_failure is not None:
                    ref = operation["principalAction"]["ref"]
                    failures.append(f"principal-action:{ref}:{action_failure}")
                    abort = action_failure
                    break
                actions.append(action)
            request = _request(operation, nonce)
            try:
                at = budget.take_observation()
            except BudgetExhausted as error:
                abort = str(error)
                break
            for document in operation["createdDocuments"]:
                resource = _resource_for(plan, document)
                if resource not in attempted:
                    attempted.append(resource)
                    journal.record("attempt", {"resource": resource})
            journal.record(
                "request", {"caseId": request["caseId"], "index": request["index"]}
            )
            if journal.failures:
                abort = "journal-failure"
                break
            try:
                raw = execute(dict(request))
            except Exception as error:  # noqa: BLE001 - type name only, no message
                status = getattr(error, "worker_reaped", None)
                if type(status) is bool:
                    worker_reaped = status
                _note_worker_failure(worker_state, error)
                raw, receipt_failure = None, f"transport:{type(error).__name__}"
            else:
                raw, receipt_failure = _accept(raw, OBSERVATION_RECEIPT_KEYS)
            facts: dict[str, Any] = {"endpoint": None, "wireSequence": None}
            if receipt_failure is None:
                facts, receipt_failure = wire.note(raw)
            if receipt_failure is not None:
                rows.append(_row(request, None, receipt_failure, at, facts))
                failures.append(f"{operation['caseId']}:{receipt_failure}")
                abort = receipt_failure
                journal.record(
                    "outcome",
                    {"caseId": request["caseId"], "failure": receipt_failure},
                )
                break
            rows.append(_row(request, raw, None, at, facts))
            journal.record(
                "outcome",
                {"caseId": request["caseId"], "status": raw.get("status")},
            )
            if raw.get("complete") is not True:
                failures.append(f"{operation['caseId']}:incomplete")
                abort = "incomplete-receipt"
                break

    except Exception as error:  # noqa: BLE001 -- processing must not skip recovery
        abort = getattr(error, "reason", None) or "collector:" + type(error).__name__
        failures.append(getattr(error, "failure", None) or abort)
        if (
            management_session is not None
            and not management_session.observation_complete
        ):
            try:
                management_session.close_observation()
            except Exception as close_error:  # noqa: BLE001 - retain the original ownership facts
                management_session.recovery_allowed = False
                if not failures:
                    failures.append("rules-management-close:" + type(close_error).__name__)
            rules_management = management_session.snapshot()
    finally:
        observation_finished = budget.stamp()
        try:
            if worker_state["unreaped"]:
                cleanup = _blocked_cleanup(plan, attempted, worker_reaped=False)
            else:
                if ownership is None and (bindings is None or role != ROLE_PRODUCTION):
                    cleanup = _recover(
                        plan, execute, budget, wire, attempted, journal,
                        worker_state=worker_state,
                    )
                else:
                    cleanup = recover_owned(
                        plan, execute, budget, wire, attempted, journal,
                        ownership=ownership,
                        recovery_dispatch=recovery_dispatch,
                        worker_state=worker_state,
                    )
                if worker_state["unreaped"]:
                    cleanup = _blocked_cleanup(plan, attempted, worker_reaped=False)
            if management_session is not None and not management_session.recovery_allowed:
                rules_management = management_session.snapshot()
                rules_management["recovery"] = {
                    "restored": False,
                    "cleanupComplete": False,
                    "held": [
                        state["name"]
                        for state in management_session.owned.values()
                        if isinstance(state.get("name"), str)
                    ],
                }
            if management_session is not None and management_session.recovery_allowed and not worker_state["unreaped"]:
                try:
                    observed_receipts = len(rules_management.get("managementReceipts", [])) if rules_management is not None else 0
                    rules_management["recovery"] = management_session.run_recovery()
                    for receipt in management_session.receipts[observed_receipts:]:
                        facts, receipt_failure = wire.note(receipt)
                        if receipt_failure is not None:
                            raise RulesManagementError(receipt_failure)
                    rules_management["managementReceipts"] = [
                        dict(entry) for entry in management_session.receipts
                    ]
                except Exception as error:  # noqa: BLE001 - retain ownership on uncertainty
                    failure = getattr(error, "reason", None) or "rules-management-recovery:" + type(error).__name__
                    rules_management = management_session.snapshot()
                    rules_management["recovery"] = {
                        "restored": False,
                        "cleanupComplete": False,
                        "held": [
                            state["name"]
                            for state in management_session.owned.values()
                            if isinstance(state.get("name"), str)
                        ],
                    }
                    if abort is None and failure not in failures:
                        failures.append(failure)
                    abort = abort or "rules-management-recovery"
        finally:
            if journal_owned:
                journal.close()
    finished = budget.stamp()
    wall_finished = _read_wall_clock(wall_clock)
    if worker_state["unreaped"]:
        worker_reaped = False

    if journal.failures:
        failures.extend(journal.failures)
        abort = abort or "journal-failure"
    # A bundle is publishable material, so it carries principal labels, not
    # the account identifiers the recovery readbacks returned. Every uid the
    # collector saw is replaced here, in both rows and recovery steps; the
    # raw value was needed only for the version-bound delete precondition.
    redacted_principals = _redact_principals(rows, cleanup)
    complete = (
        abort is None
        and len(rows) == len(operations)
        and not failures
        and cleanup["cleanupComplete"] is True
    )
    transport = {
        **wire.record(),
        "rulesetReleases": releases,
        "principalActions": actions,
        "workerReaped": worker_reaped,
        "rulesManagement": rules_management,
        "clock": {
            "started": budget.started,
            "observationFinished": observation_finished,
            "finished": finished,
        },
        "wallClock": {"startedAt": wall_started, "finishedAt": wall_finished},
    }
    # Where the requests went is a fact the transport recorded, not a label the
    # launcher chose. It is true only for a bound production run whose every
    # sequenced receipt named an allowlisted production host.
    production_executed = (
        bindings is not None
        and role == ROLE_PRODUCTION
        and environment == ENVIRONMENT_PRODUCTION
        and wire.reached_only(ENVIRONMENT_PRODUCTION)
    )
    recorded_acquisition = None
    if bindings is not None:
        recorded_acquisition = {
            **bindings,
            # The names the first comparator module asks for, so it can name
            # what a bound bundle carries; it still refuses to classify.
            "endpoint": transport["endpoints"],
            "observerDigest": observer["observerDigest"],
            "rulesetReleases": releases,
            "wireCounts": {
                "receipts": transport["receipts"],
                "sequencedReceipts": transport["sequencedReceipts"],
            },
        }
    return {
        "contract": COLLECTOR_CONTRACT,
        "status": "PREPARATION_ONLY",
        "provenance": {
            "role": role,
            "runId": run_id,
            "collectorContract": COLLECTOR_CONTRACT,
            "caseContract": plan["contract"],
            "case": {
                key: plan[key] for key in ("project", "database", "nonce", "tenant")
            },
        },
        "planDigest": plan["planDigest"],
        "rows": rows,
        "attemptedResources": attempted,
        "attemptedAccounts": attempted_accounts,
        "redactedPrincipals": redacted_principals,
        "cleanup": cleanup,
        "budget": {
            "observationCeiling": len(operations),
            "observationSpent": budget.spent,
            "rulesetCeiling": transitions,
            "rulesetSpent": budget.ruleset_spent,
            "principalActionCeiling": action_count,
            "principalActionSpent": budget.action_spent,
            "recoveryCeiling": 3 * (len(plan["ownedResources"]) + len(accounts)),
            "recoverySpent": budget.recovery_spent,
            "deadlineSeconds": float(deadline_seconds),
            "recoveryDeadlineSeconds": float(recovery_deadline_seconds),
        },
        "observer": observer,
        "transport": transport,
        "acquisition": recorded_acquisition,
        "journal": str(journal.path) if journal.path is not None else None,
        "infrastructureFailures": failures,
        "abort": abort,
        "recordingComplete": complete,
        "productionExecuted": production_executed,
        "productionReady": False,
    }


def _apply_principal_action(
    execute: Callable[[dict[str, Any]], Any],
    budget: _Budget,
    wire: _Wire,
    journal: _Journal,
    operation: Mapping[str, Any],
    bindings: Mapping[str, Any],
    *,
    worker_state: dict[str, bool] | None = None,
) -> tuple[dict[str, Any] | None, str | None]:
    """Apply one administrator action to an owned account between two rows.

    The transport performs the action (refresh tokens revoked, account
    disabled, account deleted), then reads the account back with an
    administrator lookup and reports presence, the disabled flag and the uid
    fingerprint, which must equal the launcher's binding for that principal.
    The token facts it reports are seconds, never the token.
    """
    ref = operation["principalAction"]["ref"]
    action = operation["principalAction"]["action"]
    journal.record(
        "principal-action-request",
        {"principal": ref, "action": action, "beforeIndex": operation["index"]},
    )
    if journal.failures:
        return None, "journal-failure"
    try:
        at = budget.take_action()
    except BudgetExhausted as error:
        return None, str(error)
    request = {
        "kind": "principal-action",
        "phase": "principal",
        "principalRef": ref,
        "action": action,
        "credentialRef": "administrator",
        "credentialClass": "administrator",
    }
    try:
        raw = execute(dict(request))
    except Exception as error:  # noqa: BLE001 - type name only, never a message
        _note_worker_failure(worker_state, error)
        return None, f"transport:{type(error).__name__}"
    accepted, failure = _accept(raw, PRINCIPAL_ACTION_RECEIPT_KEYS)
    if failure is not None:
        return None, failure
    if accepted.get("complete") is not True:
        return None, "incomplete-principal-action"
    facts, failure = wire.note(accepted)
    if failure is not None:
        return None, failure
    if accepted.get("action") != action:
        return None, "principal-action-mismatch"
    auth_time = accepted.get("authTime")
    valid_since = accepted.get("validSince")
    if type(auth_time) is not int or auth_time < 0:
        return None, "principal-action-unproven:authTime"
    if action == POST_SIGN_IN_REVOKE:
        if type(valid_since) is not int or valid_since <= auth_time:
            return None, "principal-action-unproven:validSince"
    elif valid_since is not None:
        return None, "principal-action-unproven:validSince"
    present = accepted.get("present")
    disabled = accepted.get("disabled")
    if action == POST_SIGN_IN_DELETE:
        if present is not False or disabled is not None:
            return None, "principal-action-unproven:readback"
    elif present is not True or disabled is not (action == POST_SIGN_IN_DISABLE):
        return None, "principal-action-unproven:readback"
    bound = bindings["principals"].get(ref)
    if not isinstance(bound, Mapping) or accepted.get("uidFingerprint") != bound.get(
        "uidFingerprint"
    ):
        return None, "principal-action-unproven:principal"
    record = {
        "ref": ref,
        "action": action,
        "beforeIndex": operation["index"],
        "at": at,
        "authTime": auth_time,
        "validSince": valid_since,
        "readback": {
            "present": present,
            "disabled": disabled,
            "uidFingerprint": accepted["uidFingerprint"],
        },
        "endpoint": facts["endpoint"],
        "wireSequence": facts["wireSequence"],
    }
    journal.record(
        "principal-action",
        {"principal": ref, "action": action, "present": present},
    )
    if journal.failures:
        return None, "journal-failure"
    return record, None


def _read_wall_clock(wall_clock: Callable[[], float]) -> float | None:
    try:
        value = wall_clock()
    except Exception:  # noqa: BLE001 -- a broken wall clock is recorded as absent
        return None
    return float(value) if _finite(value) else None


def _note_worker_failure(
    worker_state: dict[str, bool] | None, error: BaseException
) -> None:
    if worker_state is not None and getattr(error, "worker_reaped", None) is not True:
        worker_state["unreaped"] = True


def _release_ruleset(
    plan: Mapping[str, Any],
    execute: Callable[[dict[str, Any]], Any],
    budget: _Budget,
    wire: _Wire,
    journal: _Journal,
    operation: Mapping[str, Any],
    *,
    worker_state: dict[str, bool] | None = None,
) -> tuple[dict[str, Any] | None, str | None]:
    """Release one Ruleset through the transport and check its readback.

    The source digest is computed here from the plan. The transport reports the
    release it made and the digest it read back; a readback that differs from
    the plan's source aborts the run before any row runs under it.
    """
    label = operation["ruleset"]
    source_digest = digest(plan["rulesets"][label]["source"])
    journal.record(
        "ruleset-request",
        {"ruleset": label, "beforeIndex": operation["index"], "source": source_digest},
    )
    if journal.failures:
        return None, "journal-failure"
    try:
        budget.take_ruleset()
    except BudgetExhausted as error:
        return None, str(error)
    request = {
        "kind": "ruleset-release",
        "phase": "ruleset",
        "ruleset": label,
        "sourceDigest": source_digest,
        "credentialRef": "administrator",
        "credentialClass": "administrator",
    }
    try:
        raw = execute(dict(request))
    except Exception as error:  # noqa: BLE001 - type name only, never a message
        _note_worker_failure(worker_state, error)
        return None, f"transport:{type(error).__name__}"
    accepted, failure = _accept(raw, RULESET_RECEIPT_KEYS)
    if failure is not None:
        return None, failure
    if accepted.get("complete") is not True:
        return None, "incomplete-ruleset-receipt"
    facts, failure = wire.note(accepted)
    if failure is not None:
        return None, failure
    name = accepted.get("releaseName")
    if not isinstance(name, str) or _RELEASE_NAME.fullmatch(name) is None:
        return None, "ruleset-release-unnamed"
    if accepted.get("readbackKind") not in READBACK_KINDS:
        return None, "ruleset-readback-unknown"
    if accepted.get("readbackDigest") != source_digest:
        return None, "ruleset-readback-mismatch"
    active_from = budget.stamp()
    if active_from is None:
        return None, "invalid-clock"
    release = {
        "label": label,
        "sourceDigest": source_digest,
        "releaseName": name,
        "readback": {"kind": accepted["readbackKind"], "digest": source_digest},
        "endpoint": facts["endpoint"],
        "wireSequence": facts["wireSequence"],
        "beforeIndex": operation["index"],
        "activeFrom": active_from,
    }
    journal.record(
        "ruleset-release",
        {"ruleset": label, "releaseName": name, "readback": source_digest},
    )
    if journal.failures:
        return None, "journal-failure"
    return release, None


def _redact_principals(
    rows: list[dict[str, Any]], cleanup: dict[str, Any]
) -> list[str]:
    """Replace every account identifier the recovery readbacks returned.

    The map is built from the account readback steps, which are the only place
    the collector learns a uid, and applied to every string in the rows and
    the recovery steps. The replacement is the principal reference, which is
    what the compiled matrix speaks in anyway.

    Before any string is replaced, every row records which of its field
    values were equal to a read-back uid (``principalFieldBindings``, refs
    and readback indexes only). After the replacement a label in a field is
    evidence of the principal only together with that binding; a literal
    that merely looks like a label has none.
    """
    capture_principal_fields(rows, cleanup)
    labels: dict[str, str] = {}
    for step in cleanup.get("accountSteps", []):
        observed = step.get("observed") or {}
        uid = observed.get("uid")
        ref = step.get("accountRef")
        if isinstance(uid, str) and uid and isinstance(ref, str):
            labels[uid] = f"principal:{ref}"
    if not labels:
        return []

    def redact(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: redact(nested) for key, nested in value.items()}
        if isinstance(value, list):
            return [redact(nested) for nested in value]
        if isinstance(value, str):
            return labels.get(value, value)
        return value

    for index, row in enumerate(rows):
        bindings = row[BINDINGS_KEY]
        rows[index] = redact(row)
        # Logical references are metadata, not observed strings.
        rows[index][BINDINGS_KEY] = bindings
    for key in ("documentSteps", "accountSteps"):
        cleanup[key] = redact(cleanup[key])
    return sorted(set(labels.values()))


def _resource_for(plan: Mapping[str, Any], document: str) -> str:
    suffix = f"/cases/{document}"
    for resource in plan["ownedResources"]:
        if resource.endswith(suffix):
            return resource
    raise ValueError("unknown owned document")


def _row(
    request: Mapping[str, Any],
    receipt: Mapping[str, Any] | None,
    failure: str | None,
    at: float | None,
    facts: Mapping[str, Any],
) -> dict[str, Any]:
    row = {
        "caseId": request["caseId"],
        "index": request["index"],
        "ruleset": request["ruleset"],
        "method": request["method"],
        "resources": list(request["resources"]),
        "credentialRef": request["credentialRef"],
        "credentialClass": request["credentialClass"],
        "credentialFingerprint": request["credentialFingerprint"],
        "at": at,
        "endpoint": facts.get("endpoint"),
        "wireSequence": facts.get("wireSequence"),
        "observed": None,
        "failure": failure,
    }
    if receipt is not None:
        row["observed"] = {
            "status": receipt.get("status"),
            "code": receipt.get("code"),
            "documentPresent": receipt.get("documentPresent"),
            "fields": receipt.get("fields"),
        }
    return row


class RulesRecoveryContext:
    """Opaque one-run recovery resources shared across setup and collection."""

    def __init__(self, *, budget: Any, wire: Any, journal: Any, attempted: list[str], worker_state: dict[str, bool] | None = None):
        self.budget = budget
        self.wire = wire
        self.journal = journal
        self.attempted = attempted
        self.worker_state = worker_state or {"unreaped": False}


def make_recovery_context(*, budget: Any, wire: Any, journal: Any, attempted: list[str], worker_state: dict[str, bool] | None = None) -> RulesRecoveryContext:
    """Bind recovery to existing run counters; this never creates a new budget."""
    return RulesRecoveryContext(
        budget=budget,
        wire=wire,
        journal=journal,
        attempted=attempted,
        worker_state=worker_state,
    )


def recover_owned(
    plan: Mapping[str, Any],
    execute: Callable[[dict[str, Any]], Any],
    budget: _Budget | None = None,
    wire: _Wire | None = None,
    attempted: list[str] | None = None,
    journal: _Journal | None = None,
    *,
    context: RulesRecoveryContext | None = None,
    ownership: Mapping[str, Mapping[str, Any]] | None = None,
    recovery_dispatch: Callable[[dict[str, Any]], Any] | None = None,
    worker_state: dict[str, bool] | None = None,
) -> dict[str, Any]:
    """Recover response-acknowledged subjects through the existing Gate cursor.

    ``ownership`` is deliberately response-derived state.  When supplied, a
    subject is eligible only in the ``acknowledged`` state; unconfirmed and
    not-attempted subjects are returned as held without manufacturing a read
    or absence receipt.  ``recovery_dispatch`` is an orchestrator-owned
    adapter for the same bounded Gate session, not a second cleanup pass.
    """
    if context is not None:
        budget, wire, journal, attempted, worker_state = (
            context.budget,
            context.wire,
            context.journal,
            context.attempted,
            context.worker_state,
        )
    if budget is None or wire is None or journal is None or attempted is None:
        raise ValueError("shared recovery context required")
    if ownership is None:
        subjects = list(plan["ownedResources"]) + [entry["ref"] for entry in plan["ownedAccounts"]]
        return {
            "documentSteps": [],
            "accountSteps": [],
            "outstandingResources": list(plan["ownedResources"]),
            "outstandingAccounts": [entry["ref"] for entry in plan["ownedAccounts"]],
            "unrecoveredAttempted": [subject for subject in attempted if subject in subjects],
            "recovered": [],
            "held": sorted(subjects),
            "unconfirmed": [],
            "notAttempted": [],
            "cleanupComplete": False,
            "blockedReason": "ownership-proof-required",
        }
    dispatch = recovery_dispatch or execute
    selected_plan = plan
    held: list[str] = []
    unconfirmed: list[str] = []
    not_attempted: list[str] = []
    terminal: list[str] = []
    no_effect: list[str] = []
    if ownership is not None:
        acknowledged_resources: set[str] = set()
        acknowledged_accounts: set[str] = set()
        for resource in plan["ownedResources"]:
            state = ownership.get(resource)
            if state is None:
                state = ownership.get("document/" + resource.rsplit("/cases/", 1)[-1])
            phase = state.get("phase") if isinstance(state, Mapping) else None
            status = state.get("status") if isinstance(state, Mapping) else None
            if phase == "acknowledged" or status == "owned":
                acknowledged_resources.add(resource)
            elif status == "recovered":
                terminal.append(resource)
            elif status == "attempted-no-effect":
                no_effect.append(resource)
            elif status == "not-attempted":
                not_attempted.append(resource)
            elif phase == "creation-unconfirmed":
                unconfirmed.append(resource)
            elif phase in {"held", "patch-uncertain"}:
                held.append(resource)
            elif phase == "not-attempted" and isinstance(state, Mapping) and state.get("gateDisposition") == "never-attempted":
                not_attempted.append(resource)
            else:
                held.append(resource)
        for entry in plan["ownedAccounts"]:
            ref = entry["ref"]
            state = ownership.get(ref)
            if state is None:
                state = ownership.get("account/" + ref)
            phase = state.get("phase") if isinstance(state, Mapping) else None
            status = state.get("status") if isinstance(state, Mapping) else None
            if phase == "acknowledged" or status == "owned":
                acknowledged_accounts.add(ref)
            elif status == "recovered":
                terminal.append(ref)
            elif status == "attempted-no-effect":
                no_effect.append(ref)
            elif status == "not-attempted":
                not_attempted.append(ref)
            elif phase == "creation-unconfirmed":
                unconfirmed.append(ref)
            elif phase in {"held", "patch-uncertain"}:
                held.append(ref)
            elif phase == "not-attempted" and isinstance(state, Mapping) and state.get("gateDisposition") == "never-attempted":
                not_attempted.append(ref)
            else:
                held.append(ref)
        selected_plan = dict(plan)
        selected_plan["ownedResources"] = [
            resource for resource in plan["ownedResources"] if resource in acknowledged_resources
        ]
        selected_plan["ownedAccounts"] = [
            entry for entry in plan["ownedAccounts"] if entry["ref"] in acknowledged_accounts
        ]
    result = _recover(
        selected_plan,
        dispatch,
        budget,
        wire,
        attempted,
        journal,
        worker_state=worker_state,
        ownership=ownership,
    )
    result["recovered"] = terminal + [
        subject
        for subject in selected_plan["ownedResources"] + [entry["ref"] for entry in selected_plan["ownedAccounts"]]
        if subject not in result["outstandingResources"] and subject not in result["outstandingAccounts"]
    ]
    result["held"] = sorted(set(held + result["outstandingResources"] + result["outstandingAccounts"]))
    result["unconfirmed"] = sorted(set(unconfirmed))
    result["notAttempted"] = sorted(set(not_attempted))
    result["attemptedNoEffect"] = sorted(set(no_effect))
    result["cleanupComplete"] = not result["held"] and not result["unconfirmed"]
    return result


def _recover(
    plan: Mapping[str, Any],
    execute: Callable[[dict[str, Any]], Any],
    budget: _Budget,
    wire: _Wire,
    attempted: list[str],
    journal: _Journal,
    *,
    worker_state: dict[str, bool] | None = None,
    ownership: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Version-bound cleanup of every owned document and account.

    Deletion is only authorized by a readback that proves the resource exists
    with a concrete version, or, for an account, with a concrete uid. An absent
    resource is already recovered. An unreadable resource stays an open
    responsibility and is never force deleted.
    """
    document_steps: list[dict[str, Any]] = []
    outstanding: list[str] = []
    for resource in plan["ownedResources"]:
        readback = _cleanup_step(
            execute, budget, wire, journal, "readback", resource=resource,
            worker_state=worker_state,
        )
        document_steps.append(readback)
        observed = readback.get("observed") or {}
        if readback["failure"] is not None:
            outstanding.append(resource)
            continue
        if observed.get("documentPresent") is False:
            continue
        expected = ownership.get(resource) if ownership is not None else None
        if expected is not None:
            if not isinstance(expected.get("version"), str) or not expected["version"]:
                outstanding.append(resource)
                continue
            if observed.get("version") != expected["version"]:
                outstanding.append(resource)
                continue
            expected_fields = expected.get("fieldsDigest")
            if not isinstance(expected_fields, str) or not expected_fields:
                outstanding.append(resource)
                continue
            if observed.get("fieldsDigest") != expected_fields:
                outstanding.append(resource)
                continue
        version = observed.get("version")
        if not isinstance(version, str) or not version:
            outstanding.append(resource)
            continue
        delete = _cleanup_step(
            execute,
            budget,
            wire,
            journal,
            "delete",
            resource=resource,
            version=version,
            worker_state=worker_state,
        )
        document_steps.append(delete)
        absence = _cleanup_step(
            execute,
            budget,
            wire,
            journal,
            "absence",
            resource=resource,
            worker_state=worker_state,
        )
        document_steps.append(absence)
        absent = (absence.get("observed") or {}).get("documentPresent") is False
        if delete["failure"] is not None or not absent:
            outstanding.append(resource)

    account_steps: list[dict[str, Any]] = []
    outstanding_accounts: list[str] = []
    for entry in plan["ownedAccounts"]:
        ref = entry["ref"]
        readback = _cleanup_step(
            execute,
            budget,
            wire,
            journal,
            "account-readback",
            account=ref,
            worker_state=worker_state,
        )
        account_steps.append(readback)
        observed = readback.get("observed") or {}
        if readback["failure"] is not None:
            outstanding_accounts.append(ref)
            continue
        if observed.get("accountPresent") is False:
            continue
        expected = ownership.get(ref) if ownership is not None else None
        if expected is not None:
            if not isinstance(expected.get("uid"), str) or not expected["uid"]:
                outstanding_accounts.append(ref)
                continue
            if observed.get("uid") != expected["uid"]:
                outstanding_accounts.append(ref)
                continue
            if "tenantId" not in expected or observed.get("tenantId") != expected["tenantId"]:
                outstanding_accounts.append(ref)
                continue
        uid = observed.get("uid")
        if not isinstance(uid, str) or not uid:
            outstanding_accounts.append(ref)
            continue
        delete = _cleanup_step(
            execute,
            budget,
            wire,
            journal,
            "account-delete",
            account=ref,
            uid=uid,
            worker_state=worker_state,
        )
        account_steps.append(delete)
        absence = _cleanup_step(
            execute,
            budget,
            wire,
            journal,
            "account-absence",
            account=ref,
            worker_state=worker_state,
        )
        account_steps.append(absence)
        absent = (absence.get("observed") or {}).get("accountPresent") is False
        if delete["failure"] is not None or not absent:
            outstanding_accounts.append(ref)

    unrecovered = [resource for resource in attempted if resource in outstanding]
    return {
        "documentSteps": document_steps,
        "accountSteps": account_steps,
        "outstandingResources": outstanding,
        "outstandingAccounts": outstanding_accounts,
        "unrecoveredAttempted": unrecovered,
        "cleanupComplete": not outstanding and not outstanding_accounts,
    }


def _blocked_cleanup(
    plan: Mapping[str, Any], attempted: list[str], *, worker_reaped: bool
) -> dict[str, Any]:
    """Keep owned resources open when a worker's process group is uncertain."""
    resources = list(plan["ownedResources"])
    accounts = [entry["ref"] for entry in plan["ownedAccounts"]]
    return {
        "documentSteps": [],
        "accountSteps": [],
        "outstandingResources": resources,
        "outstandingAccounts": accounts,
        "unrecoveredAttempted": [resource for resource in attempted if resource in resources],
        "cleanupComplete": False,
        "blockedReason": "worker-reap-unconfirmed",
        "workerReaped": worker_reaped,
    }


def _recovery_evidence_error(kind: str, receipt: Mapping[str, Any]) -> str | None:
    """Validate semantic evidence, not just the presence of complete=True.

    Transport-normalized receipts may omit wire metadata. Any metadata they do
    supply must agree with typed presence. This does not grant production
    authority; the comparator remains locked.
    """
    present_key = "accountPresent" if kind.startswith("account-") else "documentPresent"
    present = receipt.get(present_key)
    if type(present) is not bool:
        return "untyped-recovery-presence"
    other_key = "documentPresent" if kind.startswith("account-") else "accountPresent"
    if receipt.get(other_key) is not None:
        return "unrelated-recovery-presence"
    deleting = kind in {"delete", "account-delete"}
    if deleting and present is not False:
        return "unconfirmed-recovery-delete"
    identity_key = "uid" if kind.startswith("account-") else "version"
    identity = receipt.get(identity_key)
    if present and (not isinstance(identity, str) or not identity):
        return "missing-recovery-identity"
    if not present and identity is not None:
        return "contradictory-recovery-identity"
    permitted = {"OK"}
    codes = {"OK", 0}
    http_codes = {200}
    if not present and not deleting:
        permitted |= (
            {"NOT_FOUND", "USER_NOT_FOUND"}
            if kind.startswith("account-")
            else {"NOT_FOUND"}
        )
        codes |= permitted | {5}
        http_codes.add(404)
    for key in ("status", "code"):
        if key in receipt:
            value = receipt[key]
            allowed = permitted if key == "status" else codes
            if type(value) not in (str, int) or value not in allowed:
                return "unsuccessful-recovery-" + key
    if "httpStatus" in receipt:
        value = receipt["httpStatus"]
        if type(value) is not int or value not in http_codes:
            return "unsuccessful-recovery-http-status"
    return None


def _cleanup_step(
    execute: Callable[[dict[str, Any]], Any],
    budget: _Budget,
    wire: _Wire,
    journal: _Journal,
    kind: str,
    *,
    resource: str | None = None,
    account: str | None = None,
    version: str | None = None,
    uid: str | None = None,
    worker_state: dict[str, bool] | None = None,
) -> dict[str, Any]:
    subject = resource if resource is not None else account
    request: dict[str, Any] = {
        "kind": kind,
        "phase": "recovery",
        "resource": resource,
        "accountRef": account,
        "credentialRef": "administrator",
        "credentialClass": "administrator",
        "precondition": None,
    }
    if version is not None:
        request["precondition"] = {"updateTime": version}
    elif uid is not None:
        request["precondition"] = {"uid": uid}

    at: float | int | None = None
    facts: dict[str, Any] = {"endpoint": None, "wireSequence": None}

    def outcome(failure: str | None, observed: dict[str, Any] | None) -> dict[str, Any]:
        journal.record(
            "recovery", {"step": kind, "subject": subject, "failure": failure}
        )
        return {
            "kind": kind,
            "resource": resource,
            "accountRef": account,
            "at": at,
            "endpoint": facts["endpoint"],
            "wireSequence": facts["wireSequence"],
            "observed": observed,
            "failure": failure,
        }

    if worker_state is not None and worker_state["unreaped"]:
        return outcome("worker-reap-unconfirmed", None)

    try:
        at = budget.take_recovery()
    except BudgetExhausted as error:
        return outcome(str(error), None)
    except Exception as error:  # noqa: BLE001 -- no request without a valid budget
        return outcome("recovery-budget:" + type(error).__name__, None)
    try:
        raw = execute(dict(request))
    except Exception as error:  # noqa: BLE001 - type name only, never a message
        _note_worker_failure(worker_state, error)
        return outcome(f"transport:{type(error).__name__}", None)
    try:
        accepted, failure = _accept(raw, RECOVERY_RECEIPT_KEYS)
        if failure is not None:
            return outcome(failure, None)
        facts, failure = wire.note(accepted)
        if failure is not None:
            return outcome(failure, None)
        if accepted.get("complete") is not True:
            return outcome("incomplete", None)
        failure = _recovery_evidence_error(kind, accepted)
        if failure is not None:
            return outcome(failure, None)
    except Exception as error:  # noqa: BLE001 -- keep other subjects reachable
        return outcome("recovery-processing:" + type(error).__name__, None)
    return outcome(
        None,
        {
            "documentPresent": accepted.get("documentPresent"),
            "accountPresent": accepted.get("accountPresent"),
            "version": accepted.get("version"),
            "uid": accepted.get("uid"),
            "tenantId": accepted.get("tenantId"),
            "fieldsDigest": digest(accepted.get("fields")) if "fields" in accepted else None,
            "status": accepted.get("status"),
        },
    )
