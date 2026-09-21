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
    journal = _Journal(journal_path)
    journal.record("run", {"runId": run_id, "role": role, "plan": plan["planDigest"]})
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
    attempted: list[str] = []
    # Every account exists before the first row, so all of them are owned.
    attempted_accounts = [entry["ref"] for entry in accounts]
    journal.record("accounts", {"refs": attempted_accounts})
    failures: list[str] = []
    abort: str | None = None
    worker_reaped: bool | None = None
    worker_state = {"unreaped": False}
    active_ruleset: str | None = None

    try:
        for operation in operations:
            if journal.failures:
                abort = "journal-failure"
                break
            if bindings is not None and operation["ruleset"] != active_ruleset:
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
        abort = "collector:" + type(error).__name__
        failures.append(abort)
    finally:
        observation_finished = budget.stamp()
        try:
            if worker_state["unreaped"]:
                cleanup = _blocked_cleanup(plan, attempted, worker_reaped=False)
            else:
                cleanup = _recover(
                    plan, execute, budget, wire, attempted, journal,
                    worker_state=worker_state,
                )
                if worker_state["unreaped"]:
                    cleanup = _blocked_cleanup(plan, attempted, worker_reaped=False)
        finally:
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


def _recover(
    plan: Mapping[str, Any],
    execute: Callable[[dict[str, Any]], Any],
    budget: _Budget,
    wire: _Wire,
    attempted: list[str],
    journal: _Journal,
    *,
    worker_state: dict[str, bool] | None = None,
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
            "status": accepted.get("status"),
        },
    )
