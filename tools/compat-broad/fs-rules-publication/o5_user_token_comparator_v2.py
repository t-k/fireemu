"""Acquisition comparator for the FS-RULES user-token observation matrix.

This is the second comparator module of the lane. The first,
``o5_user_token_comparator.py``, has no positive classification and stays that
way; it records the reviewed decision that a recording is not an acquisition.
This module is the separately reviewed path that can reach ``MATCH``, and it can
do so only when every binding the first module names is present on both sides
and verified here against something the bundle itself cannot fabricate:

* the collector identity, as digests of the lane sources recomputed from disk;
* the endpoint every request reached, as recorded by the transport per receipt,
  with a production host allowlist on one side and loopback on the other;
* the Ruleset releases, with their source digest, readback and activation order
  relative to the rows that depend on them;
* the principal provenance per credential reference: the row fingerprint is
  recomputed from the nonce and the reference; the per-account uid fingerprint
  is checked by shape, against the plan's provider, tenant and claims, and for
  difference between the two sides, never a token or a uid;
* the campaign manifest digest the run was admitted under, recomputed from the
  checked-in campaign module with the placeholder tenant, because the tenant
  identifier is assigned only once a run has started;
* version-bound cleanup with typed final absence for every document and account;
* monotonic time and wire-sequence consistency between rows, releases, recovery
  steps and the enforced budget;
* the nonce reservation and owner permission on the production side, and the
  artifact binding on the local side;
* the environment label, refused when it contradicts the role, the endpoints or
  the artifact binding.

Every failed binding is a named error. A bundle that fails an identity or
authority binding is ``REFUSED``; a bundle whose evidence is incomplete or
internally contradictory is ``INDETERMINATE``. Only two admitted bundles are
compared row by row, and a row that disagrees is ``SEMANTIC_MISMATCH``.

Row comparison is typed and identity-preserving (owner review d7f7ce184,
findings 1 and 3). An observed record is admitted only with a JSON-boolean
``documentPresent``, a non-empty string ``status`` and finite JSON throughout;
values are compared as encoded JSON, so ``1`` and ``true`` differ. A field the
plan resolves to a principal is mapped to the logical principal reference
through the run's own binding: the ``principal:<ref>`` label the collector's
account readback recorded, together with the row's pre-redaction
``principalFieldBindings`` entry that proves the label replaced the uid the
readback returned (external review RULES-SEMANTIC-REPAIR-006). A value with
no such binding, a label-shaped literal included, is not a principal and
leaves the row ``INDETERMINATE``, never equal.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from itertools import pairwise
from typing import Any

from o5_user_token_campaign import admitted_manifest_digest, source_digests
from o5_user_token_case import (
    ACCOUNT_PRINCIPALS,
    CAMPAIGN,
    CASE_CONTRACT,
    POST_SIGN_IN_DELETE,
    POST_SIGN_IN_DISABLE,
    POST_SIGN_IN_REVOKE,
    compile_case,
    digest,
    principal_actions,
    validate_case,
)
from o5_user_token_collector import (
    COLLECTOR_CONTRACT,
    ENVIRONMENT_LOCAL,
    ENVIRONMENT_PRODUCTION,
    LOOPBACK_HOSTS,
    PRODUCTION_HOSTS,
    READBACK_KINDS,
    READBACK_RELEASE_GET,
    ROLE_LOCAL_SHADOW,
    ROLE_PRODUCTION,
    credential_fingerprint,
    endpoint_host,
    ruleset_transitions,
)
from o5_user_token_semantics import (
    BINDINGS_KEY,
    binding_problem,
    is_typed_json,
    same_typed_json,
)
from o5_user_token_shadow import unredacted_identifiers

COMPARATOR_CONTRACT = "fs-rules-user-token-comparator-v5"

MATCH = "MATCH"
SEMANTIC_MISMATCH = "SEMANTIC_MISMATCH"
INDETERMINATE = "INDETERMINATE"
REFUSED = "REFUSED"
CLASSIFICATIONS = (MATCH, SEMANTIC_MISMATCH, INDETERMINATE, REFUSED)

SIDE_PRODUCTION = "production"
SIDE_LOCAL = "local"
_ROLE_FOR_SIDE = {SIDE_PRODUCTION: ROLE_PRODUCTION, SIDE_LOCAL: ROLE_LOCAL_SHADOW}
# Per-condition summary: the weakest row decides the condition.
_ROW_RANK = {MATCH: 0, SEMANTIC_MISMATCH: 1, INDETERMINATE: 2}
_ENVIRONMENT_FOR_SIDE = {
    SIDE_PRODUCTION: ENVIRONMENT_PRODUCTION,
    SIDE_LOCAL: ENVIRONMENT_LOCAL,
}
# The provider vocabulary a principal binding uses. It is the campaign's own,
# chosen so that a published record never carries the substring "password":
# the account kind is what the plan compiled, not a credential.
_PROVIDER_FOR_KIND = {"email-password": "email", "anonymous": "anonymous"}

# Errors of these names refuse the comparison outright: the bundle is not an
# acquisition of this campaign by this collector on the side it was passed as.
# Everything else leaves the comparison indeterminate.
REFUSAL_ERRORS = frozenset(
    {
        "not-a-bundle",
        "collector-contract-drift",
        "bundle-claims-authority",
        "local-claims-production",
        "local-claims-reservation",
        "local-mislabelled-as-production",
        "local-reached-nonloopback",
        "endpoint-outside-allowlist",
        "role-mismatch",
        "case-identity-drift",
        "campaign-identity-drift",
        "case-digest-drift",
        "observer-digest-drift",
        "manifest-mismatch",
        "self-comparison",
        "principal-shared-across-sides",
        "plan-invalid",
    }
)

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX16 = re.compile(r"^[0-9a-f]{16}$")
# A production release is named by the Rules API resource it created or read
# back; anything else in that slot is not a release name.
_PRODUCTION_RELEASE_NAME = re.compile(
    r"^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/(releases|rulesets)/[A-Za-z0-9_.-]{1,128}$"
)
# The v1-shaped duplicates the collector writes under acquisition, each of
# which must equal the canonical field it mirrors.
_ACQUISITION_MIRRORS = ("endpoint", "observerDigest", "rulesetReleases", "wireCounts")
_RULES_MANAGEMENT_IDS = (
    "baseline-release-get", "baseline-ruleset-get", "baseline-executable-get",
    "create-a", "create-a-get", "patch-a", "patch-a-get", "patch-a-executable",
    "create-b", "create-b-get", "patch-b", "patch-b-get", "patch-b-executable",
    "restore-patch", "restore-get", "restore-executable", "restore-get-executable",
    "delete-a-get", "delete-a", "delete-a-absence", "delete-b-get", "delete-b", "delete-b-absence",
)
# Wall and monotonic clocks drift; more than this between their spans is a
# contradiction, not drift.
_CLOCK_TOLERANCE_SECONDS = 60.0


def _is_number(value: Any) -> bool:
    return type(value) in (int, float) and math.isfinite(value)


def _hex(value: Any, pattern: re.Pattern[str]) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


class _Side:
    """One bundle under admission, with the plan it must bind."""

    def __init__(self, bundle: Any, side: str) -> None:
        self.bundle = bundle
        self.side = side
        self.role = _ROLE_FOR_SIDE[side]
        self.errors: list[str] = []
        self.plan: dict[str, Any] | None = None
        self.acquisition: dict[str, Any] | None = None

    def fail(self, name: str) -> None:
        entry = f"{self.side}:{name}"
        if entry not in self.errors:
            self.errors.append(entry)

    @property
    def refused(self) -> bool:
        return any(error.split(":", 2)[1] in REFUSAL_ERRORS for error in self.errors)


def _admit_side(side: _Side, production_plan: dict[str, Any], *, production_cleanup_gate: Any = None) -> None:
    bundle = side.bundle
    if not isinstance(bundle, Mapping):
        side.fail("not-a-bundle")
        return
    if bundle.get("contract") != COLLECTOR_CONTRACT:
        side.fail("collector-contract-drift")
    if (
        bundle.get("productionReady") is not False
        or bundle.get("acquisitionValidated") is True
        or bundle.get("status") != "PREPARATION_ONLY"
    ):
        side.fail("bundle-claims-authority")
    if side.side == SIDE_LOCAL and bundle.get("productionExecuted") is not False:
        side.fail("local-claims-production")
    if side.side == SIDE_PRODUCTION and bundle.get("productionExecuted") is not True:
        side.fail("production-not-executed")
    _admit_provenance(side, production_plan)
    if side.plan is None:
        return
    plan = side.plan
    if bundle.get("planDigest") != plan["planDigest"]:
        side.fail("case-digest-drift")
    _admit_acquisition(side)
    _admit_observer(side)
    rows = bundle.get("rows")
    if not isinstance(rows, list):
        side.fail("row-count")
        rows = None
    elif len(rows) != len(plan["observation"]):
        # Whatever rows are present are still scanned, so a visibly relabelled
        # bundle is refused for what it is and not left indeterminate because
        # it is also short a row.
        side.fail("row-count")
        _admit_rows(side, rows)
        rows = None
    else:
        _admit_rows(side, rows)
    leaked = unredacted_identifiers(bundle)
    if leaked:
        side.fail(f"unredacted-identifier:{len(leaked)}")
    if bundle.get("recordingComplete") is not True:
        side.fail("recording-incomplete")
    if bundle.get("abort") is not None:
        side.fail("recording-aborted")
    if bundle.get("infrastructureFailures") != []:
        side.fail("recording-incomplete:infrastructure")
    if bundle.get("attemptedAccounts") != [
        entry["ref"] for entry in plan["ownedAccounts"]
    ]:
        side.fail("cleanup-unknown:attempted-accounts")
    redacted = bundle.get("redactedPrincipals")
    if not isinstance(redacted, list) or any(
        not isinstance(label, str) or not label.startswith("principal:")
        for label in redacted
    ):
        side.fail("unredacted-identifier:labels")
    cleanup_steps = _admit_cleanup(
        side,
        production_cleanup_gate=production_cleanup_gate,
    )
    releases = _admit_releases(side, rows)
    actions = _admit_actions(side, rows)
    _admit_transport(side, rows, releases, actions, cleanup_steps)
    _admit_budget(side, rows, releases, actions, cleanup_steps)


def _admit_provenance(side: _Side, production_plan: dict[str, Any]) -> None:
    provenance = side.bundle.get("provenance")
    if not isinstance(provenance, Mapping):
        side.fail("missing-provenance")
        return
    if provenance.get("role") != side.role:
        side.fail("role-mismatch")
    if provenance.get("collectorContract") != COLLECTOR_CONTRACT:
        side.fail("collector-contract-drift")
    if provenance.get("caseContract") != CASE_CONTRACT:
        side.fail("case-contract-drift")
    run_id = provenance.get("runId")
    if not isinstance(run_id, str) or not run_id:
        side.fail("missing-run-identity")
    case = provenance.get("case")
    keys = ("project", "database", "nonce", "tenant")
    if not isinstance(case, Mapping) or any(
        not isinstance(case.get(key), str) for key in keys
    ):
        side.fail("missing-case-identity")
        return
    if side.side == SIDE_PRODUCTION:
        if all(case[key] == production_plan[key] for key in keys):
            side.plan = production_plan
            return
        # Refused, but the remaining bindings are still checked against the
        # identity the bundle declares, so a relabelled local run is named as
        # such and not only as an identity drift.
        side.fail("case-identity-drift")
    elif any(
        case[key] != production_plan[key] for key in ("project", "database", "nonce")
    ):
        # The local shadow runs the same campaign nonce against the same
        # project and database. Only the tenant identifier is assigned by the
        # local Auth emulator, so the local plan is recompiled from the
        # bundle's own identity.
        side.fail("campaign-identity-drift")
        return
    try:
        side.plan = compile_case(*(case[key] for key in keys))
    except (TypeError, ValueError):
        side.fail("case-identity-drift")


def _admit_acquisition(side: _Side) -> None:
    acquisition = side.bundle.get("acquisition")
    if not isinstance(acquisition, Mapping):
        side.fail("missing-acquisition-bindings")
        return
    side.acquisition = dict(acquisition)
    environment = acquisition.get("environment")
    kind = environment.get("kind") if isinstance(environment, Mapping) else None
    expected = _ENVIRONMENT_FOR_SIDE[side.side]
    if kind != expected:
        if side.side == SIDE_PRODUCTION and kind == ENVIRONMENT_LOCAL:
            side.fail("local-mislabelled-as-production")
        elif side.side == SIDE_LOCAL and kind == ENVIRONMENT_PRODUCTION:
            side.fail("local-claims-production")
        else:
            side.fail("missing-binding:environment")
    if not _hex(acquisition.get("campaignManifestDigest"), _HEX64):
        side.fail("missing-binding:campaignManifestDigest")
    artifact = acquisition.get("artifact")
    reservation = acquisition.get("nonceReservation")
    permission = acquisition.get("ownerPermission")
    if side.side == SIDE_PRODUCTION:
        if artifact is not None:
            side.fail("local-mislabelled-as-production")
        _admit_reservation(side, reservation)
        if (
            not isinstance(permission, Mapping)
            or not _hex(permission.get("permissionDigest"), _HEX64)
            or not isinstance(permission.get("kind"), str)
            or not permission["kind"]
        ):
            side.fail("missing-binding:ownerPermission")
        window = acquisition.get("window")
        if (
            not isinstance(window, Mapping)
            or not _is_number(window.get("startsAt"))
            or not _is_number(window.get("expiresAt"))
            or not window["startsAt"] < window["expiresAt"]
        ):
            side.fail("missing-binding:window")
    else:
        if (
            not isinstance(artifact, Mapping)
            or not _hex(artifact.get("artifactSha256"), _HEX64)
            or not _hex(artifact.get("sourceCommit"), _HEX40)
        ):
            side.fail("missing-binding:artifact")
        if reservation is not None:
            side.fail("local-claims-reservation")
    _admit_principals(side, acquisition.get("principals"))
    _admit_mirrors(side, acquisition)


def _admit_mirrors(side: _Side, acquisition: Mapping[str, Any]) -> None:
    """The v1-shaped duplicates must equal the canonical fields they mirror."""
    bundle = side.bundle
    transport = bundle.get("transport")
    observer = bundle.get("observer")
    if not isinstance(transport, Mapping) or not isinstance(observer, Mapping):
        return
    canonical = {
        "endpoint": transport.get("endpoints"),
        "observerDigest": observer.get("observerDigest"),
        "rulesetReleases": transport.get("rulesetReleases"),
        "wireCounts": {
            "receipts": transport.get("receipts"),
            "sequencedReceipts": transport.get("sequencedReceipts"),
        },
    }
    for name in _ACQUISITION_MIRRORS:
        if acquisition.get(name) != canonical[name]:
            side.fail(f"acquisition-mirror-drift:{name}")


def _admit_reservation(side: _Side, reservation: Any) -> None:
    if not isinstance(reservation, Mapping):
        side.fail("missing-binding:nonceReservation")
        return
    identifier = reservation.get("reservationId")
    if not isinstance(identifier, str) or not identifier:
        side.fail("missing-binding:nonceReservation")
    if reservation.get("campaignId") != CAMPAIGN:
        side.fail("nonce-reservation-mismatch:campaign")
    assert side.plan is not None
    if reservation.get("nonceDigest") != digest(side.plan["nonce"]):
        side.fail("nonce-reservation-mismatch:nonce")


def _admit_principals(side: _Side, principals: Any) -> None:
    assert side.plan is not None
    if not isinstance(principals, Mapping):
        side.fail("missing-binding:principals")
        return
    for entry in side.plan["ownedAccounts"]:
        ref = entry["ref"]
        principal = principals.get(ref)
        if not isinstance(principal, Mapping):
            side.fail(f"principal-mismatch:{ref}:missing")
            continue
        if not _hex(principal.get("uidFingerprint"), _HEX16):
            side.fail(f"principal-mismatch:{ref}:fingerprint")
        if principal.get("provider") != _PROVIDER_FOR_KIND.get(entry["kind"]):
            side.fail(f"principal-mismatch:{ref}:provider")
        if principal.get("tenant") != entry["tenant"]:
            side.fail(f"principal-mismatch:{ref}:tenant")
        if principal.get("claimsDigest") != digest(entry["claims"]):
            side.fail(f"principal-mismatch:{ref}:claims")
    unknown = sorted(set(principals) - set(ACCOUNT_PRINCIPALS))
    if unknown:
        side.fail("principal-mismatch:unknown-reference")


def _admit_observer(side: _Side) -> None:
    observer = side.bundle.get("observer")
    if not isinstance(observer, Mapping):
        side.fail("missing-binding:observerDigest")
        return
    expected = source_digests()
    declared = observer.get("sourceDigests")
    if not isinstance(declared, Mapping) or dict(declared) != expected:
        side.fail("observer-digest-drift")
        return
    if observer.get("observerDigest") != digest(expected):
        side.fail("observer-digest-drift")
    if observer.get("contract") != COLLECTOR_CONTRACT:
        side.fail("collector-contract-drift")


def _admit_rows(side: _Side, rows: list[Any]) -> None:
    assert side.plan is not None
    plan = side.plan
    nonce = plan["nonce"]
    previous_at: float | None = None
    # Endpoints are scanned on every row that is a mapping, before any
    # identity check can stop the loop: where a request went is a fact that
    # does not depend on the row being the right one.
    for index, row in enumerate(rows):
        if isinstance(row, Mapping):
            _admit_endpoint(side, row.get("endpoint"), f"row:{index}")
    for row, operation in zip(rows, plan["observation"], strict=False):
        if not isinstance(row, Mapping):
            side.fail("row-shape")
            return
        case_id = operation["caseId"]
        if row.get("caseId") != case_id or row.get("index") != operation["index"]:
            side.fail("row-identity")
            return
        if row.get("credentialRef") != operation["credential"]["ref"]:
            side.fail(f"principal-drift:{case_id}")
        if row.get("method") != operation["method"]:
            side.fail(f"method-drift:{case_id}")
        if row.get("credentialClass") != operation["credential"]["class"]:
            side.fail(f"credential-class-drift:{case_id}")
        if row.get("credentialFingerprint") != credential_fingerprint(
            nonce, operation["credential"]["ref"]
        ):
            side.fail(f"principal-fingerprint:{case_id}")
        if row.get("resources") != operation["resources"]:
            side.fail(f"target-drift:{case_id}")
        if row.get("ruleset") != operation["ruleset"]:
            side.fail(f"ruleset-mismatch:row:{case_id}")
        if row.get("failure") is not None:
            side.fail(f"row-failed:{case_id}")
        observed = row.get("observed")
        if not isinstance(observed, Mapping) or not isinstance(
            observed.get("status"), str
        ):
            side.fail(f"row-unobserved:{case_id}")
        else:
            _admit_observed(side, observed, case_id)
        problem = binding_problem(
            row, side.bundle.get("cleanup"), {e["ref"] for e in plan["ownedAccounts"]}
        )
        if problem is not None:
            side.fail(f"principal-binding:{case_id}:{problem}")
        at = row.get("at")
        if not _is_number(at):
            side.fail("time-contradiction:row-timestamp")
        elif previous_at is not None and at <= previous_at:
            side.fail("time-contradiction:rows-not-monotonic")
        else:
            previous_at = at


def _admit_observed(side: _Side, observed: Mapping[str, Any], case_id: str) -> None:
    """The comparable part of a row must have the schema the collector writes:
    a non-empty string status, a JSON-boolean presence flag, fields that are a
    mapping or absent, and finite JSON throughout. A number in a boolean slot
    is a malformed record, not a value to compare."""
    if not is_typed_json(dict(observed)):
        side.fail(f"row-schema:{case_id}:not-json")
    if not observed["status"]:
        side.fail(f"row-schema:{case_id}:status")
    if type(observed.get("documentPresent")) is not bool:
        side.fail(f"row-schema:{case_id}:documentPresent")
    fields = observed.get("fields")
    if fields is not None and not isinstance(fields, Mapping):
        side.fail(f"row-schema:{case_id}:fields")


def _admit_endpoint(side: _Side, endpoint: Any, where: str) -> None:
    host = endpoint_host(endpoint) if isinstance(endpoint, str) else None
    if host is None:
        side.fail(f"missing-binding:endpoint:{where}")
        return
    loopback = host in LOOPBACK_HOSTS
    production = host in PRODUCTION_HOSTS
    if side.side == SIDE_PRODUCTION:
        if loopback:
            side.fail("local-mislabelled-as-production")
        elif not production:
            side.fail("endpoint-outside-allowlist")
    elif not loopback:
        side.fail("local-reached-nonloopback")


def _gate_no_effect_subjects(gate: Any, plan: dict[str, Any]) -> frozenset[str]:
    """Derive the two atomic-denial exemptions from a live Gate replay."""
    if gate is None or not callable(getattr(gate, "snapshot", None)) or not callable(
        getattr(gate, "rules_management_ownership", None)
    ):
        return frozenset()
    try:
        snapshot = gate.snapshot()
        ownership = gate.rules_management_ownership()
    except Exception:
        return frozenset()
    gate_plan = snapshot.get("plan") if isinstance(snapshot, Mapping) else None
    if not isinstance(gate_plan, Mapping):
        return frozenset()
    if any(
        gate_plan.get(key) != plan.get(key)
        for key in ("campaignId", "project", "database", "nonce", "planDigest")
    ):
        return frozenset()
    if not isinstance(ownership, Mapping):
        return frozenset()
    rows = {
        row["index"]: row
        for row in plan["observation"]
        if row.get("method") == "commit"
        and row.get("expect", {}).get("status") == "PERMISSION_DENIED"
    }
    events = snapshot.get("managementEvents")
    if not isinstance(events, list) or any(
        not isinstance(event, Mapping) for event in events
    ):
        return frozenset()
    accepted: set[str] = set()
    for index, row in rows.items():
        resources = row.get("resources", [])
        if not isinstance(resources, list):
            continue
        event = next(
            (
                item
                for item in events
                if item.get("id") == f"observation:data/{index}"
            ),
            None,
        )
        if not isinstance(event, Mapping):
            continue
        receipt = event.get("rulesReceipt")
        body = receipt.get("body") if isinstance(receipt, Mapping) else None
        refusal = body.get("refusal") if isinstance(body, Mapping) else None
        if not (
            isinstance(receipt, Mapping)
            and event.get("complete") is receipt.get("complete") is True
            and event.get("workerReaped") is receipt.get("workerReaped") is True
            and event.get("completed") is True
            and event.get("status") == 403
            and receipt.get("complete") is True
            and receipt.get("workerReaped") is True
            and isinstance(body, Mapping)
            and body.get("effects") == []
            and isinstance(refusal, Mapping)
            and refusal.get("kind") == "rules-atomic-commit-refusal-v1"
            and refusal.get("slotId") == f"data/{index}"
            and refusal.get("rowDigest") == digest(row)
            and refusal.get("principal") == row.get("principal")
            and refusal.get("operation") == "Commit"
            and refusal.get("restCode") == 403
            and refusal.get("status") == "PERMISSION_DENIED"
        ):
            continue
        for resource in resources:
            subject = next(
                (
                    key
                    for key in ownership
                    if isinstance(key, str)
                    and key.startswith("document/")
                    and key.rsplit("/", 1)[-1] == resource.rsplit("/", 1)[-1]
                ),
                None,
            )
            state = ownership.get(subject) if subject is not None else None
            if (
                subject in {"document/getafter-control-target", "document/multiwrite-y"}
                and isinstance(state, Mapping)
                and state.get("status") == "attempted-no-effect"
            ):
                accepted.add(resource)
    return frozenset(accepted)


def _admit_cleanup(side: _Side, *, production_cleanup_gate: Any = None) -> list[dict[str, Any]]:
    """Every owned document and account must be read back, deleted under its
    observed version or uid, and then read back absent. Anything else is an
    unknown cleanup state, never a silent success."""
    assert side.plan is not None
    plan = side.plan
    cleanup = side.bundle.get("cleanup")
    if not isinstance(cleanup, Mapping):
        side.fail("cleanup-unknown:missing")
        return []
    if cleanup.get("cleanupComplete") is not True:
        side.fail("cleanup-unknown:incomplete")
    for key in (
        "outstandingResources",
        "outstandingAccounts",
        "unrecoveredAttempted",
        "held",
        "unconfirmed",
    ):
        if key in cleanup and cleanup.get(key) != []:
            side.fail(f"cleanup-unknown:{key}")
    steps: list[dict[str, Any]] = []
    for key in ("documentSteps", "accountSteps"):
        value = cleanup.get(key)
        if not isinstance(value, list) or not all(
            isinstance(s, Mapping) for s in value
        ):
            side.fail(f"cleanup-unknown:{key}")
            continue
        steps.extend(dict(step) for step in value)
    previous_at: float | None = None
    for step in steps:
        if step.get("failure") is not None:
            side.fail(f"cleanup-unknown:{step.get('kind')}")
        _admit_endpoint(side, step.get("endpoint"), f"cleanup:{step.get('kind')}")
        if not isinstance(step.get("observed"), Mapping | type(None)):
            side.fail(f"cleanup-unknown:observed-shape:{step.get('kind')}")
            step["observed"] = None
        at = step.get("at")
        if not _is_number(at):
            side.fail("time-contradiction:cleanup-timestamp")
        elif previous_at is not None and at < previous_at:
            side.fail("time-contradiction:cleanup-not-monotonic")
        else:
            previous_at = at
    exempt = (
        _gate_no_effect_subjects(production_cleanup_gate, plan)
        if side.side == SIDE_PRODUCTION
        else frozenset()
    )
    action_absences = _admit_action_absences(side)
    _admit_subjects(
        side, steps, plan["ownedResources"], "resource", "documentPresent", "version", exempt=exempt
    )
    _admit_subjects(
        side,
        steps,
        [entry["ref"] for entry in plan["ownedAccounts"]],
        "accountRef",
        "accountPresent",
        "uid",
        expected_presence={
            entry["ref"]: entry.get("postSignIn") != POST_SIGN_IN_DELETE
            for entry in plan["ownedAccounts"]
        },
        action_absences=action_absences,
    )
    attempted = side.bundle.get("attemptedResources")
    if not isinstance(attempted, list) or any(
        resource not in plan["ownedResources"] for resource in attempted
    ):
        side.fail("cleanup-unknown:attempted-outside-owned-scope")
    return steps


def _admit_action_absences(side: _Side) -> frozenset[str]:
    """Return only account deletions proven absent by their real action readback."""
    transport = side.bundle.get("transport")
    actions = transport.get("principalActions") if isinstance(transport, Mapping) else None
    if not isinstance(actions, list):
        return frozenset()
    absent: set[str] = set()
    for action in actions:
        if not isinstance(action, Mapping) or action.get("action") != "delete":
            continue
        ref = action.get("ref")
        readback = action.get("readback")
        if (
            isinstance(ref, str)
            and isinstance(readback, Mapping)
            and readback.get("present") is False
            and isinstance(readback.get("uidFingerprint"), str)
            and readback.get("uidFingerprint")
        ):
            absent.add(ref)
    return frozenset(absent)


def _admit_subjects(
    side: _Side,
    steps: list[dict[str, Any]],
    subjects: list[str],
    subject_key: str,
    presence_key: str,
    identity_key: str,
    expected_presence: Mapping[str, bool] | None = None,
    exempt: frozenset[str] = frozenset(),
    action_absences: frozenset[str] = frozenset(),
) -> None:
    """Every subject: readback, then delete under its identity and typed
    absence when it was present. When ``expected_presence`` is given, the
    readback must also show what the campaign did to the subject: an account
    the campaign deleted between rows must be absent, every other account must
    still be present, so "deleted by our action" and "never created" are two
    different records."""
    prefix = "account-" if subject_key == "accountRef" else ""
    for subject in subjects:
        own = [step for step in steps if step.get(subject_key) == subject]
        kinds = [step.get("kind") for step in own]
        readback = next((s for s in own if s.get("kind") == f"{prefix}readback"), None)
        if readback is None:
            if subject in exempt:
                continue
            if subject_key == "accountRef" and expected_presence is not None and expected_presence.get(subject) is False and subject in action_absences:
                continue
            side.fail(f"cleanup-unknown:no-readback:{subject}")
            continue
        observed = readback.get("observed") or {}
        present = observed.get(presence_key)
        if type(present) is not bool:
            side.fail(f"cleanup-unknown:untyped-presence:{subject}")
            continue
        if expected_presence is not None and present is not expected_presence[subject]:
            side.fail(
                f"cleanup-unknown:{'absent' if expected_presence[subject] else 'present'}"
                f"-at-readback:{subject}"
            )
        if present is False:
            if kinds != [f"{prefix}readback"]:
                side.fail(f"cleanup-unknown:steps-after-absence:{subject}")
            continue
        if (
            not isinstance(observed.get(identity_key), str)
            or not observed[identity_key]
        ):
            side.fail(f"cleanup-unknown:missing-identity:{subject}")
        if kinds != [f"{prefix}readback", f"{prefix}delete", f"{prefix}absence"]:
            side.fail(f"cleanup-unknown:step-sequence:{subject}")
            continue
        absence = (own[2].get("observed") or {}).get(presence_key)
        if absence is not False:
            side.fail(f"cleanup-unknown:not-absent:{subject}")


def _admit_releases(side: _Side, rows: list[Any] | None) -> list[dict[str, Any]]:
    assert side.plan is not None
    plan = side.plan
    transport = side.bundle.get("transport")
    releases = (
        transport.get("rulesetReleases") if isinstance(transport, Mapping) else None
    )
    if not isinstance(releases, list) or not releases:
        side.fail("missing-binding:rulesetReleases")
        return []
    accepted: list[dict[str, Any]] = []
    for release in releases:
        if not isinstance(release, Mapping):
            side.fail("ruleset-mismatch:shape")
            return []
        _admit_endpoint(side, release.get("endpoint"), "ruleset")
        label = release.get("label")
        if not isinstance(label, str) or label not in plan["rulesets"]:
            side.fail("ruleset-mismatch:unknown-label")
            continue
        expected = digest(plan["rulesets"][label]["source"])
        if release.get("sourceDigest") != expected:
            side.fail(f"ruleset-mismatch:{label}:source")
        readback = release.get("readback")
        if not isinstance(readback, Mapping) or readback.get("digest") != expected:
            side.fail(f"ruleset-mismatch:{label}:readback")
        elif readback.get("kind") not in READBACK_KINDS or (
            side.side == SIDE_PRODUCTION
            and readback.get("kind") != READBACK_RELEASE_GET
        ):
            side.fail(f"ruleset-mismatch:{label}:readback-kind")
        name = release.get("releaseName")
        if (
            not isinstance(name, str)
            or not name
            or (
                side.side == SIDE_PRODUCTION
                and _PRODUCTION_RELEASE_NAME.fullmatch(name) is None
            )
        ):
            side.fail(f"ruleset-mismatch:{label}:release-name")
        if (
            not _is_number(release.get("activeFrom"))
            or type(release.get("beforeIndex")) is not int
        ):
            side.fail(f"ruleset-generation-order:{label}:unbound")
            continue
        accepted.append(dict(release))
    if rows is None or len(accepted) != len(releases):
        return accepted
    # Replay the releases against the rows: each row must run under the label
    # released most recently before it, and after that release became active.
    ordered = sorted(accepted, key=lambda r: (r["beforeIndex"], r["activeFrom"]))
    if ordered != accepted:
        side.fail("ruleset-generation-order:sequence")
    active: dict[str, Any] | None = None
    pending = list(accepted)
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            break
        while pending and pending[0]["beforeIndex"] <= index:
            active = pending.pop(0)
        if active is None or active["label"] != row.get("ruleset"):
            side.fail(f"ruleset-generation-order:{row.get('caseId')}")
            continue
        at = row.get("at")
        if _is_number(at) and at < active["activeFrom"]:
            side.fail(f"ruleset-generation-order:{row.get('caseId')}")
    if pending:
        side.fail("ruleset-generation-order:unused-release")
    return accepted


def _admit_actions(side: _Side, rows: list[Any] | None) -> list[dict[str, Any]]:
    """The administrator steps between rows must be exactly the plan's, each
    proven by the transport's readback and placed between the row that accepted
    the principal and the row that presents its token again."""
    assert side.plan is not None
    plan = side.plan
    expected = principal_actions(plan)
    transport = side.bundle.get("transport")
    recorded = (
        transport.get("principalActions") if isinstance(transport, Mapping) else None
    )
    if not isinstance(recorded, list) or len(recorded) != len(expected):
        side.fail("principal-action:count")
        return []
    principals = (side.acquisition or {}).get("principals")
    accepted: list[dict[str, Any]] = []
    for action, planned in zip(recorded, expected, strict=True):
        ref = planned["ref"]
        if not isinstance(action, Mapping):
            side.fail(f"principal-action:{ref}:shape")
            continue
        if (
            action.get("ref") != ref
            or action.get("action") != planned["action"]
            or action.get("beforeIndex") != planned["beforeIndex"]
        ):
            side.fail(f"principal-action:{ref}:identity")
            continue
        _admit_endpoint(side, action.get("endpoint"), f"principal-action:{ref}")
        auth_time = action.get("authTime")
        valid_since = action.get("validSince")
        if type(auth_time) is not int or auth_time < 0:
            side.fail(f"principal-action:{ref}:authTime")
        if planned["action"] == POST_SIGN_IN_REVOKE:
            if (
                type(valid_since) is not int
                or type(auth_time) is not int
                or (valid_since <= auth_time)
            ):
                side.fail(f"principal-action:{ref}:validSince")
        elif valid_since is not None:
            side.fail(f"principal-action:{ref}:validSince")
        readback = action.get("readback")
        if not isinstance(readback, Mapping):
            side.fail(f"principal-action:{ref}:readback")
        else:
            present = readback.get("present")
            disabled = readback.get("disabled")
            if planned["action"] == POST_SIGN_IN_DELETE:
                proven = present is False and disabled is None
            else:
                proven = present is True and disabled is (
                    planned["action"] == POST_SIGN_IN_DISABLE
                )
            if not proven:
                side.fail(f"principal-action:{ref}:readback")
            bound = principals.get(ref) if isinstance(principals, Mapping) else None
            fingerprint = readback.get("uidFingerprint")
            if (
                not _hex(fingerprint, _HEX16)
                or not isinstance(bound, Mapping)
                or fingerprint != bound.get("uidFingerprint")
            ):
                side.fail(f"principal-action:{ref}:principal")
        at = action.get("at")
        index = planned["beforeIndex"]
        if not _is_number(at):
            side.fail(f"principal-action:{ref}:timestamp")
        elif rows is not None and 0 < index < len(rows):
            before = rows[index - 1] if isinstance(rows[index - 1], Mapping) else {}
            after = rows[index] if isinstance(rows[index], Mapping) else {}
            # The preceding row is the positive control for the same
            # principal; the action must fall strictly between the two.
            if before.get("credentialRef") != ref or not (
                _is_number(before.get("at"))
                and _is_number(after.get("at"))
                and before["at"] <= at <= after["at"]
            ):
                side.fail(f"principal-action:{ref}:order")
        accepted.append(dict(action))
    return accepted


def _admit_management_receipts(side: _Side) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    management = side.bundle.get("transport", {}).get("rulesManagement")
    receipts = management.get("managementReceipts") if isinstance(management, Mapping) else None
    if not isinstance(receipts, list) or len(receipts) != len(_RULES_MANAGEMENT_IDS):
        side.fail("management-receipts:count")
        return [], []
    expected = ["observation:" + slot for slot in _RULES_MANAGEMENT_IDS[:13]] + [
        "recovery:" + slot for slot in _RULES_MANAGEMENT_IDS[13:]
    ]
    actual: list[str] = []
    accepted: list[dict[str, Any]] = []
    for entry in receipts:
        if not isinstance(entry, Mapping):
            side.fail("management-receipts:shape")
            continue
        phase, slot = entry.get("phase"), entry.get("slot")
        identity = f"{phase}:{slot}"
        actual.append(identity)
        if not isinstance(entry.get("endpoint"), str) or type(entry.get("wireSequence")) is not int:
            side.fail("management-receipts:binding")
        else:
            _admit_endpoint(side, entry["endpoint"], "management")
        accepted.append(dict(entry))
    if actual != expected:
        side.fail("management-receipts:order")
    observation = accepted[:13]
    recovery = accepted[13:]
    return observation, recovery


def _admit_transport(
    side: _Side,
    rows: list[Any] | None,
    releases: list[dict[str, Any]],
    actions: list[dict[str, Any]],
    cleanup_steps: list[dict[str, Any]],
) -> None:
    transport = side.bundle.get("transport")
    if not isinstance(transport, Mapping):
        side.fail("missing-binding:transport")
        return
    endpoints = transport.get("endpoints")
    if not isinstance(endpoints, list) or not endpoints:
        side.fail("missing-binding:endpoint")
    else:
        for endpoint in endpoints:
            _admit_endpoint(side, endpoint, "transport")
    management_observation: list[dict[str, Any]] = []
    management_recovery: list[dict[str, Any]] = []
    if side.side == SIDE_PRODUCTION:
        management_observation, management_recovery = _admit_management_receipts(side)
    # Wire sequence: every receipt carries the transport's own request counter,
    # and the counters must increase strictly in the order the collector issued
    # the requests. Production management records surround data work; local
    # shadow records retain the legacy release path.
    # The production collector interleaves management and data work: the A
    # lifecycle prefix precedes row zero, the B prefix is emitted at its
    # compiled transition boundary, and recovery follows cleanup.  The old
    # comparator concatenated all management receipts before all rows, which
    # rejected the collector's genuine wire sequence (1..8, 9..41, 42..46).
    # Build the compiled event order first, then compare the transport's
    # sequence numbers in that order.  Sorting receipts by sequence would hide
    # a receipt attached to the wrong event, so only the sequence values are
    # used to validate the already-derived event order.
    events: list[tuple[str, Any]] = []
    if side.side == SIDE_PRODUCTION:
        boundary = next(
            (release.get("beforeIndex") for release in releases if release.get("label") == "B"),
            0,
        )
        for entry in management_observation:
            slot = entry.get("slot")
            events.append((f"management:{entry.get('phase')}:{slot}", entry.get("wireSequence")))
        # Move the B prefix to its compiled boundary without relying on a
        # caller-supplied order field.
        prefix = [
            event
            for event in events
            if ":create-b" not in event[0] and ":patch-b" not in event[0]
        ]
        suffix = [event for event in events if event not in prefix]
        ordered_management = prefix + suffix
        events = []
        for event in ordered_management:
            events.append(event)
        if rows is not None:
            # Rebuild around the first B management slot. The compiled Rules
            # transition is the only management/data boundary.
            before_b = next(
                (
                    i
                    for i, event in enumerate(ordered_management)
                    if ":create-b" in event[0]
                ),
                len(ordered_management),
            )
            events = ordered_management[:before_b]
            data_events: list[tuple[int, int, str, Any]] = []
            for i, row in enumerate(rows):
                data_events.append(
                    (
                        i,
                        0,
                        f"row:{i}",
                        row.get("wireSequence") if isinstance(row, Mapping) else None,
                    )
                )
            for action in actions:
                data_events.append(
                    (
                        action.get("beforeIndex", -1),
                        -1,
                        f"action:{action.get('ref')}",
                        action.get("wireSequence"),
                    )
                )
            data_events.sort(key=lambda event: (event[0], event[1]))
            events.extend((label, sequence) for index, _, label, sequence in data_events if index < boundary)
            events.extend(ordered_management[before_b:])
            events.extend((label, sequence) for index, _, label, sequence in data_events if index >= boundary)
    else:
        if rows is not None:
            data_events = [(i, 0, f"row:{i}", row.get("wireSequence") if isinstance(row, Mapping) else None) for i, row in enumerate(rows)]
            data_events.extend((a.get("beforeIndex", -1), -1, f"action:{a.get('ref')}", a.get("wireSequence")) for a in actions)
            data_events.extend((r.get("beforeIndex", -1), -2, f"release:{r.get('label')}", r.get("wireSequence")) for r in releases)
            data_events.sort(key=lambda event: (event[0], event[1]))
            events.extend((label, sequence) for _, _, label, sequence in data_events)
    events.extend(
        (
            f"cleanup:{step.get('kind')}:{step.get('resource', step.get('accountRef'))}",
            step.get("wireSequence"),
        )
        for step in cleanup_steps
    )
    events.extend(
        (
            f"management:{entry.get('phase')}:{entry.get('slot')}",
            entry.get("wireSequence"),
        )
        for entry in management_recovery
    )
    sequenced = [sequence for _, sequence in events]
    if any(type(value) is not int for value in sequenced):
        side.fail("missing-binding:wireCounts")
    elif any(b <= a for a, b in pairwise(sequenced)):
        side.fail("count-contradiction:wire-sequence")
    receipts = transport.get("receipts")
    if type(receipts) is not int or receipts != len(sequenced):
        side.fail("count-contradiction:wire-receipts")
    if sequenced and (
        transport.get("firstSequence") != sequenced[0]
        or transport.get("lastSequence") != sequenced[-1]
        or transport.get("sequencedReceipts") != len(sequenced)
    ):
        side.fail("count-contradiction:wire-summary")
    if transport.get("sequenceMonotonic") is not True:
        side.fail("count-contradiction:wire-sequence")
    _admit_clocks(side, transport, rows)


def _admit_clocks(
    side: _Side, transport: Mapping[str, Any], rows: list[Any] | None
) -> None:
    clock = transport.get("clock")
    wall = transport.get("wallClock")
    budget = side.bundle.get("budget")
    if not isinstance(clock, Mapping) or not all(
        _is_number(clock.get(key))
        for key in ("started", "observationFinished", "finished")
    ):
        side.fail("time-contradiction:clock")
        return
    started = clock["started"]
    observation_finished = clock["observationFinished"]
    finished = clock["finished"]
    if not started <= observation_finished <= finished:
        side.fail("time-contradiction:clock-order")
    if rows:
        stamps = [row.get("at") for row in rows if isinstance(row, Mapping)]
        if (
            all(_is_number(s) for s in stamps)
            and stamps
            and not (started <= stamps[0] and stamps[-1] <= observation_finished)
        ):
            side.fail("time-contradiction:rows-outside-observation")
    if isinstance(budget, Mapping):
        deadline = budget.get("deadlineSeconds")
        recovery_deadline = budget.get("recoveryDeadlineSeconds")
        if _is_number(deadline) and observation_finished - started > deadline:
            side.fail("time-contradiction:deadline")
        if _is_number(recovery_deadline) and finished - started > recovery_deadline:
            side.fail("time-contradiction:recovery-deadline")
    if not isinstance(wall, Mapping) or not all(
        _is_number(wall.get(key)) for key in ("startedAt", "finishedAt")
    ):
        side.fail("time-contradiction:wall-clock")
        return
    wall_span = wall["finishedAt"] - wall["startedAt"]
    if (
        wall_span < 0
        or abs(wall_span - (finished - started)) > _CLOCK_TOLERANCE_SECONDS
    ):
        side.fail("time-contradiction:wall-clock")
    window = (side.acquisition or {}).get("window")
    if (
        isinstance(window, Mapping)
        and all(_is_number(window.get(key)) for key in ("startsAt", "expiresAt"))
        and not (
            window["startsAt"]
            <= wall["startedAt"]
            <= wall["finishedAt"]
            <= window["expiresAt"]
        )
    ):
        side.fail("time-contradiction:outside-window")


def _admit_budget(
    side: _Side,
    rows: list[Any] | None,
    releases: list[dict[str, Any]],
    actions: list[dict[str, Any]],
    cleanup_steps: list[dict[str, Any]],
) -> None:
    assert side.plan is not None
    plan = side.plan
    budget = side.bundle.get("budget")
    if not isinstance(budget, Mapping):
        side.fail("count-contradiction:budget")
        return
    if rows is not None and budget.get("observationSpent") != len(rows):
        side.fail("count-contradiction:observation-spent")
    if budget.get("rulesetSpent") != len(releases):
        side.fail("count-contradiction:ruleset-spent")
    if budget.get("principalActionSpent") != len(actions):
        side.fail("count-contradiction:principal-action-spent")
    if budget.get("principalActionCeiling") != len(principal_actions(plan)):
        side.fail("count-contradiction:principal-action-ceiling")
    # The ceilings are what the collector enforces for this plan, not values
    # a bundle may choose; the deadlines are what the clock checks run against.
    if budget.get("observationCeiling") != len(plan["observation"]):
        side.fail("count-contradiction:observation-ceiling")
    if budget.get("rulesetCeiling") != ruleset_transitions(plan["observation"]):
        side.fail("count-contradiction:ruleset-ceiling")
    expected_recovery = 3 * (len(plan["ownedResources"]) + len(plan["ownedAccounts"]))
    recovery = budget.get("recoverySpent")
    ceiling = budget.get("recoveryCeiling")
    if ceiling != expected_recovery or type(recovery) is not int or recovery > ceiling:
        side.fail("count-contradiction:recovery-ceiling")
    elif recovery != len(cleanup_steps):
        side.fail("count-contradiction:recovery-spent")
    for key in ("deadlineSeconds", "recoveryDeadlineSeconds"):
        value = budget.get(key)
        if not _is_number(value) or value <= 0:
            side.fail(f"count-contradiction:{key}")


def _cross_errors(
    production: _Side, local: _Side, plan: dict[str, Any], manifest_digest: str | None
) -> list[str]:
    errors: list[str] = []
    if production.bundle is local.bundle:
        errors.append("self-comparison")
    production_run = _provenance_value(production.bundle, "runId")
    if production_run is not None and production_run == _provenance_value(
        local.bundle, "runId"
    ):
        errors.append("self-comparison")
    declared = {
        side.side: (side.acquisition or {}).get("campaignManifestDigest")
        for side in (production, local)
    }
    expected = admitted_manifest_digest(
        plan["project"], plan["database"], plan["nonce"]
    )
    if any(value is not None and value != expected for value in declared.values()):
        errors.append("manifest-mismatch")
    if manifest_digest is not None and manifest_digest != expected:
        errors.append("manifest-mismatch:admitted")
    shared = _shared_fingerprints(production, local)
    if shared:
        errors.append("principal-shared-across-sides:" + ",".join(shared))
    return errors


def _shared_fingerprints(production: _Side, local: _Side) -> list[str]:
    left = (production.acquisition or {}).get("principals")
    right = (local.acquisition or {}).get("principals")
    if not isinstance(left, Mapping) or not isinstance(right, Mapping):
        return []
    shared = []
    for ref in ACCOUNT_PRINCIPALS:
        a = left.get(ref) if isinstance(left.get(ref), Mapping) else {}
        b = right.get(ref) if isinstance(right.get(ref), Mapping) else {}
        fingerprint = a.get("uidFingerprint")
        if isinstance(fingerprint, str) and fingerprint == b.get("uidFingerprint"):
            shared.append(ref)
    return shared


def _provenance_value(bundle: Any, key: str) -> Any:
    if not isinstance(bundle, Mapping):
        return None
    provenance = bundle.get("provenance")
    return provenance.get(key) if isinstance(provenance, Mapping) else None


def _compare_rows(
    plan: dict[str, Any], production: dict[str, Any], local: dict[str, Any]
) -> list[dict[str, Any]]:
    labels = {
        SIDE_PRODUCTION: _principal_labels(production, plan),
        SIDE_LOCAL: _principal_labels(local, plan),
    }
    rows = []
    for operation, left, right in zip(
        plan["observation"], production["rows"], local["rows"], strict=True
    ):
        projected, unmapped = {}, []
        for side, observed_row in ((SIDE_PRODUCTION, left), (SIDE_LOCAL, right)):
            projected[side], keys = _projection(observed_row, operation, labels[side])
            unmapped.extend(f"{side}:principal-unmapped:{key}" for key in keys)
        row = {
            "caseId": operation["caseId"],
            "index": operation["index"],
            "condition": operation["condition"],
            "ruleset": operation["ruleset"],
            "expected": operation["expect"]["status"],
            "production": projected[SIDE_PRODUCTION],
            "local": projected[SIDE_LOCAL],
            "classification": MATCH,
            "reasons": [],
            "productionHypothesis": None,
            "hypothesisOutcome": None,
        }
        if unmapped:
            # A principal slot without a binding on either side cannot be
            # compared at all; equality of two unmapped values is not agreement.
            row["classification"] = INDETERMINATE
            row["reasons"] = unmapped
        elif not same_typed_json(row["production"], row["local"]):
            row["classification"] = SEMANTIC_MISMATCH
            row["reasons"] = sorted(
                key
                for key in row["production"]
                if not same_typed_json(row["production"][key], row["local"][key])
            )
        hypothesis = operation["expect"].get("productionHypothesis")
        if isinstance(hypothesis, Mapping):
            # A stated expectation about production, carried on the plan row.
            # It reads the production status only and never touches the
            # classification: a mismatch on a row whose hypothesis holds is
            # the expected outcome, and still a mismatch.
            row["productionHypothesis"] = dict(hypothesis)
            row["hypothesisOutcome"] = (
                "as-hypothesized"
                if row["production"]["status"] == hypothesis.get("status")
                else "contrary"
            )
        rows.append(row)
    return rows


def _hypotheses(rows: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    summary: dict[str, dict[str, int]] = {}
    for row in rows:
        if row["hypothesisOutcome"] is None:
            continue
        entry = summary.setdefault(
            row["condition"], {"rows": 0, "asHypothesized": 0, "contrary": 0}
        )
        entry["rows"] += 1
        key = (
            "asHypothesized"
            if row["hypothesisOutcome"] == "as-hypothesized"
            else "contrary"
        )
        entry[key] += 1
    return dict(sorted(summary.items()))


def _principal_labels(bundle: Any, plan: Mapping[str, Any]) -> dict[str, str]:
    """The run's own principal binding: ``principal:<ref>`` label to logical
    principal reference.

    The collector learns a uid only from the account readback of the recovery
    phase and replaces it everywhere with ``principal:<ref>``; the readback
    step itself then carries the label as its ``uid``. A label is evidence of
    the mapping only when the bundle declares it in ``redactedPrincipals``,
    the plan owns the account, and that account's readback recorded the
    label as the identifier it deleted under. Nothing else maps.
    """
    if not isinstance(bundle, Mapping):
        return {}
    declared = bundle.get("redactedPrincipals")
    cleanup = bundle.get("cleanup")
    steps = cleanup.get("accountSteps") if isinstance(cleanup, Mapping) else None
    if not isinstance(declared, list) or not isinstance(steps, list):
        return {}
    labels: dict[str, str] = {}
    for entry in plan["ownedAccounts"]:
        ref = entry["ref"]
        label = f"principal:{ref}"
        if label not in declared:
            continue
        for step in steps:
            if (
                isinstance(step, Mapping)
                and step.get("kind") == "account-readback"
                and step.get("accountRef") == ref
            ):
                observed = step.get("observed")
                if (
                    isinstance(observed, Mapping)
                    and observed.get("accountPresent") is True
                    and observed.get("uid") == label
                ):
                    labels[label] = ref
                break
    return labels


def _projection(
    row: Mapping[str, Any], operation: Mapping[str, Any], labels: Mapping[str, str]
) -> tuple[dict[str, Any], list[str]]:
    """The comparable part of an observed row, and the field keys whose
    principal slot could not be mapped.

    Field values that resolve to a principal differ between sides by
    construction, because the two runs mint different accounts, so each is
    mapped through ``labels`` to the logical principal ``{"$principal": ref}``
    and that is what is compared. The mapping needs two witnesses that agree:
    the label the readback recorded, and the row's own pre-redaction binding
    (validated by ``_admit_rows``) naming the same principal for that field.
    A value without both is projected as ``{"$principal": None}`` and reported
    as unmapped; being a non-empty string, or looking like a label, is not a
    mapping. Every other field value is compared literally, by typed JSON
    equality.
    """
    observed = row.get("observed") or {}
    fields = observed.get("fields")
    bindings = row.get(BINDINGS_KEY)
    bindings = bindings if isinstance(bindings, Mapping) else {}
    projected_fields: dict[str, Any] | None = None
    unmapped: list[str] = []
    if isinstance(fields, Mapping):
        expected = operation["expect"].get("fields", {})
        projected_fields = {}
        for key in sorted(fields):
            value = fields[key]
            if isinstance(expected.get(key), Mapping):
                ref = labels.get(value) if isinstance(value, str) else None
                binding = bindings.get(key)
                if ref is not None and not (
                    isinstance(binding, Mapping) and binding.get("ref") == ref
                ):
                    ref = None
                projected_fields[key] = {"$principal": ref}
                if ref is None:
                    unmapped.append(key)
            else:
                projected_fields[key] = value
    return {
        "status": observed.get("status"),
        "documentPresent": observed.get("documentPresent"),
        "fields": projected_fields,
    }, unmapped


def compare(
    production: Any,
    local: Any,
    plan: Any,
    *,
    manifest_digest: str | None = None,
    production_cleanup_gate: Any = None,
) -> dict[str, Any]:
    """Classify a production bundle against a local shadow bundle.

    ``plan`` is the compiled production case. ``manifest_digest``, when given,
    is the digest the run was admitted under and must equal the recomputed one.
    The result never carries a positive classification unless both bundles
    were admitted as acquisitions of this campaign.
    """
    result: dict[str, Any] = {
        "contract": COMPARATOR_CONTRACT,
        "classification": INDETERMINATE,
        "rows": [],
        "conditions": {},
        "hypotheses": {},
        "errors": [],
        "acquisitionValidated": False,
        "productionObserved": False,
        "promotionReady": False,
    }
    try:
        validate_case(plan)
    except (TypeError, ValueError) as error:
        result["errors"] = [f"plan-invalid:{error}"]
        result["classification"] = REFUSED
        return result
    production_side = _Side(production, SIDE_PRODUCTION)
    local_side = _Side(local, SIDE_LOCAL)
    try:
        _admit_side(
            production_side,
            plan,
            production_cleanup_gate=production_cleanup_gate,
        )
        _admit_side(local_side, plan)
        cross = _cross_errors(production_side, local_side, plan, manifest_digest)
    except Exception as error:  # noqa: BLE001 -- an unforeseen shape is named, never raised
        # Admission runs inside the O8 execution. A bundle shape this module
        # did not anticipate must be named as indeterminate there, not
        # propagate as an exception that the launcher has to interpret.
        result["errors"] = [
            *production_side.errors,
            *local_side.errors,
            f"comparator-exception:{type(error).__name__}",
        ]
        return result
    errors = [*production_side.errors, *local_side.errors]
    errors.extend(cross)
    result["errors"] = errors
    refused = (
        production_side.refused
        or local_side.refused
        or any(error.split(":", 1)[0] in REFUSAL_ERRORS for error in cross)
    )
    if refused:
        result["classification"] = REFUSED
        return result
    if errors:
        return result
    result["acquisitionValidated"] = True
    result["productionObserved"] = True
    rows = _compare_rows(plan, production, local)
    result["rows"] = rows
    conditions: dict[str, str] = {}
    for row in rows:
        current = conditions.get(row["condition"], MATCH)
        if _ROW_RANK[row["classification"]] > _ROW_RANK[current]:
            conditions[row["condition"]] = row["classification"]
        else:
            conditions[row["condition"]] = current
    result["conditions"] = dict(sorted(conditions.items()))
    result["hypotheses"] = _hypotheses(rows)
    for row in rows:
        if row["classification"] == INDETERMINATE:
            for reason in row["reasons"]:
                side, name, key = reason.split(":", 2)
                errors.append(f"{side}:{name}:{row['caseId']}:{key}")
    if errors:
        # Invariant: acquisitionValidated == (errors == []). A row whose
        # principal slot has no binding is incomplete evidence, exactly like
        # a uid-shaped string the redaction missed, and neither validates.
        result["errors"] = errors
        result["acquisitionValidated"] = False
        return result
    if all(row["classification"] == MATCH for row in rows):
        result["classification"] = MATCH
        result["promotionReady"] = True
    else:
        result["classification"] = SEMANTIC_MISMATCH
    return result
