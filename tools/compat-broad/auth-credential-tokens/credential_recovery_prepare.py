"""Prepare a secret-free Auth packet05 recovery bundle.

This is an offline operator boundary. It reads a held parent and the shared
Ledger, compiles a fresh lookup child, and writes a review request. A packet
can only be assembled when separately reviewed permission/O7/O8 documents are
supplied. It never calls a transport, begins a child reservation, or closes a
parent.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools/compat-broad"))
sys.path.insert(0, str(ROOT / "tools/compat-broad/production-admission"))
sys.path.insert(0, str(HERE))

import credential_recovery as recovery
import reservations
from broad_contract import digest
from shared_gate import Gate

PACKET_KIND = "auth-packet05-recovery-preparation-v1"
REVIEW_REQUEST_KIND = "auth-packet05-recovery-review-request-v1"
REVIEW_EVIDENCE_KIND = "auth-packet05-independent-review-evidence-v1"
ARTIFACT_NAMES = (
    "packet.json",
    "review-request.json",
    "plan.json",
    "permission.json",
    "o7.json",
    "o8.json",
    "permission-review.json",
    "o7-review.json",
    "o8-review.json",
    "parent-evidence.json",
)
SECRET_KEYS = frozenset(
    {
        "accessToken",
        "apiKey",
        "idToken",
        "password",
        "privateKey",
        "refreshToken",
        "serviceAccount",
    }
)
MAX_INPUT_BYTES = 8 * 1024 * 1024
EXECUTION_SOURCE_KIND = "auth-recovery-executor-source-v1"
EXECUTION_SOURCE_CLOSURE = (
    "tools/compat-broad/auth-credential-tokens/credential_recovery_executor.py",
    "tools/compat-broad/auth-credential-tokens/credential_recovery_prepare.py",
    "tools/compat-broad/auth-credential-tokens/credential_recovery.py",
    "tools/compat-broad/auth-credential-tokens/credential_remote_transport.py",
    "tools/compat-broad/auth-credential-tokens/credential_wire.py",
    "tools/compat-broad/batch_wire.py",
    "tools/compat-broad/auth-credential-tokens/credential_https_worker.py",
    "tools/compat-broad/shared_gate.py",
    "tools/compat-broad/production-admission/reservations.py",
)


def _refuse(reason: str) -> None:
    raise recovery.RecoveryRefusal(reason)


def _read_json(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_INPUT_BYTES:
        _refuse("bounded regular JSON input required")
    try:
        value = json.loads(path.read_bytes())
    except (OSError, ValueError):
        _refuse("bounded JSON input required")
    if not isinstance(value, dict):
        _refuse("bounded JSON object required")
    return value


def _execution_source(source_root: Path) -> dict[str, Any]:
    """Derive the reviewed executor closure from a clean checkout."""
    if source_root.is_symlink() or not source_root.is_dir():
        _refuse("clean execution source checkout required")
    try:
        source_commit = subprocess.check_output(
            ["git", "-C", str(source_root), "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        dirty = subprocess.check_output(
            [
                "git",
                "-C",
                str(source_root),
                "status",
                "--porcelain",
                "--untracked-files=all",
            ],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        _refuse("clean execution source checkout required")
    if re.fullmatch(r"[0-9a-f]{40}", source_commit) is None or dirty:
        _refuse("clean execution source checkout required")
    source_inputs: dict[str, str] = {}
    for relative in EXECUTION_SOURCE_CLOSURE:
        path = source_root / relative
        candidate = source_root
        for component in Path(relative).parts:
            candidate /= component
            if candidate.is_symlink():
                _refuse("execution source closure differs")
        try:
            regular_file = path.is_file() and stat.S_ISREG(path.stat().st_mode)
        except OSError:
            regular_file = False
        if not regular_file:
            _refuse("execution source closure differs")
        try:
            tree_entry = subprocess.check_output(
                [
                    "git",
                    "-C",
                    str(source_root),
                    "ls-tree",
                    "-z",
                    "--full-tree",
                    source_commit,
                    "--",
                    relative,
                ],
                stderr=subprocess.DEVNULL,
            )
            records = [record for record in tree_entry.split(b"\0") if record]
            if len(records) != 1:
                _refuse("execution source closure differs")
            metadata, tree_path = records[0].split(b"\t", 1)
            mode, object_type, _object_id = metadata.decode("ascii").split()
            if (
                tree_path.decode("utf-8") != relative
                or mode not in {"100644", "100755"}
                or object_type != "blob"
            ):
                _refuse("execution source closure differs")
            git_bytes = subprocess.check_output(
                ["git", "-C", str(source_root), "show", f"{source_commit}:{relative}"],
                stderr=subprocess.DEVNULL,
            )
            file_bytes = path.read_bytes()
        except (OSError, UnicodeDecodeError, ValueError, subprocess.CalledProcessError):
            _refuse("execution source closure differs")
        if file_bytes != git_bytes:
            _refuse("execution source closure differs")
        source_inputs[relative] = hashlib.sha256(git_bytes).hexdigest()
    try:
        final_commit = subprocess.check_output(
            ["git", "-C", str(source_root), "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        final_dirty = subprocess.check_output(
            [
                "git",
                "-C",
                str(source_root),
                "status",
                "--porcelain",
                "--untracked-files=all",
            ],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        _refuse("clean execution source checkout required")
    if final_commit != source_commit or final_dirty:
        _refuse("execution source checkout changed during capture")
    return {
        "kind": EXECUTION_SOURCE_KIND,
        "sourceCommit": source_commit,
        "sourceInputs": source_inputs,
        "sourceInputsDigest": digest(source_inputs),
    }


def _reconstruct_parent(parent: Mapping[str, Any], ledger: Any) -> tuple[dict[str, Any], Mapping[str, Any]]:
    ticket = parent.get("ticket")
    if not isinstance(ticket, Mapping):
        _refuse("parent Ledger ticket required")
    bound_claim_method = getattr(ledger, "bound_claim", None)
    if not callable(bound_claim_method):
        _refuse("production-admission Ledger claim API required")
    try:
        bound_claim = bound_claim_method(copy.deepcopy(dict(ticket)))
    except Exception as error:  # noqa: BLE001 -- never expose Ledger details at this boundary.
        raise recovery.RecoveryRefusal(
            f"parent Ledger claim refused: {type(error).__name__}"
        ) from None
    if not isinstance(bound_claim, Mapping) or bound_claim.get("campaignId") != recovery.CAMPAIGN:
        _refuse("canonical Auth parent claim required")
    ticket_digest = ticket.get("claimDigest")
    if ticket_digest is not None and ticket_digest != digest(bound_claim):
        _refuse("parent Ledger claim binding changed")
    snapshot_method = getattr(ledger, "snapshot", None)
    if not callable(snapshot_method):
        _refuse("production-admission Ledger snapshot API required")
    try:
        state = snapshot_method()
    except Exception as error:  # noqa: BLE001 -- never expose Ledger details at this boundary.
        raise recovery.RecoveryRefusal(f"parent Ledger snapshot refused: {type(error).__name__}") from None
    reservation = ticket.get("reservation")
    row = (state.get("reservations", {}) if isinstance(state, Mapping) else {}).get(reservation)
    if not isinstance(row, Mapping) or row.get("state") != "held":
        _refuse("canonical held Auth parent required")
    if row.get("claimDigest") not in {digest(bound_claim), bound_claim.get("claimDigest")} or row.get("claim") != dict(bound_claim):
        _refuse("parent Ledger claim binding changed")
    generation = row.get("generation")
    if not isinstance(generation, Mapping):
        _refuse("canonical parent source generation required")
    gate_path = bound_claim.get("gatePath")
    gate_job = bound_claim.get("gateJob", "auth-credential")
    try:
        if isinstance(gate_path, str):
            canonical_gate = Gate(gate_path, gate_job).snapshot()
        else:
            bound_gate = getattr(ledger, "bound_gate", None)
            if not callable(bound_gate):
                _refuse("canonical parent Gate API required")
            canonical_gate = bound_gate(copy.deepcopy(dict(ticket)))
    except recovery.RecoveryRefusal:
        raise
    except Exception as error:  # noqa: BLE001 -- never expose Gate details at this boundary.
        raise recovery.RecoveryRefusal(f"parent Gate snapshot refused: {type(error).__name__}") from None
    if not isinstance(canonical_gate, Mapping):
        _refuse("canonical parent Gate evidence required")
    gate_plan = canonical_gate.get("plan")
    if not isinstance(gate_plan, Mapping):
        _refuse("canonical parent Gate plan required")
    parent_job = bound_claim.get("gateJob", "auth-credential")
    event_index, operation, _event = recovery._select_unresolved_custom_event(
        gate_plan, canonical_gate, parent_job
    )
    immutable = {
        "kind": "auth-packet05-parent-binding-v1",
        "gateDigest": digest(canonical_gate),
        "gatePlanDigest": digest(gate_plan),
        "nonce": gate_plan.get("nonce"),
        "resource": operation.get("resource"),
        "eventIndex": event_index,
        "requestDigest": digest(operation),
        "sourceCommit": generation["sourceCommit"],
    }
    # Receipt, responsibility and immutable binding are derived from the
    # canonical claim/Gate, never accepted from the caller's parent JSON.
    canonical = {
        "state": "held",
        "ticket": copy.deepcopy(dict(ticket)),
        "claim": copy.deepcopy(dict(bound_claim)),
        "gate": copy.deepcopy(dict(canonical_gate)),
        "generation": copy.deepcopy(dict(generation)),
        "receipt": {"failure": "canonical-unresolved-parent", "postflightComplete": False},
        "responsibility": {"custom": {"state": "unknown", "uid": None}},
        "immutableParent": immutable,
    }
    recovery._parent_snapshot(canonical)
    return canonical, state


def _assert_fresh_nonce(ledger: Any, nonce: str, state: Mapping[str, Any]) -> None:
    target = digest(nonce)
    if not isinstance(state, Mapping):
        _refuse("canonical Ledger snapshot required")
    for row in (state.get("reservations", {}) or {}).values():
        if not isinstance(row, Mapping):
            continue
        claim = row.get("claim")
        if isinstance(claim, Mapping) and claim.get("nonceDigest") == target:
            _refuse("recovery nonce already reserved")
        for child in row.get("recoveryChildren", []) or []:
            child_claim = child.get("claim") if isinstance(child, Mapping) else None
            if (
                isinstance(child_claim, Mapping)
                and child_claim.get("nonceDigest") == target
            ):
                _refuse("recovery nonce already reserved")


def _verify_fixed_source(
    provenance: Mapping[str, Any],
    source_root: Path,
    expected_commit: str,
    parent_generation: Mapping[str, Any],
) -> None:
    if source_root.is_symlink() or not source_root.is_dir():
        _refuse("clean source checkout required")
    try:
        actual_commit = subprocess.check_output(
            ["git", "-C", str(source_root), "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        dirty = subprocess.check_output(
            ["git", "-C", str(source_root), "status", "--porcelain", "--untracked-files=all"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        _refuse("clean source checkout required")
    if actual_commit != expected_commit or dirty:
        _refuse("fixed source checkout differs")
    source_inputs = provenance.get("sourceInputs") if isinstance(provenance, Mapping) else None
    if not isinstance(source_inputs, Mapping) or not source_inputs:
        _refuse("source input provenance required")
    for relative, expected_digest in source_inputs.items():
        path = source_root / relative
        if not isinstance(relative, str) or not relative.startswith("tools/") or ".." in Path(relative).parts:
            _refuse("source path provenance differs")
        if path.is_symlink() or not path.is_file():
            _refuse("source checkout input missing")
        actual_digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual_digest != expected_digest:
            _refuse("source checkout digest differs")
    generation = provenance.get("generation")
    if not isinstance(generation, Mapping):
        _refuse("source generation provenance required")
    declared_generation = generation.get("sourceDigests")
    canonical_sources = parent_generation.get("sourceDigests") if isinstance(parent_generation, Mapping) else None
    if not isinstance(canonical_sources, Mapping) or not isinstance(declared_generation, Mapping):
        _refuse("source generation closure differs")
    if set(declared_generation) - set(canonical_sources) != {recovery.APPROVED_CHILD_SOURCE_EXTENSION}:
        _refuse("source generation closure differs")
    if any(declared_generation.get(name) != value for name, value in canonical_sources.items()):
        _refuse("source generation closure differs")
    generation_paths = provenance.get("generationPaths")
    if not isinstance(generation_paths, Mapping) or set(generation_paths) != set(declared_generation):
        _refuse("source generation paths required")
    if len(set(generation_paths.values())) != len(generation_paths):
        _refuse("source generation paths differ")
    for name, expected_digest in declared_generation.items():
        relative = generation_paths.get(name)
        if not isinstance(relative, str) or source_inputs.get(relative) != expected_digest:
            _refuse("source generation path binding differs")
        path = source_root / relative
        if path.is_symlink() or not path.is_file():
            _refuse("source generation input missing")
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected_digest:
            _refuse("source generation digest differs")
    recovery_path = generation_paths.get(recovery.APPROVED_CHILD_SOURCE_EXTENSION)
    if recovery_path != "tools/compat-broad/auth-credential-tokens/credential_recovery.py":
        _refuse("collector source path differs")
    if generation.get("collectorSourceDigest") != declared_generation.get(recovery.APPROVED_CHILD_SOURCE_EXTENSION):
        _refuse("collector source digest differs")


def _review_request(
    plan: Mapping[str, Any],
    parent: Mapping[str, Any],
    execution_source_digest: str,
) -> dict[str, Any]:
    return {
        "kind": REVIEW_REQUEST_KIND,
        "campaignId": recovery.CAMPAIGN,
        "planDigest": plan["planDigest"],
        "parentEvidenceDigest": parent["evidence"]["evidenceDigest"],
        "sourceCommit": plan["provenance"]["sourceCommit"],
        "recoveryNonceDigest": plan["recoveryNonceDigest"],
        "executionSourceDigest": execution_source_digest,
        "requestedAuthorityKinds": [recovery.PERMISSION_KIND, recovery.O7_KIND, recovery.O8_KIND],
        "reviewedArtifactsRequired": True,
        "productionExecuted": False,
    }


def _validate_reviewed_authorities(
    plan: Mapping[str, Any],
    permission: Mapping[str, Any] | None,
    o7: Mapping[str, Any] | None,
    o8: Mapping[str, Any] | None,
    permission_review: Mapping[str, Any] | None,
    o7_review: Mapping[str, Any] | None,
    o8_review: Mapping[str, Any] | None,
    *,
    now: float,
    execution_source_digest: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    if not all(isinstance(value, Mapping) for value in (permission, o7, o8)):
        _refuse("separately reviewed permission/O7/O8 artifacts required")
    reviews = (permission_review, o7_review, o8_review)
    if not all(isinstance(value, Mapping) for value in reviews):
        _refuse("detached independent review evidence required")
    permission = copy.deepcopy(dict(permission))
    o7 = copy.deepcopy(dict(o7))
    o8 = copy.deepcopy(dict(o8))
    recovery.validate_authority_bundle(plan, permission=permission, o7=o7, o8=o8, now=now)
    if execution_source_digest is not None:
        for authority in (permission, o7, o8):
            if authority.get("executionSourceDigest") != execution_source_digest:
                _refuse("reviewed executor source binding differs")
    authorities = (permission, o7, o8)
    reviewers: set[str] = set()
    for authority, review in zip(authorities, reviews, strict=True):
        evidence = copy.deepcopy(dict(review))
        if set(evidence) != {
            "kind", "authorityKind", "authorityDigest", "reviewerIdentity",
            "decision", "reviewedAt", "evidenceDigest",
        }:
            _refuse("independent review evidence shape differs")
        if evidence["kind"] != REVIEW_EVIDENCE_KIND:
            _refuse("independent review evidence kind differs")
        if evidence["authorityKind"] != authority["kind"] or evidence["authorityDigest"] != digest(authority):
            _refuse("independent review evidence binding differs")
        reviewer = evidence["reviewerIdentity"]
        if not isinstance(reviewer, str) or not reviewer.strip() or len(reviewer) > 256 or reviewer in reviewers:
            _refuse("independent review identity differs")
        reviewers.add(reviewer)
        if evidence["decision"] != "approved":
            _refuse("independent review decision differs")
        recovery._finite(evidence["reviewedAt"], "review evidence time")
        if evidence["reviewedAt"] > now:
            _refuse("independent review evidence is not current")
        unsigned = {key: value for key, value in evidence.items() if key != "evidenceDigest"}
        if evidence["evidenceDigest"] != digest(unsigned):
            _refuse("independent review evidence digest differs")
    return permission, o7, o8, tuple(copy.deepcopy(dict(value)) for value in reviews)


def _reject_secret_keys(value: Any) -> None:
    if isinstance(value, Mapping):
        if SECRET_KEYS.intersection(value):
            _refuse("secret-bearing recovery artifact refused")
        for child in value.values():
            _reject_secret_keys(child)
    elif isinstance(value, list):
        for child in value:
            _reject_secret_keys(child)


def _compile_context(
    parent: Mapping[str, Any],
    *,
    ledger: Any,
    provenance: Mapping[str, Any],
    source_root: Path,
    execution_source_root: Path,
    recovery_nonce: str | None,
    now: float | None,
    deadline_seconds: int,
    draft: Mapping[str, Any] | None = None,
    assembly_now: float | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    canonical_parent, ledger_state = _reconstruct_parent(parent, ledger)
    parent_snapshot = recovery._parent_snapshot(canonical_parent)
    execution_source = _execution_source(execution_source_root)
    _verify_fixed_source(
        provenance,
        source_root,
        parent_snapshot["sourceCommit"],
        parent_snapshot["generation"],
    )
    if draft is not None:
        if draft.get("kind") != "auth-packet05-recovery-review-draft-v1" or draft.get("campaignId") != recovery.CAMPAIGN:
            _refuse("persisted recovery draft required")
        if draft.get("productionExecuted") is not False or draft.get("productionAllowed") is not False or draft.get("ledgerMutated") is not False:
            _refuse("persisted recovery draft execution flags differ")
        if draft.get("immutableParent") != canonical_parent["immutableParent"] or draft.get("parentEvidence") != parent_snapshot["evidence"]:
            _refuse("persisted recovery draft parent binding differs")
        if draft.get("executionSource") != execution_source:
            _refuse("persisted recovery draft execution source differs")
        review_request = draft.get("reviewRequest")
        plan = draft.get("plan")
        if not isinstance(review_request, Mapping) or not isinstance(plan, Mapping):
            _refuse("persisted recovery draft plan required")
        if (
            review_request.get("planDigest") != plan.get("planDigest")
            or review_request.get("parentEvidenceDigest") != parent_snapshot["evidence"]["evidenceDigest"]
            or review_request.get("executionSourceDigest") != digest(execution_source)
        ):
            _refuse("persisted recovery draft digest differs")
        parent_binding = plan.get("parent")
        canonical_claim = canonical_parent["claim"]
        canonical_claim_digest = canonical_claim.get("claimDigest", digest(canonical_claim))
        if (
            not isinstance(parent_binding, Mapping)
            or parent_binding.get("ticketDigest") != digest(canonical_parent["ticket"])
            or parent_binding.get("claimDigest") != canonical_claim_digest
        ):
            _refuse("persisted recovery draft parent ticket or claim differs")
        if recovery_nonce is not None and recovery_nonce != plan.get("recoveryNonce"):
            _refuse("persisted recovery draft nonce differs")
        draft_now = assembly_now if assembly_now is not None else now
        if draft_now is None:
            draft_now = time.time()
        recovery._finite(draft_now, "draft assembly time")
        if draft_now < plan.get("issuedAt", draft_now):
            _refuse("persisted recovery draft is from the future")
        if draft_now >= plan.get("deadlineAt", draft_now):
            _refuse("persisted recovery draft expired")
        normalized_provenance = recovery._provenance(provenance)
        if normalized_provenance != plan.get("provenance"):
            _refuse("persisted recovery draft source binding differs")
        nonce = plan.get("recoveryNonce")
        recovery._nonce(nonce, "recovery")
        _assert_fresh_nonce(ledger, nonce, ledger_state)
        recovery.validate_plan(plan, canonical_parent)
        return canonical_parent, parent_snapshot, copy.deepcopy(dict(plan)), execution_source
    nonce = secrets.token_hex(16) if recovery_nonce is None else recovery_nonce
    recovery._nonce(nonce, "recovery")
    _assert_fresh_nonce(ledger, nonce, ledger_state)
    plan = recovery.compile_recovery_plan(
        canonical_parent,
        recovery_nonce=nonce,
        provenance=provenance,
        now=now,
        deadline_seconds=deadline_seconds,
    )
    return canonical_parent, parent_snapshot, plan, execution_source


def prepare_review_draft(
    parent: Mapping[str, Any],
    *,
    ledger: Any,
    provenance: Mapping[str, Any],
    source_root: Path,
    execution_source_root: Path,
    recovery_nonce: str | None = None,
    now: float | None = None,
    deadline_seconds: int = recovery.MAX_DEADLINE_SECONDS,
) -> dict[str, Any]:
    """Create a review request without fabricating permission or approvals."""
    try:
        canonical_parent, parent_snapshot, plan, execution_source = _compile_context(
            parent,
            ledger=ledger,
            provenance=provenance,
            source_root=source_root,
            execution_source_root=execution_source_root,
            recovery_nonce=recovery_nonce,
            now=now,
            deadline_seconds=deadline_seconds,
        )
    except recovery.RecoveryRefusal:
        raise
    except (AttributeError, IndexError, KeyError, TypeError, ValueError) as error:
        raise recovery.RecoveryRefusal(f"malformed Auth packet05 parent ({type(error).__name__})") from None
    draft = {
        "kind": "auth-packet05-recovery-review-draft-v1",
        "campaignId": recovery.CAMPAIGN,
        "productionExecuted": False,
        "productionAllowed": False,
        "ledgerMutated": False,
        "reviewRequest": _review_request(plan, parent_snapshot, digest(execution_source)),
        "immutableParent": copy.deepcopy(dict(canonical_parent["immutableParent"])),
        "parentEvidence": copy.deepcopy(parent_snapshot["evidence"]),
        "plan": plan,
        "executionSource": execution_source,
    }
    _reject_secret_keys(draft)
    return draft


def prepare_packet(
    parent: Mapping[str, Any],
    *,
    ledger: Any,
    provenance: Mapping[str, Any],
    source_root: Path,
    execution_source_root: Path,
    permission: Mapping[str, Any] | None,
    o7: Mapping[str, Any] | None,
    o8: Mapping[str, Any] | None,
    permission_review: Mapping[str, Any] | None = None,
    o7_review: Mapping[str, Any] | None = None,
    o8_review: Mapping[str, Any] | None = None,
    draft: Mapping[str, Any] | None = None,
    recovery_nonce: str | None = None,
    now: float | None = None,
    authority_now: float | None = None,
    deadline_seconds: int = recovery.MAX_DEADLINE_SECONDS,
) -> dict[str, Any]:
    """Compile detached recovery authorities without changing the Ledger."""
    try:
        canonical_parent, parent_snapshot, plan, execution_source = _compile_context(
            parent,
            ledger=ledger,
            provenance=provenance,
            source_root=source_root,
            execution_source_root=execution_source_root,
            recovery_nonce=recovery_nonce,
            now=now,
            deadline_seconds=deadline_seconds,
            draft=draft,
            assembly_now=authority_now,
        )
        permission, o7, o8, reviews = _validate_reviewed_authorities(
            plan,
            permission,
            o7,
            o8,
            permission_review,
            o7_review,
            o8_review,
            now=time.time() if authority_now is None else authority_now,
            execution_source_digest=digest(execution_source),
        )
        review_request = _review_request(plan, parent_snapshot, digest(execution_source))
    except recovery.RecoveryRefusal:
        raise
    except (AttributeError, IndexError, KeyError, TypeError, ValueError) as error:
        raise recovery.RecoveryRefusal(
            f"malformed Auth packet05 parent ({type(error).__name__})"
        ) from None
    bundle = {
        "kind": PACKET_KIND,
        "campaignId": recovery.CAMPAIGN,
        "productionExecuted": False,
        "productionAllowed": False,
        "ledgerMutated": False,
        "reviewRequest": review_request,
        "immutableParent": copy.deepcopy(dict(canonical_parent["immutableParent"])),
        "parentEvidence": copy.deepcopy(parent_snapshot["evidence"]),
        "plan": plan,
        "permission": permission,
        "o7": o7,
        "o8": o8,
        "permissionReview": reviews[0],
        "o7Review": reviews[1],
        "o8Review": reviews[2],
        "executionSource": execution_source,
    }
    _reject_secret_keys(bundle)
    return bundle


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    payload = (
        json.dumps(
            value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False
        ).encode()
        + b"\n"
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def write_packet(bundle: Mapping[str, Any], output: Path) -> Path:
    """Write a new private preparation directory and no parent/ledger state."""
    if not isinstance(bundle, Mapping) or bundle.get("kind") != PACKET_KIND:
        _refuse("Auth packet05 preparation bundle required")
    _reject_secret_keys(bundle)
    destination = output.resolve()
    if destination.exists():
        _refuse("new recovery output directory required")
    destination.mkdir(mode=0o700, parents=False)
    files = {
        "packet.json": dict(bundle),
        "review-request.json": bundle["reviewRequest"],
        "plan.json": bundle["plan"],
        "permission.json": bundle["permission"],
        "o7.json": bundle["o7"],
        "o8.json": bundle["o8"],
        "permission-review.json": bundle["permissionReview"],
        "o7-review.json": bundle["o7Review"],
        "o8-review.json": bundle["o8Review"],
        "parent-evidence.json": {
            "immutableParent": bundle["immutableParent"],
            "parentEvidence": bundle["parentEvidence"],
        },
    }
    try:
        for name in ARTIFACT_NAMES:
            _write_json(destination / name, files[name])
    except Exception:
        for path in destination.iterdir():
            path.unlink()
        destination.rmdir()
        raise
    return destination


def write_review_draft(draft: Mapping[str, Any], output: Path) -> Path:
    if not isinstance(draft, Mapping) or draft.get("kind") != "auth-packet05-recovery-review-draft-v1":
        _refuse("Auth packet05 review draft required")
    _reject_secret_keys(draft)
    destination = output.resolve()
    if destination.exists():
        _refuse("new recovery output directory required")
    destination.mkdir(mode=0o700, parents=False)
    files = {
        "draft.json": dict(draft),
        "review-request.json": draft["reviewRequest"],
        "plan.json": draft["plan"],
        "parent-evidence.json": {
            "immutableParent": draft["immutableParent"],
            "parentEvidence": draft["parentEvidence"],
        },
    }
    try:
        for name, value in files.items():
            _write_json(destination / name, value)
    except Exception:
        for path in destination.iterdir():
            path.unlink()
        destination.rmdir()
        raise
    return destination


def _assert_output_detached(output: Path, ledger: Any) -> None:
    ledger_path = getattr(ledger, "path", None)
    if not isinstance(ledger_path, Path):
        _refuse("canonical Ledger path required")
    destination = output.resolve()
    canonical = ledger_path.resolve()
    if destination == canonical or canonical in destination.parents:
        _refuse("recovery output must be outside canonical Ledger")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prepare an offline, secret-free Auth packet05 recovery bundle."
    )
    parser.add_argument(
        "--parent", type=Path, required=True, help="held packet05 parent evidence JSON"
    )
    parser.add_argument(
        "--provenance",
        type=Path,
        required=True,
        help="source-bound recovery provenance JSON",
    )
    parser.add_argument(
        "--ledger",
        type=Path,
        required=True,
        help="canonical shared Ledger root (read-only)",
    )
    parser.add_argument(
        "--source",
        type=Path,
        required=True,
        help="clean checkout at the immutable parent sourceCommit",
    )
    parser.add_argument(
        "--execution-source",
        type=Path,
        required=True,
        help="clean checkout for the reviewed executor runtime closure",
    )
    parser.add_argument("--permission", type=Path, help="separately reviewed permission JSON")
    parser.add_argument("--o7", type=Path, help="separately reviewed O7 approval JSON")
    parser.add_argument("--o8", type=Path, help="separately reviewed O8 capability JSON")
    parser.add_argument("--permission-review", type=Path, help="detached permission review evidence JSON")
    parser.add_argument("--o7-review", type=Path, help="detached O7 review evidence JSON")
    parser.add_argument("--o8-review", type=Path, help="detached O8 review evidence JSON")
    parser.add_argument("--draft", type=Path, help="persisted packet05 review draft JSON")
    parser.add_argument("--draft-only", action="store_true", help="write a review draft without authority artifacts")
    parser.add_argument(
        "--output", type=Path, required=True, help="new private preparation directory"
    )
    parser.add_argument(
        "--recovery-nonce",
        help="fresh 32-hex nonce; omitted generates one from the OS CSPRNG",
    )
    parser.add_argument(
        "--deadline-seconds", type=int, default=recovery.MAX_DEADLINE_SECONDS
    )
    parser.add_argument(
        "--now", type=float, help="issue time for deterministic offline rehearsal"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        ledger = reservations.Ledger(args.ledger)
        _assert_output_detached(args.output, ledger)
        if args.draft_only:
            if any((args.permission, args.o7, args.o8, args.permission_review, args.o7_review, args.o8_review, args.draft)):
                _refuse("draft-only cannot consume reviewed authority artifacts")
            draft = prepare_review_draft(
                _read_json(args.parent),
                ledger=ledger,
                provenance=_read_json(args.provenance),
                source_root=args.source,
                execution_source_root=args.execution_source,
                recovery_nonce=args.recovery_nonce,
                now=args.now,
                deadline_seconds=args.deadline_seconds,
            )
            output = write_review_draft(draft, args.output)
            print(f"AUTH-CREDENTIAL packet05 review draft prepared offline at {output}.")
            return 0
        bundle = prepare_packet(
            _read_json(args.parent),
            ledger=ledger,
            provenance=_read_json(args.provenance),
            source_root=args.source,
            execution_source_root=args.execution_source,
            permission=_read_json(args.permission) if args.permission else None,
            o7=_read_json(args.o7) if args.o7 else None,
            o8=_read_json(args.o8) if args.o8 else None,
            permission_review=_read_json(args.permission_review) if args.permission_review else None,
            o7_review=_read_json(args.o7_review) if args.o7_review else None,
            o8_review=_read_json(args.o8_review) if args.o8_review else None,
            draft=_read_json(args.draft) if args.draft else None,
            recovery_nonce=args.recovery_nonce,
            now=args.now,
            authority_now=time.time(),
            deadline_seconds=args.deadline_seconds,
        )
        output = write_packet(bundle, args.output)
    except SystemExit:
        raise
    except Exception as error:  # noqa: BLE001 -- public output must remain secret-free.
        print(
            f"AUTH-CREDENTIAL packet05 recovery refused ({type(error).__name__}).",
            file=sys.stderr,
        )
        return 2
    print(
        f"AUTH-CREDENTIAL packet05 recovery prepared offline at {output} (no production request sent)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "PACKET_KIND",
    "REVIEW_REQUEST_KIND",
    "build_parser",
    "main",
    "prepare_packet",
    "prepare_review_draft",
    "write_packet",
    "write_review_draft",
]
