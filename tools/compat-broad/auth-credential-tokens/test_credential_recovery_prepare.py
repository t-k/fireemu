"""Offline tests for the Auth packet05 recovery preparation boundary."""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import credential_gate
import credential_recovery as recovery
import credential_recovery_prepare as prepare
import credential_recovery_runner as runner
import credential_recovery_executor as executor
from broad_contract import digest
from test_credential_recovery import _authorities, _parent, _provenance


EXECUTION_CLOSURE = tuple(executor.RUNTIME_CLOSURE)


def _execution_source(tmp_path: Path) -> tuple[Path, dict]:
    source_root = tmp_path / "executor-source"
    for relative in EXECUTION_CLOSURE:
        destination = source_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(HERE.parents[2] / relative, destination)
    subprocess.run(["git", "-C", str(source_root), "init", "-q"], check=True)
    subprocess.run(
        ["git", "-C", str(source_root), "config", "user.email", "test@example.invalid"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(source_root), "config", "user.name", "Auth test"],
        check=True,
    )
    subprocess.run(["git", "-C", str(source_root), "add", "tools"], check=True)
    subprocess.run(
        ["git", "-C", str(source_root), "commit", "-qm", "runtime closure"],
        check=True,
    )
    commit = subprocess.check_output(
        ["git", "-C", str(source_root), "rev-parse", "HEAD"], text=True
    ).strip()
    source_inputs = {
        relative: hashlib.sha256((source_root / relative).read_bytes()).hexdigest()
        for relative in EXECUTION_CLOSURE
    }
    return source_root, {
        "kind": executor.EXECUTION_SOURCE_KIND,
        "sourceCommit": commit,
        "sourceInputs": source_inputs,
        "sourceInputsDigest": digest(source_inputs),
    }


class _ReadOnlyLedger:
    def __init__(self, parent: dict, *, used_nonce: str | None = None, canonical_gate: dict | None = None) -> None:
        self.path = Path("/private/ledger").resolve()
        self.identity = "l" * 64
        self.parent = copy.deepcopy(parent)
        self.used_nonce = used_nonce
        self.canonical_gate = copy.deepcopy(canonical_gate or parent["gate"])
        self.calls: list[str] = []

    def bound_claim(self, ticket: dict) -> dict:
        self.calls.append("bound_claim")
        assert ticket == self.parent["ticket"]
        return copy.deepcopy(self.parent["claim"])

    def bound_gate(self, ticket: dict) -> dict:
        self.calls.append("bound_gate")
        assert ticket == self.parent["ticket"]
        return copy.deepcopy(self.canonical_gate)

    def snapshot(self) -> dict:
        self.calls.append("snapshot")
        rows = {}
        if self.used_nonce is not None:
            rows["prior"] = {
                "claim": {
                    "campaignId": recovery.CAMPAIGN,
                    "nonceDigest": digest(self.used_nonce),
                },
                "recoveryChildren": [],
            }
        rows[self.parent["ticket"]["reservation"]] = {
            "claim": copy.deepcopy(self.parent["claim"]),
            "claimDigest": digest(self.parent["claim"]),
            "state": "held",
            "generation": copy.deepcopy(self.parent["generation"]),
        }
        return {"identity": self.identity, "reservations": rows}


def _ledger_parent() -> dict:
    parent = _parent()
    claim = {
        key: value for key, value in parent["claim"].items() if key != "claimDigest"
    }
    parent["claim"] = {**claim, "claimDigest": digest(claim)}
    return parent


def _real_signing_parent() -> dict:
    parent = _ledger_parent()
    nonce = parent["gate"]["plan"]["nonce"]
    gate_plan = credential_gate.gate_plan(
        recovery.PROJECT,
        nonce,
        signing=True,
        wall_seconds=600,
        recovery_seconds=60,
        cost_microusd=100,
        observation_window_seconds=540,
    )
    custom_index = next(
        index
        for index, operation in enumerate(gate_plan["jobs"][credential_gate.JOB]["observation"])
        if operation.get("kind") == "custom-sign-in" and operation.get("account") == "custom"
    )
    operation = gate_plan["jobs"][credential_gate.JOB]["observation"][custom_index]
    operation["binds"] = {
        "customUid": "idToken.sub",
        "customIdToken": "idToken",
        "customRefresh": "refreshToken",
    }
    parent["gate"]["plan"] = gate_plan
    parent["gate"]["planDigest"] = digest(gate_plan)
    parent["gate"]["events"] = [{
        "job": credential_gate.JOB,
        "phase": "observation",
        "index": custom_index,
        "requestDigest": digest(operation),
        "service": operation["service"],
        "method": operation["method"],
        "completed": False,
        "creationOutcome": "unknown",
        "ended": 999.0,
    }]
    parent["claim"]["gatePlanDigest"] = digest(gate_plan)
    parent["immutableParent"].update(
        gateDigest=digest(parent["gate"]),
        gatePlanDigest=digest(gate_plan),
        resource=operation["resource"],
        eventIndex=custom_index,
        requestDigest=digest(operation),
    )
    return parent


def _source_inputs(
    tmp_path: Path, parent: dict, *, include_execution_closure: bool = True
) -> tuple[Path, dict]:
    source_root = tmp_path / "clean-source"
    for relative in {
        recovery.WORKER_ENTRY,
        recovery.TRANSPORT_ENTRY,
        recovery.LAUNCHER_ENTRY,
        "tools/compat-broad/auth-credential-tokens/credential_recovery.py",
    }:
        destination = source_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(HERE.parents[2] / relative, destination)
    if include_execution_closure:
        for relative in EXECUTION_CLOSURE:
            destination = source_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(HERE.parents[2] / relative, destination)
    subprocess.run(["git", "-C", str(source_root), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(source_root), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(source_root), "config", "user.name", "Auth test"], check=True)
    subprocess.run(["git", "-C", str(source_root), "add", "tools"], check=True)
    subprocess.run(["git", "-C", str(source_root), "commit", "-qm", "source"], check=True)
    commit = subprocess.check_output(["git", "-C", str(source_root), "rev-parse", "HEAD"], text=True).strip()
    source_inputs = {}
    for relative in (
        recovery.WORKER_ENTRY,
        recovery.TRANSPORT_ENTRY,
        recovery.LAUNCHER_ENTRY,
        "tools/compat-broad/auth-credential-tokens/credential_recovery.py",
    ):
        source_inputs[relative] = hashlib.sha256((source_root / relative).read_bytes()).hexdigest()
    parent["generation"]["sourceDigests"] = {
        "worker.py": source_inputs[recovery.WORKER_ENTRY],
        "transport.py": source_inputs[recovery.TRANSPORT_ENTRY],
    }
    parent["immutableParent"]["sourceCommit"] = commit
    parent["generation"]["sourceCommit"] = commit
    provenance = _provenance()
    provenance["sourceCommit"] = commit
    provenance["sourceInputs"] = source_inputs
    for key, relative in (("worker", recovery.WORKER_ENTRY), ("transport", recovery.TRANSPORT_ENTRY), ("launcher", recovery.LAUNCHER_ENTRY)):
        provenance[key]["sha256"] = source_inputs[relative]
    provenance["generation"]["sourceCommit"] = commit
    recovery_digest = hashlib.sha256((source_root / "tools/compat-broad/auth-credential-tokens/credential_recovery.py").read_bytes()).hexdigest()
    provenance["generation"]["sourceDigests"] = {
        "worker.py": source_inputs[recovery.WORKER_ENTRY],
        "transport.py": source_inputs[recovery.TRANSPORT_ENTRY],
        "recovery.py": recovery_digest,
    }
    provenance["generationPaths"] = {
        "worker.py": recovery.WORKER_ENTRY,
        "transport.py": recovery.TRANSPORT_ENTRY,
        "recovery.py": "tools/compat-broad/auth-credential-tokens/credential_recovery.py",
    }
    provenance["generation"]["collectorSourceDigest"] = recovery_digest
    return source_root, provenance


def _reviewed(
    parent: dict, provenance: dict, execution_source_root: Path | None = None
) -> tuple[dict, dict, dict]:
    plan = recovery.compile_recovery_plan(
        parent,
        recovery_nonce="fedcba9876543210fedcba9876543210",
        provenance=provenance,
        now=1000.0,
    )
    authorities = _authorities(plan)
    if execution_source_root is not None:
        source_digest = digest(prepare._execution_source(execution_source_root))
        for authority in authorities:
            authority["executionSourceDigest"] = source_digest
        permission, o7, o8 = authorities
        o7["permissionDigest"] = digest(permission)
        o8["permissionDigest"] = digest(permission)
    return authorities


def _bind_execution_source(
    authorities: tuple[dict, dict, dict], execution_source_root: Path
) -> tuple[dict, dict, dict]:
    source_digest = digest(prepare._execution_source(execution_source_root))
    for authority in authorities:
        authority["executionSourceDigest"] = source_digest
    permission, o7, o8 = authorities
    o7["permissionDigest"] = digest(permission)
    o8["permissionDigest"] = digest(permission)
    return authorities


def _review_evidence(authority: dict, reviewer: str) -> dict:
    evidence = {
        "kind": "auth-packet05-independent-review-evidence-v1",
        "authorityKind": authority["kind"],
        "authorityDigest": digest(authority),
        "reviewerIdentity": reviewer,
        "decision": "approved",
        "reviewedAt": 1000.5,
    }
    evidence["evidenceDigest"] = digest(evidence)
    return evidence


def _reviews(permission: dict, o7: dict, o8: dict) -> tuple[dict, dict, dict]:
    return (
        _review_evidence(permission, "permission-reviewer@example.invalid"),
        _review_evidence(o7, "o7-reviewer@example.invalid"),
        _review_evidence(o8, "o8-reviewer@example.invalid"),
    )


def test_preparation_compiles_fresh_authority_bundle_without_mutating_ledger(tmp_path: Path) -> None:
    parent = _ledger_parent()
    source_root, provenance = _source_inputs(tmp_path, parent)
    permission, o7, o8 = _reviewed(parent, provenance, source_root)
    permission_review, o7_review, o8_review = _reviews(permission, o7, o8)
    ledger = _ReadOnlyLedger(parent)
    before = copy.deepcopy(ledger.snapshot())

    bundle = prepare.prepare_packet(
        parent,
        ledger=ledger,
        provenance=provenance,
        source_root=source_root,
        execution_source_root=source_root,
        permission=permission,
        o7=o7,
        o8=o8,
        recovery_nonce="fedcba9876543210fedcba9876543210",
        now=1000.0,
        authority_now=1001.0,
        permission_review=permission_review,
        o7_review=o7_review,
        o8_review=o8_review,
    )

    assert bundle["kind"] == prepare.PACKET_KIND
    assert bundle["productionExecuted"] is False
    assert bundle["productionAllowed"] is False
    assert bundle["reviewRequest"]["reviewedArtifactsRequired"] is True
    assert bundle["parentEvidence"] == recovery._parent_snapshot(parent)["evidence"]
    assert (
        bundle["immutableParent"]["sourceCommit"]
        == parent["immutableParent"]["sourceCommit"]
    )
    assert bundle["plan"]["recoveryNonce"] != parent["immutableParent"]["nonce"]
    recovery.validate_authority_bundle(
        bundle["plan"],
        permission=bundle["permission"],
        o7=bundle["o7"],
        o8=bundle["o8"],
        now=1001.0,
    )
    assert "idToken" not in json.dumps(bundle)
    assert "refreshToken" not in json.dumps(bundle)
    assert ledger.snapshot() == before
    assert ledger.calls.count("bound_claim") == 1
    assert ledger.calls.count("snapshot") == 3


def test_preparation_requires_separately_reviewed_authority_documents(tmp_path: Path) -> None:
    parent = _ledger_parent()
    source_root, provenance = _source_inputs(tmp_path, parent)

    with pytest.raises(recovery.RecoveryRefusal, match="reviewed|authority"):
        prepare.prepare_packet(
            parent,
            ledger=_ReadOnlyLedger(parent),
            provenance=provenance,
            source_root=source_root,
        execution_source_root=source_root,
            recovery_nonce="fedcba9876543210fedcba9876543210",
            now=1000.0,
            permission=None,
            o7=None,
            o8=None,
        )


def test_preparation_refuses_authority_without_detached_review_evidence(tmp_path: Path) -> None:
    parent = _ledger_parent()
    source_root, provenance = _source_inputs(tmp_path, parent)
    permission, o7, o8 = _reviewed(parent, provenance, source_root)

    with pytest.raises(recovery.RecoveryRefusal, match="review evidence"):
        prepare.prepare_packet(
            parent,
            ledger=_ReadOnlyLedger(parent),
            provenance=provenance,
            source_root=source_root,
        execution_source_root=source_root,
            permission=permission,
            o7=o7,
            o8=o8,
            recovery_nonce="fedcba9876543210fedcba9876543210",
            now=1000.0,
            authority_now=1001.0,
        )


def test_preparation_derives_source_closure_from_canonical_parent(tmp_path: Path) -> None:
    parent = _ledger_parent()
    source_root, provenance = _source_inputs(tmp_path, parent)
    source_digests = parent["generation"]["sourceDigests"]
    renamed = {"auth-worker": source_digests["worker.py"], "auth-transport": source_digests["transport.py"]}
    parent["generation"]["sourceDigests"] = renamed
    provenance["generation"]["sourceDigests"] = {
        **renamed,
        "recovery.py": provenance["generation"]["sourceDigests"]["recovery.py"],
    }
    provenance["generationPaths"] = {
        "auth-worker": recovery.WORKER_ENTRY,
        "auth-transport": recovery.TRANSPORT_ENTRY,
        "recovery.py": "tools/compat-broad/auth-credential-tokens/credential_recovery.py",
    }
    permission, o7, o8 = _reviewed(parent, provenance, source_root)
    permission_review, o7_review, o8_review = _reviews(permission, o7, o8)

    bundle = prepare.prepare_packet(
        parent,
        ledger=_ReadOnlyLedger(parent),
        provenance=provenance,
        source_root=source_root,
        execution_source_root=source_root,
        permission=permission,
        o7=o7,
        o8=o8,
        permission_review=permission_review,
        o7_review=o7_review,
        o8_review=o8_review,
        recovery_nonce="fedcba9876543210fedcba9876543210",
        now=1000.0,
        authority_now=1001.0,
    )
    assert bundle["plan"]["provenance"]["generation"]["sourceDigests"] == provenance["generation"]["sourceDigests"]


def test_review_draft_is_available_before_separate_authority_review(tmp_path: Path) -> None:
    parent = _ledger_parent()
    source_root, provenance = _source_inputs(tmp_path, parent)

    draft = prepare.prepare_review_draft(
        parent,
        ledger=_ReadOnlyLedger(parent),
        provenance=provenance,
        source_root=source_root,
        execution_source_root=source_root,
        recovery_nonce="fedcba9876543210fedcba9876543210",
        now=1000.0,
    )

    assert draft["reviewRequest"]["reviewedArtifactsRequired"] is True
    assert "permission" not in draft
    assert "o7" not in draft
    assert "o8" not in draft
    output = prepare.write_review_draft(draft, tmp_path / "draft")
    assert (output / "review-request.json").is_file()


def test_review_draft_produces_exact_execution_source_and_review_binding(
    tmp_path: Path,
) -> None:
    parent = _ledger_parent()
    source_root, provenance = _source_inputs(tmp_path, parent)
    execution_root, execution_source = _execution_source(tmp_path)

    draft = prepare.prepare_review_draft(
        parent,
        ledger=_ReadOnlyLedger(parent),
        provenance=provenance,
        source_root=source_root,
        execution_source_root=execution_root,
        recovery_nonce="fedcba9876543210fedcba9876543210",
        now=1000.0,
    )

    assert draft["executionSource"] == execution_source
    assert prepare.EXECUTION_SOURCE_CLOSURE == executor.RUNTIME_CLOSURE
    assert set(draft["executionSource"]["sourceInputs"]) == set(EXECUTION_CLOSURE)
    assert draft["reviewRequest"]["executionSourceDigest"] == digest(execution_source)


@pytest.mark.parametrize("mutation", ["dirty", "missing", "symlink"])
def test_execution_source_preflight_refuses_invalid_checkout_before_publication(
    tmp_path: Path, mutation: str,
) -> None:
    parent = _ledger_parent()
    source_root, provenance = _source_inputs(tmp_path, parent)
    execution_root, _execution = _execution_source(tmp_path)
    target = execution_root / EXECUTION_CLOSURE[0]
    if mutation == "dirty":
        target.write_text(target.read_text() + "\n# dirty\n")
    elif mutation == "missing":
        target.unlink()
    else:
        target.unlink()
        target.symlink_to(execution_root / EXECUTION_CLOSURE[1])

    with pytest.raises(recovery.RecoveryRefusal, match="execution source"):
        prepare.prepare_review_draft(
            parent,
            ledger=_ReadOnlyLedger(parent),
            provenance=provenance,
            source_root=source_root,
            execution_source_root=execution_root,
            recovery_nonce="fedcba9876543210fedcba9876543210",
            now=1000.0,
        )
    assert not (tmp_path / "published-packet").exists()


def test_execution_source_rejects_committed_intermediate_symlink(
    tmp_path: Path,
) -> None:
    parent = _ledger_parent()
    source_root, provenance = _source_inputs(tmp_path, parent)
    execution_root, _execution = _execution_source(tmp_path)
    external_tools = tmp_path / "external-tools"
    shutil.copytree(execution_root / "tools", external_tools)
    (execution_root / "tools").rename(execution_root / "tracked-tools")
    (execution_root / "tools").symlink_to(external_tools, target_is_directory=True)
    subprocess.run(["git", "-C", str(execution_root), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(execution_root), "commit", "-qm", "symlinked tree"],
        check=True,
    )

    with pytest.raises(recovery.RecoveryRefusal, match="execution source"):
        prepare.prepare_review_draft(
            parent,
            ledger=_ReadOnlyLedger(parent),
            provenance=provenance,
            source_root=source_root,
            execution_source_root=execution_root,
            recovery_nonce="fedcba9876543210fedcba9876543210",
            now=1000.0,
        )


def test_execution_source_rejects_files_that_differ_from_head_blob(
    tmp_path: Path,
) -> None:
    parent = _ledger_parent()
    source_root, provenance = _source_inputs(tmp_path, parent)
    execution_root, _execution = _execution_source(tmp_path)
    changed = execution_root / EXECUTION_CLOSURE[0]
    changed.write_text(changed.read_text() + "\n# assumed unchanged drift\n")
    subprocess.run(
        [
            "git",
            "-C",
            str(execution_root),
            "update-index",
            "--assume-unchanged",
            EXECUTION_CLOSURE[0],
        ],
        check=True,
    )
    assert subprocess.check_output(
        [
            "git",
            "-C",
            str(execution_root),
            "status",
            "--porcelain",
            "--untracked-files=all",
        ],
        text=True,
    ).strip() == ""

    with pytest.raises(recovery.RecoveryRefusal, match="execution source"):
        prepare.prepare_review_draft(
            parent,
            ledger=_ReadOnlyLedger(parent),
            provenance=provenance,
            source_root=source_root,
            execution_source_root=execution_root,
            recovery_nonce="fedcba9876543210fedcba9876543210",
            now=1000.0,
        )


def test_execution_source_refuses_head_advance_during_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = _ledger_parent()
    source_root, provenance = _source_inputs(tmp_path, parent)
    execution_root, _execution = _execution_source(tmp_path)
    original_check_output = prepare.subprocess.check_output
    advanced = False

    def advance_after_rev_parse(command, *args, **kwargs):
        nonlocal advanced
        result = original_check_output(command, *args, **kwargs)
        if (
            not advanced
            and list(command)
            == ["git", "-C", str(execution_root), "rev-parse", "HEAD"]
        ):
            advanced = True
            changed = execution_root / EXECUTION_CLOSURE[0]
            changed.write_text(changed.read_text() + "\n# commit B\n")
            subprocess.run(["git", "-C", str(execution_root), "add", "tools"], check=True)
            subprocess.run(
                ["git", "-C", str(execution_root), "commit", "-qm", "commit B"],
                check=True,
            )
        return result

    monkeypatch.setattr(prepare.subprocess, "check_output", advance_after_rev_parse)
    with pytest.raises(recovery.RecoveryRefusal, match="capture|execution source"):
        prepare.prepare_review_draft(
            parent,
            ledger=_ReadOnlyLedger(parent),
            provenance=provenance,
            source_root=source_root,
            execution_source_root=execution_root,
            recovery_nonce="fedcba9876543210fedcba9876543210",
            now=1000.0,
        )
    assert advanced is True


@pytest.mark.parametrize("tamper", ["wrong-commit", "extra-key", "map-value"])
def test_persisted_draft_refuses_execution_source_mismatch_before_authority_assembly(
    tmp_path: Path, tamper: str,
) -> None:
    parent = _ledger_parent()
    source_root, provenance = _source_inputs(tmp_path, parent)
    execution_root, _execution = _execution_source(tmp_path)
    draft = prepare.prepare_review_draft(
        parent,
        ledger=_ReadOnlyLedger(parent),
        provenance=provenance,
        source_root=source_root,
        execution_source_root=execution_root,
        recovery_nonce="fedcba9876543210fedcba9876543210",
        now=1000.0,
    )
    if tamper == "wrong-commit":
        draft["executionSource"]["sourceCommit"] = "0" * 40
    elif tamper == "extra-key":
        draft["executionSource"]["sourceInputs"]["extra.py"] = "0" * 64
    else:
        path = EXECUTION_CLOSURE[0]
        draft["executionSource"]["sourceInputs"][path] = "0" * 64

    with pytest.raises(recovery.RecoveryRefusal, match="execution source"):
        prepare.prepare_packet(
            parent,
            ledger=_ReadOnlyLedger(parent),
            provenance=provenance,
            source_root=source_root,
            execution_source_root=execution_root,
            permission=None,
            o7=None,
            o8=None,
            draft=draft,
            now=1001.0,
            authority_now=1001.0,
        )


def test_clean_changed_execution_checkout_refuses_persisted_draft(
    tmp_path: Path,
) -> None:
    parent = _ledger_parent()
    source_root, provenance = _source_inputs(tmp_path, parent)
    execution_root, _execution = _execution_source(tmp_path)
    draft = prepare.prepare_review_draft(
        parent,
        ledger=_ReadOnlyLedger(parent),
        provenance=provenance,
        source_root=source_root,
        execution_source_root=execution_root,
        recovery_nonce="fedcba9876543210fedcba9876543210",
        now=1000.0,
    )
    changed = execution_root / EXECUTION_CLOSURE[0]
    changed.write_text(changed.read_text() + "\n# reviewed source changed\n")
    subprocess.run(["git", "-C", str(execution_root), "add", "tools"], check=True)
    subprocess.run(
        ["git", "-C", str(execution_root), "commit", "-qm", "changed source"],
        check=True,
    )

    with pytest.raises(recovery.RecoveryRefusal, match="execution source"):
        prepare.prepare_packet(
            parent,
            ledger=_ReadOnlyLedger(parent),
            provenance=provenance,
            source_root=source_root,
            execution_source_root=execution_root,
            permission=None,
            o7=None,
            o8=None,
            draft=draft,
            now=1001.0,
            authority_now=1001.0,
        )


def test_reviewed_authorities_must_bind_producer_execution_source(
    tmp_path: Path,
) -> None:
    parent = _ledger_parent()
    source_root, provenance = _source_inputs(tmp_path, parent)
    execution_root, _execution = _execution_source(tmp_path)
    permission, o7, o8 = _reviewed(parent, provenance, execution_root)
    for authority in (permission, o7, o8):
        authority["executionSourceDigest"] = "0" * 64
    o7["permissionDigest"] = digest(permission)
    o8["permissionDigest"] = digest(permission)
    reviews = _reviews(permission, o7, o8)

    with pytest.raises(recovery.RecoveryRefusal, match="executor source"):
        prepare.prepare_packet(
            parent,
            ledger=_ReadOnlyLedger(parent),
            provenance=provenance,
            source_root=source_root,
            execution_source_root=execution_root,
            permission=permission,
            o7=o7,
            o8=o8,
            permission_review=reviews[0],
            o7_review=reviews[1],
            o8_review=reviews[2],
            recovery_nonce="fedcba9876543210fedcba9876543210",
            now=1000.0,
            authority_now=1001.0,
        )


@pytest.mark.parametrize("draft_nonce", [None, "fedcba9876543210fedcba9876543210"])
def test_packet_assembles_from_persisted_draft_without_reissuing_plan_at_later_clock(
    tmp_path: Path, draft_nonce: str | None,
) -> None:
    parent = _ledger_parent()
    source_root, provenance = _source_inputs(tmp_path, parent)
    ledger = _ReadOnlyLedger(parent)
    draft = prepare.prepare_review_draft(
        parent,
        ledger=ledger,
        provenance=provenance,
        source_root=source_root,
        execution_source_root=source_root,
        recovery_nonce=draft_nonce,
        now=1000.0,
    )
    permission, o7, o8 = _bind_execution_source(
        _authorities(draft["plan"]), source_root
    )
    reviews = _reviews(permission, o7, o8)

    packet = prepare.prepare_packet(
        parent,
        ledger=ledger,
        provenance=provenance,
        source_root=source_root,
        execution_source_root=source_root,
        permission=permission,
        o7=o7,
        o8=o8,
        permission_review=reviews[0],
        o7_review=reviews[1],
        o8_review=reviews[2],
        draft=draft,
        now=1001.0,
        authority_now=1001.0,
    )

    assert packet["plan"] == draft["plan"]
    assert packet["plan"]["planDigest"] == draft["plan"]["planDigest"]


def test_persisted_draft_refuses_foreign_nonce_and_source_provenance(tmp_path: Path) -> None:
    parent = _ledger_parent()
    source_root, provenance = _source_inputs(tmp_path, parent)
    draft = prepare.prepare_review_draft(
        parent,
        ledger=_ReadOnlyLedger(parent),
        provenance=provenance,
        source_root=source_root,
        execution_source_root=source_root,
        recovery_nonce="fedcba9876543210fedcba9876543210",
        now=1000.0,
    )
    permission, o7, o8 = _authorities(draft["plan"])
    reviews = _reviews(permission, o7, o8)

    with pytest.raises(recovery.RecoveryRefusal, match="draft|nonce"):
        prepare.prepare_packet(
            parent,
            ledger=_ReadOnlyLedger(parent),
            provenance=provenance,
            source_root=source_root,
            execution_source_root=source_root,
            permission=permission,
            o7=o7,
            o8=o8,
            permission_review=reviews[0],
            o7_review=reviews[1],
            o8_review=reviews[2],
            draft=draft,
            recovery_nonce="0123456789abcdef0123456789abcdef",
            now=1001.0,
            authority_now=1001.0,
        )

    foreign = copy.deepcopy(provenance)
    foreign["sourceCommit"] = "f" * 40
    with pytest.raises(recovery.RecoveryRefusal, match="draft|source"):
        prepare.prepare_packet(
            parent,
            ledger=_ReadOnlyLedger(parent),
            provenance=foreign,
            source_root=source_root,
        execution_source_root=source_root,
            permission=permission,
            o7=o7,
            o8=o8,
            permission_review=reviews[0],
            o7_review=reviews[1],
            o8_review=reviews[2],
            draft=draft,
            now=1001.0,
            authority_now=1001.0,
        )


def test_persisted_draft_refuses_when_assembly_clock_passes_deadline(tmp_path: Path) -> None:
    parent = _ledger_parent()
    source_root, provenance = _source_inputs(tmp_path, parent)
    ledger = _ReadOnlyLedger(parent)
    draft = prepare.prepare_review_draft(
        parent,
        ledger=ledger,
        provenance=provenance,
        source_root=source_root,
        execution_source_root=source_root,
        recovery_nonce="fedcba9876543210fedcba9876543210",
        now=1000.0,
    )
    permission, o7, o8 = _authorities(draft["plan"])
    permission_review, o7_review, o8_review = _reviews(permission, o7, o8)

    with pytest.raises(recovery.RecoveryRefusal, match="expired|deadline"):
        prepare.prepare_packet(
            parent,
            ledger=ledger,
            provenance=provenance,
            source_root=source_root,
        execution_source_root=source_root,
            permission=permission,
            o7=o7,
            o8=o8,
            permission_review=permission_review,
            o7_review=o7_review,
            o8_review=o8_review,
            draft=draft,
            authority_now=1100.0,
        )


def test_persisted_draft_refuses_a_different_canonical_parent_ticket_and_claim(
    tmp_path: Path,
) -> None:
    parent = _ledger_parent()
    source_root, provenance = _source_inputs(tmp_path, parent)
    draft = prepare.prepare_review_draft(
        parent,
        ledger=_ReadOnlyLedger(parent),
        provenance=provenance,
        source_root=source_root,
        execution_source_root=source_root,
        recovery_nonce="fedcba9876543210fedcba9876543210",
        now=1000.0,
    )
    permission, o7, o8 = _authorities(draft["plan"])
    permission_review, o7_review, o8_review = _reviews(permission, o7, o8)
    foreign = copy.deepcopy(parent)
    foreign["ticket"]["reservation"] = "different-reservation"
    foreign["claim"]["durationSeconds"] = 300
    foreign["claim"]["claimDigest"] = digest(
        {key: value for key, value in foreign["claim"].items() if key != "claimDigest"}
    )

    with pytest.raises(recovery.RecoveryRefusal, match="parent|ticket|claim"):
        prepare.prepare_packet(
            foreign,
            ledger=_ReadOnlyLedger(foreign),
            provenance=provenance,
            source_root=source_root,
        execution_source_root=source_root,
            permission=permission,
            o7=o7,
            o8=o8,
            permission_review=permission_review,
            o7_review=o7_review,
            o8_review=o8_review,
            draft=draft,
            now=1001.0,
            authority_now=1001.0,
        )


def test_preparation_refuses_a_nonce_already_present_in_ledger(tmp_path: Path) -> None:
    parent = _ledger_parent()
    source_root, provenance = _source_inputs(tmp_path, parent)
    permission, o7, o8 = _reviewed(parent, provenance, source_root)
    ledger = _ReadOnlyLedger(parent, used_nonce="fedcba9876543210fedcba9876543210")

    with pytest.raises(recovery.RecoveryRefusal, match="fresh|reserved"):
        prepare.prepare_packet(
            parent,
            ledger=ledger,
            provenance=provenance,
            source_root=source_root,
        execution_source_root=source_root,
            permission=permission,
            o7=o7,
            o8=o8,
            recovery_nonce="fedcba9876543210fedcba9876543210",
            now=1000.0,
        )


def test_preparation_rejects_future_reviewed_o7_and_o8(tmp_path: Path) -> None:
    parent = _ledger_parent()
    source_root, provenance = _source_inputs(tmp_path, parent)
    permission, o7, o8 = _reviewed(parent, provenance, source_root)
    o7["issuedAt"] = 1100.0
    o8["issuedAt"] = 1100.0
    permission_review, o7_review, o8_review = _reviews(permission, o7, o8)

    with pytest.raises(recovery.RecoveryRefusal, match="active|issued"):
        prepare.prepare_packet(
            parent,
            ledger=_ReadOnlyLedger(parent),
            provenance=provenance,
            source_root=source_root,
        execution_source_root=source_root,
            permission=permission,
            o7=o7,
            o8=o8,
            recovery_nonce="fedcba9876543210fedcba9876543210",
            now=1000.0,
            authority_now=1001.0,
            permission_review=permission_review,
            o7_review=o7_review,
            o8_review=o8_review,
        )


def test_preparation_refuses_source_checkout_digest_drift(tmp_path: Path) -> None:
    parent = _ledger_parent()
    source_root, provenance = _source_inputs(tmp_path, parent)
    permission, o7, o8 = _reviewed(parent, provenance, source_root)
    (source_root / recovery.WORKER_ENTRY).write_text("drift")

    with pytest.raises(recovery.RecoveryRefusal, match="source checkout|digest"):
        prepare.prepare_packet(
            parent,
            ledger=_ReadOnlyLedger(parent),
            provenance=provenance,
            source_root=source_root,
        execution_source_root=source_root,
            permission=permission,
            o7=o7,
            o8=o8,
            recovery_nonce="fedcba9876543210fedcba9876543210",
            now=1000.0,
            authority_now=1001.0,
        )


def test_preparation_refuses_generation_hash_permutation_and_collector_alias(
    tmp_path: Path,
) -> None:
    parent = _ledger_parent()
    source_root, provenance = _source_inputs(tmp_path, parent)
    worker_digest = provenance["generation"]["sourceDigests"]["worker.py"]
    provenance["generation"]["sourceDigests"]["recovery.py"] = worker_digest
    provenance["generation"]["collectorSourceDigest"] = worker_digest
    permission, o7, o8 = _reviewed(parent, provenance, source_root)
    reviews = _reviews(permission, o7, o8)

    with pytest.raises(recovery.RecoveryRefusal, match="generation|collector"):
        prepare.prepare_packet(
            parent,
            ledger=_ReadOnlyLedger(parent),
            provenance=provenance,
            source_root=source_root,
        execution_source_root=source_root,
            permission=permission,
            o7=o7,
            o8=o8,
            permission_review=reviews[0],
            o7_review=reviews[1],
            o8_review=reviews[2],
            recovery_nonce="fedcba9876543210fedcba9876543210",
            now=1000.0,
            authority_now=1001.0,
        )


def test_preparation_reconstructs_parent_gate_from_canonical_ledger_binding(tmp_path: Path) -> None:
    parent = _ledger_parent()
    canonical_gate = copy.deepcopy(parent["gate"])
    source_root, provenance = _source_inputs(tmp_path, parent)
    tampered = copy.deepcopy(parent)
    tampered["gate"]["plan"]["nonce"] = "f" * 32
    tampered["receipt"] = {"failure": "caller-forged", "postflightComplete": False}
    tampered["responsibility"] = {"custom": {"state": "unknown", "uid": "caller-forged"}}
    tampered["immutableParent"]["sourceCommit"] = "f" * 40
    permission, o7, o8 = _reviewed(parent, provenance, source_root)
    permission_review, o7_review, o8_review = _reviews(permission, o7, o8)

    bundle = prepare.prepare_packet(
        tampered,
        ledger=_ReadOnlyLedger(parent, canonical_gate=canonical_gate),
        provenance=provenance,
        source_root=source_root,
        execution_source_root=source_root,
        permission=permission,
        o7=o7,
        o8=o8,
        permission_review=permission_review,
        o7_review=o7_review,
        o8_review=o8_review,
        recovery_nonce="fedcba9876543210fedcba9876543210",
        now=1000.0,
        authority_now=1001.0,
    )

    assert bundle["parentEvidence"] == recovery._parent_snapshot(parent)["evidence"]


@pytest.mark.parametrize("authority", ["permission", "o7", "o8"])
def test_preparation_refuses_authority_bundle_before_its_issued_at(
    authority: str,
    tmp_path: Path,
) -> None:
    parent = _ledger_parent()
    source_root, provenance = _source_inputs(tmp_path, parent)
    permission, o7, o8 = _reviewed(parent, provenance, source_root)
    plan = recovery.compile_recovery_plan(parent, recovery_nonce="fedcba9876543210fedcba9876543210", provenance=provenance, now=1000.0)

    reviewed = {"permission": permission, "o7": o7, "o8": o8}
    reviewed[authority]["issuedAt"] = 1001.0
    if authority == "permission":
        permission_digest = digest(reviewed["permission"])
        reviewed["o7"]["permissionDigest"] = permission_digest
        reviewed["o8"]["permissionDigest"] = permission_digest
    with pytest.raises(recovery.RecoveryRefusal, match="active|issued|ordering"):
        recovery.validate_authority_bundle(
            plan,
            permission=reviewed["permission"],
            o7=reviewed["o7"],
            o8=reviewed["o8"],
            now=999.0,
        )


def test_preparation_normalizes_malformed_nested_parent_to_secret_free_refusal(tmp_path: Path) -> None:
    parent = _ledger_parent()
    parent["gate"]["jobs"] = None
    source_root, provenance = _source_inputs(tmp_path, parent)

    with pytest.raises(recovery.RecoveryRefusal, match="malformed|parent"):
        prepare.prepare_packet(
            parent,
            ledger=_ReadOnlyLedger(parent),
            provenance=provenance,
            source_root=source_root,
        execution_source_root=source_root,
            permission=None,
            o7=None,
            o8=None,
            recovery_nonce="fedcba9876543210fedcba9876543210",
            now=1000.0,
        )


def test_write_packet_creates_private_redacted_artifacts_without_printing_bundle(
    tmp_path: Path,
) -> None:
    parent = _ledger_parent()
    source_root, provenance = _source_inputs(tmp_path, parent)
    permission, o7, o8 = _reviewed(parent, provenance, source_root)
    permission_review, o7_review, o8_review = _reviews(permission, o7, o8)
    bundle = prepare.prepare_packet(
        parent,
        ledger=_ReadOnlyLedger(parent),
        provenance=provenance,
        source_root=source_root,
        execution_source_root=source_root,
        permission=permission,
        o7=o7,
        o8=o8,
        permission_review=permission_review,
        o7_review=o7_review,
        o8_review=o8_review,
        recovery_nonce="fedcba9876543210fedcba9876543210",
        now=1000.0,
        authority_now=1001.0,
    )
    output = tmp_path / "packet"

    result = prepare.write_packet(bundle, output)

    assert result == output
    assert output.stat().st_mode & 0o077 == 0
    assert {path.name for path in output.iterdir()} == {
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
    }
    packet = json.loads((output / "packet.json").read_text())
    assert packet["productionExecuted"] is False
    assert packet["parentEvidence"] == bundle["parentEvidence"]
    assert "idToken" not in (output / "packet.json").read_text()


def test_preparation_output_cannot_be_created_inside_canonical_ledger(
    tmp_path: Path,
) -> None:
    parent = _ledger_parent()
    ledger = _ReadOnlyLedger(parent)

    with pytest.raises(recovery.RecoveryRefusal, match="outside canonical Ledger"):
        prepare._assert_output_detached(ledger.path / "prepared", ledger)


def test_bounded_runner_emits_no_network_execution_handoff(tmp_path: Path) -> None:
    parent = _ledger_parent()
    source_root, provenance = _source_inputs(tmp_path, parent)
    permission, o7, o8 = _reviewed(parent, provenance, source_root)
    reviews = _reviews(permission, o7, o8)
    packet = prepare.prepare_packet(
        parent,
        ledger=_ReadOnlyLedger(parent),
        provenance=provenance,
        source_root=source_root,
        execution_source_root=source_root,
        permission=permission,
        o7=o7,
        o8=o8,
        permission_review=reviews[0],
        o7_review=reviews[1],
        o8_review=reviews[2],
        recovery_nonce="fedcba9876543210fedcba9876543210",
        now=1000.0,
        authority_now=1001.0,
    )

    request = runner.prepare_execution_request(
        packet,
        parent=parent,
        ledger=_ReadOnlyLedger(parent),
        source_root=source_root,
        now=1001.0,
    )

    assert request["networkAllowed"] is False
    assert request["ledgerMutationAllowed"] is False
    assert request["productionExecuted"] is False
    assert request["requiresSeparateExecutor"] is True
    assert "custom-" not in json.dumps(request)


def test_bounded_runner_refuses_tampered_detached_review_evidence(tmp_path: Path) -> None:
    parent = _ledger_parent()
    source_root, provenance = _source_inputs(tmp_path, parent)
    permission, o7, o8 = _reviewed(parent, provenance, source_root)
    reviews = _reviews(permission, o7, o8)
    packet = prepare.prepare_packet(
        parent,
        ledger=_ReadOnlyLedger(parent),
        provenance=provenance,
        source_root=source_root,
        execution_source_root=source_root,
        permission=permission,
        o7=o7,
        o8=o8,
        permission_review=reviews[0],
        o7_review=reviews[1],
        o8_review=reviews[2],
        recovery_nonce="fedcba9876543210fedcba9876543210",
        now=1000.0,
        authority_now=1001.0,
    )
    packet["o8Review"]["decision"] = "approved"
    packet["o8Review"]["evidenceDigest"] = "0" * 64

    with pytest.raises(recovery.RecoveryRefusal, match="review evidence"):
        runner.prepare_execution_request(
            packet,
            parent=parent,
            ledger=_ReadOnlyLedger(parent),
            source_root=source_root,
            now=1001.0,
        )


def test_prepare_cli_accepts_real_signing_parent_and_full_identity_bindings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = _real_signing_parent()
    source_root, provenance = _source_inputs(tmp_path, parent)
    permission, o7, o8 = _reviewed(parent, provenance, source_root)
    expiry = __import__("time").time() + 3600
    for authority in (permission, o7, o8):
        authority["expiresAt"] = expiry
    o7["permissionDigest"] = digest(permission)
    o8["permissionDigest"] = digest(permission)
    reviews = _reviews(permission, o7, o8)
    paths = {
        "parent": tmp_path / "parent.json",
        "provenance": tmp_path / "provenance.json",
        "permission": tmp_path / "permission.json",
        "o7": tmp_path / "o7.json",
        "o8": tmp_path / "o8.json",
        "permission-review": tmp_path / "permission-review.json",
        "o7-review": tmp_path / "o7-review.json",
        "o8-review": tmp_path / "o8-review.json",
    }
    values = {
        "parent": parent,
        "provenance": provenance,
        "permission": permission,
        "o7": o7,
        "o8": o8,
        "permission-review": reviews[0],
        "o7-review": reviews[1],
        "o8-review": reviews[2],
    }
    for name, path in paths.items():
        path.write_text(json.dumps(values[name]))
    ledger = _ReadOnlyLedger(parent)
    monkeypatch.setattr(prepare.reservations, "Ledger", lambda _path: ledger)
    draft_output = tmp_path / "cli-draft"
    assert prepare.main([
        "--parent", str(paths["parent"]),
        "--provenance", str(paths["provenance"]),
        "--ledger", str(ledger.path),
        "--source", str(source_root),
        "--execution-source", str(source_root),
        "--draft-only",
        "--now", "1000",
        "--output", str(draft_output),
    ]) == 0
    assert (draft_output / "draft.json").is_file()
    output = tmp_path / "cli-output"

    result = prepare.main([
        "--parent", str(paths["parent"]),
        "--provenance", str(paths["provenance"]),
        "--ledger", str(ledger.path),
        "--source", str(source_root),
        "--execution-source", str(source_root),
        "--permission", str(paths["permission"]),
        "--o7", str(paths["o7"]),
        "--o8", str(paths["o8"]),
        "--permission-review", str(paths["permission-review"]),
        "--o7-review", str(paths["o7-review"]),
        "--o8-review", str(paths["o8-review"]),
        "--recovery-nonce", "fedcba9876543210fedcba9876543210",
        "--now", "1000",
        "--output", str(output),
    ])

    assert result == 0
    packet = json.loads((output / "packet.json").read_text())
    assert packet["plan"]["parent"]["eventIndex"] == parent["immutableParent"]["eventIndex"]
    assert packet["immutableParent"]["sourceCommit"] == parent["immutableParent"]["sourceCommit"]
    parent_operation = parent["gate"]["plan"]["jobs"][credential_gate.JOB]["observation"][
        parent["immutableParent"]["eventIndex"]
    ]
    assert packet["plan"]["parent"]["requestDigest"] == digest(parent_operation)
    assert parent_operation["binds"]["customUid"] == "idToken.sub"
