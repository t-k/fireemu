"""Commander-facing Auth recovery executor tests.

These tests deliberately use a deterministic transport callback. The callback
records the one Gate operation but never opens a socket, so the executor's
ordering, private handoff and Ledger settlement rules can be exercised without
production traffic.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import credential_recovery as recovery
import credential_recovery_executor as executor
from broad_contract import digest
from test_credential_recovery_prepare import (
    _ledger_parent,
    _ReadOnlyLedger,
    _real_signing_parent,
    _reviewed,
    _reviews,
    _source_inputs,
)

RUNTIME_CLOSURE = (
    "tools/compat-broad/auth-credential-tokens/credential_recovery_executor.py",
    "tools/compat-broad/auth-credential-tokens/credential_recovery_prepare.py",
    "tools/compat-broad/auth-credential-tokens/credential_recovery.py",
    "tools/compat-broad/auth-credential-tokens/credential_remote_transport.py",
    "tools/compat-broad/shared_gate.py",
    "tools/compat-broad/production-admission/reservations.py",
)


class RecordingLedger(_ReadOnlyLedger):
    """A deterministic Ledger seam that records the child lifecycle calls."""

    def __init__(self, parent: dict) -> None:
        super().__init__(parent)
        self.lifecycle: list[str] = []
        self.child_ticket = {
            "parentReservation": parent["ticket"]["reservation"],
            "reservation": "child-ticket",
        }

    def begin_auth_recovery_extension(self, parent_ticket, child_claim, envelope, gate_plan, **kwargs):
        self.lifecycle.append("begin-child")
        assert parent_ticket == self.parent["ticket"]
        assert child_claim["gatePlanDigest"] == digest(gate_plan)
        return copy.deepcopy(self.child_ticket)

    def settle_auth_recovery_child(self, child_ticket, *, absence_proof, receipt_digest, now=None):
        self.lifecycle.append("settle-child")
        assert child_ticket == self.child_ticket
        assert absence_proof["kind"] == recovery.ABSENCE_KIND
        assert isinstance(receipt_digest, str)
        return copy.deepcopy(child_ticket)

    def close_after_auth_recovery_child(self, parent_ticket, child_ticket, *, receipt_digest, now=None):
        self.lifecycle.append("close-parent")
        assert parent_ticket == self.parent["ticket"]
        assert child_ticket == self.child_ticket
        return {"state": "closed-after-auth-recovery-child"}


def _packet(tmp_path: Path):
    parent = _ledger_parent()
    parent["claim"].pop("claimDigest", None)
    parent["ticket"]["claimDigest"] = digest(parent["claim"])
    source_root, provenance = _source_inputs(tmp_path, parent)
    _extend_runtime_closure(source_root, provenance, parent)
    permission, o7, o8 = _reviewed(parent, provenance)
    permission.update(ownerIdentity="owner@example.com", recoveryOwner="recovery@example.com")
    authority_digest = digest(permission)
    o7["permissionDigest"] = authority_digest
    o8["permissionDigest"] = authority_digest
    reviews = _reviews(permission, o7, o8)
    import credential_recovery_prepare as prepare

    bundle = prepare.prepare_packet(
        parent,
        ledger=RecordingLedger(parent),
        provenance=provenance,
        source_root=source_root,
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
    return parent, source_root, bundle


def _id_token_sub_packet(tmp_path: Path):
    parent = _real_signing_parent()
    parent["claim"].pop("claimDigest", None)
    parent["ticket"]["claimDigest"] = digest(parent["claim"])
    source_root, provenance = _source_inputs(tmp_path, parent)
    _extend_runtime_closure(source_root, provenance, parent)
    permission, o7, o8 = _reviewed(parent, provenance)
    permission.update(ownerIdentity="owner@example.com", recoveryOwner="recovery@example.com")
    authority_digest = digest(permission)
    o7["permissionDigest"] = authority_digest
    o8["permissionDigest"] = authority_digest
    reviews = _reviews(permission, o7, o8)
    import credential_recovery_prepare as prepare

    bundle = prepare.prepare_packet(
        parent,
        ledger=RecordingLedger(parent),
        provenance=provenance,
        source_root=source_root,
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
    return parent, source_root, bundle


def _extend_runtime_closure(source_root: Path, provenance: dict, parent: dict) -> None:
    """Add the executor's reviewed runtime closure to the temporary checkout."""
    for relative in RUNTIME_CLOSURE:
        destination = source_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(HERE.parents[2] / relative, destination)
        provenance.setdefault("sourceInputs", {})[relative] = hashlib.sha256(
            destination.read_bytes()
        ).hexdigest()
    subprocess.run(["git", "-C", str(source_root), "add", "tools"], check=True)
    subprocess.run(["git", "-C", str(source_root), "commit", "-qm", "runtime closure"], check=True)
    commit = subprocess.check_output(
        ["git", "-C", str(source_root), "rev-parse", "HEAD"], text=True
    ).strip()
    parent["generation"]["sourceCommit"] = commit
    parent["immutableParent"]["sourceCommit"] = commit
    provenance["sourceCommit"] = commit
    provenance["generation"]["sourceCommit"] = commit


def _credential_fd(tmp_path: Path) -> int:
    path = tmp_path / "handoff.json"
    path.write_text(json.dumps({"token": "oauth-token", "apiKey": "web-api-key"}))
    path.chmod(0o600)
    return os.open(path, os.O_RDONLY)


def test_executor_registers_child_before_fd_read_and_runs_one_typed_empty_gate_request(
    tmp_path: Path,
) -> None:
    parent, source_root, packet = _packet(tmp_path)
    ledger = RecordingLedger(parent)
    order: list[str] = []
    credential_fd = _credential_fd(tmp_path)

    def read_fd(fd):
        order.append("credential-read")
        return executor.read_private_handoff(fd)

    def transport(operation, body, *, token, api_key, deadline):
        order.append("wire")
        assert token == "oauth-token"
        assert api_key == "web-api-key"
        assert operation["path"].endswith("/projects/fireemu-35fe6/accounts:lookup")
        assert body == {"localId": [packet["plan"]["customUid"]]}
        assert deadline > 0
        return 200, {"kind": "identitytoolkit#GetAccountInfoResponse", "users": []}

    try:
        result = executor.execute_recovery(
            packet,
            parent=parent,
            ledger=ledger,
            source_root=source_root,
            credential_fd=credential_fd,
            gate_path=tmp_path / "child-gate",
            now=1001.0,
            clock=lambda: 1001.0,
            read_handoff=read_fd,
            transport=transport,
        )
    finally:
        os.close(credential_fd)

    assert order == ["credential-read", "wire"]
    assert ledger.lifecycle == ["begin-child", "settle-child", "close-parent"]
    assert result["disposition"] == "typed-empty"
    assert result["lookupCount"] == 1
    assert "oauth-token" not in repr(result)
    assert "web-api-key" not in repr(result)
    state = json.loads((tmp_path / "child-gate" / "state.json").read_text())
    job = state["jobs"][recovery.GATE_JOB]
    assert job["complete"] is True
    assert job["recovery"] == 1
    assert state["coordinatorInflight"] is False
    assert not [event for event in state["events"] if event.get("skipped")]


def test_executor_reconstructs_the_real_signing_compiler_id_token_sub_parent(
    tmp_path: Path,
) -> None:
    parent, source_root, packet = _id_token_sub_packet(tmp_path)
    ledger = RecordingLedger(parent)
    credential_fd = _credential_fd(tmp_path)
    try:
        result = executor.execute_recovery(
            packet,
            parent=parent,
            ledger=ledger,
            source_root=source_root,
            credential_fd=credential_fd,
            gate_path=tmp_path / "child-gate",
            now=1001.0,
            clock=lambda: 1001.0,
            transport=lambda *_args, **_kwargs: (
                200,
                {"kind": "identitytoolkit#GetAccountInfoResponse", "users": []},
            ),
        )
    finally:
        os.close(credential_fd)
    assert result["disposition"] == "typed-empty"
    assert packet["plan"]["parent"]["requestDigest"] == digest(
        parent["gate"]["plan"]["jobs"]["auth-credential"]["observation"][
            parent["immutableParent"]["eventIndex"]
        ]
    )


def test_absolute_deadline_is_rechecked_before_private_fd_read(tmp_path: Path) -> None:
    parent, source_root, packet = _packet(tmp_path)
    ledger = RecordingLedger(parent)
    credential_fd = _credential_fd(tmp_path)
    reads: list[str] = []
    try:
        with pytest.raises(recovery.RecoveryRefusal, match="deadline"):
            executor.execute_recovery(
                packet,
                parent=parent,
                ledger=ledger,
                source_root=source_root,
                credential_fd=credential_fd,
                gate_path=tmp_path / "child-gate",
                now=1001.0,
                clock=lambda: 1061.0,
                read_handoff=lambda _fd: reads.append("read"),
            )
    finally:
        os.close(credential_fd)
    assert reads == []
    assert ledger.lifecycle == ["begin-child"]


def test_absolute_deadline_is_rechecked_before_gate_dispatch(tmp_path: Path) -> None:
    parent, source_root, packet = _packet(tmp_path)
    ledger = RecordingLedger(parent)
    credential_fd = _credential_fd(tmp_path)
    clock_values = iter((1001.0, 1061.0))
    dispatched: list[str] = []
    try:
        with pytest.raises(recovery.RecoveryRefusal, match="deadline"):
            executor.execute_recovery(
                packet,
                parent=parent,
                ledger=ledger,
                source_root=source_root,
                credential_fd=credential_fd,
                gate_path=tmp_path / "child-gate",
                now=1001.0,
                clock=lambda: next(clock_values),
                transport=lambda *_args, **_kwargs: dispatched.append("wire"),
            )
    finally:
        os.close(credential_fd)
    assert dispatched == []
    assert ledger.lifecycle == ["begin-child"]


def test_packet_parent_ticket_binding_is_required(tmp_path: Path) -> None:
    parent, source_root, packet = _packet(tmp_path)
    packet["plan"]["parent"]["ticketDigest"] = "0" * 64
    ledger = RecordingLedger(parent)
    credential_fd = _credential_fd(tmp_path)
    try:
        with pytest.raises(recovery.RecoveryRefusal):
            executor.execute_recovery(
                packet,
                parent=parent,
                ledger=ledger,
                source_root=source_root,
                credential_fd=credential_fd,
                gate_path=tmp_path / "child-gate",
                now=1001.0,
                clock=lambda: 1001.0,
            )
    finally:
        os.close(credential_fd)
    assert ledger.lifecycle == []


def test_runtime_executor_source_must_be_in_reviewed_closure(tmp_path: Path) -> None:
    parent, source_root, packet = _packet(tmp_path)
    (source_root / executor.EXECUTOR_ENTRY).unlink()
    ledger = RecordingLedger(parent)
    credential_fd = _credential_fd(tmp_path)
    try:
        with pytest.raises(recovery.RecoveryRefusal, match="source"):
            executor.execute_recovery(
                packet,
                parent=parent,
                ledger=ledger,
                source_root=source_root,
                credential_fd=credential_fd,
                gate_path=tmp_path / "child-gate",
                now=1001.0,
                clock=lambda: 1001.0,
            )
    finally:
        os.close(credential_fd)
    assert ledger.lifecycle == []


def test_missing_reviewed_owner_identities_do_not_use_executor_defaults(
    tmp_path: Path,
) -> None:
    parent, source_root, packet = _packet(tmp_path)
    packet["permission"].pop("ownerIdentity")
    packet["permission"].pop("recoveryOwner")
    packet["o7"]["permissionDigest"] = digest(packet["permission"])
    packet["o8"]["permissionDigest"] = digest(packet["permission"])
    reviews = _reviews(packet["permission"], packet["o7"], packet["o8"])
    packet["permissionReview"], packet["o7Review"], packet["o8Review"] = reviews
    ledger = RecordingLedger(parent)
    credential_fd = _credential_fd(tmp_path)
    try:
        with pytest.raises(recovery.RecoveryRefusal):
            executor.execute_recovery(
                packet,
                parent=parent,
                ledger=ledger,
                source_root=source_root,
                credential_fd=credential_fd,
                gate_path=tmp_path / "child-gate",
                now=1001.0,
                clock=lambda: 1001.0,
            )
    finally:
        os.close(credential_fd)
    assert ledger.lifecycle == []


@pytest.mark.parametrize(
    "response",
    [
        (200, {"kind": "identitytoolkit#GetAccountInfoResponse", "users": [{"localId": "foreign"}]}),
        (200, {"kind": "identitytoolkit#GetAccountInfoResponse", "users": "malformed"}),
        (504, {}),
    ],
)
def test_non_empty_malformed_or_timeout_result_keeps_parent_held(
    tmp_path: Path, response: tuple[int, dict]
) -> None:
    parent, source_root, packet = _packet(tmp_path)
    ledger = RecordingLedger(parent)
    credential_fd = _credential_fd(tmp_path)

    def transport(_operation, _body, *, token, api_key, deadline):
        assert token and api_key and deadline > 0
        if response[0] == 504:
            raise TimeoutError("bounded timeout")
        return response

    try:
        with pytest.raises(recovery.RecoveryRefusal):
            executor.execute_recovery(
                packet,
                parent=parent,
                ledger=ledger,
                source_root=source_root,
                credential_fd=credential_fd,
                gate_path=tmp_path / "child-gate",
                now=1001.0,
                clock=lambda: 1001.0,
                transport=transport,
            )
    finally:
        os.close(credential_fd)

    assert ledger.lifecycle == ["begin-child"]
    assert not ("settle-child" in ledger.lifecycle or "close-parent" in ledger.lifecycle)


def test_invalid_packet_is_refused_before_private_fd_read_or_child_allocation(
    tmp_path: Path,
) -> None:
    parent, source_root, packet = _packet(tmp_path)
    packet["o8"]["consumed"] = True
    ledger = RecordingLedger(parent)
    credential_fd = _credential_fd(tmp_path)
    reads: list[str] = []

    try:
        with pytest.raises(recovery.RecoveryRefusal):
            executor.execute_recovery(
                packet,
                parent=parent,
                ledger=ledger,
                source_root=source_root,
                credential_fd=credential_fd,
                gate_path=tmp_path / "child-gate",
                now=1001.0,
                clock=lambda: 1001.0,
                read_handoff=lambda _fd: reads.append("read"),
                transport=lambda *_args, **_kwargs: (200, {}),
            )
    finally:
        os.close(credential_fd)

    assert reads == []
    assert ledger.lifecycle == []
    assert not (tmp_path / "child-gate").exists()


def test_fd_handoff_requires_private_regular_owned_descriptor(tmp_path: Path) -> None:
    path = tmp_path / "handoff.json"
    path.write_text('{"token":"oauth-token","apiKey":"web-api-key"}')
    path.chmod(0o644)
    fd = os.open(path, os.O_RDONLY)
    try:
        with pytest.raises(ValueError, match="contract refused"):
            executor.read_private_handoff(fd)
    finally:
        os.close(fd)
