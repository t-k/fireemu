"""Exact-name recovery can only delete documents proven to belong to one run."""

import copy
import datetime as dt
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import txn_expiry_cases as cases
import txn_expiry_collector as collector
import txn_expiry_plan as plan
import txn_sandbox_recovery as recovery

NONCE = "0123456789abcdef0123456789abcdef"
OWNER = "11111111222233334444555566667777"


def snapshot():
    return {
        "kind": "txn-responsibility-v1",
        "sourceDigest": plan.source_digest(),
        "casesDigest": cases.cases_digest(),
        "target": "production",
        "projectId": "fireemu-oracle-sbx",
        "database": "(default)",
        "nonce": NONCE,
        "ownerId": OWNER,
        "documentPrefix": f"oracle/{NONCE}/txn-expiry-04",
        "resourceStates": {
            role: "creation-confirmed" if role == "control" else "not-sent"
            for role in cases.RESOURCE_ROLES
        },
        "preconditions": [{"role": "control", "absence": True, "created": True}],
        "typedAbsenceConfirmed": [],
        "authorizesCleanup": False,
        "authorizesResume": False,
        "terminalComplete": False,
    }


def document(name, *, owner=OWNER):
    return {
        "name": name,
        "updateTime": "2026-09-27T00:00:00.000001Z",
        "fields": collector._marker_fields(owner, "control", NONCE, "created"),
    }


def test_recovery_plan_is_bounded_to_the_snapshot_owned_roles():
    targets = recovery.targets(snapshot())
    assert len(targets) == 5
    assert targets[0]["role"] == "control"
    assert targets[0]["mayDelete"] is True
    assert all(target["mayDelete"] is False for target in targets[1:])
    assert targets[0]["name"] == (
        f"projects/fireemu-oracle-sbx/databases/(default)/documents/oracle/{NONCE}/txn-expiry-04/control"
    )
    changed = snapshot()
    changed["documentPrefix"] = "oracle/other/txn-expiry-04"
    with pytest.raises(ValueError, match="prefix"):
        recovery.targets(changed)
    changed = snapshot()
    changed["resourceStates"]["control"] = "sent-unknown"
    changed["preconditions"][0]["absence"] = None
    with pytest.raises(ValueError, match="absence"):
        recovery.targets(changed)


def test_recovery_uses_read_owner_check_conditional_delete_and_typed_absence():
    target = recovery.targets(snapshot())[0]
    seen = []

    def send(request):
        seen.append(copy.deepcopy(request))
        if len(seen) == 1:
            return {"complete": True, "code": 0, "body": document(target["name"])}
        if len(seen) == 2:
            return {"complete": True, "code": 0, "body": {}}
        return {"complete": True, "code": 5, "body": {}}

    result = recovery.recover(snapshot(), send)
    assert result == {"complete": True, "requests": 7, "recovered": list(cases.RESOURCE_ROLES)}
    assert [request["rpc"] for request in seen] == ["GetDocument", "Commit", "GetDocument"] + ["GetDocument"] * 4
    assert seen[1]["body"]["writes"] == [{
        "delete": target["name"],
        "currentDocument": {"updateTime": "2026-09-27T00:00:00.000001Z"},
    }]


def test_recovery_does_not_delete_a_foreign_marker_or_unknown_response():
    target = recovery.targets(snapshot())[0]
    for answer in (
        {"complete": True, "code": 0, "body": document(target["name"], owner="0" * 32)},
        {"complete": False, "code": None, "body": None},
    ):
        calls = []
        result = recovery.recover(snapshot(), lambda request: calls.append(request) or answer)
        assert result["complete"] is False
        assert result["requests"] == 1
        assert len(calls) == 1


def fixture_context(tmp_path, monkeypatch):
    root = tmp_path
    run_dir = root / "docs.local/runs/fs-transaction-prior"
    run_dir.mkdir(parents=True)
    snapshot_path = run_dir / "responsibility.json"
    snapshot_raw = json.dumps(snapshot()).encode()
    snapshot_path.write_bytes(snapshot_raw)
    os.utime(snapshot_path, (1_800_000_000, 1_800_000_000))
    baseline_raw = b"{}"
    lock_path = root / "docs.local/runs/sandbox-locks/fireemu-oracle-sbx.lock"
    lock_path.parent.mkdir()
    commit = "a" * 40
    lock_path.write_text(json.dumps({
        "taskId": "FS-TRANSACTION-SANDBOX", "packetId": "original-packet",
        "sourceCommit": commit, "pid": 99999999,
    }))
    monkeypatch.setattr(recovery.cli, "_main_root", lambda: root)
    monkeypatch.setattr(recovery.cli, "_source_commit", lambda: commit)
    monkeypatch.setattr(recovery.cli, "runner_source_sha256", lambda: "b" * 64)
    monkeypatch.setattr(recovery.os, "kill", lambda pid, sig: (_ for _ in ()).throw(ProcessLookupError()))
    packet_sha = "c" * 64
    packet_path = "docs.local/reviews/recovery-packet.json"
    packet = {
        "schemaVersion": 1, "packetId": "recovery-packet", "originalPacketId": "original-packet",
        "originalAttemptId": "prior-attempt", "sourceCommit": commit,
        "runnerSha256": "b" * 64, "project": "fireemu-oracle-sbx", "database": "(default)",
        "maxRequests": 23, "estimatedUsd": 0.02,
        "snapshotPath": "docs.local/runs/fs-transaction-prior/responsibility.json",
        "snapshotSha256": hashlib.sha256(snapshot_raw).hexdigest(),
        "baselineSha256": hashlib.sha256(baseline_raw).hexdigest(),
        "lockSha256": hashlib.sha256(lock_path.read_bytes()).hexdigest(),
        "lockInode": lock_path.stat().st_ino, "notBefore": "2027-01-15T09:55:00Z",
        "roles": list(cases.RESOURCE_ROLES),
    }
    original = {
        "ts": "2027-01-15T09:50:00Z", "project": "fireemu-oracle-sbx",
        "taskId": "FS-TRANSACTION-SANDBOX", "packetId": "original-packet",
        "attemptId": "prior-attempt", "runDir": str(run_dir),
        "nonce": NONCE,
        "outcome": "stopped-needs-review", "estimatedUsd": 0.05,
    }
    ledger_path = root / "docs.local/runs/sandbox-ledger.jsonl"
    ledger_path.write_text(json.dumps(original) + "\n")
    ledger_path.chmod(0o600)
    decisions = (
        "- 2027-01-15 | FS-TRANSACTION recovery | decision=APPROVE; "
        f"packetSha256={packet_sha}; sourceCommit={commit}; maxRequests=23; "
        "reserveUsd=0.02; writes=exact-owned-five-documents; onStop=lock-held; "
        f"onSuccess=release-lock | オーナー（直接） | {packet_path}\n"
    )
    review = (
        "APPROVE\n"
        f"packetSha256={packet_sha}\nsourceCommit={commit}\n"
        f"runnerSha256={'b' * 64}\nwithinRecoveryEnvelope=YES\n"
    )
    now = dt.datetime(2027, 1, 15, 10, 0, tzinfo=dt.timezone.utc)
    return locals()


def test_recovery_gate_needs_exact_owner_review_and_elapsed_wait(tmp_path, monkeypatch):
    value = fixture_context(tmp_path, monkeypatch)
    common = dict(
        packet_sha=value["packet_sha"], snapshot_raw=value["snapshot_raw"],
        baseline_raw=value["baseline_raw"], lock_path=value["lock_path"],
        ledger_rows=[value["original"]], now=value["now"],
        decisions=value["decisions"], review=value["review"],
        packet_path=value["packet_path"],
    )
    assert recovery.verify_packet(value["packet"], **common)[1] == value["original"]
    with pytest.raises(ValueError, match="owner"):
        recovery.verify_packet(value["packet"], **{**common, "decisions": ""})
    with pytest.raises(ValueError, match="review"):
        recovery.verify_packet(value["packet"], **{**common, "review": "REQUEST_CHANGES"})
    with pytest.raises(ValueError, match="wait"):
        recovery.verify_packet(value["packet"], **{**common, "now": value["now"] - dt.timedelta(minutes=10)})


def test_verified_recovery_records_terminal_then_releases_exact_lock(tmp_path, monkeypatch):
    value = fixture_context(tmp_path, monkeypatch)

    class Metadata:
        def __init__(self, token, baseline, budget):
            self.budget = budget

        def preflight(self):
            for _ in range(5):
                self.budget.charge("management")
            return {"project": "same", "database": "same"}

        def postflight(self):
            for _ in range(2):
                self.budget.charge("management")
            return {"project": "same", "database": "same"}

    def wire_factory(token, budget):
        def send(request):
            budget.charge("data", phase="recovery")
            return {"complete": True, "code": 5, "body": {}}
        return send

    result = recovery.record_recovery(
        packet=value["packet"], packet_sha=value["packet_sha"],
        packet_path=value["packet_path"], snapshot_raw=value["snapshot_raw"],
        baseline_raw=value["baseline_raw"], lock_path=value["lock_path"],
        ledger_path=value["ledger_path"], private_dir=value["root"] / "docs.local/runs",
        now=value["now"], decisions=value["decisions"], review=value["review"],
        credential_fn=lambda: "test-token", metadata_factory=Metadata, wire_factory=wire_factory,
    )
    assert result["complete"] is True and result["totalRequests"] == 13
    assert not value["lock_path"].exists()
    rows = [json.loads(line) for line in value["ledger_path"].read_text().splitlines()]
    assert rows[-1]["outcome"] == "recovered-exact-name"
    assert rows[-1]["estimatedUsd"] >= 0.07


def test_unverified_recovery_keeps_lock_and_records_need(tmp_path, monkeypatch):
    value = fixture_context(tmp_path, monkeypatch)

    class Metadata:
        def __init__(self, token, baseline, budget):
            self.budget = budget

        def preflight(self):
            return {"project": "same", "database": "same"}

        def postflight(self):
            raise AssertionError("postflight must not follow an incomplete recovery")

    def wire_factory(token, budget):
        def send(request):
            budget.charge("data", phase="recovery")
            return {"complete": False, "code": None, "body": None}
        return send

    with pytest.raises(ValueError, match="incomplete"):
        recovery.record_recovery(
            packet=value["packet"], packet_sha=value["packet_sha"],
            packet_path=value["packet_path"], snapshot_raw=value["snapshot_raw"],
            baseline_raw=value["baseline_raw"], lock_path=value["lock_path"],
            ledger_path=value["ledger_path"], private_dir=value["root"] / "docs.local/runs",
            now=value["now"], decisions=value["decisions"], review=value["review"],
            credential_fn=lambda: "test-token", metadata_factory=Metadata, wire_factory=wire_factory,
        )
    assert value["lock_path"].exists()
    rows = [json.loads(line) for line in value["ledger_path"].read_text().splitlines()]
    assert rows[-1]["outcome"] == "needs-recovery"
    assert rows[-1]["requests"] == 2


def _record(value, *, credential_fn, metadata_factory, wire_factory):
    return recovery.record_recovery(
        packet=value["packet"], packet_sha=value["packet_sha"],
        packet_path=value["packet_path"], snapshot_raw=value["snapshot_raw"],
        baseline_raw=value["baseline_raw"], lock_path=value["lock_path"],
        ledger_path=value["ledger_path"], private_dir=value["root"] / "docs.local/runs",
        now=value["now"], decisions=value["decisions"], review=value["review"],
        credential_fn=credential_fn, metadata_factory=metadata_factory, wire_factory=wire_factory,
    )


class NoReadsMetadata:
    def __init__(self, token, baseline, budget):
        self.budget = budget

    def preflight(self):
        return {"project": "same", "database": "same"}

    def postflight(self):
        return {"project": "same", "database": "same"}


def _absent_wire(token, budget):
    def send(request):
        budget.charge("data", phase="recovery")
        return {"complete": True, "code": 5, "body": {}}
    return send


def test_second_recovery_cannot_enter_while_first_holds_exclusive_guard(tmp_path, monkeypatch):
    value = fixture_context(tmp_path, monkeypatch)

    def nested_attempt():
        other = dict(value)
        other["packet"] = {**value["packet"], "packetId": "another-packet"}
        other["decisions"] = value["decisions"].replace("recovery-packet.json", "another-packet.json")
        other["packet_path"] = "docs.local/reviews/another-packet.json"
        with pytest.raises((BlockingIOError, ValueError), match="lock|guard|active"):
            _record(other, credential_fn=lambda: pytest.fail("second OAuth"),
                    metadata_factory=NoReadsMetadata, wire_factory=_absent_wire)
        return "test-token"

    result = _record(value, credential_fn=nested_attempt,
                     metadata_factory=NoReadsMetadata, wire_factory=_absent_wire)
    assert result["complete"] is True


def test_new_approved_packet_can_follow_incomplete_recovery(tmp_path, monkeypatch):
    value = fixture_context(tmp_path, monkeypatch)

    def incomplete_wire(token, budget):
        def send(request):
            budget.charge("data", phase="recovery")
            return {"complete": False, "code": None, "body": None}
        return send

    with pytest.raises(ValueError, match="incomplete"):
        _record(value, credential_fn=lambda: "test-token",
                metadata_factory=NoReadsMetadata, wire_factory=incomplete_wire)
    later = dict(value)
    later["packet"] = {**value["packet"], "packetId": "approved-retry", "notBefore": "2027-01-15T10:04:00Z"}
    later["packet_path"] = "docs.local/reviews/approved-retry.json"
    later["decisions"] = value["decisions"].replace("recovery-packet.json", "approved-retry.json")
    later["now"] = value["now"] + dt.timedelta(minutes=5)
    assert _record(later, credential_fn=lambda: "test-token",
                   metadata_factory=NoReadsMetadata, wire_factory=_absent_wire)["complete"] is True


def test_new_approved_packet_can_follow_a_crashed_recovery_reservation(tmp_path, monkeypatch):
    value = fixture_context(tmp_path, monkeypatch)
    crashed = {
        **value["original"], "ts": "2027-01-15T10:00:00Z",
        "outcome": "reserved", "phase": "recovery", "recoveryPacketId": "crashed-packet",
        "estimatedUsd": 0.07,
    }
    value["ledger_path"].write_text(
        json.dumps(value["original"]) + "\n" + json.dumps(crashed) + "\n"
    )
    value["packet"] = {**value["packet"], "packetId": "approved-retry", "notBefore": "2027-01-15T10:04:00Z"}
    value["packet_path"] = "docs.local/reviews/approved-retry.json"
    value["decisions"] = value["decisions"].replace("recovery-packet.json", "approved-retry.json")
    value["now"] += dt.timedelta(minutes=5)
    assert _record(value, credential_fn=lambda: "test-token",
                   metadata_factory=NoReadsMetadata, wire_factory=_absent_wire)["complete"] is True


def test_recovery_reservation_is_a_shared_open_attempt(tmp_path, monkeypatch):
    value = fixture_context(tmp_path, monkeypatch)
    observed = []
    original_append = recovery.admission.append_ledger

    def inspect_append(path, row):
        if row.get("recoveryPacketId") == "recovery-packet" and row["outcome"] == "reserved":
            assert row["phase"] == "recovery"
            assert row["attemptId"] == "prior-attempt"
            observed.append(row)
            original_append(path, row)
            with pytest.raises(ValueError, match="open attempt"):
                recovery.admission.verify_send_gates(
                    recovery.admission.read_ledger(path), value["now"], "",
                    {"envelopeId": "unrelated-envelope", "packetId": "unrelated-packet"},
                )
            return None
        return original_append(path, row)

    monkeypatch.setattr(recovery.admission, "append_ledger", inspect_append)
    assert _record(value, credential_fn=lambda: "test-token",
                   metadata_factory=NoReadsMetadata, wire_factory=_absent_wire)["complete"] is True
    assert len(observed) == 1


def test_terminal_row_with_original_lock_can_finalize_without_requests(tmp_path, monkeypatch):
    value = fixture_context(tmp_path, monkeypatch)
    original_unlink = Path.unlink
    interrupted = False

    def interrupted_unlink(path, *args, **kwargs):
        nonlocal interrupted
        if path == value["lock_path"] and not interrupted:
            interrupted = True
            raise KeyboardInterrupt
        return original_unlink(path, *args, **kwargs)

    with patch.object(Path, "unlink", interrupted_unlink):
        with pytest.raises(KeyboardInterrupt):
            _record(value, credential_fn=lambda: "test-token",
                    metadata_factory=NoReadsMetadata, wire_factory=_absent_wire)
    assert value["lock_path"].exists()
    assert json.loads(value["ledger_path"].read_text().splitlines()[-1])["outcome"] == "recovered-exact-name"
    result = _record(value, credential_fn=lambda: pytest.fail("OAuth during finalization"),
                     metadata_factory=NoReadsMetadata, wire_factory=_absent_wire)
    assert result["complete"] is True
    assert not value["lock_path"].exists()


def test_lock_release_error_allows_request_free_finalization_only(tmp_path, monkeypatch):
    value = fixture_context(tmp_path, monkeypatch)
    original_unlink = Path.unlink
    failed = False

    def fail_once(path, *args, **kwargs):
        nonlocal failed
        if path == value["lock_path"] and not failed:
            failed = True
            raise OSError("simulated lock release error")
        return original_unlink(path, *args, **kwargs)

    with patch.object(Path, "unlink", fail_once):
        with pytest.raises(OSError, match="lock release"):
            _record(value, credential_fn=lambda: "test-token",
                    metadata_factory=NoReadsMetadata, wire_factory=_absent_wire)
    rows = [json.loads(line) for line in value["ledger_path"].read_text().splitlines()]
    assert rows[-1]["reason"] == "lock-release-failed"
    assert rows[-1]["outcome"] == "needs-recovery"
    other = dict(value)
    other["packet"] = {**value["packet"], "packetId": "different-recovery-packet"}
    other["packet_path"] = "docs.local/reviews/different-recovery-packet.json"
    other["decisions"] = value["decisions"].replace("recovery-packet.json", "different-recovery-packet.json")
    with pytest.raises(ValueError, match="request-free finalization"):
        _record(other, credential_fn=lambda: pytest.fail("OAuth for second cleanup"),
                metadata_factory=NoReadsMetadata, wire_factory=_absent_wire)
    result = _record(value, credential_fn=lambda: pytest.fail("OAuth after lock release error"),
                     metadata_factory=NoReadsMetadata, wire_factory=_absent_wire)
    assert result["complete"] is True
    assert not value["lock_path"].exists()


def test_terminal_result_sha_does_not_require_rereading_written_file(tmp_path, monkeypatch):
    value = fixture_context(tmp_path, monkeypatch)
    result_path = value["root"] / "docs.local/runs/fs-transaction-recovery-recovery-packet/recovery.json"
    original_read_bytes = Path.read_bytes

    def forbid_receipt_reread(path):
        if path == result_path:
            pytest.fail("terminal SHA reread the receipt after writing")
        return original_read_bytes(path)

    with patch.object(Path, "read_bytes", forbid_receipt_reread):
        assert _record(value, credential_fn=lambda: "test-token",
                       metadata_factory=NoReadsMetadata, wire_factory=_absent_wire)["complete"] is True
    terminal = json.loads(value["ledger_path"].read_text().splitlines()[-1])
    assert terminal["resultSha256"] == hashlib.sha256(result_path.read_bytes()).hexdigest()


def test_receipt_directory_entries_are_durable_before_terminal_row(tmp_path, monkeypatch):
    value = fixture_context(tmp_path, monkeypatch)
    result_parent = value["root"] / "docs.local/runs"
    result_dir = result_parent / "fs-transaction-recovery-recovery-packet"
    original_fsync = os.fsync
    original_append = recovery.admission.append_ledger
    synced_directories = set()

    def tracked_fsync(fd):
        details = os.fstat(fd)
        if stat.S_ISDIR(details.st_mode):
            synced_directories.add(details.st_ino)
        return original_fsync(fd)

    def checked_append(path, row):
        if row["outcome"] == "recovered-exact-name":
            assert result_parent.stat().st_ino in synced_directories
            assert result_dir.stat().st_ino in synced_directories
        return original_append(path, row)

    monkeypatch.setattr(os, "fsync", tracked_fsync)
    monkeypatch.setattr(recovery.admission, "append_ledger", checked_append)
    assert _record(value, credential_fn=lambda: "test-token",
                   metadata_factory=NoReadsMetadata, wire_factory=_absent_wire)["complete"] is True


def test_failed_receipt_directory_sync_keeps_the_original_lock(tmp_path, monkeypatch):
    value = fixture_context(tmp_path, monkeypatch)
    original_sync = recovery._fsync_directory

    def fail_result_sync(path):
        if path.name == "fs-transaction-recovery-recovery-packet":
            raise OSError("simulated directory sync failure")
        return original_sync(path)

    monkeypatch.setattr(recovery, "_fsync_directory", fail_result_sync)
    with pytest.raises(OSError, match="directory sync"):
        _record(value, credential_fn=lambda: "test-token",
                metadata_factory=NoReadsMetadata, wire_factory=_absent_wire)
    assert value["lock_path"].exists()
    rows = [json.loads(line) for line in value["ledger_path"].read_text().splitlines()]
    assert rows[-1]["outcome"] == "needs-recovery"


def test_recovery_budget_cap_rejects_before_credentials(tmp_path, monkeypatch):
    value = fixture_context(tmp_path, monkeypatch)
    value["original"]["estimatedUsd"] = 10.0
    value["ledger_path"].write_text(json.dumps(value["original"]) + "\n")
    with pytest.raises(ValueError, match="budget"):
        _record(value, credential_fn=lambda: pytest.fail("OAuth after exhausted budget"),
                metadata_factory=NoReadsMetadata, wire_factory=_absent_wire)
    assert value["lock_path"].exists()
