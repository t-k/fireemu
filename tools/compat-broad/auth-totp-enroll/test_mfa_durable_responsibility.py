"""Actual file/process failure checks; no native/Firebase or restart authority."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import select
import stat
import subprocess
import sys

import pytest

import mfa_local_shadow as shadow
import mfa_persistence as persistence
from mfa_collector import initial_state, load_checkpoint, register_owned, mark_deleted, run_complete
from mfa_manifest import compile_campaign

NONCE = "ab" * 16
ROLE = "pending-control"


def setup(tmp_path):
    plan = compile_campaign(NONCE)
    state = initial_state(plan, 100.0)
    journal = persistence.RunPersistence(tmp_path, state, plan)
    return plan, state, journal


def events(root):
    return [json.loads(path.read_bytes()) for path in sorted((root / "responsibility").glob("*.json"))]


def last_summary(root):
    return next(row["body"]["summary"] for row in reversed(events(root)) if row["kind"] == "recovery")


class Backend(shadow.Instance):
    def __init__(self, root, mode="update-failure"):
        self.root, self.mode = root, mode
        super().__init__("http://127.0.0.1:9099", "http://127.0.0.1:9100", "CONTROL")
        self.calls, self.accounts = [], {}

    def require(self, *args):
        return shadow.Instance.require(self, *args)

    def public(self, path, body):
        uid = body.get("localId")
        if isinstance(uid, list):
            uid = uid[0] if len(uid) == 1 else None
        operation = "delete" if path.endswith(":delete") else "lookup" if path.endswith(":lookup") else None
        with self._request_budget.attempt(operation=operation, uid=uid):
            pass
        self.calls.append((path, body))
        if path.endswith(":signUp"):
            intents = [row for row in events(self.root) if row["kind"] == "create-intent"]
            assert intents and intents[-1]["body"]["email"] == body.get("email")
            assert load_checkpoint((self.root / "checkpoint.json").read_bytes())["ownedResources"] == []
            self.accounts["uid-one"] = body.get("email")
            if self.mode in {"timeout", "transport-error", "interrupt"}:
                raise {"timeout": TimeoutError, "transport-error": OSError, "interrupt": KeyboardInterrupt}[self.mode]("PRIVATE")
            result = {"localId": "uid-one", "idToken": "PRIVATE-ID"}
            if "email" in body:
                result["email"] = body["email"]
            if self.mode == "missing-token":
                result.pop("idToken")
            if self.mode == "bad-uid":
                result["localId"] = None
            if self.mode == "wrong-email":
                result["email"] = "someone-else@example.invalid"
            if self.mode == "mixed-error":
                result["error"] = {}
            if self.mode == "rejected":
                return 400, {"error": {"message": "REFUSED"}}
            return 200, result
        return 200, {"localId": "uid-one", "idToken": "PRIVATE-SIGNED"}

    def admin(self, path, body):
        uid = body.get("localId")
        if isinstance(uid, list):
            uid = uid[0] if len(uid) == 1 else None
        operation = "delete" if path.endswith(":delete") else "lookup" if path.endswith(":lookup") else None
        with self._request_budget.attempt(operation=operation, uid=uid):
            pass
        self.calls.append((path, body))
        if path.endswith(":update"):
            raise ValueError("original-observation-error")
        if path.endswith(":delete"):
            if self.mode == "delete-failure":
                raise OSError("PRIVATE")
            self.accounts.pop(body["localId"], None)
            return 200, {}
        assert path.endswith(":lookup")
        return 200, {"users": []}


@pytest.mark.parametrize("mode", ["timeout", "transport-error", "interrupt", "bad-uid", "wrong-email", "mixed-error", "rejected"])
def test_unknown_signup_has_durable_intent_no_delete_authority_and_no_success(tmp_path, mode):
    backend = Backend(tmp_path, mode)
    with pytest.raises((TimeoutError, OSError, KeyboardInterrupt, ValueError, shadow.Refused)):
        shadow.run_sequence(backend, tmp_path)
    state = load_checkpoint((tmp_path / "checkpoint.json").read_bytes())
    summary = last_summary(tmp_path)
    assert state["ownedResources"] == [] and state["aborted"] is True
    assert not run_complete(state)
    assert summary["unresolvedCreations"] == 1
    assert summary["acknowledgedAccounts"] == 0
    assert summary["resourceCleanupComplete"] is False
    assert summary["authorizesCleanup"] is False
    assert len(backend.calls) == 1 and backend.accounts
    assert "PRIVATE" not in "".join(p.read_text() for p in tmp_path.rglob("*.json"))


@pytest.mark.parametrize("mode", ["update-failure", "missing-token", "delete-failure"])
def test_confirmed_uid_is_registered_before_later_setup_and_kept_after_failure(tmp_path, mode):
    backend = Backend(tmp_path, mode)
    with pytest.raises(ValueError):
        shadow.run_sequence(backend, tmp_path)
    state = load_checkpoint((tmp_path / "checkpoint.json").read_bytes())
    summary = last_summary(tmp_path)
    assert state["aborted"] is True
    assert summary["unresolvedCreations"] == 0
    assert summary["acknowledgedAccounts"] == 1
    assert summary["resourceCleanupComplete"] is (mode != "delete-failure")
    assert summary["remainingKnownAccounts"] == int(mode == "delete-failure")
    assert bool(backend.accounts) is (mode == "delete-failure")
    assert next(row for row in events(tmp_path) if row["kind"] == "create-ack")["body"]["uid"] == "uid-one"


@pytest.mark.parametrize("anonymous", [False, True])
def test_each_signup_is_preceded_by_fsynced_intent_and_ack_before_token_parse(tmp_path, monkeypatch, anonymous):
    backend = Backend(tmp_path, "missing-token")
    role = "interaction-anonymous" if anonymous else ROLE
    def only_signup(instance, state, checkpoint, rows, accounts, *, journal):
        shadow._create_owned_account(instance, state, accounts, journal, role, False)
    monkeypatch.setattr(shadow, "_walk", only_signup)
    with pytest.raises(ValueError, match="token"):
        shadow.run_sequence(backend, tmp_path)
    summary = last_summary(tmp_path)
    assert summary["acknowledgedAccounts"] == 1 and summary["resourceCleanupComplete"] is True
    assert not backend.accounts
    signup_body = backend.calls[0][1]
    assert ("email" not in signup_body) is anonymous
    assert ("password" not in signup_body) is anonymous
    assert [row["kind"] for row in events(tmp_path)] == ["launch", "create-intent", "create-ack", "recovery"]


@pytest.mark.parametrize("kind", ["create-intent", "create-ack"])
def test_event_write_failure_stops_setup_but_retains_known_inprocess_cleanup(tmp_path, monkeypatch, kind):
    original = persistence._publish
    def fail(directory, name, data, **kwargs):
        if name.endswith(f"-{kind}.json"):
            raise OSError("PRIVATE-save-error")
        return original(directory, name, data, **kwargs)
    monkeypatch.setattr(persistence, "_publish", fail)
    backend = Backend(tmp_path)
    with pytest.raises(OSError):
        shadow.run_sequence(backend, tmp_path)
    assert not any(path.endswith(":update") for path, _ in backend.calls)
    assert backend.requests == (0 if kind == "create-intent" else 3)
    assert not backend.accounts
    summary = last_summary(tmp_path)
    assert summary["journalComplete"] is False and summary["resourceCleanupComplete"] is False
    assert summary["unresolvedCreations"] == 1
    assert "PRIVATE" not in "".join(p.read_text() for p in tmp_path.rglob("*.json"))


def test_final_checkpoint_failure_does_not_skip_final_responsibility_or_mask_primary(tmp_path, monkeypatch):
    original = persistence.RunPersistence._write_checkpoint
    def fail(self, state):
        if state["aborted"]:
            self._fault(OSError())
            raise OSError("secondary-checkpoint")
        return original(self, state)
    monkeypatch.setattr(persistence.RunPersistence, "_write_checkpoint", fail)
    backend = Backend(tmp_path)
    with pytest.raises(ValueError, match="original-observation-error"):
        shadow.run_sequence(backend, tmp_path)
    assert not backend.accounts
    assert last_summary(tmp_path)["journalComplete"] is False
    # Previous fully written checkpoint remains readable; it is not current cleanup authority.
    old = load_checkpoint((tmp_path / "checkpoint.json").read_bytes())
    assert old["ownedResources"][0]["deleted"] is False


def test_final_journal_failure_occurs_after_recovery_and_preserves_prior_intent(tmp_path, monkeypatch):
    original = persistence._publish
    def fail(directory, name, data, **kwargs):
        if name.endswith("-recovery.json"):
            raise OSError("secondary-journal")
        return original(directory, name, data, **kwargs)
    monkeypatch.setattr(persistence, "_publish", fail)
    backend = Backend(tmp_path)
    with pytest.raises(ValueError, match="original-observation-error"):
        shadow.run_sequence(backend, tmp_path)
    assert not backend.accounts
    assert [row["kind"] for row in events(tmp_path)] == ["launch", "create-intent", "create-ack"]
    assert load_checkpoint((tmp_path / "checkpoint.json").read_bytes())["ownedResources"][0]["absenceVerified"] is True


@pytest.mark.parametrize("existing", ["checkpoint", "journal", "checkpoint-symlink", "journal-symlink"])
def test_existing_evidence_is_not_reused_or_overwritten(tmp_path, existing):
    target = tmp_path / ("checkpoint.json" if existing.startswith("checkpoint") else "responsibility")
    private = tmp_path / "preserve"
    private.write_bytes(b"do-not-touch")
    if existing.endswith("symlink"):
        target.symlink_to(private)
    elif existing == "journal":
        target.mkdir(mode=0o700)
    else:
        target.write_bytes(b"old-checkpoint")
        target.chmod(0o600)
    backend = Backend(tmp_path)
    with pytest.raises((OSError, ValueError)):
        shadow.run_sequence(backend, tmp_path)
    assert backend.requests == 0 and private.read_bytes() == b"do-not-touch"
    if existing == "checkpoint":
        assert target.read_bytes() == b"old-checkpoint"


@pytest.mark.parametrize("fault", ["write-zero", "write-partial", "file-fsync", "replace"])
def test_atomic_checkpoint_failure_preserves_previous_complete_bytes(tmp_path, monkeypatch, fault):
    _, state, journal = setup(tmp_path)
    old = (tmp_path / "checkpoint.json").read_bytes()
    state["requests"] = 3
    write = os.write
    if fault.startswith("write"):
        def broken(fd, data):
            if fault == "write-zero":
                return 0
            write(fd, data[:7])
            raise OSError("partial write")
        monkeypatch.setattr(os, "write", broken)
    elif fault == "file-fsync":
        sync = os.fsync
        def broken(fd):
            if stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError("sync failed")
            sync(fd)
        monkeypatch.setattr(os, "fsync", broken)
    else:
        monkeypatch.setattr(os, "replace", lambda *a, **k: (_ for _ in ()).throw(OSError("rename failed")))
    with pytest.raises(OSError):
        journal.save_checkpoint(state)
    assert (tmp_path / "checkpoint.json").read_bytes() == old
    assert load_checkpoint(old)["requests"] == 0
    assert journal.failed
    with pytest.raises(RuntimeError):
        journal.intent(ROLE)
    journal.close()


def test_short_writes_are_completed_before_publication(tmp_path, monkeypatch):
    _, state, journal = setup(tmp_path)
    write = os.write
    monkeypatch.setattr(os, "write", lambda fd, data: write(fd, data[:7]))
    state["requests"] = 3
    journal.save_checkpoint(state)
    assert load_checkpoint((tmp_path / "checkpoint.json").read_bytes())["requests"] == 3
    journal.close()


def test_post_replace_directory_fsync_failure_is_not_claimed_durable(tmp_path, monkeypatch):
    _, state, journal = setup(tmp_path)
    state["requests"] = 3
    sync = os.fsync
    def broken(fd):
        if fd == journal._root:
            raise OSError("directory sync failed")
        sync(fd)
    monkeypatch.setattr(os, "fsync", broken)
    with pytest.raises(OSError):
        journal.save_checkpoint(state)
    assert load_checkpoint((tmp_path / "checkpoint.json").read_bytes())["requests"] == 3
    assert journal.failed
    with pytest.raises(RuntimeError):
        journal.intent(ROLE)
    summary = journal.finalize(state)
    assert not summary["journalComplete"] and not summary["resourceCleanupComplete"]
    journal.close()


@pytest.mark.parametrize("change", ["replace", "symlink", "hardlink", "mode", "directory"])
def test_changed_checkpoint_is_not_overwritten(tmp_path, change):
    _, state, journal = setup(tmp_path)
    path = tmp_path / "checkpoint.json"
    if change == "mode":
        path.chmod(0o644)
    elif change == "hardlink":
        os.link(path, tmp_path / "second-link")
    else:
        path.unlink()
        if change == "replace":
            path.write_bytes(b"new-file")
            path.chmod(0o600)
        elif change == "symlink":
            path.symlink_to(tmp_path / "do-not-create")
        else:
            path.mkdir()
    with pytest.raises(ValueError):
        journal.save_checkpoint(state)
    assert not (tmp_path / "do-not-create").exists()
    assert journal.failed
    journal.close()


def test_event_chain_and_private_file_modes_do_not_depend_on_umask(tmp_path):
    mask = os.umask(0)
    try:
        plan, state, journal = setup(tmp_path)
        journal.intent(ROLE)
        journal.acknowledge(ROLE, "uid-one")
        register_owned(state, "account", "uid-one", 100)
        mark_deleted(state, "uid-one", True)
        journal.save_checkpoint(state)
        summary = journal.finalize(state)
        journal.close()
    finally:
        os.umask(mask)
    previous = None
    for sequence, path in enumerate(sorted((tmp_path / "responsibility").glob("*.json"))):
        raw = path.read_bytes()
        record = json.loads(raw)
        assert record["sequence"] == sequence and record["previousSha256"] == previous
        assert record["nonceDigest"] == plan["owner"]["nonceDigest"]
        assert record["authorizesCleanup"] is False
        assert stat.S_IMODE(path.stat().st_mode) == 0o600 and path.stat().st_nlink == 1
        previous = hashlib.sha256(raw).hexdigest()
    assert summary["recordSha256"] == previous and persistence.complete_summary(summary, 1)
    assert stat.S_IMODE((tmp_path / "checkpoint.json").stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "responsibility").stat().st_mode) == 0o700


@pytest.mark.parametrize("role,uid", [("unknown", "one"), (ROLE, ""), (ROLE, "bad\nuid"), (ROLE, None), (ROLE, "x" * 1025)])
def test_unplanned_role_or_invalid_ack_never_grants_recorded_authority(tmp_path, role, uid):
    _, state, journal = setup(tmp_path)
    if role == "unknown":
        with pytest.raises(ValueError):
            journal.intent(role)
    else:
        journal.intent(role)
        with pytest.raises(ValueError):
            journal.acknowledge(role, uid)
        assert journal.finalize(state)["unresolvedCreations"] == 1
    journal.close()


def test_duplicate_intent_and_duplicate_uid_are_rejected(tmp_path):
    plan, state, journal = setup(tmp_path)
    second = next(row["role"] for row in plan["owner"]["accounts"] if row["role"] != ROLE)
    journal.intent(ROLE)
    with pytest.raises(ValueError):
        journal.intent(ROLE)
    journal.acknowledge(ROLE, "same")
    journal.intent(second)
    with pytest.raises(ValueError):
        journal.acknowledge(second, "same")
    summary = journal.finalize(state)
    assert summary["attemptedAccounts"] == 2 and summary["unresolvedCreations"] == 1
    assert summary["resourceCleanupComplete"] is False
    journal.close()


def test_completed_observation_cannot_hide_unknown_creation(tmp_path, monkeypatch):
    from mfa_cases import observation_cases
    from mfa_collector import record_step
    def fake_walk(instance, state, checkpoint, rows, accounts, *, journal):
        journal.intent(ROLE)
        # Simulate a caller that swallowed an unknown creation failure, then wrote all rows.
        for case in observation_cases():
            expected = case["expectedLocal"]
            rows[case["id"]] = shadow._row(case["id"], expected["status"], expected["errorCode"])
            record_step(state, case["id"], expected, state["startedAt"], requests=0)
    monkeypatch.setattr(shadow, "_walk", fake_walk)
    report = shadow.run_sequence(Backend(tmp_path), tmp_path)
    assert report["recordingComplete"] is False
    assert report["recovery"]["cleanupVerified"] is False
    assert report["recovery"]["creationResponsibility"]["unresolvedCreations"] == 1
    assert not run_complete(load_checkpoint((tmp_path / "checkpoint.json").read_bytes()))


@pytest.mark.parametrize("field,value", [("authorizesCleanup", True), ("journalComplete", 1), ("resourceCleanupComplete", False),
                                         ("unresolvedCreations", 1), ("remainingKnownAccounts", 1), ("untrackedOwnedAccounts", 1),
                                         ("attemptedAccounts", True), ("acknowledgedAccounts", 0.0), ("recordSha256", "x"),
                                         ("schema", "other")])
def test_explicit_inconsistent_responsibility_is_rejected_independently(tmp_path, field, value):
    from mfa_comparator import _receipt_problems
    from mfa_provenance import repository_root
    _, state, journal = setup(tmp_path)
    summary = journal.finalize(state)
    journal.close()
    assert persistence.complete_summary(summary, 0)
    summary[field] = value
    assert not persistence.complete_summary(summary, 0)
    # Even when the caller flips broad cleanup/recording flags back to true.
    receipt = {"recordingComplete": True, "recovery": {"cleanupVerified": True, "ownedAccounts": 0,
                "remainingOwnedResources": 0, "configurationRestored": True, "creationResponsibility": summary}}
    assert "creation responsibility is incomplete or inconsistent" in _receipt_problems(receipt, "local", repository_root())


def test_nonprivate_run_directory_is_refused_before_io(tmp_path):
    tmp_path.chmod(0o755)
    backend = Backend(tmp_path)
    with pytest.raises(ValueError):
        shadow.run_sequence(backend, tmp_path)
    assert backend.requests == 0
    assert list(tmp_path.iterdir()) == []


def test_sigkill_during_signup_preserves_pre_dispatch_intent(tmp_path):
    here = Path(__file__).resolve().parent
    script = f'''
import sys, time, os
from pathlib import Path
sys.path.insert(0, {str(here)!r})
import mfa_local_shadow as shadow
class Hung(shadow.Instance):
    def __init__(self):
        super().__init__("http://127.0.0.1:9099", "http://127.0.0.1:9100", "CONTROL")
    def public(self, path, body):
        uid = body.get("localId")
        if isinstance(uid, list):
            uid = uid[0] if len(uid) == 1 else None
        operation = "delete" if path.endswith(":delete") else "lookup" if path.endswith(":lookup") else None
        with self._request_budget.attempt(operation=operation, uid=uid):
            pass
        os.write(1, b"dispatch-reached\\n")
        time.sleep(60)
    def require(self, *args):
        return shadow.Instance.require(self, *args)
shadow.run_sequence(Hung(), Path(sys.argv[1]))
'''
    child = subprocess.Popen([sys.executable, "-I", "-S", "-B", "-c", script, str(tmp_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        ready, _, _ = select.select([child.stdout], [], [], 10)
        assert ready, "child did not reach dispatch"
        assert os.read(child.stdout.fileno(), 1024) == b"dispatch-reached\n"
        child.kill()
        out, err = child.communicate(timeout=10)
        assert child.returncode < 0 and not err
        assert [row["kind"] for row in events(tmp_path)] == ["launch", "create-intent"]
        assert not any(row["kind"] == "create-ack" for row in events(tmp_path))
        checkpoint = load_checkpoint((tmp_path / "checkpoint.json").read_bytes())
        assert not run_complete(checkpoint)
    finally:
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=10)


@pytest.mark.parametrize("where", ["before-replace", "after-replace"])
def test_process_death_during_atomic_replace_keeps_old_or_new_complete_checkpoint(tmp_path, where):
    here = Path(__file__).resolve().parent
    script = f'''
import sys, os
from pathlib import Path
sys.path.insert(0, {str(here)!r})
from mfa_manifest import compile_campaign
from mfa_collector import initial_state
from mfa_persistence import RunPersistence
plan = compile_campaign("ab" * 16)
state = initial_state(plan, 100)
journal = RunPersistence(Path(sys.argv[1]), state, plan)
original = os.replace
def die(*args, **kwargs):
    if {where!r} == "after-replace": original(*args, **kwargs)
    os._exit(17)
os.replace = die
state["requests"] = 3
journal.save_checkpoint(state)
'''
    result = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", script, str(tmp_path)], capture_output=True, timeout=15)
    assert result.returncode == 17, result.stderr
    state = load_checkpoint((tmp_path / "checkpoint.json").read_bytes())
    assert state["requests"] == (0 if where == "before-replace" else 3)
    assert not run_complete(state)


def test_intent_directory_sync_failure_prevents_signup_even_when_file_is_visible(tmp_path, monkeypatch):
    sync = os.fsync
    event_syncs = 0
    def fail_second(fd):
        nonlocal event_syncs
        info = os.fstat(fd)
        root = tmp_path / "responsibility"
        if root.exists() and (info.st_dev, info.st_ino) == (root.stat().st_dev, root.stat().st_ino):
            event_syncs += 1
            if event_syncs == 2:
                raise OSError("intent directory sync failed")
        return sync(fd)
    monkeypatch.setattr(os, "fsync", fail_second)
    backend = Backend(tmp_path)
    with pytest.raises(OSError, match="intent directory sync"):
        shadow.run_sequence(backend, tmp_path)
    assert backend.requests == 0
    assert any(row["kind"] == "create-intent" for row in events(tmp_path))
    assert last_summary(tmp_path)["journalComplete"] is False
    assert last_summary(tmp_path)["resourceCleanupComplete"] is False


def test_positive_completed_sequence_keeps_observation_and_cleanup_separate(tmp_path, monkeypatch):
    from mfa_cases import observation_cases
    from mfa_collector import record_step
    def one_owned_account(instance, state, checkpoint, rows, accounts, *, journal):
        shadow._create_owned_account(instance, state, accounts, journal, ROLE, False)
        for case in observation_cases():
            expected = case["expectedLocal"]
            rows[case["id"]] = shadow._row(case["id"], expected["status"], expected["errorCode"])
            record_step(state, case["id"], expected, state["startedAt"], requests=0)
    monkeypatch.setattr(shadow, "_walk", one_owned_account)
    report = shadow.run_sequence(Backend(tmp_path, "normal"), tmp_path)
    assert report["recordingComplete"] is True
    assert report["recovery"]["cleanupVerified"] is True
    assert persistence.complete_summary(report["recovery"]["creationResponsibility"], 1)
    assert report["productionExecuted"] is False
    assert report["requestsCharged"] == 3


@pytest.mark.parametrize("action", ["intent", "ack", "checkpoint", "finalize"])
def test_finalized_record_cannot_be_reused_for_more_operations(tmp_path, action):
    _, state, journal = setup(tmp_path)
    journal.finalize(state)
    with pytest.raises(RuntimeError):
        {"intent": lambda: journal.intent(ROLE), "ack": lambda: journal.acknowledge(ROLE, "uid"),
         "checkpoint": lambda: journal.save_checkpoint(state), "finalize": lambda: journal.finalize(state)}[action]()
    journal.close()


def test_anonymous_walk_uses_the_same_owned_creation_path():
    # Guard the actual walk's late anonymous branch, not merely the helper.
    import inspect
    source = inspect.getsource(shadow._walk)
    assert 'account_for("interaction-anonymous", verified=False)' in source
    assert '"/v1/accounts:signUp"' not in source


@pytest.mark.parametrize("operation", ["initialize", "checkpoint", "finalize"])
def test_a_different_plan_cannot_replace_this_runs_binding(tmp_path, operation):
    plan = compile_campaign(NONCE)
    wrong = initial_state(compile_campaign("cd" * 16), 100)
    if operation == "initialize":
        with pytest.raises(ValueError, match="binding"):
            persistence.RunPersistence(tmp_path, wrong, plan)
        assert list(tmp_path.iterdir()) == []
    else:
        _, state, journal = setup(tmp_path)
        old = (tmp_path / "checkpoint.json").read_bytes()
        with pytest.raises(ValueError, match="different local run"):
            (journal.save_checkpoint if operation == "checkpoint" else journal.finalize)(wrong)
        assert (tmp_path / "checkpoint.json").read_bytes() == old
        journal.close()


def test_final_recovery_publication_failure_never_leaves_done_checkpoint(tmp_path, monkeypatch):
    from mfa_cases import observation_cases
    from mfa_collector import record_step
    def all_rows(instance, state, checkpoint, rows, accounts, *, journal):
        for case in observation_cases():
            expected = case["expectedLocal"]
            rows[case["id"]] = shadow._row(case["id"], expected["status"], expected["errorCode"])
            record_step(state, case["id"], expected, state["startedAt"], requests=0)
    monkeypatch.setattr(shadow, "_walk", all_rows)
    original = persistence._publish
    def fail(directory, name, data, **kwargs):
        if name.endswith("-recovery.json"):
            raise OSError("recovery publication failed")
        return original(directory, name, data, **kwargs)
    monkeypatch.setattr(persistence, "_publish", fail)
    with pytest.raises(OSError):
        shadow.run_sequence(Backend(tmp_path), tmp_path)
    state = load_checkpoint((tmp_path / "checkpoint.json").read_bytes())
    assert state["aborted"] is True
    assert state["abortReason"] == "local-finalization-pending"
    assert not run_complete(state)


def test_final_outcome_requires_prior_recovery_and_cannot_clear_unknown(tmp_path):
    _, state, journal = setup(tmp_path)
    with pytest.raises(RuntimeError):
        journal.finish_checkpoint(state)
    journal.intent(ROLE)
    summary = journal.finalize(state)
    assert summary["unresolvedCreations"] == 1
    with pytest.raises(ValueError):
        journal.finish_checkpoint(state)
    state["aborted"] = True
    state["abortReason"] = "local-responsibility-incomplete"
    journal.finish_checkpoint(state)
    with pytest.raises(RuntimeError):
        journal.finish_checkpoint(state)
    assert not run_complete(load_checkpoint((tmp_path / "checkpoint.json").read_bytes()))
    journal.close()
