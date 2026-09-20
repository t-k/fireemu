"""Offline recovery evidence inspection, not a live cleanup authorization test."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

import pytest
from o6_listen_resume import local_recovery_inspect as m
from o6_listen_resume import local_supervisor as sup
from o6_listen_resume.campaign import owned_paths

NONCE = "a" * 32
PROJECT = "demo-recovery-local"
UID = "same-run-private-user"
GOOD = dict(complete=True, accountCleanupComplete=True, clientsComplete=True, documentsCleanupComplete=True)
BAD = {**GOOD, "complete": False}


def put(path, value):
    path.write_bytes(sup._encode(value))
    path.chmod(0o600)


def root_run(tmp_path, phases=(0, 1, 2, 3), *, final=BAD):
    root = tmp_path / "run"
    root.mkdir(mode=0o700)
    (root / "checkpoints").mkdir(mode=0o700)
    inputs = {"campaign.json": m.campaign_document(NONCE), "catalog.json": m.cases_document(),
              "budget.json": m.budget_document()}
    for name, value in inputs.items():
        put(root / name, value)
    launch = dict(schema=sup.SCHEMA, nonce=NONCE, projectId=PROJECT,
                  accountEmail=f"o6-{NONCE}@example.test", firestoreEndpoint="127.0.0.1:18081",
                  authEndpoint="127.0.0.1:18082", timeoutSeconds=820.0,
                  sourceDigests=sup._bindings(),
                  inputDigests={name: sup._sha((root / name).read_bytes()) for name in inputs},
                  productionExecuted=False, authorizesCleanup=False,
                  recoveryState="possibly-outstanding-until-typed-completion")
    put(root / "launch.json", launch)
    previous = None
    for index in phases:
        value = {"uid": UID, "paths": owned_paths(NONCE, UID)} if index == 2 else final if index == 4 else {}
        item = dict(schema="local-listen-checkpoint-v1", phase=m.PHASES[index], nonce=NONCE,
                    projectId=PROJECT, accountEmail=launch["accountEmail"], previousSha256=previous,
                    authorizesCleanup=False, value=value)
        file = root / "checkpoints" / m.CHECKPOINTS[index]
        put(file, item)
        previous = sup._sha(file.read_bytes())
    return root


def change(path, transform):
    value = json.loads(path.read_bytes())
    value = transform(value)
    put(path, value)


def parent(root, **overrides):
    value = dict(schema=sup.SCHEMA, nonceDigest=sup._sha(NONCE.encode()), productionExecuted=False,
                 authorizesCleanup=False, completed=True, resourceCleanupComplete=True,
                 processCleanupComplete=True, recoveryRequired=False)
    value.update(overrides)
    put(root / "result.json", value)


def unchanged(root):
    return {str(p.relative_to(root)): (p.read_bytes(), p.stat().st_mode)
            for p in root.rglob("*") if p.is_file()}


def assert_no_authority(result):
    assert result["authorizesCleanup"] is False
    assert result["productionExecuted"] is False
    assert result["currentArtifactVerified"] is False
    assert result["currentResourceStateVerified"] is False
    assert result["processStateVerified"] is False
    assert result["requiresLiveRevalidation"] is True
    assert "recoveryRequired" not in result  # never replaces the supervisor's live judgment


@pytest.mark.parametrize("phases,account,docs", [
    ((), "not-recorded", 0), ((0,), "not-recorded", 0), ((0, 4), "not-recorded", 0),
    ((0, 1), "attempted-outcome-unknown", 0), ((0, 1, 4), "attempted-outcome-unknown", 0),
    ((0, 1, 2), "acknowledgement-recorded-current-state-unknown", 5),
    ((0, 1, 2, 4), "acknowledgement-recorded-current-state-unknown", 5),
    ((0, 1, 2, 3), "acknowledgement-recorded-current-state-unknown", 5),
    ((0, 1, 2, 3, 4), "acknowledgement-recorded-current-state-unknown", 5),
])
def test_each_interruption_point_retains_only_recorded_scope(tmp_path, phases, account, docs):
    root = root_run(tmp_path, phases)
    before = unchanged(root)
    result = m.inspect(root)
    assert result["evidenceIntact"] is True, result
    assert result["sourceMatchesCurrent"] is True
    assert result["inputsMatchCurrent"] is True
    assert result["candidateScope"]["accountCreation"] == account
    assert len(result["candidateScope"]["documents"]) == docs
    assert len(result["verifiedPrefix"]) == len(phases)
    assert result["disposition"] == "review-recorded-responsibility"
    assert unchanged(root) == before
    for item in result["candidateScope"]["documents"]:
        assert item["creationProven"] is False and item["versionEvidence"] is None
    assert_no_authority(result)


def test_recorded_success_is_never_live_absence_or_deletion_permission(tmp_path):
    root = root_run(tmp_path, (0, 1, 2, 3, 4), final=GOOD)
    parent(root)
    result = m.inspect(root)
    assert result["evidenceIntact"]
    assert result["parentCompletionClaim"] == "reported"
    assert result["disposition"] == "review-recorded-completion"
    assert len(result["candidateScope"]["documents"]) == 5
    assert_no_authority(result)


@pytest.mark.parametrize("field", ["completed", "resourceCleanupComplete", "processCleanupComplete", "recoveryRequired"])
@pytest.mark.parametrize("value", [1, 0, None, "true"])
def test_parent_untyped_flags_do_not_clear_responsibility(tmp_path, field, value):
    root = root_run(tmp_path, (0, 1, 2, 3, 4), final=GOOD)
    parent(root, **{field: value})
    result = m.inspect(root)
    assert not result["evidenceIntact"]
    assert len(result["candidateScope"]["documents"]) == 5
    assert_no_authority(result)


@pytest.mark.parametrize("overrides", [
    {"nonceDigest": "b" * 64}, {"productionExecuted": True}, {"authorizesCleanup": True},
    {"resourceCleanupComplete": False}, {"processCleanupComplete": False}, {"recoveryRequired": True},
])
def test_wrong_run_and_contradictory_parent_claims_are_rejected(tmp_path, overrides):
    root = root_run(tmp_path, (0, 1, 2, 3, 4), final=GOOD)
    parent(root, **overrides)
    result = m.inspect(root)
    assert not result["evidenceIntact"]
    assert_no_authority(result)


def test_parent_success_after_unknown_signup_cannot_invent_uid(tmp_path):
    root = root_run(tmp_path, (0, 1, 4))
    parent(root)
    result = m.inspect(root)
    assert not result["evidenceIntact"]
    assert result["candidateScope"]["accountCreation"] == "attempted-outcome-unknown"
    assert result["candidateScope"]["uid"] is None


@pytest.mark.parametrize("tail", [b'{"value":', b'{}', b'null', b'{"a":1,"a":2}',
                                   b'{"v":NaN}', '{"v":1}'.encode('utf-16')])
def test_invalid_tail_preserves_the_earlier_verified_account_scope(tmp_path, tail):
    root = root_run(tmp_path)
    file = root / "checkpoints" / m.CHECKPOINTS[4]
    file.write_bytes(tail); file.chmod(0o600)
    result = m.inspect(root)
    assert not result["evidenceIntact"]
    assert len(result["verifiedPrefix"]) == 4
    assert result["candidateScope"]["uid"] == UID
    assert result["candidateScope"]["uncertaintyAfterVerifiedPrefix"]
    assert_no_authority(result)


@pytest.mark.parametrize("index", [0, 1, 2])
def test_deleted_chain_prefix_is_not_repaired(tmp_path, index):
    root = root_run(tmp_path)
    (root / "checkpoints" / m.CHECKPOINTS[index]).unlink()
    before = unchanged(root)
    result = m.inspect(root)
    assert not result["evidenceIntact"]
    assert len(result["verifiedPrefix"]) == index
    assert unchanged(root) == before


@pytest.mark.parametrize("mutate", [
    lambda v: {**v, "nonce": "b" * 32}, lambda v: {**v, "previousSha256": "0" * 64},
    lambda v: {**v, "authorizesCleanup": True}, lambda v: {**v, "phase": "ready"},
    lambda v: {**v, "value": {**v["value"], "uid": "different"}},
    lambda v: {**v, "value": {**v["value"], "paths": {}}},
    lambda v: {**v, "password": "DO-NOT-PRINT"},
])
def test_mutated_ack_never_becomes_cleanup_scope(tmp_path, mutate):
    root = root_run(tmp_path)
    change(root / "checkpoints" / m.CHECKPOINTS[2], mutate)
    result = m.inspect(root)
    assert not result["evidenceIntact"]
    assert result["candidateScope"]["uid"] is None
    assert result["candidateScope"]["accountCreation"] == "attempted-outcome-unknown"
    assert "DO-NOT-PRINT" not in json.dumps(result)


@pytest.mark.parametrize("field", ["accountCleanupComplete", "clientsComplete", "documentsCleanupComplete"])
def test_contradictory_completion_is_refused_by_inspector_and_supervisor(tmp_path, field):
    root = root_run(tmp_path, (0, 1, 2, 3, 4), final={**GOOD, field: False})
    result = m.inspect(root)
    assert not result["evidenceIntact"]
    assert "contradictory-checkpoint-completion" in result["issues"]
    with pytest.raises(sup.Refused, match="contradictory-lifecycle-completion"):
        sup._journal_summary(root / "checkpoints", NONCE, PROJECT)


@pytest.mark.parametrize("phases", [(0, 4), (0, 1, 4), (0, 1, 2, 4)])
def test_premature_success_is_refused_in_both_readers(tmp_path, phases):
    root = root_run(tmp_path, phases, final=GOOD)
    assert not m.inspect(root)["evidenceIntact"]
    with pytest.raises(sup.Refused, match="contradictory-lifecycle-completion"):
        sup._journal_summary(root / "checkpoints", NONCE, PROJECT)


@pytest.mark.parametrize("name", m.INPUTS)
def test_input_digest_drift_is_not_silently_rebased(tmp_path, name):
    root = root_run(tmp_path)
    (root / name).write_bytes((root / name).read_bytes() + b" ")
    result = m.inspect(root)
    assert not result["evidenceIntact"]
    assert "input-digest-mismatch" in result["issues"]


def test_historical_source_drift_retains_scope_but_cannot_authorize_reuse(tmp_path):
    root = root_run(tmp_path)
    change(root / "launch.json", lambda v: {**v, "sourceDigests": {k: "b" * 64 for k in v["sourceDigests"]}})
    result = m.inspect(root)
    assert result["evidenceIntact"]
    assert result["sourceMatchesCurrent"] is False
    assert len(result["candidateScope"]["documents"]) == 5
    assert_no_authority(result)


def test_rehashed_different_inputs_are_reported_not_treated_as_current(tmp_path):
    root = root_run(tmp_path)
    change(root / "budget.json", lambda v: {**v, "budget": {**v["budget"], "maxDocuments": 9999}})
    change(root / "launch.json", lambda v: {**v, "inputDigests": {
        **v["inputDigests"], "budget.json": sup._sha((root / "budget.json").read_bytes())}})
    result = m.inspect(root)
    assert result["evidenceIntact"] and result["inputsMatchCurrent"] is False
    assert len(result["candidateScope"]["documents"]) == 5  # never widens scope from the changed budget
    assert_no_authority(result)


@pytest.mark.parametrize("field,value", [("productionExecuted", True), ("authorizesCleanup", True),
    ("projectId", "production-project"), ("firestoreEndpoint", "remote.invalid:443"),
    ("authEndpoint", "localhost:8080"), ("timeoutSeconds", float("nan")), ("timeoutSeconds", 10**400),
    ("nonce", "bad"), ("accountEmail", "other@example.test"), ("sourceDigests", {"../../secrets": "a" * 64})])
def test_invalid_launch_never_yields_actionable_scope(tmp_path, field, value):
    root = root_run(tmp_path)
    launch = json.loads((root / "launch.json").read_bytes()); launch[field] = value
    (root / "launch.json").write_text(json.dumps(launch))
    result = m.inspect(root)
    assert not result["evidenceIntact"]
    assert result["candidateScope"] is None
    assert_no_authority(result)


@pytest.mark.parametrize("relative", ["launch.json", "result.json", "checkpoints/2-account-created.json"])
@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "public", "oversize"])
def test_unsafe_files_are_not_followed_or_blocked_on(tmp_path, relative, kind):
    root = root_run(tmp_path)
    target = root / relative
    valid = target.read_bytes() if target.exists() else sup._encode(dict(
        schema=sup.SCHEMA, nonceDigest=sup._sha(NONCE.encode()), productionExecuted=False,
        authorizesCleanup=False, completed=False, resourceCleanupComplete=False,
        processCleanupComplete=False, recoveryRequired=True))
    if target.exists(): target.unlink()
    other = tmp_path / "private-secret"; other.write_bytes(b"DO-NOT-PRINT"); other.chmod(0o600)
    if kind == "symlink": target.symlink_to(other)
    elif kind == "hardlink": os.link(other, target)
    elif kind == "fifo": os.mkfifo(target, 0o600)
    elif kind == "public": target.write_bytes(valid); target.chmod(0o644)
    else: target.write_bytes(b"x" * (m.MAX_FILE + 1)); target.chmod(0o600)
    result = m.inspect(root)
    assert not result["evidenceIntact"]
    assert "DO-NOT-PRINT" not in json.dumps(result)
    assert relative not in {item["file"] for item in result.get("evidenceFiles", [])}


@pytest.mark.parametrize("which", ["root", "checkpoints", "parent"])
def test_symlink_directory_components_are_refused(tmp_path, which):
    root = root_run(tmp_path)
    if which == "root":
        alias = tmp_path / "alias"; alias.symlink_to(root, target_is_directory=True); root = alias
    elif which == "checkpoints":
        actual = root / "real"; (root / "checkpoints").rename(actual); (root / "checkpoints").symlink_to(actual)
    else:
        alias = tmp_path / "alias"; alias.symlink_to(tmp_path, target_is_directory=True); root = alias / "run"
    assert not m.inspect(root)["evidenceIntact"]


def test_unknown_tail_entry_is_not_read_and_preserves_prefix(tmp_path):
    root = root_run(tmp_path, (0, 1, 2, 3, 4))
    (root / "checkpoints" / "6-DO-NOT-PRINT").symlink_to("/no/such/file")
    result = m.inspect(root)
    assert not result["evidenceIntact"]
    assert len(result["verifiedPrefix"]) == 5
    assert result["candidateScope"]["uid"] == UID
    assert "DO-NOT-PRINT" not in json.dumps(result)


@pytest.mark.parametrize("mutation", ["earlier-bytes", "earlier-mode", "new-report", "replaced-directory"])
def test_concurrent_changes_cannot_be_certified_as_stable(tmp_path, monkeypatch, mutation):
    root = root_run(tmp_path)
    original = m.Archive.stable
    changed = False
    def stable(archive):
        nonlocal changed
        if not changed:
            changed = True
            file = root / "checkpoints" / m.CHECKPOINTS[0]
            if mutation == "earlier-bytes": file.write_bytes(file.read_bytes().replace(b"ready", b"wrong"))
            elif mutation == "earlier-mode": file.chmod(0o644)
            elif mutation == "new-report": parent(root)
            else:
                (root / "checkpoints").rename(root / "old-checkpoints")
                (root / "checkpoints").mkdir(mode=0o700)
        return original(archive)
    monkeypatch.setattr(m.Archive, "stable", stable)
    assert not m.inspect(root)["evidenceIntact"]


def test_inspection_performs_no_network_process_signal_or_sdk_operation(tmp_path, monkeypatch):
    root = root_run(tmp_path)
    def forbidden(*_args, **_kwargs): pytest.fail("inspector must be offline and read-only")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "kill", forbidden)
    monkeypatch.setattr(os, "killpg", forbidden)
    before = unchanged(root)
    result = m.inspect(root)
    assert result["evidenceIntact"]
    assert unchanged(root) == before


@pytest.mark.parametrize("where", ["same", "inside", "ancestor", "existing", "symlink"])
def test_output_never_overwrites_input_or_existing_evidence(tmp_path, where):
    root = root_run(tmp_path)
    output = {"same":root, "inside":root / "inspection", "ancestor":tmp_path,
              "existing":tmp_path / "old", "symlink":tmp_path / "link"}[where]
    if where == "existing": output.mkdir()
    if where == "symlink": output.symlink_to(tmp_path / "missing")
    before = unchanged(root)
    with pytest.raises((m.InvalidEvidence, OSError)):
        m.run(root, output)
    assert unchanged(root) == before


def test_cli_saves_private_scope_but_prints_only_fixed_public_summary(tmp_path):
    root = root_run(tmp_path)
    before = unchanged(root)
    output = tmp_path / "inspection"
    p = subprocess.run([sys.executable, "-I", "-S", "-B", str(Path(m.__file__).resolve()),
                        "--run", str(root), "--output", str(output)], capture_output=True, text=True, timeout=10)
    assert p.returncode == 0, p.stderr
    public = json.loads(p.stdout)
    assert public["knownAccount"] and public["candidateDocuments"] == 5
    assert public["authorizesCleanup"] is False and public["requiresLiveRevalidation"]
    for secret in (UID, NONCE, PROJECT, "example.test", "127.0.0.1", "o6_listen/"):
        assert secret not in p.stdout + p.stderr
    private = json.loads((output / "inspection.json").read_bytes())
    assert private["candidateScope"]["uid"] == UID
    assert output.stat().st_mode & 0o777 == 0o700
    assert (output / "inspection.json").stat().st_mode & 0o777 == 0o600
    assert unchanged(root) == before


def test_invalid_tail_cli_nonzero_still_records_known_scope(tmp_path):
    root = root_run(tmp_path)
    put(root / "checkpoints" / m.CHECKPOINTS[4], {})
    out = tmp_path / "inspection"
    code = m.main(["--run", str(root), "--output", str(out)])
    assert code == 1
    private = json.loads((out / "inspection.json").read_bytes())
    assert private["candidateScope"]["uid"] == UID


def test_publication_failure_never_prints_success_or_mutates_input(tmp_path, monkeypatch, capsys):
    root = root_run(tmp_path)
    before = unchanged(root)
    def fail(*_args): raise OSError("DO-NOT-PRINT")
    monkeypatch.setattr(os, "fsync", fail)
    assert m.main(["--run", str(root), "--output", str(tmp_path / "out")]) == 2
    out = capsys.readouterr()
    assert out.out == "" and "DO-NOT-PRINT" not in out.err
    assert unchanged(root) == before


def test_actual_node_checkpoint_writer_interoperates_without_firebase_sdk(tmp_path):
    root = root_run(tmp_path, ())
    code = '''
      import {createLifecycleJournal} from './tools/compat-broad/fs-listen-resume/listen_journal.mjs';
      import {ownedPaths} from './tools/compat-broad/fs-listen-resume/listen_collector.mjs';
      const [dir, nonce, projectId, uid] = process.argv.slice(1);
      const checkpoint = createLifecycleJournal(dir, {nonce, projectId});
      checkpoint('account-create-intent');
      checkpoint('account-created', {uid, paths: ownedPaths(nonce, uid)});
      checkpoint('documents-at-risk');
      checkpoint('lifecycle-result', {complete:false, accountCleanupComplete:false,clientsComplete:true,documentsCleanupComplete:false});
    '''
    p = subprocess.run(["node", "--input-type=module", "-e", code, str(root / "checkpoints"), NONCE, PROJECT, UID],
                       cwd=sup.ROOT, text=True, capture_output=True, timeout=10)
    assert p.returncode == 0, p.stderr
    result = m.inspect(root)
    assert result["evidenceIntact"] and len(result["verifiedPrefix"]) == 5
    existing = sup._journal_summary(root / "checkpoints", NONCE, PROJECT)
    assert existing["checkpoints"] == result["verifiedPrefix"]
    assert_no_authority(result)


@pytest.mark.parametrize("fault", ["missing-input", "changed-input", "missing-current-source", "no-checkpoint-directory"])
def test_other_missing_evidence_does_not_erase_known_or_unknown_responsibility(tmp_path, monkeypatch, fault):
    root = root_run(tmp_path)
    if fault == "missing-input": (root / "budget.json").unlink()
    elif fault == "changed-input": (root / "budget.json").write_bytes(b"{}")
    elif fault == "missing-current-source":
        def missing(): raise OSError("DO-NOT-PRINT")
        monkeypatch.setattr(sup, "_bindings", missing)
    else:
        for p in (root / "checkpoints").iterdir(): p.unlink()
        (root / "checkpoints").rmdir()
    result = m.inspect(root)
    assert not result["evidenceIntact"]
    if fault != "no-checkpoint-directory":
        assert result["candidateScope"]["uid"] == UID
        assert len(result["candidateScope"]["documents"]) == 5
    else:
        assert result["candidateScope"]["accountCreation"] == "not-yet-inspected"
        assert result["candidateScope"]["documentsAtRisk"] is None
    assert "DO-NOT-PRINT" not in json.dumps(result)
    assert_no_authority(result)


def test_owned_zero_length_truncated_ack_keeps_signup_unknown(tmp_path):
    root = root_run(tmp_path, (0, 1))
    target = root / "checkpoints" / m.CHECKPOINTS[2]
    target.touch(mode=0o600)
    result = m.inspect(root)
    assert not result["evidenceIntact"]
    assert result["candidateScope"]["accountCreation"] == "attempted-outcome-unknown"
    assert result["candidateScope"]["uid"] is None
    assert target.read_bytes() == b""  # never fills in a partial ACK


def test_rehashed_but_out_of_scope_path_is_not_admitted(tmp_path):
    root = root_run(tmp_path)
    path = root / "checkpoints" / m.CHECKPOINTS[2]
    change(path, lambda v: {**v, "value": {**v["value"], "paths": {
        **v["value"]["paths"], "alpha": "foreign/target"}}})
    digest = sup._sha(path.read_bytes())
    change(root / "checkpoints" / m.CHECKPOINTS[3], lambda v: {**v, "previousSha256": digest})
    result = m.inspect(root)
    assert not result["evidenceIntact"]
    assert result["candidateScope"]["uid"] is None
    assert "foreign/target" not in json.dumps(result)


def test_unauthenticated_coherent_history_is_not_a_live_state_attestation(tmp_path):
    # A same-user writer can produce this whole internally consistent fixture.
    # Its valid hashes do not authenticate the writer or establish current state.
    root = root_run(tmp_path, (0, 1, 2, 3, 4), final=GOOD)
    parent(root)
    result = m.inspect(root)
    assert result["evidenceIntact"]
    assert_no_authority(result)
    assert "verify-current-emulator-instance-not-merely-recorded-loopback-ports" in result["requiredBeforeAnyRecovery"]
