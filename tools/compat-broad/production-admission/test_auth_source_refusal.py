"""Offline-only Auth forensic retirement, with real temporary Ledger and Gate."""

import copy
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(
    0, str(Path(__file__).resolve().parent.parent / "auth-credential-tokens")
)
from broad_contract import digest
from reservations import Ledger

KNOWN_COMMIT = "4bb0e9a4204d7bbaeefd9e028bea8dd85417c7fb"
LANE = "tools/compat-broad/auth-credential-tokens"
REPO = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def historical_source(tmp_path_factory):
    import credential_descriptor as campaign

    source = tmp_path_factory.mktemp("frozen-auth-source")
    names = subprocess.check_output(
        ["git", "ls-tree", "-r", "--name-only", KNOWN_COMMIT, LANE], cwd=REPO, text=True
    ).splitlines()
    names = [name for name in names if name.endswith(".py")] + list(
        campaign.SHARED_SOURCES
    )
    hashes = {}
    for name in names:
        raw = subprocess.check_output(
            ["git", "show", f"{KNOWN_COMMIT}:{name}"], cwd=REPO
        )
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        hashes[name] = hashlib.sha256(raw).hexdigest()
    assert (
        digest(hashes)
        == "e6de1dd5670494cefeacc4bb021ac6d81cd86049f929afe5784afd0298387292"
    )
    return source, hashes


CHILD = r"""
import json, pathlib, subprocess, sys
import credential_gate, credential_responsibility, credential_remote_transport
from shared_gate import Gate
root, source = map(pathlib.Path, sys.argv[1:])
plan = json.loads((root / 'plan.json').read_bytes())
credential_gate.create(root / 'gate', plan)
gate = Gate(root / 'gate', 'auth-credential')
gate.claim()
for slot in plan['management']['observation'][:10]:
    body = {'syntheticOfflineManagementFixture':True}
    if slot['id'] == 'oauth-tokeninfo':
        body = {'kind':'request-byte-token-attestation-v1','principalDigest':'a'*64,
            'identityMode':'subject','expiresInSeconds':3600,'remainingSecondsAtVerification':3500,
            'requiredSeconds':600,**{k:True for k in ('requiredScopeVerified','identityVerified',
                'oauthClientVerified','complete','workerReaped')}}
    gate.management_dispatch('observation', slot['id'], lambda deadline: {
        'status':200, 'complete':True, 'workerReaped':True, 'bodyKind':'json',
        'body':body})
tracker = {'nonce': plan['nonce']}
inputs = json.loads((root / 'inputs.json').read_bytes())
credential_responsibility.attach(tracker, root / 'responsibility', {
    'sourceCommit': inputs['sourceCommit'], 'inputsDigest': inputs['inputsDigest']})
operation = plan['jobs']['auth-credential']['observation'][0]
credential_responsibility.begin(tracker, 'signup', email=operation['body']['email'])
def send():
    worker = source / 'tools/compat-broad/auth-credential-tokens/credential_https_worker.py'
    result = subprocess.run([sys.executable, '-I', '-S', '-B', str(worker)],
        input=json.dumps({'url':'https://' + operation['path'] + '?key=synthetic',
            'body':json.dumps({'email':'synthetic@example.invalid','password':'synthetic'}),
            'headers':{},'seconds':1}).encode(),capture_output=True,timeout=3)
    assert result.returncode == 2 and not result.stdout and not result.stderr
    raise credential_remote_transport.WorkerFailure('synthetic frozen refusal', worker_reaped=True)
try:
    gate.dispatch(operation, False, send)
except credential_remote_transport.WorkerFailure:
    pass
credential_responsibility.close(tracker)
"""


def incident(tmp_path, historical_source):
    import credential_descriptor as campaign
    import credential_gate
    from shared_gate import Gate

    source, hashes = historical_source
    output = tmp_path / "execution"
    output.mkdir()
    nonce = "d" * 32
    permission = {
        "kind": "auth-credential-owner-execution-permission-v1",
        "nonce": nonce,
        "ownerIdentity": "synthetic-owner",
        "recoveryOwner": "synthetic-recovery",
        "sourceCommit": KNOWN_COMMIT,
        "sourceInputs": hashes,
    }
    inputs = {
        "kind": "auth-credential-frozen-inputs-v1",
        "sourceCommit": KNOWN_COMMIT,
        "sourceInputs": hashes,
        "permission": permission,
        "permissionDigest": digest(permission),
    }
    inputs["inputsDigest"] = digest(inputs)
    prep_permission = {
        **permission,
        "kind": "auth-credential-bootstrap-permission-v1",
        "fixtureOrigin": None,
    }
    prep_inputs = {
        **inputs,
        "kind": "auth-credential-bootstrap-frozen-inputs-v1",
        "permission": prep_permission,
        "permissionDigest": digest(prep_permission),
    }
    prep_inputs["inputsDigest"] = digest(
        {k: v for k, v in prep_inputs.items() if k != "inputsDigest"}
    )
    plan = credential_gate.bootstrap_plan(
        campaign.compile_gate_plan(nonce, signing=True),
        permission_digest=digest(prep_permission),
    )
    plan["collectorSourceDigest"] = digest(hashes)
    plan["permissionExpiresAt"] = time.time() + 600
    generation = {
        "sourceCommit": KNOWN_COMMIT,
        "collectorSourceDigest": digest(hashes),
        "sourceDigests": {
            Path(name).name: hashes[name] for name in campaign.ABORT_CLOSURE_SOURCES
        },
    }
    ledger = Ledger.create(tmp_path / "ledger")
    claim = {
        "campaignId": campaign.CAMPAIGN,
        "manifestDigest": digest(plan),
        "nonceDigest": digest(nonce),
        "gatePath": str(output / "gate"),
        "gatePlanDigest": digest(plan),
        "gateJob": "auth-credential",
        "locks": campaign.lock_scopes(campaign.plan_compiler(nonce, signing=True)),
        "budget": campaign.ledger_budget(),
        "durationSeconds": 600,
    }
    envelope = {
        "permissionDigest": digest(prep_permission),
        "issuedAt": time.time() - 1,
        "expiresAt": time.time() + 900,
        "limits": claim["budget"],
        "concurrency": 1,
        "scopes": claim["locks"],
    }
    ticket = ledger.reserve(envelope, claim, plan, generation=generation)
    preparation = {
        "kind": "auth-credential-bootstrap-proof-v1",
        "fixtureOrigin": None,
        "nonce": nonce,
        "generation": generation,
        "ticket": ticket,
        "claimDigest": ticket["claimDigest"],
        "gatePlanDigest": digest(plan),
        "requestCount": 4,
        "inputsDigest": prep_inputs["inputsDigest"],
        "permissionDigest": digest(prep_permission),
        "reservationDeadline": ledger.snapshot()["reservations"][ticket["reservation"]][
            "deadline"
        ],
    }
    import credential_bootstrap

    permission["bootstrap"] = credential_bootstrap.observation_binding(preparation)
    inputs["permissionDigest"] = digest(permission)
    inputs["inputsDigest"] = digest(
        {k: v for k, v in inputs.items() if k != "inputsDigest"}
    )
    for name, value in (
        ("inputs.json", inputs),
        ("preparation-inputs.json", prep_inputs),
        ("plan.json", plan),
    ):
        (output / name).write_text(json.dumps(value))
    search = [
        REPO / "tools/compat-broad",
        REPO / LANE,
        REPO / "tools/compat-broad/production-admission",
    ]
    child = subprocess.run(
        [sys.executable, "-c", CHILD, str(output), str(source)],
        env={
            "PYTHONPATH": os.pathsep.join(map(str, search)),
            "PATH": os.environ["PATH"],
        },
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert child.returncode == 0, child.stderr
    gate = Gate(output / "gate", "auth-credential").snapshot()
    receipt = {
        "kind": "auth-credential-acquisition-receipt-v1",
        "campaignId": campaign.CAMPAIGN,
        "ticket": ticket,
        "claimDigest": ticket["claimDigest"],
        "planDigest": digest(plan),
        "gateDigest": digest(gate),
        "generation": generation,
        "inputsDigest": inputs["inputsDigest"],
        "permissionDigest": digest(permission),
        "reservationStateAtPublication": "held",
        "releaseEligible": False,
        "executionKind": "fixed-production-wire",
        "productionExecuted": True,
        "chargedCalls": 11,
        "failure": "collection-incomplete",
        "stopPoint": "sign-up-unsettled",
        "preflightComplete": True,
        "postflightComplete": False,
        "workerSha256": hashes[f"{LANE}/credential_https_worker.py"],
        "metadata": [
            {
                "id": "observation:000",
                "route": plan["jobs"]["auth-credential"]["observation"][0]["path"],
                "status": None,
                "responseDigest": digest(None),
            }
        ],
    }
    receipt["routeDigest"] = digest(receipt["metadata"])
    receipt["preparationProof"] = preparation
    (output / "preparation-proof.json").write_text(json.dumps(preparation))
    approval = {
        "kind": "auth-credential-o8-approval-v1",
        "status": "approved",
        "campaignId": campaign.CAMPAIGN,
        "sourceCommit": KNOWN_COMMIT,
        "sourceInputsDigest": digest(hashes),
        "inputsDigest": inputs["inputsDigest"],
        "permissionDigest": digest(permission),
        "nonceDigest": digest(nonce),
        "ledgerRoot": str(ledger.path),
        "launcherSha256": hashes[f"{LANE}/credential_bootstrap.py"],
    }
    (tmp_path / "approval.json").write_text(json.dumps(approval))
    admission = {
        "approvalDigest": digest(approval),
        "bootstrap": permission["bootstrap"],
        "inputsDigest": inputs["inputsDigest"],
    }
    (output / "observation-admission.json").write_text(json.dumps(admission))
    receipt["observationApprovalDigest"] = digest(admission)
    (output / "receipt.json").write_text(json.dumps(receipt))
    return ledger, ticket, output, source


def resolution(ledger, ticket, output, source, **changes):
    import credential_source_refusal as refusal

    record = refusal.prepare_resolution(
        ticket=ticket,
        receipt_path=output / "receipt.json",
        source_root=source,
        approval_path=output.parent / "approval.json",
    )
    now = time.time()
    record["attestation"] = {
        "kind": "auth-source-refusal-attestation-v1",
        "status": "approved",
        "purpose": "retire-source-proven-unsent",
        "resolutionDigest": digest(
            {k: v for k, v in record.items() if k != "attestation"}
        ),
        "ownerIdentity": "synthetic-owner",
        "recoveryOwner": "synthetic-recovery",
        "reviewerIdentity": "independent-fixture-reviewer",
        "attestedAt": now - 1,
        "expiresAt": now + 120,
        "executionHost": {
            "platform": platform.system().lower(),
            "machine": platform.machine(),
        },
    }
    record["attestation"].update(changes)
    return record


def test_exact_source_refusal_retires_without_rewriting_history(
    tmp_path, historical_source
):
    ledger, ticket, output, source = incident(tmp_path, historical_source)
    record = resolution(ledger, ticket, output, source)
    original = {str(p): p.read_bytes() for p in output.rglob("*") if p.is_file()}
    before = ledger.snapshot()
    ledger.close_after_source_refusal(ticket, record)
    final = ledger.snapshot()
    row = final["reservations"][ticket["reservation"]]
    assert row["state"] == "closed-after-escalation"
    assert row["resolutionDisposition"] == "source-proven-unsent"
    assert (
        row["claim"]["budget"]
        == before["reservations"][ticket["reservation"]]["claim"]["budget"]
    )
    assert all(Path(p).read_bytes() == raw for p, raw in original.items())
    ledger.close_after_source_refusal(ticket, record)
    assert ledger.snapshot() == final
    changed = copy.deepcopy(record)
    changed["attestation"]["reviewerIdentity"] = "another-independent-reviewer"
    with pytest.raises(ValueError, match="different terminal"):
        ledger.close_after_source_refusal(ticket, changed)
    assert ledger.snapshot() == final
    from reservations import task_spent_microusd

    assert task_spent_microusd(final, "AUTH-CREDENTIAL-TOKENS-01") == 50_000
    for key, value in before.items():
        if key != "reservations":
            assert final[key] == value
    # An actual subsequent reservation can acquire the released namespace lock,
    # while both permanent task allocations remain charged. No worker is started.
    import credential_descriptor as campaign
    import credential_gate

    nonce = "e" * 32
    plan = credential_gate.bootstrap_plan(
        campaign.compile_gate_plan(nonce, signing=True), permission_digest="b" * 64
    )
    next_claim = {
        **row["claim"],
        "nonceDigest": digest(nonce),
        "manifestDigest": digest(plan),
        "gatePath": str(tmp_path / "next-gate"),
        "gatePlanDigest": digest(plan),
        "locks": campaign.lock_scopes(campaign.plan_compiler(nonce, signing=True)),
    }
    next_envelope = {
        "permissionDigest": "b" * 64,
        "issuedAt": time.time() - 1,
        "expiresAt": time.time() + 900,
        "limits": next_claim["budget"],
        "concurrency": 1,
        "scopes": next_claim["locks"],
    }
    ledger.reserve(next_envelope, next_claim, plan, generation=row["generation"])
    assert task_spent_microusd(ledger.snapshot(), campaign.CAMPAIGN) == 100_000


@pytest.mark.parametrize(
    "damage",
    [
        "fixture-mode",
        "missing-mode",
        "receipt",
        "journal",
        "extra-journal",
        "worker",
        "transport",
        "launcher",
        "source-map",
        "route",
        "body",
        "extra-event",
        "nonce",
        "live-pid",
        "missing-authority",
        "stale-authority",
        "foreign-owner",
        "self-review",
        "purpose",
        "different-proof",
    ],
)
def test_source_refusal_refuses_drift_without_ledger_or_history_changes(
    tmp_path, historical_source, damage
):
    from shared_gate import Gate, _save

    ledger, ticket, output, source = incident(tmp_path, historical_source)
    record = resolution(ledger, ticket, output, source)
    if damage in {"fixture-mode", "missing-mode"}:
        path = output / "preparation-proof.json"
        value = json.loads(path.read_bytes())
        if damage == "fixture-mode":
            value["fixtureOrigin"] = "http://127.0.0.1:12345"
        else:
            del value["fixtureOrigin"]
        path.write_text(json.dumps(value))
        receipt = json.loads((output / "receipt.json").read_bytes())
        receipt["preparationProof"] = value
        (output / "receipt.json").write_text(json.dumps(receipt))
        record["receiptDigest"] = digest(receipt)
    elif damage in {"worker", "transport", "launcher"}:
        import shutil

        copied = tmp_path / "changed-source"
        shutil.copytree(source, copied)
        name = {
            "worker": "credential_https_worker.py",
            "transport": "credential_remote_transport.py",
            "launcher": "credential_bootstrap.py",
        }[damage]
        path = copied / LANE / name
        path.write_bytes(path.read_bytes() + b"\n# changed\n")
        record["sourceRoot"] = str(copied)
    elif damage in {"receipt", "journal", "source-map", "nonce"}:
        path = (
            output
            / {
                "receipt": "receipt.json",
                "journal": "responsibility/0001.json",
                "source-map": "inputs.json",
                "nonce": "responsibility/0001.json",
            }[damage]
        )
        value = json.loads(path.read_bytes())
        if damage == "nonce":
            value["nonce"] = "f" * 32
        else:
            value["unexpected"] = True
        path.write_text(json.dumps(value))
    elif damage == "extra-journal":
        (output / "responsibility/0002.json").write_text("{}")
    elif damage in {"route", "body", "extra-event", "live-pid"}:
        gate = Gate(output / "gate", "auth-credential")
        with gate.locked() as state:
            if damage == "live-pid":
                state["coordinatorPid"] = os.getpid()
            elif damage == "extra-event":
                state["events"].append(copy.deepcopy(state["events"][0]))
            else:
                op = state["plan"]["jobs"]["auth-credential"]["observation"][0]
                op["path" if damage == "route" else "body"] = (
                    "identitytoolkit.googleapis.com/v1/accounts:lookup"
                    if damage == "route"
                    else None
                )
                state["planDigest"] = digest(state["plan"])
            _save(gate.path, state)
        record["gateDigest"] = digest(
            json.loads((output / "gate/state.json").read_bytes())
        )
    elif damage == "missing-authority":
        record["attestation"] = None
    elif damage == "stale-authority":
        record["attestation"].update(
            attestedAt=time.time() - 200, expiresAt=time.time() - 100
        )
    elif damage == "foreign-owner":
        record["attestation"]["ownerIdentity"] = "foreign"
    elif damage == "self-review":
        record["attestation"]["reviewerIdentity"] = "synthetic-owner"
    elif damage == "purpose":
        record["attestation"]["purpose"] = "retry-signup"
    else:
        record["proof"]["attemptDispatched"] = True
    before = ledger.snapshot()
    ledger_bytes = (ledger.path / "state.json").read_bytes()
    original = {str(p): p.read_bytes() for p in output.rglob("*") if p.is_file()}
    with pytest.raises(ValueError):
        ledger.close_after_source_refusal(ticket, record)
    assert ledger.snapshot() == before
    assert (ledger.path / "state.json").read_bytes() == ledger_bytes
    assert all(Path(p).read_bytes() == raw for p, raw in original.items())


def test_source_refusal_never_accepts_a_caller_boolean(tmp_path):
    ledger = Ledger.create(tmp_path / "ledger")
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="exact Auth source-refusal"):
        ledger.close_after_source_refusal({}, {"attemptDispatched": False})
    assert ledger.snapshot() == before


def test_changed_parent_permission_cannot_be_rebound_by_new_resolution(
    tmp_path, historical_source
):
    import credential_source_refusal as refusal

    ledger, ticket, output, source = incident(tmp_path, historical_source)
    path = output / "preparation-inputs.json"
    value = json.loads(path.read_bytes())
    value["permission"]["ownerIdentity"] = "replacement-owner"
    value["permissionDigest"] = digest(value["permission"])
    value["inputsDigest"] = digest(
        {k: v for k, v in value.items() if k != "inputsDigest"}
    )
    path.write_text(json.dumps(value))
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="parent preparation"):
        refusal.prepare_resolution(
            ticket=ticket,
            receipt_path=output / "receipt.json",
            source_root=source,
            approval_path=output.parent / "approval.json",
        )
    assert ledger.snapshot() == before


@pytest.mark.parametrize("copied_source", [False, True])
def test_active_frozen_worker_refuses_without_fabricating_reaping(
    tmp_path, historical_source, copied_source
):
    import shutil

    import credential_source_refusal as refusal

    ledger, ticket, output, source = incident(tmp_path, historical_source)
    proof_source = source
    if copied_source:
        proof_source = tmp_path / "same-source-copy"
        shutil.copytree(source, proof_source)
    record = resolution(ledger, ticket, output, proof_source)
    process = subprocess.Popen(
        [sys.executable, "-I", "-S", "-B", str(source / refusal.WORKER)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    before = ledger.snapshot()
    try:
        assert process.poll() is None
        with pytest.raises(ValueError, match="worker still active"):
            ledger.close_after_source_refusal(ticket, record)
        assert ledger.snapshot() == before
    finally:
        process.communicate(input=b"", timeout=3)
    assert process.returncode == 2


def test_existing_child_link_keeps_parent_held(tmp_path, historical_source):
    ledger, ticket, output, source = incident(tmp_path, historical_source)
    record = resolution(ledger, ticket, output, source)
    before = ledger.snapshot()
    # Exercise the existing terminal guard without inventing a valid Auth child
    # allocation: this campaign has no authorized child producer.
    state = copy.deepcopy(before)
    state["reservations"][ticket["reservation"]]["recoveryChildren"] = [
        "synthetic-child"
    ]
    with pytest.raises(ValueError, match="recovery child"):
        ledger._terminal_row(
            state,
            ticket,
            record,
            digest_key="sourceRefusalRecordDigest",
            final="closed-after-escalation",
        )
    assert ledger.snapshot() == before


def test_replay_rechecks_immutable_history_even_after_retirement(
    tmp_path, historical_source
):
    ledger, ticket, output, source = incident(tmp_path, historical_source)
    record = resolution(ledger, ticket, output, source)
    ledger.close_after_source_refusal(ticket, record)
    before = ledger.snapshot()
    path = output / "responsibility/0001.json"
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(ValueError, match="proof differs"):
        ledger.close_after_source_refusal(ticket, record)
    assert ledger.snapshot() == before


def test_receipt_cannot_name_another_gate_even_with_a_fresh_proposal(
    tmp_path, historical_source
):
    import credential_source_refusal as refusal

    ledger, ticket, output, source = incident(tmp_path, historical_source)
    path = output / "receipt.json"
    receipt = json.loads(path.read_bytes())
    receipt["gateDigest"] = "0" * 64
    path.write_text(json.dumps(receipt))
    before = ledger.snapshot()
    with pytest.raises(ValueError, match="failure receipt"):
        refusal.prepare_resolution(
            ticket=ticket,
            receipt_path=path,
            source_root=source,
            approval_path=output.parent / "approval.json",
        )
    assert ledger.snapshot() == before
