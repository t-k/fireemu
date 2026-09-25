"""Planning-only null annotations must not change request-bound absence hashes."""
import copy
from pathlib import Path
import sys
from urllib.parse import quote

import pytest
sys.path.insert(0, str(Path(__file__).resolve().parent / "production-admission"))

import reservations
import shared_gate
from broad_contract import digest
from test_shared_read_completion import (
    ABSENT, READS, RESOURCE, VERSION, operation, plan, start,
)
from test_shared_read_completion import isolated  # noqa: F401 -- Reuse the autouse clock/network guard.


def complete(tmp_path, scheduled, annotate_first, annotate_final):
    frozen = plan(operation(*READS[0]), scheduled=scheduled)
    job = frozen["jobs"]["read"]
    job["recovery"] = [copy.deepcopy(op) for op in job["recovery"]]
    for index, enabled in ((0, annotate_first), (2, annotate_final)):
        if enabled:
            job["recovery"][index]["versionFrom"] = None
    ledger = reservations.Ledger.create(tmp_path / "ledger")
    claim = {
        "campaignId": "FS-DATA-WRITE-LIMITS-02", "gateJob": "read",
        "manifestDigest": digest("local-only"), "nonceDigest": digest(frozen["nonce"]),
        "gatePath": str((tmp_path / "gate").resolve()), "gatePlanDigest": digest(frozen),
        "locks": [{"key": "project/p/firestore/(default)/documents/campaign", "mode": "WRITE"}],
        "budget": {"requests": 5, "accounts": 0, "resources": 1, "costMicrousd": 20},
        "durationSeconds": 300,
    }
    envelope = {
        "permissionDigest": "a" * 64, "issuedAt": 1000, "expiresAt": 10000,
        "limits": {"requests": 10, "accounts": 0, "resources": 2, "costMicrousd": 40},
        "concurrency": 1, "scopes": [{"key": "project/p", "mode": "EXCLUSIVE"}],
    }
    ticket = ledger.reserve(envelope, claim, frozen, now=1100)
    gate = start(tmp_path, frozen)
    setup, read = job["observation"]
    doc = {"name": RESOURCE, "fields": setup["body"]["fields"], "updateTime": VERSION}
    gate.dispatch(setup, False, lambda: (200, copy.deepcopy(doc)))
    gate.dispatch(read, False, lambda: (200, []))
    for index, declared in enumerate(job["recovery"]):
        request = copy.deepcopy(declared)
        source = request.pop("versionFrom", None)
        if source is not None:
            request["path"] += "?currentDocument.updateTime=" + quote(VERSION, safe="")
        response = [(200, doc), (200, {}), (404, ABSENT)][index]
        gate.dispatch(request, True, lambda: copy.deepcopy(response))
    gate.finish()
    return gate, ledger, ticket, claim, envelope


@pytest.mark.parametrize("scheduled", [False, True])
@pytest.mark.parametrize("annotate_first,annotate_final", [(False,False),(True,False),(False,True),(True,True)])
def test_null_read_annotations_allow_typed_gate_ledger_retirement(tmp_path, scheduled, annotate_first, annotate_final):
    gate, ledger, ticket, claim, envelope = complete(tmp_path, scheduled, annotate_first, annotate_final)
    shared_gate.validate_absence_proofs(gate.snapshot(), "read")
    ledger.finish(ticket)
    state = ledger.snapshot()
    assert state["reservations"][ticket["reservation"]]["state"] == "released"
    assert state["envelopes"][digest(envelope)]["allocated"] == claim["budget"]


@pytest.mark.parametrize("source", [0,1,False,True,"capture",[],{}])
def test_non_null_final_read_version_annotation_is_not_silently_ignored(tmp_path, source):
    gate, *_ = complete(tmp_path, False, False, False)
    state = gate.snapshot()
    state["plan"]["jobs"]["read"]["recovery"][2]["versionFrom"] = source
    with pytest.raises(ValueError):
        shared_gate.validate_absence_proofs(state, "read")


@pytest.mark.parametrize("mutation", ["extra-field", "body", "request", "response", "resource"])
def test_removing_null_annotation_does_not_relax_other_evidence_bindings(tmp_path, mutation):
    gate, *_ = complete(tmp_path, False, False, True)
    state = gate.snapshot()
    op = state["plan"]["jobs"]["read"]["recovery"][2]
    if mutation == "extra-field": op["extra"] = True
    elif mutation == "body": op["body"] = {}
    elif mutation == "request": state["events"][-1]["requestDigest"] = "0" * 64
    elif mutation == "response": state["events"][-1]["responseDigest"] = "0" * 64
    else: op["path"] += "foreign"
    with pytest.raises(ValueError):
        shared_gate.validate_absence_proofs(state, "read")
