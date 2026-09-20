"""Wire-valid JSON may still be a contradictory API envelope.

Exercise actual local TCP, both bounded worker flavors, Gate and Ledger.
Only the HTTP responder is a fixture; no cloud endpoint or credential is used.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
from urllib.parse import quote

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import shared_gate
from broad_contract import digest
from test_batch_wire_completion import ABSENT, VERSION, _gate_and_ledger
from test_json_wire_integrity import worker_result


@pytest.mark.parametrize("flavor", ["batch", "limits"])
@pytest.mark.parametrize("scheduled", [False, True])
@pytest.mark.parametrize("mode", ["normal", "create-error", "refusal-with-result", "absence-with-document"])
def test_wire_complete_contradictions_never_grant_or_retire_ownership(tmp_path, flavor, scheduled, mode):
    gate, ledger, ticket, job, document, envelope, claim = _gate_and_ledger(tmp_path, scheduled)
    setup = job["observation"][0]
    body, status = copy.deepcopy(document), 200
    if mode == "create-error":
        body["error"] = {"code": 403, "status": "PERMISSION_DENIED"}
    elif mode == "refusal-with-result":
        body["error"] = {"code": 400, "status": "INVALID_ARGUMENT"}
        status = 400
    encoded = json.dumps(body).encode()
    if mode == "create-error":
        with pytest.raises(ValueError, match="success response contains an API error"):
            gate.dispatch(setup, False, lambda: worker_result(flavor, encoded, status, setup))
    else:
        gate.dispatch(setup, False, lambda: worker_result(flavor, encoded, status, setup))
    unknown = mode in {"create-error", "refusal-with-result"}
    if unknown:
        assert shared_gate.unconfirmed_creates(gate.snapshot(), "wire") == 1
        assert gate.snapshot()["jobs"]["wire"]["creationProofs"] == {}
        for frozen in job["recovery"]:
            operation = copy.deepcopy(frozen)
            operation.pop("versionFrom", None)
            gate.dispatch(operation, True, lambda: (404, copy.deepcopy(ABSENT)))
    else:
        read, declared, final = job["recovery"]
        gate.dispatch(read, True, lambda: (200, copy.deepcopy(document)))
        deletion = {k: v for k, v in declared.items() if k != "versionFrom"}
        deletion["path"] += "?currentDocument.updateTime=" + quote(VERSION, safe="")
        gate.dispatch(deletion, True, lambda: (200, {}))
        body = copy.deepcopy(ABSENT)
        if mode == "absence-with-document":
            body.update(document)
        encoded = json.dumps(body).encode()
        if mode == "absence-with-document":
            with pytest.raises(ValueError, match="typed Firestore absence required"):
                gate.dispatch(final, True, lambda: worker_result(flavor, encoded, 404, final))
        else:
            gate.dispatch(final, True, lambda: worker_result(flavor, encoded, 404, final))
    if mode == "normal":
        gate.finish()
        ledger.finish(ticket)
        assert ledger.snapshot()["reservations"][ticket["reservation"]]["state"] == "released"
    else:
        with pytest.raises(ValueError):
            gate.finish()
        before = ledger.snapshot()
        with pytest.raises(ValueError):
            ledger.finish(ticket)
        assert ledger.snapshot() == before
        assert before["reservations"][ticket["reservation"]]["state"] == "held"
    assert ledger.snapshot()["envelopes"][digest(envelope)]["allocated"] == claim["budget"]
