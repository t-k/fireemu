"""Shared fixtures for the FS-WRITE-LIMITS tests.

Nothing here reaches production or the canonical Ledger.
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import shared_gate


@pytest.fixture
def gate_accounts_the_empty_batch_item(monkeypatch):
    """The proposed shared-Gate rule, applied to the test process only.

    HEAD's `_creation_outcome` settles a BatchWrite as unknown as soon as one
    item is not a create-shaped write, so the campaign's malformed-item batch
    (an empty `{}` item that names no document) leaves one create unconfirmed
    and the normal close is refused. The rule below accounts an empty item
    only when production refused it per item with INVALID_ARGUMENT and the
    empty result slot; anything else stays unknown. It is not applied to the
    shared module here: the Gate is outside this lane's ownership, and the
    exact diff is in the worker report.
    """
    original = shared_gate._creation_outcome

    def accounted(operation, status, body, proofs):
        outcome = original(operation, status, body, proofs)
        writes = shared_gate._bulk_writes(operation)
        if (
            outcome != "unknown"
            or writes is None
            or not operation["path"].endswith(":batchWrite")
            or not isinstance(body, dict)
            or not isinstance(body.get("status"), list)
            or not isinstance(body.get("writeResults"), list)
            or len(body["status"]) != len(writes)
            or len(body["writeResults"]) != len(writes)
        ):
            return outcome
        kept = [
            index
            for index, write in enumerate(writes)
            if write != {}
            or not (
                isinstance(body["status"][index], dict)
                and body["status"][index].get("code") == 3
                and body["writeResults"][index] == {}
            )
        ]
        if len(kept) == len(writes) or not kept:
            return outcome
        reduced = copy.deepcopy(operation)
        reduced["body"]["writes"] = [writes[index] for index in kept]
        reduced_body = {
            **body,
            "status": [body["status"][index] for index in kept],
            "writeResults": [body["writeResults"][index] for index in kept],
        }
        return original(reduced, status, reduced_body, proofs)

    monkeypatch.setattr(shared_gate, "_creation_outcome", accounted)
