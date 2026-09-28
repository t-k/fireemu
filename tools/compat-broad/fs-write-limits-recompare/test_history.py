"""The historical adapter accepts no receipt-selected source or failed receipt."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from limits_evidence_history import (
    INPUTS_SHA256,
    PRODUCTION_COMMIT,
    RECEIPT_SHA256,
    _run,
    validate_production,
)


@pytest.mark.parametrize("failure", ["ValueError", None, "", False, {}, []])
def test_legacy_failure_key_is_refused_before_trusted_code_selection(failure):
    receipt = {
        "kind": "fs-write-limits-production-receipt-v1",
        "acquisitionValidated": True,
        "acquisitionFailure": failure,
    }
    with pytest.raises(ValueError, match="unrecognized or failed"):
        validate_production(
            receipt, {"sourceCommit": PRODUCTION_COMMIT}, RECEIPT_SHA256, INPUTS_SHA256
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("acquisitionValidated", False),
        ("failure", "ValueError"),
        ("reservationFailure", None),
        ("kind", "fs-write-limits-production-receipt-v2"),
    ],
)
def test_legacy_invalid_marker_or_contract_is_refused(field, value):
    receipt = {
        "kind": "fs-write-limits-production-receipt-v1",
        "acquisitionValidated": True,
    }
    receipt[field] = value
    with pytest.raises(ValueError, match="unrecognized or failed"):
        validate_production(
            receipt, {"sourceCommit": PRODUCTION_COMMIT}, RECEIPT_SHA256, INPUTS_SHA256
        )


@pytest.mark.parametrize(
    "receipt_hash,input_hash,commit",
    [
        ("0" * 64, INPUTS_SHA256, PRODUCTION_COMMIT),
        (RECEIPT_SHA256, "0" * 64, PRODUCTION_COMMIT),
        (RECEIPT_SHA256, INPUTS_SHA256, "0" * 40),
    ],
)
def test_legacy_identity_is_exact(receipt_hash, input_hash, commit):
    receipt = {
        "kind": "fs-write-limits-production-receipt-v1",
        "acquisitionValidated": True,
    }
    with pytest.raises(ValueError, match="unrecognized or failed"):
        validate_production(receipt, {"sourceCommit": commit}, receipt_hash, input_hash)


def test_historical_runner_never_executes_receipt_selected_commit():
    with pytest.raises(ValueError, match="not allowlisted"):
        _run("0" * 40, "production", {})
