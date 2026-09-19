"""Proof of the non-authorizing O8 local preparation path.

This test deliberately uses the existing injected transport preparation mode.
It exercises the real acquisition, Coordinator, shared Gate/Ledger, collector,
cleanup, receipt and release path while proving that the production capability
and production transport are never used.
"""

from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
import sys

sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "production-admission"))
sys.path.insert(0, str(HERE))

import commit_acquisition as acquisition
import commit_remote_transport as production_transport
from test_commit_acquisition import fixture


def test_local_adapter_proves_full_lifecycle_without_production_execution(
    tmp_path, monkeypatch
):
    """The local proof reaches release without authorizing production traffic."""
    inputs, ledger, calls, kwargs = fixture(tmp_path, monkeypatch)

    def unexpected_production_transport(*_args, **_kwargs):
        pytest.fail("local preparation must not call the production transport")

    monkeypatch.setattr(production_transport, "request", unexpected_production_transport)
    monkeypatch.setattr(
        production_transport, "request_bound", unexpected_production_transport
    )
    # commit_acquisition imports these symbols as aliases; guard those aliases
    # too so this local proof fails closed if the injected path drifts.
    monkeypatch.setattr(acquisition, "remote_request", unexpected_production_transport)
    monkeypatch.setattr(
        acquisition, "remote_request_bound", unexpected_production_transport
    )

    result = acquisition.run_acquisition(tmp_path / "output", inputs, **kwargs)

    assert result["executionKind"] == "injected-transport"
    assert result["productionExecuted"] is False
    assert result["workerArchiveSha256"] is None
    assert result["failure"] is None
    assert result["releaseEligible"] is True
    assert result["reservationReleased"] is True
    assert result["collection"]["collectionComplete"] is True
    assert result["chargedCalls"] == 27
    assert calls[:2] == ["refresh", "tokeninfo"]
    assert calls[-4:] == ["project", "database", "auth", "key"]

    receipt = (tmp_path / "output/receipt.json").read_text()
    release = (tmp_path / "output/release.json").read_text()
    assert '"productionExecuted": false' in receipt
    assert '"executionKind": "injected-transport"' in receipt
    assert '"state": "released"' in release
    assert ledger.snapshot()["reservations"][result["ticket"]["reservation"]][
        "state"
    ] == "released"
