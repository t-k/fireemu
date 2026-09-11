"""Approved deletion recheck remains bound to its recorded pre-lookup-fix source."""

import lookup_history as history


def test_lookup_history_anchor_and_frozen_membership():
    assert history.ANCHOR == "5c17391656aa31504611205270178533d8c7badf"
    assert "spec/compatibility/evidence/auth-deleted-recheck" in history.FROZEN
    assert "tools/auth-deleted-recheck-approval.py" in history.FROZEN
    assert "docs/compatibility/auth-deleted-recheck-approval.md" in history.FROZEN
    history.verify_frozen(history.ROOT, history.ANCHOR, history.FROZEN)
