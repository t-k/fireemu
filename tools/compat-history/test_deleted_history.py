"""The deleted mismatch and disable approval retain their recorded source."""

import deleted_history as history


def test_deleted_history_anchor_and_frozen_membership():
    assert history.ANCHOR == "3e565f5775c255d8f39168f5aeb27258a770c6c8"
    for name in ("auth-deleted", "auth-disabled-recheck"):
        assert f"spec/compatibility/evidence/{name}" in history.FROZEN
        assert f"docs/compatibility/{name}.md" in history.FROZEN
    history.verify_frozen(history.ROOT, history.ANCHOR, history.FROZEN)
