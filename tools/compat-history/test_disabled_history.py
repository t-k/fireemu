"""The disable mismatch and earlier approvals retain their original runtime."""

import importlib.util
from pathlib import Path


def test_disabled_history_anchor_and_frozen_membership():
    path = Path(__file__).with_name("disabled_history.py")
    assert path.exists()
    spec = importlib.util.spec_from_file_location("disabled_history", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.ANCHOR == "1856e4708c7abe2dd0e329f5593d6c46a32c6849"
    for name in (
        "auth-disabled",
        "auth-password-unicode-boundary",
        "auth-password-unicode-recheck",
    ):
        assert f"spec/compatibility/evidence/{name}" in module.FROZEN
        assert f"docs/compatibility/{name}.md" in module.FROZEN
    module.verify_frozen(module.ROOT, module.ANCHOR, module.FROZEN)
