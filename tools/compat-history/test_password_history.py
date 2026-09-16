"""The second trusted anchor preserves the four subsequently approved slices."""

import importlib.util
from pathlib import Path


def test_password_history_pins_reviewed_anchor_and_complete_slice_membership():
    path = Path(__file__).with_name("password_history.py")
    assert path.exists()
    spec = importlib.util.spec_from_file_location("password_history", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.ANCHOR == "631380e462c1124e41a3f5d1c43ec504705fe331"
    assert len(module.TEST_DIRS) == 4
    assert len(module.CHECKERS) == 8
    module.verify_frozen(module.ROOT, module.ANCHOR, module.FROZEN)
    for name in module.SLICES:
        assert "spec/compatibility/evidence/" + name in module.FROZEN
        assert "docs/compatibility/" + name + "-approval.md" in module.FROZEN
