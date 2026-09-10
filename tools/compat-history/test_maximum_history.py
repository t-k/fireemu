"""Maximum approval remains bound to its pre-field-authorization artifact."""

import importlib.util
from pathlib import Path


def test_maximum_history_anchor_and_frozen_membership():
    path = Path(__file__).with_name("maximum_history.py")
    assert path.exists()
    spec = importlib.util.spec_from_file_location("maximum_history", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.ANCHOR == "7d76ab0adc9db719d5d983bc2ca9ece1c0d459d0"
    assert module.SLICES == ("auth-password-maximum",)
    assert len(module.CHECKERS) == 2
    module.verify_frozen(module.ROOT, module.ANCHOR, module.FROZEN)
