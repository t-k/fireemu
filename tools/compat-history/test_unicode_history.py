"""The original mismatch stays bound to the pre-fix artifact."""

import importlib.util
from pathlib import Path


def test_unicode_history_anchor_and_frozen_membership():
    path = Path(__file__).with_name("unicode_history.py")
    assert path.exists()
    spec = importlib.util.spec_from_file_location("unicode_history", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.ANCHOR == "51724d98514bc54e1cb9a516c3cde74e4b66664e"
    assert "tools/auth-password-unicode" in module.FROZEN
    assert "tools/publish-auth-password-unicode.py" in module.FROZEN
    assert "spec/compatibility/evidence/auth-password-unicode" in module.FROZEN
    assert "docs/compatibility/auth-password-unicode.md" in module.FROZEN
    module.verify_frozen(module.ROOT, module.ANCHOR, module.FROZEN)
