"""Validate a new artifact without rewriting the original mismatch."""

import importlib.util
from pathlib import Path


def test_recheck_publisher_exists_and_preserves_original_subject():
    path = Path(__file__).with_name("publish-auth-password-unicode-recheck.py")
    assert path.exists()
    spec = importlib.util.spec_from_file_location("unicode_recheck", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert (
        module.PREVIOUS_SUBJECT
        == "9c0364b6cabdf9497c243db1956655e9d455a08578b0ce1f58bd39d5aa9dcfbf"
    )
    assert module.BUNDLE != module.old.BUNDLE
