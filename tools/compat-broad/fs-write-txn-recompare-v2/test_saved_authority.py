"""Run against the retained campaign files; never performs an observation."""

import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "saved_authority", Path(__file__).with_name("saved_authority.py")
)
ROOT = (
    Path(os.environ["STREAM_RECOMPARE_ROOT"])
    if "STREAM_RECOMPARE_ROOT" in os.environ
    else None
)


class SavedAuthorityTests(unittest.TestCase):
    def test_source_diff_disables_external_diff_and_textconv(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
            subprocess.run(
                ["git", "-C", str(root), "config", "user.name", "Test"], check=True
            )
            subprocess.run(
                ["git", "-C", str(root), "config", "user.email", "test@example.invalid"],
                check=True,
            )
            source = root / "tools/validator.txt"
            source.parent.mkdir()
            source.write_text("before\n")
            (root / ".gitattributes").write_text("*.txt diff=canary\n")
            subprocess.run(
                ["git", "-C", str(root), "add", ".gitattributes", "tools/validator.txt"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(root), "commit", "-qm", "base"], check=True
            )
            commit = subprocess.check_output(
                ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
            ).strip()
            source.write_text("after\n")
            external_marker = Path(temporary) / "external-ran"
            textconv_marker = Path(temporary) / "textconv-ran"
            external = Path(temporary) / "external-diff"
            external.write_text(f"#!/bin/sh\ntouch {external_marker}\n")
            external.chmod(0o700)
            textconv = Path(temporary) / "textconv"
            textconv.write_text(f"#!/bin/sh\ntouch {textconv_marker}\ncat\n")
            textconv.chmod(0o700)
            subprocess.run(
                ["git", "-C", str(root), "config", "diff.external", str(external)],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(root), "config", "diff.canary.textconv", str(textconv)],
                check=True,
            )

            module = importlib.util.module_from_spec(SPEC)
            SPEC.loader.exec_module(module)
            with self.assertRaisesRegex(ValueError, "validator source differs"):
                module.source_checkout(root, commit)
            self.assertFalse(external_marker.exists())
            self.assertFalse(textconv_marker.exists())

    @unittest.skipUnless(ROOT, "set STREAM_RECOMPARE_ROOT for retained private inputs")
    def test_saved_pairs_and_forgery(self):
        module = importlib.util.module_from_spec(SPEC)
        SPEC.loader.exec_module(module)
        result = module.compare_saved(ROOT)
        self.assertTrue(result["acquisitionValidated"])
        self.assertEqual(
            result["originalComparison"]["classification"], "SEMANTIC_MISMATCH"
        )
        self.assertEqual(result["oldPair"]["classification"], "SEMANTIC_MISMATCH")
        self.assertEqual(result["newPair"]["classification"], "EXPECTED_NONDETERMINISM")
        with self.assertRaises((TypeError, ValueError)):
            module.compare_saved(
                ROOT, permission={}, v1Source="fake", artifact={"fake": "binary"}
            )
        originals = ROOT / "docs.local/logs/2026-09-17/stream-production-preflight"
        for path, expected in [
            (originals / "execution-dee737c14/receipt.json", module.PRODUCTION_SHA),
            (originals / "approved-prepared-inputs-dee.json", module.PREPARED_SHA),
        ]:
            value = json.loads(path.read_bytes())
            value["permission"] = {}
            with self.assertRaises(ValueError):
                module.require_hash(
                    json.dumps(value).encode(), expected, "forged authority"
                )


if __name__ == "__main__":
    unittest.main()
