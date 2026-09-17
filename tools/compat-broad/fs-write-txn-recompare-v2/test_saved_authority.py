"""Run against the retained campaign files; never performs an observation."""

import importlib.util
import json
import os
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
