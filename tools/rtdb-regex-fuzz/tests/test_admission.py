"""Regression checks for fail-open classification and recorded-fixture admission."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


TOOLS = Path(__file__).resolve().parent.parent
CELLS = ("ra", "ru", "qa", "qu", "sa", "su", "xa", "xu", "la", "lu", "wa", "wu", "va", "vu")
RESOURCE = "Illegal regular expression, could not determinize efficiently"


def row(load, status, error=None):
    return {
        "expr": "'a'.matches(/a/)",
        **{f"load{c}": load for c in "RWV"},
        **{f"err{c}": error for c in "RWV"},
        **{cell: status if load == 200 else None for cell in CELLS},
    }


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)

    def write(self, name, value):
        path = self.directory / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def run_tool(self, name, *args):
        return subprocess.run(
            [sys.executable, str(TOOLS / name), *map(str, args)],
            text=True, capture_output=True, check=False, timeout=10,
        )

    def compare(self, official, local):
        report = self.directory / "report.txt"
        result = self.run_tool(
            "compare.py", self.write("official.json", [official]),
            self.write("local.json", [local]), report,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return report.read_text(encoding="utf-8")

    def test_resource_refusal_cannot_exempt_any_grant_cell(self):
        for cell in CELLS:
            with self.subTest(cell=cell):
                local = row(200, 401)
                local[cell] = 200
                report = self.compare(row(400, None, RESOURCE), local)
                self.assertIn("BLOCKING 1", report)
                self.assertRegex(report, r"(?m)^BLOCKING ")
                self.assertIn(f"{cell} open 1 closed 0", report)

    def test_error_text_cannot_change_grant_classification(self):
        for error in (None, "some other refusal", RESOURCE):
            with self.subTest(error=error):
                self.assertIn("BLOCKING 1", self.compare(row(400, None, error), row(200, 200)))

    def test_equal_refusals_and_closed_differences_are_distinct(self):
        official = row(400, None, RESOURCE)
        self.assertIn("same 1", self.compare(official, official))
        report = self.compare(official, row(200, 401))
        self.assertIn("fail-closed 1", report)
        self.assertIn("BLOCKING 0", report)

    def test_equal_transport_failures_are_blocking_in_every_cell(self):
        for status in (503, "gone"):
            for cell in CELLS:
                with self.subTest(status=status, cell=cell):
                    failed = row(200, 401)
                    failed[cell] = status
                    report = self.compare(failed, failed)
                    self.assertIn("BLOCKING 1", report)
                    self.assertRegex(report, r"(?m)^BLOCKING ")
                    self.assertIn(f"{cell} open 1 closed 0", report)

    def test_equal_successes_and_denials_remain_agreements(self):
        for status in (200, 401):
            with self.subTest(status=status):
                agreed = row(200, status)
                report = self.compare(agreed, agreed)
                self.assertIn("same 1", report)
                self.assertIn("BLOCKING 0", report)

    def test_new_fixture_rejects_resource_allow_through(self):
        for cell in CELLS:
            with self.subTest(cell=cell):
                local = row(200, 401)
                local[cell] = 200
                pairs = self.write("pairs.json", [{"jar": row(400, None, RESOURCE), "fireemu": local}])
                output = self.directory / "fixture.json"
                result = self.run_tool("cells_fixture.py", output, pairs)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("fail-open row", result.stderr)
                self.assertFalse(output.exists())

    def test_base_fixture_cannot_restore_an_old_resource_exemption(self):
        for size in (12, 14):
            with self.subTest(cell_count=size):
                base = [{
                    "expr": "'a'.matches(/a/)", "load": [400] * 3,
                    "error": [RESOURCE] * 3, "cells": [None] * size,
                    "fireemu": {"load": [200] * 3, "error": [None] * 3,
                                "cells": [200] + [401] * (size - 1), "why": "historical M14"},
                }]
                output = self.directory / "base-output.json"
                result = self.run_tool("cells_fixture.py", "--base", self.write("base.json", base), output)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("fail-open row", result.stderr)
                self.assertFalse(output.exists())

    def test_fixture_accepts_equal_refusals_and_preserves_legacy_missing_cells(self):
        official = row(400, None, RESOURCE)
        pairs = self.write("pairs.json", [{"jar": official, "fireemu": official}])
        base = [{
            "expr": "false", "load": [200] * 3, "error": [None] * 3, "cells": [200] * 12,
            "fireemu": {"load": [200] * 3, "error": [None] * 3,
                        "cells": [401] * 12, "why": "fail-closed difference"},
        }]
        output = self.directory / "accepted.json"
        result = self.run_tool("cells_fixture.py", "--base", self.write("base.json", base), output, pairs)
        self.assertEqual(result.returncode, 0, result.stderr)
        actual = json.loads(output.read_text(encoding="utf-8"))
        self.assertNotIn("fireemu", actual[0])
        self.assertEqual(actual[0]["error"], [RESOURCE] * 3)
        self.assertEqual(actual[1]["cells"], [200] * 6 + [None, None] + [200] * 6)
        self.assertEqual(actual[1]["fireemu"]["cells"], [401] * 6 + [None, None] + [401] * 6)


if __name__ == "__main__":
    unittest.main()
