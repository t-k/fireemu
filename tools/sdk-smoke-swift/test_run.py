"""Finite result accounting regressions; no network or subprocesses."""
import unittest
from run import CASES, complete

class ResultsTests(unittest.TestCase):
    def test_complete_success(self):
        self.assertTrue(complete([{"case": case, "status": "passed"} for case in CASES]))

    def test_missing_duplicate_failed_and_blocked_cases_fail(self):
        rows = [{"case": case, "status": "passed"} for case in CASES]
        self.assertFalse(complete(rows[:-1]))
        self.assertFalse(complete(rows + rows[:1]))
        for status in ["failed", "blocked", None]:
            self.assertFalse(complete([{**row, "status": status} if i == 0 else row for i, row in enumerate(rows)]))

if __name__ == "__main__":
    unittest.main()
