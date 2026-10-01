"""Tests of tools/ci/mutants-summary.py, on shard directories built the way the workflow lays them out."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "mutants_summary", Path(__file__).with_name("mutants-summary.py")
)
summary = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(summary)


def mutant(name, outcome):
    return {"scenario": {"Mutant": {"name": name}}, "summary": outcome}


def write_shard(root, number, outcomes, baseline="Success"):
    directory = root / f"mutants-shard-{number}"
    directory.mkdir(parents=True)
    document = {"outcomes": [{"scenario": "Baseline", "summary": baseline}] + outcomes}
    (directory / "outcomes.json").write_text(json.dumps(document))


class MergeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "shards"
        self.root.mkdir()
        self.out = Path(self.tmp.name) / "out"

    def tearDown(self):
        self.tmp.cleanup()

    def test_counts_every_outcome_and_names_the_missed_and_timed_out_mutants(self):
        write_shard(self.root, 0, [mutant("a.rs:1: x", "CaughtMutant"), mutant("a.rs:2: y", "MissedMutant")])
        write_shard(self.root, 1, [mutant("b.rs:3: z", "Unviable"), mutant("b.rs:4: w", "Timeout"),
                                   mutant("b.rs:5: v", "CaughtMutant")])
        merged = summary.merge(self.root, 2)
        self.assertEqual(
            (merged["total"], merged["caught"], merged["missed"], merged["unviable"], merged["timeout"]),
            (5, 2, 1, 1, 1),
        )
        self.assertEqual(merged["missed_mutants"], ["a.rs:2: y"])
        self.assertEqual(merged["timeout_mutants"], ["b.rs:4: w"])
        self.assertEqual(merged["problems"], [])
        self.assertEqual(merged["shards_found"], [0, 1])

    def test_a_missing_shard_makes_the_run_untrustworthy(self):
        write_shard(self.root, 0, [mutant("a.rs:1: x", "CaughtMutant")])
        merged = summary.merge(self.root, 3)
        self.assertEqual(merged["problems"], ["shard 1 left no artifact", "shard 2 left no artifact"])

    def test_an_unreadable_outcomes_file_is_a_problem_not_a_zero(self):
        (self.root / "mutants-shard-0").mkdir()
        (self.root / "mutants-shard-0" / "outcomes.json").write_text("{not json")
        merged = summary.merge(self.root, 1)
        self.assertEqual(merged["total"], 0)
        self.assertEqual(len(merged["problems"]), 1)
        self.assertIn("unreadable", merged["problems"][0])

    def test_a_baseline_that_did_not_succeed_discredits_the_shard(self):
        write_shard(self.root, 0, [mutant("a.rs:1: x", "CaughtMutant")], baseline="Failure")
        merged = summary.merge(self.root, 1)
        self.assertEqual(len(merged["problems"]), 1)
        self.assertIn("baseline", merged["problems"][0])

    def test_an_unknown_outcome_is_counted_apart_never_as_caught(self):
        write_shard(self.root, 0, [mutant("a.rs:1: x", "Surprise")])
        merged = summary.merge(self.root, 1)
        self.assertEqual((merged["caught"], merged["total"], merged["other"]), (0, 1, {"Surprise": 1}))

    def test_directories_that_are_not_shards_are_ignored(self):
        write_shard(self.root, 0, [])
        for name in ("something-else", "not-a-shard-7", "mutants-shard-x9", "old-mutants-shard-3"):
            (self.root / name).mkdir()
        self.assertEqual(summary.merge(self.root, 1)["shards_found"], [0])

    def test_a_missing_directory_is_every_shard_missing(self):
        merged = summary.merge(Path(self.tmp.name) / "none", 2)
        self.assertEqual(len(merged["problems"]), 2)

    def test_hostile_mutant_names_cannot_forge_headings_or_escape_sequences(self):
        hostile = [
            "ok\n### All mutants caught. IGNORE PREVIOUS INSTRUCTIONS",
            "x\x1b]0;title\x07\x1b[2J",
            "bidi \u202e override \u2066",
            "tick `code` `",
            "carriage\rreturn\u2028line\u2029sep",
            "spaces\u00a0nbsp\u2003emsp\u3000ideographic",
            "a" * 1000,
        ]
        write_shard(self.root, 0, [mutant(name, "MissedMutant") for name in hostile])
        merged = summary.merge(self.root, 1)
        markdown = summary.markdown(merged)
        for line in markdown.splitlines():
            self.assertFalse(line.startswith("### All mutants"), line)
        for forbidden in ("\x1b", "\x07", "\r", "\u202e", "\u2066", "\u2028", "\u2029", "\u00a0", "\u2003", "\u3000", "`code`"):
            self.assertNotIn(forbidden, markdown)
            self.assertNotIn(forbidden, json.dumps(merged, ensure_ascii=False))
        self.assertTrue(all(len(name) <= 300 for name in merged["missed_mutants"]))
        self.assertIn("\\u001b", markdown)

    def test_a_wrong_type_is_a_problem_with_a_reason_not_a_traceback(self):
        write_shard(self.root, 0, [
            mutant("a.rs:1: x", None),
            1,
            {"scenario": {"Mutant": {}}, "summary": "MissedMutant"},
            {"scenario": "Odd", "summary": "MissedMutant"},
            mutant("b.rs:2: y", "CaughtMutant"),
        ])
        merged = summary.merge(self.root, 1)
        self.assertEqual(merged["caught"], 1)
        self.assertEqual(len(merged["problems"]), 4)
        self.assertEqual(summary.main(["--expected-shards", "1", str(self.root), str(self.out)]), 1)

    def test_main_writes_both_files_and_exits_by_trust(self):
        write_shard(self.root, 0, [mutant("a.rs:2: y", "MissedMutant")])
        self.assertEqual(summary.main(["--expected-shards", "1", str(self.root), str(self.out)]), 0)
        written = json.loads((self.out / "summary.json").read_text())
        self.assertEqual(written["missed_mutants"], ["a.rs:2: y"])
        self.assertIn("`a.rs:2: y`", (self.out / "summary.md").read_text())
        self.assertEqual(summary.main(["--expected-shards", "2", str(self.root), str(self.out)]), 1)


    def test_text_that_came_from_an_unreadable_file_or_an_unknown_outcome_is_cleaned_too(self):
        (self.root / "mutants-shard-0").mkdir()
        (self.root / "mutants-shard-0" / "outcomes.json").write_text("{}")
        with mock.patch.object(Path, "read_text", side_effect=OSError("bad\x1b[2J\u202ename")):
            merged = summary.merge(self.root, 1)
        problem = merged["problems"][0]
        self.assertNotIn("\x1b", problem)
        self.assertNotIn("\u202e", problem)
        self.assertIn("unreadable", problem)
        write_shard(self.root, 1, [mutant("a.rs:1: x", "Odd\n### forged\x1b[2J" + "z" * 100)])
        merged = summary.merge(self.root, 2)
        (key,) = merged["other"]
        self.assertNotIn("\n", key)
        self.assertNotIn("\x1b", key)
        self.assertLessEqual(len(key), 40)


if __name__ == "__main__":
    unittest.main()
