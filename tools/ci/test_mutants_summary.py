"""Tests of tools/ci/mutants-summary.py, on shard directories built the way the workflow lays them out."""

import contextlib
import importlib.util
import io
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


END_TIME = "2026-10-02T03:04:05Z"


def write_shard(root, number, outcomes, baseline="Success", listed=None, end_time=END_TIME):
    """A finished shard as cargo-mutants lays it out: `mutants.json` (what it was given, written first)
    and `outcomes.json` (rewritten after every mutant, `end_time` set when it finishes)."""
    directory = root / f"mutants-shard-{number}"
    directory.mkdir(parents=True)
    document = {
        "outcomes": [{"scenario": "Baseline", "summary": baseline}] + outcomes,
        "end_time": end_time,
    }
    (directory / "outcomes.json").write_text(json.dumps(document))
    if listed is None:
        listed = [
            {"name": o["scenario"]["Mutant"]["name"]}
            for o in outcomes
            if isinstance(o, dict)
            and isinstance(o.get("scenario"), dict)
            and isinstance(o["scenario"].get("Mutant"), dict)
            and "name" in o["scenario"]["Mutant"]
        ]
    (directory / "mutants.json").write_text(json.dumps(listed))


def write_empty_shard(root, number):
    """What cargo-mutants leaves when its `--shard` holds no mutant (observed with cargo-mutants 27.1.0):
    no outcomes.json at all, an empty mutants.json, and empty result lists."""
    directory = root / f"mutants-shard-{number}"
    directory.mkdir(parents=True)
    (directory / "mutants.json").write_text("[]")
    (directory / "lock.json").write_text('{"cargo_mutants_version": "27.1.0"}')
    for name in ("missed.txt", "caught.txt", "timeout.txt", "unviable.txt"):
        (directory / name).write_text("")


class MergeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "shards"
        self.root.mkdir()
        self.out = Path(self.tmp.name) / "out"

    def tearDown(self):
        self.tmp.cleanup()

    def test_counts_every_outcome_and_names_the_missed_and_timed_out_mutants(self):
        # Five mutants over two shards: the default slice sharding gives 3 and 2.
        write_shard(self.root, 0, [mutant("a.rs:1: x", "CaughtMutant"), mutant("a.rs:2: y", "MissedMutant"),
                                   mutant("b.rs:3: z", "Unviable")])
        write_shard(self.root, 1, [mutant("b.rs:4: w", "Timeout"), mutant("b.rs:5: v", "CaughtMutant")])
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
        ], listed=[{"name": "b.rs:2: y"}])
        merged = summary.merge(self.root, 1)
        self.assertEqual(merged["caught"], 0, "a shard with a problem contributes nothing")
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

    def test_a_shard_that_held_no_mutant_is_zero_mutants_not_a_failure(self):
        # Two mutants over three shards: the slice sharding gives 1, 1 and 0.
        write_shard(self.root, 0, [mutant("a.rs:1: x", "CaughtMutant")])
        write_shard(self.root, 1, [mutant("a.rs:2: y", "MissedMutant")])
        write_empty_shard(self.root, 2)
        merged = summary.merge(self.root, 3)
        self.assertEqual(merged["problems"], [])
        self.assertEqual((merged["total"], merged["caught"], merged["missed"]), (2, 1, 1))
        self.assertEqual(merged["shards_empty"], [2])
        self.assertEqual(merged["shards_found"], [0, 1, 2])
        self.assertEqual(merged["mutants_listed"], 2)
        self.assertIn("Empty shards (no mutants): 2", summary.markdown(merged))
        self.assertEqual(summary.main(["--expected-shards", "3", str(self.root), str(self.out)]), 0)

    def test_the_live_run_shape_is_trusted(self):
        # Run 36885315799: five mutants over eight shards, one each on shards 0-4, shards 5-7 empty.
        for number in range(5):
            write_shard(self.root, number, [mutant(f"a.rs:{number}: x", "MissedMutant")])
        for number in range(5, 8):
            write_empty_shard(self.root, number)
        merged = summary.merge(self.root, 8)
        self.assertEqual((merged["problems"], merged["total"], merged["shards_empty"]), ([], 5, [5, 6, 7]))

    def test_a_run_whose_every_shard_is_empty_is_a_problem(self):
        for number in range(3):
            write_empty_shard(self.root, number)
        merged = summary.merge(self.root, 3)
        (problem,) = merged["problems"]
        self.assertIn("every shard is empty", problem)
        self.assertEqual(summary.main(["--expected-shards", "3", str(self.root), str(self.out)]), 1)
        self.assertNotIn("No mutant was generated", summary.markdown(merged))

    def test_an_empty_first_shard_while_a_later_one_holds_mutants_is_a_problem(self):
        write_empty_shard(self.root, 0)
        write_shard(self.root, 1, [mutant("a.rs:1: x", "CaughtMutant")])
        merged = summary.merge(self.root, 2)
        self.assertEqual(len(merged["problems"]), 2, merged["problems"])
        self.assertIn("shard 0 holds 0 mutants but the default slice sharding of 1 mutants over 2 shards gives 1", merged["problems"][0])

    def test_an_uneven_split_that_the_slice_sharding_does_not_make_is_a_problem(self):
        # Four mutants over two shards must be 2 and 2, not 3 and 1.
        write_shard(self.root, 0, [mutant(f"a.rs:{i}: x", "CaughtMutant") for i in range(3)])
        write_shard(self.root, 1, [mutant("b.rs:1: y", "CaughtMutant")])
        merged = summary.merge(self.root, 2)
        self.assertEqual(len(merged["problems"]), 2, merged["problems"])
        self.assertTrue(all("slice sharding" in problem for problem in merged["problems"]))

    def test_the_slice_layout_of_cargo_mutants_is_trusted_for_every_size(self):
        for total in range(1, 41):
            for shards in range(1, 17):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    position = 0
                    for k in range(shards):
                        size = summary.slice_size(total, shards, k)
                        names = [mutant(f"a.rs:{position + i}: m", "CaughtMutant") for i in range(size)]
                        position += size
                        if size:
                            write_shard(root, k, names)
                        else:
                            write_empty_shard(root, k)
                    self.assertEqual(position, total)
                    merged = summary.merge(root, shards)
                    self.assertEqual(merged["problems"], [], (total, shards))
                    self.assertEqual(merged["total"], total)

    def test_moving_or_emptying_a_shard_of_a_slice_layout_is_a_problem_unless_it_is_another_slice_layout(self):
        for total, shards in [(5, 2), (7, 3), (10, 4), (3, 3), (9, 5), (16, 16), (40, 7)]:
            sizes = [summary.slice_size(total, shards, k) for k in range(shards)]
            variants = []
            for k in range(shards):
                if sizes[k]:
                    emptied = list(sizes)
                    emptied[k] = 0
                    variants.append(emptied)
                    for other in range(shards):
                        if other != k:
                            moved = list(sizes)
                            moved[k] -= 1
                            moved[other] += 1
                            if moved != sizes:
                                variants.append(moved)
            for variant in variants:
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    for k, size in enumerate(variant):
                        if size:
                            write_shard(root, k, [mutant(f"a.rs:{k}.{i}: m", "CaughtMutant") for i in range(size)])
                        else:
                            write_empty_shard(root, k)
                    merged = summary.merge(root, shards)
                    # A layout that is itself a slice layout of its own total (the last shard of 10 mutants
                    # over 4 shards losing its single mutant is the slice layout of 9) cannot be told from
                    # a real run by the artifacts alone: the shards' lists are all there is to check.
                    new_total = sum(variant)
                    itself_valid = new_total > 0 and all(
                        variant[k] == summary.slice_size(new_total, shards, k) for k in range(shards)
                    )
                    self.assertEqual(bool(merged["problems"]), not itself_valid, (total, shards, variant))

    def test_an_empty_artifact_directory_is_a_failure_that_names_the_shard(self):
        write_shard(self.root, 0, [mutant("a.rs:1: x", "CaughtMutant")])
        (self.root / "mutants-shard-1").mkdir()
        merged = summary.merge(self.root, 2)
        self.assertEqual(merged["shards_empty"], [])
        (problem,) = merged["problems"]
        self.assertTrue(problem.startswith("shard 1: "), problem)
        self.assertIn("wrote nothing", problem)

    def test_a_shard_that_listed_mutants_but_has_no_outcomes_did_not_finish(self):
        directory = self.root / "mutants-shard-0"
        directory.mkdir(parents=True)
        (directory / "mutants.json").write_text(json.dumps([{"name": "a.rs:1: x"}, {"name": "a.rs:2: y"}]))
        merged = summary.merge(self.root, 1)
        self.assertEqual(merged["shards_empty"], [])
        (problem,) = merged["problems"]
        self.assertIn("shard 0", problem)
        self.assertIn("2 mutants", problem)
        self.assertIn("did not finish", problem)

    def test_a_malformed_mutants_list_or_outcomes_file_is_a_failure_with_the_shard_and_the_reason(self):
        for number, files in enumerate(
            [
                {"mutants.json": "{not json"},
                {"mutants.json": '{"a": 1}'},
                {"mutants.json": "[]", "outcomes.json": "{not json"},
                {"outcomes.json": '{"outcomes": "no"}'},
            ]
        ):
            directory = self.root / f"mutants-shard-{number}"
            directory.mkdir(parents=True)
            for name, text in files.items():
                (directory / name).write_text(text)
        merged = summary.merge(self.root, 4)
        self.assertEqual(merged["shards_empty"], [])
        self.assertEqual(len(merged["problems"]), 4, merged["problems"])
        for number, problem in enumerate(merged["problems"]):
            self.assertTrue(problem.startswith(f"shard {number}: "), problem)

    def test_an_outcomes_file_that_covers_more_mutants_than_were_listed_is_a_problem(self):
        write_shard(self.root, 0, [mutant("a.rs:1: x", "CaughtMutant")], listed=[])
        merged = summary.merge(self.root, 1)
        self.assertTrue(any("covers 1 of 0 listed" in problem for problem in merged["problems"]), merged["problems"])

    def test_a_shard_stopped_after_the_baseline_leaves_a_partial_outcomes_file_that_is_not_a_result(self):
        directory = self.root / "mutants-shard-0"
        directory.mkdir(parents=True)
        (directory / "mutants.json").write_text(json.dumps([{"name": "a"}, {"name": "b"}, {"name": "c"}]))
        document = {
            "outcomes": [
                {"scenario": "Baseline", "summary": "Success"},
                {"scenario": {"Mutant": {"name": "a"}}, "summary": "CaughtMutant"},
            ],
            "end_time": None,
        }
        (directory / "outcomes.json").write_text(json.dumps(document))
        merged = summary.merge(self.root, 1)
        (problem,) = merged["problems"]
        self.assertIn("shard 0", problem)
        self.assertIn("no end_time", problem)
        self.assertEqual(merged["total"], 0, "a partial result is not counted")

    def test_a_shard_with_an_end_time_but_fewer_outcomes_than_listed_mutants_is_a_problem(self):
        write_shard(
            self.root, 0, [mutant("a", "CaughtMutant")], listed=[{"name": "a"}, {"name": "b"}, {"name": "c"}]
        )
        merged = summary.merge(self.root, 1)
        (problem,) = merged["problems"]
        self.assertIn("covers 1 of 3 listed mutants", problem)
        self.assertIn("did not finish", problem)

    def test_outcomes_without_a_list_of_mutants_is_a_problem(self):
        write_shard(self.root, 0, [mutant("a", "CaughtMutant")])
        (self.root / "mutants-shard-0" / "mutants.json").unlink()
        merged = summary.merge(self.root, 1)
        (problem,) = merged["problems"]
        self.assertIn("outcomes.json exists but mutants.json is missing", problem)

    def test_a_failed_baseline_is_reported_as_such_not_as_missing_mutants(self):
        write_shard(self.root, 0, [], baseline="Failure", listed=[{"name": "a"}, {"name": "b"}])
        merged = summary.merge(self.root, 1)
        (problem,) = merged["problems"]
        self.assertIn("the baseline did not succeed", problem)

    def test_a_shard_number_beyond_the_expected_count_is_not_counted(self):
        write_shard(self.root, 0, [mutant("a", "CaughtMutant")])
        write_shard(self.root, 5, [mutant("b", "MissedMutant")])
        merged = summary.merge(self.root, 1)
        self.assertEqual(merged["total"], 1)
        self.assertEqual(merged["missed"], 0)
        self.assertEqual(merged["shards_unexpected"], [5])
        (problem,) = merged["problems"]
        self.assertIn("shard 5 is beyond the 1 expected shards", problem)

    def test_the_result_of_the_shard_job_is_a_problem_unless_it_is_success(self):
        write_shard(self.root, 0, [mutant("a", "CaughtMutant")])
        self.assertEqual(summary.merge(self.root, 1, "success")["problems"], [])
        self.assertEqual(summary.merge(self.root, 1, None)["problems"], [])
        for result in ("failure", "cancelled", "skipped"):
            merged = summary.merge(self.root, 1, result)
            (problem,) = merged["problems"]
            self.assertIn(f"the mutants job ended {result}", problem)
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = summary.main(["--expected-shards", "1", "--mutants-result", "failure", str(self.root), str(self.out)])
        self.assertEqual(code, 1)
        self.assertIn("the mutants job ended failure", stderr.getvalue())

    def test_the_command_says_what_failed_on_stderr_and_exits_non_zero(self):
        write_shard(self.root, 0, [mutant("a.rs:1: x", "CaughtMutant")])
        (self.root / "mutants-shard-1").mkdir()
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = summary.main(["--expected-shards", "3", str(self.root), str(self.out)])
        self.assertEqual(code, 1)
        text = stderr.getvalue()
        self.assertIn("mutants-summary: shard 1: ", text)
        self.assertIn("mutants-summary: shard 2 left no artifact", text)
        self.assertIn("cannot be trusted", text)

    def test_the_command_is_quiet_on_stderr_when_the_run_can_be_trusted(self):
        write_shard(self.root, 0, [mutant("a.rs:1: x", "CaughtMutant")])
        write_empty_shard(self.root, 1)
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = summary.main(["--expected-shards", "2", str(self.root), str(self.out)])
        self.assertEqual((code, stderr.getvalue()), (0, ""))

    def test_a_run_that_cannot_be_trusted_does_not_claim_that_no_mutant_was_generated(self):
        write_empty_shard(self.root, 0)
        merged = summary.merge(self.root, 2)  # shard 1 left no artifact
        self.assertEqual(merged["total"], 0)
        self.assertEqual(len(merged["problems"]), 1)
        self.assertNotIn("No mutant was generated", summary.markdown(merged))
        self.assertIn("cannot be trusted", summary.markdown(merged))

    def test_the_names_of_the_outcomes_must_be_the_names_listed(self):
        # `a, a` against a list of `a, b`: the count is right and the result of `b` would disappear.
        write_shard(
            self.root, 0, [mutant("a", "CaughtMutant"), mutant("a", "CaughtMutant")],
            listed=[{"name": "a"}, {"name": "b"}],
        )
        merged = summary.merge(self.root, 1)
        (problem,) = merged["problems"]
        self.assertIn("shard 0", problem)
        self.assertIn("do not match", problem)
        self.assertIn("b", problem)
        self.assertEqual(merged["total"], 0)

    def test_another_name_in_the_outcomes_than_in_the_list_is_a_problem(self):
        write_shard(self.root, 0, [mutant("z", "CaughtMutant")], listed=[{"name": "a"}])
        merged = summary.merge(self.root, 1)
        (problem,) = merged["problems"]
        self.assertIn("do not match", problem)
        self.assertIn("z", problem)
        self.assertIn("a", problem)

    def test_a_listed_mutant_without_a_name_is_a_problem(self):
        write_shard(self.root, 0, [mutant("a", "CaughtMutant")], listed=[{"nom": "a"}])
        merged = summary.merge(self.root, 1)
        self.assertTrue(any("without a name" in problem for problem in merged["problems"]), merged["problems"])

    def test_the_names_are_compared_as_a_multiset_so_a_repeated_mutant_must_repeat(self):
        write_shard(
            self.root, 0, [mutant("a", "CaughtMutant"), mutant("a", "MissedMutant")],
            listed=[{"name": "a"}, {"name": "a"}],
        )
        merged = summary.merge(self.root, 1)
        self.assertEqual(merged["problems"], [])
        self.assertEqual((merged["total"], merged["caught"], merged["missed"]), (2, 1, 1))

    def test_a_long_list_of_differences_is_cut_and_every_name_is_cleaned(self):
        outcomes = [mutant(f"x{i}\x1b[2J", "CaughtMutant") for i in range(30)]
        write_shard(self.root, 0, outcomes, listed=[{"name": f"y{i}"} for i in range(30)])
        merged = summary.merge(self.root, 1)
        (problem,) = merged["problems"]
        self.assertNotIn("\x1b", problem)
        self.assertLess(len(problem), 900)

    def test_a_shard_with_an_end_time_but_too_few_outcomes_adds_nothing_to_the_totals(self):
        write_shard(
            self.root, 0, [mutant("a", "MissedMutant")], listed=[{"name": "a"}, {"name": "b"}]
        )
        merged = summary.merge(self.root, 1)
        self.assertEqual(len(merged["problems"]), 1)
        self.assertEqual((merged["total"], merged["missed"], merged["missed_mutants"]), (0, 0, []))

    def test_a_trusted_shard_is_counted_beside_a_shard_with_a_problem(self):
        # Four mutants over two shards: two each. Shard 1 covers only one of its two.
        write_shard(self.root, 0, [mutant("a", "CaughtMutant"), mutant("b", "MissedMutant")])
        write_shard(self.root, 1, [mutant("c", "TimeoutX")], listed=[{"name": "c"}, {"name": "d"}])
        merged = summary.merge(self.root, 2)
        self.assertEqual(len(merged["problems"]), 1)
        self.assertEqual((merged["total"], merged["caught"], merged["missed"]), (2, 1, 1))
        self.assertEqual(merged["other"], {})


if __name__ == "__main__":
    unittest.main()
