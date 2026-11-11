"""Tests of tools/ci/critical-selection.py: the list, the regex it prints and the path and name checks."""

import importlib.util
import io
import contextlib
import random
import re
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("critical_selection", Path(__file__).with_name("critical-selection.py"))
selection = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(selection)

FIXTURE = """
# header
crates/a/src/jwt.rs  # 3, whole file
crates/a/src/eval.rs @ build_request request_path  # 2, scoped
"""

NAMES = [
    "crates/a/src/jwt.rs:4:5: replace verify -> bool with true",
    "crates/a/src/jwt.rs:9:1: delete ! in verify",
    "crates/a/src/eval.rs:10:3: replace build_request -> RulesValue with Default::default()",
    "crates/a/src/eval.rs:12:3: replace == with != in build_request",
    "crates/a/src/eval.rs:14:3: delete ! in request_path",
    "crates/a/src/eval.rs:20:3: replace build_request_with_resource -> RulesValue with Default::default()",
    "crates/a/src/eval.rs:30:3: replace other -> bool with true",
    "crates/b/src/jwt.rs:4:5: replace verify -> bool with true",
    "crates/a/src/evaluator.rs:4:5: replace verify -> bool with true",
]


def selected(regex, names=NAMES):
    return [name for name in names if re.search(regex, name)]


def write(root: Path, relative: str, text: str) -> None:
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


class RegexTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.list = Path(self.tmp.name) / "list.txt"
        self.list.write_text(FIXTURE, encoding="utf-8")

    def regex(self):
        return selection.regex_of(selection.parse(self.list.read_text(encoding="utf-8")))

    def test_whole_file_selects_every_mutant_of_that_file_only(self):
        hits = selected(self.regex())
        self.assertIn(NAMES[0], hits)
        self.assertIn(NAMES[1], hits)
        self.assertNotIn(NAMES[7], hits)  # same basename in another crate
        self.assertNotIn(NAMES[8], hits)  # a longer file name with the same prefix

    def test_scoped_entry_selects_only_the_named_functions(self):
        hits = selected(self.regex())
        self.assertIn(NAMES[2], hits)
        self.assertIn(NAMES[3], hits)
        self.assertIn(NAMES[4], hits)
        self.assertNotIn(NAMES[5], hits)  # build_request_with_resource is not build_request
        self.assertNotIn(NAMES[6], hits)  # another function of the same file

    def test_the_regex_is_one_line(self):
        self.assertNotIn("\n", self.regex())

    def test_comments_blank_lines_and_the_path_order_are_handled(self):
        entries = selection.parse("\n# only comments\n\ncrates/a/src/x.rs  # tail\n")
        self.assertEqual(entries, [("crates/a/src/x.rs", [])])

    def test_bad_paths_and_names_fail_closed(self):
        for text in ["crates/../x.rs\n", "crates/a//x.rs\n", "tools/x.py\n", "crates/a/x.rs @ bad-name\n", "crates/a/x.rs @\n", "\n# nothing\n"]:
            with self.subTest(text=text):
                with self.assertRaises(selection.ListError):
                    selection.parse(text)

    def test_property_random_names_match_iff_path_and_function_are_listed(self):
        rng = random.Random(4721)
        paths = ["crates/a/src/jwt.rs", "crates/a/src/eval.rs", "crates/b/src/jwt.rs", "crates/a/src/other.rs"]
        functions = ["build_request", "request_path", "verify", "build_request_with_resource", "other"]
        regex = self.regex()
        for _ in range(300):
            path = rng.choice(paths)
            function = rng.choice(functions)
            line, column = rng.randrange(1, 9999), rng.randrange(1, 200)
            verb = rng.choice(["replace", "delete"])
            name = f"{path}:{line}:{column}: {verb} {function} -> bool with true" if verb == "replace" else f"{path}:{line}:{column}: delete ! in {function}"
            expected = (path == "crates/a/src/jwt.rs") or (path == "crates/a/src/eval.rs" and function in ("build_request", "request_path"))
            self.assertEqual(bool(re.search(regex, name)), expected, name)


class CliTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.list = self.root / "list.txt"

    def run_main(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = selection.main(list(args))
        return code, out.getvalue(), err.getvalue()

    def test_paths_mode_lists_each_file_once(self):
        self.list.write_text("crates/a/src/x.rs @ f\ncrates/a/src/x.rs @ g\ncrates/a/src/y.rs\n", encoding="utf-8")
        code, out, _ = self.run_main("--paths", str(self.list))
        self.assertEqual((code, out), (0, "crates/a/src/x.rs\ncrates/a/src/y.rs\n"))

    def test_packages_mode_lists_each_package_once(self):
        self.list.write_text("crates/a/src/x.rs @ f\ncrates/b/src/y.rs\ncrates/a/src/z.rs\n", encoding="utf-8")
        code, out, _ = self.run_main("--packages", str(self.list))
        self.assertEqual((code, out), (0, "a b\n"))

    def test_check_accepts_existing_paths_and_functions(self):
        write(self.root, "crates/a/src/x.rs", "pub fn build_request() {}\n")
        self.list.write_text("crates/a/src/x.rs @ build_request\n", encoding="utf-8")
        self.assertEqual(self.run_main("--check", str(self.list), str(self.root))[0], 0)

    def test_check_refuses_a_missing_file_or_function(self):
        write(self.root, "crates/a/src/x.rs", "pub fn other() {}\n")
        self.list.write_text("crates/a/src/missing.rs\n", encoding="utf-8")
        code, _, err = self.run_main("--check", str(self.list), str(self.root))
        self.assertEqual(code, 1)
        self.assertIn("no such file", err)
        self.list.write_text("crates/a/src/x.rs @ build_request\n", encoding="utf-8")
        code, _, err = self.run_main("--check", str(self.list), str(self.root))
        self.assertEqual(code, 1)
        self.assertIn("no function build_request", err)

    def test_usage_errors_exit_two(self):
        self.assertEqual(self.run_main()[0], 2)
        self.assertEqual(self.run_main("--regex")[0], 2)
        self.assertEqual(self.run_main("--check", str(self.list))[0], 2)

    def test_the_committed_list_is_valid_and_matches_the_counts_of_the_file(self):
        committed = Path(__file__).with_name("mutation-critical.txt")
        entries = selection.parse(committed.read_text(encoding="utf-8"))
        self.assertEqual(len(entries), 7)
        self.assertEqual(self.run_main("--check", str(committed), str(Path(__file__).resolve().parents[2]))[0], 0)


if __name__ == "__main__":
    unittest.main()
