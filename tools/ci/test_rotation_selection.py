"""Tests of tools/ci/rotation-selection.py: the rotation line becomes a regex over the package's files."""

import importlib.util
import random
import re
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("rotation_selection", Path(__file__).with_name("rotation-selection.py"))
rotation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rotation)

FILES = [
    "crates/fireemu-core-auth/src/jwt.rs",
    "crates/fireemu-core-auth/src/mfa.rs",
    "crates/fireemu-core-auth/src/store.rs",
    "crates/fireemu-core-auth/src/sub/jwt.rs",
    "crates/fireemu-core-authz/src/jwt.rs",
    "crates/fireemu-core-auth/tests/jwt.rs",
]
NAMES = [
    "crates/fireemu-core-auth/src/jwt.rs:4:5: replace verify -> bool with true",
    "crates/fireemu-core-auth/src/mfa.rs:9:1: delete ! in verify",
    "crates/fireemu-core-auth/src/store.rs:3:3: replace x with y in z",
    "crates/fireemu-core-auth/src/sub/jwt.rs:2:2: replace v -> u with 0",
    "crates/fireemu-core-authz/src/jwt.rs:4:5: replace verify -> bool with true",
]


def selected(regex):
    return [name for name in NAMES if re.search(regex, name)]


class SelectionTest(unittest.TestCase):
    def regex(self, *tokens, files=FILES, package="fireemu-core-auth"):
        return rotation.select(package, list(tokens), files)

    def test_no_token_selects_every_file_of_the_package(self):
        hits = selected(self.regex())
        self.assertEqual(len(hits), 4)
        self.assertNotIn(NAMES[4], hits)  # the same prefix in another package

    def test_an_include_path_selects_only_that_file(self):
        self.assertEqual(selected(self.regex("crates/fireemu-core-auth/src/mfa.rs")), [NAMES[1]])

    def test_a_glob_include_selects_the_matching_files_and_its_star_crosses_directories(self):
        # Like the globset that cargo-mutants uses, `*` also matches across `/`: src/sub/jwt.rs is included.
        self.assertEqual(
            selected(self.regex("crates/fireemu-core-auth/src/*.rs")),
            [NAMES[0], NAMES[1], NAMES[2], NAMES[3]],
        )

    def test_an_exclusion_removes_a_file_from_the_package(self):
        hits = selected(self.regex("!crates/fireemu-core-auth/src/store.rs"))
        self.assertNotIn(NAMES[2], hits)
        self.assertIn(NAMES[0], hits)

    def test_a_dot_in_a_name_is_literal(self):
        # The include `jwt.rs` must not match `jwtXrs.rs`: with only that file present, nothing is selected.
        files = ["crates/fireemu-core-auth/src/jwtXrs.rs"]
        with self.assertRaises(ValueError):
            self.regex("crates/fireemu-core-auth/src/jwt.rs", files=files)

    def test_the_regex_is_one_line_without_spaces_or_lookaround(self):
        regex = self.regex("crates/fireemu-core-auth/src/*.rs", "!crates/fireemu-core-auth/src/store.rs")
        self.assertNotIn(" ", regex)
        self.assertNotIn("\n", regex)
        self.assertNotIn("(?", regex)

    def test_bad_input_is_refused(self):
        for args in [
            ("fireemu-core-auth", "../x.rs"),
            ("fireemu-core-auth", "a b"),
            ("Bad_Package",),
            ("fireemu-core-auth", "crates/fireemu-core-auth/src/none.rs"),
            ("fireemu-core-auth", "crates/fireemu-core-auth/src/*.rs", "!crates/fireemu-core-auth/src/*.rs"),
        ]:
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    rotation.select(args[0], list(args[1:]), FILES)

    def test_a_random_name_matches_iff_its_file_is_selected(self):
        rng = random.Random(9031)
        universe = FILES + ["crates/fireemu-core-auth/src/other.rs"]
        regex = self.regex("crates/fireemu-core-auth/src/*.rs", "!crates/fireemu-core-auth/src/store.rs", files=universe)
        for _ in range(300):
            path = rng.choice(universe)
            name = f"{path}:{rng.randrange(1, 9999)}:{rng.randrange(1, 99)}: replace f -> bool with true"
            expected = (
                path.startswith("crates/fireemu-core-auth/src/")
                and path.endswith(".rs")
                and path != "crates/fireemu-core-auth/src/store.rs"
            )
            self.assertEqual(bool(re.search(regex, name)), expected, name)


if __name__ == "__main__":
    unittest.main()
