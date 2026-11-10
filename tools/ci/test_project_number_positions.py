"""No project number of a real project may be written into a tracked text file (a backstop, not the exact check).

Owner decision 2026-11-10 (ledger 2409): the project number of the retired oracle project is masked as
`<project-number>` (record: spec/compatibility/oracle-number-mask-2026-11-10.json). This guard knows no number. It
looks at the places where a project number is written and fails on a run of 10 to 13 digits there, unless the run is
on the list of made-up numbers below (test data). The places are `projects/<digits>` path segments, `<digits>-compute@`
and `service-<digits>@` service accounts, `gcf-sources-`/`gcf-v2-uploads-` bucket names, `acat.p2-<digits>` operation
names, `NUMBER = <digits>` constants, `projectNumber`/`project number`, `project_id`/`project id`, `project <digits>`
and `user-project` forms, and a project id followed by a number (`fireemu-35fe6 / <digits>`, `{"id": "<digits>"}`).
A number written in any other way passes this guard. Exact-match detection is done by the local pre-commit and pre-push
hooks, which read the real numbers from the untracked local sources, and by `docs.local/tools/scan-encoded-numbers`
(plain and base64 forms). A new made-up number for a test goes into ALLOWED_MADE_UP_NUMBERS in the same commit, which
is a visible edit; `test_no_made_up_number_is_near_a_real_local_project_number` keeps every entry at least 3 digits
away from the real numbers wherever the local sources exist.
"""

import random
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ALLOWED_MADE_UP_NUMBERS = frozenset(
    """
    123456789012
    1234567890
    111111111111
    000000000000
    222222222222
    9876543210
    999999999999
    637500000000
    555500000001
    111222333444
    444455556666
    123456789013
    333333333333
    12345678901
    999888777666
    100000000001
    555555555555
    1234567890123
    424242424242
    444444444444
    5555555555
    2222222222
    0123456789
    210987654321
    9999999999
    """.split()
)
POSITIONS = {
    "projects path": re.compile(r"projects/(\d{10,13})(?!\d)"),
    "compute service account": re.compile(r"(?<!\d)(\d{10,13})-compute@"),
    "service agent": re.compile(r"(?<!\d)(?:service-)?(\d{10,13})@[a-z0-9.-]*(?:gserviceaccount|gcp-sa)"),
    "gcf bucket": re.compile(r"gcf-(?:v2-)?(?:sources|uploads)-(\d{10,13})(?!\d)"),
    "operation name": re.compile(r"acat\.p2-(\d{10,13})(?!\d)"),
    "number constant": re.compile(r"(?<![A-Za-z0-9])(?:[A-Z]+_)*NUMBER[ \t]*=[ \t]*[\"']?(\d{10,13})(?![0-9A-Za-z])"),
    "project number field": re.compile(
        r"(?i)project(?:[_-]|\s+)?number\W{0,8}(?:is)?[\s\"'`]*(\d{10,13})(?![0-9A-Za-z])"
    ),
    "project id field": re.compile(
        r"(?i)project(?:[_-]|\s+)?id\W{0,8}(?:is)?[\s\"'`]*(\d{10,13})(?![0-9A-Za-z])"
    ),
    "project in prose": re.compile(r"(?i)\bproject(?:[\s\"'`]|\\[nrt])*(\d{10,13})(?![0-9A-Za-z])"),
    "id and number pair": re.compile(
        r"(?i)(?<![a-z0-9])[a-z][a-z0-9]*(?:-[a-z0-9]+)+[\"'`]?\s*(?:[/:]|\bto\b)\s*(?:number\s*)?[\"'`]?\s*(\d{10,13})(?![0-9A-Za-z])"
    ),
    "user project header": re.compile(r"(?i)user-project\W{0,4}(\d{10,13})(?![0-9A-Za-z])"),
}


def numbers_in_positions(text, allowed=ALLOWED_MADE_UP_NUMBERS):
    """(position, number) for every project-number position that holds a number not on the made-up list."""
    return [
        (name, match.group(1))
        for name, pattern in POSITIONS.items()
        for match in pattern.finditer(text)
        if match.group(1) not in allowed
    ]


def too_close(candidate, real):
    """A made-up number must not reveal a real one: at most 2 digits apart (same length), or sharing 8 leading digits."""
    if len(candidate) == len(real) and sum(a != b for a, b in zip(candidate, real)) <= 2:
        return True
    return len(real) >= 8 and candidate[:8] == real[:8]


def local_real_numbers(root=ROOT):
    """Every 10 to 13 digit number in the local, untracked sources of the real project numbers, or None when absent."""
    sources = []
    for base in (root, *root.parents):
        for relative in ("CLAUDE.local.md", "docs.local/sandbox-oracles.md"):
            if (base / relative).is_file():
                sources.append(base / relative)
    if not sources:
        return None
    return {
        number
        for source in sources
        for number in re.findall(r"(?<!\d)(\d{10,13})(?!\d)", source.read_text(encoding="utf-8", errors="replace"))
    }


# One or more written forms per position, as they appeared in the files (made-up values are put in by the tests).
SAMPLES = {
    "projects path": ["name: projects/%s/config"],
    "compute service account": ["%s-compute@developer.gserviceaccount.com"],
    "service agent": ["service-%s@gcp-sa-pubsub.iam.gserviceaccount.com"],
    "gcf bucket": ["gcf-v2-uploads-%s.us-central1.cloudfunctions.appspot.com"],
    "operation name": ["operations/acat.p2-%s-0123abcd-4567"],
    "number constant": ['NUMBER = "%s"'],
    "project number field": ['"projectNumber": "%s"', "project number `%s`;", "bound to project number %s."],
    "project id field": ["project_id = '%s'", "Production project_id is %s, local", "project_id is%s,"],
    "project in prose": ["API-key ownership in project %s", "ownership in project\\n%s"],
    "id and number pair": [
        'authorized fireemu-35fe6 / %s project',
        'fixed to `fireemu-35fe6` / `%s`.',
        '{"fireemu-35fe6": "%s"}',
        "fireemu-35fe6/number `%s`, database",
        "`fireemu-35fe6` to number`%s`.",
    ],
    "user project header": ["x-goog-user-project: %s"],
}


def found_in(text, allowed=ALLOWED_MADE_UP_NUMBERS):
    return {(name, number) for name, number in numbers_in_positions(text, allowed)}


class ProjectNumberPositionsTest(unittest.TestCase):
    def test_a_number_in_every_written_form_of_every_position_is_found(self):
        for name, samples in SAMPLES.items():
            for sample in samples:
                self.assertIn((name, "987654321098"), found_in(sample % "987654321098"), sample)

    def test_the_six_prose_and_map_shapes_the_first_guard_missed_are_each_found(self):
        planted = "987654321098"
        for text in (
            "project number `%s`",  # a space, not an underscore
            "fireemu-35fe6 / %s",  # id slash number
            '{"fireemu-35fe6": "%s"}',  # the map form
            "ownership in project %s",
            "Production project_id is %s",
            "operations/acat.p2-%s-eef3de6",
        ):
            self.assertTrue(found_in(text % planted), text)

    def test_spacing_and_quoting_variants_are_found(self):
        planted = "987654321098"
        for text in (
            "project `%s`",  # a backtick-quoted number after the word
            'project_id is "%s"',  # a quote after is
            "project_id is '%s'",
            "project  number %s",  # two spaces
            "project\tnumber %s",  # a tab
            "project \t number\n%s",
            "project_number is `%s`",
            "project  id is %s",
            'project number is "%s"',
            "project\tid %s",
            '{"fireemu-35fe6" : " %s"}',  # a space before the colon and one inside the value
            "{'fireemu-35fe6' :\t'%s'}",
            "fireemu-35fe6 /  `%s`",
            "fireemu-35fe6\t/\tnumber \"%s\"",
        ):
            self.assertTrue(found_in(text % planted), repr(text))

    def test_near_misses_of_the_variants_are_not_findings(self):
        planted = "987654321098"
        for text in (
            "projectile %s",  # not the word project
            "subproject %s",
            "my-project %sx",
            "project number %s77",  # fourteen digits
            "project number %sab",  # a word or hex continues
            "project_id is %sxyz",
            "project  numbers",  # no number
            'NUMBER = "%sab"',
            "x-goog-user-project: %sx",
            "project_id is 987654321",  # nine digits
            'project_id is "98765432109876"',  # fourteen digits
            "projects",
        ):
            self.assertEqual(found_in(text % planted if "%s" in text else text), set(), repr(text))

    def test_a_thirteen_and_a_ten_digit_number_are_found_too(self):
        for number in ("9876543210987", "9876543210"):
            self.assertTrue(numbers_in_positions("projects/" + number + "/x", frozenset()), number)

    def test_placeholders_made_up_numbers_and_other_digit_runs_are_not_findings(self):
        for text in (
            "projects/<project-number>/config",
            '"projectNumber": "<project-number>"',
            "projects/123456789012/config",
            "projects/987654321/config",
            "projects/98765432109876/config",
            "order 987654321098 shipped",
            "projectNumber missing",
        ):
            self.assertEqual(numbers_in_positions(text), [], text)

    def test_every_number_in_a_text_is_reported_not_only_the_first(self):
        numbers = ["987654321098", "876543210987", "765432109876"]
        text = "projects/%s/a projects/%s/b" % (numbers[0], numbers[1]) + ' "projectNumber": "%s"' % numbers[2]
        self.assertEqual(sorted(number for _, number in numbers_in_positions(text)), sorted(numbers))

    def test_a_constant_must_be_named_NUMBER_not_end_in_it_mid_word(self):
        number = "987654321098"
        self.assertEqual(numbers_in_positions('PHONENUMBER = "%s"' % number), [])
        self.assertEqual(numbers_in_positions('PROJECT_NUMBER = "%s"' % number)[0][0], "number constant")

    def test_the_distance_rule_catches_a_near_miss_and_a_shared_prefix(self):
        real = "246813579024"  # made up
        # 1 or 2 digits apart, changed within the first eight so that only the distance rule can catch them
        for near in ("146813579024", "156813579024", "246813579025", "256813579024", "246813578024"):
            self.assertTrue(too_close(near, real), near)
        self.assertTrue(too_close("246813578999", real))  # exactly eight shared leading digits, far apart otherwise
        for far in ("157813579024", "246803579134", "987654321098", "14681357902", "246813589999"):
            self.assertFalse(too_close(far, real), far)  # 3 apart, unrelated, shorter, seven shared digits

    def test_local_sources_are_found_in_an_ancestor_of_the_checkout(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            top = Path(tmp)
            checkout = top / ".worktree" / "x"
            checkout.mkdir(parents=True)
            self.assertIsNone(local_real_numbers(checkout))
            first, second = "123456789000", "1234567890123"
            (top / "CLAUDE.local.md").write_text("owner note: %s and 12345" % first)
            (top / "docs.local").mkdir()
            (top / "docs.local" / "sandbox-oracles.md").write_text("note %s, phone 5" % second)
            self.assertEqual(local_real_numbers(checkout), {first, second})

    def assert_none_close(self, allowed, real_numbers):
        # A boolean and a fixed message: a failure must never print a number.
        self.assertFalse(
            any(too_close(a, r) for a in allowed for r in real_numbers),
            "an allowlist entry is within 2 digits of a local project number",
        )

    def test_the_proximity_failure_prints_no_number(self):
        allowed, real = {"246813579025"}, {"246813579024"}  # made up
        with self.assertRaises(AssertionError) as caught:
            self.assert_none_close(allowed, real)
        output = str(caught.exception)
        self.assertIn("within 2 digits", output)
        self.assertNotRegex(output, r"\d{6,}")
        for number in allowed | real:
            self.assertNotIn(number, output)
        self.assert_none_close({"135792468013"}, real)

    def test_no_made_up_number_is_near_a_real_local_project_number(self):
        real_numbers = local_real_numbers()
        if real_numbers is None:
            self.skipTest("CLAUDE.local.md and docs.local/sandbox-oracles.md are not present (CI); the pre-commit run checks this")
        self.assert_none_close(ALLOWED_MADE_UP_NUMBERS, real_numbers)

    def test_the_list_holds_only_digit_runs(self):
        self.assertTrue(all(re.fullmatch(r"\d{10,13}", number) for number in ALLOWED_MADE_UP_NUMBERS))

    def test_a_hex_identifier_that_starts_with_digits_is_not_a_number(self):
        for text in ("FS-LISTEN-SDK/8171997312777ab0d3a88fe1bc6699dd", "o6/FS-LISTEN-SDK/8171997312777ab0", "project 8171997312777ab0"):
            self.assertEqual(found_in(text), set(), text)

    def test_property_a_planted_number_is_found_in_random_surroundings(self):
        rng = random.Random(20261110)
        shapes = [(name, sample) for name, samples in SAMPLES.items() for sample in samples]
        for _ in range(400):
            number = str(rng.randrange(10**11, 10**12))
            if number in ALLOWED_MADE_UP_NUMBERS:
                continue
            name, sample = rng.choice(shapes)
            around = "".join(rng.choice(" /=\"\n,-") for _ in range(rng.randrange(0, 6)))
            text = around + sample % number + around
            self.assertIn((name, number), found_in(text), text)
            self.assertEqual({n for _, n in found_in(text)}, {number}, text)
            self.assertEqual(found_in(text, frozenset({number})), set(), text)

    def test_no_tracked_text_file_writes_a_real_project_number(self):
        names = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout.split(b"\0")
        findings = []
        for name in filter(None, names):
            path = ROOT / name.decode()
            if path.is_symlink() or not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            findings += [f"{name.decode()}: {position}" for position, _ in numbers_in_positions(text)]
        self.assertEqual(findings, [], "a project number is written outside the made-up list (the number is not printed)")


if __name__ == "__main__":
    unittest.main()
