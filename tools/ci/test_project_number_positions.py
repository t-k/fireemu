"""No project number of a real project may be written into a tracked text file.

Owner decision 2026-11-10 (ledger 2409): the project number of the retired oracle project is masked as
`<project-number>` (record: spec/compatibility/oracle-number-mask-2026-11-10.json). This guard does not know any
number. It looks at the places where a project number is written and fails on a run of 10 to 13 digits there, unless
the run is on the list of made-up numbers below (test data). The places are the `projects/<digits>` path segments,
the `<digits>-compute@` and `service-<digits>@` service accounts, the `gcf-sources-`/`gcf-v2-uploads-` bucket names,
`NUMBER = <digits>` constants, and `projectNumber`, `project_number`, `project_id` and `user-project` fields. A new made-up number for a test goes
into ALLOWED_MADE_UP_NUMBERS in the same commit, which is a visible edit. Encoded forms (a base64 protobuf varint)
are not found here; run `docs.local/tools/scan-encoded-numbers` before a push.
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
    592603257416
    210987654321
    9999999999
    """.split()
)
POSITIONS = {
    "projects path": re.compile(r"projects/(\d{10,13})(?!\d)"),
    "compute service account": re.compile(r"(?<!\d)(\d{10,13})-compute@"),
    "service agent": re.compile(r"(?<!\d)(?:service-)?(\d{10,13})@[a-z0-9.-]*(?:gserviceaccount|gcp-sa)"),
    "gcf bucket": re.compile(r"gcf-(?:v2-)?(?:sources|uploads)-(\d{10,13})(?!\d)"),
    "number constant": re.compile(r"(?<![A-Za-z0-9])(?:[A-Z]+_)*NUMBER[ \t]*=[ \t]*[\"']?(\d{10,13})(?!\d)"),
    "project number field": re.compile(r"(?i)project[_-]?number\W{0,8}(\d{10,13})(?!\d)"),
    "project id field": re.compile(r"(?i)project[_-]?id\W{0,8}(\d{10,13})(?!\d)"),
    "user project header": re.compile(r"(?i)user-project\W{0,4}(\d{10,13})(?!\d)"),
}


def numbers_in_positions(text, allowed=ALLOWED_MADE_UP_NUMBERS):
    """(position, number) for every project-number position that holds a number not on the made-up list."""
    return [
        (name, match.group(1))
        for name, pattern in POSITIONS.items()
        for match in pattern.finditer(text)
        if match.group(1) not in allowed
    ]


SAMPLES = {
    "projects path": "name: projects/%s/config",
    "compute service account": "%s-compute@developer.gserviceaccount.com",
    "service agent": "service-%s@gcp-sa-pubsub.iam.gserviceaccount.com",
    "gcf bucket": "gcf-v2-uploads-%s.us-central1.cloudfunctions.appspot.com",
    "number constant": 'NUMBER = "%s"',
    "project number field": '"projectNumber": "%s"',
    "project id field": "project_id = '%s'",
    "user project header": "x-goog-user-project: %s",
}


class ProjectNumberPositionsTest(unittest.TestCase):
    def test_a_number_in_every_position_is_found(self):
        for name, sample in SAMPLES.items():
            self.assertEqual(numbers_in_positions(sample % "987654321098"), [(name, "987654321098")], name)

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

    def test_the_list_holds_only_digit_runs(self):
        self.assertTrue(all(re.fullmatch(r"\d{10,13}", number) for number in ALLOWED_MADE_UP_NUMBERS))

    def test_property_a_planted_number_is_found_in_random_surroundings(self):
        rng = random.Random(20261110)
        names = list(SAMPLES)
        for _ in range(300):
            number = str(rng.randrange(10**11, 10**12))
            if number in ALLOWED_MADE_UP_NUMBERS:
                continue
            name = rng.choice(names)
            around = "".join(rng.choice(" /=\"\n,-") for _ in range(rng.randrange(0, 6)))
            text = around + SAMPLES[name] % number + around
            self.assertEqual(numbers_in_positions(text), [(name, number)], text)
            self.assertEqual(numbers_in_positions(text, frozenset({number})), [], text)

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
