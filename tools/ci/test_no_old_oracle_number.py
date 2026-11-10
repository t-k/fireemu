"""The number of the retired production oracle project must not come back into a tracked file.

The number is not written here: the guard keeps only a salted SHA-256 of it and compares every run of
twelve digits in every tracked text file (and every twelve-digit window of a longer run). Owner decision
2026-11-10 (ledger 2409): the number is masked as `<project-number>` and the evidence is rebound; see
spec/compatibility/oracle-number-mask-2026-11-10.json. An encoded form (base64 of a protobuf varint, for
example) cannot be found from a hash; `docs.local/tools/scan-encoded-numbers` covers that before a push.
"""

import hashlib
import random
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SALT = "bad1c4537893e98c9e3868163c51982f"
RETIRED_NUMBER_SHA256 = "bb461703130f601b4ae2be712c7d26cf687110ce45b95349a4439d9229a6dde5"
DIGIT_RUN = re.compile(rb"\d{12,}")


def salted(number: bytes, salt: str = SALT) -> str:
    return hashlib.sha256(salt.encode() + b":" + number).hexdigest()


def finds_number(data: bytes, wanted: str, salt: str = SALT) -> bool:
    for run in DIGIT_RUN.findall(data):
        for start in range(len(run) - 11):
            if salted(run[start : start + 12], salt) == wanted:
                return True
    return False


class RetiredOracleNumberTest(unittest.TestCase):
    def test_detector_finds_a_listed_number_in_a_digit_run(self):
        made_up = b"123456789012"
        wanted = salted(made_up, "test-salt")
        for text in (b"x=123456789012;", b"projects/123456789012/config", b"9123456789012", b"123456789012345"):
            self.assertTrue(finds_number(text, wanted, "test-salt"), text)

    def test_detector_ignores_other_numbers_and_short_runs(self):
        wanted = salted(b"123456789012", "test-salt")
        for text in (b"123456789013", b"12345678901 2", b"12345678901", b"abc", b""):
            self.assertFalse(finds_number(text, wanted, "test-salt"), text)

    def test_detector_property_over_random_surroundings(self):
        rng = random.Random(20261110)
        for _ in range(300):
            number = str(rng.randrange(10**11, 10**12)).encode()
            wanted = salted(number, "p")
            head = bytes(rng.choice(b"abc/=\"- \n") for _ in range(rng.randrange(0, 6))) + bytes(
                rng.choice(b"0123456789") for _ in range(rng.randrange(0, 4))
            )
            tail = bytes(rng.choice(b"0123456789") for _ in range(rng.randrange(0, 4))) + bytes(
                rng.choice(b"xyz/,\"- \n") for _ in range(rng.randrange(0, 6))
            )
            self.assertTrue(finds_number(head + number + tail, wanted, "p"), (head, number, tail))
            other = bytes(number[:-1]) + bytes([ord("0") + (number[-1] - ord("0") + 1) % 10])
            self.assertFalse(finds_number(head + other + tail, wanted, "p"), (head, other, tail))

    def test_the_hash_is_salt_colon_number(self):
        # Pins the construction: the guard's stored hash was made this way, so a different
        # construction would compare against nothing and pass silently.
        self.assertEqual(salted(b"123456789012", "test-salt"), "cdabbd99cc8e65e631ccdafe205939506ee6a534ebaf9e6eb7c0c6ca1391892e")
        self.assertRegex(RETIRED_NUMBER_SHA256, r"^[0-9a-f]{64}$")

    def test_salt_matters(self):
        self.assertFalse(finds_number(b"123456789012", salted(b"123456789012", "a"), "b"))

    def test_no_tracked_text_file_holds_the_retired_number(self):
        names = subprocess.run(
            ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True
        ).stdout.split(b"\0")
        hits = []
        for name in filter(None, names):
            path = ROOT / name.decode()
            if path.is_symlink() or not path.is_file():
                continue
            data = path.read_bytes()
            if finds_number(data, RETIRED_NUMBER_SHA256):
                hits.append(name.decode())
        self.assertEqual(hits, [], "the retired oracle project number is back in: " + ", ".join(hits))


if __name__ == "__main__":
    unittest.main()
