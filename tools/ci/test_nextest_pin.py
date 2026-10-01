"""Every workflow installs the same cargo-nextest version.

.config/nextest.toml relies on the experimental `wrapper-scripts` feature
(tools/ci/nextest-private-tmpdir.sh), so a nextest release that changes its syntax must not reach
a pull request or a release by an unpinned install. heavy-verification.yml pins the version the
wrapper was checked with; ci.yml and release.yml must name the same one.
"""

import re
import unittest
from pathlib import Path

WORKFLOWS = Path(__file__).resolve().parents[2] / ".github" / "workflows"
INSTALL = re.compile(r"^\s*tool:\s*(.+)$", re.MULTILINE)


def nextest_installs(text):
    """The cargo-nextest entries of every `tool:` line, as written (with or without @version)."""
    found = []
    for line in INSTALL.findall(text):
        for tool in line.split(","):
            tool = tool.strip()
            if tool == "cargo-nextest" or tool.startswith("cargo-nextest@"):
                found.append(tool)
    return found


class NextestPinTest(unittest.TestCase):
    def test_the_parser_finds_pinned_and_unpinned_installs(self):
        text = "        with:\n          tool: cargo-mutants@27.1.0,cargo-nextest@0.9.143\n          tool: cargo-nextest\n"
        self.assertEqual(nextest_installs(text), ["cargo-nextest@0.9.143", "cargo-nextest"])
        self.assertEqual(nextest_installs("          tool: cargo-nextest-extra\n"), [])

    def test_every_install_names_the_heavy_verification_version(self):
        reference = nextest_installs((WORKFLOWS / "heavy-verification.yml").read_text())
        self.assertTrue(reference)
        versions = {tool for tool in reference}
        self.assertEqual(len(versions), 1, versions)
        (pinned,) = versions
        self.assertRegex(pinned, r"^cargo-nextest@\d+\.\d+\.\d+$")
        for name in ("ci.yml", "release.yml"):
            installs = nextest_installs((WORKFLOWS / name).read_text())
            self.assertTrue(installs, name)
            for tool in installs:
                self.assertEqual(tool, pinned, f"{name} installs {tool}")


if __name__ == "__main__":
    unittest.main()
