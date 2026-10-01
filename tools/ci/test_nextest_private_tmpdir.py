"""Tests of tools/ci/nextest-private-tmpdir.sh, the nextest wrapper that gives each test process a
private TMPDIR, removes it afterwards and fails a test that left anything in it."""

import os
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

WRAPPER = Path(__file__).with_name("nextest-private-tmpdir.sh")
# CI runs the wrapper with dash as /bin/sh; run it the same way here, not with the login shell.
SHELL = "/bin/sh"


class WrapperTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.parent = Path(self.tmp.name)
        self.root = self.parent / "fireemu-test-tmp"

    def tearDown(self):
        self.tmp.cleanup()

    def run_wrapped(self, script, env=None):
        environment = dict(os.environ, TMPDIR=str(self.parent) + "/", **(env or {}))
        return subprocess.run(
            [SHELL, str(WRAPPER), SHELL, "-c", script],
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
        )

    def private_dirs(self):
        return sorted(self.root.iterdir()) if self.root.exists() else []

    def test_the_test_sees_a_private_directory_under_the_run_root(self):
        result = self.run_wrapped('printf "%s" "$TMPDIR"')
        self.assertEqual(result.returncode, 0, result.stderr)
        seen = Path(result.stdout)
        self.assertEqual(seen.parent, self.root)
        self.assertRegex(seen.name, r"^[0-9]+\.[A-Za-z0-9]{6}$")
        self.assertTrue(result.stdout.endswith("/"))
        self.assertEqual(self.private_dirs(), [], "the private directory is removed")

    def test_a_clean_test_keeps_its_exit_status(self):
        self.assertEqual(self.run_wrapped("exit 0").returncode, 0)
        self.assertEqual(self.run_wrapped("exit 101").returncode, 101)
        self.assertEqual(self.private_dirs(), [])

    def test_a_passing_test_that_leaves_an_entry_fails_and_names_it(self):
        result = self.run_wrapped('mkdir "$TMPDIR/leaked-dir" && : > "$TMPDIR/leaked-file"')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("leaked-dir", result.stderr)
        self.assertIn("leaked-file", result.stderr)
        self.assertEqual(self.private_dirs(), [], "the leftovers are removed anyway")

    def test_a_failing_test_keeps_its_own_status_and_its_leftovers_are_removed(self):
        result = self.run_wrapped('mkdir -p "$TMPDIR/a/b" && chmod 500 "$TMPDIR/a" && exit 7')
        self.assertEqual(result.returncode, 7)
        self.assertIn("a", result.stderr)
        self.assertEqual(self.private_dirs(), [], "even a read-only leftover is removed")

    def test_dot_entries_count_as_leftovers(self):
        result = self.run_wrapped(': > "$TMPDIR/.hidden"')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(".hidden", result.stderr)

    def test_a_nested_run_shares_the_outer_root_and_leaves_nothing_in_the_outer_test(self):
        # crates/fireemu/tests/leak_fixture.rs runs nextest inside a test.
        nested = f'{SHELL} {WRAPPER} {SHELL} -c "printf %s \\"\\$TMPDIR\\""'
        result = self.run_wrapped(nested)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(Path(result.stdout).parent, self.root)
        self.assertEqual(self.private_dirs(), [])

    def test_an_unset_tmpdir_falls_back_to_tmp(self):
        environment = {k: v for k, v in os.environ.items() if k != "TMPDIR"}
        result = subprocess.run(
            [SHELL, str(WRAPPER), SHELL, "-c", 'printf "%s" "$TMPDIR"'],
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.startswith("/tmp/fireemu-test-tmp/"), result.stdout)

    def test_a_dead_wrappers_directory_is_reclaimed_and_a_live_ones_is_kept(self):
        self.root.mkdir()
        dead = subprocess.Popen(["true"])
        dead.wait()
        stale = self.root / f"{dead.pid}.AAAAAA"
        (stale / "inner").mkdir(parents=True)
        live = self.root / f"{os.getpid()}.BBBBBB"
        live.mkdir()
        foreign = self.root / "not-a-wrapper-dir"
        foreign.mkdir()
        self.assertEqual(self.run_wrapped("exit 0").returncode, 0)
        self.assertFalse(stale.exists(), "the killed wrapper's directory is removed")
        self.assertTrue(live.exists(), "a running wrapper's directory is kept")
        self.assertTrue(foreign.exists(), "a name the wrapper did not make is left alone")

    def test_a_terminated_run_still_removes_the_private_directory(self):
        environment = dict(os.environ, TMPDIR=str(self.parent) + "/")
        process = subprocess.Popen(
            [SHELL, str(WRAPPER), SHELL, "-c", 'mkdir "$TMPDIR/x"; trap "exit 143" TERM; while :; do sleep 0.1; done'],
            env=environment,
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not any(d.joinpath("x").exists() for d in self.private_dirs()):
            time.sleep(0.05)
        self.assertTrue(self.private_dirs(), "the test started")
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=10)
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(self.private_dirs(), [])


if __name__ == "__main__":
    unittest.main()
