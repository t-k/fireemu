"""Tests of tools/ci/nextest-private-tmpdir.sh, the nextest wrapper that gives each test process a
private TMPDIR, removes it afterwards and fails a test that left anything in it."""

import os
import signal
import stat
import sys
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

WRAPPER = Path(__file__).with_name("nextest-private-tmpdir.sh")
# CI runs the wrapper with dash as /bin/sh; run it the same way here, not with the login shell.
# WRAPPER_TEST_SHELL=/bin/dash checks dash on a machine whose /bin/sh is bash.
SHELL = os.environ.get("WRAPPER_TEST_SHELL", "/bin/sh")


def backdate(path, days=2):
    """Makes `path` look older than the wrapper's one-day reclaim threshold."""
    then = time.time() - days * 86400
    os.utime(path, (then, then), follow_symlinks=False)


class WrapperTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.parent = Path(self.tmp.name)
        self.root = self.parent / f"fireemu-test-tmp-{os.getuid()}"

    def tearDown(self):
        if sys.platform == "darwin":
            subprocess.run(["chflags", "-R", "nouchg", self.tmp.name], check=False)
        self.tmp.cleanup()

    def run_wrapped(self, script, env=None):
        environment = {**os.environ, "TMPDIR": str(self.parent) + "/", **(env or {})}
        return subprocess.run(
            [SHELL, str(WRAPPER), SHELL, "-c", script],
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
        )

    def start_wrapped(self, script):
        """A wrapped long-running test in its own process group, killed at the end of the test
        whatever happens, so a failing assertion never leaves it running."""
        environment = dict(os.environ, TMPDIR=str(self.parent) + "/")
        process = subprocess.Popen(
            [SHELL, str(WRAPPER), SHELL, "-c", script],
            env=environment,
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        def reap():
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()

        self.addCleanup(reap)
        return process

    def private_dirs(self):
        return sorted(self.root.iterdir()) if self.root.exists() else []

    def test_the_test_sees_a_private_directory_under_the_run_root(self):
        result = self.run_wrapped('printf "%s" "$TMPDIR"')
        self.assertEqual(result.returncode, 0, result.stderr)
        seen = Path(result.stdout)
        self.assertEqual(seen.parent, self.root)
        self.assertRegex(seen.name, r"^run-[0-9]+\.[A-Za-z0-9]{6}$")
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o700, "the root is private")
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
        self.assertTrue(result.stdout.startswith(f"/tmp/fireemu-test-tmp-{os.getuid()}/run-"), result.stdout)

    def test_a_dead_wrappers_directory_is_reclaimed_and_a_live_ones_is_kept(self):
        self.root.mkdir(mode=0o700)
        dead = subprocess.Popen(["true"])
        dead.wait()
        stale = self.root / f"run-{dead.pid}.AAAAAA"
        (stale / "inner").mkdir(parents=True)
        live = self.root / f"run-{os.getpid()}.BBBBBB"
        live.mkdir()
        unprefixed = self.root / f"{dead.pid}.DDDDDD"
        unprefixed.mkdir()
        long_suffix = self.root / f"run-{dead.pid}.keepme1"
        long_suffix.mkdir()
        not_a_pid = self.root / "run-notapid.AAAAAA"
        not_a_pid.mkdir()
        foreign = self.root / "not-a-wrapper-dir"
        foreign.mkdir()
        bare_pid = self.root / str(dead.pid)
        bare_pid.mkdir()
        outside = self.parent / "outside"
        (outside / "kept").mkdir(parents=True)
        link = self.root / f"run-{dead.pid}.CCCCCC"
        link.symlink_to(outside)
        for entry in self.root.iterdir():
            backdate(entry)
        self.assertEqual(self.run_wrapped("exit 0").returncode, 0)
        self.assertFalse(stale.exists(), "the killed wrapper's directory is removed")
        self.assertTrue(live.exists(), "a running wrapper's directory is kept")
        self.assertTrue(foreign.exists(), "a name the wrapper did not make is left alone")
        self.assertTrue(bare_pid.exists(), "a bare number is not a name the wrapper makes")
        self.assertTrue(unprefixed.exists(), "nor is a pid without the run- prefix")
        self.assertTrue(long_suffix.exists(), "nor a suffix mktemp does not make")
        self.assertTrue(not_a_pid.exists(), "nor a name without a pid")
        self.assertTrue(link.is_symlink(), "a symbolic link is left alone")
        self.assertTrue((outside / "kept").is_dir(), "and so is what it points to")

    def test_a_dead_wrappers_directory_younger_than_a_day_is_kept(self):
        # A pid that reads as gone may be alive in another pid namespace that shares this TMPDIR.
        self.root.mkdir(mode=0o700)
        dead = subprocess.Popen(["true"])
        dead.wait()
        fresh = self.root / f"run-{dead.pid}.AAAAAA"
        fresh.mkdir()
        old = self.root / f"run-{dead.pid}.BBBBBB"
        old.mkdir()
        backdate(old)
        self.assertEqual(self.run_wrapped("exit 0").returncode, 0)
        self.assertTrue(fresh.exists(), "a directory younger than a day is kept")
        self.assertFalse(old.exists(), "the same directory older than a day is reclaimed")

    @unittest.skipIf(os.getuid() == 0, "root may signal pid 1")
    def test_a_directory_whose_pid_exists_but_cannot_be_signalled_is_kept(self):
        # pid 1 exists and belongs to root: kill -0 fails with EPERM, not "No such process".
        self.root.mkdir(mode=0o700)
        other = self.root / "run-1.AAAAAA"
        (other / "data").mkdir(parents=True)
        backdate(other)
        self.assertEqual(self.run_wrapped("exit 0").returncode, 0)
        self.assertTrue((other / "data").is_dir(), "only a pid that is certainly gone is reclaimed")

    def test_a_terminated_run_still_removes_the_private_directory(self):
        process = self.start_wrapped('mkdir "$TMPDIR/x"; trap "exit 143" TERM; while :; do sleep 0.1; done')
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not any(d.joinpath("x").exists() for d in self.private_dirs()):
            time.sleep(0.05)
        self.assertTrue(self.private_dirs(), "the test started")
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=10)
        self.assertEqual(process.returncode, -signal.SIGTERM, "the signal is re-raised after cleanup")
        self.assertEqual(self.private_dirs(), [])

    def test_a_test_that_exits_0_after_a_terminating_signal_still_reports_the_signal(self):
        process = self.start_wrapped(': > "$TMPDIR/../started"; trap "exit 0" TERM; while :; do sleep 0.1; done')
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not (self.root / "started").exists():
            time.sleep(0.05)
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=10)
        self.assertEqual(process.returncode, -signal.SIGTERM)
        self.assertEqual([d for d in self.private_dirs() if d.name != "started"], [])

    def test_a_test_killed_by_a_signal_is_reported_killed_by_that_signal(self):
        for number in (signal.SIGABRT, signal.SIGSEGV):
            result = self.run_wrapped(f'mkdir "$TMPDIR/left"; kill -{int(number)} $$')
            self.assertEqual(result.returncode, -number, result.stderr)
            self.assertEqual(self.private_dirs(), [])

    def test_a_leftover_in_an_unreadable_tmpdir_is_still_found(self):
        result = self.run_wrapped(': > "$TMPDIR/hidden-file"; chmod 000 "$TMPDIR"')
        self.assertEqual(result.returncode, 1)
        self.assertIn("hidden-file", result.stderr)
        self.assertEqual(self.private_dirs(), [])

    def test_a_test_that_removes_its_tmpdir_fails(self):
        result = self.run_wrapped('rm -rf "$TMPDIR"')
        self.assertEqual(result.returncode, 1)
        self.assertIn("could not be listed", result.stderr)

    @unittest.skipUnless(sys.platform == "darwin", "an undeletable file needs chflags (macOS)")
    def test_a_leftover_that_cannot_be_removed_fails_the_test(self):
        result = self.run_wrapped(': > "$TMPDIR/locked"; chflags uchg "$TMPDIR/locked"')
        self.assertEqual(result.returncode, 1)
        self.assertIn("could not be removed", result.stderr)

    def refused(self, result, reason):
        self.assertEqual(result.returncode, 70, result.stderr)
        self.assertIn("refusing", result.stderr)
        self.assertIn(reason, result.stderr)

    def victim(self):
        victim = self.parent / "victim"
        dead = subprocess.Popen(["true"])
        dead.wait()
        for name in (f"run-{dead.pid}.AAAAAA", f"{dead.pid}.keepme"):
            (victim / name / "data").mkdir(parents=True)
        return victim

    def assert_untouched(self, victim):
        for entry in victim.iterdir():
            self.assertTrue((entry / "data").is_dir(), entry)

    def assert_untouched_runs(self, victim):
        for entry in victim.iterdir():
            if entry.name != "x":
                self.assertTrue((entry / "data").is_dir(), entry)

    def test_a_symlinked_root_is_refused_and_nothing_behind_it_is_deleted(self):
        victim = self.victim()
        victim.chmod(0o700)
        self.root.symlink_to(victim)
        self.refused(self.run_wrapped("exit 0"), "is a symbolic link")
        self.assertEqual(len(list(victim.iterdir())), 2)
        self.assert_untouched(victim)

    def test_a_root_others_can_write_is_refused(self):
        for mode in (0o777, 0o770, 0o755):
            with self.subTest(mode=oct(mode)):
                victim = self.victim()
                victim.chmod(mode)
                result = self.run_wrapped("exit 0", env={"FIREEMU_TEST_TMP_ROOT": str(victim)})
                self.refused(result, "mode 0700")
                self.assertEqual(len(list(victim.iterdir())), 2)
                self.assert_untouched(victim)
                for entry in victim.iterdir():
                    subprocess.run(["rm", "-rf", str(entry)], check=True)
                victim.rmdir()

    @unittest.skipUnless(sys.platform == "darwin", "extended ACL inspection is macOS-specific")
    def test_a_root_with_an_extended_acl_is_refused_before_any_child_is_changed(self):
        self.parent.chmod(0o755)
        for with_xattr in (False, True):
            with self.subTest(with_xattr=with_xattr):
                victim = self.victim()
                victim = victim.rename(self.parent / f"victim-{with_xattr}")
                victim.chmod(0o700)
                subprocess.run(["xattr", "-c", str(victim)], check=True)
                subprocess.run(
                    ["chmod", "+a", "everyone allow list,search,add_file,add_subdirectory,delete_child", str(victim)],
                    check=True,
                )
                if with_xattr:
                    subprocess.run(["xattr", "-w", "com.fireemu.test", "harmless metadata", str(victim)], check=True)
                mode = subprocess.check_output(["ls", "-ld", str(victim)], text=True).split()[0]
                self.assertIn(mode, ("drwx------+", "drwx------@"))
                if with_xattr:
                    self.assertEqual(mode, "drwx------@")
                for entry in victim.iterdir():
                    (entry / "data" / "payload").write_bytes(b"must remain untouched")
                    backdate(entry)
                before = {str(p.relative_to(victim)): (p.stat().st_mode, p.stat().st_mtime_ns, p.read_bytes() if p.is_file() else None) for p in victim.rglob("*")}
                result = self.run_wrapped(': > "$TMPDIR/../executed"', env={"FIREEMU_TEST_TMP_ROOT": str(victim)})
                self.refused(result, "ACL")
                after = {str(p.relative_to(victim)): (p.stat().st_mode, p.stat().st_mtime_ns, p.read_bytes() if p.is_file() else None) for p in victim.rglob("*")}
                self.assertEqual(before, after, "refusal must preserve every child and its data")
                subprocess.run(["chmod", "-N", str(victim)], check=True)
                subprocess.run(["rm", "-rf", str(victim)], check=True)

    @unittest.skipUnless(sys.platform == "darwin", "extended attributes are macOS-specific")
    def test_a_private_root_with_only_harmless_extended_attributes_is_accepted(self):
        self.root.mkdir(mode=0o700)
        subprocess.run(["xattr", "-w", "com.fireemu.test", "harmless metadata", str(self.root)], check=True)
        result = self.run_wrapped("exit 0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.private_dirs(), [])
        self.assertEqual(subprocess.check_output(["xattr", "-p", "com.fireemu.test", str(self.root)], text=True).strip(), "harmless metadata")

    @unittest.skipUnless(sys.platform == "darwin", "extended ACL inspection is macOS-specific")
    def test_a_failed_acl_inspection_is_refused_before_any_child_is_changed(self):
        victim = self.victim()
        victim.chmod(0o700)
        for entry in victim.iterdir():
            backdate(entry)
        tools = self.parent / "tools"
        tools.mkdir()
        probe = tools / "ls"
        probe.write_text('#!/bin/sh\nif [ "$1" = "-lde" ]; then exit 1; fi\nexec /bin/ls "$@"\n')
        probe.chmod(0o700)
        result = self.run_wrapped(
            ': > "$TMPDIR/../executed"',
            env={"FIREEMU_TEST_TMP_ROOT": str(victim), "PATH": f"{tools}:{os.environ['PATH']}"},
        )
        self.refused(result, "ACL")
        self.assertEqual(len(list(victim.iterdir())), 2)
        self.assert_untouched(victim)

    def test_a_failed_platform_inspection_is_refused(self):
        self.root.mkdir(mode=0o700)
        tools = self.parent / "tools"
        tools.mkdir()
        probe = tools / "uname"
        probe.write_text("#!/bin/sh\nexit 1\n")
        probe.chmod(0o700)
        result = self.run_wrapped(
            ': > "$TMPDIR/../executed"', env={"PATH": f"{tools}:{os.environ['PATH']}"}
        )
        self.refused(result, "platform")
        self.assertEqual(self.private_dirs(), [])

    @unittest.skipUnless(sys.platform == "darwin", "extended ACL inspection is macOS-specific")
    def test_acl_inspection_is_independent_of_the_extended_mode_marker(self):
        self.root.mkdir(mode=0o700)
        subprocess.run(["chmod", "+a", "everyone allow list,search,add_file,add_subdirectory,delete_child", str(self.root)], check=True)
        tools = self.parent / "tools"
        tools.mkdir()
        probe = tools / "ls"
        for marker in ("+", "@"):
            with self.subTest(marker=marker):
                # Real ACL inspection, with each documented presentation of the mode field.
                probe.write_text(f'#!/bin/sh\nif [ "$1" = "-ld" ]; then printf "drwx------{marker} root\\n"; else exec /bin/ls "$@"; fi\n')
                probe.chmod(0o700)
                result = self.run_wrapped(
                    ': > "$TMPDIR/../executed"', env={"PATH": f"{tools}:{os.environ['PATH']}"}
                )
                self.refused(result, "ACL")
                self.assertEqual(self.private_dirs(), [])

    def test_an_inherited_root_that_is_a_symlink_is_refused(self):
        victim = self.victim()
        victim.chmod(0o700)
        link = self.parent / "link-root"
        link.symlink_to(victim)
        self.refused(
            self.run_wrapped("exit 0", env={"FIREEMU_TEST_TMP_ROOT": str(link)}), "is a symbolic link"
        )
        self.assertEqual(len(list(victim.iterdir())), 2)

    def test_a_root_spelled_through_a_symlink_alias_is_refused(self):
        # `link/`, `link/.` and `link/x/..` resolve through the link, so `test -L` and `ls -ld` would
        # look at the directory behind it; only a canonical absolute spelling is accepted.
        victim = self.victim()
        victim.chmod(0o700)
        (victim / "x").mkdir()
        link = self.parent / "link-root"
        link.symlink_to(victim)
        for spelling in (f"{link}/", f"{link}/.", f"{link}/x/..", f"{link}//", f"{self.parent}//link-root"):
            with self.subTest(root=spelling):
                result = self.run_wrapped("exit 0", env={"FIREEMU_TEST_TMP_ROOT": spelling})
                self.refused(result, "canonical")
                self.assertEqual(len(list(victim.iterdir())), 3)
                self.assert_untouched_runs(victim)

    def test_a_relative_root_is_refused(self):
        victim = self.victim()
        victim.chmod(0o700)
        result = subprocess.run(
            [SHELL, str(WRAPPER), SHELL, "-c", "exit 0"],
            env=dict(os.environ, TMPDIR=str(self.parent) + "/", FIREEMU_TEST_TMP_ROOT="victim"),
            cwd=self.parent,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.refused(result, "absolute")
        self.assert_untouched(victim)

    def test_a_tmpdir_with_several_trailing_slashes_still_works(self):
        result = self.run_wrapped('printf "%s" "$TMPDIR"', env={"TMPDIR": str(self.parent) + "///"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(Path(result.stdout).parent, self.root)

    def test_a_root_owned_by_another_user_is_refused(self):
        # A private (0700) directory of another user: /root on Linux, /var/audit on macOS.
        for candidate in ("/root", "/var/audit"):
            try:
                info = os.lstat(candidate)
            except OSError:
                continue
            if stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid != os.getuid():
                break
        else:
            self.skipTest("no private directory of another user to point the root at")
        self.refused(self.run_wrapped("exit 0", env={"FIREEMU_TEST_TMP_ROOT": candidate}), "not owned")

    def test_a_root_that_is_a_file_is_refused(self):
        self.root.write_text("not a directory")
        result = self.run_wrapped("exit 0")
        self.assertEqual(result.returncode, 70)
        self.assertEqual(self.root.read_text(), "not a directory")


if __name__ == "__main__":
    unittest.main()
