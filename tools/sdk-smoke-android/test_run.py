import argparse
import contextlib
import io
import json
import os
import signal
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch, Mock
import run


class RunnerContractTest(unittest.TestCase):
    def pair_fixture(self, busy=(), failure=None, release_failure=False):
        held = {9999: "unrelated"}
        events = []
        def claim(service, port):
            events.append(("claim", port))
            if failure == port:
                raise OSError("registry unavailable")
            if port in busy:
                raise run.PortUnavailable("occupied")
            held[port] = service
            return port
        def release(port):
            events.append(("release", port))
            if release_failure:
                raise OSError("release unavailable")
            del held[port]
        return held, events, claim, release

    def test_pair_rolls_back_only_its_console_then_tries_next_candidate(self):
        held, events, claim, release = self.pair_fixture(busy={5557})
        self.assertEqual(run.claim_emulator_pair(claim, release), 5554)
        self.assertEqual(held, {9999: "unrelated", 5554: "console", 5555: "device-adb"})
        self.assertEqual(events[:3], [("claim", 5556), ("claim", 5557), ("release", 5556)])

    def test_pair_skips_busy_console_and_preserves_unrelated_lease(self):
        held, _, claim, release = self.pair_fixture(busy={5556})
        self.assertEqual(run.claim_emulator_pair(claim, release), 5554)
        self.assertIn(9999, held)

    def test_pair_success_is_even_adjacent_without_release(self):
        held, events, claim, release = self.pair_fixture()
        self.assertEqual(run.claim_emulator_pair(claim, release), 5556)
        self.assertEqual(set(held), {9999, 5556, 5557})
        self.assertNotIn("release", [event[0] for event in events])

    def test_pair_exhaustion_releases_all_partial_pairs(self):
        held, _, claim, release = self.pair_fixture(busy=set(range(5555, 5586, 2)))
        with self.assertRaisesRegex(RuntimeError, "no available emulator port pair"):
            run.claim_emulator_pair(claim, release)
        self.assertEqual(held, {9999: "unrelated"})

    def test_pair_does_not_retry_unrelated_error_or_failed_rollback(self):
        for options in [{"failure": 5556}, {"failure": 5557}, {"busy": {5557}, "release_failure": True}]:
            held, events, claim, release = self.pair_fixture(**options)
            with self.assertRaises(OSError):
                run.claim_emulator_pair(claim, release)
            self.assertNotIn(("claim", 5554), events)
            self.assertEqual(held[9999], "unrelated")


    def test_pair_rejects_an_unexpected_registry_port(self):
        for service in ["console", "device-adb"]:
            def claim(current, port):
                return port + 2 if current == service else port
            with self.assertRaisesRegex(RuntimeError, "registry returned a different"):
                run.claim_emulator_pair(claim, Mock())

    def test_registry_uses_singleton_ranges_and_rolls_back_before_server_launch(self):
        with tempfile.TemporaryDirectory() as temp:
            tool = Path(temp)
            apk = tool / "build/outputs/apk/androidTest/debug/sdk-smoke-android-debug-androidTest.apk"
            apk.parent.mkdir(parents=True)
            apk.touch()
            events = []
            def checked(command, **_kwargs):
                if command[0] == "node":
                    return "/fixture/node"
                if "release" in command:
                    events.append(("release", command[-1]))
                    return ""
                bounds = command[command.index("--range") + 1]
                service = command[command.index("--service") + 1]
                events.append((service, bounds))
                if bounds == "5557-5557":
                    raise subprocess.CalledProcessError(2, command, stderr="portctl: No available port for service='android-device-adb' in range(s): 5557-5557\n")
                self.assertNotIn("--preferred", command)
                port = int(bounds.split("-")[0])
                return json.dumps({"port": port, "token": "owned-" + str(port)})
            args = argparse.Namespace(sdk="/fixture/sdk", portctl="/fixture/portctl.py", case=None, backend="official")
            with patch.object(run, "TOOL", tool), patch.object(run, "checked", side_effect=checked), patch.object(run, "cleanup", side_effect=lambda _owned, children, _leases, _registry, _work, temporary, _observe, _primary, groups=None: ([stream.close() for _, stream in children], temporary.cleanup())), patch.object(run.subprocess, "Popen", side_effect=OSError("fixture stop")) as launch, contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(OSError, "fixture stop"):
                    run.run(args)
                self.assertEqual(launch.call_count, 1)
            self.assertEqual(events[:5], [("android-console", "5556-5556"), ("android-device-adb", "5557-5557"), ("release", "owned-5556"), ("android-console", "5554-5554"), ("android-device-adb", "5555-5555")])
            self.assertEqual(events[5], ("android-adb-server", "10000-19999"))

    def test_disappearing_owned_process_is_already_clean(self):
        with patch.object(run.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "S Sun Nov  8 10:00:00 2026\n")), patch.object(run.os, "kill", side_effect=ProcessLookupError):
            run.stop(12345, "Sun Nov  8 10:00:00 2026")

    def test_reused_pid_with_another_start_time_is_not_signaled(self):
        with patch.object(run.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "S Sun Nov  8 11:00:00 2026\n")), patch.object(run.os, "kill") as kill:
            run.stop(12345, "Sun Nov  8 10:00:00 2026")
            kill.assert_not_called()

    def test_real_process_with_a_different_recorded_start_is_left_alone(self):
        process = subprocess.Popen(["python3", "-c", "import time; time.sleep(60)"])
        try:
            real = None
            for _ in range(100):
                real = run.process_start(process.pid)
                if real:
                    break
                time.sleep(0.02)
            run.stop(process.pid, "Mon Jan  1 00:00:00 2001")
            time.sleep(0.3)
            self.assertIsNone(process.poll())
            self.assertEqual(run.process_start(process.pid), real)
        finally:
            process.kill()
            process.wait()

    def test_zombie_does_not_count_as_a_live_identity(self):
        with patch.object(run.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "Z+ Sun Nov  8 10:00:00 2026\n")):
            self.assertIsNone(run.process_start(1))

    def test_ps_failure_is_not_read_as_gone(self):
        with patch.object(run.subprocess, "run", return_value=subprocess.CompletedProcess([], 2, "")):
            with self.assertRaises(RuntimeError):
                run.process_start(1)

    def test_owned_adb_server_excludes_external_key_override(self):
        with tempfile.TemporaryDirectory() as temp:
            tool = Path(temp)
            apk = tool / "build/outputs/apk/androidTest/debug/sdk-smoke-android-debug-androidTest.apk"
            apk.parent.mkdir(parents=True)
            apk.touch()
            args = argparse.Namespace(sdk="/fixture/sdk", portctl=None, case=None, backend="official")
            with patch.object(run, "TOOL", tool), patch.dict(os.environ, {"CI": "true", "ADB_VENDOR_KEYS": "/synthetic/never-read-key"}, clear=True), patch.object(run, "claim_emulator_pair", return_value=5556), patch.object(run.socket, "socket") as sock, patch.object(run, "checked", return_value="/fixture/node"), patch.object(run, "cleanup", side_effect=lambda _owned, children, _leases, _registry, _work, temporary, _observe, _primary, groups=None: ([stream.close() for _, stream in children], temporary.cleanup())), patch.object(run.subprocess, "Popen", side_effect=OSError("fixture stop")) as launch:
                sock.return_value.__enter__.return_value.getsockname.return_value = ("127.0.0.1", 10000)
                with self.assertRaises(OSError):
                    run.run(args)
                self.assertNotIn("ADB_VENDOR_KEYS", launch.call_args.kwargs["env"])
                self.assertTrue(launch.call_args.kwargs["env"]["HOME"].endswith("adb-home"))

    def cleanup_fixture(self, failure, primary=None):
        events = []
        def action(name, result=None):
            def invoke(*_args, **_kwargs):
                events.append(name)
                if name in (failure if isinstance(failure, set) else {failure}):
                    raise OSError("synthetic private text")
                return result
            return invoke
        first = Mock(pid=101, wait=action("wait-first"))
        second = Mock(pid=102, wait=action("wait-second"))
        stream1 = Mock(close=action("close-first"))
        stream2 = Mock(close=action("close-second"))
        temporary = Mock(cleanup=action("temporary"))
        work = Mock(glob=action("glob", [Path("fixture.log")]))
        with tempfile.TemporaryDirectory() as temp, patch.object(run, "TOOL", Path(temp)), patch.object(run.os, "killpg", side_effect=ProcessLookupError), patch.object(run, "stop", side_effect=lambda pid, command: action("stop-" + str(pid))()), patch.object(run.shutil, "copy2", side_effect=action("copy")), patch.object(run, "checked", side_effect=lambda command: action("release-" + command[-1])()), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            try:
                run.cleanup({1: "one", 2: "two"}, [(first, stream1), (second, stream2)], [{"token": "one"}, {"token": "two"}], ["registry"], work, temporary, action("observe"), primary)
            except BaseException as error:
                return events, error
        return events, None

    def test_cleanup_attempts_every_finalizer_after_failures(self):
        expected = {"observe", "stop-1", "stop-2", "wait-first", "wait-second", "close-first", "close-second", "glob", "copy", "temporary", "release-one", "release-two"}
        for failure in ["wait-first", "copy", "release-two"]:
            with self.subTest(failure=failure):
                events, error = self.cleanup_fixture(failure)
                self.assertEqual(set(events), expected)
                self.assertIsInstance(error, RuntimeError)
                self.assertNotIn("synthetic private text", str(error))

    def test_failed_stop_or_observe_keeps_every_lease_but_finishes_the_rest(self):
        expected = {"observe", "stop-1", "stop-2", "wait-first", "wait-second", "close-first", "close-second", "glob", "copy", "temporary"}
        for failure in ["stop-1", "stop-2", "observe"]:
            with self.subTest(failure=failure):
                events, error = self.cleanup_fixture(failure)
                self.assertEqual(set(events), expected)
                self.assertFalse([event for event in events if event.startswith("release-")])
                self.assertIsInstance(error, RuntimeError)
                self.assertNotIn("synthetic private text", str(error))

    def test_cleanup_preserves_primary_error_and_attaches_failures(self):
        primary = ValueError("primary")
        events, error = self.cleanup_fixture("copy", primary)
        self.assertIsNone(error)
        self.assertIn("release-one", events)
        self.assertTrue(primary.cleanup_failures)

    def test_cleanup_reporting_failure_does_not_mask_primary(self):
        primary = ValueError("primary")
        with patch("builtins.print", side_effect=OSError("closed output")):
            events, error = self.cleanup_fixture("copy", primary)
        self.assertIsNone(error)
        self.assertIn("release-one", events)
        self.assertIn(("cleanup-report", "OSError"), primary.cleanup_failures)

    def test_cleanup_aggregates_multiple_failures(self):
        primary = ValueError("primary")
        events, error = self.cleanup_fixture({"wait-first", "copy", "release-two"}, primary)
        self.assertIsNone(error)
        self.assertEqual(len(primary.cleanup_failures), 3)
        self.assertIn("release-one", events)
        events, error = self.cleanup_fixture({"stop-2", "copy"}, primary)
        self.assertEqual(len(primary.cleanup_failures), 2)
        self.assertFalse([event for event in events if event.startswith("release-")])

    def client_result(self, output, unsafe=False):
        with tempfile.TemporaryDirectory() as temp:
            args = argparse.Namespace(adb="/fixture/adb", adb_port=12345, serial="fixture-device", backend="official", report=str(Path(temp) / "report.json"))
            env = {key: "127.0.0.1:12345" for key in ["FIRESTORE_EMULATOR_HOST", "FIREBASE_AUTH_EMULATOR_HOST", "FIREBASE_STORAGE_EMULATOR_HOST", "FIREBASE_DATABASE_EMULATOR_HOST"]}
            env["ANDROID_SMOKE_ADB_HOME"] = temp
            env["ADB_VENDOR_KEYS"] = "/synthetic/never-read-key"
            if unsafe:
                env["FIRESTORE_EMULATOR_HOST"] = "example.com:12345"
            with patch.dict(os.environ, env, clear=True), patch.object(run.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, output, "")) as invoke, contextlib.redirect_stdout(io.StringIO()):
                if unsafe:
                    with self.assertRaises(ValueError):
                        run.client(args)
                    invoke.assert_not_called()
                    return None
                result = run.client(args)
                self.assertNotIn("ADB_VENDOR_KEYS", invoke.call_args.kwargs["env"])
                return result

    def test_exited_parent_child_is_stopped_before_release(self):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp)
            marker = work / "child"
            parent = subprocess.Popen(["python3", "-c", "import subprocess,sys; subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); open(sys.argv[1], 'w').close()", str(marker)], start_new_session=True)
            try:
                parent.wait(timeout=5)
                self.assertTrue(marker.exists())
                with patch.object(run, "TOOL", work), contextlib.redirect_stdout(io.StringIO()):
                    run.cleanup({}, [(parent, io.StringIO())], [], None, work, Mock(), lambda: None)
                with self.assertRaises(ProcessLookupError):
                    os.killpg(parent.pid, 0)
            finally:
                try:
                    os.killpg(parent.pid, 9)
                except ProcessLookupError:
                    pass

    def wait_for(self, path):
        for _ in range(500):
            if path.exists() and path.read_text():
                return int(path.read_text())
            time.sleep(0.02)
        self.fail("marker not written")

    def alive(self, pid):
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False

    def kill_all(self, pids):
        for pid in pids:
            if pid is not None:
                for kill in (os.killpg, os.kill):
                    try:
                        kill(pid, signal.SIGKILL)
                    except (ProcessLookupError, PermissionError):
                        pass

    def test_observed_separate_group_stops_before_release(self):
        # The parent stays alive until the scan, then exits; its child has its own session
        # (as fireemu's client does) and outlives it, so only the recorded pgid can reach it.
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp)
            marker, go = work / "child", work / "go"
            child_code = "import os,subprocess,sys,time; os.setsid(); open(sys.argv[1], 'w').write(str(os.getpid())); [time.sleep(0.02) for _ in range(500) if not os.path.exists(sys.argv[1] + '.go')]; subprocess.Popen([sys.executable, '-c', 'import os,sys,time; open(sys.argv[1], \\'w\\').write(str(os.getpid())); time.sleep(60)', sys.argv[1] + '.grand']); time.sleep(60)"
            parent_code = "import os,subprocess,sys,time; subprocess.Popen([sys.executable, '-c', sys.argv[3], sys.argv[1]]); [time.sleep(0.02) for _ in range(500) if not os.path.exists(sys.argv[2])]"
            parent = subprocess.Popen(["python3", "-c", parent_code, str(marker), str(go), child_code], start_new_session=True)
            child = grandchild = None
            try:
                child = self.wait_for(marker)
                self.assertEqual(os.getpgid(child), child)
                groups = {}
                owned = run.descendants(parent.pid, groups)
                self.assertEqual(set(groups), {child})
                # A process the child forks after the scan is in the child's group but not in `owned`.
                Path(str(marker) + ".go").touch()
                grandchild = self.wait_for(Path(str(marker) + ".grand"))
                self.assertNotIn(grandchild, owned)
                self.assertEqual(os.getpgid(grandchild), child)
                go.touch()
                parent.wait(timeout=5)
                alive_at_release = []
                with patch.object(run, "TOOL", work), patch.object(run, "checked", side_effect=lambda _command: alive_at_release.append([self.alive(child), self.alive(grandchild)])), contextlib.redirect_stdout(io.StringIO()):
                    run.cleanup(owned, [(parent, io.StringIO())], [{"token": "fixture"}], ["registry"], work, Mock(), lambda: None, groups=groups)
                self.assertEqual(alive_at_release, [[False, False]])
            finally:
                self.kill_all([parent.pid, child, grandchild])

    def test_descendant_scan_records_every_group_it_sees(self):
        with tempfile.TemporaryDirectory() as temp:
            marker = Path(temp) / "child"
            code = "import os,subprocess,sys,time; subprocess.Popen([sys.executable, '-c', 'import os,sys,time; os.setsid(); open(sys.argv[1], \\'w\\').write(str(os.getpid())); time.sleep(60)', sys.argv[1]]); time.sleep(60)"
            parent = subprocess.Popen(["python3", "-c", code, str(marker)], start_new_session=True)
            child = None
            try:
                child = self.wait_for(marker)
                groups = {}
                owned = run.descendants(parent.pid, groups)
                self.assertEqual(owned, {child: run.process_start(child)})
                self.assertEqual(groups, {child: {child: run.process_start(child)}})
            finally:
                self.kill_all([parent.pid, child])
                parent.wait()

    def test_sigterm_ignoring_group_is_killed_and_verified(self):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp)
            marker = work / "ready"
            process = subprocess.Popen(["python3", "-c", "import signal,sys,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); open(sys.argv[1], 'w').close(); time.sleep(60)", str(marker)], start_new_session=True)
            try:
                for _ in range(250):
                    if marker.exists():
                        break
                    time.sleep(0.02)
                self.assertTrue(marker.exists())
                released = []
                with patch.object(run, "TOOL", work), patch.object(run, "checked", side_effect=lambda command: released.append(command)), contextlib.redirect_stdout(io.StringIO()):
                    run.cleanup({}, [(process, io.StringIO())], [{"token": "fixture"}], ["registry"], work, Mock(), lambda: None)
                self.assertIsNotNone(process.poll())
                self.assertLess(process.returncode, 0)
                with self.assertRaises(ProcessLookupError):
                    os.killpg(process.pid, 0)
                self.assertEqual(len(released), 1)
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()

    def test_stop_kills_a_sigterm_ignoring_pid_and_verifies_it_is_gone(self):
        process = subprocess.Popen(["python3", "-c", "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); print('ready', flush=True); time.sleep(60)"], stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(process.stdout.readline().strip(), "ready")
            run.stop(process.pid, run.process_start(process.pid))
            process.wait(timeout=5)
            self.assertLess(process.returncode, 0)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            process.stdout.close()

    def test_stop_reports_a_pid_that_survives_sigkill(self):
        ps = subprocess.CompletedProcess([], 0, "S Sun Nov  8 10:00:00 2026\n")
        with patch.object(run.subprocess, "run", return_value=ps), patch.object(run.os, "kill") as kill, patch.object(run.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "survived"):
                run.stop(12345, "Sun Nov  8 10:00:00 2026")
        self.assertEqual([call.args[1] for call in kill.call_args_list], [signal.SIGTERM, signal.SIGKILL])

    def test_unverifiable_group_keeps_leases(self):
        process = Mock(pid=12345)
        with tempfile.TemporaryDirectory() as temp, patch.object(run, "TOOL", Path(temp)), patch.object(run.os, "killpg"), patch.object(run.time, "sleep"), patch.object(run, "checked") as checked, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, "stop-group"):
                run.cleanup({}, [(process, io.StringIO())], [{"token": "fixture"}], ["registry"], Path(temp), Mock(), lambda: None)
            checked.assert_not_called()

    def test_group_that_only_reports_permission_denied_is_not_treated_as_gone(self):
        process = Mock(pid=12345)
        with tempfile.TemporaryDirectory() as temp, patch.object(run, "TOOL", Path(temp)), patch.object(run.os, "killpg", side_effect=lambda _group, number: (_ for _ in ()).throw(PermissionError) if number == 0 else None), patch.object(run.time, "sleep"), patch.object(run, "checked") as checked, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, "stop-group"):
                run.cleanup({}, [(process, io.StringIO())], [{"token": "fixture"}], ["registry"], Path(temp), Mock(), lambda: None)
            checked.assert_not_called()

    def test_unstoppable_owned_pid_keeps_leases(self):
        ps = subprocess.CompletedProcess([], 0, "S Sun Nov  8 10:00:00 2026\n")
        with tempfile.TemporaryDirectory() as temp, patch.object(run, "TOOL", Path(temp)), patch.object(run.subprocess, "run", return_value=ps), patch.object(run.os, "kill"), patch.object(run.time, "sleep"), patch.object(run, "checked") as checked, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, "stop"):
                run.cleanup({12345: "Sun Nov  8 10:00:00 2026"}, [], [{"token": "fixture"}], ["registry"], Path(temp), Mock(), lambda: None)
            checked.assert_not_called()

    def test_runner_never_signals_its_own_process_group(self):
        process = Mock(pid=os.getpgrp())
        with tempfile.TemporaryDirectory() as temp, patch.object(run, "TOOL", Path(temp)), patch.object(run.os, "killpg") as killpg, patch.object(run, "checked"), contextlib.redirect_stdout(io.StringIO()):
            run.cleanup({}, [(process, io.StringIO())], [], ["registry"], Path(temp), Mock(), lambda: None, groups={os.getpgrp(): {}, 0: {}, 1: {}})
            killpg.assert_not_called()

    def test_descendant_of_an_exited_root_is_still_scanned(self):
        # A (launched) creates B in its own session and exits; B stays alive and later
        # creates C in yet another session. C must be found by a later scan and stopped
        # before the leases are released.
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp)
            b_marker, a_go, b_go = work / "b", work / "a-go", work / "b-go"
            c_code = "import os,sys,time; os.setsid(); open(sys.argv[1], 'w').write(str(os.getpid())); time.sleep(60)"
            b_code = "import os,subprocess,sys,time; os.setsid(); open(sys.argv[1], 'w').write(str(os.getpid())); [time.sleep(0.02) for _ in range(1000) if not os.path.exists(sys.argv[2])]; subprocess.Popen([sys.executable, '-c', sys.argv[3], sys.argv[1] + '.c']); time.sleep(60)"
            a_code = "import os,subprocess,sys,time; subprocess.Popen([sys.executable, '-c', sys.argv[4], sys.argv[1], sys.argv[3], sys.argv[5]]); [time.sleep(0.02) for _ in range(1000) if not os.path.exists(sys.argv[2])]"
            launched = subprocess.Popen(["python3", "-c", a_code, str(b_marker), str(a_go), str(b_go), b_code, c_code], start_new_session=True)
            b = c = None
            try:
                b = self.wait_for(b_marker)
                owned, groups = {}, {}
                children = [(launched, io.StringIO())]
                run.observe_owned(children, owned, groups)
                self.assertIn(b, owned)
                a_go.touch()
                launched.wait(timeout=5)
                self.assertIsNotNone(launched.poll())
                b_go.touch()
                c = self.wait_for(Path(str(b_marker) + ".c"))
                self.assertEqual(os.getpgid(c), c)
                self.assertNotIn(c, groups)
                alive_at_release = []
                with patch.object(run, "TOOL", work), patch.object(run, "checked", side_effect=lambda _command: alive_at_release.append([self.alive(b), self.alive(c)])), contextlib.redirect_stdout(io.StringIO()):
                    run.cleanup(owned, children, [{"token": "fixture"}], ["registry"], work, Mock(), lambda: run.observe_owned(children, owned, groups), groups=groups)
                self.assertEqual(alive_at_release, [[False, False]])
            finally:
                self.kill_all([launched.pid, b, c])

    def test_setsid_and_exec_after_observation_is_still_stopped(self):
        # A forks B in A's group and B is observed there. A exits. B then setsid()s and
        # exec()s into a different program (new group, new command). Cleanup must still
        # find B by (pid, start time) and stop it before the leases are released.
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp)
            b_marker, a_go, b_go = work / "b", work / "a-go", work / "b-go"
            b_code = "import os,sys,time; open(sys.argv[1], 'w').write(str(os.getpid())); [time.sleep(0.02) for _ in range(1000) if not os.path.exists(sys.argv[2])]; os.setsid(); os.execvp('python3', ['python3', '-c', 'import time; time.sleep(60)', 'server']);"
            a_code = "import os,subprocess,sys,time; subprocess.Popen([sys.executable, '-c', sys.argv[4], sys.argv[1], sys.argv[3]]); [time.sleep(0.02) for _ in range(1000) if not os.path.exists(sys.argv[2])]"
            launched = subprocess.Popen(["python3", "-c", a_code, str(b_marker), str(a_go), str(b_go), b_code], start_new_session=True)
            b = None
            try:
                b = self.wait_for(b_marker)
                self.assertEqual(os.getpgid(b), launched.pid)
                owned, groups = {}, {}
                children = [(launched, io.StringIO())]
                run.observe_owned(children, owned, groups)
                self.assertEqual(set(groups), {launched.pid})
                a_go.touch()
                launched.wait(timeout=5)
                b_go.touch()
                for _ in range(500):
                    if os.getpgid(b) == b and "server" in subprocess.run(["ps", "-p", str(b), "-o", "args="], capture_output=True, text=True).stdout:
                        break
                    time.sleep(0.02)
                self.assertEqual(os.getpgid(b), b)
                alive_at_release = []
                with patch.object(run, "TOOL", work), patch.object(run, "checked", side_effect=lambda _command: alive_at_release.append(self.alive(b))), contextlib.redirect_stdout(io.StringIO()):
                    run.cleanup(owned, children, [{"token": "fixture"}], ["registry"], work, Mock(), lambda: run.observe_owned(children, owned, groups), groups=groups)
                self.assertEqual(alive_at_release, [False])
            finally:
                self.kill_all([launched.pid, b])

    def test_daemon_forked_while_the_group_is_terminating_is_still_stopped(self):
        # The second scan runs after the SIGTERM grace period, like a dying server that forked a daemon.
        # The daemon is detached (reparented to init) so that nothing here has to reap it.
        spawner = "import subprocess,sys; print(subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], start_new_session=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).pid)"
        process = Mock(pid=int(subprocess.run(["python3", "-c", spawner], capture_output=True, text=True).stdout), kill=lambda: None, wait=lambda: None)
        try:
            started = None
            for _ in range(100):
                started = run.process_start(process.pid)
                if started:
                    break
                time.sleep(0.02)
            calls = []
            owned, groups = {}, {}
            def observe():
                calls.append(1)
                if len(calls) == 2:
                    groups[process.pid] = {process.pid: started}
            released = []
            with tempfile.TemporaryDirectory() as temp, patch.object(run, "TOOL", Path(temp)), patch.object(run, "checked", side_effect=lambda _command: released.append(self.alive(process.pid))), contextlib.redirect_stdout(io.StringIO()):
                run.cleanup(owned, [], [{"token": "fixture"}], ["registry"], Path(temp), Mock(), observe, groups=groups)
            self.assertEqual(len(calls), 2)
            self.assertEqual(released, [False])
        finally:
            self.kill_all([process.pid])

    def test_group_whose_leader_pid_was_reused_is_not_signaled_and_keeps_leases(self):
        # The recorded member's start time no longer matches: the group id now belongs to an
        # unrelated process, which cleanup must leave alone; the group is unresolved, so the leases stay.
        stranger = subprocess.Popen(["python3", "-c", "import time; time.sleep(60)"], start_new_session=True)
        try:
            with tempfile.TemporaryDirectory() as temp, patch.object(run, "TOOL", Path(temp)), patch.object(run, "checked") as checked, contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(RuntimeError, "stop-group"):
                    run.cleanup({stranger.pid: "Mon Jan  1 00:00:00 2001"}, [], [{"token": "fixture"}], ["registry"], Path(temp), Mock(), lambda: None, groups={stranger.pid: {stranger.pid: "Mon Jan  1 00:00:00 2001"}})
                checked.assert_not_called()
            time.sleep(0.3)
            self.assertIsNone(stranger.poll())
        finally:
            stranger.kill()
            stranger.wait()

    def test_unresolved_group_with_a_live_unrelated_member_keeps_leases_while_another_group_is_killed(self):
        # D (observed, non-launch leader) forked C into its group G and exited; B, an observed
        # child of D, moved to its own session and ignores SIGTERM. Nothing validates membership
        # of G, but B is alive, so G is not "all members gone". G must not be signalled and the
        # leases must stay; B's own group is still killed. Real processes: C leads G, D is a dead pid.
        # B is detached (reparented to init) so that nothing here has to reap it after SIGKILL.
        c = subprocess.Popen(["python3", "-c", "import time; time.sleep(60)"], start_new_session=True)
        with tempfile.TemporaryDirectory() as ready_dir:
            ready = Path(ready_dir) / "ready"
            spawner = "import subprocess,sys; print(subprocess.Popen([sys.executable, '-c', \"import signal,sys,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); open(sys.argv[1], 'w').close(); time.sleep(60)\", sys.argv[1]], start_new_session=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).pid)"
            b_pid = int(subprocess.run(["python3", "-c", spawner, str(ready)], capture_output=True, text=True).stdout)
            try:
                for _ in range(250):
                    if ready.exists():
                        break
                    time.sleep(0.02)
                self.assertTrue(ready.exists())
                started_b = run.process_start(b_pid)
                dead_d = 2 ** 22 + 4242
                # B was recorded in G while it still shared D's group, then moved to its own session.
                groups = {c.pid: {dead_d: "Mon Jan  1 00:00:00 2001", b_pid: started_b}, b_pid: {b_pid: started_b}}
                with tempfile.TemporaryDirectory() as temp, patch.object(run, "TOOL", Path(temp)), patch.object(run, "checked") as checked, contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaisesRegex(RuntimeError, "stop-group") as raised:
                        run.cleanup({b_pid: started_b}, [], [{"token": "fixture"}], ["registry"], Path(temp), Mock(), lambda: None, groups=groups)
                    self.assertEqual(json.loads(str(raised.exception).split("failures: ", 1)[1]), [["stop-group", "RuntimeError"]])
                    checked.assert_not_called()
                self.assertFalse(self.alive(b_pid))
                self.assertIsNone(c.poll())
            finally:
                self.kill_all([c.pid, b_pid])
                c.wait()

    def test_live_group_whose_recorded_members_are_all_gone_is_unproven_and_keeps_leases(self):
        stranger = subprocess.Popen(["python3", "-c", "import time; time.sleep(60)"], start_new_session=True)
        try:
            with tempfile.TemporaryDirectory() as temp, patch.object(run, "TOOL", Path(temp)), patch.object(run, "checked") as checked, contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(RuntimeError, "stop-group"):
                    run.cleanup({}, [], [{"token": "fixture"}], ["registry"], Path(temp), Mock(), lambda: None, groups={stranger.pid: {2 ** 22 + 12345: "Mon Jan  1 00:00:00 2001"}})
                checked.assert_not_called()
            self.assertIsNone(stranger.poll())
        finally:
            stranger.kill()
            stranger.wait()

    def test_ownership_check_failure_still_signals_launched_groups_and_keeps_leases(self):
        process = subprocess.Popen(["python3", "-c", "import time; time.sleep(60)"], start_new_session=True)
        try:
            with tempfile.TemporaryDirectory() as temp, patch.object(run, "TOOL", Path(temp)), patch.object(run, "process_start", side_effect=RuntimeError("ps failed")), patch.object(run, "checked") as checked, contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(RuntimeError, "refresh"):
                    run.cleanup({}, [(process, io.StringIO())], [{"token": "fixture"}], ["registry"], Path(temp), Mock(), lambda: None, groups={process.pid + 1: {process.pid + 1: "x"}})
                checked.assert_not_called()
            self.assertIsNotNone(process.poll())
        finally:
            self.kill_all([process.pid])
            process.wait()

    def test_stop_never_signals_the_runner(self):
        started = run.process_start(os.getpid())
        with patch.object(run.os, "kill") as kill:
            run.stop(os.getpid(), started)
        kill.assert_not_called()

    def test_member_that_moved_to_another_group_does_not_prove_the_old_group(self):
        # S leads a live group. B is recorded as a member of S's group but sits in its own session:
        # S is never signalled, and being unresolved it keeps the leases.
        leader = subprocess.Popen(["python3", "-c", "import time; time.sleep(60)"], start_new_session=True)
        mover = subprocess.Popen(["python3", "-c", "import time; time.sleep(60)"], start_new_session=True)
        try:
            for _ in range(100):
                started = run.process_start(mover.pid)
                if started and run.process_start(leader.pid):
                    break
                time.sleep(0.02)
            with tempfile.TemporaryDirectory() as temp, patch.object(run, "TOOL", Path(temp)), patch.object(run, "checked") as checked, contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(RuntimeError, "stop-group"):
                    run.cleanup({}, [], [{"token": "fixture"}], ["registry"], Path(temp), Mock(), lambda: None, groups={leader.pid: {mover.pid: started}})
                checked.assert_not_called()
            time.sleep(0.3)
            self.assertIsNone(leader.poll())
            self.assertIsNone(mover.poll())
        finally:
            self.kill_all([leader.pid, mover.pid])
            leader.wait()
            mover.wait()

    def test_dead_recorded_group_is_not_a_failure(self):
        released = []
        with tempfile.TemporaryDirectory() as temp, patch.object(run, "TOOL", Path(temp)), patch.object(run, "checked", side_effect=lambda _command: released.append(1)), contextlib.redirect_stdout(io.StringIO()):
            run.cleanup({}, [], [{"token": "fixture"}], ["registry"], Path(temp), Mock(), lambda: None, groups={2 ** 22 + 99: {2 ** 22 + 98: "Mon Jan  1 00:00:00 2001"}})
        self.assertEqual(released, [1])

    def test_root_that_does_not_exit_after_cleanup_keeps_leases(self):
        process = Mock(pid=2 ** 22 + 54321, wait=Mock(side_effect=subprocess.TimeoutExpired("fixture", 5)))
        with tempfile.TemporaryDirectory() as temp, patch.object(run, "TOOL", Path(temp)), patch.object(run.os, "killpg", side_effect=ProcessLookupError), patch.object(run, "checked") as checked, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, "TimeoutExpired"):
                run.cleanup({}, [(process, io.StringIO())], [{"token": "fixture"}], ["registry"], Path(temp), Mock(), lambda: None)
            checked.assert_not_called()

    def test_reused_pid_is_dropped_and_not_traversed(self):
        gone = Mock(poll=Mock(return_value=0), pid=111)
        owned, groups = {222: "Sun Nov  8 10:00:00 2026"}, {}
        with patch.object(run, "process_start", return_value="Sun Nov  8 11:00:00 2026"), patch.object(run, "descendants") as scan:
            run.observe_owned([(gone, io.StringIO())], owned, groups)
        scan.assert_not_called()
        self.assertEqual((owned, groups), ({}, {}))

    def test_matching_start_time_keeps_an_owned_pid_in_the_scan(self):
        gone = Mock(poll=Mock(return_value=0), pid=111)
        started = "Sun Nov  8 10:00:00 2026"
        owned, groups = {222: started, 333: started}, {}
        with patch.object(run, "process_start", return_value=started), patch.object(run.os, "getpgid", return_value=222), patch.object(run, "descendants", return_value={333: started}) as scan:
            run.observe_owned([(gone, io.StringIO())], owned, groups)
        # 333 was found under 222 in the same pass, so it is not scanned a second time.
        scan.assert_called_once_with(222, groups)
        self.assertEqual(groups, {222: {222: started}})

    def test_scan_refreshes_the_group_of_a_seed_that_moved(self):
        gone = Mock(poll=Mock(return_value=0), pid=111)
        started = "Sun Nov  8 10:00:00 2026"
        owned, groups = {222: started}, {100: {222: started}}
        with patch.object(run, "process_start", return_value=started), patch.object(run.os, "getpgid", return_value=222), patch.object(run, "descendants", return_value={}):
            run.observe_owned([(gone, io.StringIO())], owned, groups)
        self.assertEqual(groups[222], {222: started})

    def test_descendant_scan_truncation_is_an_error(self):
        def fake(command, **_kwargs):
            if command[0] == "pgrep":
                return subprocess.CompletedProcess(command, 0, "\n".join(str(1000 + i) for i in range(150)))
            return subprocess.CompletedProcess(command, 0, "S Sun Nov  8 10:00:00 2026\n")
        with patch.object(run.subprocess, "run", side_effect=fake), patch.object(run.os, "getpgid", return_value=5):
            with self.assertRaisesRegex(RuntimeError, "truncated"):
                run.descendants(1)

    def test_pgrep_failure_is_an_error_not_an_empty_scan(self):
        with patch.object(run.subprocess, "run", return_value=subprocess.CompletedProcess([], 3, "")):
            with self.assertRaisesRegex(RuntimeError, "pgrep"):
                run.descendants(1)

    def backend_result(self, report):
        with tempfile.TemporaryDirectory() as temp:
            tool = Path(temp)
            apk = tool / "build/outputs/apk/androidTest/debug/sdk-smoke-android-debug-androidTest.apk"
            apk.parent.mkdir(parents=True)
            apk.touch()
            (tool / "firebase.json").write_text(json.dumps({"emulators": {}, "firestore": {}, "storage": {}, "database": {}}))
            process = Mock(pid=123, returncode=0, poll=Mock(side_effect=[None, None, None, None, 0, 0]))
            boot = subprocess.CompletedProcess([], 0, "1\n", "")
            args = argparse.Namespace(sdk="/fixture/sdk", portctl=None, case=None, backend="official", arch="x86_64")
            original_read = Path.read_text
            def read(path, *args, **kwargs):
                if path.parent.name == "reports":
                    if report is None:
                        raise FileNotFoundError()
                    return json.dumps(report)
                return original_read(path, *args, **kwargs)
            with patch.object(Path, "read_text", read), patch.object(run, "TOOL", tool), patch.dict(os.environ, {"CI": "true"}), patch.object(run, "checked", return_value="/fixture/node"), patch.object(run, "claim_emulator_pair", return_value=5556), patch.object(run.socket, "socket") as sock, patch.object(run.subprocess, "Popen", return_value=process), patch.object(run.subprocess, "run", return_value=boot), patch.object(run, "cleanup", side_effect=lambda _owned, children, _leases, _registry, _work, temporary, _observe, _primary, groups=None: ([stream.close() for _, stream in children], temporary.cleanup())), contextlib.redirect_stdout(io.StringIO()):
                sock.return_value.__enter__.return_value.getsockname.side_effect = [("127.0.0.1", port) for port in range(10000, 10008)]
                return run.run(args)

    def test_backend_success_without_client_report_fails(self):
        self.assertNotEqual(self.backend_result(None), 0)

    def test_backend_requires_exact_passing_cases_and_instrumentation(self):
        cases = [{"id": case, "status": "passed"} for case in sorted(run.REQUIRED_CASES)]
        self.assertEqual(self.backend_result({"cases": cases, "instrumentation_ok": True}), 0)
        for report in [
            {"cases": cases[:-1], "instrumentation_ok": True},
            {"cases": cases[:-1] + [{"id": "unexpected", "status": "passed"}], "instrumentation_ok": True},
            {"cases": cases[:-1] + [cases[0]], "instrumentation_ok": True},
            {"cases": cases[:-1] + [{"id": cases[-1]["id"], "status": "failed"}], "instrumentation_ok": True},
            {"cases": cases, "instrumentation_ok": False},
        ]:
            with self.subTest(report=report):
                self.assertNotEqual(self.backend_result(report), 0)

    def test_unsafe_endpoint_prevents_device_command(self):
        self.client_result("", unsafe=True)

    def test_completed_junit_without_required_cases_fails(self):
        self.assertEqual(self.client_result("OK (1 test)"), 1)

    def test_extra_duplicate_case_fails(self):
        output = "".join("CASE case." + chr(97 + index) + " passed none 1\n" for index in range(23))
        output += "CASE case.a passed none 1\nOK (1 test)"
        self.assertEqual(self.client_result(output), 1)

    def test_duplicate_case_ids_fail(self):
        output = "CASE auth.signup passed none 1\n" * 23 + "OK (1 test)"
        self.assertEqual(self.client_result(output), 1)


if __name__ == "__main__":
    unittest.main()
