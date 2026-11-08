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
        with patch.object(run.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "owned command\n")), patch.object(run.os, "kill", side_effect=ProcessLookupError):
            run.stop(12345, "owned command")

    def test_changed_pid_command_is_not_signaled(self):
        with patch.object(run.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "another command\n")), patch.object(run.os, "kill") as kill:
            run.stop(12345, "owned command")
            kill.assert_not_called()

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

    def test_observed_separate_group_stops_before_release(self):
        # The parent stays alive until the scan, then exits; its child has its own session
        # (as fireemu's client does) and outlives it, so only the recorded pgid can reach it.
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp)
            marker, go = work / "child", work / "go"
            child_code = "import os,subprocess,sys,time; os.setsid(); open(sys.argv[1], 'w').write(str(os.getpid())); [time.sleep(0.02) for _ in range(500) if not os.path.exists(sys.argv[1] + '.go')]; subprocess.Popen([sys.executable, '-c', 'import os,sys,time; open(sys.argv[1], \\'w\\').write(str(os.getpid())); time.sleep(60)', sys.argv[1] + '.grand']); time.sleep(60)"
            parent_code = "import os,subprocess,sys,time; subprocess.Popen([sys.executable, '-c', sys.argv[3], sys.argv[1]]); [time.sleep(0.02) for _ in range(500) if not os.path.exists(sys.argv[2])]"
            parent = subprocess.Popen(["python3", "-c", parent_code, str(marker), str(go), child_code], start_new_session=True)
            child = None
            try:
                for _ in range(250):
                    if marker.exists() and marker.read_text():
                        break
                    time.sleep(0.02)
                child = int(marker.read_text())
                self.assertEqual(os.getpgid(child), child)
                groups = {parent.pid}
                owned = run.descendants(parent.pid, groups)
                self.assertEqual(groups, {parent.pid, child})
                # A process the child forks after the scan is in the child's group but not in `owned`.
                Path(str(marker) + ".go").touch()
                grand_marker = Path(str(marker) + ".grand")
                for _ in range(250):
                    if grand_marker.exists() and grand_marker.read_text():
                        break
                    time.sleep(0.02)
                grandchild = int(grand_marker.read_text())
                self.assertNotIn(grandchild, owned)
                self.assertEqual(os.getpgid(grandchild), child)
                go.touch()
                parent.wait(timeout=5)
                self.assertEqual(os.getpgid(child), child)
                alive_at_release = []
                def release(_command):
                    try:
                        os.killpg(child, 0)
                        alive_at_release.append(True)
                    except ProcessLookupError:
                        alive_at_release.append(False)
                with patch.object(run, "TOOL", work), patch.object(run, "checked", side_effect=release), contextlib.redirect_stdout(io.StringIO()):
                    run.cleanup(owned, [(parent, io.StringIO())], [{"token": "fixture"}], ["registry"], work, Mock(), lambda: None, groups=groups)
                self.assertEqual(alive_at_release, [False])
                with self.assertRaises(ProcessLookupError):
                    os.kill(grandchild, 0)
            finally:
                for pid in [parent.pid, child]:
                    if pid is not None:
                        try:
                            os.killpg(pid, signal.SIGKILL)
                        except (ProcessLookupError, PermissionError):
                            pass

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
                def wait_for(path):
                    for _ in range(500):
                        if path.exists() and path.read_text():
                            return int(path.read_text())
                        time.sleep(0.02)
                    self.fail("marker not written")
                b = wait_for(b_marker)
                owned, groups, starts = {}, set(), {}
                children = [(launched, io.StringIO())]
                run.observe_owned(children, owned, groups, starts)
                self.assertIn(b, owned)
                a_go.touch()
                launched.wait(timeout=5)
                self.assertIsNotNone(launched.poll())
                b_go.touch()
                c = wait_for(Path(str(b_marker) + ".c"))
                self.assertEqual(os.getpgid(c), c)
                self.assertNotIn(c, groups)
                alive_at_release = []
                def release(_command):
                    alive_at_release.append([self.alive(b), self.alive(c)])
                with patch.object(run, "TOOL", work), patch.object(run, "checked", side_effect=release), contextlib.redirect_stdout(io.StringIO()):
                    run.cleanup(owned, children, [{"token": "fixture"}], ["registry"], work, Mock(), lambda: run.observe_owned(children, owned, groups, starts), groups=groups)
                self.assertEqual(alive_at_release, [[False, False]])
            finally:
                for pid in [launched.pid, b, c]:
                    if pid is not None:
                        try:
                            os.killpg(pid, signal.SIGKILL)
                        except (ProcessLookupError, PermissionError):
                            pass
                        try:
                            os.kill(pid, signal.SIGKILL)
                        except (ProcessLookupError, PermissionError):
                            pass

    def alive(self, pid):
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False

    def test_reused_pid_is_not_traversed(self):
        gone = Mock(poll=Mock(return_value=0), pid=111)
        owned, groups, starts = {222: "old command"}, set(), {222: "Sun Nov  8 10:00:00 2026"}
        with patch.object(run, "process_start", return_value="Sun Nov  8 11:00:00 2026"), patch.object(run, "descendants") as scan:
            run.observe_owned([(gone, io.StringIO())], owned, groups, starts)
        scan.assert_not_called()
        self.assertEqual(groups, set())

    def test_matching_start_time_keeps_an_owned_pid_in_the_scan(self):
        gone = Mock(poll=Mock(return_value=0), pid=111)
        owned, groups, starts = {222: "old command", 333: "child"}, set(), {222: "Sun Nov  8 10:00:00 2026", 333: "Sun Nov  8 10:00:00 2026"}
        with patch.object(run, "process_start", return_value="Sun Nov  8 10:00:00 2026"), patch.object(run, "descendants", return_value={333: "child"}) as scan:
            run.observe_owned([(gone, io.StringIO())], owned, groups, starts)
        # 333 was found under 222 in the same pass, so it is not scanned a second time.
        scan.assert_called_once_with(222, groups, starts)
        self.assertEqual(owned[333], "child")

    def test_descendant_scan_records_every_group_it_sees(self):
        with tempfile.TemporaryDirectory() as temp:
            marker = Path(temp) / "child"
            code = "import os,subprocess,sys,time; subprocess.Popen([sys.executable, '-c', 'import os,sys,time; os.setsid(); open(sys.argv[1], \\'w\\').write(str(os.getpid())); time.sleep(60)', sys.argv[1]]); time.sleep(60)"
            parent = subprocess.Popen(["python3", "-c", code, str(marker)], start_new_session=True)
            try:
                for _ in range(250):
                    if marker.exists() and marker.read_text():
                        break
                    time.sleep(0.02)
                child = int(marker.read_text())
                groups = set()
                owned = run.descendants(parent.pid, groups)
                self.assertIn(child, owned)
                self.assertEqual(groups, {child})
                without = run.descendants(parent.pid)
                self.assertIn(child, without)
            finally:
                for pid in [parent.pid, int(marker.read_text() or 0) if marker.exists() else None]:
                    if pid:
                        try:
                            os.killpg(pid, signal.SIGKILL)
                        except (ProcessLookupError, PermissionError):
                            pass
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
            command = subprocess.run(["ps", "-p", str(process.pid), "-o", "comm=,args="], capture_output=True, text=True).stdout.strip()
            run.stop(process.pid, command)
            process.wait(timeout=5)
            self.assertLess(process.returncode, 0)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            process.stdout.close()

    def test_stop_reports_a_pid_that_survives_sigkill(self):
        ps = subprocess.CompletedProcess([], 0, "owned command\n")
        with patch.object(run.subprocess, "run", return_value=ps), patch.object(run.os, "kill") as kill, patch.object(run.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "survived"):
                run.stop(12345, "owned command")
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
        ps = subprocess.CompletedProcess([], 0, "owned command\n")
        with tempfile.TemporaryDirectory() as temp, patch.object(run, "TOOL", Path(temp)), patch.object(run.subprocess, "run", return_value=ps), patch.object(run.os, "kill"), patch.object(run.time, "sleep"), patch.object(run, "checked") as checked, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, "stop"):
                run.cleanup({12345: "owned command"}, [], [{"token": "fixture"}], ["registry"], Path(temp), Mock(), lambda: None)
            checked.assert_not_called()

    def test_runner_never_signals_its_own_process_group(self):
        process = Mock(pid=os.getpgrp())
        with tempfile.TemporaryDirectory() as temp, patch.object(run, "TOOL", Path(temp)), patch.object(run.os, "killpg") as killpg, patch.object(run, "checked"), contextlib.redirect_stdout(io.StringIO()):
            run.cleanup({}, [(process, io.StringIO())], [], ["registry"], Path(temp), Mock(), lambda: None, groups={os.getpgrp(), 0, 1})
            killpg.assert_not_called()

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
