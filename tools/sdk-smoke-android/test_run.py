import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
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
            with patch.object(run, "TOOL", tool), patch.object(run, "checked", side_effect=checked), patch.object(run, "cleanup", side_effect=lambda _owned, _children, _leases, _registry, _work, temporary, _observe, _primary: temporary.cleanup()), patch.object(run.subprocess, "Popen", side_effect=OSError("fixture stop")) as launch, contextlib.redirect_stdout(io.StringIO()):
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
            with patch.object(run, "TOOL", tool), patch.dict(os.environ, {"CI": "true", "ADB_VENDOR_KEYS": "/synthetic/never-read-key"}, clear=True), patch.object(run, "checked", return_value="/fixture/node"), patch.object(run, "cleanup", side_effect=lambda _owned, _children, _leases, _registry, _work, temporary, _observe, _primary: temporary.cleanup()), patch.object(run.subprocess, "Popen", side_effect=OSError("fixture stop")) as launch:
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
        first = Mock(wait=action("wait-first"))
        second = Mock(wait=action("wait-second"))
        stream1 = Mock(close=action("close-first"))
        stream2 = Mock(close=action("close-second"))
        temporary = Mock(cleanup=action("temporary"))
        work = Mock(glob=action("glob", [Path("fixture.log")]))
        with tempfile.TemporaryDirectory() as temp, patch.object(run, "TOOL", Path(temp)), patch.object(run, "stop", side_effect=lambda pid, command: action("stop-" + str(pid))()), patch.object(run.shutil, "copy2", side_effect=action("copy")), patch.object(run, "checked", side_effect=lambda command: action("release-" + command[-1])()), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            try:
                run.cleanup({1: "one", 2: "two"}, [(first, stream1), (second, stream2)], [{"token": "one"}, {"token": "two"}], ["registry"], work, temporary, action("observe"), primary)
            except BaseException as error:
                return events, error
        return events, None

    def test_cleanup_attempts_every_finalizer_after_failures(self):
        expected = {"observe", "stop-1", "stop-2", "wait-first", "wait-second", "close-first", "close-second", "glob", "copy", "temporary", "release-one", "release-two"}
        for failure in ["stop-2", "wait-first", "copy", "release-two"]:
            with self.subTest(failure=failure):
                events, error = self.cleanup_fixture(failure)
                self.assertEqual(set(events), expected)
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
        events, error = self.cleanup_fixture({"stop-2", "copy", "release-two"}, primary)
        self.assertIsNone(error)
        self.assertEqual(len(primary.cleanup_failures), 3)
        self.assertIn("release-one", events)

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
