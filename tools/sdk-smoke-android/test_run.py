import argparse
import contextlib
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch, Mock
import run


class RunnerContractTest(unittest.TestCase):
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
