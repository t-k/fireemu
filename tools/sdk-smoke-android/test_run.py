import argparse
import contextlib
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import run


class RunnerContractTest(unittest.TestCase):
    def test_disappearing_owned_process_is_already_clean(self):
        with patch.object(run.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "owned command\n")), patch.object(run.os, "kill", side_effect=ProcessLookupError):
            run.stop(12345, "owned command")

    def test_changed_pid_command_is_not_signaled(self):
        with patch.object(run.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "another command\n")), patch.object(run.os, "kill") as kill:
            run.stop(12345, "owned command")
            kill.assert_not_called()

    def client_result(self, output, unsafe=False):
        with tempfile.TemporaryDirectory() as temp:
            args = argparse.Namespace(adb="/fixture/adb", adb_port=12345, serial="fixture-device", backend="official", report=str(Path(temp) / "report.json"))
            env = {key: "127.0.0.1:12345" for key in ["FIRESTORE_EMULATOR_HOST", "FIREBASE_AUTH_EMULATOR_HOST", "FIREBASE_STORAGE_EMULATOR_HOST", "FIREBASE_DATABASE_EMULATOR_HOST"]}
            env["ANDROID_SMOKE_ADB_HOME"] = temp
            if unsafe:
                env["FIRESTORE_EMULATOR_HOST"] = "example.com:12345"
            with patch.dict(os.environ, env, clear=True), patch.object(run.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, output, "")) as invoke, contextlib.redirect_stdout(io.StringIO()):
                if unsafe:
                    with self.assertRaises(ValueError):
                        run.client(args)
                    invoke.assert_not_called()
                    return None
                return run.client(args)

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
