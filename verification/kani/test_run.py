"""Fail-closed tests using executable cargo shims and actual child processes."""

import csv
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("kani_runner", Path(__file__).with_name("run.py"))


def successful_output(names):
    # The terse block and summary syntax come from actual Kani0.67 output.
    return "".join(
        f"Checking harness {name}...\n\nVERIFICATION RESULT:\n ** 0 of 174 failed (1 unreachable)\n\n"
        "VERIFICATION:- SUCCESSFUL\nVerification Time: 0.1s\n\n"
        for name in names
    ) + f"Manual Harness Summary:\nComplete - {len(names)} successfully verified harnesses, 0 failures, {len(names)} total.\n"


class RunnerContract(unittest.TestCase):
    def setUp(self):
        self.runner = importlib.util.module_from_spec(SPEC)
        SPEC.loader.exec_module(self.runner)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.output = self.directory / "output.txt"
        self.output.write_text(successful_output(self.runner.EXPECTED_HARNESSES))
        self.child_path = self.directory / "child.pid"
        cargo = self.directory / "cargo"
        cargo.write_text(f"#!{sys.executable}\n" + '''import os, pathlib, signal, subprocess, sys, time
if "--version" in sys.argv:
    print("cargo-kani " + os.environ["FAKE_VERSION"])
    sys.exit(0)
pathlib.Path(os.environ["FAKE_LAUNCHED"]).write_text("proof")
if os.environ.get("FAKE_CHILD") == "yes":
    if os.environ.get("FAKE_EARLY_OUTPUT"):
        print("partial proof stdout", flush=True)
        print("partial proof stderr", file=sys.stderr, flush=True)
    child = subprocess.Popen([sys.executable, "-c", "import pathlib,signal,sys,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); pathlib.Path(sys.argv[1]).write_text('ready'); time.sleep(30)", os.environ["FAKE_CHILD_PID"] + ".ready"])
    pathlib.Path(os.environ["FAKE_CHILD_PID"]).write_text(str(child.pid))
    time.sleep(2)
print(pathlib.Path(os.environ["FAKE_OUTPUT"]).read_text())
if os.environ.get("FAKE_STDERR"):
    print(os.environ["FAKE_STDERR"], file=sys.stderr)
sys.exit(int(os.environ.get("FAKE_EXIT", "0")))
''')
        cargo.chmod(0o755)
        self.environment = {
            "PATH": str(self.directory) + os.pathsep + os.environ["PATH"],
            "FAKE_VERSION": self.runner.KANI_VERSION,
            "FAKE_OUTPUT": str(self.output),
            "FAKE_LAUNCHED": str(self.directory / "proof.launched"),
            "FAKE_CHILD_PID": str(self.child_path),
            "FAKE_EXIT": "0",
            "FAKE_CHILD": "no",
        }
        self.environ = mock.patch.dict(os.environ, self.environment)
        self.environ.start()
        self.addCleanup(self.environ.stop)
        quiet = mock.patch("sys.stdout", new=io.StringIO())
        quiet.start()
        self.addCleanup(quiet.stop)

    @staticmethod
    def process_alive(pid):
        result = subprocess.run(["ps", "-p", str(pid), "-o", "stat="], capture_output=True, text=True)
        return bool(result.stdout.strip()) and not result.stdout.strip().startswith("Z")

    def assert_child_stopped(self):
        child = int(self.child_path.read_text())
        try:
            for _ in range(100):
                if not self.process_alive(child):
                    break
                time.sleep(0.01)
            self.assertFalse(self.process_alive(child), "owned child survived cleanup")
        finally:
            if self.process_alive(child):
                os.kill(child, signal.SIGKILL)

    def test_inventory_requires_every_declared_proof(self):
        self.assertEqual(len(self.runner.discover_harnesses()), 9)
        self.assertEqual(set(self.runner.discover_harnesses()), set(self.runner.EXPECTED_HARNESSES))

    def test_actual_proof_success_publishes_runner_provenance(self):
        receipt = self.directory / "result.json"
        self.runner.execute(receipt)
        result = json.loads(receipt.read_text())
        self.assertEqual(result["producer"], "fireemu-kani-runner")
        self.assertEqual(result["kani_version"], self.runner.KANI_VERSION)
        self.assertEqual(result["harnesses"], list(self.runner.EXPECTED_HARNESSES))
        self.assertEqual(len(result["source_sha256"]), 64)
        self.assertEqual(len(result["output_sha256"]), 64)
        self.assertTrue(Path(self.environment["FAKE_LAUNCHED"]).exists())

    def test_empty_failed_partial_duplicate_unfinished_and_malformed_output_rejected(self):
        good = self.output.read_text()
        changed = ["", good.replace("SUCCESSFUL", "FAILED", 1),
                   successful_output(self.runner.EXPECTED_HARNESSES[:-1]),
                   good.replace(self.runner.EXPECTED_HARNESSES[-1], self.runner.EXPECTED_HARNESSES[0]),
                   good.replace("Complete -", "Incomplete -"),
                   good.replace("0 of 174 failed", "1 of 174 failed", 1),
                   good.replace("9 successfully", "8 successfully"),
                   good.replace("9 total", "8 total"),
                   good.replace("0 failures", "1 failures"),
                   good.replace("VERIFICATION:- SUCCESSFUL", "", 1)]
        for output in changed:
            with self.subTest(output=output[:90]):
                self.output.write_text(output)
                with self.assertRaises(ValueError):
                    self.runner.execute(self.directory / "result.json")
                self.assertFalse((self.directory / "result.json").exists())

    def test_missing_extra_and_duplicate_source_inventory_rejected(self):
        expected = self.runner.EXPECTED_HARNESSES
        for inventory in [expected[:-1], expected + ("harnesses::unknown",), expected[:-1] + expected[:1]]:
            with self.subTest(inventory=inventory), mock.patch.object(self.runner, "discover_harnesses", return_value=inventory):
                with self.assertRaises(ValueError):
                    self.runner.execute(self.directory / "result.json")
        self.assertFalse(Path(self.environment["FAKE_LAUNCHED"]).exists())

    def test_existing_receipt_is_rejected_without_overwrite(self):
        receipt = self.directory / "result.json"
        receipt.write_text("stale")
        with self.assertRaises(FileExistsError):
            self.runner.execute(receipt)
        self.assertEqual(receipt.read_text(), "stale")
        self.assertFalse(Path(self.environment["FAKE_LAUNCHED"]).exists())

    def test_wrong_version_missing_tool_and_failed_proof_cannot_create_receipt(self):
        receipt = self.directory / "result.json"
        with mock.patch.dict(os.environ, {"FAKE_VERSION": "0.68.0"}):
            with self.assertRaises(ValueError):
                self.runner.execute(receipt)
        self.assertFalse(Path(self.environment["FAKE_LAUNCHED"]).exists())
        with mock.patch.dict(os.environ, {"PATH": str(self.directory / "missing")}):
            with self.assertRaises(FileNotFoundError):
                self.runner.execute(receipt)
        with mock.patch.dict(os.environ, {"FAKE_EXIT": "7"}):
            with self.assertRaises(subprocess.CalledProcessError):
                self.runner.execute(receipt)
        self.assertTrue(Path(self.environment["FAKE_LAUNCHED"]).exists())
        self.assertFalse(receipt.exists())

    def test_cli_reports_captured_solver_diagnostics_on_failure(self):
        self.output.write_text("actual solver failure details")
        with mock.patch.dict(os.environ, {"FAKE_EXIT": "7", "FAKE_STDERR": "actual solver stderr details"}):
            result = subprocess.run([sys.executable, str(Path(__file__).with_name("run.py"))], capture_output=True, text=True, timeout=3)
        self.assertEqual(result.returncode, 1)
        self.assertIn("actual solver failure details", result.stdout)
        self.assertIn("actual solver stderr details", result.stderr)
        self.assertNotIn("Kani verified all", result.stdout)

    def test_owned_child_is_cleaned_after_proof_timeout_and_unrelated_process_survives(self):
        unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            with mock.patch.dict(os.environ, {"FAKE_CHILD": "yes"}), mock.patch.object(self.runner, "PROOF_TIMEOUT", 0.3, create=True):
                with self.assertRaises(subprocess.TimeoutExpired):
                    self.runner.execute(self.directory / "result.json")
            self.assert_child_stopped()
            self.assertIsNone(unrelated.poll())
        finally:
            unrelated.terminate()
            unrelated.wait(timeout=2)
        self.assertFalse((self.directory / "result.json").exists())

    def test_sigterm_interrupt_cleans_owned_child(self):
        with mock.patch.dict(os.environ, {"FAKE_CHILD": "yes"}):
            process = subprocess.Popen([sys.executable, str(Path(__file__).with_name("run.py")), "--receipt", str(self.directory / "result.json")], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 3
            while not self.child_path.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(self.child_path.exists(), "proof child never launched")
            process.send_signal(signal.SIGTERM)
            process.communicate(timeout=3)
            self.assertNotEqual(process.returncode, 0)
            self.assert_child_stopped()
            self.assertFalse((self.directory / "result.json").exists())
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=2)
            if self.child_path.exists() and self.process_alive(int(self.child_path.read_text())):
                os.kill(int(self.child_path.read_text()), signal.SIGKILL)

    def test_cleanup_eperm_preserves_primary_timeout_and_stops_group_signals(self):
        original_killpg = os.killpg
        original_popen = subprocess.Popen
        for failed_signal in [signal.SIGTERM, 0, signal.SIGKILL]:
            with self.subTest(failed_signal=failed_signal):
                self.child_path.unlink(missing_ok=True)
                calls = []
                failures = []
                observed_timeouts = []
                cleanup_waits = []

                def observed_process(*args, **kwargs):
                    process = original_popen(*args, **kwargs)
                    communicate, wait = process.communicate, process.wait

                    def observe_communicate(*args, **kwargs):
                        try:
                            return communicate(*args, **kwargs)
                        except subprocess.TimeoutExpired as error:
                            observed_timeouts.append(error)
                            raise

                    def observe_wait(*args, **kwargs):
                        if failures:
                            cleanup_waits.append(kwargs.get("timeout"))
                        return wait(*args, **kwargs)

                    process.communicate, process.wait = observe_communicate, observe_wait
                    return process

                def controlled_signal(pgid, requested_signal):
                    calls.append(requested_signal)
                    if requested_signal == failed_signal and self.child_path.exists() and not failures:
                        error = PermissionError(1, "controlled owned-group EPERM")
                        failures.append((error, len(calls)))
                        raise error
                    return original_killpg(pgid, requested_signal)

                try:
                    with mock.patch.dict(os.environ, {"FAKE_CHILD": "yes", "FAKE_EARLY_OUTPUT": "yes"}), mock.patch.object(self.runner, "PROOF_TIMEOUT", 0.3), mock.patch.object(self.runner.os, "killpg", side_effect=controlled_signal), mock.patch.object(self.runner.subprocess, "Popen", side_effect=observed_process), mock.patch("sys.stderr", new=io.StringIO()) as diagnostics:
                        with self.assertRaises(subprocess.TimeoutExpired) as caught:
                            self.runner.execute(self.directory / "result.json")
                    self.assertEqual(len(failures), 1)
                    self.assertIs(caught.exception, observed_timeouts[0])
                    self.assertIn(observed_timeouts[-1], caught.exception.cleanup_errors)
                    self.assertIn(2, cleanup_waits)
                    self.assertIn("cleanup UNCONFIRMED", diagnostics.getvalue())
                    self.assertEqual(len(calls), failures[0][1], "group signaling continued after EPERM")
                    self.assertIn(failures[0][0], caught.exception.cleanup_errors)
                    self.assertIn(b"partial proof stdout", caught.exception.stdout)
                    self.assertIn(b"partial proof stderr", caught.exception.stderr)
                    self.assertFalse((self.directory / "result.json").exists())
                finally:
                    if self.child_path.exists() and self.process_alive(int(self.child_path.read_text())):
                        os.kill(int(self.child_path.read_text()), signal.SIGKILL)

    def test_cleanup_eperm_after_success_fails_with_captured_output(self):
        original_killpg = os.killpg
        calls_after_error = []
        failures = []

        def controlled_signal(pgid, requested_signal):
            if failures:
                calls_after_error.append(requested_signal)
            if requested_signal == signal.SIGTERM and Path(self.environment["FAKE_LAUNCHED"]).exists() and not failures:
                error = PermissionError(1, "controlled post-success EPERM")
                failures.append(error)
                raise error
            return original_killpg(pgid, requested_signal)

        with mock.patch.dict(os.environ, {"FAKE_STDERR": "captured proof stderr"}), mock.patch.object(self.runner.os, "killpg", side_effect=controlled_signal), mock.patch("sys.stderr", new=io.StringIO()) as diagnostics:
            with self.assertRaises(PermissionError) as caught:
                self.runner.execute(self.directory / "result.json")
        self.assertIs(caught.exception, failures[0])
        self.assertIn("cleanup UNCONFIRMED", diagnostics.getvalue())
        self.assertEqual(calls_after_error, [])
        self.assertIn("Manual Harness Summary:", caught.exception.stdout)
        self.assertIn("captured proof stderr", caught.exception.stderr)
        self.assertFalse((self.directory / "result.json").exists())

    def test_outer_handled_exception_cannot_hide_cleanup_failure(self):
        original_killpg = os.killpg
        cleanup_error = PermissionError(1, "controlled outer-except EPERM")

        def controlled_signal(pgid, requested_signal):
            if requested_signal == signal.SIGTERM and Path(self.environment["FAKE_LAUNCHED"]).exists():
                raise cleanup_error
            return original_killpg(pgid, requested_signal)

        outer_error = ValueError("unrelated caller exception")
        try:
            raise outer_error
        except ValueError:
            with mock.patch.object(self.runner.os, "killpg", side_effect=controlled_signal), mock.patch("sys.stderr", new=io.StringIO()):
                with self.assertRaises(PermissionError) as caught:
                    self.runner.execute(self.directory / "result.json")
        self.assertIs(caught.exception, cleanup_error)
        self.assertFalse(hasattr(outer_error, "cleanup_errors"))
        self.assertFalse((self.directory / "result.json").exists())

    def test_repeated_interrupts_cannot_interrupt_owned_cleanup(self):
        for second_signal in [signal.SIGTERM, signal.SIGINT]:
            with self.subTest(second_signal=second_signal):
                ready = Path(str(self.child_path) + ".ready")
                ready.unlink(missing_ok=True)
                self.child_path.unlink(missing_ok=True)
                with mock.patch.dict(os.environ, {"FAKE_CHILD": "yes"}):
                    process = subprocess.Popen([sys.executable, str(Path(__file__).with_name("run.py"))], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    deadline = time.monotonic() + 3
                    while not ready.exists() and time.monotonic() < deadline:
                        time.sleep(0.01)
                    self.assertTrue(ready.exists(), "child did not confirm TERM-ignore readiness")
                    process.send_signal(signal.SIGTERM)
                    time.sleep(0.32)
                    process.send_signal(second_signal)
                    self.assertEqual(process.wait(timeout=3), 130)
                    self.assert_child_stopped()
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=2)
                    if self.child_path.exists() and self.process_alive(int(self.child_path.read_text())):
                        os.kill(int(self.child_path.read_text()), signal.SIGKILL)

    def test_generated_pict_rows(self):
        table = os.environ.get("KANI_RUNNER_MATRIX")
        if not table:
            self.skipTest("set KANI_RUNNER_MATRIX to execute generated PICT rows")
        with Path(table).open() as stream:
            for row in csv.DictReader(stream, delimiter="\t"):
                with self.subTest(row=row):
                    receipt = self.directory / "result.json"
                    receipt.unlink(missing_ok=True)
                    self.output.write_text(successful_output(self.runner.EXPECTED_HARNESSES) if row["Output"] == "exact" else "")
                    if row["Output"] == "stale":
                        receipt.write_text("stale")
                    environment = {"FAKE_VERSION": self.runner.KANI_VERSION if row["Version"] == "exact" else "0.0.0",
                                   "FAKE_EXIT": "0" if row["Exit"] == "zero" else "7",
                                   "FAKE_CHILD": "yes" if row["Exit"] == "timeout" else "no"}
                    with mock.patch.dict(os.environ, environment), mock.patch.object(self.runner, "PROOF_TIMEOUT", 0.3, create=True):
                        if row == {"Version": "exact", "Exit": "zero", "Output": "exact"}:
                            self.runner.execute(receipt)
                        else:
                            with self.assertRaises((ValueError, OSError, subprocess.SubprocessError)):
                                self.runner.execute(receipt)
                    if row["Version"] == "exact" and row["Exit"] == "timeout" and row["Output"] != "stale":
                        self.assert_child_stopped()


if __name__ == "__main__":
    unittest.main()
