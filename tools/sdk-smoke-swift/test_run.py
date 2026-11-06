"""Finite result accounting and process cleanup regressions; no network."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from run import CASES, complete

class ResultsTests(unittest.TestCase):
    def test_complete_success(self):
        self.assertTrue(complete([{"case": case, "status": "passed"} for case in CASES]))

    def test_missing_duplicate_failed_and_blocked_cases_fail(self):
        rows = [{"case": case, "status": "passed"} for case in CASES]
        self.assertFalse(complete(rows[:-1]))
        self.assertFalse(complete(rows + rows[:1]))
        for status in ["failed", "blocked", None]:
            self.assertFalse(complete([{**row, "status": status} if i == 0 else row for i, row in enumerate(rows)]))

    def test_signals_terminate_and_reap_active_child(self):
        for signum in (signal.SIGTERM, signal.SIGINT):
            for ignore_term in (False, True):
                with self.subTest(signal=signum, ignore_term=ignore_term), tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
                    root = Path(directory)
                    pid_file = root / "child.pid"
                    binary = root / "fake-child"
                    binary.write_text(
                        f"#!{sys.executable}\n"
                        "import os, signal, time\n"
                        f"signal.signal(signal.SIGTERM, signal.SIG_IGN if {ignore_term!r} else signal.SIG_DFL)\n"
                        f"with open({str(pid_file)!r}, 'w') as output:\n"
                        "    output.write(str(os.getpid()))\n"
                        "while True: time.sleep(1)\n"
                    )
                    binary.chmod(0o700)
                    child_pid = None
                    runner = subprocess.Popen(
                        [sys.executable, str(Path(__file__).with_name("run.py")), "--binary", str(binary), "--output", str(root / "results")],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    )
                    try:
                        deadline = time.monotonic() + 5
                        while time.monotonic() < deadline:
                            if pid_file.exists() and pid_file.read_text():
                                child_pid = int(pid_file.read_text())
                                break
                            time.sleep(0.01)
                        self.assertIsNotNone(child_pid, "fake child did not start")
                        self.assertEqual(os.getpgid(child_pid), child_pid)
                        runner.send_signal(signum)
                        self.assertNotEqual(runner.wait(timeout=5), 0)
                        with self.assertRaises(ProcessLookupError):
                            os.kill(child_pid, 0)
                    finally:
                        if child_pid is not None:
                            try:
                                os.kill(child_pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                        if runner.poll() is None:
                            runner.kill()
                        runner.wait(timeout=5)

if __name__ == "__main__":
    unittest.main()
