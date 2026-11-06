import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CleanupTest(unittest.TestCase):
    def test_termination_stops_the_owned_child_before_parent_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'child.log'
            source = '''import run, os, sys
from pathlib import Path
run.execute([sys.executable, '-c', 'import os,time; print(os.getpid(),flush=True); time.sleep(30)', 'flutter-smoke-owned-leaf'], os.environ.copy(), '.', Path(sys.argv[1]), 60)
'''
            parent = subprocess.Popen([sys.executable, '-c', source, str(log)], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            child = None
            try:
                until = time.monotonic() + 5
                while time.monotonic() < until:
                    if log.exists() and log.read_text().strip():
                        child = int(log.read_text().strip())
                        break
                    time.sleep(0.02)
                self.assertIsNotNone(child, 'The owned child did not start.')
                parent.send_signal(signal.SIGTERM)
                parent.wait(timeout=5)
                with self.assertRaises(ProcessLookupError):
                    os.kill(child, 0)
            finally:
                if parent.poll() is None:
                    parent.kill()
                    parent.wait(timeout=5)
                if child is not None:
                    info = subprocess.run(['ps', '-o', 'args=', '-p', str(child)], capture_output=True, text=True, timeout=5).stdout
                    if 'flutter-smoke-owned-leaf' in info and os.getpgid(child) == child:
                        os.killpg(child, signal.SIGTERM)
