import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


def capture_owner(child):
    group = os.getpgid(child)
    identity = subprocess.check_output(['ps', '-p', str(group), '-o', 'lstart=,comm=,args='], text=True)
    return group, identity


def cleanup_owner(owner):
    if owner is None:
        return
    group, identity = owner
    current = subprocess.run(['ps', '-p', str(group), '-o', 'lstart=,comm=,args='], capture_output=True, text=True).stdout
    if current == identity and str(ROOT / 'scripts/process_owner.py') in current and os.getpgid(group) == group:
        os.killpg(group, signal.SIGKILL)


class CleanupTest(unittest.TestCase):
    def test_termination_stops_the_owned_child_before_parent_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'child.log'
            source = '''import run, os, sys
from pathlib import Path
run.execute([sys.executable, '-c', 'import os,time; print(os.getpid(),flush=True); time.sleep(30)', 'flutter-smoke-owned-leaf'], os.environ.copy(), '.', Path(sys.argv[1]), 60)
'''
            parent = subprocess.Popen([sys.executable, '-c', source, str(log)], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=None)
            child = None
            owner = None
            try:
                until = time.monotonic() + 5
                while time.monotonic() < until:
                    if log.exists() and log.read_text().strip():
                        child = int(log.read_text().strip())
                        owner = capture_owner(child)
                        break
                    time.sleep(0.02)
                self.assertIsNotNone(child, 'The owned child did not start.')
                parent.send_signal(signal.SIGTERM)
                parent.wait(timeout=5)
                with self.assertRaises(ProcessLookupError):
                    os.kill(child, 0)
            finally:
                cleanup_owner(owner)
                if parent.poll() is None:
                    parent.kill()
                    parent.wait(timeout=5)
                if child is not None:
                    info = subprocess.run(['ps', '-o', 'args=', '-p', str(child)], capture_output=True, text=True, timeout=5).stdout
                    if 'flutter-smoke-owned-leaf' in info and os.getpgid(child) == child:
                        os.killpg(child, signal.SIGTERM)

class DescendantCleanupTest(unittest.TestCase):
    def run_descendant(self, early_exit):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'child.log'
            leaf = "import os,signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); print(os.getpid(),flush=True); time.sleep(30)"
            launcher = "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',sys.argv[1],'flutter-smoke-review-owned-grandchild']); " + ('time.sleep(0.2)' if early_exit else 'time.sleep(30)')
            source = """import run,os,sys,json
from pathlib import Path
original = run.owner_identity
identities = []
def recorded(process):
    value = original(process)
    identities.append(value)
    return value
run.owner_identity = recorded
status = run.execute([sys.executable,'-c',sys.argv[1],sys.argv[2]],os.environ.copy(),'.',Path(sys.argv[3]),0.5)
print('OWNED_IDENTITY_TUPLES ' + json.dumps(identities),flush=True)
assert identities and all(value == identities[0] for value in identities)
sys.exit(status)
"""
            parent = subprocess.Popen([sys.executable, '-B', '-c', source, launcher, leaf, str(log)], cwd=ROOT)
            child = None
            owner = None
            identity = None
            try:
                until = time.monotonic() + 5
                while time.monotonic() < until:
                    if log.exists() and log.read_text().strip():
                        child = int(log.read_text().strip())
                        owner = capture_owner(child)
                        identity = subprocess.check_output(['ps','-p',str(child),'-o','lstart=,comm=,args='],text=True)
                        break
                    time.sleep(0.02)
                self.assertIsNotNone(child)
                parent.wait(timeout=8)
                self.assertEqual(parent.returncode, 0 if early_exit else 124)
                until = time.monotonic() + 2
                while time.monotonic() < until:
                    state = subprocess.run(['ps','-p',str(child),'-o','stat='],capture_output=True,text=True).stdout.strip()
                    if not state or state.startswith('Z'): break
                    time.sleep(0.02)
                self.assertTrue(not state or state.startswith('Z'), 'Owned grandchild survived execute cleanup')
            finally:
                cleanup_owner(owner)
                if parent.poll() is None: parent.kill(); parent.wait(timeout=5)
                if child is not None:
                    current = subprocess.run(['ps','-p',str(child),'-o','lstart=,comm=,args='],capture_output=True,text=True).stdout
                    if current == identity and 'flutter-smoke-review-owned-grandchild' in current:
                        os.kill(child, signal.SIGKILL)

    def test_early_launcher_exit_stops_surviving_grandchild(self):
        self.run_descendant(True)

    def test_timeout_escalates_after_launcher_exits_on_term(self):
        self.run_descendant(False)

class StartupHandshakeTest(unittest.TestCase):
    def test_helper_waits_for_go_and_eof_never_launches_work(self):
        import select
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'started'
            reader, writer = os.pipe()
            go_reader, go_writer = os.pipe()
            command = [sys.executable, str(ROOT/'scripts/process_owner.py'), str(writer), str(go_reader), sys.executable, '-c', 'from pathlib import Path; import sys; Path(sys.argv[1]).touch()', str(marker)]
            process = subprocess.Popen(command, pass_fds=(writer, go_reader), start_new_session=True)
            os.close(writer); os.close(go_reader)
            try:
                self.assertTrue(select.select([reader], [], [], 5)[0])
                self.assertEqual(os.read(reader, 64), ('READY '+str(process.pid)+'\n').encode())
                self.assertFalse(marker.exists())
                os.close(go_writer); go_writer = None
                self.assertEqual(process.wait(timeout=5), 125)
                self.assertFalse(marker.exists())
            finally:
                os.close(reader)
                if go_writer is not None: os.close(go_writer)
                if process.poll() is None: process.kill(); process.wait(timeout=5)
