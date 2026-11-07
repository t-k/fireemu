import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class NestedCleanupTest(unittest.TestCase):
    def check_nested(self, cancellation):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            leaf = """import json,os,signal,sys,time
from pathlib import Path
signal.signal(signal.SIGTERM, signal.SIG_IGN)
Path(sys.argv[1]).write_text(json.dumps({'pid':os.getpid(),'group':os.getpgid(0)}))
time.sleep(30)
"""
            inner = """import json,os,run,sys,time
from pathlib import Path
original = run.owner_identity
def capture(process):
    value = original(process)
    Path(sys.argv[1]+'/inner.json').write_text(json.dumps({'pid':process.pid,'group':os.getpgid(process.pid),'identity':value}))
    return value
run.owner_identity = capture
stop = run.stop_owned_group
def delayed(process, identity):
    time.sleep(0.5)
    stop(process, identity)
run.stop_owned_group = delayed
run.execute([sys.executable,'-c',sys.argv[2],sys.argv[1]+'/leaf.json'],os.environ.copy(),'.',Path(sys.argv[1]+'/inner.log'),20)
"""
            outer = """import json,os,run,sys
from pathlib import Path
original = run.owner_identity
def capture(process):
    value = original(process)
    Path(sys.argv[1]+'/outer.json').write_text(json.dumps({'pid':process.pid,'group':os.getpgid(process.pid),'identity':value}))
    return value
run.owner_identity = capture
run.execute([sys.executable,'-c',sys.argv[2],sys.argv[1],sys.argv[3]],os.environ.copy(),'.',Path(sys.argv[1]+'/outer.log'),25)
"""
            caller = subprocess.Popen([sys.executable, '-B', '-c', outer, str(directory), inner, leaf], cwd=ROOT)
            owners = []
            try:
                deadline = time.monotonic()+5
                while not (directory/'leaf.json').exists() and time.monotonic()<deadline:
                    time.sleep(0.02)
                self.assertTrue((directory/'leaf.json').exists(), 'Nested workload did not start')
                owners = [json.loads((directory/(name+'.json')).read_text()) for name in ['outer','inner']]
                leaf_record = json.loads((directory/'leaf.json').read_text())
                self.assertNotEqual(owners[0]['group'], owners[1]['group'])
                self.assertEqual(leaf_record['group'], owners[1]['group'])
                print('NESTED_OWNED_IDENTITIES '+json.dumps({'owners':owners,'leaf':leaf_record,'signal':cancellation}), flush=True)
                caller.send_signal(cancellation)
                caller.wait(timeout=8)
                expected = 143 if cancellation == signal.SIGTERM else -signal.SIGKILL
                self.assertEqual(caller.returncode, expected)
                deadline = time.monotonic()+4
                remaining = []
                while time.monotonic()<deadline:
                    remaining = []
                    for owner in owners:
                        result = subprocess.run(['ps','-g',str(owner['group']),'-o','pid=,stat='],capture_output=True,text=True)
                        remaining.extend(line for line in result.stdout.splitlines() if not line.split()[1].startswith('Z'))
                    if not remaining: break
                    time.sleep(0.02)
                self.assertEqual(remaining, [], 'Nested owned groups survived caller cancellation')
            finally:
                for owner in owners:
                    current = subprocess.run(['ps','-p',str(owner['pid']),'-o','lstart=,comm=,args='],capture_output=True,text=True).stdout
                    if current == owner['identity'] and str(ROOT/'scripts/process_owner.py') in current and os.getpgid(owner['pid']) == owner['group']:
                        os.killpg(owner['group'], signal.SIGKILL)
                if caller.poll() is None:
                    caller.kill(); caller.wait(timeout=5)
                for name in ['outer.log','inner.log']:
                    if (directory/name).exists():
                        print('NESTED_CHILD_LOG '+name+'\n'+(directory/name).read_text(), flush=True)

    def test_outer_term_cleans_both_sessions_during_inner_cleanup(self):
        self.check_nested(signal.SIGTERM)

    def test_caller_sigkill_after_go_cleans_both_sessions(self):
        self.check_nested(signal.SIGKILL)

    def test_closed_result_pipe_stops_group_while_lifeline_stays_open(self):
        import select
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            leaf = "import os,signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); print(os.getpid(),flush=True); time.sleep(30)"
            workload = """import subprocess,sys,time
from pathlib import Path
with Path(sys.argv[1]+'/leaf').open('w') as log:
    subprocess.Popen([sys.executable,'-c',sys.argv[2],'flutter-smoke-broken-result-leaf'],stdout=log)
while not Path(sys.argv[1]+'/finish').exists(): time.sleep(0.01)
"""
            reader, writer = os.pipe()
            go_reader, go_writer = os.pipe()
            process = subprocess.Popen([sys.executable,str(ROOT/'scripts/process_owner.py'),str(writer),str(go_reader),sys.executable,'-c',workload,str(directory),leaf],pass_fds=(writer,go_reader),start_new_session=True)
            os.close(writer); os.close(go_reader)
            leaf_pid = None
            leaf_identity = None
            owner_identity = None
            try:
                self.assertTrue(select.select([reader],[],[],5)[0])
                self.assertEqual(os.read(reader,64),('READY '+str(process.pid)+'\n').encode())
                owner_identity = subprocess.check_output(['ps','-p',str(process.pid),'-o','lstart=,comm=,args='],text=True)
                os.write(go_writer,b'GO\n')
                deadline = time.monotonic()+5
                while time.monotonic()<deadline:
                    if (directory/'leaf').exists() and (directory/'leaf').read_text().strip():
                        leaf_pid=int((directory/'leaf').read_text().strip());break
                    time.sleep(0.02)
                self.assertIsNotNone(leaf_pid)
                self.assertEqual(os.getpgid(leaf_pid),process.pid)
                leaf_identity=subprocess.check_output(['ps','-p',str(leaf_pid),'-o','lstart=,comm=,args='],text=True)
                print('BROKEN_RESULT_OWNERS '+json.dumps({'ownerPid':process.pid,'ownerIdentity':owner_identity,'leafPid':leaf_pid,'leafIdentity':leaf_identity}),flush=True)
                os.close(reader);reader=None
                (directory/'finish').touch()
                process.wait(timeout=5)
                deadline=time.monotonic()+2
                remaining=[]
                while time.monotonic()<deadline:
                    result=subprocess.run(['ps','-g',str(process.pid),'-o','pid=,stat='],capture_output=True,text=True)
                    remaining=[line for line in result.stdout.splitlines() if not line.split()[1].startswith('Z')]
                    if not remaining:break
                    time.sleep(0.02)
                self.assertEqual(remaining,[],'Closed result pipe left owned descendants while lifeline remained open')
                self.assertEqual(process.returncode,-signal.SIGKILL)
            finally:
                if reader is not None:os.close(reader)
                os.close(go_writer)
                if process.poll() is None:process.kill();process.wait(timeout=5)
                if leaf_pid is not None:
                    current=subprocess.run(['ps','-p',str(leaf_pid),'-o','lstart=,comm=,args='],capture_output=True,text=True).stdout
                    if current==leaf_identity and 'flutter-smoke-broken-result-leaf' in current:
                        os.kill(leaf_pid,signal.SIGKILL)
