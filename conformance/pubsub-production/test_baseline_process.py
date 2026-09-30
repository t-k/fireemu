"""Offline process ownership tests; no ports, credentials or production calls."""
import os
from pathlib import Path
import shutil
import sys
import time
import tempfile
import unittest
from unittest.mock import Mock, patch

# macOS's developer python3 is a launcher that execs Python.app. Strict
# no-spawn fixtures use the actual installed runtime, not that launcher.
app = Path(sys.base_prefix) / "Resources/Python.app/Contents/MacOS/Python"
REAL_PYTHON = str(app if app.is_file() else Path(sys.executable).resolve())
volta_node = Path.home() / ".volta/tools/image/node/24.14.0/bin/node"
REAL_NODE = str(volta_node if volta_node.is_file() else Path(shutil.which("node")).resolve())


class ProcessTests(unittest.TestCase):
    def setUp(self):
        import baseline_process as m
        self.children = []
        original = m.subprocess.Popen
        def start(argv, **kwargs):
            child = original(argv, **kwargs)
            if argv[0] in (REAL_PYTHON, REAL_NODE, "/bin/echo", "/bin/bash"):
                try:
                    birth = m.birth_identity(child.pid)
                except m.ProcessGone:
                    birth = None
                self.children.append((child, birth))
            return child
        self.start_patch = patch.object(m.subprocess, "Popen", side_effect=start)
        self.start_patch.start()
        self.addCleanup(self.stop_fixtures)

    def stop_fixtures(self):
        import baseline_process as m
        self.start_patch.stop()
        deadline = time.monotonic()+5
        for child, birth in self.children:
            if child.poll() is None:
                try:
                    identities = m.session_members(child.pid, deadline)
                    for number in (m.signal.SIGTERM, m.signal.SIGKILL):
                        # Fixture-only ownership: this directly launched root's birth
                        # and fresh SID plus exact runtime/known synthetic arguments.
                        for identity in identities:
                            if identity.pid == child.pid and identity.birth != birth:
                                continue
                            known = (identity.args.startswith(REAL_PYTHON + " ")
                                     or identity.args.startswith(REAL_NODE + " ")
                                     or "synthetic-token" in identity.args)
                            if known:
                                m.signal_verified(identity, number,
                                    inspect=lambda pid: m.inspect(pid, deadline))
                        try:
                            child.wait(timeout=.2)
                            break
                        except m.subprocess.TimeoutExpired:
                            identities = m.session_members(child.pid, deadline)
                finally:
                    child.wait(timeout=max(.01, deadline-time.monotonic()))
            for stream in (child.stdin, child.stdout, child.stderr):
                if stream is not None:
                    stream.close()

    def test_platform_birth_identity_is_stable_for_owned_parent(self):
        from baseline_process import birth_identity
        self.assertEqual(birth_identity(os.getpid()), birth_identity(os.getpid()))
        self.assertTrue(birth_identity(os.getpid()))

    def test_blocked_node_loop_is_independently_stopped_and_reaped(self):
        from baseline_process import ProcessStopped, run_owned
        node = REAL_NODE
        self.assertIsNotNone(node)
        started = time.monotonic()
        with self.assertRaises(ProcessStopped) as stopped:
            run_owned([node, "-e", "process.stdin.once('data',()=>{process.stdout.write('READY');while(true){}})"],
                      input="synthetic", timeout=2, cleanup_seconds=1, env=dict(os.environ))
        self.assertTrue(stopped.exception.quiescent)
        self.assertTrue(stopped.exception.reaped)
        self.assertLess(time.monotonic() - started, 3)

    def test_normal_exit_still_requires_owned_session_to_be_empty(self):
        from baseline_process import run_owned
        result = run_owned([REAL_PYTHON, "-c", "import sys; print(sys.stdin.read())"],
                           input="synthetic", timeout=3, cleanup_seconds=0.5, env=dict(os.environ))
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "synthetic")
        self.assertTrue(result.processQuiescent)
        self.assertTrue(result.directChildReaped)

    def test_unexpected_descendant_is_cleaned_but_never_admitted_as_normal_success(self):
        from baseline_process import ProcessStopped, run_owned
        script = f"REAL_PYTHON = {REAL_PYTHON!r}\n" + "import subprocess,sys; subprocess.Popen([REAL_PYTHON,'-c','import time; time.sleep(30)']); print('spawned',flush=True)"
        with self.assertRaises(ProcessStopped) as stopped:
            run_owned([REAL_PYTHON, "-c", script], timeout=6, cleanup_seconds=3, env=dict(os.environ))
        self.assertTrue(stopped.exception.unexpected_descendant)
        self.assertTrue(stopped.exception.reaped)
        # A killed orphan can remain kernel-visible until the OS reaps it. The
        # adversarial fixture must be rejected whether absence is proven or not.
        self.assertIsInstance(stopped.exception.quiescent, bool)

    def test_changed_birth_or_command_is_never_signalled(self):
        from baseline_process import Identity, signal_verified
        original = Identity(123, 1, 123, (1, 2), "node", "node owned.mjs")
        for changed in [Identity(123, 1, 123, (2, 2), "node", "node owned.mjs"),
                        Identity(123, 1, 123, (1, 2), "node", "node foreign.mjs")]:
            calls = []
            self.assertFalse(signal_verified(original, 15, inspect=lambda _: changed,
                                             signal_pid=lambda *args: calls.append(args)))
            self.assertEqual(calls, [])

    def test_unreadable_live_session_member_cannot_be_reported_absent(self):
        import baseline_process as m
        with patch.object(m.subprocess, "run", return_value=Mock(stdout="123\n")), \
             patch.object(m.os, "getsid", return_value=123), \
             patch.object(m, "inspect", side_effect=ProcessLookupError("metadata unavailable")):
            with self.assertRaises(ProcessLookupError):
                m.session_members(123, time.monotonic() + 1)

    def test_confirmed_linux_disappearance_is_normalized_but_live_hidden_proc_is_not(self):
        import baseline_process as m
        with patch.object(m.sys, "platform", "linux"), \
             patch.object(m.Path, "read_text", side_effect=FileNotFoundError):
            with patch.object(m.os, "getsid", side_effect=ProcessLookupError):
                with self.assertRaises(m.ProcessGone):
                    m.birth_identity(123)
            with patch.object(m.os, "getsid", return_value=123):
                with self.assertRaises(m.InspectionUnavailable):
                    m.birth_identity(123)


    def test_interrupted_communication_preserves_cancellation_after_owned_cleanup(self):
        import baseline_process as m
        original = m.subprocess.Popen
        children = []
        def start(*args, **kwargs):
            child = original(*args, **kwargs)
            if args[0][0] != REAL_PYTHON:
                return child
            children.append(child)
            original_communicate = child.communicate
            def interrupted(*call_args, **call_kwargs):
                child.communicate = original_communicate
                raise KeyboardInterrupt()
            child.communicate = interrupted
            return child
        with patch.object(m.subprocess, "Popen", side_effect=start):
            with self.assertRaises(m.ProcessStopped) as stopped:
                m.run_owned([REAL_PYTHON, "-c", "import time;time.sleep(30)"],
                            timeout=3, cleanup_seconds=1, env=dict(os.environ))
        self.assertEqual(stopped.exception.reason, "cancelled")
        self.assertTrue(stopped.exception.quiescent)
        self.assertTrue(stopped.exception.reaped)
        self.assertIsNotNone(children[0].returncode)

    def test_disappearing_member_does_not_hide_another_verified_live_member(self):
        import baseline_process as m
        live = m.Identity(124, 123, 123, (1, 2), "node", "node owned.mjs")
        with patch.object(m.subprocess, "run", return_value=Mock(stdout="123\n124\n")), \
             patch.object(m.os, "getsid", return_value=123), \
             patch.object(m, "inspect", side_effect=[m.ProcessGone(), live]):
            self.assertEqual(m.session_members(123, time.monotonic() + 1), [live])

    def test_unreadable_member_preserves_other_verified_members_for_cleanup(self):
        import baseline_process as m
        live = m.Identity(124, 123, 123, (1, 2), "node", "node owned.mjs")
        with patch.object(m.subprocess, "run", return_value=Mock(stdout="123\n124\n")), \
             patch.object(m.os, "getsid", return_value=123), \
             patch.object(m, "inspect", side_effect=[m.InspectionUnavailable("unreadable"), live]):
            with self.assertRaises(m.InspectionUnavailable) as unavailable:
                m.session_members(123, time.monotonic() + 1)
            self.assertEqual(unavailable.exception.members, [live])

    def test_term_resistant_collector_is_killed_by_verified_pid_and_reaped(self):
        import baseline_process as m
        signals = []
        original = m.signal_verified
        def recorded(identity, number, **kwargs):
            sent = original(identity, number, **kwargs)
            signals.append((number, sent))
            return sent
        with patch.object(m, "signal_verified", side_effect=recorded):
            with self.assertRaises(m.ProcessStopped) as stopped:
                m.run_owned([REAL_NODE, "-e", "process.on('SIGTERM',()=>{});process.stdin.once('data',()=>{while(true){}})"],
                            input="synthetic", timeout=6, cleanup_seconds=5, env=dict(os.environ))
        self.assertIn((15, True), signals)
        self.assertIn((9, True), signals)
        self.assertTrue(stopped.exception.quiescent)
        self.assertTrue(stopped.exception.reaped)

    def test_successful_exit_with_detached_pipes_still_cleans_same_session_child(self):
        import baseline_process as m
        script = f"REAL_PYTHON = {REAL_PYTHON!r}\n" + "import subprocess,sys;subprocess.Popen([REAL_PYTHON,'-c','import time;time.sleep(30)'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);print('done')"
        with self.assertRaises(m.ProcessStopped) as stopped:
            m.run_owned([REAL_PYTHON, "-c", script], timeout=3, cleanup_seconds=1, env=dict(os.environ))
        self.assertTrue(stopped.exception.unexpected_descendant)
        self.assertTrue(stopped.exception.reaped)
        # Deliberate orphaning may leave a kernel-visible zombie after the
        # bounded cleanup; the self-reaping fixture separately proves absence.
        self.assertIsInstance(stopped.exception.quiescent, bool)

    def test_interruption_during_signal_cleanup_still_stops_and_reaps_owned_child(self):
        import baseline_process as m
        start_original, signal_original = m.subprocess.Popen, m.signal_verified
        children, interrupted = [], [False]
        def start(*args, **kwargs):
            child = start_original(*args, **kwargs)
            if args[0][0] == REAL_PYTHON:
                children.append(child)
            return child
        def stop(identity, number, **kwargs):
            if not interrupted[0]:
                interrupted[0] = True
                raise KeyboardInterrupt()
            return signal_original(identity, number, **kwargs)
        try:
            with patch.object(m.subprocess, "Popen", side_effect=start), \
                 patch.object(m, "signal_verified", side_effect=stop):
                with self.assertRaises(m.ProcessStopped) as stopped:
                    m.run_owned([REAL_PYTHON, "-c", "import time;time.sleep(30)"],
                                timeout=2, cleanup_seconds=1, env=dict(os.environ))
            self.assertEqual(stopped.exception.reason, "cancelled")
            self.assertTrue(stopped.exception.quiescent)
            self.assertTrue(stopped.exception.reaped)
        finally:
            # A RED cleanup test must not leave its fake process behind.
            for child in children:
                if child.poll() is None:
                    identity = m.inspect(child.pid, time.monotonic() + 1)
                    signal_original(identity, 9, inspect=lambda pid: m.inspect(pid, time.monotonic() + 1))
                    child.wait(timeout=1)

    def test_descendant_first_seen_after_term_always_invalidates_admission(self):
        import baseline_process as m
        owned = m.Identity(123, os.getpid(), 123, (1, 2), "node", "node owned.mjs")
        descendant = m.Identity(124, 123, 123, (3, 4), "node", "node child.mjs")
        child = Mock(pid=123, returncode=0, stdin=None)
        child.communicate.return_value = ("", "")
        child.wait.return_value = 0
        inspected = [False]
        def inspect(pid, _deadline):
            if pid == 123 and not inspected[0]:
                inspected[0] = True
                return owned
            raise m.ProcessGone()
        with patch.object(m.subprocess, "Popen", return_value=child), \
             patch.object(m, "inspect", side_effect=inspect), \
             patch.object(m, "session_members", side_effect=[[owned], [], [descendant], [], []]), \
             patch.object(m, "signal_verified", return_value=True):
            with self.assertRaises(m.ProcessStopped) as stopped:
                m.run_owned(["synthetic"], timeout=3, cleanup_seconds=1, env={})
        self.assertTrue(stopped.exception.unexpected_descendant)

    def test_observed_descendant_leaving_session_is_not_verified_absent(self):
        import baseline_process as m
        owned = m.Identity(123, os.getpid(), 123, (1, 2), "node", "node owned.mjs")
        descendant = m.Identity(124, 123, 123, (3, 4), "node", "node child.mjs")
        escaped = m.Identity(124, 1, 999, (3, 4), "node", "node child.mjs")
        child = Mock(pid=123, returncode=0, stdin=None)
        child.wait.return_value = 0
        initialized = [False]
        def inspect(pid, _deadline):
            if pid == 123 and not initialized[0]:
                initialized[0] = True
                return owned
            if pid == 124:
                return escaped
            raise m.ProcessGone()
        with patch.object(m.subprocess, "Popen", return_value=child), \
             patch.object(m, "inspect", side_effect=inspect), \
             patch.object(m, "session_members", side_effect=[[owned, descendant], [descendant], [], [], []]), \
             patch.object(m, "signal_verified", return_value=True):
            with self.assertRaises(m.ProcessStopped) as stopped:
                m.run_owned(["synthetic"], timeout=3, cleanup_seconds=1, env={})
        self.assertTrue(stopped.exception.unexpected_descendant)
        self.assertFalse(stopped.exception.quiescent)

    def test_self_reaping_descendant_has_positive_kernel_absence_evidence(self):
        import baseline_process as m
        script = f"REAL_PYTHON = {REAL_PYTHON!r}\n" + """import signal, subprocess, sys, time
child = None
def stop(*_):
    if child is not None:
        child.wait(timeout=2)
    sys.exit(0)
signal.signal(signal.SIGTERM, stop)
child = subprocess.Popen([REAL_PYTHON, '-c', 'import time;time.sleep(30)'])
print('spawned', flush=True)
while True: time.sleep(.1)
"""
        with self.assertRaises(m.ProcessStopped) as stopped:
            m.run_owned([REAL_PYTHON, "-c", script], timeout=4, cleanup_seconds=2, env=dict(os.environ))
        self.assertTrue(stopped.exception.unexpected_descendant)
        self.assertTrue(stopped.exception.reaped)
        self.assertTrue(stopped.exception.quiescent)

    def test_one_shot_cancellation_in_every_shutdown_phase_is_retried(self):
        import baseline_process as m
        phases = ("first-census", "refresh-census", "final-census", "term", "kill", "grace", "wait", "close")
        for phase in phases:
            for cancellation in (KeyboardInterrupt, SystemExit):
                with self.subTest(phase=phase, cancellation=cancellation.__name__):
                    owned = m.Identity(123, os.getpid(), 123, (1, 2), "node", "node owned.mjs")
                    child = Mock(pid=123, returncode=0, stdin=None)
                    child.communicate.return_value = ("", "")
                    child.wait.return_value = 0
                    counters = {"census": 0, "inspect": 0}
                    interrupted = [False]
                    def interrupt(at):
                        if phase == at and not interrupted[0]:
                            interrupted[0] = True
                            raise cancellation()
                    def inspect(pid, deadline):
                        counters["inspect"] += 1
                        if counters["inspect"] == 1:
                            return owned
                        raise m.ProcessGone()
                    def census(sid, deadline):
                        counters["census"] += 1
                        at = {2: "first-census", 3: "refresh-census", 5: "final-census"}.get(counters["census"])
                        interrupt(at)
                        return []
                    def stop(identity, number, **kwargs):
                        interrupt("term" if number == 15 else "kill")
                        return True
                    def sleep(seconds):
                        interrupt("grace")
                    def wait(**kwargs):
                        interrupt("wait")
                        return 0
                    child.wait.side_effect = wait
                    child.stdout.close.side_effect = lambda: interrupt("close")
                    with patch.object(m.subprocess, "Popen", return_value=child), \
                         patch.object(m, "inspect", side_effect=inspect), \
                         patch.object(m, "session_members", side_effect=census), \
                         patch.object(m, "signal_verified", side_effect=stop), \
                         patch.object(m.time, "sleep", side_effect=sleep):
                        with self.assertRaises(m.ProcessStopped) as stopped:
                            m.run_owned(["synthetic"], timeout=3, cleanup_seconds=1, env={})
                    self.assertTrue(interrupted[0])
                    self.assertEqual(stopped.exception.reason, "cancelled")
                    self.assertTrue(stopped.exception.quiescent)
                    self.assertTrue(stopped.exception.reaped)
                    self.assertGreaterEqual(child.wait.call_count, 1)
                    self.assertTrue(child.stdout.close.called)
                    self.assertTrue(child.stderr.close.called)

    def test_repeated_cleanup_cancellation_exhausts_original_deadline(self):
        import baseline_process as m
        owned = m.Identity(123, os.getpid(), 123, (1, 2), "node", "node owned.mjs")
        child = Mock(pid=123, returncode=0, stdin=None)
        child.communicate.return_value = ("", "")
        clock, calls = [0], [0]
        def now():
            clock[0] += .02
            return clock[0]
        def census(sid, deadline):
            calls[0] += 1
            if calls[0] == 1:
                return []
            raise KeyboardInterrupt()
        with patch.object(m.subprocess, "Popen", return_value=child), \
             patch.object(m.time, "monotonic", side_effect=now), \
             patch.object(m, "inspect", return_value=owned), \
             patch.object(m, "session_members", side_effect=census):
            with self.assertRaises(m.ProcessStopped) as stopped:
                m.run_owned(["synthetic"], timeout=1, cleanup_seconds=.5, env={})
        self.assertEqual(stopped.exception.reason, "cancelled")
        self.assertFalse(stopped.exception.quiescent)
        self.assertLess(calls[0], 60)
        self.assertLess(clock[0], 1.3)


    def test_real_operator_signal_between_cleanup_phases_is_deferred_and_handlers_restored(self):
        import baseline_process as m
        owned = m.Identity(123, os.getpid(), 123, (1, 2), "node", "node owned.mjs")
        for number in (m.signal.SIGINT, m.signal.SIGTERM):
            with self.subTest(signal=number):
                child = Mock(pid=123, returncode=0, stdin=None)
                child.communicate.return_value = ("", "")
                child.wait.return_value = 0
                count = [0]
                def inspect(pid, deadline):
                    count[0] += 1
                    if count[0] == 1:
                        return owned
                    raise namespace["ProcessGone"]()
                def interrupted_values():
                    # Outside cleanup_step's operation boundary, in terminate's loop.
                    os.kill(os.getpid(), number)
                    return []
                class Ledger(dict):
                    def values(self):
                        if not getattr(self, "interrupted", False):
                            self.interrupted = True
                            return interrupted_values()
                        return super().values()
                # Injection replaces only the observation dictionary via a small source snapshot.
                source = Path(m.__file__).read_text().replace("observed = {}", "observed = injected_ledger()")
                namespace = dict(m.__dict__, injected_ledger=Ledger)
                exec(compile(source, m.__file__, "exec"), namespace)
                previous = m.signal.getsignal(number)
                def throwing(*_):
                    raise KeyboardInterrupt()
                m.signal.signal(number, throwing)
                try:
                    with patch.object(m.subprocess, "Popen", return_value=child):
                        namespace["inspect"] = inspect
                        namespace["session_members"] = Mock(return_value=[])
                        namespace["signal_verified"] = Mock(return_value=True)
                        with self.assertRaises(namespace["ProcessStopped"]) as stopped:
                            namespace["run_owned"](["synthetic"], timeout=3, cleanup_seconds=1, env={})
                    self.assertEqual(stopped.exception.reason, "cancelled")
                    self.assertTrue(stopped.exception.reaped)
                    self.assertTrue(stopped.exception.quiescent)
                    self.assertIs(m.signal.getsignal(number), throwing)
                finally:
                    m.signal.signal(number, previous)

    def test_signal_received_during_handler_restoration_cannot_become_success(self):
        import baseline_process as m
        result = Mock(processQuiescent=True, directChildReaped=True)
        original = m.signal.signal
        previous = m.signal.getsignal(m.signal.SIGINT)
        sent = [False]
        def install(number, handler):
            if number == m.signal.SIGINT and handler is previous and not sent[0]:
                sent[0] = True
                os.kill(os.getpid(), number)
            return original(number, handler)
        with patch.object(m, "_run_owned", return_value=result), \
             patch.object(m.signal, "signal", side_effect=install):
            with self.assertRaises(m.ProcessStopped) as stopped:
                m.run_owned(["synthetic"], timeout=3, cleanup_seconds=1, env={})
        self.assertTrue(sent[0])
        self.assertEqual(stopped.exception.reason, "cancelled")
        self.assertTrue(stopped.exception.quiescent)
        self.assertTrue(stopped.exception.reaped)
        self.assertIs(m.signal.getsignal(m.signal.SIGINT), previous)

    def test_credential_wrapper_exec_chain_and_bounded_subshells_complete(self):
        import baseline_process as m
        with tempfile.TemporaryDirectory() as temporary:
            outer, inner = Path(temporary)/"outer.sh", Path(temporary)/"inner.sh"
            outer.write_text('exec -a "$0" /bin/bash "$1"\n')
            inner.write_text(f"""a="$(dirname "$0")"
b="$(realpath "$0")"
c="$(uname -m)"
sleep .15
exec "{REAL_PYTHON}" -c 'import time;time.sleep(.15);print("synthetic-token")'
""")
            result = m.run_owned(["/bin/bash", str(outer), str(inner)], timeout=8,
                                cleanup_seconds=5, env=dict(os.environ), policy="credential-wrapper")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "synthetic-token")
        self.assertTrue(result.processQuiescent)
        self.assertTrue(result.directChildReaped)

    def test_credential_policy_reaps_a_shim_shaped_single_child(self):
        import baseline_process as m
        script = f"REAL_PYTHON = {REAL_PYTHON!r}\n" + "import subprocess,sys;subprocess.run([REAL_PYTHON,'-c','import time;time.sleep(.15);print(\"synthetic-token\")'],check=True)"
        result = m.run_owned([REAL_PYTHON, "-c", script], timeout=8, cleanup_seconds=5,
                            env=dict(os.environ), policy="credential-wrapper")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "synthetic-token")
        self.assertTrue(result.processQuiescent)
        self.assertTrue(result.directChildReaped)

    def test_fast_clean_child_exit_is_accepted_after_reaping_and_absence(self):
        import baseline_process as m
        for _ in range(4):
            result = m.run_owned(["/bin/echo", "synthetic"], timeout=6, cleanup_seconds=5,
                                env=dict(os.environ))
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout.strip(), "synthetic")
            self.assertTrue(result.processQuiescent)
            self.assertTrue(result.directChildReaped)

    def test_kernel_disappearance_during_getsid_is_normalized(self):
        import baseline_process as m
        with patch.object(m, "birth_identity", return_value=(1, 2)), \
             patch.object(m.subprocess, "run", return_value=Mock(stdout="1 node node owned.mjs Z", returncode=0)), \
             patch.object(m.os, "getsid", side_effect=ProcessLookupError):
            with self.assertRaises(m.ProcessGone):
                m.inspect(123, time.monotonic()+1)

    def test_terminal_snapshot_never_authorizes_a_signal(self):
        import baseline_process as m
        zombie = m.Identity(123, 1, 123, (1, 2), "node", "node owned.mjs")
        object.__setattr__(zombie, "state", "Z")
        calls = []
        self.assertFalse(m.signal_verified(zombie, 9, inspect=lambda _: zombie,
            signal_pid=lambda *args: calls.append(args)))
        self.assertEqual(calls, [])

    def test_terminal_command_presentation_is_present_until_reap_without_poisoning_clean_exit(self):
        import baseline_process as m
        owned = m.Identity(123, os.getpid(), 123, (1, 2), "node", "node owned.mjs")
        terminal = m.Identity(123, os.getpid(), 123, (1, 2), "(node)", "(node)")
        object.__setattr__(terminal, "state", "Z")
        child = Mock(pid=123, returncode=0, stdin=None)
        child.communicate.return_value=("synthetic", "")
        child.wait.return_value=0
        def inspect(pid, deadline):
            if not getattr(inspect, "started", False):
                inspect.started = True
                return owned
            raise m.ProcessGone()
        with patch.object(m.subprocess, "Popen", return_value=child), \
             patch.object(m, "inspect", side_effect=inspect), \
             patch.object(m, "session_members", side_effect=[[terminal], [], [], [], []]), \
             patch.object(m, "signal_verified", return_value=False):
            result=m.run_owned(["synthetic"], timeout=3, cleanup_seconds=1, env={})
        self.assertTrue(result.processQuiescent)
        self.assertTrue(result.directChildReaped)
        child.wait.assert_called()

    def test_live_scheduling_state_change_does_not_change_owned_identity(self):
        import baseline_process as m
        sleeping=m.Identity(123, 1, 123, (1, 2), "node", "node owned.mjs", "S")
        running=m.Identity(123, 1, 123, (1, 2), "node", "node owned.mjs", "R")
        calls=[]
        self.assertTrue(m.signal_verified(sleeping, 15, inspect=lambda _: running,
            signal_pid=lambda *args: calls.append(args)))
        self.assertEqual(calls, [(123, 15)])

    def test_credential_child_surviving_parent_exit_invalidates_normal_success(self):
        import baseline_process as m
        root=m.Identity(123, os.getpid(), 123, (1, 2), "bash", "bash wrapper")
        helper=m.Identity(124, 123, 123, (3, 4), "helper", "helper synthetic-token")
        child=Mock(pid=123, returncode=0, stdin=None)
        child.communicate.return_value=("synthetic-token", "")
        child.wait.return_value=0
        count=[0]
        def inspect(pid, deadline):
            count[0]+=1
            if count[0]==1:return root
            raise m.ProcessGone()
        with patch.object(m.subprocess, "Popen", return_value=child), \
             patch.object(m, "inspect", side_effect=inspect), \
             patch.object(m, "session_members", side_effect=[[root], [helper], [], [], []]), \
             patch.object(m, "signal_verified", return_value=True):
            with self.assertRaises(m.ProcessStopped) as stopped:
                m.run_owned(["synthetic"], timeout=3, cleanup_seconds=1, env={}, policy="credential-wrapper")
        self.assertTrue(stopped.exception.unexpected_descendant)
        self.assertTrue(stopped.exception.reaped)
        self.assertTrue(stopped.exception.quiescent)

    def test_credential_exec_policy_never_signals_reused_birth_or_changed_session(self):
        import baseline_process as m
        owned=m.Identity(123, os.getpid(), 123, (1, 2), "bash", "bash wrapper")
        for changed in (m.Identity(123, os.getpid(), 123, (9, 9), "python", "python synthetic-token"),
                        m.Identity(123, os.getpid(), 999, (1, 2), "python", "python synthetic-token")):
            with self.subTest(changed=changed):
                child=Mock(pid=123, returncode=0, stdin=None)
                child.communicate.return_value=("synthetic-token", "")
                child.wait.return_value=0
                first=[True];clock=[0]
                def inspect(pid, deadline):
                    if first[0]:first[0]=False;return owned
                    return changed
                def now():clock[0]+=.05;return clock[0]
                signals=Mock(return_value=True)
                with patch.object(m.subprocess, "Popen", return_value=child), \
                     patch.object(m, "inspect", side_effect=inspect), \
                     patch.object(m, "session_members", return_value=[changed]), \
                     patch.object(m.time, "monotonic", side_effect=now), \
                     patch.object(m.time, "sleep"), \
                     patch.object(m, "signal_verified", signals):
                    with self.assertRaises(m.ProcessStopped) as stopped:
                        m.run_owned(["synthetic"], timeout=3, cleanup_seconds=1, env={}, policy="credential-wrapper")
                signals.assert_not_called()
                self.assertFalse(stopped.exception.quiescent)



if __name__ == "__main__":
    unittest.main()
